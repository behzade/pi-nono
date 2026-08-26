import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import type { SandboxExecRequest } from "./sandbox-protocol.ts";
import { DEFAULT_CONFIG } from "./sandbox-config.ts";
import { buildNonoProfile, NonoClient, sandboxCommandStdio } from "./nono-client.ts";
import { buildSandboxExecRequest } from "./sandbox-policy.ts";

function request(network: SandboxExecRequest["policy"]["network"]): SandboxExecRequest {
	return {
		type: "exec",
		id: "test",
		command: { program: "/bin/sh", args: ["-c", "true"] },
		cwd: "/work",
		env: { PATH: "/bin", HOME: "/home/test" },
		timeout_ms: null,
		policy: {
			base_rights: [
				{ access: "read", path: "/work", scope: "tree", missing_path: "reject" },
				{ access: "write", path: "/work", scope: "tree", missing_path: "reject" },
			],
			grants: [
				{ access: "read", path: "/outside/input.txt", scope: "file", missing_path: "reject" },
			],
			denies: [],
			network,
			unix_socket_roots: [],
			output_limit_bytes: 1024,
		},
	};
}

test("one-shot commands close stdin; interactive jobs keep a writable pipe", () => {
	assert.deepEqual(sandboxCommandStdio(false), ["ignore", "pipe", "pipe"]);
	assert.deepEqual(sandboxCommandStdio(true), ["pipe", "pipe", "pipe"]);
});

test("profile maps exact filesystem scopes and blocks network by default", () => {
	const profile = buildNonoProfile(request({ mode: "blocked" })) as {
		filesystem: Record<string, string[]>;
		network: { block: boolean; allow_domain: string[] };
	};
	assert.deepEqual(profile.filesystem.allow, ["/work"]);
	assert.deepEqual(profile.filesystem.read, existsSync("/nix/store") ? ["/nix/store", "/work"] : ["/work"]);
	const devices = ["/dev/null", "/dev/random", "/dev/urandom", "/dev/zero"].filter(existsSync).sort();
	assert.deepEqual(profile.filesystem.allow_file, devices);
	assert.deepEqual(profile.filesystem.read_file, [...devices, "/outside/input.txt"].sort());
	assert.equal(profile.network.block, true);
	assert.deepEqual(profile.network.allow_domain, []);
});

test("Linux delegates overlapping denies to the mount layer while macOS keeps Seatbelt denies", () => {
	const value = request({ mode: "blocked" });
	value.policy.denies = [{ access: "read_write", pattern: "/work/.env", scope: "file" }];
	const linux = buildNonoProfile(value, "linux") as { filesystem: { deny: string[] } };
	const macos = buildNonoProfile(value, "darwin") as { filesystem: { deny: string[] } };
	assert.deepEqual(linux.filesystem.deny, []);
	assert.deepEqual(macos.filesystem.deny, ["/work/.env"]);
});

test("macOS grants Zig the exact machine trust-store file", () => {
	const trustStore = "/Library/Keychains/System.keychain";
	const darwin = buildNonoProfile(request({ mode: "blocked" }), "darwin") as {
		filesystem: { read_file: string[]; bypass_protection: string[] };
	};
	const linux = buildNonoProfile(request({ mode: "blocked" }), "linux") as {
		filesystem: { read_file: string[]; bypass_protection: string[] };
	};

	assert(darwin.filesystem.read_file.includes(trustStore));
	assert(darwin.filesystem.bypass_protection.includes(trustStore));
	assert.equal(linux.filesystem.read_file.includes(trustStore), false);
	assert.equal(linux.filesystem.bypass_protection.includes(trustStore), false);
	assert.equal(darwin.filesystem.read_file.includes("/Library/Keychains"), false);
});

test("macOS keeps project .guardian readable but read-only", () => {
	const value = request({ mode: "blocked" });
	value.policy.denies = [{ access: "write", pattern: "/work/.guardian", scope: "tree" }];
	const profile = buildNonoProfile(value, "darwin") as {
		filesystem: { read: string[]; deny: string[] };
		unsafe_macos_seatbelt_rules: string[];
	};

	assert(profile.filesystem.read.includes("/work"));
	assert.deepEqual(profile.filesystem.deny, []);
	assert.deepEqual(profile.unsafe_macos_seatbelt_rules, [
		'(deny file-write* (subpath "/work/.guardian"))',
	]);
});

test("profile maps exact hosts without enabling unrestricted network", () => {
	const profile = buildNonoProfile(request({
		mode: "proxy",
		allowed_hosts: ["api.example.com", "192.0.2.1"],
		local_ports: [3000],
	})) as { network: { block: boolean; allow_domain: string[]; open_port: number[] } };
	assert.equal(profile.network.block, false);
	assert.deepEqual(profile.network.allow_domain, ["api.example.com", "192.0.2.1"]);
	assert.deepEqual(profile.network.open_port, [3000]);
});

test("local endpoints map only their exact approved ports", () => {
	for (const platform of ["linux", "darwin"] as const) {
		const profile = buildNonoProfile(
			request({ mode: "loopback", ports: [3000, 43127] }),
			platform,
		) as { network: { open_port: number[]; open_port_range?: unknown } };
		assert.deepEqual(profile.network.open_port, [3000, 43127]);
		assert.equal(profile.network.open_port_range, undefined);
	}
});

const zigHttpsHost = "deps.files.ghostty.org";
const zigHttpsUrl = `https://${zigHttpsHost}/uucode-2826a37a4562284fdacd8fa029d49509cc9bffcd.tar.gz`;
const zigHttpsNono = process.env.PI_NONO_ZIG_HTTPS_TEST_NONO;
const zigHttpsZig = process.env.PI_NONO_ZIG_HTTPS_TEST_ZIG;
const runZigHttpsRegression = process.platform === "darwin" &&
	zigHttpsNono !== undefined && zigHttpsZig !== undefined;

test("macOS Zig HTTPS works from a fresh cache only for the permitted host", {
	skip: runZigHttpsRegression
		? false
		: "set PI_NONO_ZIG_HTTPS_TEST_NONO and PI_NONO_ZIG_HTTPS_TEST_ZIG on macOS",
}, async () => {
	assert(zigHttpsNono);
	assert(zigHttpsZig);
	const cwd = mkdtempSync(join(tmpdir(), "pi-zig-https-"));
	writeFileSync(join(cwd, "build.zig"),
		'const std = @import("std");\npub fn build(b: *std.Build) void { _ = b; }\n');
	writeFileSync(join(cwd, "build.zig.zon"), [
		".{",
		"    .name = .pi_nono_https_test,",
		'    .version = "0.0.0",',
		"    .fingerprint = 0x79f557e732bd0123,",
		'    .minimum_zig_version = "0.16.0",',
		"    .dependencies = .{},",
		'    .paths = .{""},',
		"}",
		"",
	].join("\n"));
	const client = await NonoClient.start(zigHttpsNono, "");
	try {
		const fetch = async (id: string, allowedHosts: string[]) => {
			const cache = join(cwd, id);
			mkdirSync(cache);
			const command = `${shellArg(zigHttpsZig)} fetch --global-cache-dir ${shellArg(cache)} ${shellArg(zigHttpsUrl)}`;
			const request = buildSandboxExecRequest(
				id,
				command,
				cwd,
				60,
				DEFAULT_CONFIG,
				[],
				allowedHosts,
				[],
				process.env,
			);
			const output: Buffer[] = [];
			const result = await client.exec(request, (chunk) => output.push(chunk));
			return { result, output: Buffer.concat(output).toString("utf8") };
		};

		const permitted = await fetch("permitted-cache", [zigHttpsHost]);
		assert.equal(permitted.result.exitCode, 0, permitted.output);
		assert.match(permitted.output, /^uucode-0\.2\.0-/m);

		const blocked = await fetch("blocked-cache", ["example.com"]);
		assert.notEqual(blocked.result.exitCode, 0, blocked.output);
	} finally {
		await client.shutdown();
		rmSync(cwd, { recursive: true, force: true });
	}
});

function shellArg(value: string): string {
	return `'${value.replaceAll("'", `'"'"'`)}'`;
}
