import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import test from "node:test";
import type { SandboxExecRequest } from "./sandbox-protocol.ts";
import { buildNonoProfile, sandboxCommandStdio } from "./nono-client.ts";

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
