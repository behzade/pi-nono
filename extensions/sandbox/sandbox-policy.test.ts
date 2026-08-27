import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { buildSandboxExecRequest } from "./sandbox-policy.ts";
import { DEFAULT_CONFIG } from "./sandbox-config.ts";
import { canonicalize } from "./io-permissions.ts";

const sourceEnvironment = Object.freeze({ ...process.env });

test("maps current base rights and command-local folder grants", () => {
	const cwd = mkdtempSync(join(tmpdir(), "pi-sandbox-policy-"));
	const canonicalCwd = canonicalize(cwd);
	const state = join(homedir(), ".local", "share", `issues-fixture-${process.pid}`);
	mkdirSync(state, { recursive: true });
	const request = buildSandboxExecRequest(
		"one",
		"issues search view=issue number=79",
		cwd,
		30,
		DEFAULT_CONFIG,
		[{ kind: "write", path: state, directory: true }],
		[],
		[],
		sourceEnvironment,
	);
	assert.match(request.command.program, /\/bash$/);
	assert.deepEqual(request.command.args, ["-c", "issues search view=issue number=79"]);
	assert.equal(request.interactive, false);
	assert.equal(request.timeout_ms, 30_000);
	assert.ok(
		request.policy.base_rights.some(
			(right) => right.access === "read" && right.path === canonicalCwd && right.scope === "tree",
		),
	);
	assert.ok(
		request.policy.base_rights.some(
			(right) =>
				right.access === "write" &&
				right.path === canonicalize(cwd) &&
				right.scope === "tree",
		),
	);
	const broadCacheRoots = [
		canonicalize(join(homedir(), ".cargo")),
		canonicalize(join(homedir(), ".npm")),
		canonicalize(join(homedir(), "Library", "Caches")),
	];
	assert.equal(
		request.policy.base_rights.some(
			(right) => right.access === "write" && broadCacheRoots.includes(right.path),
		),
		false,
	);
	assert.deepEqual(request.policy.grants, [
		{
			access: "write",
			path: state,
			scope: "tree",
			missing_path: "reject",
		},
	]);
	assert.ok(
		request.policy.denies.some(
			(rule) =>
				rule.access === "read_write" && rule.pattern === `${canonicalCwd}/**/*.key`,
		),
	);
	assert.ok(
		request.policy.denies.some(
			(rule) =>
				rule.access === "read_write" &&
				rule.pattern === `${canonicalCwd}/**/.env` &&
				rule.scope === "glob",
		),
	);
	assert.equal(
		request.policy.denies.some(
			(rule) => rule.pattern === join(cwd, ".env") && rule.scope !== "glob",
		),
		false,
	);
});

test("existing host development caches become base rights without creating missing caches", () => {
	const cwd = mkdtempSync(join(tmpdir(), "pi-sandbox-policy-cache-"));
	const bunBin = join(homedir(), ".bun", "bin");
	const npmCache = join(homedir(), ".npm");
	const missingCache = join(homedir(), ".cache", "uv");
	mkdirSync(bunBin, { recursive: true });
	mkdirSync(npmCache, { recursive: true });
	const request = buildSandboxExecRequest(
		"cache-rights",
		"true",
		cwd,
		undefined,
		DEFAULT_CONFIG,
		[],
		[],
		[],
		sourceEnvironment,
	);
	assert(request.policy.base_rights.some((right) =>
		right.access === "write" && right.path === npmCache && right.scope === "tree"));
	assert(request.policy.base_rights.some((right) =>
		right.access === "read" && right.path === bunBin && right.scope === "tree"));
	assert.equal(request.policy.base_rights.some((right) =>
		right.access === "write" && right.path === bunBin), false);
	assert.equal(request.policy.base_rights.some((right) => right.path === missingCache), false);
});

test("legacy :root read setting is ignored for nono", () => {
	const cwd = mkdtempSync(join(tmpdir(), "pi-sandbox-policy-"));
	const request = buildSandboxExecRequest(
		"one",
		"true",
		cwd,
		undefined,
		{
			...DEFAULT_CONFIG,
			filesystem: {
				...DEFAULT_CONFIG.filesystem,
				allowRead: [":root"],
			},
		},
		[],
		[],
		[],
		sourceEnvironment,
	);
	assert.equal(request.policy.base_rights.some((right) => right.path === "/"), false);
});

test("missing configured read roots are omitted instead of becoming create rights", () => {
	const cwd = mkdtempSync(join(tmpdir(), "pi-sandbox-policy-"));
	const missing = join(cwd, "not-created");
	const request = buildSandboxExecRequest(
		"one",
		"true",
		cwd,
		undefined,
		{
			...DEFAULT_CONFIG,
			filesystem: {
				...DEFAULT_CONFIG.filesystem,
				allowRead: [...(DEFAULT_CONFIG.filesystem?.allowRead ?? []), missing],
			},
		},
		[],
		[],
		[],
		sourceEnvironment,
	);
	assert.equal(request.policy.base_rights.some((right) => right.path === missing), false);
});

test("native deny globs reject dot segments before reaching Rust", () => {
	const cwd = mkdtempSync(join(tmpdir(), "pi-sandbox-policy-"));
	for (const denyWrite of ["dir/../*.secret", "./*.secret", "/tmp/../*.secret"]) {
		assert.throws(
			() =>
				buildSandboxExecRequest(
					"one",
					"true",
					cwd,
					undefined,
					{
						...DEFAULT_CONFIG,
						filesystem: { ...DEFAULT_CONFIG.filesystem, denyWrite: [denyWrite] },
					},
					[],
					[],
					[],
					sourceEnvironment,
				),
			/cannot contain \. or \.\./,
		);
	}
});

test("nono policy maps approved hosts and exact loopback ports", () => {
	const cwd = mkdtempSync(join(tmpdir(), "pi-sandbox-policy-"));
	const proxied = buildSandboxExecRequest(
		"one",
		"true",
		cwd,
		undefined,
		DEFAULT_CONFIG,
		[],
		["example.com"],
		[],
		sourceEnvironment,
	);
	assert.deepEqual(proxied.policy.network, {
		mode: "proxy",
		allowed_hosts: ["example.com"],
		local_ports: [],
	});
	const local = buildSandboxExecRequest(
		"local",
		"true",
		cwd,
		undefined,
		DEFAULT_CONFIG,
		[],
		[],
		[43127],
		sourceEnvironment,
	);
	assert.deepEqual(local.policy.network, { mode: "loopback", ports: [43127] });
	const localAndProxy = buildSandboxExecRequest(
		"local-and-proxy",
		"true",
		cwd,
		undefined,
		DEFAULT_CONFIG,
		[],
		["example.com"],
		[43127],
		sourceEnvironment,
	);
	assert.deepEqual(localAndProxy.policy.network, {
		mode: "proxy",
		allowed_hosts: ["example.com"],
		local_ports: [43127],
	});
	assert.throws(
		() => buildSandboxExecRequest(
			"invalid", "true", cwd, undefined, DEFAULT_CONFIG, [], [], [0], sourceEnvironment,
		),
		/ports must be integers from 1 to 65535/,
	);
	const request = buildSandboxExecRequest(
		"one",
		"true",
		cwd,
		undefined,
		{
			...DEFAULT_CONFIG,
			network: { ...DEFAULT_CONFIG.network, allowUnixSockets: ["/tmp/service.sock"] },
		},
		[],
		[],
		[],
		sourceEnvironment,
	);
	assert.deepEqual(request.policy.network, { mode: "blocked" });
	assert.deepEqual(request.policy.unix_socket_roots, [canonicalize("/tmp/service.sock")]);
});

test("nono policy rejects broad and relative Unix socket access", () => {
	const cwd = mkdtempSync(join(tmpdir(), "pi-sandbox-policy-"));
	assert.throws(
		() =>
			buildSandboxExecRequest(
				"one",
				"true",
				cwd,
				undefined,
				{
					...DEFAULT_CONFIG,
					network: { ...DEFAULT_CONFIG.network, allowAllUnixSockets: true },
				},
				[],
				[],
				[],
				sourceEnvironment,
			),
		/does not support allowing all Unix sockets/,
	);
	assert.throws(
		() =>
			buildSandboxExecRequest(
				"one",
				"true",
				cwd,
				undefined,
				{
					...DEFAULT_CONFIG,
					network: { ...DEFAULT_CONFIG.network, allowUnixSockets: ["service.sock"] },
				},
				[],
				[],
				[],
				sourceEnvironment,
			),
		/must be absolute/,
	);
});
