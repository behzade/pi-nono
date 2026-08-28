import assert from "node:assert/strict";
import test from "node:test";
import {
	DEFAULT_CONFIG,
	buildShellEnvironment,
	mergeGlobalConfig,
	normalizeConfig,
	restoreCapturedShellEnvironment,
} from "./sandbox-config.ts";

test("nono is the only and default backend", () => {
	assert.equal(DEFAULT_CONFIG.backend, "nono");
	assert.equal(normalizeConfig({ backend: "nono" }).backend, "nono");
	assert.throws(() => normalizeConfig({ backend: "codex" }), /backend must be nono/);
	assert.throws(() => normalizeConfig({ codexCommand: "codex" }), /unknown fields/);
	assert.throws(() => normalizeConfig({ permissionProfile: "pi" }), /unknown fields/);
	assert.throws(() => normalizeConfig({ allowPty: true }), /unknown fields/);
});

test("normalizes exact hosts and rejects broad command grants", () => {
	const config = normalizeConfig({
		network: {
			allowedDomains: ["API.Example.COM."],
			deniedDomains: ["*.internal.example"],
			allowUnixSockets: ["/safe.sock"],
		},
	});
	assert.deepEqual(config.network?.allowedDomains, ["api.example.com"]);
	assert.deepEqual(config.network?.deniedDomains, ["*.internal.example"]);
	assert.deepEqual(config.network?.allowUnixSockets, ["/safe.sock"]);
	assert.throws(
		() => normalizeConfig({ network: { allowedDomains: ["*"] } }),
		/exact hostnames or IPs/,
	);
	assert.deepEqual(
		normalizeConfig({ network: { deniedDomains: ["*", "**.Example.COM.", "api.example.com"] } }).network?.deniedDomains,
		["*", "**.example.com", "api.example.com"],
	);
	for (const pattern of ["api.*.example.com", "foo*", "***.example.com", "example.*", "*example.com", "*.127.0.0.1"]) {
		assert.throws(
			() => normalizeConfig({ network: { deniedDomains: [pattern] } }),
			/exact hosts, \*, \*\.domain, or \*\*\.domain/,
			pattern,
		);
	}
});

test("global config extends defaults without dropping hard rules", () => {
	const result = mergeGlobalConfig(
		DEFAULT_CONFIG,
		normalizeConfig({
			filesystem: { allowWrite: ["/state"], denyRead: ["**/private.json"] },
			network: { allowedDomains: ["grafana.example.com"] },
		}),
	);
	assert(result.filesystem?.allowWrite?.includes("."));
	assert(result.filesystem?.allowRead?.includes(":root"));
	assert(result.filesystem?.allowWrite?.includes(":development_storage"));
	assert(result.filesystem?.allowWrite?.includes("/state"));
	assert(result.filesystem?.denyRead?.includes("~/.ssh"));
	assert(result.filesystem?.denyRead?.includes("~/.config/pi-nono"));
	assert(result.filesystem?.denyWrite?.includes("~/.config/pi-nono"));
	assert(result.filesystem?.denyRead?.includes("**/private.json"));
	assert(result.network?.allowedDomains?.includes("github.com"));
	assert(result.network?.allowedDomains?.includes("registry.npmjs.org"));
	assert(result.network?.allowedDomains?.includes("grafana.example.com"));
});

test("shell environment preserves the active development shell and removes secret names", () => {
	const environment = buildShellEnvironment(
		DEFAULT_CONFIG,
		{
			PATH: "/bin",
			HOME: "/home/test",
			SDKROOT: "/nix/store/sdk",
			NIX_LDFLAGS: "-L/nix/store/lib",
			BINDGEN_EXTRA_CLANG_ARGS: "-isystem /nix/store/include",
			API_TOKEN: "secret",
			DATABASE_PASSWORD: "secret",
			UNRELATED: "drop",
		},
	);
	assert.equal(environment.PATH, "/bin");
	assert.equal(environment.HOME, "/home/test");
	assert.equal(environment.SDKROOT, "/nix/store/sdk");
	assert.equal(environment.NIX_LDFLAGS, "-L/nix/store/lib");
	assert.equal(
		environment.BINDGEN_EXTRA_CLANG_ARGS,
		"-isystem /nix/store/include",
	);
	assert.equal(environment.API_TOKEN, undefined);
	assert.equal(environment.DATABASE_PASSWORD, undefined);
	assert.equal(environment.UNRELATED, undefined);
	assert.equal(environment.PYTHONDONTWRITEBYTECODE, "1");
});

test("disabled sandbox restores captured PATH with current session metadata", () => {
	const environment = restoreCapturedShellEnvironment(
		{
			PATH: "/captured/cargo:/captured/git",
			HOME: "/home/test",
			PI_SESSION_ID: "stale",
			PI_SESSION_FILE: "/stale/session.jsonl",
		},
		{
			PATH: "/runtime/tools",
			PI_SESSION_ID: "current",
			PI_PROVIDER: "provider",
			PI_MODEL: "model",
		},
	);

	assert.equal(environment.PATH, "/captured/cargo:/captured/git");
	assert.equal(environment.HOME, "/home/test");
	assert.equal(environment.PI_SESSION_ID, "current");
	assert.equal(environment.PI_SESSION_FILE, undefined);
	assert.equal(environment.PI_PROVIDER, "provider");
	assert.equal(environment.PI_MODEL, "model");
});

test("rejects malformed config instead of weakening policy", () => {
	assert.throws(() => normalizeConfig(null), /JSON object/);
	assert.throws(() => normalizeConfig({ enabled: "yes" }), /enabled/);
	assert.throws(() => normalizeConfig({ nonoPath: "/custom/nono" }), /unknown fields/);
	assert.throws(() => normalizeConfig({ network: { enabled: "yes" } }), /network.enabled/);
	assert.throws(() => normalizeConfig({ network: { allowAllUnixSockets: "yes" } }), /boolean/);
	assert.throws(() => normalizeConfig({ shellEnvironment: { inherit: "some" } }), /inherit/);
});
