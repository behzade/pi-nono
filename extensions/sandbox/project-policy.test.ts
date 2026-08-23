import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { buildSandboxExecRequest } from "./sandbox-policy.ts";
import { DEFAULT_CONFIG, mergeGlobalConfig, normalizeConfig } from "./sandbox-config.ts";
import {
	accessPolicyAdditions,
	activateProjectPolicy,
	addProjectAccess,
	addProjectRights,
	addSessionAccess,
	loadProjectPolicy,
	loadProjectPolicyForUpdate,
	mergeAccessPolicies,
	projectPolicyDiff,
	projectPolicyPath,
	sameProjectPolicy,
	sandboxPolicySummary,
	saveProjectPolicy,
	serializeProjectPolicy,
	type ProjectSandboxPolicy,
} from "./project-policy.ts";

function workspace(): string {
	return mkdtempSync(join(tmpdir(), "pi-project-policy-"));
}

const basePolicy = (): ProjectSandboxPolicy => ({ version: 1, rights: [] });
const machine = mergeGlobalConfig(DEFAULT_CONFIG, {});

test("loads and saves one portable versioned project policy under pi-nono's control root", () => {
	const cwd = workspace();
	assert.equal(projectPolicyPath(cwd), join(cwd, ".guardian", "sandbox.json"));
	const policy: ProjectSandboxPolicy = {
		version: 1,
		rights: [
			{ kind: "filesystem", access: "write", path: "state", scope: "tree" },
			{ kind: "filesystem", access: "write", path: "~/shared.txt", scope: "file" },
			{ kind: "network_host", host: "API.Example.COM." },
		],
	};
	saveProjectPolicy(cwd, policy);
	const serialized = readFileSync(projectPolicyPath(cwd), "utf8");
	assert.equal(serialized, serializeProjectPolicy(policy));
	assert.match(serialized, /"path": "state"/);
	assert.match(serialized, /"path": "~\/shared.txt"/);
	assert.doesNotMatch(serialized, new RegExp(cwd.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
	const loaded = loadProjectPolicy(cwd, machine);
	assert.equal(loaded.networkHosts[0], "api.example.com");
	assert(loaded.filesystem.some((right) => right.path === join(cwd, "state") && right.directory));
});

test("activates exact loopback endpoints, hosts, file rights, and tree rights", () => {
	const cwd = workspace();
	writeFileSync(join(cwd, "input.txt"), "input");
	const active = activateProjectPolicy({
		version: 1,
		rights: [
			{ kind: "network_endpoint", host: "127.0.0.1", port: 43127 },
			{ kind: "network_endpoint", host: "::1", port: 43127 },
			{ kind: "network_host", host: "registry.npmjs.org" },
			{ kind: "filesystem", access: "read", path: "input.txt", scope: "file" },
			{ kind: "filesystem", access: "write", path: "output", scope: "tree" },
		],
	}, cwd, machine);
	assert.deepEqual(active.localPorts, [43127]);
	assert.deepEqual(active.networkHosts, ["registry.npmjs.org"]);
	assert(active.filesystem.some((right) => right.kind === "read" && !right.directory));
	assert(active.filesystem.some((right) => right.kind === "write" && right.directory));
	assert.deepEqual(active.policy.rights.find((right) => right.kind === "network_endpoint"), {
		kind: "network_endpoint",
		host: "localhost",
		port: 43127,
	});
	for (const endpoint of [
		{ kind: "network_endpoint", host: "192.0.2.1", port: 43127 },
		{ kind: "network_endpoint", host: "127.0.0.1", port: 0 },
	] as const) {
		assert.throws(() => activateProjectPolicy({ version: 1, rights: [endpoint] }, cwd, machine), /network_endpoint/);
	}
	assert.throws(() => activateProjectPolicy({
		version: 1,
		rights: [{ kind: "filesystem", access: "read", path: "missing.txt", scope: "file" }],
	}, cwd, machine), /read rights must target an existing path/);
});

test("project .git writes are grants while pi-nono and Pi control writes are rejected", () => {
	const cwd = workspace();
	mkdirSync(join(cwd, ".git"));
	const active = activateProjectPolicy({
		version: 1,
		rights: [{ kind: "filesystem", access: "write", path: ".git", scope: "tree" }],
	}, cwd, machine);
	const request = buildSandboxExecRequest("id", "true", cwd, undefined, active.config, active.filesystem, [], undefined);
	assert.deepEqual(request.policy.grants, [{
		access: "write",
		path: join(cwd, ".git"),
		scope: "tree",
		missing_path: "reject",
	}]);
	assert.throws(() => activateProjectPolicy({
		version: 1,
		rights: [{ kind: "filesystem", access: "write", path: ".pi", scope: "tree" }],
	}, cwd, machine), /cannot grant sandboxed writes to project \.pi/);
	assert.throws(() => activateProjectPolicy({
		version: 1,
		rights: [{ kind: "filesystem", access: "write", path: ".guardian", scope: "tree" }],
	}, cwd, machine), /cannot grant sandboxed writes to project \.guardian/);
	assert.throws(() => activateProjectPolicy({
		version: 1,
		rights: [{ kind: "filesystem", access: "write", path: "~/.config/guardian", scope: "tree" }],
	}, cwd, machine), /cannot grant protected or machine-denied write access/);
	assert.throws(() => activateProjectPolicy({
		version: 1,
		rights: [{ kind: "filesystem", access: "read", path: "~/.config/guardian", scope: "tree" }],
	}, cwd, machine), /cannot grant protected or machine-denied read access/);

	const linked = workspace();
	const target = workspace();
	symlinkSync(target, join(linked, ".git"));
	assert.throws(() => activateProjectPolicy({
		version: 1,
		rights: [{ kind: "filesystem", access: "write", path: ".git", scope: "tree" }],
	}, linked, machine), /cannot cross an existing symlink/);
});

test("machine filesystem and network denies take precedence", () => {
	const cwd = workspace();
	const hard = mergeGlobalConfig(machine, normalizeConfig({
		filesystem: { denyWrite: ["blocked"] },
		network: { deniedDomains: ["api.denied.example"] },
	}));
	assert.throws(() => activateProjectPolicy({
		version: 1,
		rights: [{ kind: "filesystem", access: "write", path: "blocked", scope: "tree" }],
	}, cwd, hard), /machine-denied/);
	assert.throws(() => activateProjectPolicy({
		version: 1,
		rights: [{ kind: "network_host", host: "api.denied.example" }],
	}, cwd, hard), /denied by the machine/);

	const broad = activateProjectPolicy({
		version: 1,
		rights: [{ kind: "filesystem", access: "write", path: ".", scope: "tree" }],
	}, cwd, hard);
	const request = buildSandboxExecRequest("hard-deny", "true", cwd, undefined, broad.config, broad.filesystem, [], undefined);
	assert(request.policy.grants.some((right) => right.path === cwd && right.scope === "tree"));
	assert(request.policy.denies.some((deny) => deny.pattern === join(cwd, "blocked")));
});

test("safe project cache environment additions stay under the shared managed root", () => {
	const cwd = workspace();
	const active = activateProjectPolicy({
		version: 1,
		rights: [],
		developmentCache: { environment: { CUSTOM_TOOL_CACHE: "custom/tool" } },
	}, cwd, machine);
	assert.equal(active.config.developmentCache?.root, machine.developmentCache?.root);
	assert.equal(active.config.developmentCache?.environment?.CUSTOM_TOOL_CACHE, "custom/tool");
	assert.throws(() => activateProjectPolicy({
		version: 1,
		rights: [],
		developmentCache: { environment: { CUSTOM_TOOL_CACHE: "../escape" } },
	}, cwd, machine), /beneath its root/);
	assert.throws(() => activateProjectPolicy({
		version: 1,
		rights: [],
		developmentCache: { environment: { CARGO_HOME: "replacement" } },
	}, cwd, machine), /cannot replace managed (?:cache )?mapping CARGO_HOME/);
});

test("symlinked project policy directories cannot supply or receive policy", () => {
	const guardianLink = workspace();
	const guardianTarget = workspace();
	symlinkSync(guardianTarget, join(guardianLink, ".guardian"));
	assert.throws(() => loadProjectPolicy(guardianLink, machine), /symlinked project control folder/);
	assert.throws(() => saveProjectPolicy(guardianLink, basePolicy()), /symlinked project control folder/);

	const projectRootLink = workspace();
	const target = workspace();
	symlinkSync(target, join(projectRootLink, ".pi"));
	assert.throws(() => loadProjectPolicy(projectRootLink, machine), /symlinked project control folder/);
	assert.throws(() => saveProjectPolicy(projectRootLink, basePolicy()), /symlinked project control folder/);

	const extensionsLink = workspace();
	mkdirSync(join(extensionsLink, ".pi"));
	symlinkSync(target, join(extensionsLink, ".pi", "extensions"));
	assert.throws(() => loadProjectPolicy(extensionsLink, machine), /symlinked project control folder/);
	assert.throws(() => saveProjectPolicy(extensionsLink, basePolicy()), /symlinked project control folder/);

	const sandboxLink = workspace();
	mkdirSync(join(sandboxLink, ".pi", "extensions"), { recursive: true });
	symlinkSync(target, join(sandboxLink, ".pi", "extensions", "sandbox"));
	assert.throws(() => loadProjectPolicy(sandboxLink, machine), /symlinked project control folder/);
	assert.throws(() => saveProjectPolicy(sandboxLink, basePolicy()), /symlinked project control folder/);
});

test("request paths are converted to portable forms while external absolutes are session-only", () => {
	const cwd = workspace();
	const external = workspace();
	const active = addProjectRights(basePolicy(), [
		{ kind: "filesystem", access: "write", path: join(cwd, "state"), scope: "tree" },
		{ kind: "filesystem", access: "write", path: join(homedir(), "shared.txt"), scope: "file" },
	], cwd, machine);
	assert(active.policy.rights.some((right) => right.kind === "filesystem" && right.path === "state"));
	assert(active.policy.rights.some((right) => right.kind === "filesystem" && right.path === "~/shared.txt"));
	const session = addSessionAccess(basePolicy(), [{
		kind: "filesystem", access: "read", path: external, scope: "tree",
	}], cwd, machine);
	assert(session.policy.rights.some((right) => right.kind === "filesystem" && right.path === external));
	assert(session.filesystem.some((right) => right.path === external && right.directory));
	assert.throws(() => addProjectRights(basePolicy(), [{
		kind: "filesystem", access: "read", path: external, scope: "tree",
	}], cwd, machine), /must be inside the project or home/);
	assert.throws(() => activateProjectPolicy({
		version: 1,
		rights: [{ kind: "filesystem", access: "write", path: join(cwd, "state"), scope: "tree" }],
	}, cwd, machine), /Checked-in filesystem paths must be project-relative/);
	assert.throws(() => activateProjectPolicy({
		version: 1,
		rights: [{ kind: "filesystem", access: "read", path: "~/../outside", scope: "file" }],
	}, cwd, machine), /cannot escape the home directory/);
});

test("filesystem grants reject symlinks and are invalid after missing-path symlink retarget", () => {
	const cwd = workspace();
	const target = workspace();
	mkdirSync(join(cwd, "linked-parent"));
	symlinkSync(target, join(cwd, "linked-parent", "link"));
	assert.throws(() => addProjectRights(basePolicy(), [{
		kind: "filesystem", access: "write", path: "linked-parent/link/state", scope: "tree",
	}], cwd, machine), /cannot cross an existing symlink/);

	const approved = addProjectRights(basePolicy(), [{
		kind: "filesystem", access: "write", path: "later-link", scope: "tree",
	}], cwd, machine);
	symlinkSync(target, join(cwd, "later-link"));
	assert.throws(() => activateProjectPolicy(approved.policy, cwd, machine), /cannot cross an existing symlink/);
});

test("project and session policies compose without widening or replacing cache mappings", () => {
	const project: ProjectSandboxPolicy = {
		version: 1,
		rights: [{ kind: "network_host", host: "project.example.com" }],
		developmentCache: { environment: { PROJECT_CACHE: "project" } },
	};
	const session: ProjectSandboxPolicy = {
		version: 1,
		rights: [{ kind: "network_endpoint", host: "localhost", port: 4321 }],
		developmentCache: { environment: { SESSION_CACHE: "session" } },
	};
	const merged = mergeAccessPolicies(project, session);
	assert.equal(merged.rights.length, 2);
	assert.deepEqual(merged.developmentCache?.environment, {
		PROJECT_CACHE: "project",
		SESSION_CACHE: "session",
	});
	assert.deepEqual(accessPolicyAdditions(project, merged), session);
	assert.throws(() => mergeAccessPolicies(project, {
		version: 1,
		rights: [],
		developmentCache: { environment: { PROJECT_CACHE: "replacement" } },
	}), /conflicting development-cache mapping PROJECT_CACHE/);
});

test("request batches check only net-new sibling files and support cache adapters", () => {
	const cwd = workspace();
	assert.throws(() => activateProjectPolicy({
		version: 1,
		rights: Array.from({ length: 65 }, (_, index) => ({
			kind: "filesystem" as const,
			access: "write" as const,
			path: `many/tree-${index}`,
			scope: "tree" as const,
		})),
	}, cwd, machine), /at most 64 filesystem rights/);
	assert.throws(() => addProjectRights(basePolicy(), ["a", "b", "c", "d"].map((path) => ({
		kind: "filesystem" as const,
		access: "write" as const,
		path: `state/${path}`,
		scope: "file" as const,
	})), cwd, machine), /request one tree right/);
	const historical: ProjectSandboxPolicy = {
		version: 1,
		rights: ["a", "b", "c", "d"].map((path) => ({
			kind: "filesystem" as const,
			access: "write" as const,
			path: `history/${path}`,
			scope: "file" as const,
		})),
	};
	const active = addProjectAccess(historical, [
		{ kind: "network_host", host: "example.com" },
		{ kind: "development_cache", environment: { CUSTOM_BUILD_CACHE: "custom/build" } },
	], cwd, machine);
	assert.equal(active.networkHosts[0], "example.com");
	assert.equal(active.policy.developmentCache?.environment.CUSTOM_BUILD_CACHE, "custom/build");
	assert.throws(() => addProjectAccess(basePolicy(), [{
		kind: "development_cache", environment: { CARGO_HOME: "replacement" },
	}], cwd, machine), /cannot replace managed (?:cache )?mapping CARGO_HOME/);
	const diff = projectPolicyDiff(historical, active.policy, cwd);
	assert.match(diff, /^Project policy additions:/);
	assert.match(diff, /network host       "example\.com"/);
	assert.match(diff, /cache   CUSTOM_BUILD_CACHE  "custom\/build"/);
	assert.doesNotMatch(diff, /```json|^\+ /m);
	assert.doesNotMatch(diff, /history\/a/);
});

test("approval summaries render validated rights once as a compact list", () => {
	const summary = sandboxPolicySummary({
		version: 1,
		rights: [
			{ kind: "filesystem", access: "read", path: "docs", scope: "tree" },
			{ kind: "filesystem", access: "write", path: "result.txt", scope: "file" },
			{ kind: "network_host", host: "example.com" },
			{ kind: "network_endpoint", host: "localhost", port: 3000 },
		],
		developmentCache: { environment: { CARGO_HOME: "cargo" } },
	});
	assert.equal(summary, [
		"Requested sandbox rights:",
		"  read    directory  \"docs\"",
		"  write   file       \"result.txt\"",
		"  network host       \"example.com\"",
		"  network endpoint   \"localhost:3000\"",
		"  cache   CARGO_HOME  \"cargo\"",
	].join("\n"));
	assert.equal(summary.match(/Requested sandbox rights:/g)?.length, 1);
});

test("a fresh project snapshot treats another agent's approved rights as existing", () => {
	const cwd = workspace();
	const firstAgent = loadProjectPolicy(cwd, machine);
	assert.deepEqual(firstAgent.policy, basePolicy());
	mkdirSync(join(homedir(), "shared"));

	saveProjectPolicy(cwd, {
		version: 1,
		rights: [{ kind: "filesystem", access: "read", path: "~/shared", scope: "tree" }],
	});
	const synchronized = loadProjectPolicyForUpdate(cwd, machine);
	const candidate = addProjectAccess(synchronized.policy, [
		{ kind: "filesystem", access: "write", path: ".git", scope: "tree" },
	], cwd, machine);
	const diff = projectPolicyDiff(synchronized.policy, candidate.policy, cwd);

	assert.match(diff, /write   directory  "\.git"/);
	assert.doesNotMatch(diff, /~\/shared/);
	assert.equal(sameProjectPolicy(
		{ ...synchronized.policy, developmentCache: { environment: {} } },
		synchronized.policy,
	), true);
});

test("policy updates reload pre-approval edits but reject edits made during approval", () => {
	const cwd = workspace();
	const initial = saveProjectPolicy(cwd, basePolicy());
	const changed = {
		version: 1 as const,
		rights: [{ kind: "network_endpoint" as const, host: "localhost" as const, port: 3000 }],
	};
	const changedSource = saveProjectPolicy(cwd, changed);
	const current = loadProjectPolicyForUpdate(cwd, machine);
	assert.equal(current.sourceText, changedSource);
	assert.deepEqual(current.policy, changed);
	writeFileSync(projectPolicyPath(cwd), `${changedSource}\n`);
	assert.throws(
		() => saveProjectPolicy(cwd, changed, current.sourceText),
		/changed while request_access was awaiting approval/,
	);
	assert.equal(readFileSync(projectPolicyPath(cwd), "utf8"), `${changedSource}\n`);
	assert.notEqual(initial, changedSource);
});
