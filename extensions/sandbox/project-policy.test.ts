import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { buildSandboxExecRequest } from "./sandbox-policy.ts";
import { DEFAULT_CONFIG, mergeGlobalConfig, normalizeConfig } from "./sandbox-config.ts";
import {
	accessPolicyAdditions,
	activateProjectPolicy,
	addProjectAccess,
	addSessionAccess,
	loadProjectPolicy,
	loadProjectPolicyForUpdate,
	mergeAccessPolicies,
	projectPolicyPath,
	sameProjectPolicy,
	sandboxPolicySummary,
	saveProjectPolicy,
	type ProjectSandboxPolicy,
} from "./project-policy.ts";

function workspace(): string {
	return mkdtempSync(join(tmpdir(), "pi-project-policy-"));
}

const basePolicy = (): ProjectSandboxPolicy => ({ version: 1, rights: [] });
const machine = mergeGlobalConfig(DEFAULT_CONFIG, {});

test("project grants are host-owned and bound to the workspace identity", () => {
	const cwd = workspace();
	const state = join(cwd, "state");
	mkdirSync(state);
	const policy: ProjectSandboxPolicy = {
		version: 1,
		rights: [
			{ kind: "filesystem", access: "write", path: "state", scope: "tree" },
			{ kind: "network_host", host: "API.Example.COM." },
		],
	};
	const source = saveProjectPolicy(cwd, policy);
	const path = projectPolicyPath(cwd);
	assert(path.startsWith(join(homedir(), ".config", "pi-nono", "projects")));
	assert.equal(readFileSync(path, "utf8"), source);
	assert.match(source, /"device"/);
	assert.match(source, /"policy"/);

	const loaded = loadProjectPolicy(cwd, machine);
	assert.deepEqual(loaded.inactive, []);
	assert.equal(loaded.networkHosts[0], "api.example.com");
	assert(loaded.filesystem.some((right) => right.path === state && right.directory));
});

test("activates exact endpoints, hosts, files, and existing trees", () => {
	const cwd = workspace();
	writeFileSync(join(cwd, "input.txt"), "input");
	mkdirSync(join(cwd, "output"));
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
	assert.equal(active.filesystem.length, 2);
	assert.throws(() => activateProjectPolicy({
		version: 1,
		rights: [{ kind: "filesystem", access: "write", path: "missing", scope: "tree" }],
	}, cwd, machine), /approve an existing parent/);
});

test("broad grants retain nested machine denies", () => {
	const cwd = workspace();
	const active = activateProjectPolicy({
		version: 1,
		rights: [{ kind: "filesystem", access: "read", path: "~", scope: "tree" }],
	}, cwd, machine);
	const request = buildSandboxExecRequest(
		"broad-read", "true", cwd, undefined, active.config, active.filesystem, [], [], process.env,
	);
	assert(request.policy.grants.some((right) => right.path === homedir() && right.scope === "tree"));
	assert(request.policy.denies.some((deny) => deny.pattern === join(homedir(), ".ssh")));
	assert(request.policy.denies.some((deny) => deny.pattern === `${cwd}/**/.env`));

	const homeWrite = activateProjectPolicy({
		version: 1,
		rights: [{ kind: "filesystem", access: "write", path: "~", scope: "tree" }],
	}, cwd, machine);
	assert(homeWrite.filesystem.some((right) => right.path === homedir() && right.directory));

	mkdirSync(join(cwd, "blocked"));
	const fixedDenyConfig = { filesystem: { denyWrite: ["blocked"] } };
	const broadWrite = activateProjectPolicy({
		version: 1,
		rights: [{ kind: "filesystem", access: "write", path: ".", scope: "tree" }],
	}, cwd, fixedDenyConfig);
	const writeRequest = buildSandboxExecRequest(
		"broad-write", "true", cwd, undefined, fixedDenyConfig, broadWrite.filesystem, [], [], process.env,
	);
	assert(writeRequest.policy.denies.some((deny) => deny.pattern === join(cwd, "blocked")));
});

test("machine denies and protected control paths take precedence", () => {
	const cwd = workspace();
	mkdirSync(join(cwd, "blocked"));
	mkdirSync(join(cwd, ".pi"));
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
	assert.throws(() => activateProjectPolicy({
		version: 1,
		rights: [{ kind: "filesystem", access: "write", path: ".pi", scope: "tree" }],
	}, cwd, machine), /project \.pi/);
	assert.throws(() => activateProjectPolicy({
		version: 1,
		rights: [{ kind: "filesystem", access: "read", path: "~/.config/pi-nono", scope: "tree" }],
	}, cwd, machine), /protected or machine-denied/);
});

test("stored grants activate independently and stale paths become inactive", () => {
	const cwd = workspace();
	const stale = join(cwd, "stale");
	mkdirSync(stale);
	saveProjectPolicy(cwd, {
		version: 1,
		rights: [
			{ kind: "filesystem", access: "read", path: "stale", scope: "tree" },
			{ kind: "network_host", host: "example.com" },
		],
	});
	rmSync(stale, { recursive: true });
	const loaded = loadProjectPolicy(cwd, machine);
	assert.deepEqual(loaded.networkHosts, ["example.com"]);
	assert.equal(loaded.filesystem.length, 0);
	assert(loaded.inactive.some((entry) => /stale/.test(entry)));
});

test("malformed stored entries grant nothing without disabling valid siblings", () => {
	const cwd = workspace();
	saveProjectPolicy(cwd, { version: 1, rights: [{ kind: "network_host", host: "example.com" }] });
	const path = projectPolicyPath(cwd);
	const record = JSON.parse(readFileSync(path, "utf8"));
	record.policy.rights.push({ kind: "filesystem", access: "write", path: "x", scope: "invalid" });
	record.policy.obsoleteField = true;
	writeFileSync(path, `${JSON.stringify(record, null, 2)}\n`);
	const loaded = loadProjectPolicy(cwd, machine);
	assert.deepEqual(loaded.networkHosts, ["example.com"]);
	assert(loaded.inactive.some((entry) => /right 2/.test(entry)));
	assert(loaded.inactive.some((entry) => /obsoleteField/.test(entry)));
});

test("an approved update can repair a corrupt optional project-grants file", () => {
	const cwd = workspace();
	saveProjectPolicy(cwd, basePolicy());
	const path = projectPolicyPath(cwd);
	writeFileSync(path, "{broken\n");
	const loaded = loadProjectPolicyForUpdate(cwd, machine);
	assert.equal(loaded.sourceText, "{broken\n");
	assert(loaded.inactive.some((entry) => /Project grants ignored/.test(entry)));
	const repaired = saveProjectPolicy(cwd, basePolicy(), loaded.sourceText);
	assert.equal(readFileSync(path, "utf8"), repaired);
});

test("filesystem grants reject symlinks and type changes", () => {
	const cwd = workspace();
	const target = "/etc";
	mkdirSync(join(cwd, "linked-parent"));
	symlinkSync(target, join(cwd, "linked-parent", "link"));
	assert.throws(() => addProjectAccess(basePolicy(), [{
		kind: "filesystem", access: "write", path: "linked-parent/link", scope: "tree",
	}], cwd, machine), /cannot cross an existing symlink/);

	const changing = join(cwd, "changing");
	mkdirSync(changing);
	saveProjectPolicy(cwd, {
		version: 1,
		rights: [{ kind: "filesystem", access: "read", path: "changing", scope: "tree" }],
	});
	rmSync(changing, { recursive: true });
	writeFileSync(changing, "file");
	const loaded = loadProjectPolicy(cwd, machine);
	assert.equal(loaded.filesystem.length, 0);
	assert(loaded.inactive.some((entry) => /scope does not match/.test(entry)));
});

test("project and session rights compose without widening", () => {
	const project: ProjectSandboxPolicy = {
		version: 1,
		rights: [{ kind: "network_host", host: "project.example.com" }],
	};
	const session: ProjectSandboxPolicy = {
		version: 1,
		rights: [{ kind: "network_endpoint", host: "localhost", port: 4321 }],
	};
	const merged = mergeAccessPolicies(project, session);
	assert.equal(merged.rights.length, 2);
	assert.deepEqual(accessPolicyAdditions(project, merged), session);
	assert.equal(sameProjectPolicy(merged, mergeAccessPolicies(session, project)), true);
});

test("request paths become portable while external absolutes remain session-only", () => {
	const cwd = workspace();
	mkdirSync(join(cwd, ".git"));
	const active = addProjectAccess(basePolicy(), [{
		kind: "filesystem", access: "write", path: join(cwd, ".git"), scope: "tree",
	}], cwd, machine);
	assert(active.policy.rights.some(
		(right) => right.kind === "filesystem" && right.path === ".git"));

	const external = "/etc";
	const session = addSessionAccess(basePolicy(), [{
		kind: "filesystem", access: "write", path: external, scope: "tree",
	}], cwd, machine);
	assert(session.filesystem.some((right) => right.path === external));
	assert.throws(() => addProjectAccess(basePolicy(), [{
		kind: "filesystem", access: "write", path: external, scope: "tree",
	}], cwd, machine), /must be inside the project or home/);
});

test("access modes avoid redundant or ineffective grants", () => {
	const cwd = workspace();
	writeFileSync(join(cwd, "input.txt"), "input");
	const defaults = addProjectAccess(basePolicy(), [
		{ kind: "filesystem", access: "read", path: "input.txt", scope: "file" },
		{ kind: "filesystem", access: "write", path: ".", scope: "tree" },
		{ kind: "network_host", host: "registry.npmjs.org" },
	], cwd, machine);
	assert.deepEqual(defaults.policy.rights, []);

	const readOnly = mergeGlobalConfig(machine, { filesystem: { mode: "read-only" } });
	assert.throws(() => addProjectAccess(basePolicy(), [{
		kind: "filesystem", access: "write", path: ".", scope: "tree",
	}], cwd, readOnly), /Read-only/);

	const full = mergeGlobalConfig(machine, {
		filesystem: { mode: "full" },
		network: { mode: "full" },
	});
	const external = "/etc";
	const unrestricted = addSessionAccess(basePolicy(), [
		{ kind: "filesystem", access: "write", path: external, scope: "tree" },
		{ kind: "network_host", host: "example.com" },
	], cwd, full);
	assert.deepEqual(unrestricted.policy.rights, []);
});

test("approval summaries and diffs contain only validated net-new rights", () => {
	const before: ProjectSandboxPolicy = { version: 1, rights: [] };
	const after: ProjectSandboxPolicy = {
		version: 1,
		rights: [
			{ kind: "filesystem", access: "read", path: "docs", scope: "tree" },
			{ kind: "network_host", host: "example.com" },
		],
	};
	assert.equal(sandboxPolicySummary(after), [
		"Requested sandbox rights:",
		"  read    directory  \"docs\"",
		"  network host       \"example.com\"",
	].join("\n"));
});

test("policy updates reject edits made during approval", () => {
	const cwd = workspace();
	const initial = saveProjectPolicy(cwd, basePolicy());
	const changed: ProjectSandboxPolicy = {
		version: 1,
		rights: [{ kind: "network_endpoint", host: "localhost", port: 3000 }],
	};
	const changedSource = saveProjectPolicy(cwd, changed, initial);
	const current = loadProjectPolicyForUpdate(cwd, machine);
	assert.equal(current.sourceText, changedSource);
	writeFileSync(projectPolicyPath(cwd), `${changedSource}\n`);
	assert.throws(
		() => saveProjectPolicy(cwd, changed, current.sourceText),
		/changed while request_access was awaiting approval/,
	);
});

test("host project-rights storage rejects symlinked control directories", () => {
	const cwd = workspace();
	const path = projectPolicyPath(cwd);
	const root = dirname(dirname(path));
	const target = workspace();
	mkdirSync(dirname(root), { recursive: true });
	if (existsSync(root)) rmSync(root, { recursive: true });
	symlinkSync(target, root);
	assert.throws(() => saveProjectPolicy(cwd, basePolicy()), /symlinked pi-nono config directory/);
});
