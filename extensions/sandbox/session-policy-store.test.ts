import assert from "node:assert/strict";
import {
	mkdirSync,
	mkdtempSync,
	readFileSync,
	rmSync,
	statSync,
	symlinkSync,
	unlinkSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { DEFAULT_CONFIG, mergeGlobalConfig } from "./sandbox-config.ts";
import {
	loadSessionPolicy,
	saveSessionPolicy,
	sessionPolicyPath,
	type SessionPolicyIdentity,
} from "./session-policy-store.ts";

const machine = mergeGlobalConfig(DEFAULT_CONFIG, {});

function fixture(): { cwd: string; root: string; identity: SessionPolicyIdentity } {
	const base = mkdtempSync(join(tmpdir(), "pi-session-policy-"));
	const cwd = join(base, "workspace");
	const root = join(base, "config", "guardian");
	const sessionFile = join(base, "session.jsonl");
	mkdirSync(cwd);
	writeFileSync(sessionFile, `${JSON.stringify({ type: "session", version: 3, id: "session-one", cwd })}\n`);
	return { cwd, root, identity: { sessionId: "session-one", sessionFile, cwd } };
}

test("session rights persist in a user-local sidecar bound to exact Pi session identity", () => {
	const { cwd, root, identity } = fixture();
	const external = join(cwd, "..", "mounted-assets");
	mkdirSync(external);
	const initial = loadSessionPolicy(identity, machine, root);
	assert.deepEqual(initial.policy, { version: 1, rights: [] });
	const source = saveSessionPolicy(identity, {
		version: 1,
		rights: [
			{ kind: "filesystem", access: "write", path: "state", scope: "tree" },
			{ kind: "filesystem", access: "read", path: external, scope: "tree" },
			{ kind: "network_host", host: "API.Example.COM." },
		],
	}, initial.sourceText, root);
	const path = sessionPolicyPath(identity, root);
	assert.equal(readFileSync(path, "utf8"), source);
	assert.equal(statSync(path).mode & 0o777, 0o600);
	assert.equal(statSync(join(root, "session-rights")).mode & 0o777, 0o700);
	assert.doesNotMatch(path, /session-one/);
	const restored = loadSessionPolicy(identity, machine, root);
	assert.equal(restored.networkHosts[0], "api.example.com");
	assert(restored.filesystem.some((right) => right.path === join(cwd, "state")));
	assert(restored.filesystem.some((right) => right.path === external && right.directory));

	assert.throws(
		() => loadSessionPolicy({ ...identity, cwd: join(cwd, "other") }, machine, root),
		/working directory|identity does not match/,
	);
	const copiedFile = join(cwd, "other.jsonl");
	writeFileSync(copiedFile, readFileSync(identity.sessionFile));
	assert.throws(
		() => loadSessionPolicy({ ...identity, sessionFile: copiedFile }, machine, root),
		/identity does not match/,
	);
});

test("a session without durable rights does not require an existing Pi session file", () => {
	const cwd = mkdtempSync(join(tmpdir(), "pi-session-policy-cwd-"));
	const root = mkdtempSync(join(tmpdir(), "pi-session-policy-root-"));
	const identity = {
		sessionId: "new-session",
		sessionFile: join(cwd, "not-created-yet.jsonl"),
		cwd,
	};
	const active = loadSessionPolicy(identity, machine, root);
	assert.deepEqual(active.policy, { version: 1, rights: [] });
	assert.equal(active.sourceText, null);
});

test("existing durable rights still require a valid Pi session file", () => {
	const { root, identity } = fixture();
	saveSessionPolicy(identity, { version: 1, rights: [] }, null, root);
	unlinkSync(identity.sessionFile);
	assert.throws(
		() => loadSessionPolicy(identity, machine, root),
		/regular non-symlink Pi session file/,
	);
});

test("session policy writes reject stale snapshots and symlinked control paths", () => {
	const { root, identity } = fixture();
	const source = saveSessionPolicy(identity, { version: 1, rights: [] }, null, root);
	assert.throws(
		() => saveSessionPolicy(identity, {
			version: 1,
			rights: [{ kind: "network_endpoint", host: "localhost", port: 43127 }],
		}, null, root),
		/changed while request_access was awaiting approval/,
	);
	assert.equal(loadSessionPolicy(identity, machine, root).sourceText, source);

	const linked = fixture();
	const target = mkdtempSync(join(tmpdir(), "pi-session-policy-target-"));
	mkdirSync(join(linked.root, "session-rights"), { recursive: true });
	const rightsRoot = join(linked.root, "session-rights");
	rmSync(rightsRoot, { recursive: true });
	symlinkSync(target, rightsRoot);
	assert.throws(() => loadSessionPolicy(linked.identity, machine, linked.root), /symlinked pi-nono config directory/);
});

test("session files themselves cannot be forged or symlink aliases", () => {
	const { cwd, root, identity } = fixture();
	writeFileSync(identity.sessionFile, `${JSON.stringify({ type: "session", version: 3, id: "different", cwd })}\n`);
	assert.throws(
		() => saveSessionPolicy(identity, { version: 1, rights: [] }, null, root),
		/header does not match the active session ID/,
	);
	writeFileSync(identity.sessionFile, `${JSON.stringify({ type: "session", version: 3, id: identity.sessionId, cwd })}\n`);
	const alias = join(cwd, "session-link.jsonl");
	symlinkSync(identity.sessionFile, alias);
	assert.throws(
		() => saveSessionPolicy({ ...identity, sessionFile: alias }, { version: 1, rights: [] }, null, root),
		/regular non-symlink Pi session file/,
	);
});
