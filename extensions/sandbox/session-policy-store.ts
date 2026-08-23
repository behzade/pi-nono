import { createHash, randomUUID } from "node:crypto";
import {
	closeSync,
	lstatSync,
	mkdirSync,
	openSync,
	readFileSync,
	readSync,
	realpathSync,
	renameSync,
	unlinkSync,
	writeFileSync,
} from "node:fs";
import { homedir } from "node:os";
import { resolve } from "node:path";
import type { NativeSandboxConfig } from "./sandbox-config.ts";
import { canonicalize } from "./io-permissions.ts";
import {
	activateSessionPolicy,
	EMPTY_PROJECT_POLICY,
	normalizeSessionPolicy,
	type ActiveProjectPolicy,
	type ProjectSandboxPolicy,
} from "./project-policy.ts";

export interface SessionPolicyIdentity {
	sessionId: string;
	sessionFile: string;
	cwd: string;
}

interface SessionPolicyRecord {
	version: 1;
	sessionId: string;
	sessionFile: string;
	cwd: string;
	policy: ProjectSandboxPolicy;
}

export function guardianConfigRoot(): string {
	return resolve(homedir(), ".config", "guardian");
}

export function sessionPolicyPath(
	identity: SessionPolicyIdentity,
	configRoot = guardianConfigRoot(),
): string {
	const key = createHash("sha256").update(identity.sessionId).digest("hex");
	return resolve(configRoot, "session-rights", `${key}.json`);
}

export function loadSessionPolicy(
	identity: SessionPolicyIdentity,
	globalConfig: NativeSandboxConfig,
	configRoot = guardianConfigRoot(),
): ActiveProjectPolicy {
	validateSessionId(identity.sessionId);
	assertSafeStorage(configRoot, false);
	const path = sessionPolicyPath(identity, configRoot);
	const sourceText = readPolicySource(path);
	if (sourceText === null) {
		return activateSessionPolicy(EMPTY_PROJECT_POLICY, identity.cwd, globalConfig);
	}
	const expected = validateSessionIdentity(identity);
	const record = normalizeRecord(JSON.parse(sourceText));
	if (
		record.sessionId !== expected.sessionId ||
		record.sessionFile !== expected.sessionFile ||
		record.cwd !== expected.cwd
	) {
		throw new Error("Session sandbox policy identity does not match the active Pi session");
	}
	return activateSessionPolicy(record.policy, expected.cwd, globalConfig, sourceText);
}

/** Trusted-host write after approval, conditional on the exact loaded bytes. */
export function saveSessionPolicy(
	identity: SessionPolicyIdentity,
	policy: ProjectSandboxPolicy,
	expectedSourceText: string | null,
	configRoot = guardianConfigRoot(),
): string {
	const expected = validateSessionIdentity(identity);
	assertSafeStorage(configRoot, true);
	const path = sessionPolicyPath(expected, configRoot);
	if (readPolicySource(path) !== expectedSourceText) {
		throw new Error("Session sandbox policy changed while request_access was awaiting approval");
	}
	const record: SessionPolicyRecord = {
		version: 1,
		...expected,
		policy: normalizeSessionPolicy(policy),
	};
	const sourceText = `${JSON.stringify(record, null, 2)}\n`;
	const temporary = `${path}.${process.pid}.${randomUUID()}.tmp`;
	writeFileSync(temporary, sourceText, { mode: 0o600, flag: "wx" });
	try {
		assertSafeStorage(configRoot, false);
		if (readPolicySource(path) !== expectedSourceText) {
			throw new Error("Session sandbox policy changed while request_access was awaiting approval");
		}
		renameSync(temporary, path);
	} catch (error) {
		tryUnlink(temporary);
		throw error;
	}
	return sourceText;
}

function validateSessionIdentity(identity: SessionPolicyIdentity): SessionPolicyIdentity {
	validateSessionId(identity.sessionId);
	const lexicalFile = resolve(identity.sessionFile);
	const metadata = lstatIfExists(lexicalFile);
	if (!metadata || metadata.isSymbolicLink() || !metadata.isFile()) {
		throw new Error("Durable session rights require a regular non-symlink Pi session file");
	}
	const sessionFile = realpathSync.native(lexicalFile);
	const cwd = canonicalize(identity.cwd);
	const header = readSessionHeader(sessionFile);
	if (header.type !== "session" || header.id !== identity.sessionId) {
		throw new Error("Pi session file header does not match the active session ID");
	}
	if (typeof header.cwd !== "string" || canonicalize(header.cwd) !== cwd) {
		throw new Error("Pi session file header does not match the active working directory");
	}
	return { sessionId: identity.sessionId, sessionFile, cwd };
}

function validateSessionId(sessionId: string): void {
	if (sessionId.length === 0 || sessionId.length > 256) {
		throw new Error("Pi session ID must be a non-empty string of at most 256 characters");
	}
}

function readSessionHeader(path: string): Record<string, unknown> {
	const handle = openSync(path, "r");
	try {
		const buffer = Buffer.alloc(65_536);
		const bytes = readSync(handle, buffer, 0, buffer.length, 0);
		const newline = buffer.subarray(0, bytes).indexOf(0x0a);
		if (newline < 0) throw new Error("Pi session header exceeds 65535 bytes or is incomplete");
		const parsed: unknown = JSON.parse(buffer.subarray(0, newline).toString("utf8"));
		if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
			throw new Error("Pi session header must be a JSON object");
		}
		return parsed as Record<string, unknown>;
	} finally {
		closeSync(handle);
	}
}

function normalizeRecord(value: unknown): SessionPolicyRecord {
	if (!value || typeof value !== "object" || Array.isArray(value)) {
		throw new Error("session sandbox policy must be a JSON object");
	}
	const input = value as Record<string, unknown>;
	assertKnownKeys(input, ["version", "sessionId", "sessionFile", "cwd", "policy"]);
	if (input.version !== 1) throw new Error("session sandbox policy version must be 1");
	if (typeof input.sessionId !== "string" || input.sessionId.length === 0 || input.sessionId.length > 256) {
		throw new Error("session sandbox policy sessionId must be a non-empty string of at most 256 characters");
	}
	if (typeof input.sessionFile !== "string" || typeof input.cwd !== "string") {
		throw new Error("session sandbox policy identity paths must be strings");
	}
	return {
		version: 1,
		sessionId: input.sessionId,
		sessionFile: resolve(input.sessionFile),
		cwd: resolve(input.cwd),
		policy: normalizeSessionPolicy(input.policy),
	};
}

function assertSafeStorage(configRoot: string, create: boolean): void {
	const root = resolve(configRoot);
	const rightsRoot = resolve(root, "session-rights");
	for (const directory of [root, rightsRoot]) {
		const metadata = lstatIfExists(directory);
		if (metadata?.isSymbolicLink()) {
			throw new Error(`A symlinked pi-nono config directory cannot hold session rights: ${directory}`);
		}
		if (metadata && !metadata.isDirectory()) {
			throw new Error(`pi-nono session-rights control path must be a directory: ${directory}`);
		}
	}
	if (!create) return;
	mkdirSync(rightsRoot, { recursive: true, mode: 0o700 });
	for (const directory of [root, rightsRoot]) {
		const metadata = lstatSync(directory);
		if (metadata.isSymbolicLink() || !metadata.isDirectory()) {
			throw new Error(`pi-nono session-rights control path is unsafe: ${directory}`);
		}
	}
}

function readPolicySource(path: string): string | null {
	const metadata = lstatIfExists(path);
	if (!metadata) return null;
	if (metadata.isSymbolicLink() || !metadata.isFile()) {
		throw new Error(`Session sandbox policy must be a regular non-symlink file: ${path}`);
	}
	return readFileSync(path, "utf8");
}

function lstatIfExists(path: string): ReturnType<typeof lstatSync> | undefined {
	try {
		return lstatSync(path);
	} catch (error) {
		if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") return undefined;
		throw error;
	}
}

function tryUnlink(path: string): void {
	try { unlinkSync(path); } catch { /* Preserve the policy error. */ }
}

function assertKnownKeys(value: Record<string, unknown>, allowed: readonly string[]): void {
	const unknown = Object.keys(value).filter((key) => !allowed.includes(key));
	if (unknown.length > 0) throw new Error(`session sandbox policy contains unknown fields: ${unknown.join(", ")}`);
}
