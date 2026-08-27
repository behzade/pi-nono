import { createHash } from "node:crypto";
import {
	closeSync,
	openSync,
	readSync,
	realpathSync,
} from "node:fs";
import { resolve } from "node:path";
import {
	assertSafePolicyStorage,
	lstatIfExists,
	piNonoConfigRoot,
	readPolicySource,
	replacePolicySource,
} from "./policy-storage.ts";
import type { NativeSandboxConfig } from "./sandbox-config.ts";
import { canonicalize } from "./io-permissions.ts";
import {
	activateSessionPolicy,
	activateStoredSessionPolicy,
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
	policy: unknown;
}

export function sessionPolicyPath(
	identity: SessionPolicyIdentity,
	configRoot = piNonoConfigRoot(),
): string {
	const key = createHash("sha256").update(identity.sessionId).digest("hex");
	return resolve(configRoot, "sessions", `${key}.json`);
}

export function loadSessionPolicy(
	identity: SessionPolicyIdentity,
	globalConfig: NativeSandboxConfig,
	configRoot = piNonoConfigRoot(),
): ActiveProjectPolicy {
	let sourceText: string | null = null;
	try {
		validateSessionId(identity.sessionId);
		assertSafePolicyStorage(configRoot, "sessions", "session rights", false);
		const path = sessionPolicyPath(identity, configRoot);
		sourceText = readPolicySource(path, "Session sandbox policy");
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
		return activateStoredSessionPolicy(record.policy, expected.cwd, globalConfig, sourceText);
	} catch (error) {
		const active = activateSessionPolicy(EMPTY_PROJECT_POLICY, identity.cwd, globalConfig, sourceText);
		active.inactive.push(`Session grants ignored: ${errorMessage(error)}`);
		return active;
	}
}

/** Trusted-host write after approval, conditional on the exact loaded bytes. */
export function saveSessionPolicy(
	identity: SessionPolicyIdentity,
	policy: ProjectSandboxPolicy,
	expectedSourceText: string | null,
	configRoot = piNonoConfigRoot(),
): string {
	const expected = validateSessionIdentity(identity);
	const path = sessionPolicyPath(expected, configRoot);
	const record: SessionPolicyRecord = {
		version: 1,
		...expected,
		policy: normalizeSessionPolicy(policy),
	};
	const sourceText = `${JSON.stringify(record, null, 2)}\n`;
	replacePolicySource(
		path,
		sourceText,
		expectedSourceText,
		(create) => assertSafePolicyStorage(configRoot, "sessions", "session rights", create),
		"Session sandbox policy changed while request_access was awaiting approval",
	);
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
		policy: input.policy,
	};
}

function errorMessage(error: unknown): string {
	return error instanceof Error ? error.message : String(error);
}

function assertKnownKeys(value: Record<string, unknown>, allowed: readonly string[]): void {
	const unknown = Object.keys(value).filter((key) => !allowed.includes(key));
	if (unknown.length > 0) throw new Error(`session sandbox policy contains unknown fields: ${unknown.join(", ")}`);
}
