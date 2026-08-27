import { createHash } from "node:crypto";
import { realpathSync, statSync } from "node:fs";
import { resolve } from "node:path";
import {
	assertSafePolicyStorage,
	lstatIfExists,
	piNonoConfigRoot,
	readPolicySource,
	replacePolicySource,
} from "./policy-storage.ts";

interface WorkspaceIdentity {
	cwd: string;
	device: string;
	inode: string;
}

interface ProjectPolicyRecord extends WorkspaceIdentity {
	version: 1;
	policy: unknown;
}

export interface ProjectPolicySource {
	sourceText: string;
	policy: unknown;
	error?: string;
}

export function projectPolicyPath(cwd: string, configRoot = piNonoConfigRoot()): string {
	return projectPolicyPathForIdentity(workspaceIdentity(cwd), configRoot);
}

export function readProjectPolicySource(
	cwd: string,
	configRoot = piNonoConfigRoot(),
): ProjectPolicySource | null {
	const identity = workspaceIdentity(cwd);
	assertSafePolicyStorage(configRoot, "projects", "project rights", false);
	const path = projectPolicyPathForIdentity(identity, configRoot);
	const sourceText = readPolicySource(path, "Project sandbox policy");
	if (sourceText === null) return null;
	try {
		const record = normalizeRecord(JSON.parse(sourceText));
		if (!sameIdentity(record, identity)) {
			throw new Error("Project sandbox policy identity does not match the active workspace");
		}
		return { sourceText, policy: record.policy };
	} catch (error) {
		return { sourceText, policy: null, error: errorMessage(error) };
	}
}

/** Writes trusted host policy bytes only if the exact approved source is current. */
export function writeProjectPolicySource(
	cwd: string,
	policy: unknown,
	expectedSourceText?: string | null,
	configRoot = piNonoConfigRoot(),
): string {
	const identity = workspaceIdentity(cwd);
	const path = projectPolicyPathForIdentity(identity, configRoot);
	const sourceText = `${JSON.stringify({ version: 1, ...identity, policy }, null, 2)}\n`;
	replacePolicySource(
		path,
		sourceText,
		expectedSourceText,
		(create) => assertSafePolicyStorage(configRoot, "projects", "project rights", create),
		"Project sandbox policy changed while request_access was awaiting approval",
	);
	return sourceText;
}

function projectPolicyPathForIdentity(identity: WorkspaceIdentity, configRoot: string): string {
	const key = createHash("sha256").update(identity.cwd).digest("hex");
	return resolve(configRoot, "projects", `${key}.json`);
}

function workspaceIdentity(cwd: string): WorkspaceIdentity {
	const lexical = resolve(cwd);
	const metadata = lstatIfExists(lexical);
	if (!metadata) throw new Error("Project sandbox rights require an existing workspace directory");
	const actual = realpathSync.native(lexical);
	const stat = statSync(actual, { bigint: true });
	if (!stat.isDirectory()) throw new Error("Project sandbox rights require a workspace directory");
	return { cwd: actual, device: stat.dev.toString(), inode: stat.ino.toString() };
}

function normalizeRecord(value: unknown): ProjectPolicyRecord {
	if (!value || typeof value !== "object" || Array.isArray(value)) {
		throw new Error("project sandbox policy record must be a JSON object");
	}
	const input = value as Record<string, unknown>;
	assertKnownKeys(input, ["version", "cwd", "device", "inode", "policy"]);
	if (input.version !== 1) throw new Error("project sandbox policy record version must be 1");
	if (
		typeof input.cwd !== "string" ||
		typeof input.device !== "string" ||
		typeof input.inode !== "string"
	) {
		throw new Error("project sandbox policy workspace identity is invalid");
	}
	return {
		version: 1,
		cwd: resolve(input.cwd),
		device: input.device,
		inode: input.inode,
		policy: input.policy,
	};
}

function sameIdentity(left: WorkspaceIdentity, right: WorkspaceIdentity): boolean {
	return left.cwd === right.cwd && left.device === right.device && left.inode === right.inode;
}

function errorMessage(error: unknown): string {
	return error instanceof Error ? error.message : String(error);
}

function assertKnownKeys(value: Record<string, unknown>, allowed: readonly string[]): void {
	const unknown = Object.keys(value).filter((key) => !allowed.includes(key));
	if (unknown.length > 0) {
		throw new Error(`project sandbox policy record contains unknown fields: ${unknown.join(", ")}`);
	}
}
