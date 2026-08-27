import { randomUUID } from "node:crypto";
import {
	lstatSync,
	mkdirSync,
	readFileSync,
	renameSync,
	unlinkSync,
	writeFileSync,
} from "node:fs";
import { homedir } from "node:os";
import { resolve } from "node:path";

export function piNonoConfigRoot(): string {
	return resolve(homedir(), ".config", "pi-nono");
}

export function assertSafePolicyStorage(
	configRoot: string,
	directoryName: string,
	label: string,
	create: boolean,
): void {
	const root = resolve(configRoot);
	const directory = resolve(root, directoryName);
	for (const path of [root, directory]) {
		const metadata = lstatIfExists(path);
		if (metadata?.isSymbolicLink()) {
			throw new Error(`A symlinked pi-nono config directory cannot hold ${label}: ${path}`);
		}
		if (metadata && !metadata.isDirectory()) {
			throw new Error(`pi-nono ${label} path must be a directory: ${path}`);
		}
	}
	if (!create) return;
	mkdirSync(directory, { recursive: true, mode: 0o700 });
	for (const path of [root, directory]) {
		const metadata = lstatSync(path);
		if (metadata.isSymbolicLink() || !metadata.isDirectory()) {
			throw new Error(`pi-nono ${label} path is unsafe: ${path}`);
		}
	}
}

export function readPolicySource(path: string, label: string): string | null {
	const metadata = lstatIfExists(path);
	if (!metadata) return null;
	if (metadata.isSymbolicLink() || !metadata.isFile()) {
		throw new Error(`${label} must be a regular non-symlink file: ${path}`);
	}
	return readFileSync(path, "utf8");
}

export function replacePolicySource(
	path: string,
	sourceText: string,
	expectedSourceText: string | null | undefined,
	ensureStorage: (create: boolean) => void,
	changedMessage: string,
): void {
	ensureStorage(true);
	if (expectedSourceText !== undefined && readPolicySource(path, "Sandbox policy") !== expectedSourceText) {
		throw new Error(changedMessage);
	}
	const temporary = `${path}.${process.pid}.${randomUUID()}.tmp`;
	writeFileSync(temporary, sourceText, { mode: 0o600, flag: "wx" });
	try {
		ensureStorage(false);
		if (expectedSourceText !== undefined && readPolicySource(path, "Sandbox policy") !== expectedSourceText) {
			throw new Error(changedMessage);
		}
		renameSync(temporary, path);
	} catch (error) {
		try { unlinkSync(temporary); } catch { /* Preserve the policy error. */ }
		throw error;
	}
}

export function lstatIfExists(path: string): ReturnType<typeof lstatSync> | undefined {
	try {
		return lstatSync(path);
	} catch (error) {
		if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") {
			return undefined;
		}
		throw error;
	}
}
