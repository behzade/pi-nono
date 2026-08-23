import { createHash } from "node:crypto";
import { accessSync, constants, lstatSync, readFileSync, realpathSync } from "node:fs";
import { createRequire } from "node:module";
import { delimiter, dirname, isAbsolute, join, relative } from "node:path";

const NATIVE_VERSION = "3.0.0";
const require = createRequire(import.meta.url);

interface NativePackage {
	name: string;
	nonoPath: string;
}

const NATIVE_PACKAGES: Record<string, NativePackage> = {
	"darwin:arm64": {
		name: "pi-guardian-darwin-arm64",
		nonoPath: "bin/nono",
	},
	"linux:x64": {
		name: "pi-guardian-linux-x64",
		nonoPath: "bin/nono",
	},
};

type ResolveManifest = (specifier: string) => string;

export interface PackagedExecutables {
	nonoPath: string;
	bwrapPath: string;
	packageName: string;
}

/** Resolves fixed nono from the platform package and Linux Bubblewrap from PATH. */
export function resolvePackagedExecutables(
	platform = process.platform,
	arch = process.arch,
	resolveManifest: ResolveManifest = (specifier) => require.resolve(specifier),
	pathValue = process.env.PATH,
): PackagedExecutables {
	const selected = NATIVE_PACKAGES[`${platform}:${arch}`];
	if (!selected) {
		throw new Error(`Guardian npm packages do not support ${platform}/${arch}`);
	}

	let manifestPath: string;
	try {
		manifestPath = realpathSync(resolveManifest(`${selected.name}/package.json`));
	} catch (error) {
		throw new Error(
			`Guardian native package ${selected.name}@${NATIVE_VERSION} is missing`,
			{ cause: error },
		);
	}
	const manifest = parseManifest(manifestPath);
	if (manifest.name !== selected.name || manifest.version !== NATIVE_VERSION) {
		throw new Error(
			`Guardian native package must be ${selected.name}@${NATIVE_VERSION}; found ${stringField(manifest.name)}@${stringField(manifest.version)}`,
		);
	}
	if (
		!arrayField(manifest.os).includes(platform) ||
		!arrayField(manifest.cpu).includes(arch) ||
		manifest.guardian?.nono?.path !== selected.nonoPath
	) {
		throw new Error(`Guardian native package ${selected.name} has invalid platform or executable metadata`);
	}
	const root = dirname(manifestPath);
	return {
		nonoPath: verifiedExecutable(root, selected.nonoPath, manifest.guardian?.nono?.sha256),
		bwrapPath: resolveSystemBubblewrap(platform, pathValue),
		packageName: selected.name,
	};
}

interface NativeManifest extends Record<string, unknown> {
	name?: unknown;
	version?: unknown;
	os?: unknown;
	cpu?: unknown;
	guardian?: {
		nono?: { path?: unknown; sha256?: unknown };
	};
}

function parseManifest(path: string): NativeManifest {
	try {
		const value: unknown = JSON.parse(readFileSync(path, "utf8"));
		if (!value || typeof value !== "object" || Array.isArray(value)) {
			throw new Error("manifest is not an object");
		}
		return value as NativeManifest;
	} catch (error) {
		throw new Error(`Guardian native package manifest is invalid: ${path}`, { cause: error });
	}
}

function verifiedExecutable(root: string, relativePath: string, expectedSha256: unknown): string {
	if (typeof expectedSha256 !== "string" || !/^[a-f0-9]{64}$/.test(expectedSha256)) {
		throw new Error(`Guardian native executable ${relativePath} has invalid checksum metadata`);
	}
	const lexicalPath = join(root, relativePath);
	const metadata = lstatSync(lexicalPath);
	if (!metadata.isFile() || metadata.isSymbolicLink() || (metadata.mode & 0o111) === 0) {
		throw new Error(`Guardian native executable must be a regular executable file: ${lexicalPath}`);
	}
	const path = realpathSync(lexicalPath);
	const fromRoot = relative(root, path);
	if (fromRoot === ".." || fromRoot.startsWith(`..${process.platform === "win32" ? "\\" : "/"}`) || isAbsolute(fromRoot)) {
		throw new Error(`Guardian native executable escapes its package: ${lexicalPath}`);
	}
	const actualSha256 = createHash("sha256").update(readFileSync(path)).digest("hex");
	if (actualSha256 !== expectedSha256) {
		throw new Error(`Guardian native executable checksum mismatch: ${lexicalPath}`);
	}
	return path;
}

export function resolveSystemBubblewrap(
	platform = process.platform,
	pathValue = process.env.PATH,
): string {
	if (platform !== "linux") return "";
	for (const directory of pathValue?.split(delimiter) ?? []) {
		if (!isAbsolute(directory)) continue;
		const candidate = join(directory, "bwrap");
		try {
			accessSync(candidate, constants.X_OK);
			const path = realpathSync(candidate);
			if (lstatSync(path).isFile()) return path;
		} catch {
			// Continue to the next PATH entry.
		}
	}
	throw new Error("Bubblewrap is required on Linux but was not found in PATH");
}

function arrayField(value: unknown): string[] {
	return Array.isArray(value) && value.every((entry) => typeof entry === "string") ? value : [];
}

function stringField(value: unknown): string {
	return typeof value === "string" ? value : "unknown";
}
