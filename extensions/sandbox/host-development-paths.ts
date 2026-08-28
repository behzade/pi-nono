import { lstatSync, realpathSync } from "node:fs";
import { homedir } from "node:os";
import { resolve } from "node:path";

export interface HostDevelopmentPath {
	path: string;
	directory: boolean;
}

const READ_WRITE_PATHS = [
	".cache",
	".local/state",
	".config/jj",
	".bun/install/cache",
	".cargo/.package-cache",
	".cargo/.package-cache-mutate",
	".cargo/git",
	".cargo/registry",
	".gradle/caches",
	".gradle/wrapper/dists",
	".ivy2/cache",
	".local/share/pnpm/store",
	".m2/repository",
	".npm",
	".nuget/packages",
	".rustup/downloads",
	".rustup/tmp",
	".yarn/berry/cache",
	".yarn/berry/index",
	".yarn/berry/metadata",
	".yarn/berry/mirror",
	".yarn/berry/virtual",
	"go/pkg/mod",
	"Library/Caches",
	"Library/Logs",
	"Library/pnpm/store",
] as const;

/** Existing development storage reached without crossing a symlink. */
export function hostDevelopmentPaths(home = homedir()): HostDevelopmentPath[] {
	let root: string;
	try {
		root = realpathSync.native(home);
	} catch {
		return [];
	}
	return existingPaths(root, READ_WRITE_PATHS);
}

function existingPaths(root: string, entries: readonly string[]): HostDevelopmentPath[] {
	return entries.flatMap((entry) => {
		let path = root;
		let metadata: ReturnType<typeof lstatSync> | undefined;
		for (const part of entry.split("/")) {
			path = resolve(path, part);
			try {
				metadata = lstatSync(path);
			} catch {
				return [];
			}
			if (metadata.isSymbolicLink()) return [];
		}
		return metadata ? [{ path, directory: metadata.isDirectory() }] : [];
	});
}
