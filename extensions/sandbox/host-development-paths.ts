import { lstatSync, realpathSync } from "node:fs";
import { homedir } from "node:os";
import { resolve } from "node:path";

export interface HostDevelopmentPath {
	path: string;
	directory: boolean;
	writable: boolean;
}

const READ_ONLY_PATHS = [
	".bun/bin",
	".cargo/bin",
	".local/state/nix/profiles",
	".rustup/toolchains",
] as const;

const XDG_CACHE_NAMES = [
	".bun/install",
	"bazel",
	"bazel-repo-cache",
	"bazel-repo-contents-cache",
	"bluwy-giget",
	"buf",
	"bun",
	"ccache",
	"composer",
	"Cypress",
	"deno",
	"devbox",
	"fontconfig",
	"go-build",
	"gpui-libghostty",
	"ms-playwright",
	"nix",
	"node/corepack",
	"org.swift.swiftpm",
	"pip",
	"pipx",
	"pnpm",
	"pre-commit",
	"puppeteer",
	"pypoetry",
	"sccache",
	"selenium",
	"tree-sitter",
	"treefmt",
	"ty",
	"typescript",
	"uv",
	"vscode-ripgrep",
	"yarn",
	"yt-dlp",
	"zig",
] as const;

const MACOS_CACHE_NAMES = [
	"bazel",
	"CocoaPods",
	"com.apple.DeveloperTools",
	"Cypress",
	"deno",
	"dev.biomejs.biome",
	"engram/tree-sitter",
	"go",
	"go-build",
	"gpui-libghostty",
	"Homebrew",
	"Mozilla.sccache",
	"ms-playwright",
	"node/corepack",
	"org.swift.swiftpm",
	"pip",
	"pipx",
	"pre-commit",
	"puppeteer",
	"pypoetry",
	"selenium",
	"uv",
	"Yarn",
	"zig",
] as const;

const READ_WRITE_PATHS = [
	...XDG_CACHE_NAMES.map((name) => `.cache/${name}`),
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
	...MACOS_CACHE_NAMES.map((name) => `Library/Caches/${name}`),
	"Library/Logs/CoreSimulator",
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
	return [
		...existingPaths(root, READ_ONLY_PATHS, false),
		...existingPaths(root, READ_WRITE_PATHS, true),
	];
}

function existingPaths(
	root: string,
	entries: readonly string[],
	writable: boolean,
): HostDevelopmentPath[] {
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
		return metadata ? [{ path, directory: metadata.isDirectory(), writable }] : [];
	});
}
