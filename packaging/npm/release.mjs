#!/usr/bin/env node

import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const manifestPath = "extensions/sandbox/package.json";
const lockPath = "extensions/sandbox/package-lock.json";

export function bumpVersion(version, bump) {
	if (!["patch", "minor", "major"].includes(bump)) {
		throw new Error("Use make release BUMP=patch|minor|major");
	}
	if (typeof version !== "string" || !/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.test(version)) {
		throw new Error(`Expected a stable major.minor.patch version, got ${JSON.stringify(version)}`);
	}
	const parts = version.split(".").map(Number);
	const index = { major: 0, minor: 1, patch: 2 }[bump];
	parts[index] += 1;
	for (let i = index + 1; i < parts.length; i++) parts[i] = 0;
	if (!parts.every(Number.isSafeInteger)) throw new Error("Version exceeds safe integer range");
	return parts.join(".");
}

export function release(root, bump) {
	const git = (...args) => execFileSync("git", args, { cwd: root, encoding: "utf8" }).trim();
	const manifest = JSON.parse(readFileSync(join(root, manifestPath), "utf8"));
	const lock = JSON.parse(readFileSync(join(root, lockPath), "utf8"));
	const version = bumpVersion(manifest.version, bump);
	const tag = `v${version}`;

	if (git("status", "--porcelain", "--untracked-files=all")) {
		throw new Error("Working tree must be clean. Commit or resolve existing changes before releasing.");
	}
	git("symbolic-ref", "--quiet", "--short", "HEAD");
	for (const state of ["MERGE_HEAD", "CHERRY_PICK_HEAD", "REVERT_HEAD", "rebase-merge", "rebase-apply"]) {
		if (existsSync(resolve(root, git("rev-parse", "--git-path", state)))) {
			throw new Error(`Finish the in-progress Git operation before releasing (${state})`);
		}
	}
	git("diff", "--check");
	if (lock.version !== manifest.version || lock.packages?.[""]?.version !== manifest.version) {
		throw new Error("package.json and both package-lock.json version fields must match before releasing");
	}
	const existing = spawnSync("git", ["show-ref", "--verify", "--quiet", `refs/tags/${tag}`], { cwd: root });
	if (existing.error) throw existing.error;
	if (existing.status === 0) throw new Error(`Tag ${tag} already exists`);
	if (existing.status !== 1) throw new Error("Could not check existing release tags");

	manifest.version = version;
	lock.version = version;
	lock.packages[""].version = version;
	for (const [path, value] of [[manifestPath, manifest], [lockPath, lock]]) {
		writeFileSync(join(root, path), `${JSON.stringify(value, null, "\t")}\n`);
	}
	git("add", "--", manifestPath, lockPath);
	git("commit", "--only", "-m", `chore(release): bump version to ${version}`, "--", manifestPath, lockPath);
	git("tag", "-a", tag, "-m", `Release ${tag}`, "HEAD");
	return tag;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
	try {
		const tag = release(resolve(dirname(fileURLToPath(import.meta.url)), "../.."), process.argv[2]);
		console.log(`Created release commit and ${tag}. Nothing has been pushed.\nPublish with: git push --atomic origin HEAD ${tag}`);
	} catch (error) {
		console.error(error instanceof Error ? error.message : String(error));
		process.exitCode = 1;
	}
}
