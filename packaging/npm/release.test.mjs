import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { bumpVersion, release } from "./release.mjs";

const manifestPath = "extensions/sandbox/package.json";
const lockPath = "extensions/sandbox/package-lock.json";

function repository(t) {
	const root = mkdtempSync(join(tmpdir(), "pi-release-test-"));
	t.after(() => rmSync(root, { recursive: true, force: true }));
	const git = (...args) => execFileSync("git", args, { cwd: root, encoding: "utf8", stdio: ["pipe", "pipe", "pipe"] }).trim();
	git("init", "--initial-branch=main");
	for (const [key, value] of Object.entries({
		"user.name": "Release test", "user.email": "test@example.invalid",
		"commit.gpgsign": "false", "tag.gpgsign": "false", "core.hooksPath": join(root, "no-hooks"),
	})) git("config", key, value);
	mkdirSync(join(root, "extensions/sandbox"), { recursive: true });
	writeFileSync(join(root, manifestPath), JSON.stringify({ name: "pi-nono", version: "3.2.4", private: true }));
	writeFileSync(join(root, lockPath), JSON.stringify({
		name: "pi-nono", version: "3.2.4", lockfileVersion: 3,
		packages: { "": { name: "pi-nono", version: "3.2.4" }, "node_modules/example": { version: "1.0.0", integrity: "unchanged" } },
	}));
	git("add", ".");
	git("commit", "-m", "Initial fixture");
	return { root, git };
}

for (const [bump, version] of [["patch", "3.2.5"], ["minor", "3.3.0"], ["major", "4.0.0"]]) {
	test(`${bump} updates both manifests and tags the release commit`, (t) => {
		const { root, git } = repository(t);
		assert.equal(release(root, bump), `v${version}`);
		assert.equal(git("rev-parse", `v${version}^{commit}`), git("rev-parse", "HEAD"));
		assert.equal(git("cat-file", "-t", `v${version}`), "tag");
		assert.equal(git("log", "-1", "--format=%s"), `chore(release): bump version to ${version}`);
		assert.equal(git("status", "--porcelain"), "");
		const manifest = JSON.parse(git("show", `v${version}:${manifestPath}`));
		const lock = JSON.parse(git("show", `v${version}:${lockPath}`));
		assert.equal(manifest.version, version);
		assert.equal(lock.version, version);
		assert.equal(lock.packages[""].version, version);
		assert.deepEqual(lock.packages["node_modules/example"], { version: "1.0.0", integrity: "unchanged" });
	});
}

test("rejects dirty trees, existing tags, and mismatched versions before mutation", (t) => {
	const { root, git } = repository(t);
	const before = readFileSync(join(root, manifestPath), "utf8");
	writeFileSync(join(root, "unrelated.txt"), "someone else's work");
	assert.throws(() => release(root, "patch"), /must be clean/);
	assert.equal(readFileSync(join(root, "unrelated.txt"), "utf8"), "someone else's work");
	git("add", "unrelated.txt");
	git("commit", "-m", "Preserve unrelated work");
	git("tag", "v3.2.5");
	assert.throws(() => release(root, "patch"), /already exists/);
	assert.equal(readFileSync(join(root, manifestPath), "utf8"), before);
	const lock = JSON.parse(readFileSync(join(root, lockPath), "utf8"));
	lock.packages[""].version = "3.2.3";
	writeFileSync(join(root, lockPath), JSON.stringify(lock));
	git("add", lockPath);
	git("commit", "-m", "Mismatched fixture");
	assert.throws(() => release(root, "minor"), /must match/);
	assert.equal(readFileSync(join(root, manifestPath), "utf8"), before);
	assert.equal(git("status", "--porcelain"), "");
});

test("invalid bumps and non-stable versions are rejected", () => {
	assert.throws(() => bumpVersion("3.2.4", "typo"), /BUMP/);
	for (const version of ["3.2.4-beta.1", "v3.2.4", "03.2.4", "3.2", null]) {
		assert.throws(() => bumpVersion(version, "patch"), /stable/);
	}
});
