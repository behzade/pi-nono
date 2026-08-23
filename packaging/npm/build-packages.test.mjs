import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

const repositoryRoot = resolve(import.meta.dirname, "../..");

test("stages a publishable main package with exact optional native packages", () => {
	const outputRoot = mkdtempSync(join(tmpdir(), "guardian-npm-test-"));
	try {
		const result = spawnSync(
			process.execPath,
			[join(repositoryRoot, "packaging/npm/build-packages.mjs"), "main", "--out", outputRoot],
			{ encoding: "utf8" },
		);
		assert.equal(result.status, 0, result.stderr);
		const packageRoot = join(outputRoot, "pi-guardian");
		const manifest = JSON.parse(readFileSync(join(packageRoot, "package.json"), "utf8"));
		assert.equal(manifest.private, false);
		assert.deepEqual(manifest.scripts, {});
		assert.equal(manifest.devDependencies, undefined);
		assert.deepEqual(manifest.optionalDependencies, {
			"pi-guardian-darwin-arm64": "3.0.0",
			"pi-guardian-linux-x64": "3.0.0",
		});
		assert.deepEqual(manifest.publishConfig, { access: "public", tag: "next" });
		const names = readdirSync(packageRoot);
		assert(names.includes("README.md"));
		assert(names.includes("LICENSE"));
		assert(names.includes("index.ts"));
		assert(names.includes("packaged-executables.ts"));
		assert.equal(names.some((name) => name.endsWith(".test.ts")), false);
		assert.equal(names.includes("test-setup.ts"), false);
		assert.equal(names.includes("package-lock.json"), false);
	} finally {
		rmSync(outputRoot, { recursive: true, force: true });
	}
});
