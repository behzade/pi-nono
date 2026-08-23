import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { resolvePackagedExecutables } from "./packaged-executables.ts";

const roots: string[] = [];

test.afterEach(() => {
	for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

test("resolves fixed nono and OS-provided Bubblewrap", () => {
	const root = nativePackage("pi-nono-linux-x64", "3.0.0");
	const result = resolvePackagedExecutables(
		"linux",
		"x64",
		() => join(root, "package.json"),
		join(root, "bin"),
	);
	assert.deepEqual(result, {
		nonoPath: join(root, "bin", "nono"),
		bwrapPath: join(root, "bin", "bwrap"),
		packageName: "pi-nono-linux-x64",
	});
});

test("macOS packages never supply Bubblewrap", () => {
	const root = nativePackage("pi-nono-darwin-arm64", "3.0.0");
	const result = resolvePackagedExecutables("darwin", "arm64", () => join(root, "package.json"));
	assert.equal(result.bwrapPath, "");
	assert.equal(result.nonoPath, join(root, "bin", "nono"));
});

test("rejects a native executable changed after packaging", () => {
	const root = nativePackage("pi-nono-linux-x64", "3.0.0");
	writeFileSync(join(root, "bin", "nono"), "tampered", { mode: 0o755 });
	assert.throws(
		() => resolvePackagedExecutables("linux", "x64", () => join(root, "package.json")),
		/checksum mismatch/,
	);
});

test("fails closed when Bubblewrap is missing", () => {
	const root = nativePackage("pi-nono-linux-x64", "3.0.0");
	assert.throws(
		() => resolvePackagedExecutables("linux", "x64", () => join(root, "package.json"), ""),
		/Bubblewrap is required on Linux but was not found in PATH/,
	);
});

test("fails closed for missing, mismatched, or unsupported native packages", () => {
	assert.throws(
		() => resolvePackagedExecutables("linux", "arm64"),
		/do not support linux\/arm64/,
	);
	assert.throws(
		() => resolvePackagedExecutables("linux", "x64", () => "/missing/package.json"),
		/native package .* is missing/,
	);
	const root = nativePackage("pi-nono-linux-x64", "2.0.0");
	assert.throws(
		() => resolvePackagedExecutables("linux", "x64", () => join(root, "package.json")),
		/must be .*@3\.0\.0/,
	);
});

function nativePackage(name: string, version: string): string {
	const root = mkdtempSync(join(tmpdir(), "guardian-native-test-"));
	roots.push(root);
	mkdirSync(join(root, "bin"));
	const darwin = name.endsWith("darwin-arm64");
	const nono = Buffer.from("fixed nono");
	const bwrap = Buffer.from("fixed bwrap");
	writeFileSync(join(root, "bin", "nono"), nono, { mode: 0o755 });
	if (!darwin) writeFileSync(join(root, "bin", "bwrap"), bwrap, { mode: 0o755 });
	writeFileSync(join(root, "package.json"), `${JSON.stringify({
		name,
		version,
		os: [darwin ? "darwin" : "linux"],
		cpu: [darwin ? "arm64" : "x64"],
		piNono: {
			nono: { path: "bin/nono", sha256: sha256(nono) },
		},
	})}\n`);
	return realpathSync(root);
}

function sha256(value: Buffer): string {
	return createHash("sha256").update(value).digest("hex");
}
