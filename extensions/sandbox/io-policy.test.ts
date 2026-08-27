import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, symlinkSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { DEFAULT_CONFIG } from "./sandbox-config.ts";
import {
	isBaseReadAllowed,
	isBaseWriteAllowed,
	isDeniedByConfig,
	matchesPathRule,
} from "./io-policy.ts";
import { canonicalize } from "./io-permissions.ts";

test("base rights allow workspace reads and workspace or temp writes", () => {
	const root = mkdtempSync(join(tmpdir(), "pi-policy-"));
	const workspace = join(root, "workspace");
	mkdirSync(workspace);
	const outside = canonicalize("/home/sandbox-user/pi-policy-outside/file.txt");

	assert.equal(isBaseReadAllowed(join(workspace, "input.txt"), DEFAULT_CONFIG, workspace), true);
	assert.equal(isBaseReadAllowed(outside, DEFAULT_CONFIG, workspace), false);
	assert.equal(isBaseWriteAllowed(join(workspace, "out.txt"), DEFAULT_CONFIG, workspace), true);
	assert.equal(isBaseWriteAllowed(join(tmpdir(), "out.txt"), DEFAULT_CONFIG, workspace), true);
	assert.equal(isBaseWriteAllowed(outside, DEFAULT_CONFIG, workspace), false);
	assert.equal(isBaseWriteAllowed(join(workspace, ".git", "index"), DEFAULT_CONFIG, workspace), false);
	assert.equal(
		isBaseWriteAllowed(join(workspace, ".pi", "extensions", "unsafe.ts"), DEFAULT_CONFIG, workspace),
		false,
	);
});

test("host development caches require ordinary filesystem rights", () => {
	const workspace = "/work";
	for (const path of [
		join(homedir(), ".cargo", "registry", "cache", "package.crate"),
		join(homedir(), ".npm", "_cacache", "entry"),
		join(homedir(), ".cache", "tool", "entry"),
	]) {
		assert.equal(isBaseWriteAllowed(path, DEFAULT_CONFIG, workspace), false, path);
	}
});

test("git metadata in a configured cache stays writable", () => {
	assert.equal(
		isBaseWriteAllowed(
			"/cache/cargo/git/checkouts/package/.git/config",
			{ filesystem: { allowWrite: ["/cache"] } },
			"/work",
		),
		true,
	);
});

test("a symlinked workspace git folder stays read-only", () => {
	const root = mkdtempSync(join(tmpdir(), "pi-policy-git-link-"));
	const workspace = join(root, "workspace");
	const target = join(workspace, "git-control");
	mkdirSync(target, { recursive: true });
	symlinkSync(target, join(workspace, ".git"));

	assert.equal(
		isBaseWriteAllowed(join(workspace, ".git", "hooks", "pre-commit"), DEFAULT_CONFIG, workspace),
		false,
	);
	assert.equal(
		isBaseWriteAllowed(join(target, "hooks", "pre-commit"), DEFAULT_CONFIG, workspace),
		false,
	);
});

test("configured secret file rules cover top-level and nested paths", () => {
	const root = mkdtempSync(join(tmpdir(), "pi-policy-"));
	const workspace = join(root, "workspace");
	mkdirSync(workspace);
	const config = {
		...DEFAULT_CONFIG,
		filesystem: {
			...DEFAULT_CONFIG.filesystem,
			denyRead: ["**/.env", "**/.env.*", "**/*.key"],
			denyWrite: ["**/.env", "**/.env.*", "**/*.pem", "**/*.key"],
		},
	};

	for (const path of [
		join(workspace, ".env"),
		join(workspace, "app", ".env.local"),
		join(workspace, "keys", "deploy.key"),
	]) {
		assert.equal(isDeniedByConfig(canonicalize(path), "read", config, workspace), true);
		assert.equal(isDeniedByConfig(canonicalize(path), "write", config, workspace), true);
	}
});

test("relative secret globs do not hide public keys outside the workspace", () => {
	const workspace = canonicalize("/tmp/project");
	const publicRootKey = canonicalize("/nix/store/nixpkgs-source/root.key");
	const config = { filesystem: { denyRead: ["**/*.key"] } };

	assert.equal(isDeniedByConfig(publicRootKey, "read", config, workspace), false);
	assert.equal(
		isDeniedByConfig(join(workspace, "root.key"), "read", config, workspace),
		true,
	);
});

test("relative PEM rules stay scoped to the workspace", () => {
	const workspace = canonicalize("/tmp/project");
	const systemBundle = canonicalize("/etc/ssl/cert.pem");
	const config = { filesystem: { denyWrite: ["**/*.pem"] } };

	assert.equal(isDeniedByConfig(systemBundle, "read", config, workspace), false);
	assert.equal(isDeniedByConfig(systemBundle, "write", config, workspace), false);
	assert.equal(
		isDeniedByConfig(join(workspace, "cert.pem"), "write", config, workspace),
		true,
	);
});

test("path globs match names without widening sibling prefixes", () => {
	const cwd = canonicalize("/tmp/project");
	assert.equal(matchesPathRule("*.key", canonicalize("/tmp/project/a.key"), cwd), true);
	assert.equal(matchesPathRule("**/.env.*", canonicalize("/tmp/project/app/.env.test"), cwd), true);
	assert.equal(matchesPathRule("/tmp/data", canonicalize("/tmp/database/file"), cwd), false);
});
