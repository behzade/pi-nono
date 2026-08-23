import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import type { SandboxExecRequest, SandboxExecResult } from "./sandbox-protocol.ts";
import { DEFAULT_CONFIG } from "./sandbox-config.ts";
import { formatDenialSummary } from "./denial-summary.ts";
import { createNativeSandboxOps, type SandboxExecutor } from "./native-sandbox-ops.ts";

class FakeSandboxExecutor implements SandboxExecutor {
	readonly requests: SandboxExecRequest[] = [];
	readonly result: SandboxExecResult;
	constructor(result: SandboxExecResult) {
		this.result = result;
	}
	async exec(request: SandboxExecRequest, onData: (data: Buffer) => void): Promise<SandboxExecResult> {
		this.requests.push(request);
		onData(Buffer.from("command failed\n"));
		return this.result;
	}
}

const environmentOptions = { sourceEnvironment: process.env };
function sandboxOps(
	executor: SandboxExecutor,
	commandId: string,
	revalidatePermissions?: () => never,
) {
	return createNativeSandboxOps(executor, DEFAULT_CONFIG, [], [], [], commandId, {
		...environmentOptions,
		revalidatePermissions,
	});
}

test("sandbox commands use the supplied captured environment", async () => {
	const cwd = mkdtempSync(join(tmpdir(), "pi-captured-environment-"));
	const executor = new FakeSandboxExecutor({ exitCode: 0, denials: [], denialsComplete: true });
	const capturedEnvironment = Object.freeze({
		...process.env,
		PATH: "/captured/bun/bin:/captured/system/bin",
	});
	const operations = createNativeSandboxOps(
		executor,
		DEFAULT_CONFIG,
		[],
		[],
		[],
		"captured-environment",
		{ sourceEnvironment: capturedEnvironment },
	);
	await operations.exec("bun --version", cwd, { onData() {} });

	assert.equal(executor.requests[0]?.env.PATH, capturedEnvironment.PATH);
});

test("one failed command makes exactly one executor request and returns a bounded grouped denial", async () => {
	const cwd = mkdtempSync(join(tmpdir(), "pi-one-run-denial-"));
	const paths = Array.from({ length: 20 }, (_, index) => `/external/state/file-${index}.db`);
	const executor = new FakeSandboxExecutor({
		exitCode: 1,
		denials: paths.map((path) => ({ operation: "file-write-create", path, process: "tool" })),
		denialsComplete: false,
	});
	const output: Buffer[] = [];
	const operations = sandboxOps(executor, "tool-one-run");
	const result = await operations.exec("failing-tool", cwd, { onData: (data) => output.push(data) });
	const text = Buffer.concat(output).toString("utf8");
	assert.equal(result.exitCode, 1);
	assert.equal(executor.requests.length, 1);
	assert.equal(executor.requests[0]?.id, "tool-one-run");
	assert.match(text, /Sandbox reported 20 denial hints/);
	assert.match(text, /write access: 20 under \/external\/state/);
	assert.equal((text.match(/  example:/g) ?? []).length, 3);
	assert.match(text, /Use request_access/);
	assert.match(text, /No command was retried/);
	assert.doesNotMatch(text, /Retrying command|Allow once/);
});

test("known host development caches recommend the managed cache adapter", async () => {
	const cwd = mkdtempSync(join(tmpdir(), "pi-cache-denial-"));
	const executor = new FakeSandboxExecutor({
		exitCode: 1,
		denials: [{
			operation: "file-write-create",
			path: join(homedir(), ".cargo", "registry", "cache.db"),
			process: "cargo",
		}],
		denialsComplete: true,
	});
	const output: Buffer[] = [];
	await sandboxOps(executor, "cache-denial").exec("cargo build", cwd, {
		onData: (data) => output.push(data),
	});
	const text = Buffer.concat(output).toString("utf8");
	assert.match(text, /host development cache \(Cargo\)/);
	assert.match(text, /development_cache environment mapping/);
	assert.doesNotMatch(text, /smallest portable file\/tree/);
	assert.equal(executor.requests.length, 1);
});

test("network-only and mixed denial hints stay grouped with three total examples", async () => {
	const networkOnly = formatDenialSummary([
		{ operation: "network-outbound", path: null, process: "curl" },
	], false);
	assert.match(networkOnly ?? "", /network access: 1/);
	assert.match(networkOnly ?? "", /example: process curl/);
	assert.match(networkOnly ?? "", /exact network host, or exact loopback endpoint/);

	const cwd = mkdtempSync(join(tmpdir(), "pi-mixed-denial-"));
	const executor = new FakeSandboxExecutor({
		exitCode: 1,
		denials: [
			{ operation: "file-read-data", path: "/dev/null", process: "cat" },
			{ operation: "file-write-create", path: join(homedir(), ".npm", "cache", "a"), process: "npm" },
			{ operation: "file-write-create", path: "/external/state/a", process: "tool" },
			{ operation: "network-outbound", path: "api.example.com:443", process: "curl" },
			{ operation: "network-bind", path: "127.0.0.1:3000", process: "server" },
		],
		denialsComplete: false,
	});
	const output: Buffer[] = [];
	await sandboxOps(executor, "mixed-denial").exec("tool", cwd, {
		onData: (data) => output.push(data),
	});
	const text = Buffer.concat(output).toString("utf8");
	assert.match(text, /Sandbox reported 4 denial hints/);
	assert.match(text, /host development cache \(npm\)/);
	assert.match(text, /write access/);
	assert.match(text, /network access: 2/);
	assert.match(text, /development_cache environment mapping/);
	assert.match(text, /smallest portable file\/tree, exact network host, or exact loopback endpoint/);
	assert.equal((text.match(/  example:/g) ?? []).length, 3);
	assert.doesNotMatch(text, /\/dev\/null/);
	assert.equal(executor.requests.length, 1);
});

test("interruption aborts one nono command with its exact host snapshot", async () => {
	let request: SandboxExecRequest | undefined;
	let startedResolve!: () => void;
	const started = new Promise<void>((resolve) => {
		startedResolve = resolve;
	});
	const executor: SandboxExecutor = {
		exec(next, _onData, signal) {
			request = next;
			startedResolve();
			return new Promise((_resolve, reject) => {
				signal?.addEventListener("abort", () => reject(new Error("aborted")), { once: true });
			});
		},
	};
	const controller = new AbortController();
	const running = createNativeSandboxOps(
		executor,
		DEFAULT_CONFIG,
		[],
		["example.com"],
		[],
		"interrupt-cleanup",
		environmentOptions,
	).exec("sleep", tmpdir(), {
		onData() {},
		signal: controller.signal,
	});
	await started;
	controller.abort();
	await assert.rejects(running);

	assert.equal(request?.policy.network.mode, "proxy");
	if (request?.policy.network.mode !== "proxy") throw new Error("proxy request missing");
	assert.deepEqual(request.policy.network.allowed_hosts, ["example.com"]);
});

test("filesystem grants are revalidated immediately before the executor request", async () => {
	const cwd = mkdtempSync(join(tmpdir(), "pi-revalidate-grants-"));
	const executor = new FakeSandboxExecutor({ exitCode: 0, denials: [], denialsComplete: true });
	const operations = sandboxOps(
		executor,
		"revalidate",
		() => { throw new Error("approved path became a symlink"); },
	);
	await assert.rejects(
		operations.exec("true", cwd, { onData() {} }),
		/approved path became a symlink/,
	);
	assert.equal(executor.requests.length, 0);
});
