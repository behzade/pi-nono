import assert from "node:assert/strict";
import test from "node:test";
import { Effect } from "effect";
import type { SandboxExecRequest, SandboxExecResult } from "./sandbox-protocol.ts";
import { DEFAULT_CONFIG } from "./sandbox-config.ts";
import { NativeProcessSessions } from "./native-process-sessions.ts";

class FakeProcessClient {
	request?: SandboxExecRequest;
	onData?: (data: Buffer) => void;
	resolve?: (result: SandboxExecResult) => void;
	writes: Buffer[] = [];
	closedStdin = false;
	signals: string[] = [];

	execEffect(
		request: SandboxExecRequest,
		onData: (data: Buffer) => void,
		onStarted?: (pid: number) => void,
	) {
		return Effect.tryPromise({
			try: () => new Promise<SandboxExecResult>((resolve) => {
				this.request = request;
				this.onData = onData;
				this.resolve = resolve;
				onStarted?.(1234);
			}),
			catch: (error) => error,
		});
	}

	writeStdin(_id: string, data: Buffer): void { this.writes.push(data); }
	closeStdin(): void { this.closedStdin = true; }
	signal(_id: string, signal: string): void { this.signals.push(signal); }
	emit(text: string): void { this.onData?.(Buffer.from(text)); }
	finish(exitCode = 0): void {
		this.resolve?.({ exitCode, denials: [], denialsComplete: true });
	}
}

const startOptions = () => ({
	command: "long-command",
	cwd: process.cwd(),
	config: DEFAULT_CONFIG,
	permissions: [],
	networkHosts: [],
	localPorts: [],
});

test("detached processes preserve incremental output and interaction", async () => {
	const client = new FakeProcessClient();
	const manager = new NativeProcessSessions(client, process.env);
	try {
		const id = await manager.start(startOptions());
		assert.match(id, /^pi-[0-9a-f-]+$/);
		assert.equal(client.request?.id, `process/${id}`);
		assert.equal(client.request?.interactive, true);

		client.emit("before\n");
		assert.equal((await manager.detachAfter(id, 1)).output, "before\n");
		client.emit("after\n");
		const continued = await manager.continue(id, {
			input: "answer\n",
			closeStdin: true,
			signal: "INT",
		});
		assert.equal(continued.output, "after\n");
		assert.deepEqual(client.writes, [Buffer.from("answer\n")]);
		assert.equal(client.closedStdin, true);
		await manager.continue(id, { signal: "TERM" });
		await manager.continue(id, { signal: "KILL" });
		assert.deepEqual(client.signals, ["SIGINT", "SIGTERM", "SIGKILL"]);
	} finally {
		await manager.shutdown();
	}
});

test("only detached completion sends a notification", async () => {
	const foregroundClient = new FakeProcessClient();
	const foregroundNotifications: unknown[] = [];
	const foreground = new NativeProcessSessions(foregroundClient, process.env, (value) => foregroundNotifications.push(value));
	try {
		const id = await foreground.start(startOptions());
		foregroundClient.finish();
		assert.equal((await foreground.detachAfter(id, 100)).state, "completed");
		assert.deepEqual(foregroundNotifications, []);
	} finally {
		await foreground.shutdown();
	}

	const backgroundClient = new FakeProcessClient();
	let notify!: (value: unknown) => void;
	const notification = new Promise((resolve) => { notify = resolve; });
	const background = new NativeProcessSessions(backgroundClient, process.env, notify);
	try {
		const id = await background.start(startOptions());
		await background.detachAfter(id, 1);
		backgroundClient.emit("later\n");
		backgroundClient.finish(7);
		assert.deepEqual(await notification, { id, state: "exited", output: "later\n", exitCode: 7 });
	} finally {
		await background.shutdown();
	}
});

test("process control returns current state without waiting", async () => {
	const client = new FakeProcessClient();
	const manager = new NativeProcessSessions(client, process.env);
	try {
		const id = await manager.start(startOptions());
		assert.deepEqual(await manager.continue(id, {}), { id, state: "running", output: "" });
		client.emit("still running\n");
		assert.deepEqual(await manager.continue(id, {}), { id, state: "running", output: "still running\n" });
		client.finish();
		assert.deepEqual(await manager.continue(id, {}), { id, state: "completed", output: "", exitCode: 0 });
	} finally {
		await manager.shutdown();
	}
});

test("inspecting a detached process does not suppress its completion notification", async () => {
	const client = new FakeProcessClient();
	let notify!: (value: unknown) => void;
	const notification = new Promise((resolve) => { notify = resolve; });
	const manager = new NativeProcessSessions(client, process.env, notify);
	try {
		const id = await manager.start(startOptions());
		await manager.detachAfter(id, 1);
		assert.deepEqual(await manager.continue(id, {}), { id, state: "running", output: "" });
		client.emit("final\n");
		client.finish();
		assert.deepEqual(await notification, { id, state: "completed", output: "final\n", exitCode: 0 });
	} finally {
		await manager.shutdown();
	}
});

test("permission revalidation fails before execution", async () => {
	const client = new FakeProcessClient();
	const manager = new NativeProcessSessions(client, process.env);
	try {
		await assert.rejects(manager.start({
			...startOptions(),
			revalidatePermissions: () => { throw new Error("approved path changed"); },
		}), /approved path changed/);
		assert.equal(client.request, undefined);
	} finally {
		await manager.shutdown();
	}
});
