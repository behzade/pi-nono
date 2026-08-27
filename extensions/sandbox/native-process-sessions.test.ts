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
	shutdownCount = 0;

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
	async shutdown(): Promise<void> { this.shutdownCount += 1; }
	emit(text: string): void { this.onData?.(Buffer.from(text)); }
	finish(exitCode = 0): void {
		this.resolve?.({ exitCode, denials: [], denialsComplete: true });
	}
}

function startOptions() {
	return {
		command: "long-command",
		cwd: process.cwd(),
		config: DEFAULT_CONFIG,
		permissions: [],
		networkHosts: [],
		localPorts: [],
	};
}

async function nextTask(): Promise<void> {
	await new Promise((resolve) => setImmediate(resolve));
}

test("bash promotion executes once and continuation output is incremental", async () => {
	const client = new FakeProcessClient();
	const settlements: unknown[] = [];
	const manager = new NativeProcessSessions("nono", "bwrap", process.env, (value) => settlements.push(value), async () => client);
	try {
		const id = await manager.start(startOptions());
		assert.match(id, /^pi-[0-9a-f-]+$/);
		assert.equal(client.request?.id, `process/${id}`);
		assert.equal(client.request?.interactive, true);
		client.emit("before yield\n");
		const promoted = await manager.yield(id, 1);
		assert.equal(promoted.state, "running");
		assert.equal(promoted.output, "before yield\n");

		client.emit("after yield\n");
		const continued = await manager.continue(id, {
			input: "answer\n",
			closeStdin: true,
			yieldMs: 1,
		});
		assert.equal(continued.output, "after yield\n");
		assert.deepEqual(client.writes, [Buffer.from("answer\n")]);
		assert.equal(client.closedStdin, true);
		assert.equal(settlements.length, 0);
	} finally {
		await manager.shutdown();
	}
});

test("completion before yield stays foreground and completion after yield wakes once", async () => {
	const foregroundClient = new FakeProcessClient();
	const foregroundSettlements: unknown[] = [];
	const foreground = new NativeProcessSessions("nono", "bwrap", process.env, (value) => foregroundSettlements.push(value), async () => foregroundClient);
	try {
		const id = await foreground.start(startOptions());
		foregroundClient.emit("done\n");
		foregroundClient.finish(0);
		const result = await foreground.yield(id, 100);
		assert.equal(result.state, "completed");
		assert.equal(result.output, "done\n");
		assert.equal(foregroundSettlements.length, 0);
	} finally {
		await foreground.shutdown();
	}

	const backgroundClient = new FakeProcessClient();
	let settle!: (value: unknown) => void;
	const settled = new Promise((resolve) => { settle = resolve; });
	const background = new NativeProcessSessions("nono", "bwrap", process.env, settle, async () => backgroundClient);
	try {
		const id = await background.start(startOptions());
		assert.equal((await background.yield(id, 1)).state, "running");
		backgroundClient.emit("later\n");
		backgroundClient.finish(7);
		const notification = await settled as { id: string; state: string; output: string; exitCode: number };
		assert.deepEqual(notification, { id, state: "exited", output: "later\n", exitCode: 7 });
		await nextTask();
	} finally {
		await background.shutdown();
	}
});

test("completion observed by process does not also enqueue a wakeup", async () => {
	const client = new FakeProcessClient();
	const settlements: unknown[] = [];
	const manager = new NativeProcessSessions("nono", "bwrap", process.env, (value) => settlements.push(value), async () => client);
	try {
		const id = await manager.start(startOptions());
		await manager.yield(id, 1);
		const observing = manager.continue(id, { yieldMs: 100 });
		client.emit("final\n");
		client.finish(0);
		const result = await observing;
		assert.equal(result.state, "completed");
		assert.equal(result.output, "final\n");
		assert.deepEqual(settlements, []);
	} finally {
		await manager.shutdown();
	}
});

test("permission revalidation fails before a process client starts", async () => {
	let starts = 0;
	const manager = new NativeProcessSessions("nono", "bwrap", process.env, () => {}, async () => {
		starts += 1;
		return new FakeProcessClient();
	});
	try {
		await assert.rejects(
			manager.start({
				...startOptions(),
				revalidatePermissions: () => { throw new Error("approved path changed"); },
			}),
			/approved path changed/,
		);
		assert.equal(starts, 0);
	} finally {
		await manager.shutdown();
	}
});

test("process continuation sends exact group signals", async () => {
	const client = new FakeProcessClient();
	const manager = new NativeProcessSessions("nono", "bwrap", process.env, () => {}, async () => client);
	try {
		const id = await manager.start(startOptions());
		await manager.yield(id, 1);
		for (const signal of ["INT", "TERM", "KILL"] as const) {
			await manager.continue(id, { signal, yieldMs: 1 });
		}
		assert.deepEqual(client.signals, ["SIGINT", "SIGTERM", "SIGKILL"]);
	} finally {
		await manager.shutdown();
	}
});
