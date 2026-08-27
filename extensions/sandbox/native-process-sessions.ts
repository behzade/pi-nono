import { randomUUID } from "node:crypto";
import { Cause, Deferred, Effect, Exit, Fiber, Scope } from "effect";
import type { SandboxExecRequest, SandboxExecResult } from "./sandbox-protocol.ts";
import {
	buildSandboxExecRequest,
	type NativeFilePermission,
	type SandboxSourceEnvironment,
} from "./sandbox-policy.ts";
import { formatDenialSummary } from "./denial-summary.ts";
import type { NativeSandboxConfig } from "./sandbox-config.ts";

const MAX_RETAINED_BYTES = 2 * 1024 * 1024;
const MAX_SESSIONS = 32;

export type ProcessSessionState = "running" | "completed" | "exited" | "failed" | "stopped";

export interface ProcessSessionSnapshot {
	id: string;
	state: ProcessSessionState;
	output: string;
	exitCode?: number;
	error?: string;
}

export interface ProcessSessionClient {
	execEffect(
		request: SandboxExecRequest,
		onData: (data: Buffer) => void,
		onStarted?: (pid: number) => void,
	): Effect.Effect<SandboxExecResult, unknown>;
	writeStdin(id: string, data: Buffer): void;
	closeStdin(id: string): void;
	signal(id: string, signal: "SIGINT" | "SIGTERM" | "SIGKILL"): void;
}

interface NativeSession {
	id: string;
	output: Buffer;
	outputStart: number;
	totalOutput: number;
	deliveredOutput: number;
	result?: SandboxExecResult;
	error?: string;
	stopped: boolean;
	detached: boolean;
	observers: number;
	listeners: Set<() => void>;
	fiber: Fiber.Fiber<void, never>;
}

export interface StartProcessSessionOptions {
	command: string;
	cwd: string;
	timeout?: number;
	config: NativeSandboxConfig;
	permissions: readonly NativeFilePermission[];
	revalidatePermissions?: () => readonly NativeFilePermission[];
	networkHosts: readonly string[];
	localPorts: readonly number[];
}

export interface ContinueProcessSessionOptions {
	input?: string;
	closeStdin?: boolean;
	signal?: "INT" | "TERM" | "KILL";
	yieldMs: number;
}

function processError(cause: unknown): Error {
	return cause instanceof Error ? cause : new Error(String(cause));
}

export class NativeProcessSessions {
	readonly #client: ProcessSessionClient;
	readonly #sourceEnvironment: SandboxSourceEnvironment;
	readonly #sessions = new Map<string, NativeSession>();
	readonly #scope = Scope.makeUnsafe();
	readonly #onSettled: (settlement: ProcessSessionSnapshot) => void;
	#closed = false;

	constructor(
		client: ProcessSessionClient,
		sourceEnvironment: SandboxSourceEnvironment,
		onSettled: (settlement: ProcessSessionSnapshot) => void = () => {},
	) {
		this.#client = client;
		this.#sourceEnvironment = sourceEnvironment;
		this.#onSettled = onSettled;
	}

	readonly startEffect = Effect.fn("NativeProcessSessions.start")(function* (
		this: NativeProcessSessions,
		options: StartProcessSessionOptions,
	) {
		if (this.#closed) return yield* Effect.fail(new Error("process sessions are shut down"));
		this.#pruneSettled();
		if (this.#sessions.size >= MAX_SESSIONS) {
			return yield* Effect.fail(new Error(`process session limit reached: ${MAX_SESSIONS}`));
		}

		const manager = this;
		const id = `pi-${randomUUID()}`;
		const request = yield* Effect.try({
			try: () => buildSandboxExecRequest(
				`process/${id}`,
				options.command,
				options.cwd,
				options.timeout,
				options.config,
				options.revalidatePermissions?.() ?? options.permissions,
				options.networkHosts,
				options.localPorts,
				manager.#sourceEnvironment,
			),
			catch: processError,
		});
		request.interactive = true;
		const started = yield* Deferred.make<void, Error>();
		const session = {
			id,
			output: Buffer.alloc(0),
			outputStart: 0,
			totalOutput: 0,
			deliveredOutput: 0,
			stopped: false,
			detached: false,
			observers: 0,
			listeners: new Set<() => void>(),
		} as NativeSession;

		const run = Effect.gen(function* () {
			const exit = yield* Effect.exit(manager.#client.execEffect(
				request,
				(data) => manager.#appendOutput(session, data),
				() => Deferred.doneUnsafe(started, Effect.void),
			));
			if (Exit.isSuccess(exit)) {
				session.result = exit.value;
				if (exit.value.exitCode !== 0) {
					const summary = formatDenialSummary(exit.value.denials, exit.value.denialsComplete);
					if (summary) manager.#appendOutput(session, Buffer.from(summary));
				}
			} else if (!session.stopped) {
				const error = processError(Cause.squash(exit.cause));
				session.error = error.message;
				Deferred.doneUnsafe(started, Effect.fail(error));
			}
			manager.#wake(session);
			manager.#notifyIfUnobserved(session);
		}).pipe(
			Effect.onExit(() => Effect.sync(() => {
				if (!Deferred.isDoneUnsafe(started)) {
					Deferred.doneUnsafe(started, Effect.fail(new Error("process ended before starting")));
				}
			})),
			Effect.catchCause(() => Effect.void),
		);
		session.fiber = yield* Effect.forkIn(run, this.#scope);
		this.#sessions.set(id, session);
		yield* Deferred.await(started).pipe(Effect.onExit((exit) => {
			if (Exit.isSuccess(exit)) return Effect.void;
			this.#sessions.delete(id);
			return Fiber.interrupt(session.fiber);
		}));
		return id;
	});

	start(options: StartProcessSessionOptions, signal?: AbortSignal): Promise<string> {
		return Effect.runPromise(this.startEffect(options), signal ? { signal } : undefined);
	}

	async yield(id: string, yieldMs: number, signal?: AbortSignal): Promise<ProcessSessionSnapshot> {
		const session = this.#require(id);
		try {
			await this.#wait(session, () => this.#state(session) !== "running", yieldMs, signal);
		} catch (error) {
			if (signal?.aborted && this.#state(session) === "running") {
				session.stopped = true;
				await Effect.runPromise(Fiber.interrupt(session.fiber));
			}
			throw error;
		}
		if (this.#state(session) === "running") session.detached = true;
		return this.#snapshot(session, true);
	}

	async continue(
		id: string,
		options: ContinueProcessSessionOptions,
		signal?: AbortSignal,
	): Promise<ProcessSessionSnapshot> {
		const session = this.#require(id);
		if (this.#state(session) !== "running") return this.#snapshot(session, true);
		session.observers += 1;
		try {
			const baseline = session.totalOutput;
			if (options.input !== undefined) this.#client.writeStdin(`process/${id}`, Buffer.from(options.input));
			if (options.closeStdin) this.#client.closeStdin(`process/${id}`);
			if (options.signal) this.#client.signal(`process/${id}`, `SIG${options.signal}`);
			if (session.deliveredOutput >= session.totalOutput) {
				await this.#wait(
					session,
					() => session.totalOutput > baseline || this.#state(session) !== "running",
					options.yieldMs,
					signal,
				);
			}
			return this.#snapshot(session, true);
		} finally {
			session.observers -= 1;
		}
	}

	readonly shutdownEffect = Effect.fn("NativeProcessSessions.shutdown")(function* (this: NativeProcessSessions) {
		if (this.#closed) return;
		this.#closed = true;
		for (const session of this.#sessions.values()) {
			session.stopped = true;
			yield* Fiber.interrupt(session.fiber);
		}
		this.#sessions.clear();
		yield* Scope.close(this.#scope, Exit.void);
	});

	shutdown(): Promise<void> { return Effect.runPromise(this.shutdownEffect()); }

	#require(id: string): NativeSession {
		const session = this.#sessions.get(id);
		if (!session) throw new Error(`unknown process session: ${id}`);
		return session;
	}

	#appendOutput(session: NativeSession, data: Buffer): void {
		session.totalOutput += data.length;
		session.output = Buffer.concat([session.output, data]);
		if (session.output.length > MAX_RETAINED_BYTES) {
			const dropped = session.output.length - MAX_RETAINED_BYTES;
			session.output = session.output.subarray(dropped);
			session.outputStart += dropped;
		}
		this.#wake(session);
	}

	#snapshot(session: NativeSession, consume: boolean): ProcessSessionSnapshot {
		const start = Math.max(session.deliveredOutput, session.outputStart);
		let output = session.output.subarray(start - session.outputStart).toString("utf8");
		if (session.deliveredOutput < session.outputStart) {
			output = `[Process output truncated before delivery]\n${output}`;
		}
		if (consume) session.deliveredOutput = session.totalOutput;
		const state = this.#state(session);
		return {
			id: session.id,
			state,
			output,
			...(session.result?.exitCode === undefined || session.result.exitCode === null
				? {}
				: { exitCode: session.result.exitCode }),
			...(session.error === undefined ? {} : { error: session.error }),
		};
	}

	#state(session: NativeSession): ProcessSessionState {
		if (session.stopped) return "stopped";
		if (session.error) return "failed";
		if (session.result) return session.result.exitCode === 0 ? "completed" : "exited";
		return "running";
	}

	#notifyIfUnobserved(session: NativeSession): void {
		if (!session.detached || session.observers > 0) return;
		try { this.#onSettled(this.#snapshot(session, false)); } catch { /* Notification cannot corrupt process state. */ }
	}

	#wake(session: NativeSession): void {
		for (const listener of [...session.listeners]) listener();
	}

	#wait(
		session: NativeSession,
		predicate: () => boolean,
		yieldMs: number,
		signal?: AbortSignal,
	): Promise<void> {
		if (predicate()) return Promise.resolve();
		return new Promise((resolve, reject) => {
			let timer: ReturnType<typeof setTimeout> | undefined;
			const cleanup = () => {
				if (timer) clearTimeout(timer);
				session.listeners.delete(check);
				signal?.removeEventListener("abort", abort);
			};
			const finish = () => { cleanup(); resolve(); };
			const check = () => { if (predicate()) finish(); };
			const abort = () => { cleanup(); reject(new Error("aborted")); };
			session.listeners.add(check);
			timer = setTimeout(finish, yieldMs);
			if (signal?.aborted) abort();
			else signal?.addEventListener("abort", abort, { once: true });
		});
	}

	#pruneSettled(): void {
		for (const [id, session] of this.#sessions) {
			if (this.#sessions.size < MAX_SESSIONS) return;
			if (this.#state(session) !== "running") this.#sessions.delete(id);
		}
	}
}
