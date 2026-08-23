import { Cause, Deferred, Effect, Exit, Fiber, Schema, Scope } from "effect";
import type { SandboxExecResult } from "./sandbox-protocol.ts";
import { NonoClient } from "./nono-client.ts";
import {
	buildSandboxExecRequest,
	type NativeFilePermission,
	type SandboxSourceEnvironment,
} from "./sandbox-policy.ts";
import { formatDenialSummary } from "./denial-summary.ts";
import type { NativeSandboxConfig } from "./sandbox-config.ts";

const MAX_RETAINED_BYTES = 2 * 1024 * 1024;
const MAX_JOBS = 32;

export class NativeBackgroundJobError extends Schema.TaggedError<NativeBackgroundJobError>()(
	"NativeBackgroundJobError",
	{ message: Schema.String, cause: Schema.optional(Schema.Defect()) },
) {}

const jobError = (cause: unknown) => new NativeBackgroundJobError({
	message: cause instanceof Error ? cause.message : String(cause),
	cause,
});

interface NativeJob {
	name: string;
	client: NonoClient;
	output: Buffer;
	startedAt: Date;
	pid?: number;
	result?: SandboxExecResult;
	error?: string;
	fiber: Fiber.Fiber<void, never>;
}

export interface BackgroundJobSettlement {
	name: string;
	state: "completed" | "exited" | "failed";
	exitCode?: number;
	error?: string;
}

interface StartOptions {
	name: string;
	command: string;
	cwd: string;
	config: NativeSandboxConfig;
	permissions: readonly NativeFilePermission[];
	revalidatePermissions?: () => readonly NativeFilePermission[];
	networkHosts: readonly string[];
	localPorts: readonly number[];
}

export class NativeBackgroundJobs {
	readonly #nonoPath: string;
	readonly #bwrapPath: string;
	readonly #sourceEnvironment: SandboxSourceEnvironment;
	readonly #jobs = new Map<string, NativeJob>();
	readonly #scope = Scope.makeUnsafe();
	readonly #onSettled: (settlement: BackgroundJobSettlement) => void;
	#closed = false;

	constructor(
		nonoPath: string,
		bwrapPath: string,
		sourceEnvironment: SandboxSourceEnvironment,
		onSettled: (settlement: BackgroundJobSettlement) => void = () => {},
	) {
		this.#nonoPath = nonoPath;
		this.#bwrapPath = bwrapPath;
		this.#sourceEnvironment = sourceEnvironment;
		this.#onSettled = onSettled;
	}

	readonly startEffect = Effect.fn("NativeBackgroundJobs.start")(function* (this: NativeBackgroundJobs, options: StartOptions) {
		if (this.#closed) return yield* Effect.fail(jobError("background jobs are shut down"));
		if (this.#jobs.has(options.name)) return yield* Effect.fail(jobError(`job already exists: ${options.name}`));
		if (this.#jobs.size >= MAX_JOBS) return yield* Effect.fail(jobError(`background job limit reached: ${MAX_JOBS}`));

		const manager = this;
		const client = yield* Effect.tryPromise({
			try: () => NonoClient.start(manager.#nonoPath, manager.#bwrapPath),
			catch: jobError,
		});
		const request = yield* Effect.try({
			try: () => buildSandboxExecRequest(
				`background/${options.name}`,
				options.command,
				options.cwd,
				undefined,
				options.config,
				options.revalidatePermissions?.() ?? options.permissions,
				options.networkHosts,
				options.localPorts,
				manager.#sourceEnvironment,
			),
			catch: jobError,
		});
		request.interactive = true;
		const started = yield* Deferred.make<void, NativeBackgroundJobError>();
		const job = {
			name: options.name,
			client,
			output: Buffer.alloc(0),
			startedAt: new Date(),
		} as NativeJob;

		const run = Effect.gen(function* () {
			const exit = yield* Effect.exit(client.execEffect(
				request,
				(data) => appendOutput(job, data),
				(pid) => {
					job.pid = pid;
					Deferred.doneUnsafe(started, Effect.void);
				},
			));
			if (Exit.isSuccess(exit)) {
				job.result = exit.value;
				if (exit.value.exitCode !== 0) {
					const summary = formatDenialSummary(exit.value.denials, exit.value.denialsComplete);
					if (summary) appendOutput(job, Buffer.from(summary));
				}
			} else {
				const cause = Cause.squash(exit.cause);
				job.error = cause instanceof Error ? cause.message : String(cause);
				Deferred.doneUnsafe(started, Effect.fail(jobError(cause)));
			}
			if (job.pid !== undefined) {
				yield* Effect.sync(() => manager.#onSettled(jobSettlement(job))).pipe(
					Effect.catchCause(() => Effect.void),
				);
			}
		}).pipe(
			Effect.onExit(() => Effect.sync(() => {
				if (!Deferred.isDoneUnsafe(started)) Deferred.doneUnsafe(started, Effect.fail(jobError("background job ended before starting")));
			}).pipe(Effect.andThen(Effect.promise(() => client.shutdown())))),
			Effect.catchCause(() => Effect.void),
		);
		job.fiber = yield* Effect.forkIn(run, this.#scope);
		this.#jobs.set(options.name, job);
		yield* Deferred.await(started).pipe(Effect.onExit((exit) => {
			if (Exit.isSuccess(exit)) return Effect.void;
			this.#jobs.delete(options.name);
			return Fiber.interrupt(job.fiber);
		}));
		return `started ${options.name}`;
	});

	/** Promise boundary adapter. */
	start(options: StartOptions, signal?: AbortSignal): Promise<string> {
		return Effect.runPromise(this.startEffect(options), signal ? { signal } : undefined);
	}

	list(): string {
		if (this.#jobs.size === 0) return "no background jobs";
		return [...this.#jobs.values()].map((job) => `${job.name} ${jobState(job)} pid=${job.pid ?? "unknown"} started=${job.startedAt.toISOString()}`).join("\n");
	}

	status(name: string): string {
		const job = this.#require(name);
		return `name=${name} state=${jobState(job)} pid=${job.pid ?? "unknown"}${job.result ? ` exit=${job.result.exitCode ?? 1}` : ""}${job.error ? ` error=${job.error}` : ""}`;
	}

	read(name: string, lines: number): string { return this.#require(name).output.toString("utf8").split("\n").slice(-lines).join("\n"); }

	write(name: string, data: Buffer): string {
		const job = this.#requireRunning(name);
		job.client.writeStdin(`background/${name}`, data);
		return `sent input to ${name}`;
	}

	readonly stopEffect = Effect.fn("NativeBackgroundJobs.stop")(function* (this: NativeBackgroundJobs, name: string) {
		const job = this.#require(name);
		if (!job.result && !job.error) yield* Fiber.interrupt(job.fiber);
		else yield* Fiber.await(job.fiber);
		this.#jobs.delete(name);
		return `stopped ${name}`;
	});

	/** Promise boundary adapter. */
	stop(name: string): Promise<string> { return Effect.runPromise(this.stopEffect(name)); }

	readonly shutdownEffect = Effect.fn("NativeBackgroundJobs.shutdown")(function* (this: NativeBackgroundJobs) {
		if (this.#closed) return;
		this.#closed = true;
		for (const job of this.#jobs.values()) yield* Fiber.interrupt(job.fiber);
		this.#jobs.clear();
		yield* Scope.close(this.#scope, Exit.void);
	});

	/** Promise boundary adapter. */
	shutdown(): Promise<void> { return Effect.runPromise(this.shutdownEffect()); }

	#require(name: string): NativeJob {
		const job = this.#jobs.get(name);
		if (!job) throw new Error(`unknown background job: ${name}`);
		return job;
	}
	#requireRunning(name: string): NativeJob {
		const job = this.#require(name);
		if (job.result || job.error) throw new Error(`background job is not running: ${name}`);
		return job;
	}
}

function appendOutput(job: NativeJob, data: Buffer): void {
	job.output = Buffer.concat([job.output, data]);
	if (job.output.length > MAX_RETAINED_BYTES) job.output = job.output.subarray(job.output.length - MAX_RETAINED_BYTES);
}
function jobState(job: NativeJob): string {
	if (job.error) return "failed";
	if (job.result) return job.result.exitCode === 0 ? "completed" : "exited";
	return "running";
}

function jobSettlement(job: NativeJob): BackgroundJobSettlement {
	if (job.error) return { name: job.name, state: "failed", error: job.error };
	const exitCode = job.result?.exitCode ?? 1;
	return {
		name: job.name,
		state: exitCode === 0 ? "completed" : "exited",
		exitCode,
	};
}
