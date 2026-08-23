import type { BashOperations } from "@earendil-works/pi-coding-agent";
import { Effect, Schema } from "effect";
import type {
	SandboxExecRequest,
	SandboxExecResult,
} from "./sandbox-protocol.ts";
import type { NativeSandboxConfig } from "./sandbox-config.ts";
import {
	buildSandboxExecRequest,
	type NativeFilePermission,
	type SandboxSourceEnvironment,
} from "./sandbox-policy.ts";
import { formatDenialSummary } from "./denial-summary.ts";

export interface SandboxExecutor {
	exec(
		request: SandboxExecRequest,
		onData: (data: Buffer) => void,
		signal?: AbortSignal,
	): Promise<SandboxExecResult>;
	execEffect?: (
		request: SandboxExecRequest,
		onData: (data: Buffer) => void,
	) => Effect.Effect<SandboxExecResult, unknown>;
}

export class NativeSandboxExecError extends Schema.TaggedError<NativeSandboxExecError>()(
	"NativeSandboxExecError",
	{
		message: Schema.String,
		cause: Schema.optional(Schema.Defect()),
	},
) {}

const sandboxError = (cause: unknown) => new NativeSandboxExecError({
	message: cause instanceof Error ? cause.message : String(cause),
	cause,
});

export const executeNativeSandboxCommand = Effect.fn("Sandbox.executeNativeCommand")(
	function* (params: {
		client: SandboxExecutor;
		config: NativeSandboxConfig;
		permissions: readonly NativeFilePermission[];
		networkHosts: readonly string[];
		localPorts: readonly number[];
		commandId: string;
		sourceEnvironment: SandboxSourceEnvironment;
		revalidatePermissions?: () => readonly NativeFilePermission[];
		command: string;
		cwd: string;
		onData: (data: Buffer) => void;
		signal?: AbortSignal;
		timeout?: number;
	}) {
		const request = yield* Effect.try({
			try: () => buildSandboxExecRequest(
				params.commandId,
				params.command,
				params.cwd,
				params.timeout,
				params.config,
				params.revalidatePermissions?.() ?? params.permissions,
				params.networkHosts,
				params.localPorts,
				params.sourceEnvironment,
			),
			catch: sandboxError,
		});
		const result = yield* (params.client.execEffect
			? params.client.execEffect(request, params.onData).pipe(Effect.mapError(sandboxError))
			: Effect.tryPromise({
				try: (effectSignal) => params.client.exec(request, params.onData, params.signal ?? effectSignal),
				catch: sandboxError,
			}));
		if (result.exitCode !== 0) {
			const summary = formatDenialSummary(result.denials, result.denialsComplete);
			if (summary) yield* Effect.sync(() => params.onData(Buffer.from(summary)));
		}
		return result;
	},
);

interface NativeSandboxOpsOptions {
	sourceEnvironment: SandboxSourceEnvironment;
	revalidatePermissions?: () => readonly NativeFilePermission[];
}

/** Executes exactly once. Access changes are separate request_access tool calls. */
export function createNativeSandboxOps(
	client: SandboxExecutor,
	config: NativeSandboxConfig,
	permissions: readonly NativeFilePermission[],
	networkHosts: readonly string[],
	localPorts: readonly number[],
	commandId: string,
	options: NativeSandboxOpsOptions,
): BashOperations {
	return {
		exec(command, cwd, { onData, signal, timeout }) {
			return Effect.runPromise(Effect.scoped(executeNativeSandboxCommand({
				client,
				config,
				permissions,
				networkHosts,
				localPorts,
				commandId,
				sourceEnvironment: options.sourceEnvironment,
				revalidatePermissions: options.revalidatePermissions,
				command,
				cwd,
				onData,
				signal,
				timeout,
			})), { signal });
		},
	};
}
