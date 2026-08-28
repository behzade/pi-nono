import {
	Context,
	Effect,
	Exit,
	Layer,
	Scope,
	SynchronizedRef,
} from "effect";
import { ActiveAccessPolicy } from "./active-access-policy.ts";
import { FIXED_NONO_PATH } from "./fixed-executables.ts";
import { NonoClient } from "./nono-client.ts";
import { NativeProcessSessions } from "./native-process-sessions.ts";
import type { ProcessSessionSnapshot } from "./native-process-sessions.ts";
import {
	resolvePackagedExecutables,
	resolveSystemBubblewrap,
} from "./packaged-executables.ts";
import type { ActiveProjectPolicy } from "./project-policy.ts";
import {
	filesystemAccessMode,
	networkAccessMode,
	type NativeSandboxConfig,
	withAccessModes,
} from "./sandbox-config.ts";
import {
	sandboxModeError,
	type SandboxModeError,
	type SandboxModeRequest,
} from "./sandbox-mode.ts";
import type {
	NativeFilePermission,
	SandboxSourceEnvironment,
} from "./sandbox-policy.ts";
import type { SessionPolicyIdentity } from "./session-policy-store.ts";

export interface SandboxSessionInput {
	cwd: string;
	machineConfig: NativeSandboxConfig;
	trusted: boolean;
	sessionIdentity?: SessionPolicyIdentity;
	environment: SandboxSourceEnvironment;
}

export interface SandboxBackend {
	client: NonoClient;
	processSessions: NativeProcessSessions;
}

export type SandboxBackendFactory = (
	environment: SandboxSourceEnvironment,
	onSettled: (settlement: ProcessSessionSnapshot) => void,
) => Effect.Effect<SandboxBackend, SandboxModeError, Scope.Scope>;

export interface CapturedAccessPolicy {
	access: ActiveAccessPolicy;
	policy: ActiveProjectPolicy;
	environment: SandboxSourceEnvironment;
	revalidatePermissions: () => readonly NativeFilePermission[];
}

export type SandboxCommandPolicy =
	| {
		kind: "local";
		environment: SandboxSourceEnvironment;
	}
	| CapturedAccessPolicy & SandboxBackend & { kind: "sandboxed" };

export type SandboxRuntimeStatus =
	| { kind: "disabled"; reason: string }
	| { kind: "initializing" }
	| { kind: "transitioning" }
	| { kind: "failed"; reason: string }
	| { kind: "ready"; config: NativeSandboxConfig };

interface ReadyState {
	kind: "ready";
	session: SandboxSessionInput;
	access: ActiveAccessPolicy;
	backend?: SandboxBackend;
	scope: Scope.Closeable;
}

type RuntimeState =
	| { kind: "disabled"; reason: string; environment: SandboxSourceEnvironment }
	| { kind: "initializing"; token: symbol; scope?: Scope.Closeable }
	| { kind: "transitioning"; token: symbol; previous: ReadyState }
	| { kind: "failed"; reason: string }
	| ReadyState;

export interface SandboxRuntimeService {
	readonly status: Effect.Effect<SandboxRuntimeStatus>;
	readonly activeAccess: Effect.Effect<ActiveAccessPolicy, SandboxModeError>;
	readonly processSessions: Effect.Effect<NativeProcessSessions, SandboxModeError>;
	readonly disable: (
		reason: string,
		environment: SandboxSourceEnvironment,
	) => Effect.Effect<void>;
	readonly fail: (reason: string) => Effect.Effect<void>;
	readonly initialize: (
		input: SandboxSessionInput,
	) => Effect.Effect<NativeSandboxConfig, SandboxModeError>;
	readonly changeMode: (
		request: SandboxModeRequest,
	) => Effect.Effect<NativeSandboxConfig, SandboxModeError>;
	readonly captureAccess: Effect.Effect<CapturedAccessPolicy, SandboxModeError>;
	readonly captureCommand: Effect.Effect<SandboxCommandPolicy, SandboxModeError>;
}

export class SandboxRuntime extends Context.Service<
	SandboxRuntime,
	SandboxRuntimeService
>()("pi-nono/SandboxRuntime") {}

export interface SandboxRuntimeLayerOptions {
	onProcessSettled?: (settlement: ProcessSessionSnapshot) => void;
	acquireBackend?: SandboxBackendFactory;
	loadAccessPolicy?: (input: SandboxSessionInput) => ActiveAccessPolicy;
}

export function sandboxRuntimeLayer(
	options: SandboxRuntimeLayerOptions,
): Layer.Layer<SandboxRuntime> {
	return Layer.effect(SandboxRuntime, Effect.gen(function* () {
		const state = yield* SynchronizedRef.make<RuntimeState>({
			kind: "initializing",
			token: Symbol("initial"),
		});
		const acquireBackend = options.acquireBackend ?? nativeSandboxBackend;
		const loadAccessPolicy = options.loadAccessPolicy ?? ((input: SandboxSessionInput) =>
			ActiveAccessPolicy.load(
				input.cwd,
				input.machineConfig,
				input.trusted,
				input.sessionIdentity,
			));

		const replaceState = Effect.fn("SandboxRuntime.replaceState")(function* (
			next: RuntimeState,
		) {
			const previous = yield* SynchronizedRef.getAndSet(state, next);
			const previousScope = stateScope(previous);
			const nextScope = stateScope(next);
			if (previousScope && previousScope !== nextScope) {
				yield* Scope.close(previousScope, Exit.void);
			}
		});

		const disable = Effect.fn("SandboxRuntime.disable")(function* (
			reason: string,
			environment: SandboxSourceEnvironment,
		) {
			yield* replaceState({ kind: "disabled", reason, environment });
		});

		const fail = Effect.fn("SandboxRuntime.fail")(function* (reason: string) {
			yield* replaceState({ kind: "failed", reason });
		});

		const initialize = Effect.fn("SandboxRuntime.initialize")(function* (
			input: SandboxSessionInput,
		) {
			const token = Symbol("session");
			const scope = Scope.makeUnsafe();
			yield* replaceState({ kind: "initializing", token, scope });

			const setup = Effect.gen(function* () {
				const access = yield* Effect.try({
					try: () => loadAccessPolicy(input),
					catch: (cause) => sandboxModeError(errorMessage(cause), cause),
				});
				let backend: SandboxBackend | undefined;
				if (!isFullAccess(input.machineConfig)) {
					backend = yield* acquireBackend(
						input.environment,
						activeSettlementHandler(state, scope, options.onProcessSettled),
					).pipe(Effect.provideService(Scope.Scope, scope));
				}
				const ready: ReadyState = {
					kind: "ready",
					session: input,
					access,
					...(backend ? { backend } : {}),
					scope,
				};
				const committed = yield* SynchronizedRef.modify(state, (current) =>
					current.kind === "initializing" && current.token === token
						? [true, ready] as const
						: [false, current] as const,
				);
				if (!committed) {
					yield* Scope.close(scope, Exit.void);
					return yield* sandboxModeError("Sandbox session changed while initializing");
				}
				return access.effective.config;
			});

			return yield* setup.pipe(Effect.catch((error) =>
				Effect.gen(function* () {
					yield* Scope.close(scope, Exit.void);
					yield* SynchronizedRef.update(state, (current): RuntimeState =>
						current.kind === "initializing" && current.token === token
							? { kind: "failed", reason: error.message }
							: current,
					);
					return yield* error;
				}),
			));
		});

		const changeMode = Effect.fn("SandboxRuntime.changeMode")(function* (
			request: SandboxModeRequest,
		) {
			const token = Symbol("mode");
			const previous = yield* SynchronizedRef.modifyEffect(state, (current) => {
				if (current.kind !== "ready") {
					return Effect.fail(stateError(current));
				}
				return Effect.succeed([
					current,
					{ kind: "transitioning", token, previous: current } satisfies RuntimeState,
				] as const);
			});

			const transition = Effect.gen(function* () {
				const machineConfig = withAccessModes(
					previous.session.machineConfig,
					request.files,
					request.network,
				);
				const session = { ...previous.session, machineConfig };
				const access = yield* Effect.try({
					try: () => loadAccessPolicy(session),
					catch: (cause) => sandboxModeError(errorMessage(cause), cause),
				});
				let backend = previous.backend;
				if (!isFullAccess(machineConfig) && !backend) {
					backend = yield* acquireBackend(
						session.environment,
						activeSettlementHandler(state, previous.scope, options.onProcessSettled),
					).pipe(Effect.provideService(Scope.Scope, previous.scope));
				}
				const ready: ReadyState = {
					kind: "ready",
					session,
					access,
					...(backend ? { backend } : {}),
					scope: previous.scope,
				};
				const committed = yield* SynchronizedRef.modify(state, (current) =>
					current.kind === "transitioning" && current.token === token
						? [true, ready] as const
						: [false, current] as const,
				);
				if (!committed) {
					return yield* sandboxModeError(
						"Sandbox session changed while applying access modes",
					);
				}
				return access.effective.config;
			});

			return yield* transition.pipe(Effect.catch((error) =>
				SynchronizedRef.update(state, (current): RuntimeState =>
					current.kind === "transitioning" && current.token === token
						? previous
						: current,
				).pipe(Effect.andThen(Effect.fail(error))),
			));
		});

		const captureAccess = SynchronizedRef.modifyEffect(state, captureAccessState);
		const captureCommand = SynchronizedRef.modifyEffect(state, (current) => {
			if (current.kind === "disabled") {
				return Effect.succeed([
					{ kind: "local", environment: current.environment } satisfies SandboxCommandPolicy,
					current,
				] as const);
			}
			if (current.kind !== "ready") return Effect.fail(stateError(current));
			if (isFullAccess(current.access.effective.config)) {
				return Effect.succeed([
					{ kind: "local", environment: current.session.environment } satisfies SandboxCommandPolicy,
					current,
				] as const);
			}
			if (!current.backend) {
				return Effect.fail(sandboxModeError("Nono sandbox is not ready"));
			}
			return captureReadyAccess(current).pipe(Effect.map(([captured, next]) => [{
				...captured,
				...current.backend,
				kind: "sandboxed",
			} satisfies SandboxCommandPolicy, next] as const));
		});

		const service: SandboxRuntimeService = {
			status: SynchronizedRef.get(state).pipe(Effect.map(runtimeStatus)),
			activeAccess: SynchronizedRef.get(state).pipe(Effect.flatMap((current) =>
				current.kind === "ready"
					? Effect.succeed(current.access)
					: Effect.fail(stateError(current)),
			)),
			processSessions: SynchronizedRef.get(state).pipe(Effect.flatMap((current) => {
				const backend = current.kind === "ready"
					? current.backend
					: current.kind === "transitioning"
						? current.previous.backend
						: undefined;
				return backend
					? Effect.succeed(backend.processSessions)
					: Effect.fail(sandboxModeError("The native sandbox is not ready"));
			})),
			disable,
			fail,
			initialize,
			changeMode,
			captureAccess,
			captureCommand,
		};
		yield* Effect.addFinalizer(() => replaceState({
			kind: "initializing",
			token: Symbol("closed"),
		}));
		return service;
	}));
}

function captureAccessState(
	current: RuntimeState,
): Effect.Effect<readonly [CapturedAccessPolicy, RuntimeState], SandboxModeError> {
	if (current.kind !== "ready") return Effect.fail(stateError(current));
	return captureReadyAccess(current);
}

function captureReadyAccess(
	current: ReadyState,
): Effect.Effect<readonly [CapturedAccessPolicy, RuntimeState], SandboxModeError> {
	return Effect.try({
		try: () => {
			const policy = current.access.synchronize();
			const captured: CapturedAccessPolicy = {
				access: current.access,
				policy,
				environment: current.session.environment,
				revalidatePermissions: () => current.access.revalidate(policy).filesystem,
			};
			return [captured, current] as const;
		},
		catch: (cause) => sandboxModeError(errorMessage(cause), cause),
	});
}

function runtimeStatus(state: RuntimeState): SandboxRuntimeStatus {
	switch (state.kind) {
		case "disabled": return { kind: "disabled", reason: state.reason };
		case "initializing": return { kind: "initializing" };
		case "transitioning": return { kind: "transitioning" };
		case "failed": return { kind: "failed", reason: state.reason };
		case "ready": return { kind: "ready", config: state.access.effective.config };
	}
}

function stateError(state: RuntimeState): SandboxModeError {
	switch (state.kind) {
		case "disabled": return sandboxModeError(`Sandbox is ${state.reason}`);
		case "initializing": return sandboxModeError("Sandbox is still initializing; command blocked");
		case "transitioning": return sandboxModeError("Sandbox access is changing; command blocked");
		case "failed": return sandboxModeError(state.reason);
		case "ready": return sandboxModeError("Sandbox is not ready");
	}
}

function stateScope(state: RuntimeState): Scope.Closeable | undefined {
	if (state.kind === "ready") return state.scope;
	if (state.kind === "transitioning") return state.previous.scope;
	if (state.kind === "initializing") return state.scope;
	return undefined;
}

function activeSettlementHandler(
	state: SynchronizedRef.SynchronizedRef<RuntimeState>,
	scope: Scope.Closeable,
	onSettled: ((settlement: ProcessSessionSnapshot) => void) | undefined,
): (settlement: ProcessSessionSnapshot) => void {
	return (settlement) => {
		if (stateScope(SynchronizedRef.getUnsafe(state)) === scope) onSettled?.(settlement);
	};
}

function isFullAccess(config: NativeSandboxConfig): boolean {
	return filesystemAccessMode(config) === "full" && networkAccessMode(config) === "full";
}

const nativeSandboxBackend: SandboxBackendFactory = (environment, onSettled) => {
	if (process.platform !== "darwin" && process.platform !== "linux") {
		return Effect.fail(sandboxModeError("The native sandbox supports macOS and Linux only"));
	}
	return Effect.acquireRelease(
		Effect.gen(function* () {
			const executables = yield* Effect.try({
				try: fixedPackagedExecutables,
				catch: (cause) => sandboxModeError(errorMessage(cause), cause),
			});
			const client = yield* Effect.tryPromise({
				try: () => NonoClient.start(executables.nonoPath, executables.bwrapPath),
				catch: (cause) => sandboxModeError(errorMessage(cause), cause),
			});
			return yield* Effect.try({
				try: () => ({
					client,
					processSessions: new NativeProcessSessions(client, environment, onSettled),
				}),
				catch: (cause) => sandboxModeError(errorMessage(cause), cause),
			}).pipe(Effect.onError(() => Effect.promise(() => client.shutdown())));
		}),
		(backend) => Effect.promise(() => backend.processSessions.shutdown()).pipe(
			Effect.ensuring(Effect.promise(() => backend.client.shutdown())),
		),
	);
};

function fixedPackagedExecutables(): { nonoPath: string; bwrapPath: string } {
	if (FIXED_NONO_PATH !== null) {
		return { nonoPath: FIXED_NONO_PATH, bwrapPath: resolveSystemBubblewrap() };
	}
	return resolvePackagedExecutables();
}

function errorMessage(error: unknown): string {
	return error instanceof Error ? error.message : String(error);
}
