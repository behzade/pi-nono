/** Native command sandbox with host-owned project and session access policy. */

import { randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, resolve } from "node:path";
import type {
	ExtensionAPI,
	ExtensionContext,
	ToolCallEvent,
} from "@earendil-works/pi-coding-agent";
import { Effect, ManagedRuntime } from "effect";
import {
	type BashOperations,
	createBashTool,
	getAgentDir,
} from "@earendil-works/pi-coding-agent";
import {
	formatProcessSnapshot,
	modelVisibleProcessOutput,
	notifyProcessSettlement,
	processSessionDetails,
} from "./process-sessions.ts";
import { registerAccessRequest } from "./access-request.ts";
import {
	captureLaunchEnvironment,
	DEFAULT_CONFIG,
	filesystemAccessMode,
	type NativeSandboxConfig,
	mergeGlobalConfig,
	networkAccessMode,
	normalizeConfig,
	parseFilesystemAccessMode,
	parseNetworkAccessMode,
	restoreCapturedShellEnvironment,
	withAccessModes,
} from "./sandbox-config.ts";
import {
	canonicalize,
	gitControlRoot,
	isControlRootSymlink,
	isProtectedPath,
	isProtectedWritePath,
	permissionCoversPath,
	projectControlRoot,
	resolveLexicalPermissionPath,
} from "./io-permissions.ts";
import {
	isBaseReadAllowed,
	isBaseWriteAllowed,
	isDeniedByConfig,
} from "./io-policy.ts";
import { createNativeSandboxOps } from "./native-sandbox-ops.ts";
import {
	hostBash,
	type SandboxSourceEnvironment,
} from "./sandbox-policy.ts";
import {
	decodeSandboxModeRequest,
	SANDBOX_MODE_STATUS_KEY,
	sandboxModeError,
	sandboxModeResult,
} from "./sandbox-mode.ts";
import {
	SandboxRuntime,
	sandboxRuntimeLayer,
	type CapturedAccessPolicy,
	type SandboxRuntimeStatus,
} from "./sandbox-runtime.ts";
import { runtimeNetworkHosts } from "./network-policy.ts";
import {
	registerApprovalSession,
	unregisterApprovalSession,
} from "./approval-transport.ts";
import {
	BashParams,
	ProcessParams,
} from "./tool-schemas.ts";
import {
	projectPolicyPath,
	type ActiveProjectPolicy,
	type ProjectAccessRight,
} from "./project-policy.ts";
import { sessionPolicyPath } from "./session-policy-store.ts";

function readGlobalConfig(): NativeSandboxConfig {
	const path = resolve(homedir(), ".config", "pi-nono", "sandbox.json");
	const legacy = resolve(getAgentDir(), "extensions", "sandbox.json");
	const source = existsSync(path) ? path : legacy;
	if (!existsSync(source)) return mergeGlobalConfig(DEFAULT_CONFIG, {});
	const parsed: unknown = JSON.parse(readFileSync(source, "utf8"));
	return mergeGlobalConfig(DEFAULT_CONFIG, normalizeConfig(parsed));
}

function unavailableBashOps(reason: string): BashOperations {
	return { async exec() { throw new Error(reason); } };
}

const AUTO_DETACH_MS = 5_000;

function createCapturedLocalBash(
	cwd: string,
	environment: SandboxSourceEnvironment,
) {
	return createBashTool(cwd, {
		shellPath: hostBash(environment),
		spawnHook: (invocation) => ({
			...invocation,
			env: restoreCapturedShellEnvironment(environment, invocation.env),
		}),
	});
}

export default function (pi: ExtensionAPI) {
	pi.registerFlag("no-sandbox", {
		description: "Disable OS-level sandboxing for bash commands",
		type: "boolean",
		default: false,
	});
	pi.registerFlag("sandbox-files", {
		description: "Filesystem access: read-only, sandboxed, or full",
		type: "string",
		default: "sandboxed",
	});
	pi.registerFlag("sandbox-network", {
		description: "Network access: sandboxed or full",
		type: "string",
		default: "sandboxed",
	});

	const localCwd = process.cwd();
	const localBash = createBashTool(localCwd);
	const sandbox = ManagedRuntime.make(sandboxRuntimeLayer({
		onProcessSettled: (settlement) => notifyProcessSettlement(pi, settlement),
	}));
	let userBashCounter = 0;
	let approvalContext: ExtensionContext | undefined;

	const activeAccess = () => sandbox.runSync(
		SandboxRuntime.use((runtime) => runtime.activeAccess),
	);
	const runtimeStatus = (): SandboxRuntimeStatus => sandbox.runSync(
		SandboxRuntime.use((runtime) => runtime.status),
	);
	const networkHosts = (policy: ActiveProjectPolicy) =>
		runtimeNetworkHosts(policy.config, policy.networkHosts);
	const updateSandboxStatus = (ctx: ExtensionContext, config: NativeSandboxConfig): void => {
		if (filesystemAccessMode(config) === "full" && networkAccessMode(config) === "full") {
			ctx.ui.setStatus("sandbox", ctx.ui.theme.fg("warning", "Sandbox off · full access"));
			return;
		}
		const backendLabel = `nono ${process.platform === "linux" ? "Landlock" : "Seatbelt"}`;
		ctx.ui.setStatus("sandbox", ctx.ui.theme.fg("accent", `🔒 ${backendLabel}`));
	};

	registerAccessRequest(pi, activeAccess);

	pi.registerTool({
		name: "process",
		label: "Process session",
		description:
			"Inspect or interact with a sandboxed process session returned by bash. Optionally write stdin, close stdin, or signal the process group. Returns immediately; completion wakes the agent automatically. Existing sessions keep the immutable policy captured by bash.",
		promptSnippet:
			"Inspect or interact with a detached bash process. Never poll or wait; completion wakes the agent automatically.",
		parameters: ProcessParams,
		executionMode: "sequential",
		async execute(_toolCallId, params) {
			try {
				const processSessions = await sandbox.runPromise(
					SandboxRuntime.use((runtime) => runtime.processSessions),
				);
				const snapshot = await processSessions.continue(params.id, {
					...(params.input === undefined ? {} : { input: params.input }),
					...(params.close_stdin === undefined ? {} : { closeStdin: params.close_stdin }),
					...(params.signal === undefined ? {} : { signal: params.signal }),
				});
				return {
					content: [{ type: "text", text: formatProcessSnapshot(snapshot) }],
					details: processSessionDetails(snapshot),
				};
			} catch (error) {
				return toolError(errorMessage(error));
			}
		},
	});

	pi.registerTool({
		...localBash,
		label: "bash (OS sandbox)",
		description:
			"Execute one bash command with the active project and Pi-session sandbox policy. Sandboxed commands still running after five seconds detach automatically and wake the agent on completion. The call cannot declare rights and is never automatically retried. Use request_access separately after a denial.",
		promptSnippet:
			"Run once under the active policy. Long sandboxed commands detach automatically and wake you on completion; never poll. On denial, request the smallest right and explicitly rerun later.",
		parameters: BashParams,
		executionMode: "sequential",
		renderShell: "self",
		async execute(id, params, signal, onUpdate, ctx) {
			const commandPolicy = await sandbox.runPromise(
				SandboxRuntime.use((runtime) => runtime.captureCommand),
			);
			if (commandPolicy.kind === "local") {
				return createCapturedLocalBash(localCwd, commandPolicy.environment)
					.execute(id, params, signal, onUpdate, ctx);
			}
			const sessionId = await commandPolicy.processSessions.start({
				command: params.command,
				cwd: ctx?.cwd ?? localCwd,
				...(params.timeout === undefined ? {} : { timeout: params.timeout }),
				config: commandPolicy.policy.config,
				permissions: commandPolicy.policy.filesystem,
				revalidatePermissions: commandPolicy.revalidatePermissions,
				networkHosts: networkHosts(commandPolicy.policy),
				localPorts: commandPolicy.policy.localPorts,
			}, signal);
			const snapshot = await commandPolicy.processSessions.detachAfter(sessionId, AUTO_DETACH_MS, signal);
			if (snapshot.state === "running") {
				return {
					content: [{ type: "text", text: formatProcessSnapshot(snapshot) }],
					details: processSessionDetails(snapshot),
				};
			}
			const output = modelVisibleProcessOutput(snapshot.output).trimEnd() || "(no output)";
			if (snapshot.state === "failed") {
				throw new Error(`${output}\n\nCommand failed: ${snapshot.error ?? "unknown error"}`);
			}
			if (snapshot.state === "exited") {
				throw new Error(`${output}\n\nCommand exited with code ${snapshot.exitCode ?? 1}`);
			}
			if (snapshot.state === "stopped") throw new Error(`${output}\n\nCommand aborted`);
			return { content: [{ type: "text", text: output }], details: undefined };
		},
	});

	pi.on("tool_call", async (event, ctx) => {
		const status = runtimeStatus();
		if (status.kind === "disabled") return;
		if (!["read", "write", "edit", "grep", "find", "ls"].includes(event.toolName)) return;
		if (status.kind === "ready" && filesystemAccessMode(status.config) === "full") return;
		if (status.kind !== "ready") {
			return {
				block: true,
				reason: status.kind === "failed"
					? status.reason
					: "Sandbox access is not ready; file operation blocked",
			};
		}
		if (event.toolName === "grep" || event.toolName === "find") {
			return {
				block: true,
				reason: `Use ${event.toolName === "grep" ? "rg" : "fd"} through bash; this recursive host tool cannot enforce the sandbox policy. If bash is denied, use request_access and rerun explicitly.`,
			};
		}
		const lexicalPath = toolLexicalPath(event, ctx.cwd);
		if (!lexicalPath) return { block: true, reason: "File path is missing" };
		const path = canonicalize(lexicalPath);
		const access = event.toolName === "write" || event.toolName === "edit" ? "write" : "read";
		let captured: CapturedAccessPolicy;
		try {
			captured = await sandbox.runPromise(
				SandboxRuntime.use((runtime) => runtime.captureAccess),
			);
		} catch (error) {
			return { block: true, reason: errorMessage(error) };
		}
		const config = captured.policy.config;
		if (filesystemAccessMode(config) === "read-only" && access === "write") {
			return {
				block: true,
				reason: `Files are read-only. Change Files to Sandboxed or Full before writing ${path}.`,
			};
		}
		if (
			isProtectedPath(lexicalPath) ||
			(access === "write" && isProtectedWritePath(lexicalPath)) ||
			isDeniedByConfig(path, access, config, ctx.cwd)
		) {
			return { block: true, reason: `Protected or machine-denied ${access} path cannot be granted: ${path}` };
		}
		const gitRoot = access === "write" ? gitControlRoot(lexicalPath, ctx.cwd) : undefined;
		const projectRoot = access === "write" ? projectControlRoot(lexicalPath, ctx.cwd) : undefined;
		if (projectRoot) return { block: true, reason: `Sandboxed tools cannot write project ${basename(projectRoot)}; trusted host tools own that control folder.` };
		if (gitRoot && isControlRootSymlink(gitRoot)) {
			return { block: true, reason: `Writes to a symlinked control folder cannot be granted: ${gitRoot}` };
		}
		const controlRoot = gitRoot;
		const fileRights = captured.revalidatePermissions();
		const allowed = controlRoot
			? fileRights.some((permission) =>
				permission.kind === access && permission.directory && lexicalControlKey(permission.path) === lexicalControlKey(controlRoot))
			: fileRights.some((permission) =>
				(permission.kind === access || (access === "read" && permission.kind === "write")) && permissionCoversPath(permission, path)) ||
				(access === "read" ? isBaseReadAllowed(path, config, ctx.cwd) : isBaseWriteAllowed(path, config, ctx.cwd));
		if (!allowed) {
			return {
				block: true,
				reason: `Sandbox policy denied ${access} access to ${controlRoot ?? path}. Use request_access for the smallest file or tree right, then explicitly retry the file tool.`,
			};
		}
		if ("path" in event.input && typeof event.input.path === "string") event.input.path = path;
	});

	pi.on("user_bash", () => {
		try {
			const commandPolicy = sandbox.runSync(
				SandboxRuntime.use((runtime) => runtime.captureCommand),
			);
			if (commandPolicy.kind === "local") return;
			return {
				operations: createNativeSandboxOps(
					commandPolicy.client,
					commandPolicy.policy.config,
					commandPolicy.policy.filesystem,
					networkHosts(commandPolicy.policy),
					commandPolicy.policy.localPorts,
					`user-bash-${++userBashCounter}-${randomUUID()}`,
					{
						sourceEnvironment: commandPolicy.environment,
						revalidatePermissions: commandPolicy.revalidatePermissions,
					},
				),
			};
		} catch (error) {
			return { operations: unavailableBashOps(errorMessage(error)) };
		}
	});

	pi.on("session_start", async (_event, ctx) => {
		const environment = Object.freeze(captureLaunchEnvironment());
		if (approvalContext) unregisterApprovalSession(approvalContext);
		approvalContext = ctx;
		registerApprovalSession(ctx);
		if (pi.getFlag("no-sandbox") as boolean) {
			await sandbox.runPromise(SandboxRuntime.use((runtime) =>
				runtime.disable("disabled via --no-sandbox", environment),
			));
			ctx.ui.notify("Sandbox disabled via --no-sandbox", "warning");
			return;
		}
		try {
			const machineConfig = withAccessModes(
				readGlobalConfig(),
				parseFilesystemAccessMode(pi.getFlag("sandbox-files"), "--sandbox-files"),
				parseNetworkAccessMode(pi.getFlag("sandbox-network"), "--sandbox-network"),
			);
			if (!machineConfig.enabled) {
				await sandbox.runPromise(SandboxRuntime.use((runtime) =>
					runtime.disable("disabled via global config", environment),
				));
				ctx.ui.notify("Sandbox disabled via global config", "warning");
				return;
			}
			const sessionFile = ctx.sessionManager.getSessionFile();
			const config = await sandbox.runPromise(SandboxRuntime.use((runtime) =>
				runtime.initialize({
					cwd: ctx.cwd,
					machineConfig,
					trusted: ctx.isProjectTrusted(),
					...(sessionFile
						? { sessionIdentity: {
							sessionId: ctx.sessionManager.getSessionId(),
							sessionFile,
							cwd: ctx.cwd,
						} }
						: {}),
					environment,
				}),
			));
			updateSandboxStatus(ctx, config);
		} catch (error) {
			const reason = `Sandbox unavailable; commands are blocked: ${errorMessage(error)}`;
			await sandbox.runPromise(SandboxRuntime.use((runtime) => runtime.fail(reason)));
			ctx.ui.notify(reason, "error");
		}
	});

	pi.on("session_shutdown", async () => {
		if (approvalContext) unregisterApprovalSession(approvalContext);
		approvalContext = undefined;
		await sandbox.dispose();
		userBashCounter = 0;
	});

	pi.registerCommand("sandbox-mode", {
		description: "Change OS sandbox access for subsequent commands",
		handler: async (args, ctx) => {
			const program = decodeSandboxModeRequest(args).pipe(
				Effect.flatMap((request) => {
					const change = ctx.isIdle()
						? SandboxRuntime.use((runtime) => runtime.changeMode(request)).pipe(
							Effect.tap((config) => Effect.sync(() => updateSandboxStatus(ctx, config))),
						)
						: Effect.fail(sandboxModeError(
							"Wait for Pi to become idle before changing sandbox access",
						));
					return change.pipe(
						Effect.as(sandboxModeResult(request)),
						Effect.catch((error) => Effect.succeed(
							sandboxModeResult(request, error.message),
						)),
					);
				}),
				Effect.flatMap((result) => Effect.sync(() => {
					if (ctx.mode === "rpc") {
						ctx.ui.setStatus(SANDBOX_MODE_STATUS_KEY, JSON.stringify(result));
					} else {
						ctx.ui.notify(
							result.error ?? `Sandbox access changed to files=${result.files}, network=${result.network}`,
							result.success ? "info" : "error",
						);
					}
				})),
				Effect.catch((error) => Effect.sync(() => {
					ctx.ui.notify(error.message, "error");
				})),
			);
			await sandbox.runPromise(program);
		},
	});

	pi.registerCommand("sandbox", {
		description: "Show OS sandbox rights",
		handler: async (_args, ctx) => {
			const status = runtimeStatus();
			if (status.kind !== "ready") {
				ctx.ui.notify(
					status.kind === "disabled"
						? `Sandbox is ${status.reason}`
						: status.kind === "failed"
							? status.reason
							: "Sandbox is initializing",
					status.kind === "failed" ? "error" : "info",
				);
				return;
			}
			let captured: CapturedAccessPolicy;
			try {
				captured = await sandbox.runPromise(
					SandboxRuntime.use((runtime) => runtime.captureAccess),
				);
			} catch (error) {
				ctx.ui.notify(`Sandbox policy could not be synchronized: ${errorMessage(error)}`, "error");
				return;
			}
			const { access, policy } = captured;
			const networkMode = networkAccessMode(policy.config);
			ctx.ui.notify([
				"OS sandbox (nono):",
				`  Files: ${filesystemAccessMode(policy.config)}`,
				`  Network: ${networkMode}`,
				`  Project policy: ${projectPolicyPath(ctx.cwd)}`,
				`  Project rights: ${access.project.policy.rights.map(rightLabel).join(", ") || "(none)"}`,
				`  Session rights: ${access.session.policy.rights.map(rightLabel).join(", ") || "(none)"}`,
				`  Session policy: ${access.sessionIdentity ? sessionPolicyPath(access.sessionIdentity) : "ephemeral"}`,
				`  Network hosts: ${networkMode === "full" ? "(unrestricted)" : networkHosts(policy).join(", ") || "(blocked)"}`,
				`  Loopback ports: ${networkMode === "full" ? "(unrestricted)" : policy.localPorts.join(", ") || "(blocked)"}`,
				...(policy.inactive.length > 0
					? ["  Inactive grants:", ...policy.inactive.map((entry) => `    - ${entry}`)]
					: []),
				"  Denials: bounded diagnostics; no automatic retry",
			].join("\n"), "info");
		},
	});
}

function toolError(message: string) {
	return { content: [{ type: "text" as const, text: message }], isError: true };
}

function errorMessage(error: unknown): string {
	return error instanceof Error ? error.message : String(error);
}

function lexicalControlKey(path: string): string {
	return resolve(canonicalize(dirname(path)), basename(path));
}

function toolLexicalPath(event: ToolCallEvent, cwd: string): string | undefined {
	if (!("path" in event.input) || event.input.path === undefined) return event.toolName === "ls" ? resolve(cwd) : undefined;
	if (typeof event.input.path !== "string") return undefined;
	return resolveLexicalPermissionPath(event.input.path, cwd);
}

function rightLabel(right: ProjectAccessRight): string {
	if (right.kind === "filesystem") return `${right.access} ${right.scope} ${right.path}`;
	if (right.kind === "network_host") return `host ${right.host}`;
	return `endpoint ${right.host}:${right.port}`;
}
