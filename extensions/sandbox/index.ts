/** Native command sandbox with checked-in project access policy. */

import { randomUUID } from "node:crypto";
import { existsSync, readFileSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, resolve } from "node:path";
import type {
	ExtensionAPI,
	ExtensionContext,
	ToolCallEvent,
} from "@earendil-works/pi-coding-agent";
import {
	type BashOperations,
	createBashTool,
	getAgentDir,
} from "@earendil-works/pi-coding-agent";
import { NonoClient } from "./nono-client.ts";
import {
	backgroundKeyBytes,
	isValidBackgroundJobName,
	modelVisibleBackgroundJobOutput,
	notifyBackgroundJobSettlement,
} from "./background-jobs.ts";
import { developmentCacheRoot } from "./development-caches.ts";
import { ActiveAccessPolicy } from "./active-access-policy.ts";
import { registerAccessRequest } from "./access-request.ts";
import {
	DEFAULT_CONFIG,
	type NativeSandboxConfig,
	mergeGlobalConfig,
	normalizeConfig,
} from "./sandbox-config.ts";
import {
	canonicalize,
	gitControlRoot,
	isControlRootSymlink,
	isInside,
	isProtectedPath,
	isProtectedWritePath,
	permissionCoversPath,
	projectControlRoot,
	resolveLexicalPermissionPath,
	resolvePermissionPath,
} from "./io-permissions.ts";
import {
	isBaseReadAllowed,
	isBaseWriteAllowed,
	isDeniedByConfig,
} from "./io-policy.ts";
import { createNativeSandboxOps } from "./native-sandbox-ops.ts";
import type { SandboxSourceEnvironment } from "./sandbox-policy.ts";
import { runtimeNetworkHosts } from "./network-policy.ts";
import {
	registerApprovalSession,
	unregisterApprovalSession,
} from "./approval-transport.ts";
import { NativeBackgroundJobs } from "./native-background-jobs.ts";
import {
	BackgroundJobParams,
	BashParams,
	validateBackgroundJobParams,
} from "./tool-schemas.ts";
import {
	projectPolicyPath,
	type ActiveProjectPolicy,
	type ProjectAccessRight,
} from "./project-policy.ts";
import { sessionPolicyPath } from "./session-policy-store.ts";
import {
	resolvePackagedExecutables,
	resolveSystemBubblewrap,
} from "./packaged-executables.ts";
import { FIXED_NONO_PATH } from "./fixed-executables.ts";

function readGlobalConfig(): NativeSandboxConfig {
	const path = resolve(homedir(), ".config", "guardian", "sandbox.json");
	const legacy = resolve(getAgentDir(), "extensions", "sandbox.json");
	const source = existsSync(path) ? path : legacy;
	if (!existsSync(source)) return mergeGlobalConfig(DEFAULT_CONFIG, {});
	const parsed: unknown = JSON.parse(readFileSync(source, "utf8"));
	return mergeGlobalConfig(DEFAULT_CONFIG, normalizeConfig(parsed));
}

function unavailableBashOps(reason: string): BashOperations {
	return { async exec() { throw new Error(reason); } };
}

type SandboxState =
	| { kind: "disabled"; reason: string }
	| { kind: "initializing" }
	| {
			kind: "ready";
			config: NativeSandboxConfig;
			machineConfig: NativeSandboxConfig;
			environment: SandboxSourceEnvironment;
	  }
	| { kind: "failed"; reason: string };

export default function (pi: ExtensionAPI) {
	pi.registerFlag("no-sandbox", {
		description: "Disable OS-level sandboxing for bash commands",
		type: "boolean",
		default: false,
	});

	const localCwd = process.cwd();
	const localBash = createBashTool(localCwd);
	let sandboxState: SandboxState = { kind: "initializing" };
	let accessPolicy: ActiveAccessPolicy | undefined;
	let nonoClient: NonoClient | undefined;
	let backgroundJobs: NativeBackgroundJobs | undefined;
	let userBashCounter = 0;
	let sessionGeneration = 0;
	let approvalContext: ExtensionContext | undefined;

	const activeAccess = (): ActiveAccessPolicy => {
		if (sandboxState.kind !== "ready" || !accessPolicy) throw new Error("Sandbox is not ready");
		return accessPolicy;
	};
	const setEffectiveConfig = (config: NativeSandboxConfig): void => {
		sandboxState = { ...requireReadyState(sandboxState), config };
	};
	const synchronizeAccess = (): ActiveProjectPolicy => {
		const effective = activeAccess().synchronize();
		setEffectiveConfig(effective.config);
		return effective;
	};
	const networkHosts = (policy: ActiveProjectPolicy = activeAccess().effective) =>
		runtimeNetworkHosts(policy.config, policy.networkHosts);

	registerAccessRequest(pi, activeAccess, setEffectiveConfig);

	pi.registerTool({
		name: "background_job",
		label: "Background job",
		description:
			"Start, list, inspect, interact with, or stop a session-scoped long-running command. New jobs capture the active project and Pi-session rights at start; existing jobs keep their start policy. Job completion is delivered automatically.",
		promptSnippet:
			"Use background_job for long-running servers, watchers, builds, and tests. Completion wakes the agent automatically; do not poll. Use request_access separately if policy must change, then start a new job.",
		parameters: BackgroundJobParams,
		executionMode: "sequential",
		async execute(_toolCallId, params, signal, _onUpdate, ctx) {
			const validated = validateBackgroundJobParams(params);
			if (typeof validated === "string") return toolError(validated);
			if ("name" in validated && !isValidBackgroundJobName(validated.name)) {
				return toolError("Job names must start with pi- and use only letters, digits, dots, underscores, or hyphens.");
			}
			if (sandboxState.kind !== "ready" || !backgroundJobs) return toolError("The native sandbox is not ready.");
			try {
				let output: string;
				if (validated.action === "start") {
					const cwd = resolvePermissionPath(validated.cwd ?? ctx.cwd, ctx.cwd);
					if (!isInside(canonicalize(ctx.cwd), cwd)) throw new Error("Background jobs must start inside the current workspace.");
					if (!existsSync(cwd) || !statSync(cwd).isDirectory()) throw new Error(`Background job directory does not exist: ${cwd}`);
					const policyAtStart = synchronizeAccess();
					output = await backgroundJobs.start({
						name: validated.name,
						command: validated.command,
						cwd,
						config: policyAtStart.config,
						permissions: policyAtStart.filesystem,
						revalidatePermissions: () => activeAccess().revalidate(policyAtStart).filesystem,
						networkHosts: networkHosts(policyAtStart),
						localPorts: policyAtStart.localPorts,
					}, signal);
				} else if (validated.action === "list") output = backgroundJobs.list();
				else if (validated.action === "status") output = backgroundJobs.status(validated.name);
				else if (validated.action === "read") output = modelVisibleBackgroundJobOutput("read", backgroundJobs.read(validated.name, validated.lines ?? 200));
				else if (validated.action === "write") output = backgroundJobs.write(validated.name, Buffer.from(validated.text));
				else if (validated.action === "line") output = backgroundJobs.write(validated.name, Buffer.from(`${validated.text}\n`));
				else if (validated.action === "keys") output = backgroundJobs.write(validated.name, backgroundKeyBytes(validated.keys));
				else output = await backgroundJobs.stop(validated.name);
				return { content: [{ type: "text", text: output || "Done" }], details: { action: validated.action } };
			} catch (error) {
				return toolError(errorMessage(error));
			}
		},
	});

	pi.registerTool({
		...localBash,
		label: "bash (OS sandbox)",
		description:
			"Execute one bash command with the active project and Pi-session sandbox policy. The call cannot declare rights and is never automatically retried. Use request_access separately after a denial.",
		promptSnippet:
			"Run once under the active policy. On denial, inspect the bounded summary, request the smallest right, and explicitly rerun later. Prefer managed development caches over host cache grants.",
		parameters: BashParams,
		executionMode: "sequential",
		renderShell: "self",
		async execute(id, params, signal, onUpdate) {
			if (sandboxState.kind === "disabled") return localBash.execute(id, params, signal, onUpdate);
			if (sandboxState.kind !== "ready") throw new Error(sandboxState.kind === "failed" ? sandboxState.reason : "Sandbox is still initializing; command blocked");
			if (!nonoClient) throw new Error("Nono sandbox is not ready");
			const policyAtStart = synchronizeAccess();
			const operations = createNativeSandboxOps(
				nonoClient,
				policyAtStart.config,
				policyAtStart.filesystem,
				networkHosts(policyAtStart),
				policyAtStart.localPorts,
				id,
				{
					sourceEnvironment: requireReadyState(sandboxState).environment,
					revalidatePermissions: () => activeAccess().revalidate(policyAtStart).filesystem,
				},
			);
			return createBashTool(localCwd, { operations }).execute(id, params, signal, onUpdate);
		},
	});

	pi.on("tool_call", async (event, ctx) => {
		if (sandboxState.kind === "disabled") return;
		if (!["read", "write", "edit", "grep", "find", "ls"].includes(event.toolName)) return;
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
		const synchronizedPolicy = synchronizeAccess();
		const config = activeConfig(sandboxState);
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
		const fileRights = activeAccess().revalidate(synchronizedPolicy).filesystem;
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
		if (sandboxState.kind === "disabled") return;
		if (sandboxState.kind === "ready") {
			if (!nonoClient) return { operations: unavailableBashOps("Nono sandbox is not ready") };
			try {
				const policyAtStart = synchronizeAccess();
				return {
					operations: createNativeSandboxOps(
						nonoClient,
						policyAtStart.config,
						policyAtStart.filesystem,
						networkHosts(policyAtStart),
						policyAtStart.localPorts,
						`user-bash-${++userBashCounter}-${randomUUID()}`,
						{
							sourceEnvironment: requireReadyState(sandboxState).environment,
							revalidatePermissions: () => activeAccess().revalidate(policyAtStart).filesystem,
						},
					),
				};
			} catch (error) {
				return { operations: unavailableBashOps(errorMessage(error)) };
			}
		}
		return { operations: unavailableBashOps(sandboxState.kind === "failed" ? sandboxState.reason : "Sandbox is still initializing; command blocked") };
	});

	pi.on("session_start", async (_event, ctx) => {
		const generation = ++sessionGeneration;
		const sessionEnvironment: SandboxSourceEnvironment = Object.freeze({ ...process.env });
		if (approvalContext) unregisterApprovalSession(approvalContext);
		approvalContext = ctx;
		registerApprovalSession(ctx);
		if (pi.getFlag("no-sandbox") as boolean) {
			sandboxState = { kind: "disabled", reason: "disabled via --no-sandbox" };
			ctx.ui.notify("Sandbox disabled via --no-sandbox", "warning");
			return;
		}
		try {
			const machineConfig = readGlobalConfig();
			if (!machineConfig.enabled) {
				sandboxState = { kind: "disabled", reason: "disabled via global config" };
				ctx.ui.notify("Sandbox disabled via global config", "warning");
				return;
			}
			const sessionFile = ctx.sessionManager.getSessionFile();
			accessPolicy = ActiveAccessPolicy.load(
				ctx.cwd,
				machineConfig,
				ctx.isProjectTrusted(),
				sessionFile
					? { sessionId: ctx.sessionManager.getSessionId(), sessionFile, cwd: ctx.cwd }
					: undefined,
			);
			sandboxState = { kind: "initializing" };
			if (process.platform !== "darwin" && process.platform !== "linux") throw new Error("the native sandbox supports macOS and Linux only");
			const packagedExecutables = fixedPackagedExecutables();
			const nonoPath = packagedExecutables.nonoPath;
			const client = await NonoClient.start(nonoPath, packagedExecutables.bwrapPath);
			if (generation !== sessionGeneration) { await client.shutdown(); return; }
			nonoClient = client;
			backgroundJobs = new NativeBackgroundJobs(
				nonoPath,
				packagedExecutables.bwrapPath,
				sessionEnvironment,
				(settlement) => {
					if (generation === sessionGeneration) notifyBackgroundJobSettlement(pi, settlement);
				},
			);
			sandboxState = {
				kind: "ready",
				config: accessPolicy.effective.config,
				machineConfig,
				environment: sessionEnvironment,
			};
			const backendLabel = `nono ${process.platform === "linux" ? "Landlock" : "Seatbelt"}`;
			ctx.ui.setStatus("sandbox", ctx.ui.theme.fg("accent", `🔒 ${backendLabel}`));
		} catch (error) {
			if (generation !== sessionGeneration) return;
			const reason = `Sandbox unavailable; commands are blocked: ${errorMessage(error)}`;
			sandboxState = { kind: "failed", reason };
			ctx.ui.notify(reason, "error");
		}
	});

	pi.on("session_shutdown", async () => {
		sessionGeneration += 1;
		if (approvalContext) unregisterApprovalSession(approvalContext);
		approvalContext = undefined;
		const client = nonoClient;
		nonoClient = undefined;
		const jobs = backgroundJobs;
		backgroundJobs = undefined;
		if (jobs) await jobs.shutdown();
		if (client) await client.shutdown();
		accessPolicy = undefined;
		userBashCounter = 0;
		sandboxState = { kind: "initializing" };
	});

	pi.registerCommand("sandbox", {
		description: "Show OS sandbox rights",
		handler: async (_args, ctx) => {
			if (sandboxState.kind !== "ready") {
				ctx.ui.notify(sandboxState.kind === "disabled" ? `Sandbox is ${sandboxState.reason}` : sandboxState.kind === "failed" ? sandboxState.reason : "Sandbox is initializing", sandboxState.kind === "failed" ? "error" : "info");
				return;
			}
			try {
				synchronizeAccess();
			} catch (error) {
				ctx.ui.notify(`Sandbox policy could not be synchronized: ${errorMessage(error)}`, "error");
				return;
			}
			const access = activeAccess();
			ctx.ui.notify([
				"OS sandbox (nono):",
				`  Project policy: ${projectPolicyPath(ctx.cwd)}`,
				`  Project rights: ${access.project.policy.rights.map(rightLabel).join(", ") || "(none)"}`,
				`  Session rights: ${access.session.policy.rights.map(rightLabel).join(", ") || "(none)"}`,
				`  Session policy: ${access.sessionIdentity ? sessionPolicyPath(access.sessionIdentity) : "ephemeral"}`,
				`  Network hosts: ${networkHosts().join(", ") || "(blocked)"}`,
				`  Loopback ports: ${access.effective.localPorts.join(", ") || "(blocked)"}`,
				`  Development cache: ${developmentCacheRoot(sandboxState.config.developmentCache)}`,
				"  Denials: bounded diagnostics; no automatic retry",
			].join("\n"), "info");
		},
	});
}

function fixedPackagedExecutables(): { nonoPath: string; bwrapPath: string } {
	if (FIXED_NONO_PATH !== null) {
		return { nonoPath: FIXED_NONO_PATH, bwrapPath: resolveSystemBubblewrap() };
	}
	return resolvePackagedExecutables();
}

function requireReadyState(state: SandboxState): Extract<SandboxState, { kind: "ready" }> {
	if (state.kind !== "ready") throw new Error("Sandbox is not ready");
	return state;
}

function toolError(message: string) {
	return { content: [{ type: "text" as const, text: message }], isError: true };
}

function errorMessage(error: unknown): string {
	return error instanceof Error ? error.message : String(error);
}

function activeConfig(state: SandboxState): NativeSandboxConfig {
	return state.kind === "ready" ? state.config : DEFAULT_CONFIG;
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
