import { Effect } from "effect";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { ActiveAccessPolicy } from "./active-access-policy.ts";
import { requestUserApproval } from "./approval-transport.ts";
import {
	accessPolicyAdditions,
	activateSessionPolicy,
	addProjectAccess,
	addSessionAccess,
	loadProjectPolicyForUpdate,
	mergeAccessPolicies,
	projectPolicyPath,
	requestsRequireSessionScope,
	sameProjectPolicy,
	sandboxPolicySummary,
	saveProjectPolicy,
	type ActiveProjectPolicy,
	type ProjectAccessRequest,
} from "./project-policy.ts";
import {
	loadSessionPolicy,
	saveSessionPolicy,
	sessionPolicyPath,
} from "./session-policy-store.ts";
import { RequestAccessParams } from "./tool-schemas.ts";

export function registerAccessRequest(
	pi: ExtensionAPI,
	getAccess: () => ActiveAccessPolicy,
): void {
	pi.registerTool({
		name: "request_access",
		label: "Request sandbox access",
		description:
			"Ask the user to grant filesystem, exact network host, and/or loopback endpoint rights. Host-specific absolute paths can be approved only for this Pi session. This host tool updates policy only; it never runs or retries a command.",
		promptSnippet:
			"After a sandbox denial, request the smallest useful right. The user chooses session or project scope. If approved, explicitly rerun later.",
		parameters: RequestAccessParams,
		executionMode: "sequential",
		async execute(toolCallId, params, signal, _onUpdate, ctx) {
			let access: ActiveAccessPolicy;
			try {
				access = getAccess();
			} catch {
				return accessError("The sandbox is not ready, so access policy was not changed.", "sandbox-not-ready");
			}
			if (!ctx.isProjectTrusted()) {
				return accessError("Sandbox access can be changed only for a trusted project.", "project-untrusted");
			}
			try {
				access.synchronize();
			} catch (error) {
				return accessError(errorMessage(error), "invalid-policy");
			}

			const diskProject = access.project;
			const diskSession = access.session;
			const effective = access.effective;
			let projectCandidate: ActiveProjectPolicy | undefined;
			let sessionCandidate: ActiveProjectPolicy;
			let effectiveCandidate: ActiveProjectPolicy;
			const requests = params.rights as ProjectAccessRequest[];
			try {
				effectiveCandidate = addSessionAccess(
					effective.policy,
					requests,
					ctx.cwd,
					access.machineConfig,
				);
				if (!requestsRequireSessionScope(requests, ctx.cwd)) {
					projectCandidate = addProjectAccess(
						diskProject.policy,
						requests,
						ctx.cwd,
						access.machineConfig,
					);
				}
				sessionCandidate = activateSessionPolicy(
					mergeAccessPolicies(
						diskSession.policy,
						accessPolicyAdditions(effective.policy, effectiveCandidate.policy),
					),
					ctx.cwd,
					access.machineConfig,
					diskSession.sourceText,
				);
			} catch (error) {
				return accessError(errorMessage(error), "invalid-request");
			}
			if (
				sameProjectPolicy(effectiveCandidate.policy, effective.policy) &&
				(!projectCandidate || sameProjectPolicy(projectCandidate.policy, diskProject.policy))
			) {
				return {
					content: [{ type: "text", text: "All requested rights are already active. No command was retried." }],
					details: { granted: true, existing: true, commandRetried: false },
				};
			}

			const sessionChanged = !sameProjectPolicy(sessionCandidate.policy, diskSession.policy);
			const sessionTarget = access.sessionIdentity
				? sessionPolicyPath(access.sessionIdentity)
				: "the current ephemeral Pi session";
			// Both choices grant the same request at different lifetimes. Render the
			// validated additions once instead of repeating session and project JSON.
			const displayedAdditions = projectCandidate
				? accessPolicyAdditions(diskProject.policy, projectCandidate.policy)
				: accessPolicyAdditions(effective.policy, effectiveCandidate.policy);
			const diff = sandboxPolicySummary(displayedAdditions);
			const projectSourceSnapshot = diskProject.sourceText;
			const sessionSourceSnapshot = diskSession.sourceText;
			pi.events.emit("approval:requested", {
				kind: "io-permission",
				title: "Grant sandbox rights",
				summary: diff,
				toolName: "request_access",
				toolCallId,
				sessionId: ctx.sessionManager.getSessionId(),
				cwd: ctx.cwd,
			});
			let approvalDecision: "allowed" | "denied" = "denied";
			const result = await Effect.runPromise(requestUserApproval(ctx, {
				requestId: toolCallId,
				title: "Grant sandbox rights",
				message: `${diff}\n\nReason: ${params.reason}`,
				source: "tool_call",
				surface: "project_policy",
				value: projectCandidate
					? access.sessionIdentity
						? `${sessionTarget} or ${projectPolicyPath(ctx.cwd)}`
						: projectPolicyPath(ctx.cwd)
					: sessionTarget,
				choices: [
					...(sessionChanged ? [{ id: "session", label: access.sessionIdentity ? "Allow for this Pi session" : "Allow until this ephemeral session exits" }] : []),
					...(projectCandidate ? [{ id: "project", label: "Add to project policy" }] : []),
					{ id: "deny", label: "Deny" },
				],
				signal,
			}).pipe(
				Effect.tap((value) => Effect.sync(() => {
					approvalDecision = value.choiceId === "session" || value.choiceId === "project" ? "allowed" : "denied";
				})),
				Effect.ensuring(Effect.sync(() => pi.events.emit("approval:resolved", {
					kind: "io-permission",
					toolName: "request_access",
					toolCallId,
					decision: approvalDecision,
				}))),
			), { signal });
			if (result.choiceId !== "session" && result.choiceId !== "project") {
				return accessError(result.unavailableReason ?? "Sandbox access denied.", "denied");
			}

			try {
				const freshProject = loadProjectPolicyForUpdate(ctx.cwd, access.machineConfig);
				const freshSession = access.sessionIdentity
					? loadSessionPolicy(access.sessionIdentity, access.machineConfig)
					: access.session;
				if (freshProject.sourceText !== projectSourceSnapshot || freshSession.sourceText !== sessionSourceSnapshot) {
					throw new Error("Sandbox access policy changed while request_access was awaiting approval");
				}
				if (result.choiceId === "project") {
					if (!projectCandidate) throw new Error("Host-specific filesystem paths can be approved only for this Pi session");
					projectCandidate.sourceText = saveProjectPolicy(ctx.cwd, projectCandidate.policy, projectSourceSnapshot);
					access.replace(projectCandidate, freshSession);
				} else {
					if (access.sessionIdentity) {
						sessionCandidate.sourceText = saveSessionPolicy(
							access.sessionIdentity,
							sessionCandidate.policy,
							sessionSourceSnapshot,
						);
					}
					access.replace(freshProject, sessionCandidate);
				}
			} catch (error) {
				return accessError(`Sandbox access was not activated: ${errorMessage(error)}`, "save-failed");
			}
			const scope = result.choiceId;
			const policyPath = scope === "project" ? projectPolicyPath(ctx.cwd) : sessionTarget;
			return {
				content: [{
					type: "text",
					text: `Updated and activated ${scope} sandbox rights in ${policyPath}. No command was retried; explicitly rerun it in a later tool call.`,
				}],
				details: { granted: true, scope, policyPath, requests: params.rights, commandRetried: false },
			};
		},
	});
}

function accessError(message: string, reason: string) {
	return {
		content: [{ type: "text" as const, text: `${message} No command was retried.` }],
		details: { granted: false, reason, commandRetried: false },
		isError: true,
	};
}

function errorMessage(error: unknown): string {
	return error instanceof Error ? error.message : String(error);
}
