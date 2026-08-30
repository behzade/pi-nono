import assert from "node:assert/strict";
import { delimiter, dirname } from "node:path";
import test from "node:test";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import registerSandbox from "./index.ts";
import { SANDBOX_MODE_STATUS_KEY } from "./sandbox-mode.ts";
import { hostBash } from "./sandbox-policy.ts";

interface RegisteredTool {
	name: string;
	execute(
		id: string,
		params: { command: string },
		signal: AbortSignal | undefined,
		onUpdate: undefined,
		context: unknown,
	): Promise<{ content: Array<{ text?: string }> }>;
}

test("PI_NONO_DISABLED skips all extension setup", () => {
	const original = process.env.PI_NONO_DISABLED;
	try {
		process.env.PI_NONO_DISABLED = "1";
		const pi = new Proxy({}, {
			get() { throw new Error("disabled extension accessed Pi"); },
		}) as ExtensionAPI;
		registerSandbox(pi);
	} finally {
		if (original === undefined) delete process.env.PI_NONO_DISABLED;
		else process.env.PI_NONO_DISABLED = original;
	}
});

test("disabled sandbox does not intercept built-in file tools", async () => {
	let sessionStart: ((event: unknown, context: unknown) => Promise<unknown>) | undefined;
	let toolCall: ((event: unknown, context: unknown) => Promise<unknown>) | undefined;
	const pi = {
		registerFlag() {},
		getFlag() { return true; },
		registerTool() {},
		registerCommand() {},
		on(event: string, handler: (event: unknown, context: unknown) => Promise<unknown>) {
			if (event === "session_start") sessionStart = handler;
			if (event === "tool_call") toolCall = handler;
		},
		events: { emit() {} },
	} as unknown as ExtensionAPI;
	registerSandbox(pi);
	const context = {
		hasUI: false,
		sessionManager: { getSessionFile: () => undefined },
		ui: { notify() {} },
	};
	assert(sessionStart && toolCall);
	await sessionStart({ reason: "startup" }, context);
	assert.equal(
		await toolCall({ toolName: "write", input: { path: "/outside/file" } }, context),
		undefined,
	);
});

test("full mode preserves captured PATH and acknowledges live mode requests", async () => {
	const originalPath = process.env.PATH;
	const originalHandoff = process.env.PI_GUI_CAPTURED_PROJECT_PATH;
	const capturedPath = `${dirname(hostBash({ PATH: originalPath }))}${delimiter}/captured/project`;
	let sessionStart: ((event: unknown, context: unknown) => Promise<unknown>) | undefined;
	let bashTool: RegisteredTool | undefined;
	let sandboxMode: {
		handler(args: string, context: unknown): Promise<void>;
	} | undefined;
	const statuses = new Map<string, string | undefined>();
	try {
		process.env.PATH = capturedPath;
		process.env.PI_GUI_CAPTURED_PROJECT_PATH = capturedPath;
		const pi = {
			registerFlag() {},
			getFlag(name: string) {
				if (name === "sandbox-files" || name === "sandbox-network") return "full";
				return false;
			},
			registerTool(tool: RegisteredTool) {
				if (tool.name === "bash") bashTool = tool;
			},
			registerCommand(name: string, command: { handler(args: string, context: unknown): Promise<void> }) {
				if (name === "sandbox-mode") sandboxMode = command;
			},
			on(event: string, handler: (event: unknown, context: unknown) => Promise<unknown>) {
				if (event === "session_start") sessionStart = handler;
			},
			events: { emit() {} },
		} as unknown as ExtensionAPI;
		registerSandbox(pi);

		const context = {
			cwd: process.cwd(),
			model: { provider: "test-provider", id: "test-model" },
			mode: "rpc",
			isIdle: () => true,
			isProjectTrusted: () => false,
			sessionManager: {
				getSessionFile: () => undefined,
				getSessionId: () => "current-session",
			},
			ui: {
				notify() {},
				setStatus(key: string, value: string | undefined) { statuses.set(key, value); },
				theme: { fg(_color: string, value: string) { return value; } },
			},
		};
		assert(sessionStart && bashTool && sandboxMode);
		await sessionStart({ reason: "startup" }, context);
		const result = await bashTool.execute(
			"test-bash",
			{
				command:
					'printf "%s|%s|%s" "$PATH" "${PI_GUI_CAPTURED_PROJECT_PATH-unset}" "$PI_SESSION_ID"',
			},
			undefined,
			undefined,
			context,
		);
		assert.equal(
			result.content[0]?.text,
			`${capturedPath}|unset|current-session`,
		);

		await sandboxMode.handler(JSON.stringify({
			requestId: "gpui-permission-1",
			files: "full",
			network: "full",
		}), context);
		assert.deepEqual(
			JSON.parse(statuses.get(SANDBOX_MODE_STATUS_KEY) ?? "null"),
			{
				version: 1,
				requestId: "gpui-permission-1",
				files: "full",
				network: "full",
				success: true,
			},
		);

		await sandboxMode.handler(JSON.stringify({
			requestId: "gpui-permission-2",
			files: "sandboxed",
			network: "sandboxed",
		}), { ...context, isIdle: () => false });
		assert.deepEqual(
			JSON.parse(statuses.get(SANDBOX_MODE_STATUS_KEY) ?? "null"),
			{
				version: 1,
				requestId: "gpui-permission-2",
				files: "sandboxed",
				network: "sandboxed",
				success: false,
				error: "Wait for Pi to become idle before changing sandbox access",
			},
		);
	} finally {
		if (originalPath === undefined) delete process.env.PATH;
		else process.env.PATH = originalPath;
		if (originalHandoff === undefined) delete process.env.PI_GUI_CAPTURED_PROJECT_PATH;
		else process.env.PI_GUI_CAPTURED_PROJECT_PATH = originalHandoff;
	}
});
