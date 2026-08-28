import assert from "node:assert/strict";
import { delimiter, dirname } from "node:path";
import test from "node:test";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import registerSandbox from "./index.ts";
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

test("full mode bypasses host wrappers that replace captured PATH", async () => {
	const originalPath = process.env.PATH;
	const originalHandoff = process.env.PI_GUI_CAPTURED_PROJECT_PATH;
	const capturedPath = `${dirname(hostBash({ PATH: originalPath }))}${delimiter}/captured/project`;
	let sessionStart: ((event: unknown, context: unknown) => Promise<unknown>) | undefined;
	let bashTool: RegisteredTool | undefined;
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
			registerCommand() {},
			on(event: string, handler: (event: unknown, context: unknown) => Promise<unknown>) {
				if (event === "session_start") sessionStart = handler;
			},
			events: { emit() {} },
		} as unknown as ExtensionAPI;
		registerSandbox(pi);

		const context = {
			cwd: process.cwd(),
			model: { provider: "test-provider", id: "test-model" },
			sessionManager: {
				getSessionFile: () => undefined,
				getSessionId: () => "current-session",
			},
			ui: {
				notify() {},
				setStatus() {},
				theme: { fg(_color: string, value: string) { return value; } },
			},
		};
		assert(sessionStart && bashTool);
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
	} finally {
		if (originalPath === undefined) delete process.env.PATH;
		else process.env.PATH = originalPath;
		if (originalHandoff === undefined) delete process.env.PI_GUI_CAPTURED_PROJECT_PATH;
		else process.env.PI_GUI_CAPTURED_PROJECT_PATH = originalHandoff;
	}
});
