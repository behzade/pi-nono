import assert from "node:assert/strict";
import test from "node:test";
import {
	modelVisibleProcessOutput,
	notifyProcessSettlement,
} from "./process-sessions.ts";

test("process output is bounded before model emission", () => {
	const output = Array.from({ length: 4000 }, (_, index) => `line-${index}`).join("\n");
	const visible = modelVisibleProcessOutput(output);
	assert(Buffer.byteLength(visible) <= 50 * 1024);
	assert(visible.split("\n").length <= 2000);
	assert.match(visible, /truncated/);
	assert.match(visible, /line-3999$/);
});

test("process completion wakes the agent without polling", () => {
	const sent: unknown[][] = [];
	const settlement = { id: "pi-check", state: "exited" as const, output: "failed\n", exitCode: 1 };
	notifyProcessSettlement({
		sendMessage: (...args: unknown[]) => sent.push(args),
	}, settlement);

	assert.deepEqual(sent, [[{
		customType: "process-session-result",
		content: "failed\n\nProcess pi-check exited with exit code 1.\n\nContinue the interrupted task now. Use the process result above, take any appropriate next actions, and provide a user-visible response before ending your turn.",
		display: false,
		details: { id: "pi-check", state: "exited", exitCode: 1 },
	}, { triggerTurn: true, deliverAs: "steer" }]]);
});
