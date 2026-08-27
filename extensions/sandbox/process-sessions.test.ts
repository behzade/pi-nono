import assert from "node:assert/strict";
import test from "node:test";
import {
	formatProcessSnapshot,
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

test("process snapshots combine incremental output and structured state", () => {
	assert.equal(
		formatProcessSnapshot({ id: "pi-123", state: "running", output: "ready\n" }),
		"ready\n\nProcess pi-123 is still running. Completion will be delivered automatically; use process only to interact or inspect new output.",
	);
	assert.equal(
		formatProcessSnapshot({ id: "pi-123", state: "completed", output: "", exitCode: 0 }),
		"Process pi-123 completed with exit code 0.",
	);
});

test("process completion wakes the agent without polling", () => {
	const sent: unknown[][] = [];
	const settlement = { id: "pi-check", state: "exited" as const, output: "failed\n", exitCode: 1 };
	notifyProcessSettlement({
		sendMessage: (...args: unknown[]) => sent.push(args),
	}, settlement);

	assert.deepEqual(sent, [[{
		customType: "process-session-result",
		content: "failed\n\nProcess pi-check exited with exit code 1.",
		display: true,
		details: { id: "pi-check", state: "exited", exitCode: 1 },
	}, { triggerTurn: true, deliverAs: "steer" }]]);
});
