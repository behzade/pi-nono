import assert from "node:assert/strict";
import test from "node:test";
import { modelVisibleProcessOutput, ProcessCompletionQueue } from "./process-sessions.ts";
import type { ProcessSessionSnapshot } from "./native-process-sessions.ts";

type Message = Parameters<ConstructorParameters<typeof ProcessCompletionQueue>[0]["sendMessage"]>[0];
type Delivery = Parameters<ConstructorParameters<typeof ProcessCompletionQueue>[0]["sendMessage"]>[1];

function fixture() {
	let idle = false;
	const sent: { message: Message; options: Delivery }[] = [];
	const queue = new ProcessCompletionQueue({
		sendMessage: (message, options) => sent.push({ message, options }),
	}, () => idle);
	return {
		queue, sent,
		setIdle: (value: boolean) => { idle = value; },
		results: () => sent.filter(({ message }) => message.customType === "process-session-result"),
	};
}

function completed(id: string, output = "done\n"): ProcessSessionSnapshot {
	return { id, state: "completed", output, exitCode: 0 };
}

test("process output is bounded before model emission", () => {
	const output = Array.from({ length: 4000 }, (_, index) => `line-${index}`).join("\n");
	const visible = modelVisibleProcessOutput(output);
	assert(Buffer.byteLength(visible) <= 50 * 1024);
	assert(visible.split("\n").length <= 2000);
	assert.match(visible, /truncated/);
	assert.match(visible, /line-3999$/);
});

test("status updates are immediate; ready results wake once at the turn boundary", () => {
	const { queue, sent, results } = fixture();
	queue.settle(completed("pi-one"));
	queue.settle({ id: "pi-two", state: "exited", output: "failed\n", exitCode: 1 });
	assert.equal(sent.length, 2);
	assert(sent.every(({ message, options }) => message.customType === "process-session-status" && !options.triggerTurn));
	queue.flush();
	queue.flush();
	assert.equal(results().length, 1);
	const [{ message, options }] = results();
	assert.deepEqual(options, { triggerTurn: true, deliverAs: "steer" });
	assert.deepEqual(message.details, { processes: [
		{ id: "pi-one", state: "completed", exitCode: 0 },
		{ id: "pi-two", state: "exited", exitCode: 1 },
	] });
	assert.match(message.content, /pi-one: completed/);
	assert.match(message.content, /pi-two: exited/);
	assert.match(message.content, /failed/);
	assert.doesNotMatch(message.content, /Continue the interrupted|user-visible response/);
	queue.close();
});

test("terminal reads suppress only their pending result, not running-process completion", () => {
	const { queue, results } = fixture();
	queue.acknowledge({ id: "pi-running", state: "running", output: "partial" });
	queue.settle(completed("pi-read"));
	queue.settle(completed("pi-running"));
	queue.acknowledge(completed("pi-read"));
	queue.flush();
	assert.equal(results().length, 1);
	assert.doesNotMatch(results()[0].message.content, /pi-read/);
	assert.match(results()[0].message.content, /pi-running/);
	queue.close();
});

test("idle completions coalesce without waiting for other processes", (t) => {
	t.mock.timers.enable({ apis: ["setTimeout"] });
	const { queue, setIdle, results } = fixture();
	setIdle(true);
	queue.settle(completed("pi-one"));
	t.mock.timers.tick(20);
	queue.settle(completed("pi-two"));
	t.mock.timers.tick(30);
	assert.equal(results().length, 1);
	assert.match(results()[0].message.content, /pi-one/);
	assert.match(results()[0].message.content, /pi-two/);
	queue.settle(completed("pi-later"));
	t.mock.timers.tick(50);
	assert.equal(results().length, 2);
	queue.close();
});

test("a new active turn defers idle delivery so a tool can consume the result", (t) => {
	t.mock.timers.enable({ apis: ["setTimeout"] });
	const { queue, setIdle, results } = fixture();
	setIdle(true);
	queue.settle(completed("pi-read"));
	setIdle(false);
	t.mock.timers.tick(50);
	assert.equal(results().length, 0);
	queue.acknowledge(completed("pi-read"));
	queue.flush();
	assert.equal(results().length, 0);
	queue.close();
});

test("settling wakes late results; shutdown cancels pending delivery", (t) => {
	t.mock.timers.enable({ apis: ["setTimeout"] });
	const { queue, sent, setIdle, results } = fixture();
	queue.settle(completed("pi-late"));
	setIdle(true);
	queue.scheduleIdleDelivery();
	t.mock.timers.tick(50);
	assert.equal(results().length, 1);
	queue.settle(completed("pi-abandoned"));
	queue.close();
	const count = sent.length;
	queue.settle(completed("pi-old-session"));
	t.mock.timers.tick(100);
	queue.flush();
	assert.equal(sent.length, count);
});

test("batch output is bounded while every process keeps its status summary", () => {
	const { queue, results } = fixture();
	for (let i = 0; i < 3; i++) queue.settle(completed(`pi-${i}`, "سلام\n".repeat(20000)));
	queue.flush();
	const content = results()[0].message.content;
	assert(Buffer.byteLength(content) <= 50 * 1024);
	assert(content.split("\n").length <= 2000);
	for (let i = 0; i < 3; i++) assert.match(content, new RegExp(`pi-${i}: completed`));
	assert(!content.includes("�"));
	queue.close();
});
