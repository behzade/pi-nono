import assert from "node:assert/strict";
import test from "node:test";
import { Effect } from "effect";
import { decodeSandboxModeRequest } from "./sandbox-mode.ts";

test("decodes the exact host sandbox mode request", async () => {
	const request = await Effect.runPromise(decodeSandboxModeRequest(JSON.stringify({
		requestId: "gpui-permission-12",
		files: "read-only",
		network: "full",
	})));

	assert.deepEqual({ ...request }, {
		requestId: "gpui-permission-12",
		files: "read-only",
		network: "full",
	});
});

test("rejects malformed or widened sandbox mode requests", async () => {
	for (const value of [
		"not json",
		JSON.stringify(null),
		JSON.stringify({ requestId: "id", files: "full", network: "all" }),
		JSON.stringify({ requestId: "id", files: "write", network: "full" }),
		JSON.stringify({ requestId: "bad id", files: "full", network: "full" }),
		JSON.stringify({ requestId: "id", files: "full", network: "full", extra: true }),
	]) {
		await assert.rejects(Effect.runPromise(decodeSandboxModeRequest(value)));
	}
});
