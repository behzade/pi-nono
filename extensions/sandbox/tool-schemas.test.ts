import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { BashParams, ProcessParams } from "./tool-schemas.ts";

const accessRequestSource = readFileSync(new URL("./access-request.ts", import.meta.url), "utf8");
const schemaSource = readFileSync(new URL("./tool-schemas.ts", import.meta.url), "utf8");

test("bash does not expose automatic detachment timing", () => {
	const schema = BashParams as { type?: unknown; properties?: Record<string, unknown> };
	assert.equal(schema.type, "object");
	assert.deepEqual(Object.keys(schema.properties ?? {}), ["command", "timeout"]);
});

test("process exposes only immediate control primitives", () => {
	const schema = ProcessParams as { properties?: Record<string, unknown>; required?: string[] };
	assert.deepEqual(Object.keys(schema.properties ?? {}), ["id", "input", "close_stdin", "signal"]);
	assert.deepEqual(schema.required, ["id"]);
});

test("bash and process cannot request per-command permissions", () => {
	const bashStart = schemaSource.indexOf("export const BashParams");
	const processStart = schemaSource.indexOf("export const ProcessParams");
	const bashSchema = schemaSource.slice(bashStart, processStart);
	const processSchema = schemaSource.slice(processStart);
	assert.doesNotMatch(bashSchema, /permissions/);
	assert.doesNotMatch(processSchema, /permissions/);
});

test("request_access owns every durable access request variant", () => {
	const requestStart = schemaSource.indexOf("const AccessRightParams");
	const bashStart = schemaSource.indexOf("export const BashParams", requestStart);
	const schema = schemaSource.slice(requestStart, bashStart);
	assert.match(schema, /Type\.Literal\("filesystem"\)/);
	assert.match(schema, /Type\.Literal\("network_host"\)/);
	assert.match(schema, /Type\.Literal\("network_endpoint"\)/);
	assert.match(schema, /minimum: 1, maximum: 65_535/);
	assert.doesNotMatch(schema, /development_cache/);
	assert.match(accessRequestSource, /name: "request_access"/);
	assert.doesNotMatch(accessRequestSource, /name: "request_network_permission"/);
});
