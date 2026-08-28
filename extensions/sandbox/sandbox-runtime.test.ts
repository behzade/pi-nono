import assert from "node:assert/strict";
import test from "node:test";
import { Deferred, Effect, ManagedRuntime } from "effect";
import type { NonoClient } from "./nono-client.ts";
import type { NativeProcessSessions } from "./native-process-sessions.ts";
import {
	SandboxRuntime,
	sandboxRuntimeLayer,
	type SandboxBackend,
	type SandboxBackendFactory,
} from "./sandbox-runtime.ts";
import { DEFAULT_CONFIG, withAccessModes } from "./sandbox-config.ts";
import { SandboxModeRequest, sandboxModeError } from "./sandbox-mode.ts";

const environment = Object.freeze({ PATH: process.env.PATH ?? "" });
const fullConfig = withAccessModes(DEFAULT_CONFIG, "full", "full");
const backend = {
	client: {} as NonoClient,
	processSessions: {} as NativeProcessSessions,
} satisfies SandboxBackend;

function request(files: "read-only" | "sandboxed" | "full", network: "sandboxed" | "full") {
	return new SandboxModeRequest({ requestId: "test-mode-1", files, network });
}

function initialize(runtime: ManagedRuntime.ManagedRuntime<SandboxRuntime, never>) {
	return runtime.runPromise(SandboxRuntime.use((service) => service.initialize({
		cwd: process.cwd(),
		machineConfig: fullConfig,
		trusted: false,
		environment,
	})));
}

test("full access lazily acquires one backend and retains it across later mode changes", async () => {
	let acquired = 0;
	let released = 0;
	const acquireBackend: SandboxBackendFactory = () => Effect.acquireRelease(
		Effect.sync(() => {
			acquired += 1;
			return backend;
		}),
		() => Effect.sync(() => { released += 1; }),
	);
	const runtime = ManagedRuntime.make(sandboxRuntimeLayer({ acquireBackend }));
	try {
		await initialize(runtime);
		assert.equal(acquired, 0);
		assert.equal(
			(await runtime.runPromise(SandboxRuntime.use((service) => service.captureCommand))).kind,
			"local",
		);

		await runtime.runPromise(SandboxRuntime.use((service) =>
			service.changeMode(request("sandboxed", "sandboxed")),
		));
		assert.equal(acquired, 1);
		assert.equal(
			(await runtime.runPromise(SandboxRuntime.use((service) => service.captureCommand))).kind,
			"sandboxed",
		);

		await runtime.runPromise(SandboxRuntime.use((service) =>
			service.changeMode(request("full", "full")),
		));
		assert.equal(acquired, 1);
		assert.equal(
			(await runtime.runPromise(SandboxRuntime.use((service) => service.captureCommand))).kind,
			"local",
		);
		assert.equal(
			await runtime.runPromise(SandboxRuntime.use((service) => service.processSessions)),
			backend.processSessions,
			"yielded sandbox sessions remain continuable in full mode",
		);
	} finally {
		await runtime.dispose();
	}
	assert.equal(released, 1);
});

test("mode transitions fail closed and restore the previous mode after backend failure", async () => {
	const started = Deferred.makeUnsafe<void>();
	const continueAcquire = Deferred.makeUnsafe<void>();
	const acquireBackend: SandboxBackendFactory = () => Effect.acquireRelease(
		Effect.gen(function* () {
			yield* Deferred.succeed(started, undefined);
			yield* Deferred.await(continueAcquire);
			return yield* sandboxModeError("backend unavailable");
		}),
		() => Effect.void,
	);
	const runtime = ManagedRuntime.make(sandboxRuntimeLayer({ acquireBackend }));
	try {
		await initialize(runtime);
		const changing = runtime.runPromise(SandboxRuntime.use((service) =>
			service.changeMode(request("sandboxed", "sandboxed")),
		));
		await Effect.runPromise(Deferred.await(started));
		await assert.rejects(
			runtime.runPromise(SandboxRuntime.use((service) => service.captureCommand)),
			/Sandbox access is changing/,
		);
		Effect.runSync(Deferred.succeed(continueAcquire, undefined));
		await assert.rejects(changing, /backend unavailable/);

		const status = await runtime.runPromise(SandboxRuntime.use((service) => service.status));
		assert.equal(status.kind, "ready");
		assert.equal(
			(await runtime.runPromise(SandboxRuntime.use((service) => service.captureCommand))).kind,
			"local",
		);
	} finally {
		await runtime.dispose();
	}
});
