import { Effect, Schema } from "effect";

/** Private RPC status channel used to acknowledge a GPUI-owned mode change. */
export const SANDBOX_MODE_STATUS_KEY = "\u001fpi-gpui-sandbox-mode\u001f";

const RequestId = Schema.String.check(
	Schema.isPattern(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/),
);

export class SandboxModeRequest extends Schema.Class<SandboxModeRequest>(
	"SandboxModeRequest",
)({
	requestId: RequestId,
	files: Schema.Literals(["read-only", "sandboxed", "full"]),
	network: Schema.Literals(["sandboxed", "full"]),
}) {}

export class SandboxModeResult extends Schema.Class<SandboxModeResult>(
	"SandboxModeResult",
)({
	version: Schema.Literals([1]),
	requestId: RequestId,
	files: Schema.Literals(["read-only", "sandboxed", "full"]),
	network: Schema.Literals(["sandboxed", "full"]),
	success: Schema.Boolean,
	error: Schema.optional(Schema.String),
}) {}

export class SandboxModeError extends Schema.TaggedError<SandboxModeError>()(
	"SandboxModeError",
	{ message: Schema.String, cause: Schema.optional(Schema.Defect()) },
) {}

const modeError = (message: string, cause?: unknown) => new SandboxModeError({
	message,
	...(cause === undefined ? {} : { cause }),
});

const decodeRequest = Schema.decodeUnknownEffect(SandboxModeRequest, {
	onExcessProperty: "error",
});

export const decodeSandboxModeRequest = Effect.fn("Sandbox.decodeModeRequest")(
	function* (args: string) {
		const input = yield* Effect.try({
			try: () => JSON.parse(args) as unknown,
			catch: (cause) => modeError("Sandbox mode request must be JSON", cause),
		});
		return yield* decodeRequest(input).pipe(
			Effect.mapError((cause) => modeError("Sandbox mode request is invalid", cause)),
		);
	},
);

export function sandboxModeResult(
	request: SandboxModeRequest,
	error?: string,
): SandboxModeResult {
	return new SandboxModeResult({
		version: 1,
		...request,
		success: error === undefined,
		...(error === undefined ? {} : { error }),
	});
}

export const sandboxModeError = modeError;
