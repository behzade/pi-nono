import { Type } from "typebox";

const AccessRightParams = Type.Union([
	Type.Object(
		{
			kind: Type.Literal("filesystem"),
			access: Type.Union([Type.Literal("read"), Type.Literal("write")]),
			path: Type.String({
				description: "Project-relative or home-relative (~/); absolute paths outside those roots can be approved only for this Pi session",
				maxLength: 1024,
			}),
			scope: Type.Union([Type.Literal("file"), Type.Literal("tree")]),
		},
		{ additionalProperties: false },
	),
	Type.Object(
		{
			kind: Type.Literal("network_host"),
			host: Type.String({ description: "One exact hostname or IP, without scheme, port, path, or wildcard" }),
		},
		{ additionalProperties: false },
	),
	Type.Object(
		{
			kind: Type.Literal("network_endpoint"),
			host: Type.String({ description: "Loopback host: localhost, 127.0.0.1, or ::1" }),
			port: Type.Integer({ minimum: 1, maximum: 65_535 }),
		},
		{ additionalProperties: false },
	),
]);

export const RequestAccessParams = Type.Object(
	{
		rights: Type.Array(AccessRightParams, { minItems: 1, maxItems: 32 }),
		reason: Type.String({ description: "Why the project needs these rights", maxLength: 2000 }),
	},
	{ additionalProperties: false },
);

const BashCommand = Type.String({ description: "Bash command to execute" });
const BashTimeout = Type.Optional(Type.Number({
	description: "Hard timeout in seconds (optional, no default timeout)",
	exclusiveMinimum: 0,
	maximum: 86_400,
}));

export const BashParams = Type.Union([
	Type.Object(
		{
			command: BashCommand,
			timeout: BashTimeout,
			execution: Type.Optional(Type.Literal("sync", {
				description: "Wait for the command to finish (default)",
			})),
		},
		{ additionalProperties: false },
	),
	Type.Object(
		{
			command: BashCommand,
			timeout: BashTimeout,
			execution: Type.Literal("async", {
				description: "Run independently and return a process handle",
			}),
			label: Type.String({ description: "Short sidebar label for the async process", minLength: 1, maxLength: 80 }),
		},
		{ additionalProperties: false },
	),
]);

export const ProcessParams = Type.Object(
	{
		id: Type.String({ description: "Process session ID returned by bash", minLength: 1 }),
		input: Type.Optional(Type.String({ description: "Bytes to write to stdin before returning" })),
		close_stdin: Type.Optional(Type.Boolean({ description: "Close stdin after writing input, if any" })),
		signal: Type.Optional(Type.Union([
			Type.Literal("INT"),
			Type.Literal("TERM"),
			Type.Literal("KILL"),
		], { description: "Signal the process group before returning" })),
	},
	{ additionalProperties: false },
);
