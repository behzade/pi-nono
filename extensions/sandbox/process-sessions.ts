import type {
	ProcessSessionSettlement,
	ProcessSessionSnapshot,
} from "./native-process-sessions.ts";

const MODEL_MAX_OUTPUT_BYTES = 50 * 1024;
const MODEL_MAX_OUTPUT_LINES = 2000;

/** Bound process output before its first model-visible emission. */
export function modelVisibleProcessOutput(output: string): string {
	const lines = output.split("\n");
	const totalBytes = Buffer.byteLength(output);
	if (lines.length <= MODEL_MAX_OUTPUT_LINES && totalBytes <= MODEL_MAX_OUTPUT_BYTES) return output;

	const notice = [
		`[Process output truncated from ${lines.length} lines (${totalBytes} bytes) to the model-output limit.`,
		"Redirect output to a workspace log when complete output is required.]",
	].join("\n");
	const separator = "\n\n";
	const outputByteBudget = MODEL_MAX_OUTPUT_BYTES - Buffer.byteLength(notice + separator);
	const outputLineBudget = MODEL_MAX_OUTPUT_LINES - notice.split("\n").length - 2;
	let kept = lines.slice(-outputLineBudget);
	while (kept.length > 1 && Buffer.byteLength(kept.join("\n")) > outputByteBudget) kept.shift();
	let tail = kept.join("\n");
	if (Buffer.byteLength(tail) > outputByteBudget) {
		const bytes = Buffer.from(tail);
		let start = bytes.length - outputByteBudget;
		while (start < bytes.length && (bytes[start]! & 0xc0) === 0x80) start++;
		tail = bytes.subarray(start).toString("utf8");
	}
	return `${notice}${separator}${tail}`;
}

export function processSessionDetails(snapshot: ProcessSessionSnapshot): Omit<ProcessSessionSnapshot, "output"> {
	const { output: _output, ...details } = snapshot;
	return details;
}

export function formatProcessSnapshot(snapshot: ProcessSessionSnapshot): string {
	const output = modelVisibleProcessOutput(snapshot.output).trimEnd();
	const status = snapshot.state === "running"
		? `Process ${snapshot.id} is still running. Completion will be delivered automatically; use process only to interact or inspect new output.`
		: snapshot.state === "failed"
			? `Process ${snapshot.id} failed: ${snapshot.error ?? "unknown error"}`
			: snapshot.state === "stopped"
				? `Process ${snapshot.id} stopped.`
				: `Process ${snapshot.id} ${snapshot.state} with exit code ${snapshot.exitCode ?? 1}.`;
	return output ? `${output}\n\n${status}` : status;
}

interface ProcessCompletionMessenger {
	sendMessage(
		message: {
			customType: string;
			content: string;
			display: boolean;
			details: Omit<ProcessSessionSettlement, "output">;
		},
		options: { triggerTurn: true; deliverAs: "steer" },
	): void;
}

export function notifyProcessSettlement(
	messenger: ProcessCompletionMessenger,
	settlement: ProcessSessionSettlement,
): void {
	messenger.sendMessage({
		customType: "process-session-result",
		content: formatProcessSnapshot(settlement),
		display: true,
		details: processSessionDetails(settlement),
	}, { triggerTurn: true, deliverAs: "steer" });
}
