import type { ProcessSessionSnapshot } from "./native-process-sessions.ts";

const MODEL_MAX_OUTPUT_BYTES = 50 * 1024;
const MODEL_MAX_OUTPUT_LINES = 2000;

/** Bound process output before its first model-visible emission. */
export function modelVisibleProcessOutput(
	output: string, maxBytes = MODEL_MAX_OUTPUT_BYTES, maxLines = MODEL_MAX_OUTPUT_LINES,
): string {
	const lines = output.split("\n");
	const totalBytes = Buffer.byteLength(output);
	if (lines.length <= maxLines && totalBytes <= maxBytes) return output;

	const notice = [
		`[Process output truncated from ${lines.length} lines (${totalBytes} bytes) to the model-output limit.`,
		"Redirect output to a workspace log when complete output is required.]",
	].join("\n");
	const separator = "\n\n";
	const outputByteBudget = maxBytes - Buffer.byteLength(notice + separator);
	const outputLineBudget = maxLines - notice.split("\n").length - 2;
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

type ProcessDetails = Omit<ProcessSessionSnapshot, "output">;

interface ProcessCompletionMessenger {
	sendMessage(
		message: {
			customType: string;
			content: string;
			display: false;
			details: ProcessDetails | { processes: ProcessDetails[] };
		},
		options: { triggerTurn: boolean; deliverAs: "steer" },
	): void;
}

function formatProcessBatch(settlements: ProcessSessionSnapshot[]): string {
	const summary = settlements.map(({ id, state, exitCode }) =>
		`${id}: ${state}${exitCode === undefined ? "" : ` (exit ${exitCode})`}`
	).join("\n");
	const prefix = `Background processes completed:\n${summary}\n\n`;
	return prefix + modelVisibleProcessOutput(
		settlements.map(formatProcessSnapshot).join("\n\n"),
		MODEL_MAX_OUTPUT_BYTES - Buffer.byteLength(prefix),
		MODEL_MAX_OUTPUT_LINES - prefix.split("\n").length,
	);
}

/** Own the queue until a safe delivery point, so tool reads can acknowledge it. */
export class ProcessCompletionQueue {
	readonly #pending = new Map<string, ProcessSessionSnapshot>();
	readonly #messenger: ProcessCompletionMessenger;
	readonly #isIdle: () => boolean;
	#timer: ReturnType<typeof setTimeout> | undefined;
	#closed = false;

	constructor(messenger: ProcessCompletionMessenger, isIdle: () => boolean) {
		this.#messenger = messenger;
		this.#isIdle = isIdle;
	}

	settle(settlement: ProcessSessionSnapshot): void {
		if (this.#closed || settlement.state === "running") return;
		this.#pending.set(settlement.id, {
			...settlement,
			output: modelVisibleProcessOutput(settlement.output),
		});
		// Keep the existing host-facing status event immediate and non-triggering.
		this.#messenger.sendMessage({
			customType: "process-session-status",
			content: "",
			display: false,
			details: processSessionDetails(settlement),
		}, { triggerTurn: false, deliverAs: "steer" });
		this.scheduleIdleDelivery();
	}

	acknowledge(snapshot: ProcessSessionSnapshot): void {
		if (snapshot.state !== "running") this.#pending.delete(snapshot.id);
		if (this.#pending.size === 0) this.#cancelTimer();
	}

	/** An idle burst gets one wake-up, without waiting for still-running jobs. */
	scheduleIdleDelivery(): void {
		if (this.#closed || this.#timer || this.#pending.size === 0 || !this.#isIdle()) return;
		this.#timer = setTimeout(() => {
			this.#timer = undefined;
			if (this.#isIdle()) this.flush();
		}, 50);
	}

	/** Called after the current turn's tool results, before the next model call. */
	flush(): void {
		this.#cancelTimer();
		if (this.#closed || this.#pending.size === 0) return;
		const settlements = [...this.#pending.values()];
		this.#messenger.sendMessage({
			customType: "process-session-result",
			content: formatProcessBatch(settlements),
			display: false,
			details: { processes: settlements.map(processSessionDetails) },
		}, { triggerTurn: true, deliverAs: "steer" });
		for (const settlement of settlements) this.#pending.delete(settlement.id);
	}

	close(): void {
		this.#closed = true;
		this.#cancelTimer();
		this.#pending.clear();
	}

	#cancelTimer(): void {
		if (this.#timer) clearTimeout(this.#timer);
		this.#timer = undefined;
	}
}
