import { dirname, resolve, sep } from "node:path";
import type { SandboxDenial } from "./sandbox-protocol.ts";

const MAX_EXAMPLES = 3;

interface DenialGroup {
	label: string;
	count: number;
	paths: string[];
	examples: string[];
}

export function formatDenialSummary(
	denials: readonly SandboxDenial[],
	complete: boolean,
): string | undefined {
	const groups = new Map<string, DenialGroup>();
	let retained = 0;

	for (const denial of denials) {
		const access = denial.operation.startsWith("file-write")
			? "write"
			: denial.operation.startsWith("file-read")
				? "read"
				: undefined;
		if (access) {
			if (!denial.path || isInside("/dev", resolve(denial.path))) continue;
			const key = `filesystem:${access}`;
			const group = groups.get(key) ?? {
				label: `${access} access`,
				count: 0,
				paths: [],
				examples: [],
			};
			group.count += 1;
			if (!group.paths.includes(denial.path)) group.paths.push(denial.path);
			if (!group.examples.includes(denial.path)) group.examples.push(denial.path);
			groups.set(key, group);
			retained += 1;
			continue;
		}
		if (denial.operation.startsWith("network")) {
			const key = "network";
			const group = groups.get(key) ?? {
				label: "network access",
				count: 0,
				paths: [],
				examples: [],
			};
			group.count += 1;
			if (denial.path && !group.examples.includes(denial.path)) {
				group.examples.push(denial.path);
			} else if (denial.process) {
				const example = `process ${denial.process}`;
				if (!group.examples.includes(example)) group.examples.push(example);
			}
			groups.set(key, group);
			retained += 1;
		}
	}
	if (retained === 0) return undefined;

	let remainingExamples = MAX_EXAMPLES;
	const lines = [
		`Sandbox reported ${retained} denial hint${retained === 1 ? "" : "s"}${complete ? "" : " (best-effort diagnostics)"}.`,
	];
	for (const group of groups.values()) {
		const location = group.paths.length > 0 ? ` under ${commonCategoryRoot(group.paths)}` : "";
		lines.push(`- ${group.label}: ${group.count}${location}`);
		const examples = group.examples.slice(0, remainingExamples);
		for (const example of examples) lines.push(`  example: ${example}`);
		remainingExamples -= examples.length;
	}
	lines.push(
		"Use request_access for the smallest portable file/tree, exact network host, or exact loopback endpoint right, then explicitly rerun the command.",
	);
	lines.push("No command was retried.");
	return `\n${lines.join("\n")}\n`;
}

function commonCategoryRoot(paths: readonly string[]): string {
	if (paths.length === 0) return "/";
	let parts = dirname(paths[0] ?? "/").split(sep);
	for (const path of paths.slice(1)) {
		const candidate = dirname(path).split(sep);
		let index = 0;
		while (index < parts.length && parts[index] === candidate[index]) index += 1;
		parts = parts.slice(0, index);
	}
	const joined = parts.join(sep);
	return joined || sep;
}
