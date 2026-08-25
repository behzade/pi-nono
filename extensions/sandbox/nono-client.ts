import { spawn, type ChildProcess, type StdioOptions } from "node:child_process";
import {
	accessSync,
	closeSync,
	constants,
	existsSync,
	mkdirSync,
	mkdtempSync,
	openSync,
	rmSync,
	writeFileSync,
} from "node:fs";
import { homedir, tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { Effect, Schema } from "effect";
import type {
	SandboxExecRequest,
	SandboxExecResult,
	SandboxFilesystemRight,
} from "./sandbox-protocol.ts";
import { buildLinuxDenyLaunch } from "./linux-deny-layer.ts";

const READY_TIMEOUT_MS = 10_000;
const SHUTDOWN_GRACE_MS = 500;

export class NonoClientError extends Schema.TaggedError<NonoClientError>()(
	"NonoClientError",
	{ message: Schema.String, cause: Schema.optional(Schema.Defect()) },
) {}

const nonoError = (cause: unknown) => new NonoClientError({
	message: cause instanceof Error ? cause.message : String(cause),
	cause,
});

interface PendingProcess {
	child: ChildProcess;
	profileDirectory: string;
	outputBytes: number;
	outputLimit: number;
	truncated: boolean;
}

/** One-shot bash is not a TTY. Keep stdin open only when a job will write to it. */
export function sandboxCommandStdio(interactive: boolean): StdioOptions {
	return [interactive ? "pipe" : "ignore", "pipe", "pipe"];
}

export class NonoClient {
	readonly #path: string;
	readonly #bwrapPath: string;
	readonly #pending = new Map<string, PendingProcess>();
	#closed = false;

	private constructor(path: string, bwrapPath: string) {
		this.#path = path;
		this.#bwrapPath = bwrapPath;
	}

	static async start(path: string, bwrapPath: string): Promise<NonoClient> {
		accessSync(path, constants.X_OK);
		if (process.platform === "linux") accessSync(bwrapPath, constants.X_OK);
		await checkNono(path);
		return new NonoClient(path, bwrapPath);
	}

	readonly execEffect = (
		request: SandboxExecRequest,
		onData: (data: Buffer) => void,
		onStarted?: (pid: number) => void,
	): Effect.Effect<SandboxExecResult, NonoClientError> =>
		Effect.tryPromise({
			try: (signal) => this.exec(request, onData, signal, onStarted),
			catch: nonoError,
		});

	exec(
		request: SandboxExecRequest,
		onData: (data: Buffer) => void,
		signal?: AbortSignal,
		onStarted?: (pid: number) => void,
	): Promise<SandboxExecResult> {
		if (this.#closed) return Promise.reject(new Error("nono sandbox client is closed"));
		if (this.#pending.has(request.id)) return Promise.reject(new Error(`Duplicate command ID: ${request.id}`));
		const profileDirectory = mkdtempSync(join(tmpdir(), ".guardian-nono-"));
		const profilePath = join(profileDirectory, "profile.json");
		try {
			prepareMissingRights([...request.policy.base_rights, ...request.policy.grants]);
			writeFileSync(profilePath, `${JSON.stringify(buildNonoProfile(request), null, 2)}\n`, {
				mode: 0o600,
				flag: "wx",
			});
		} catch (error) {
			rmSync(profileDirectory, { recursive: true, force: true });
			return Promise.reject(error);
		}

		return new Promise((resolve, reject) => {
			const nonoArgs = [
				"--silent",
				"run",
				"--profile",
				profilePath,
				"--",
				request.command.program,
				...request.command.args,
			];
			const launch = process.platform === "linux"
				? buildLinuxDenyLaunch(
						this.#bwrapPath,
						this.#path,
						nonoArgs,
						request,
						profileDirectory,
					)
				: { program: this.#path, args: nonoArgs };
			const child = spawn(launch.program, launch.args, {
				cwd: request.cwd,
				env: request.env,
				stdio: sandboxCommandStdio(request.interactive === true),
				detached: true,
			});
			const pending: PendingProcess = {
				child,
				profileDirectory,
				outputBytes: 0,
				outputLimit: request.policy.output_limit_bytes,
				truncated: false,
			};
			this.#pending.set(request.id, pending);
			let timedOut = false;
			let cancelled = false;
			const timeout = request.timeout_ms === null
				? undefined
				: setTimeout(() => {
					timedOut = true;
					terminateGroup(child);
				}, request.timeout_ms);
			const abort = () => {
				cancelled = true;
				terminateGroup(child);
			};
			signal?.addEventListener("abort", abort, { once: true });
			const emit = (chunk: Buffer) => {
				const remaining = Math.max(0, pending.outputLimit - pending.outputBytes);
				const visible = chunk.subarray(0, remaining);
				pending.outputBytes += visible.length;
				if (visible.length > 0) onData(visible);
				if (visible.length < chunk.length) pending.truncated = true;
			};
			child.stdout.on("data", emit);
			child.stderr.on("data", emit);
			child.once("spawn", () => onStarted?.(child.pid ?? 0));
			child.once("error", (error) => {
				cleanup();
				reject(error);
			});
			child.once("close", (code) => {
				cleanup();
				if (pending.truncated) onData(Buffer.from("\n[Sandbox output truncated at the configured limit]\n"));
				if (cancelled || signal?.aborted) reject(new Error("aborted"));
				else if (timedOut) reject(new Error(`timeout:${request.timeout_ms === null ? "nono" : request.timeout_ms / 1000}`));
				else resolve({ exitCode: code ?? 1, denials: [], denialsComplete: false });
			});

			const cleanup = () => {
				if (timeout) clearTimeout(timeout);
				signal?.removeEventListener("abort", abort);
				this.#pending.delete(request.id);
				rmSync(profileDirectory, { recursive: true, force: true });
			};
		});
	}

	writeStdin(id: string, data: Buffer): void {
		const pending = this.#pending.get(id);
		if (!pending?.child.stdin?.writable) throw new Error(`Command is not running: ${id}`);
		pending.child.stdin.write(data);
	}

	cancel(id: string): void {
		const pending = this.#pending.get(id);
		if (pending) terminateGroup(pending.child);
	}

	async shutdown(): Promise<void> {
		if (this.#closed) return;
		this.#closed = true;
		for (const pending of this.#pending.values()) terminateGroup(pending.child);
		await new Promise((resolve) => setTimeout(resolve, SHUTDOWN_GRACE_MS));
		for (const pending of this.#pending.values()) {
			killGroup(pending.child, "SIGKILL");
			rmSync(pending.profileDirectory, { recursive: true, force: true });
		}
		this.#pending.clear();
	}
}

export function buildNonoProfile(
	request: SandboxExecRequest,
	platform: NodeJS.Platform = process.platform,
): Record<string, unknown> {
	const rights = [...request.policy.base_rights, ...request.policy.grants];
	const runtimeDeviceFiles = ["/dev/null", "/dev/zero", "/dev/random", "/dev/urandom"]
		.filter(existsSync);
	const runtimeConfigFiles = [join(homedir(), ".gitconfig")].filter(existsSync);
	const runtimeConfigDirectories = [join(homedir(), ".config", "git")].filter(existsSync);
	// Nono's portable `deny` blocks reads too. Linux mounts this fixed control
	// root read-only; macOS needs an exact Seatbelt write deny instead.
	const guardianWriteDeny = platform === "darwin"
		? request.policy.denies.find((deny) =>
				deny.access === "write" &&
				deny.scope === "tree" &&
				deny.pattern === join(request.cwd, ".guardian")
			)
		: undefined;
	const seatbeltDenies = request.policy.denies.filter((deny) => deny !== guardianWriteDeny);
	const filesystem = {
		allow: rightPaths(rights, "write", "tree"),
		read: [...new Set([
			...rightPaths(rights, "read", "tree"),
			...(existsSync("/nix/store") ? ["/nix/store"] : []),
			...runtimeConfigDirectories,
		])].sort(),
		allow_file: [...new Set([
			...rightPaths(rights, "write", "file"),
			...runtimeDeviceFiles,
		])].sort(),
		read_file: [...new Set([
			...rightPaths(rights, "read", "file"),
			...runtimeDeviceFiles,
			...runtimeConfigFiles,
		])].sort(),
		bypass_protection: [...runtimeConfigFiles, ...runtimeConfigDirectories],
		unix_socket: [...request.policy.unix_socket_roots].sort(),
		deny: platform === "linux"
			? []
			: [...new Set(seatbeltDenies.map((deny) => deny.pattern))].sort(),
	};
	const network = request.policy.network;
	const allowedHosts = network.mode === "proxy" ? network.allowed_hosts : [];
	const localPorts = network.mode === "blocked"
		? []
		: network.mode === "loopback"
			? network.ports
			: network.local_ports;
	return {
		$schema: "https://nono.sh/schemas/nono-profile.schema.json",
		extends: "default",
		meta: {
			name: "pi-nono-command",
			version: "1",
			description: "Ephemeral profile generated from a validated pi-nono policy snapshot",
		},
		filesystem,
		...(guardianWriteDeny
			? {
					unsafe_macos_seatbelt_rules: [
						`(deny file-write* (subpath ${JSON.stringify(guardianWriteDeny.pattern)}))`,
					],
				}
			: {}),
		network: {
			block: allowedHosts.length === 0,
			allow_domain: allowedHosts,
			...(localPorts.length > 0 ? { open_port: localPorts } : {}),
		},
	};
}

function rightPaths(
	rights: readonly SandboxFilesystemRight[],
	access: "read" | "write",
	scope: "file" | "tree",
): string[] {
	return [...new Set(
		rights
			.filter((right) => right.access === access && right.scope === scope)
			.map((right) => right.path),
	)].sort();
}

function prepareMissingRights(rights: readonly SandboxFilesystemRight[]): void {
	for (const right of rights) {
		if (existsSync(right.path) || right.missing_path === "reject") continue;
		if (right.missing_path === "create_tree") mkdirSync(right.path, { recursive: true, mode: 0o700 });
		else {
			mkdirSync(dirname(right.path), { recursive: true, mode: 0o700 });
			closeSync(openSync(right.path, "wx", 0o600));
		}
	}
}

async function checkNono(path: string): Promise<void> {
	await new Promise<void>((resolve, reject) => {
		const child = spawn(path, ["setup", "--check-only"], {
			stdio: ["ignore", "ignore", "pipe"],
			env: process.env,
		});
		let error = "";
		child.stderr.on("data", (chunk) => { if (error.length < 8_192) error += chunk.toString("utf8"); });
		const timeout = setTimeout(() => {
			child.kill("SIGKILL");
			reject(new Error("nono readiness check timed out"));
		}, READY_TIMEOUT_MS);
		child.once("error", (cause) => {
			clearTimeout(timeout);
			reject(cause);
		});
		child.once("close", (code) => {
			clearTimeout(timeout);
			if (code === 0) resolve();
			else reject(new Error(`nono readiness check failed (${code ?? "signal"}): ${error.trim()}`));
		});
	});
}

function terminateGroup(child: ChildProcess): void {
	killGroup(child, "SIGTERM");
	setTimeout(() => killGroup(child, "SIGKILL"), SHUTDOWN_GRACE_MS).unref();
}

function killGroup(child: ChildProcess, signal: NodeJS.Signals): void {
	if (!child.pid) return;
	try {
		process.kill(-child.pid, signal);
	} catch {
		try { child.kill(signal); } catch { /* Process already exited. */ }
	}
}
