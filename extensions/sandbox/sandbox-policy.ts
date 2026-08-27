import { accessSync, constants, existsSync, statSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { delimiter, isAbsolute, join, resolve } from "node:path";
import type {
	SandboxExecRequest,
	SandboxFilesystemDeny,
	SandboxFilesystemRight,
} from "./sandbox-protocol.ts";
import { hostDevelopmentPaths } from "./host-development-paths.ts";
import {
	DEFAULT_CONFIG,
	buildShellEnvironment,
	mergeGlobalConfig,
	type NativeSandboxConfig,
} from "./sandbox-config.ts";
import {
	canonicalize,
	isInside,
	type IoPermission,
	resolvePermissionPath,
} from "./io-permissions.ts";

const OUTPUT_LIMIT_BYTES = 10 * 1024 * 1024;

export type NativeFilePermission = IoPermission;
export type SandboxSourceEnvironment = Readonly<NodeJS.ProcessEnv>;

export function buildSandboxExecRequest(
	id: string,
	command: string,
	cwd: string,
	timeoutSeconds: number | undefined,
	config: NativeSandboxConfig,
	permissions: readonly NativeFilePermission[],
	networkHosts: readonly string[],
	localPorts: readonly number[],
	sourceEnvironment: SandboxSourceEnvironment,
): SandboxExecRequest {
	const effective = mergeGlobalConfig(DEFAULT_CONFIG, config);
	if (localPorts.some((port) => !Number.isInteger(port) || port < 1 || port > 65_535)) {
		throw new Error("Local network ports must be integers from 1 to 65535");
	}
	const ports = [...new Set(localPorts)].sort((left, right) => left - right);
	if (effective.network?.allowAllUnixSockets) {
		throw new Error("The native sandbox does not support allowing all Unix sockets");
	}
	if (
		timeoutSeconds !== undefined &&
		(!Number.isFinite(timeoutSeconds) || timeoutSeconds > 86_400)
	) {
		throw new Error("Native sandbox timeout must be finite and no more than 24 hours");
	}
	const actualCwd = canonicalize(cwd);
	return {
		type: "exec",
		id,
		command: { program: hostBash(sourceEnvironment), args: ["-c", command] },
		cwd: actualCwd,
		env: {
			...buildShellEnvironment(effective, sourceEnvironment),
			IN_SANDBOX: "1",
			PI_SANDBOX: "nono",
		},
		timeout_ms:
			timeoutSeconds === undefined || timeoutSeconds <= 0
				? null
				: Math.max(1, Math.round(timeoutSeconds * 1000)),
		interactive: false,
		policy: {
			base_rights: baseRights(effective, actualCwd),
			grants: permissions.map(permissionRight),
			denies: denyRules(effective, actualCwd, permissions),
			network: networkHosts.length > 0
				? {
						mode: "proxy",
						allowed_hosts: [...networkHosts],
						local_ports: ports,
					}
				: ports.length > 0
					? { mode: "loopback", ports }
					: { mode: "blocked" },
			unix_socket_roots: unixSocketRoots(effective),
			output_limit_bytes: OUTPUT_LIMIT_BYTES,
		},
	};
}

function hostBash(sourceEnvironment: SandboxSourceEnvironment): string {
	for (const directory of (sourceEnvironment.PATH ?? "").split(delimiter)) {
		if (!directory) continue;
		const candidate = join(directory, "bash");
		try {
			accessSync(candidate, constants.X_OK);
			return canonicalize(candidate);
		} catch {
			// Continue to the fixed fallback.
		}
	}
	return canonicalize("/bin/bash");
}

function unixSocketRoots(config: NativeSandboxConfig): string[] {
	const roots = new Set<string>();
	for (const socket of config.network?.allowUnixSockets ?? []) {
		if (!isAbsolute(socket)) {
			throw new Error(`Native sandbox Unix socket paths must be absolute: ${socket}`);
		}
		const path = canonicalize(socket);
		roots.add(path);
	}
	return [...roots].sort();
}

function baseRights(
	config: NativeSandboxConfig,
	cwd: string,
): SandboxFilesystemRight[] {
	const rights = new Map<string, SandboxFilesystemRight>();
	for (const [access, entries] of [
		["read" as const, config.filesystem?.allowRead ?? []],
		["write" as const, config.filesystem?.allowWrite ?? []],
	] as const) {
		for (const entry of entries) {
			for (const right of configRights(access, entry, cwd)) {
				rights.set(`${access}:${right.path}:${right.scope}`, right);
			}
		}
	}
	return [...rights.values()];
}

function configRights(
	access: "read" | "write",
	entry: string,
	cwd: string,
): SandboxFilesystemRight[] {
	if (entry === ":development_storage") {
		return hostDevelopmentPaths()
			.filter((entry) => access === "read" || entry.writable)
			.map(({ path, directory }) => ({
				access,
				path,
				scope: directory ? "tree" : "file",
				missing_path: "reject",
			}));
	}
	let path: string;
	if (entry === ":root") return [];
	if (entry === "." || entry === ":workspace_roots") path = cwd;
	else if (entry === ":tmpdir") path = canonicalize(tmpdir());
	else if (entry === ":slash_tmp") path = canonicalize("/tmp");
	else if (entry.startsWith(":")) return [];
	else if (containsGlob(entry)) {
		throw new Error(`Native sandbox read/write roots cannot contain globs: ${entry}`);
	} else path = resolvePermissionPath(entry, cwd);

	if (access === "read" && !existsSync(path)) return [];
	const directory = path === "/" || !existsSync(path) || statSync(path).isDirectory();
	return [{
		access,
		path,
		scope: directory ? "tree" : "file",
		missing_path: existsSync(path)
			? "reject"
			: directory
				? "create_tree"
				: "create_file",
	}];
}

function permissionRight(permission: NativeFilePermission): SandboxFilesystemRight {
	return {
		access: permission.kind,
		path: permission.path,
		scope: permission.directory ? "tree" : "file",
		missing_path: "reject",
	};
}

function denyRules(
	config: NativeSandboxConfig,
	cwd: string,
	permissions: readonly NativeFilePermission[],
): SandboxFilesystemDeny[] {
	const rules = new Map<string, SandboxFilesystemDeny>();
	for (const [access, entries] of [
		["read" as const, config.filesystem?.denyRead ?? []],
		["write" as const, config.filesystem?.denyWrite ?? []],
	] as const) {
		for (const entry of entries) {
			const normalized = normalizeDeny(entry, cwd);
			const key = `${normalized.pattern}:${normalized.scope}`;
			const current = rules.get(key);
			rules.set(key, {
				...normalized,
				access:
					current && current.access !== access
						? "read_write"
						: current?.access ?? access,
			});
		}
	}
	const actualCwd = canonicalize(cwd);
	const excludedDynamicRoots = [
		actualCwd,
		canonicalize(tmpdir()),
		canonicalize("/tmp"),
		...hostDevelopmentPaths().map((entry) => entry.path),
	];
	const externalTrees = new Set([
		...baseRights(config, cwd)
			.filter((right) => right.scope === "tree")
			.map((right) => right.path),
		...permissions.filter((permission) => permission.directory).map((permission) => permission.path),
	].filter((root) => !excludedDynamicRoots.some((excluded) => isInside(excluded, root))));
	for (const root of externalTrees) {
		for (const suffix of ["**/.env", "**/.env.*", "**/*.pem", "**/*.key"]) {
			const deny: SandboxFilesystemDeny = {
				access: "read_write",
				pattern: `${root}/${suffix}`,
				scope: "glob",
			};
			rules.set(`${deny.pattern}:${deny.scope}`, deny);
		}
	}
	return [...rules.values()].filter((deny) => !permissions.some((permission) =>
		permission.kind === "write" &&
		permission.directory &&
		deny.access === "write" &&
		deny.scope !== "glob" &&
		resolve(deny.pattern) === resolve(permission.path),
	));
}

function normalizeDeny(
	entry: string,
	cwd: string,
): Omit<SandboxFilesystemDeny, "access"> {
	if (containsGlob(entry)) {
		assertGlobHasNoDotSegments(entry);
		let pattern: string;
		if (entry.startsWith("~/")) pattern = `${homedir()}/${entry.slice(2)}`;
		else if (isAbsolute(entry)) pattern = entry;
		else pattern = `${cwd}/${entry.includes("/") ? entry : `**/${entry}`}`;
		return { pattern, scope: "glob" };
	}
	const pattern = lexicalPath(entry, cwd);
	let scope: "file" | "tree" = "tree";
	try {
		if (existsSync(pattern) && !statSync(pattern).isDirectory()) scope = "file";
	} catch {
		// An unreadable deny root stays a tree deny without probing it further.
	}
	return { pattern, scope };
}

function lexicalPath(path: string, cwd: string): string {
	if (path === "~") return homedir();
	if (path.startsWith("~/")) return resolve(homedir(), path.slice(2));
	return isAbsolute(path) ? resolve(path) : resolve(cwd, path);
}

function assertGlobHasNoDotSegments(value: string): void {
	if (value.split("/").some((part) => part === "." || part === "..")) {
		throw new Error(`Native sandbox deny globs cannot contain . or .. segments: ${value}`);
	}
}

function containsGlob(value: string): boolean {
	return value.includes("*") || value.includes("?") || value.includes("[");
}
