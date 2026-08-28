import { existsSync, lstatSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, isAbsolute, normalize, relative, resolve, sep } from "node:path";
import {
	filesystemAccessMode,
	networkAccessMode,
	type NativeSandboxConfig,
} from "./sandbox-config.ts";
import {
	canonicalize,
	gitControlRoot,
	isControlRootSymlink,
	isInside,
	isProtectedPath,
	isProtectedWritePath,
	normalizeNetworkHost,
	permissionCoversPath,
	projectControlRoot,
	type IoPermission,
} from "./io-permissions.ts";
import {
	isBaseReadAllowed,
	isBaseWriteAllowed,
	isDeniedByConfig,
} from "./io-policy.ts";
import { networkRuleMatches, runtimeNetworkHosts } from "./network-policy.ts";
import {
	projectPolicyPath,
	readProjectPolicySource,
	writeProjectPolicySource,
} from "./project-policy-store.ts";
export { projectPolicyPath } from "./project-policy-store.ts";

export type ProjectAccessRight =
	| {
			kind: "filesystem";
			access: "read" | "write";
			path: string;
			scope: "file" | "tree";
	  }
	| { kind: "network_host"; host: string }
	| { kind: "network_endpoint"; host: string; port: number };

export type ProjectAccessRequest = ProjectAccessRight;

export interface ProjectSandboxPolicy {
	version: 1;
	rights: ProjectAccessRight[];
}

export interface ActiveProjectPolicy {
	policy: ProjectSandboxPolicy;
	filesystem: IoPermission[];
	networkHosts: string[];
	localPorts: number[];
	config: NativeSandboxConfig;
	inactive: string[];
	/** Exact file bytes loaded or written by the trusted host; null means absent. */
	sourceText: string | null;
}
export const EMPTY_PROJECT_POLICY: ProjectSandboxPolicy = { version: 1, rights: [] };

export function loadProjectPolicy(
	cwd: string,
	globalConfig: NativeSandboxConfig,
): ActiveProjectPolicy {
	try {
		const source = readProjectPolicySource(cwd);
		if (source === null) {
			return activateProjectPolicy(structuredClone(EMPTY_PROJECT_POLICY), cwd, globalConfig);
		}
		const active = activateStoredAccessPolicy(source.policy, cwd, globalConfig, source.sourceText, false);
		if (source.error) active.inactive.unshift(`Project grants ignored: ${source.error}`);
		return active;
	} catch (error) {
		return inactiveEmptyPolicy(cwd, globalConfig, `Project grants ignored: ${errorMessage(error)}`);
	}
}

export function loadProjectPolicyForUpdate(
	cwd: string,
	globalConfig: NativeSandboxConfig,
): ActiveProjectPolicy {
	// Callers synchronize this fresh project snapshot before preparing an
	// approval; the conditional save below still rejects edits made meanwhile.
	return loadProjectPolicy(cwd, globalConfig);
}

export function activateProjectPolicy(
	policy: ProjectSandboxPolicy,
	cwd: string,
	globalConfig: NativeSandboxConfig,
	sourceText: string | null = null,
): ActiveProjectPolicy {
	return activateAccessPolicy(policy, cwd, globalConfig, sourceText, false);
}

/** Activates a session/effective policy, which may contain host-specific absolute paths. */
export function activateSessionPolicy(
	policy: ProjectSandboxPolicy,
	cwd: string,
	globalConfig: NativeSandboxConfig,
	sourceText: string | null = null,
): ActiveProjectPolicy {
	return activateAccessPolicy(policy, cwd, globalConfig, sourceText, true);
}

export function activateStoredSessionPolicy(
	value: unknown,
	cwd: string,
	globalConfig: NativeSandboxConfig,
	sourceText: string | null = null,
): ActiveProjectPolicy {
	return activateStoredAccessPolicy(value, cwd, globalConfig, sourceText, true);
}

function activateAccessPolicy(
	policy: ProjectSandboxPolicy,
	cwd: string,
	globalConfig: NativeSandboxConfig,
	sourceText: string | null,
	allowAbsolutePaths: boolean,
): ActiveProjectPolicy {
	return activateNormalizedPolicy(
		normalizeAccessPolicy(policy, allowAbsolutePaths),
		cwd,
		globalConfig,
		sourceText,
	);
}

function activateStoredAccessPolicy(
	value: unknown,
	cwd: string,
	globalConfig: NativeSandboxConfig,
	sourceText: string | null,
	allowAbsolutePaths: boolean,
): ActiveProjectPolicy {
	const { policy, inactive } = normalizeStoredPolicy(value, allowAbsolutePaths);
	return activateNormalizedPolicy(policy, cwd, globalConfig, sourceText, inactive);
}

function activateNormalizedPolicy(
	policy: ProjectSandboxPolicy,
	cwd: string,
	config: NativeSandboxConfig,
	sourceText: string | null,
	inactive?: string[],
): ActiveProjectPolicy {
	const activeRights: ProjectAccessRight[] = [];
	const filesystem: IoPermission[] = [];
	const networkHosts = new Set<string>();
	const localPorts = new Set<number>();
	for (const right of policy.rights) {
		try {
			if (right.kind === "network_endpoint") {
				assertNetworkEndpointAllowed(right, config);
				localPorts.add(right.port);
			} else if (right.kind === "network_host") {
				assertNetworkHostAllowed(right, config);
				networkHosts.add(right.host);
			} else {
				filesystem.push(activateFilesystemRight(right, cwd, config));
			}
			activeRights.push(right);
		} catch (error) {
			if (!inactive) throw error;
			inactive.push(`${rightLabel(right)}: ${errorMessage(error)}`);
		}
	}
	return {
		policy: { version: 1, rights: activeRights },
		filesystem,
		networkHosts: [...networkHosts].sort(),
		localPorts: [...localPorts].sort((left, right) => left - right),
		config,
		inactive: inactive ?? [],
		sourceText,
	};
}

function inactiveEmptyPolicy(
	cwd: string,
	globalConfig: NativeSandboxConfig,
	message: string,
): ActiveProjectPolicy {
	const active = activateProjectPolicy(EMPTY_PROJECT_POLICY, cwd, globalConfig);
	active.inactive.push(message);
	return active;
}

export function addProjectAccess(
	current: ProjectSandboxPolicy,
	requests: readonly ProjectAccessRequest[],
	cwd: string,
	globalConfig: NativeSandboxConfig,
): ActiveProjectPolicy {
	return addAccess(current, requests, cwd, globalConfig, false);
}

export function addSessionAccess(
	current: ProjectSandboxPolicy,
	requests: readonly ProjectAccessRequest[],
	cwd: string,
	globalConfig: NativeSandboxConfig,
): ActiveProjectPolicy {
	return addAccess(current, requests, cwd, globalConfig, true);
}

function addAccess(
	current: ProjectSandboxPolicy,
	requests: readonly ProjectAccessRequest[],
	cwd: string,
	globalConfig: NativeSandboxConfig,
	allowAbsolutePaths: boolean,
): ActiveProjectPolicy {
	if (requests.length === 0) throw new Error("request_access needs at least one access request");
	if (requests.length > 32) throw new Error("request_access accepts at most 32 access requests");

	const requestedRights = requests.map((request) =>
		normalizeRequestedRight(request, cwd, allowAbsolutePaths));
	if (
		filesystemAccessMode(globalConfig) === "read-only" &&
		requestedRights.some((right) => right.kind === "filesystem" && right.access === "write")
	) {
		throw new Error("Filesystem writes cannot be granted while Files is Read-only");
	}

	const currentNormalized = normalizeAccessPolicy(current, allowAbsolutePaths);
	const currentActive = allowAbsolutePaths
		? activateSessionPolicy(currentNormalized, cwd, globalConfig)
		: activateProjectPolicy(currentNormalized, cwd, globalConfig);
	const uniqueRequestedRights = [...new Map(
		requestedRights.map((right) => [rightKey(right), right]),
	).values()];
	const netNewRights = uniqueRequestedRights.filter((right) =>
		!rightAlreadyAllowed(right, currentActive, cwd, globalConfig));
	assertNoGiantSiblingFileList(netNewRights);
	const candidate = normalizeAccessPolicy({
		...currentNormalized,
		rights: [...currentNormalized.rights, ...netNewRights],
	}, allowAbsolutePaths);
	return allowAbsolutePaths
		? activateSessionPolicy(candidate, cwd, globalConfig)
		: activateProjectPolicy(candidate, cwd, globalConfig);
}

function rightAlreadyAllowed(
	request: ProjectAccessRight,
	active: ActiveProjectPolicy,
	cwd: string,
	config: NativeSandboxConfig,
): boolean {
	if (request.kind === "network_host") {
		return networkAccessMode(config) === "full" ||
			runtimeNetworkHosts(config, []).includes(request.host) ||
			active.networkHosts.includes(request.host);
	}
	if (request.kind === "network_endpoint") {
		return networkAccessMode(config) === "full" || active.localPorts.includes(request.port);
	}

	if (filesystemAccessMode(config) === "full") return true;
	const lexical = expandPortablePath(request.path, cwd);
	const actual = canonicalize(lexical);
	if (active.filesystem.some((permission) =>
		(permission.kind === request.access || (request.access === "read" && permission.kind === "write")) &&
		permissionCoversPath(permission, actual))) {
		return true;
	}
	if (
		isProtectedPath(lexical) ||
		(request.access === "write" && isProtectedWritePath(lexical)) ||
		isDeniedByConfig(actual, request.access, config, cwd)
	) {
		return false;
	}
	return request.access === "read"
		? isBaseReadAllowed(actual, config, cwd)
		: isBaseWriteAllowed(actual, config, cwd);
}

export function requestsRequireSessionScope(
	requests: readonly ProjectAccessRequest[],
	cwd: string,
): boolean {
	const workspace = resolve(cwd);
	const home = resolve(homedir());
	return requests.some((request) => {
		if (request.kind !== "filesystem" || !isAbsolute(request.path)) return false;
		const absolute = resolve(request.path);
		return !isInside(workspace, absolute) && !isInside(home, absolute);
	});
}

/** Trusted host write used only after the user approves the displayed additions. */
export function saveProjectPolicy(
	cwd: string,
	policy: ProjectSandboxPolicy,
	expectedSourceText?: string | null,
): string {
	const normalized = normalizeProjectPolicy(policy);
	return writeProjectPolicySource(cwd, normalized, expectedSourceText);
}

export function sameProjectPolicy(
	left: ProjectSandboxPolicy,
	right: ProjectSandboxPolicy,
): boolean {
	return JSON.stringify(normalizeSessionPolicy(left)) === JSON.stringify(normalizeSessionPolicy(right));
}

export function mergeAccessPolicies(
	...policies: readonly ProjectSandboxPolicy[]
): ProjectSandboxPolicy {
	const rights = policies.flatMap((policy) => normalizeSessionPolicy(policy).rights);
	return normalizeSessionPolicy({ version: 1, rights });
}

export function accessPolicyAdditions(
	before: ProjectSandboxPolicy,
	after: ProjectSandboxPolicy,
): ProjectSandboxPolicy {
	const beforeNormalized = normalizeSessionPolicy(before);
	const afterNormalized = normalizeSessionPolicy(after);
	const beforeRights = new Set(beforeNormalized.rights.map(rightKey));
	const rights = afterNormalized.rights.filter((right) => !beforeRights.has(rightKey(right)));
	return normalizeSessionPolicy({ version: 1, rights });
}

export function sandboxPolicyDiff(
	before: ProjectSandboxPolicy,
	after: ProjectSandboxPolicy,
	heading: string,
): string {
	return sandboxPolicySummary(accessPolicyAdditions(before, after), heading);
}

export function sandboxPolicySummary(
	additions: ProjectSandboxPolicy,
	heading = "Requested sandbox rights:",
): string {
	const lines = additions.rights.map((right) => {
		if (right.kind === "filesystem") {
			return `  ${right.access.padEnd(8)}${(right.scope === "tree" ? "directory" : "file").padEnd(11)}${JSON.stringify(right.path)}`;
		}
		if (right.kind === "network_host") {
			return `  ${"network".padEnd(8)}${"host".padEnd(11)}${JSON.stringify(right.host)}`;
		}
		return `  ${"network".padEnd(8)}${"endpoint".padEnd(11)}${JSON.stringify(`${right.host}:${right.port}`)}`;
	});
	return [heading, ...lines].join("\n");
}

export function normalizeProjectPolicy(value: unknown): ProjectSandboxPolicy {
	return normalizeAccessPolicy(value, false);
}

export function normalizeSessionPolicy(value: unknown): ProjectSandboxPolicy {
	return normalizeAccessPolicy(value, true);
}

function normalizeAccessPolicy(value: unknown, allowAbsolutePaths: boolean): ProjectSandboxPolicy {
	if (!value || typeof value !== "object" || Array.isArray(value)) {
		throw new Error("project sandbox policy must be a JSON object");
	}
	const input = value as Record<string, unknown>;
	assertKnownKeys(input, ["version", "rights"], "project sandbox policy");
	if (input.version !== 1) throw new Error("project sandbox policy version must be 1");
	if (!Array.isArray(input.rights)) throw new Error("project sandbox policy rights must be an array");
	if (input.rights.length > 256) throw new Error("project sandbox policy accepts at most 256 rights");
	const rights = input.rights.map((right) => normalizeRight(right, allowAbsolutePaths));
	const uniqueRights = [...new Map(rights.map((right) => [rightKey(right), right])).values()]
		.sort((left, right) => rightKey(left).localeCompare(rightKey(right)));
	if (uniqueRights.filter((right) => right.kind === "filesystem").length > 64) {
		throw new Error("Project policy accepts at most 64 filesystem rights; use tree rights instead of file lists");
	}
	return { version: 1, rights: uniqueRights };
}

function normalizeStoredPolicy(
	value: unknown,
	allowAbsolutePaths: boolean,
): { policy: ProjectSandboxPolicy; inactive: string[] } {
	const inactive: string[] = [];
	if (!value || typeof value !== "object" || Array.isArray(value)) {
		return { policy: structuredClone(EMPTY_PROJECT_POLICY), inactive: ["Stored grants must be a JSON object"] };
	}
	const input = value as Record<string, unknown>;
	if (input.version !== 1 || !Array.isArray(input.rights)) {
		return { policy: structuredClone(EMPTY_PROJECT_POLICY), inactive: ["Stored grants need version 1 and a rights array"] };
	}
	const unknown = Object.keys(input).filter((key) => !["version", "rights"].includes(key));
	if (unknown.length > 0) inactive.push(`Unknown stored grant fields ignored: ${unknown.join(", ")}`);
	const rights: ProjectAccessRight[] = [];
	for (const [index, value] of input.rights.entries()) {
		try {
			rights.push(normalizeRight(value, allowAbsolutePaths));
		} catch (error) {
			inactive.push(`right ${index + 1}: ${errorMessage(error)}`);
		}
	}
	const unique = [...new Map(rights.map((right) => [rightKey(right), right])).values()]
		.sort((left, right) => rightKey(left).localeCompare(rightKey(right)));
	return { policy: { version: 1, rights: unique }, inactive };
}

function assertNetworkEndpointAllowed(
	right: Extract<ProjectAccessRight, { kind: "network_endpoint" }>,
	config: NativeSandboxConfig,
): void {
	if (config.network?.enabled === false) {
		throw new Error(`${right.host}:${right.port} is denied because network access is disabled by machine policy`);
	}
	if ((config.network?.deniedDomains ?? []).some((rule) => networkRuleMatches(rule, right.host))) {
		throw new Error(`${right.host}:${right.port} is denied by the machine sandbox policy`);
	}
}

function assertNetworkHostAllowed(
	right: Extract<ProjectAccessRight, { kind: "network_host" }>,
	config: NativeSandboxConfig,
): void {
	if (config.network?.enabled === false) {
		throw new Error(`${right.host} is denied because network access is disabled by machine policy`);
	}
	if ((config.network?.deniedDomains ?? []).some((rule) => networkRuleMatches(rule, right.host))) {
		throw new Error(`${right.host} is denied by the machine sandbox policy`);
	}
}

function normalizeRequestedRight(
	right: ProjectAccessRight,
	cwd: string,
	allowAbsolutePaths: boolean,
): ProjectAccessRight {
	if (right.kind !== "filesystem") return normalizeRight(right, allowAbsolutePaths);
	return normalizeRight({
		...right,
		path: portableRequestPath(right.path, cwd, allowAbsolutePaths),
	}, allowAbsolutePaths);
}

function normalizeRight(value: unknown, allowAbsolutePaths = false): ProjectAccessRight {
	if (!value || typeof value !== "object" || Array.isArray(value)) {
		throw new Error("each project sandbox right must be a JSON object");
	}
	const right = value as Record<string, unknown>;
	if (right.kind === "filesystem") {
		assertKnownKeys(right, ["kind", "access", "path", "scope"], "filesystem right");
		if (right.access !== "read" && right.access !== "write") {
			throw new Error("filesystem access must be read or write");
		}
		if (right.scope !== "file" && right.scope !== "tree") {
			throw new Error("filesystem scope must be file or tree");
		}
		return {
			kind: "filesystem",
			access: right.access,
			path: normalizeFilesystemPath(right.path, allowAbsolutePaths),
			scope: right.scope,
		};
	}
	if (right.kind === "network_host") {
		assertKnownKeys(right, ["kind", "host"], "network_host right");
		if (typeof right.host !== "string") throw new Error("network_host host must be a string");
		return { kind: "network_host", host: normalizeNetworkHost(right.host) };
	}
	if (right.kind === "network_endpoint") {
		assertKnownKeys(right, ["kind", "host", "port"], "network_endpoint right");
		if (typeof right.host !== "string") throw new Error("network_endpoint host must be a string");
		const host = normalizeNetworkHost(right.host);
		if (!["localhost", "127.0.0.1", "::1"].includes(host)) {
			throw new Error("network_endpoint host must be localhost, 127.0.0.1, or ::1");
		}
		if (!Number.isInteger(right.port) || (right.port as number) < 1 || (right.port as number) > 65_535) {
			throw new Error("network_endpoint port must be an integer from 1 to 65535");
		}
		return { kind: "network_endpoint", host: "localhost", port: right.port as number };
	}
	throw new Error("project sandbox right kind must be filesystem, network_host, or network_endpoint");
}

function activateFilesystemRight(
	right: Extract<ProjectAccessRight, { kind: "filesystem" }>,
	cwd: string,
	config: NativeSandboxConfig,
): IoPermission {
	const lexical = expandPortablePath(right.path, cwd);
	assertNoExistingSymlink(right.path, cwd);
	const actual = canonicalize(lexical);
	const projectRoot = right.access === "write" ? projectControlRoot(lexical, cwd) : undefined;
	if (projectRoot) {
		throw new Error("Project policy cannot grant sandboxed writes to project .pi");
	}
	const gitRoot = right.access === "write" ? gitControlRoot(lexical, cwd) : undefined;
	const explicitGitRoot = gitRoot !== undefined && actual === canonicalize(gitRoot);
	if (
		isProtectedPath(lexical) ||
		(right.access === "write" && isProtectedWritePath(lexical)) ||
		(isDeniedByConfig(actual, right.access, config, cwd) && !explicitGitRoot)
	) {
		throw new Error(`Project policy cannot grant protected or machine-denied ${right.access} access: ${right.path}`);
	}
	if (!existsSync(actual)) {
		throw new Error(`Filesystem rights must target an existing path; approve an existing parent directory instead: ${right.path}`);
	}
	if (existsSync(actual)) {
		const directory = statSync(actual).isDirectory();
		if ((right.scope === "tree") !== directory) {
			throw new Error(`Project policy ${right.scope} scope does not match the existing path type: ${right.path}`);
		}
	}
	if (right.access === "write") {
		if (gitRoot && isControlRootSymlink(gitRoot)) {
			throw new Error(`Project policy cannot grant a symlinked control root: ${gitRoot}`);
		}
	}
	return { kind: right.access, path: actual, directory: right.scope === "tree" };
}

function portableRequestPath(value: unknown, cwd: string, allowAbsolutePaths: boolean): string {
	if (typeof value !== "string" || value.length === 0 || value.includes("\0")) {
		throw new Error("filesystem path must be a non-empty portable path");
	}
	if (value.length > 1024) throw new Error("filesystem paths must be at most 1024 characters");
	if (!isAbsolute(value)) return normalizePortablePath(value);
	const absolute = resolve(value);
	const workspace = resolve(cwd);
	if (isInside(workspace, absolute)) {
		const path = relative(workspace, absolute);
		return path || ".";
	}
	const home = resolve(homedir());
	if (isInside(home, absolute)) {
		const path = relative(home, absolute);
		return path ? `~/${path}` : "~";
	}
	if (allowAbsolutePaths) return absolute;
	throw new Error("Absolute filesystem request paths must be inside the project or home directory");
}

function normalizeFilesystemPath(value: unknown, allowAbsolutePaths: boolean): string {
	if (allowAbsolutePaths && typeof value === "string" && isAbsolute(value)) {
		if (value.length === 0 || value.includes("\0")) {
			throw new Error("filesystem path must be a non-empty path");
		}
		if (value.length > 1024) throw new Error("filesystem paths must be at most 1024 characters");
		return resolve(value);
	}
	return normalizePortablePath(value);
}

function normalizePortablePath(value: unknown): string {
	if (typeof value !== "string" || value.length === 0 || value.includes("\0")) {
		throw new Error("filesystem path must be a non-empty portable path");
	}
	if (value.length > 1024) throw new Error("filesystem paths must be at most 1024 characters");
	if (isAbsolute(value)) {
		throw new Error("Project filesystem paths must be project-relative or home-relative (~/)");
	}
	if (value === "~") return value;
	const homeRelative = value.startsWith("~/");
	const body = homeRelative ? value.slice(2) : value;
	const normalized = normalize(body);
	if (
		isAbsolute(body) ||
		normalized === ".." ||
		normalized.startsWith(`..${sep}`)
	) {
		throw new Error(
			homeRelative
				? "home-relative filesystem paths cannot escape the home directory"
				: "relative filesystem paths cannot escape the project root",
		);
	}
	return homeRelative ? `~/${normalized}` : normalized;
}

function expandPortablePath(path: string, cwd: string): string {
	if (path === "~") return homedir();
	if (path.startsWith("~/")) return resolve(homedir(), path.slice(2));
	if (isAbsolute(path)) return resolve(path);
	return resolve(cwd, path);
}

function assertNoExistingSymlink(path: string, cwd: string): void {
	const root = isAbsolute(path)
		? resolve(path).split(sep)[0] || sep
		: path === "~" || path.startsWith("~/")
			? resolve(homedir())
			: resolve(cwd);
	const target = expandPortablePath(path, cwd);
	const rel = relative(root, target);
	let current = root;
	for (const part of rel === "" ? [] : rel.split(sep)) {
		current = resolve(current, part);
		const metadata = lstatIfExists(current);
		if (!metadata) break;
		if (metadata.isSymbolicLink()) {
			throw new Error(`Project filesystem rights cannot cross an existing symlink: ${current}`);
		}
	}
}

function assertNoGiantSiblingFileList(rights: readonly ProjectAccessRight[]): void {
	const groups = new Map<string, number>();
	for (const right of rights) {
		if (right.kind !== "filesystem" || right.scope !== "file") continue;
		const key = `${right.access}:${dirname(right.path)}`;
		groups.set(key, (groups.get(key) ?? 0) + 1);
	}
	for (const [key, count] of groups) {
		if (count > 3) {
			throw new Error(`Rejecting ${count} new sibling file rights under ${key.slice(key.indexOf(":") + 1)}; request one tree right instead`);
		}
	}
}

function lstatIfExists(path: string): ReturnType<typeof lstatSync> | undefined {
	try {
		return lstatSync(path);
	} catch (error) {
		if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") {
			return undefined;
		}
		throw error;
	}
}

function rightKey(right: ProjectAccessRight): string {
	return JSON.stringify(right);
}

function rightLabel(right: ProjectAccessRight): string {
	if (right.kind === "filesystem") return `${right.access} ${right.scope} ${right.path}`;
	if (right.kind === "network_host") return `network host ${right.host}`;
	return `network endpoint ${right.host}:${right.port}`;
}

function errorMessage(error: unknown): string {
	return error instanceof Error ? error.message : String(error);
}

function assertKnownKeys(value: Record<string, unknown>, allowed: readonly string[], field: string): void {
	const unknown = Object.keys(value).filter((key) => !allowed.includes(key));
	if (unknown.length > 0) throw new Error(`${field} contains unknown fields: ${unknown.join(", ")}`);
}
