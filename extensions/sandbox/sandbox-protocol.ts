export interface SandboxFilesystemRight {
	access: "read" | "write";
	path: string;
	scope: "file" | "tree";
	missing_path: "reject" | "create_file" | "create_tree";
}

export interface SandboxFilesystemDeny {
	access: "read" | "write" | "read_write";
	pattern: string;
	scope: "file" | "tree" | "glob";
}

export interface SandboxDenial {
	operation: string;
	path: string | null;
	process: string | null;
}

export interface SandboxExecResult {
	exitCode: number | null;
	denials: SandboxDenial[];
	denialsComplete: boolean;
}

export interface SandboxExecRequest {
	type: "exec";
	id: string;
	command: { program: string; args: string[] };
	cwd: string;
	env: Record<string, string>;
	timeout_ms: number | null;
	interactive?: boolean;
	policy: {
		filesystem_mode: "read-only" | "sandboxed" | "full";
		base_rights: SandboxFilesystemRight[];
		grants: SandboxFilesystemRight[];
		denies: SandboxFilesystemDeny[];
		network:
			| { mode: "full" }
			| { mode: "blocked" }
			| { mode: "loopback"; ports: number[] }
			| {
					mode: "proxy";
					allowed_hosts: string[];
					local_ports: number[];
			  };
		unix_socket_roots: string[];
		output_limit_bytes: number;
	};
}
