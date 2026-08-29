# pi-nono

pi-nono is a sandbox and permission system for the [Pi coding agent](https://pi.dev), powered by [nono](https://github.com/nolabs-ai/nono).
It gives Pi broad safe reads, development writes, and common package-network
access by default, then asks for approval only outside those boundaries.
Unlike command-based sandboxes that allow or deny volatile scripts, pi-nono enforces permissions at stable I/O boundaries: files, network services, and local ports.

> **Alpha:** pi-nono uses nono, which is still alpha upstream.

## Default permissions

| Resource | Default access |
| --- | --- |
| Computer files | Read, except protected credentials and secrets |
| Workspace | Read and write |
| System temporary directories | Read and write |
| Existing user caches, logs, and state | Read and write |
| Existing Jujutsu configuration | Read and write |
| Workspace Git metadata | Read; write with explicit `.git` approval |
| Workspace `.pi` control files | Read-only |
| GitHub and common package repositories | Allowed |
| Other remote hosts | Explicit host approval |
| Loopback HTTP hosts | Allowed through nono's proxy |
| Raw loopback services | Explicit port approval |

pi-nono does not create or redirect package-manager caches. It grants existing,
symlink-free cache, state, log, and development roots at their normal host
locations. Credentials, authentication files, `.env` files, private keys, and
pi-nono/Pi/Codex control paths remain protected.

The policy covers Pi's built-in file tools and shell commands. A bash command
may yield a session-scoped process handle; continued interaction keeps the
immutable policy captured when that command started.

## Install

npm packages support macOS on Apple Silicon and Linux x86-64. Linux requires
unprivileged user namespaces and `bwrap` from the system package manager.

```sh
pi install npm:pi-nono@next
```

Nix users can use the repository flake. Tagged releases also include the main
package and platform-specific npm tarballs.

## Long-running processes

`bash` runs commands synchronously by default. Set `execution` to `async` and
provide a short `label` when independent execution is intentional; the call
then returns a process session. Async execution supports finite work such as a
long test as well as persistent servers and watchers. At most three async
processes may run at once, and duplicate commands in the same canonical working
directory are rejected. The `process` tool can inspect current output, write or
close stdin, or send `INT`, `TERM`, or `KILL`; it never waits for future output.
Async processes use piped stdio rather than a pseudo-terminal. Completion wakes
the agent automatically, so agents must not poll.

## Access modes

Filesystem and network access are independent startup modes. Files can be
`read-only`, `sandboxed` (the default), or `full`; network can be `sandboxed`
(the default) or `full`. Pi GPUI exposes both axes in one composer menu and
restarts the child process when either changes. The equivalent flags are
`--sandbox-files <mode>` and `--sandbox-network <mode>`.

Full mode removes pi-nono restrictions only for its selected axis. Selecting
Full for both axes bypasses nono entirely; async process handles are then
unavailable. Existing project and session grants remain stored and become
active again when returning to sandboxed mode. Running async processes retain
the immutable mode and grants they started with.

## Permissions

When a task needs more access, pi-nono shows the exact capability and lets the
user approve it for the current Pi session or the project.

Supported capabilities are:

- file or directory `read` and `write` access;
- outbound access to an exact hostname;
- access to an exact loopback host and port.

| Policy | Path | Scope |
| --- | --- | --- |
| Machine | `~/.config/pi-nono/sandbox.json` | All pi-nono projects |
| Project | `~/.config/pi-nono/projects/<workspace-hash>.json` | One workspace identity |
| Session | `~/.config/pi-nono/sessions/<session-id-hash>.json` | One Pi session identity |

Project and session grants are host-owned. No active permission policy is
stored in the repository. Project records are bound to the canonical workspace
path and filesystem identity; session records are also bound to the exact Pi
session file.

Invalid, deleted, symlinked, or type-changed optional grants are inactive and
shown by `/sandbox`; they do not disable other grants or the sandbox. Deleted
paths are not recreated. A malformed machine policy still blocks commands
because ignoring machine restrictions could widen access.

Broad read grants retain all nested machine denials. Broad write grants are
rejected when the platform cannot safely enforce denied descendants.

## How it works

pi-nono generates an immutable, temporary nono profile from the active machine,
project, and session policy for each command. It does not use persistent nono
profiles from `~/.config/nono`. Detached process sessions keep the policy
captured when they start, deliver completion automatically, and never retry.

- **Linux:** Landlock and nono enforce filesystem and network access. Bubblewrap
  applies protected subpaths inside writable directories.
- **macOS:** Seatbelt and nono enforce filesystem and network access.

The Nix package uses a fixed Nix-store nono executable. npm releases select an
exact-version native nono package for the current platform.

## Development

```bash
npm run check --prefix extensions/sandbox
git diff --check
```

Release packaging is documented in [`packaging/npm`](packaging/npm/README.md).
