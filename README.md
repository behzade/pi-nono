# Guardian

Guardian is a sandbox and permission system for the [Pi coding agent](https://pi.dev), powered by [nono](https://github.com/nolabs-ai/nono).
It gives Pi workspace access by default and asks for approval when a task needs
access to another file, service, or local port.

> **Alpha:** Guardian uses nono, which is still alpha upstream.

## Default permissions

| Resource | Default access |
| --- | --- |
| Workspace | Read and write |
| System temporary directories | Read and write |
| `~/.cache/pi-sandbox` | Read and write |
| Workspace Git metadata | Read; write with explicit `.git` approval |
| Remote hosts | Explicit host approval |
| Loopback services | Explicit host and port approval |

Guardian redirects common package-manager caches into
`~/.cache/pi-sandbox`. Credentials, authentication files, `.env` files, private
keys, and Guardian/Pi/Codex control paths remain protected.

The policy covers Pi's built-in file tools, shell commands, and Guardian
background jobs.

## Install

npm packages support macOS on Apple Silicon and Linux x86-64. Linux requires
unprivileged user namespaces and `bwrap` from the system package manager.

```sh
pi install npm:pi-extension-sandbox@next
```

Nix users can use the repository flake. Tagged releases also include the main
package and platform-specific npm tarballs.

## Permissions

When a task needs more access, Guardian shows the exact capability and lets the
user approve it for the current Pi session or the project.

Supported capabilities are:

- file or directory `read` and `write` access;
- outbound access to an exact hostname;
- access to an exact loopback host and port;
- managed development-cache mappings.

| Policy | Path | Scope |
| --- | --- | --- |
| Machine | `~/.config/guardian/sandbox.json` | All Guardian projects |
| Project | `.guardian/sandbox.json` | Current trusted project |
| Session | `~/.config/guardian/session-rights/<session-id-hash>.json` | Current Pi session |

Session permissions are bound to the exact Pi session and persist when that
session is resumed.

## How it works

Guardian builds an immutable nono profile from the active machine, project, and
session policy for each command. Background jobs keep the policy captured when
they start.

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
