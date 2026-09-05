# pi-nono

OS sandboxing and explicit permissions for the [Pi coding agent](https://pi.dev),
powered by [nono](https://github.com/nolabs-ai/nono). Permissions apply to files,
network hosts, and ports—not shell command strings.

> **Alpha:** nono is still alpha upstream.

## Install

```sh
pi install npm:pi-nono@next
```

Supports macOS Apple Silicon and Linux x86-64. Linux requires unprivileged user
namespaces and an OS-installed `bwrap`. Nix users can use the repository flake.

## Permissions

| Resource | Default access |
| --- | --- |
| Computer files | Read, except protected credentials and secrets |
| Workspace and system temporary directories | Read and write |
| Existing user caches, logs, state, and Jujutsu configuration | Read and write |
| Workspace Git metadata | Read; writes require explicit `.git` approval |
| Workspace `.pi` control files | Read-only |
| GitHub and common package repositories | Allowed |
| Other remote hosts | Explicit host approval |
| Loopback HTTP | Allowed through nono's proxy |
| Raw loopback services | Explicit port approval |

The policy covers built-in file tools and shell commands. Additional rights
require approval for the current session or project. Denied operations are
never retried automatically. Credentials, `.env` files, private keys, and
Pi control paths remain protected; caches are not created or redirected.

Use `/sandbox` to inspect rights and inactive grants. Policies live under
`~/.config/pi-nono/`: `sandbox.json` for machine configuration, `projects/` for
project grants, and `sessions/` for session grants. No active policy is stored
in the repository. Invalid optional grants become inactive; malformed machine
configuration blocks commands. Broader grants never override protected paths.

## Access modes

- `--sandbox-files`: `read-only`, `sandboxed` (default), or `full`.
- `--sandbox-network`: `sandboxed` (default) or `full`.

Full access removes restrictions for that axis. Full access on both axes
bypasses nono and disables new async process handles. Existing processes keep
the policy captured at launch. Grants remain stored when modes change.

Hosts providing their own sandbox can set `PI_NONO_DISABLED=1` to disable the
extension entirely.

## Async commands

`bash` is synchronous by default. Use `execution: "async"` with a short `label`
for independent work. Up to three processes can run concurrently; duplicate
active commands are rejected.

Use `process` to inspect output, write/close stdin, or send a signal. Stdio is
piped, not a terminal. Completions are batched automatically without waiting
for other running jobs; reading a finished process suppresses its pending
notification. No polling or mandatory completion reply is needed.

## Development

```sh
npm run check --prefix extensions/sandbox
git diff --check
```

For version bumps, tagging, and npm publishing, see [Releases](packaging/npm/README.md).
