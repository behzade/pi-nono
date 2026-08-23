# Pi Guardian

Fail-closed native command sandbox and explicit access policy for the Pi coding
agent. Guardian uses nono for filesystem and network enforcement and adds a
Linux Bubblewrap layer for deny-over-allow rules.

> **Alpha:** nono's security guarantees are not stable and upstream does not
> recommend production use before its 1.0 security work. Guardian should be
> treated as alpha too.

## Install

After the npm packages are published under the `next` dist-tag:

```sh
pi install npm:pi-extension-sandbox@next
```

Supported npm targets:

- macOS on Apple Silicon;
- Linux x86-64 with unprivileged user namespaces and OS-provided `bwrap` on
  `PATH`.

Guardian has no lifecycle scripts and never resolves nono through `PATH`. The
main package selects an exact-version native package. Linux startup fails closed
when Bubblewrap is unavailable.

Tagged releases also provide reviewed npm tarballs on GitHub. Nix users can use
the repository flake, which substitutes a fixed Nix-store nono executable.

## Scope

Guardian covers Pi's built-in file tools, shell commands, and Guardian
background jobs. It assumes the host, Pi process, installed extensions, nono,
and system Bubblewrap are trusted. It does not claim to contain a compromised
host or a malicious in-process extension.

See the [repository README](https://github.com/behzade/pi-guardian#readme) for
the trust boundary, policy schema, approval lifetime, enforcement details, and
development checks.
