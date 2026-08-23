# pi-nono

nono sandboxing and explicit permissions for the Pi coding agent.

> **Alpha:** pi-nono uses nono, which is still alpha upstream.

## Install

```sh
pi install npm:pi-nono@next
```

Supported npm targets:

- macOS on Apple Silicon;
- Linux x86-64 with unprivileged user namespaces and `bwrap` from the system
  package manager.

The main package selects an exact-version native nono package for the current
platform. Nix users can use the repository flake.

See the [repository README](https://github.com/behzade/pi-nono#readme) for
default permissions, policy scopes, and development instructions.
