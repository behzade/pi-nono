# Agent Instructions

Keep the pi-nono policy adapter, fixed nono executable, and Linux-only fixed
Bubblewrap deny layer as one security boundary. Preserve fail-closed behavior, explicit approval, exact policy
validation, immutable command snapshots, and no automatic retry.

The project shell is already active. Do not run Nix commands unless the user
asks for that exact check. Never create alternate dependency folders, Nix
caches, Rust target directories, or Node module folders.

Run the narrowest relevant check first. For adapter changes use
`npm run check --prefix extensions/sandbox`. Always run `git diff --check`.

nono is security-critical and currently alpha upstream. Keep it pinned through
the flake's nixpkgs revision. Review upstream security and release notes before
updating. Production code must use fixed packaged executables and must never
resolve nono through `PATH`. The Linux deny layer may scan only
static non-root glob directories and must not follow directory symlinks.
