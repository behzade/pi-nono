# npm release packaging

Guardian publishes one TypeScript package plus platform-specific nono packages. The source
package remains private to prevent publishing without its native dependencies;
`build-packages.mjs main` creates the publishable manifest.

Supported targets:

| Package | Native contents |
| --- | --- |
| `pi-extension-sandbox-darwin-arm64` | nono 0.61.1 |
| `pi-extension-sandbox-linux-x64` | nono 0.61.1 |

The build accepts only explicit absolute input paths. It checks nono's version,
architecture, checksum, and runtime linkage, and rejects symlinks and Nix-store
runtime dependencies. At runtime, Linux requires an OS-provided `bwrap` on
`PATH`; startup fails closed with an explicit error when it is missing. nono is
never resolved through `PATH`.

## Stage packages

```sh
node packaging/npm/build-packages.mjs main --out "$PWD/dist/npm"

node packaging/npm/build-packages.mjs native \
  --platform darwin --arch arm64 \
  --out "$PWD/dist/npm" \
  --nono /absolute/path/to/nono \
  --nono-license /absolute/path/to/nono-LICENSE

node packaging/npm/build-packages.mjs native \
  --platform linux --arch x64 \
  --out "$PWD/dist/npm" \
  --nono /absolute/path/to/nono \
  --nono-license /absolute/path/to/nono-LICENSE
```

The nono inputs must come from the official v0.61.1 release artifacts pinned by
Guardian's nixpkgs revision. Linux hosts must install Bubblewrap through their
OS package manager. Review upstream security and release notes before changing
nono.

A `v*` Git tag runs all three package jobs and creates a prerelease GitHub
release containing the main and native tarballs. The tag must match the package
version exactly, for example `v3.0.0` for package version `3.0.0`.

npm publishing remains deliberately manual. Reserve all three package names,
review the generated manifests, checksums, licenses, and platform results, test
installation with `npm install --ignore-scripts`, publish both native packages
first, and publish the main package last with the `next` dist-tag.
