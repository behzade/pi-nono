# npm release packaging

pi-nono publishes one TypeScript package plus platform-specific nono packages. The source
package remains private to prevent publishing without its native dependencies;
`build-packages.mjs main` creates the publishable manifest.

Supported targets:

| Package | Native contents |
| --- | --- |
| `pi-nono-darwin-arm64` | nono 0.61.1 |
| `pi-nono-linux-x64` | nono 0.61.1 |

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
pi-nono's nixpkgs revision. Linux hosts must install Bubblewrap through their
OS package manager. Review upstream security and release notes before changing
nono.

## Publish on tag push

Pushing a `v*` Git tag runs all three packaging jobs, publishes their tested
artifacts to npm with the `next` dist-tag, then creates a GitHub prerelease
containing the same tarballs. Both native packages are published before the
main package. Pull requests and manual workflow runs only build and test;
they never publish or create releases.

## npm Trusted Publishing setup

Configure a GitHub Actions trusted publisher separately in the npm settings for
**each** package: `pi-nono`, `pi-nono-darwin-arm64`, and `pi-nono-linux-x64`.
Use the same settings for all three:

- **Organization or user:** the GitHub owner of this repository.
- **Repository:** this repository's name.
- **Workflow filename:** `npm-packages.yml` (not the full path).
- **Environment name:** leave blank; the publish job has no GitHub environment.
- If npm offers allowed-action controls, enable direct `npm publish`.

The packages must already exist to configure their trusted publishers. If a
name is new, create its initial release manually first, then use a new version
for the first automated release.

The publish job uses GitHub-hosted runners, Node 24 (npm >= 11.5.1), and
job-scoped `id-token: write`. npm obtains short-lived credentials through OIDC;
no `NPM_TOKEN` or `NODE_AUTH_TOKEN` secret is required. Remove any old publishing
token secret once it is no longer used elsewhere. Do not add token-based npm
configuration to the publish job.

Restrict creation of `v*` tags to release maintainers: pushing one authorizes
public publication through the configured trusted publishers.

Set the version in `extensions/sandbox/package.json` and its lockfile, commit
and push the release changes, then push the matching tag:

```sh
git tag v3.0.0
git push origin v3.0.0
```

The tag must match the manifest version exactly. Choose a version that has not
already been published; npm package versions are immutable. Publication is not
atomic across the three packages: if a job fails after publishing a native
package, inspect npm before retrying (a plain rerun cannot republish that
version). Resolve the partial release manually or publish a new version.

Do not publish `extensions/sandbox` directly: its source manifest intentionally
remains private. The workflow publishes only generated tarballs after platform
installation checks pass.
