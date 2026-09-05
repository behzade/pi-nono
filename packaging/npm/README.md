# Releases

From a clean working tree with matching manifest and lockfile versions:

```sh
make release BUMP=patch  # default; also accepts minor or major
```

This updates both manifests, commits them, and creates an annotated version
tag. It refuses existing tags and does not push. Review the result, then run
the printed `git push --atomic origin HEAD v<VERSION>` command.

Tag pushes build and test all three packages, stage them on npm under `next`,
and create a **draft** GitHub prerelease. PRs and manual workflow runs only test
and build.

Review the **Staged Packages** on npmjs.com and approve with 2FA: both native
packages first, then `pi-nono`. CLI users can use `npm stage list <package>` and
`npm stage approve <stage-id>` (npm >= 11.15.0). Once all three are live, publish
the GitHub release draft. Inspect partial staging before retrying: staged and
published versions both reserve the package version.

## One-time npm setup

Configure GitHub Actions Trusted Publishing separately for `pi-nono`,
`pi-nono-darwin-arm64`, and `pi-nono-linux-x64`:

- **Owner / repository:** this GitHub repository.
- **Workflow filename:** `npm-packages.yml`.
- **Environment:** leave blank.
- **Permission:** `npm stage publish`; direct `npm publish` is not needed.

New packages need an initial manual publication before trusted publishers can
be configured. The workflow uses OIDC; no npm token secret is required.
Restrict `v*` tag creation to release maintainers.

## Packaging

The source manifest is intentionally private—publish generated tarballs, not
`extensions/sandbox` directly. CI uses `build-packages.mjs`:

```sh
node packaging/npm/build-packages.mjs main --out "$PWD/dist/npm"
node packaging/npm/build-packages.mjs native \
  --platform darwin --arch arm64 --out "$PWD/dist/npm" \
  --nono /absolute/path/to/nono --nono-license /absolute/path/to/LICENSE
# Use --platform linux --arch x64 for Linux.
```

Native inputs must be official nono v0.75.0 artifacts. Packaging validates
version, architecture, checksum, and portable linkage; symlinks and Nix-store
runtime dependencies are rejected. Linux requires OS-installed Bubblewrap.
See the [workflow](../../.github/workflows/npm-packages.yml) for pinned downloads
and installation checks. Review upstream security notes before changing nono.
