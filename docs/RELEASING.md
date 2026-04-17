# Releasing `mcpx`

## Cadence

- **Patch** (`0.9.x`): bug fixes, docs, non-breaking dep updates. Ship
  whenever backlog justifies it.
- **Minor** (`0.x.0`): new features; pre-1.0 may include breaking changes
  (documented in CHANGELOG).
- **Major** (`x.0.0`): reserved for 1.0 and later; strict semver from 1.0
  onward.

## Pre-flight checklist

1. All CI jobs green on `main`.
2. `cargo +nightly fmt --all -- --check` clean.
3. `cargo clippy --all-targets --all-features -- -D warnings` clean.
4. `cargo test --all-features` passes on Linux / macOS / Windows.
5. `cargo deny check` and `cargo audit` clean.
6. `cargo doc --no-deps --all-features` — no broken intra-doc links.
7. `cargo publish --dry-run --all-features` succeeds.

## Step-by-step

```bash
# 1. Pick the version
export NEW_VERSION=0.9.31

# 2. Update CHANGELOG.md
#    - Move "Unreleased" items under "## [$NEW_VERSION] - YYYY-MM-DD"
#    - Add a fresh empty "## [Unreleased]" header at the top

# 3. Bump version in Cargo.toml
sed -i 's/^version = ".*"$/version = "'$NEW_VERSION'"/' Cargo.toml

# 4. Commit and push
git add Cargo.toml CHANGELOG.md
git commit -m "chore: release $NEW_VERSION"
git push origin main

# 5. Tag
git tag -a "$NEW_VERSION" -m "mcpx $NEW_VERSION"
git push origin "$NEW_VERSION"
```

The `release.yml` workflow then:

1. Verifies the tag matches the crate version.
2. Runs `cargo publish --dry-run`.
3. Runs `cargo publish` (requires `CARGO_REGISTRY_TOKEN` secret).
4. Creates a GitHub release with auto-generated notes.

## Yanking

If a release needs to be withdrawn:

```bash
cargo yank --version $VERSION mcpx
```

Then cut a follow-up patch release that fixes the issue and document both
in CHANGELOG.md under a `### Security` or `### Fixed` subsection.

## Downstream coordination

When publishing a release that affects downstream crates (e.g.
`atlassian-mcp`):

1. Update the downstream `Cargo.toml` to the new version.
2. Run the downstream test suite against the new `mcpx`.
3. Open a PR on the downstream repo; link back to the `mcpx` release
   notes.
