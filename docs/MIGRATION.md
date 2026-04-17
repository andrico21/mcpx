# Migrating to the standalone `mcpx` crate

This guide covers moving a downstream project (e.g. `atlassian-mcp` or
your own MCP server) from an in-repo `path` dependency on `mcpx` to the
standalone crate.

## 1. Update your `Cargo.toml`

### Git dependency (development / pre-release)

Pin to a tagged release:

```toml
[dependencies]
# Public mirror (GitHub):
mcpx = { git = "https://github.com/andrico21/mcp-mcpx", tag = "0.9.30", features = ["oauth"] }

# Internal mirror (GitLab):
# mcpx = { git = "[REDACTED]", tag = "0.9.30", features = ["oauth"] }
```

### crates.io dependency (stable / production)

Use a caret range so patch releases flow in automatically:

```toml
[dependencies]
mcpx = { version = "0.9", features = ["oauth"] }
```

Avoid the exact-version pin (`version = "=0.9.30"`); it prevents security
patches from reaching your build.

## 2. Remove the workspace member

If `mcpx` was a member of your `[workspace]`, delete the `mcpx/`
directory and the `"mcpx"` entry in `Cargo.toml`:

```diff
 [workspace]
-members = ["mcpx", "my-app"]
+members = ["my-app"]
 resolver = "3"
```

If `my-app` was the only other member, consider flattening the workspace
to a single crate — see the host project's `docs/EXPORT.md` for the full
procedure.

## 3. Keep workspace-level lints in sync

`mcpx` previously inherited `[workspace.lints.*]` from your root
`Cargo.toml`. After extraction, `mcpx` owns its own lint table; the
downstream crate keeps (or promotes) its workspace lints independently.

## 4. Public-API changes

The extraction itself introduces **no breaking changes** in the public
API. Only stray doc comments and a hardcoded test hostname were scrubbed
(see `CHANGELOG.md` 0.9.30).

## 5. Build & verify

```bash
cargo update -p mcpx
cargo build --all-features
cargo test --all-features
```

Expected: identical behavior to the pre-split build. If you observe
different `rmcp` version resolution, pin `rmcp` in your own `Cargo.toml`
to match the version declared in `mcpx`'s `[dependencies]`.

## 6. Feature-flag parity

| Feature   | Meaning                                                  |
|-----------|----------------------------------------------------------|
| `oauth`   | Enables OAuth 2.1 JWT validation and token exchange.     |
| `metrics` | Exposes a Prometheus registry and `/metrics` endpoint.   |

Both remain opt-in to keep the default dependency footprint small.
