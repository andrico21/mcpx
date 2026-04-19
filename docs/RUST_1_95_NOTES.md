# Rust 1.95 Adoption Notes

> **Audience:** LLM-driven coding agents (Copilot, Claude, Cursor) working in
> this workspace.
> **Status:** Rust 1.95.0 released 2026-04-16. This document is the
> authoritative summary of 1.95 changes that affect this codebase and the
> workspace's strict lint posture.
> **Scope:** documentation-only. No code or lint-config changes have been
> made based on 1.95 yet. Open questions at the end list deferred decisions.

This workspace runs with:

- `resolver = "3"`
- `clippy::all = "deny"`, `clippy::pedantic = "warn"` (see workspace lints in
  [Cargo.toml](../Cargo.toml))
- `unsafe_code = "forbid"`
- `unwrap_used = "deny"`, `panic = "deny"`, `todo = "deny"`,
  `unimplemented = "deny"`, `print_stdout = "deny"`, `print_stderr = "deny"`,
  `dbg_macro = "deny"`

Consequently, even pedantic-tier lint additions in 1.95 WILL produce
warnings on upgrade. Read the [Clippy 1.95](#clippy-195) section before
running `cargo clippy` against this workspace on the new toolchain.

---

## 1. Language Changes

### 1.1 `cfg_select!` macro — stable

Replaces the third-party `cfg-if` crate with a `match`-like compile-time
selector.

```rust
cfg_select! {
    unix => { fn foo() { /* unix */ } }
    target_pointer_width = "32" => { fn foo() { /* 32-bit */ } }
    _ => { fn foo() { /* fallback */ } }
}

let os = cfg_select! {
    windows => "windows",
    _ => "not windows",
};
```

**Policy for this workspace:**

- ✅ Use `cfg_select!` in new code instead of adding the `cfg-if` dependency.
- ❌ **Do NOT** proactively migrate existing `cfg-if` usages. Migrate only
  when the surrounding code is being touched for another reason
  (AGENTS.md §7 "Coding standards", RUST_GUIDELINES.md §10 "Don't Over-Engineer").

### 1.2 `if let` guards in `match`

Let-chains (stabilized in 1.88) are now allowed inside match guards.

```rust
match value {
    Some(x) if let Ok(y) = compute(x) => {
        // Both x and y are in scope here
        tracing::debug!(%x, %y, "ok");
    }
    _ => {}
}
```

**Caveat (critical):** Patterns matched in `if let` guards **do NOT
participate in exhaustiveness checking**, same rule as plain `if` guards.
Do not use an `if let` guard to justify removing a wildcard arm or to
collapse an enum match — the compiler will still force the wildcard or an
exhaustive listing.

### 1.3 Destabilized: custom JSON target specs on stable

`rustc` no longer accepts JSON target spec files on stable. **Not
applicable** to this workspace — we target only default tuples and never
built custom `core`.

---

## 2. Stdlib APIs Worth Preferring

These replace idioms already present or likely to appear in this codebase.

### 2.1 `*_mut` insertion methods — return `&mut T`

```rust
// OLD pattern (two-step, requires unwrap or reborrow):
v.push(x);
let last = v.last_mut().expect("just pushed");

// NEW (1.95):
let last = v.push_mut(x);        // Vec
let slot = v.insert_mut(i, x);   // Vec
let front = dq.push_front_mut(x); // VecDeque
let back  = dq.push_back_mut(x);  // VecDeque
let f = ll.push_front_mut(x);     // LinkedList
let b = ll.push_back_mut(x);      // LinkedList
```

**Use these** — they eliminate the `.unwrap()` / `expect()` pairs that our
`unwrap_used = "deny"` policy forbids.

### 2.2 `Atomic*::update` / `try_update`

Available on `AtomicPtr`, `AtomicBool`, `AtomicIsize`, `AtomicUsize`
(and the fixed-width atomics via the same pattern). Replaces hand-rolled
compare-exchange loops.

```rust
// OLD
loop {
    let cur = counter.load(Ordering::Acquire);
    let new = cur.saturating_add(1);
    if counter.compare_exchange_weak(cur, new, Ordering::AcqRel, Ordering::Acquire).is_ok() {
        break;
    }
}

// NEW
counter.update(Ordering::AcqRel, Ordering::Acquire, |n| n.saturating_add(1));
```

**Relevant targets in this workspace:** any CAS loop in
[`src/metrics.rs`](../src/metrics.rs) or auth middleware. Prefer
`update` / `try_update` when touching those paths.

### 2.3 `core::hint::cold_path()`

Branch hint for unlikely paths. Perf only — never use for correctness.

```rust
if token.is_expired() {
    core::hint::cold_path();
    return Err(AuthError::Expired);
}
```

**Relevant targets:** error-return paths in auth middleware, RBAC denials,
rate-limit exceeded branches. Apply sparingly and only with measurement.

### 2.4 `bool: TryFrom<{integer}>`

```rust
// OLD
let flag: bool = n != 0;
// NEW (when n is "truly 0 or 1, anything else is a bug")
let flag: bool = bool::try_from(n)?;
```

Use `TryFrom` at boundaries where non-0/1 is actually invalid. Keep the
plain `!= 0` form when you specifically mean "any nonzero is true."

### 2.5 `core::range::RangeInclusive`

New ergonomic range type in `core::range`. **Caveat:** it coexists with the
legacy `std::ops::RangeInclusive` and the two are distinct types. Do not
mix them in public APIs within a module. Prefer `std::ops::RangeInclusive`
unless you have a concrete reason to adopt the new one.

### 2.6 Unsafe-adjacent — not for us

`Layout::dangling_ptr`, `Layout::repeat`, `Layout::repeat_packed`,
`Layout::extend_packed`, `<*const T>::as_ref_unchecked`, `<*mut T>::as_ref_unchecked`,
`<*mut T>::as_mut_unchecked` all require `unsafe`. This workspace has
`unsafe_code = "forbid"`. **Do not use** without a documented exception.

---

## 3. Cargo 1.95

Behavioral changes an agent may trip over:

| Change | Impact |
| --- | --- |
| `cargo init` is now **forbidden** in the user's home directory | No impact on builds, but do not suggest running `cargo init` in `$HOME`. |
| HTML timing report is **SVG-only** (canvas renderer removed entirely) | If any script or doc references the canvas renderer, update it. |
| Cargo error formatting migrated to **rustc diagnostic style** | Test snapshots that scrape Cargo stderr may need regeneration. |
| `cargo install` error messages now aware of `build.build-dir` | Informational only. |
| `cargo remove` suggests `--dev` / `--build` / `--target` when a dep sits in another table | Informational only. |

**No Cargo.toml schema changes** affect this workspace. Resolver stays at
`"3"`.

---

## 4. Clippy 1.95

This is the section that matters most. The workspace's `pedantic = "warn"`
setting means new pedantic lints WILL fire on upgrade, and several
enhancements widen existing lints.

### 4.1 New lints that will fire

| Lint | Group | What it catches | Expected in this codebase? |
| --- | --- | --- | --- |
| `unnecessary_trailing_comma` | pedantic | Trailing commas in places they add noise | Very likely — fix by removing. |
| `duration_suboptimal_units` | pedantic | `Duration::from_millis(60_000)` should be `from_secs(60)` | Check timeout/retry code. |
| `manual_checked_ops` | complexity | Hand-rolled overflow checks that `checked_add` etc. replace | Possible in retry/backoff math. |
| `manual_take` | complexity | `mem::replace(&mut x, Default::default())` when `mem::take` fits | Possible — straightforward fix. |
| `disallowed_fields` | style | Configurable allowlist of disallowed struct fields | **Not enabled** — opt-in only. |

### 4.2 Enhancements that widen existing lints

These are the ones most likely to break a previously-clean `cargo clippy
-D warnings` run:

- `useless_conversion` — now fires inside compiler desugarings. May trigger
  in macro-heavy code (for example, code generated by `rmcp::tool` macros
  under [src/](../src/)).
- `collapsible_match` — now covers `if` / `else if` chains as well as
  nested `match` arms.
- `iter_kv_map` — extended to `flat_map` and `filter_map`.
- `question_mark` — now fires on `else if` branches.
- `double_comparisons` — catches `x != y && x >= y` and similar redundant
  pairs.
- `unnecessary_fold` — matches an accumulator appearing on either side of
  the binop, not just the left.
- `unchecked_time_subtraction` — now handles `Duration` literals directly.
- `int_plus_one` — false-negative on negative literals (`-1 + x <= y`)
  fixed.

### 4.3 Fixed false positives (less noise)

These previously produced spurious warnings; after 1.95 you may see fewer:

- `str_to_string` on non-str types
- `redundant_iter_cloned` with move closures / coroutines
- `manual_dangling_ptr` on unsized pointees
- `assertions_on_result_states` on edition 2015/2018
- `cmp_owned` when `to_string` originates from macro input
- `unnecessary_cast` on external FFI return types

### 4.4 New config option: `allow-unwrap-types` — **DO NOT ENABLE**

Clippy 1.95 adds an `allow-unwrap-types` key in `clippy.toml` that tells
`unwrap_used` / `expect_used` to ignore specific types.

This crate's policy (AGENTS.md §7, RUST_GUIDELINES.md §9 "Panic
Prevention") **explicitly forbids `unwrap()` / `expect()` in library
code**. Do not add `allow-unwrap-types` to [clippy.toml](../clippy.toml).
Use `?`, `unwrap_or`, `unwrap_or_else`, `unwrap_or_default`, or explicit
`match` instead. If a value is truly proven-unreachable, use
`#[allow(clippy::unwrap_used)]` on the single line with a safety comment.

### 4.5 Semantic tweak

- `must_use_candidate` no longer fires on `main()` functions with return
  values. No action needed.

---

## 5. Upgrade Procedure for Agents

When a repo is moving from a pre-1.95 toolchain to 1.95:

1. **Toolchain**

   ```powershell
   rustup update stable
   rustc --version  # must report 1.95.0 or newer
   ```

2. **Format check** (unchanged by 1.95):

   ```powershell
   cargo fmt --all -- --check
   ```

3. **Lint pass — expect new diagnostics:**

   ```powershell
   cargo clippy --all-targets --all-features -- -D warnings
   ```

   Match failures against Section 4. **Fix at the source.** Do not blanket-
   allow new lints at crate root — that defeats the workspace's strict
   posture.

4. **Tests, audit, deny** per AGENTS.md §8:

   ```powershell
   cargo test --all-features
   cargo audit
   cargo deny check
   ```

5. **Commit discipline:** scope each category of fix separately
   (`fix(lints): remove unnecessary trailing commas`,
   `refactor(metrics): use Atomic::update`, etc.). Do not bundle lint
   cleanup with feature work.

---

## 6. Action Matrix (symptom → action)

| Symptom observed after upgrade | Action |
| --- | --- |
| `error: unnecessary trailing comma` | Remove the comma. Do not allow the lint. |
| `error: sub-optimal time unit used` | Switch to the larger unit (`from_secs` etc.). |
| `error: manual checked operation` | Use `checked_add` / `checked_sub` / `checked_mul`. |
| `error: manual_take` | Replace with `std::mem::take(&mut x)`. |
| `error: useless_conversion` inside a macro-expanded block | Drop the `.into()` / `From::from(...)`. If the macro is third-party, `#[allow(clippy::useless_conversion)]` on the smallest enclosing item, with a one-line justification. |
| New `collapsible_match` / `question_mark` firings | Collapse to single `if let ... else` or use `?`. |
| CAS loops flagged for review | Replace with `Atomic::update` / `try_update`. |
| Desire to silence `unwrap_used` for a whole module | **NO.** Fix the code, per §4.4. |
| `cargo init` fails in `$HOME` | Run it elsewhere. |
| Test snapshot diffs from Cargo stderr format changes | Regenerate snapshots; do not try to patch them to match old output. |
| Consider adding `rust-toolchain.toml` to pin 1.95 | **NO.** RUST_GUIDELINES §12: no pin; CI uses whatever `stable` resolves to. |

---

## 7. Deferred Decisions (do not act without approval)

1. **Enable `manual_checked_ops` and `manual_take` as `warn` in
   `[workspace.lints.clippy]`?** Both are `complexity`-tier and already
   surface via `clippy::all = "deny"`, so explicit elevation is redundant.
   Defer.
2. **Proactively migrate existing `cfg-if` usages to `cfg_select!`?**
   Defer. Migrate opportunistically when the surrounding code is touched.
3. **Pin the toolchain to 1.95 via `rust-toolchain.toml`?** Defer.
   Conflicts with current RUST_GUIDELINES §12 policy.

Raise a separate plan and get approval before flipping any of these.

---

## References

- [Rust 1.95.0 release notes](https://blog.rust-lang.org/2026/04/16/Rust-1.95.0/)
- [Cargo 1.95 changelog](https://doc.rust-lang.org/nightly/cargo/CHANGELOG.html#cargo-195-2026-04-16)
- [Clippy 1.95 changelog](https://github.com/rust-lang/rust-clippy/blob/master/CHANGELOG.md#rust-195)
- Workspace lint baseline: [Cargo.toml](../Cargo.toml)
- Workspace clippy thresholds: [clippy.toml](../clippy.toml)
- Mandatory coding standards: [RUST_GUIDELINES.md](../RUST_GUIDELINES.md)
- Governing agent directives: [AGENTS.md](../AGENTS.md)
