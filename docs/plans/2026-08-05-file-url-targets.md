# file:// URL Targets Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `forward open file:///path/to/doc.md` behave exactly like `forward open /path/to/doc.md`, by converting the file URL to a preview URL on the devbox so the laptop never sees a scheme it drops.

**Architecture:** One branch in `target::to_url`. After `Url::parse` succeeds, a `file` scheme is turned into a `PathBuf` with `Url::to_file_path()` and fed through the flow a bare path already takes — canonicalize → `encode_path` → `http://<listen>:<files_port>/<path>` — with the URL fragment carried onto the minted preview URL. Nothing on the laptop side changes.

**Tech Stack:** Rust 2024, `url` 2.5.8 (already a dependency), `thiserror` for the module's error enum, `percent_encoding` for path encoding.

**Design document:** `docs/design/2026-08-05-file-url-targets.md`. Read it first — it carries the reasoning and the rejected alternatives.

**Baseline:** `main` at `1ff2fd6b`. `cargo test --all` is green: 102 lib unit tests (12 of them `target::tests`), 7 `src/main.rs` unit tests, and 86 integration tests across nine test binaries.

## Global Constraints

- **Every gate below must pass before the work is handed off.** These are the CI jobs in `.github/workflows/ci.yml`, verbatim:
  - `cargo fmt --all -- --check`
  - `cargo clippy --locked --all-targets --all-features -- -D warnings`
  - `cargo clippy --locked --lib --bins --all-features -- -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic -D clippy::indexing_slicing`
  - `cargo test --locked`
  - `bash scripts/check-source-line-limit.sh`
- **No `unwrap`, `expect`, `panic!`, or indexing in non-test code.** The strict clippy pass above covers `--lib --bins`, which do not compile under `cfg(test)`, so `mod tests` stays exempt.
- **Line limit: every file under `src/**` and `tests/**` must have strictly fewer than 250 raw lines** (`wc -l`; the script fails at `>= 250`, so 249 is the maximum). `src/target.rs` is **211/250** today. See "Line budget" below — the arithmetic forces the test module into `src/target/tests.rs`.
- **No new dependencies.** `Cargo.toml` `[dependencies]` must not grow. `url` already provides `to_file_path`.
- **No laptop-side or protocol change.** `src/request.rs` and `src/daemon.rs` are not touched. The laptop's `http`/`https` scheme whitelist stays as it is; it only ever receives the http preview URL.
- **MSRV is 1.88.** CI runs the suite on 1.88.0 as well as stable.
- Errors: `thiserror` enums inside modules, `anyhow` only in `src/main.rs`. This task adds no new error variant — `TargetError::Invalid` and `TargetError::NotFound` already cover it.
- Tests follow the existing conventions in `src/target.rs`: snake-case behavioural names in the indicative (`opaque_url_scheme_is_not_openable`), and Given/When/Then comments on the tests that need explaining.
- **Version control is jj, never git.** **One commit per PR for the `forward` repo** — no per-task commits; Task 1 ends leaving the work in the working copy. Task 2 is a different repo (`~/.dotfiles`) and gets its own commit there.

### Line budget (why the test module moves)

| | lines |
|---|---|
| `src/target.rs` today | 211 (67 non-test incl. trailing blank, 144 test module) |
| `to_url` grows from 15 to 28 lines | +13 → **224** |
| Headroom left before the gate | 249 − 224 = **25** |
| Six new tests need | **91** |

Six tests cannot fit in 25 lines: each needs `#[test]`, a signature, at least two statements, a closing brace, and a blank separator — six lines minimum, thirty-six for six — before any file setup or Given/When/Then comment. So the arithmetic forces the split, and the repo already has the pattern twice: `src/config.rs` + `src/config/tests.rs`, `src/policy.rs` + `src/policy/tests.rs`, both ending in

```rust
#[cfg(test)]
mod tests;
```

After Task 1: `src/target.rs` **82** lines, `src/target/tests.rs` **232** lines — both measured in a temp copy carrying the exact code in this plan, not estimated. `src/target.rs` is comfortable; `src/target/tests.rs` has **17 lines of headroom**, enough for this plan and nothing more, so a later addition to that file needs its own split rather than a squeeze. Do not split anything else now.

## Settled decisions — do not relitigate

- **The fragment is carried, concretely, by `preview.set_fragment(fragment.as_deref())`** on the parsed preview URL, where `fragment` was captured as `url.fragment().map(str::to_owned)` before the source URL went out of scope. `file:///doc.md#anchor` → `http://<listen>:12802/doc.md#anchor`. Anchors mean the same thing on both sides of the conversion, which is why this one component travels.
- **Query strings on file URLs are dropped.** `to_file_path()` ignores the query, and the minted preview URL carries none, so `file:///doc.md?raw=1` opens the rendered preview rather than the raw source. Accepted deliberately: `?raw=1` is a parameter of the *preview* server, and forwarding file-URL queries would mean deciding which of them are preview parameters. Nobody asked for that.
- **`file://localhost/path` is local.** `Url::to_file_path()` accepts an absent host or the domain `localhost`; `url` 2.5.8 normalizes `file://localhost/x` to `file:///x` at parse time regardless. No special-casing.
- **Any host other than that is refused:** `file://otherhost/path` → `to_file_path()` returns `Err(())` → `TargetError::Invalid`, message `forward: cannot use target: file://otherhost/path is not a local file URL`. The file is on this machine or it is not openable.
- **Relative and opaque `file:` forms get no cwd resolution.** `Url::parse` normalizes most of them (`file:x` becomes `file:///x`, which then takes the ordinary missing-file path to `NotFound`). Any form where `to_file_path()` fails becomes `Invalid` with the same message. There is no attempt to resolve a relative file URL against the working directory.
- **Missing file → `TargetError::NotFound`**, from the same `canonicalize` call a bare path uses. No new variant, no new message.
- **A directory file URL behaves exactly like a bare directory path.** Directory handling is untouched.
- **The branch produces a `PathBuf`, never a `&str`, and must not recurse through `to_url`.** Re-entering `to_url` would need `path.to_str()`, which fails on non-UTF-8 paths — `non_utf8_path_components_are_percent_encoded` exists precisely because those work today. `encode_path` operates on bytes; keep the path a `PathBuf` all the way to it.
- **No `--share`, no config knob, no new CLI surface.** The feature is one scheme branch.

## File structure

| File | Responsibility |
|---|---|
| `src/target.rs` (modify) | `to_url` gains the `file` branch; the test module becomes a `mod tests;` declaration. Ends at 82 lines. |
| `src/target/tests.rs` (create) | The existing 12 `target` unit tests, moved verbatim, plus the 6 new ones. 232 lines. |
| `~/.dotfiles/scripts/tmux-urls` (modify, separate repo) | One grep pattern gains `file`, so the picker lists file URLs and routes them through `forward open`. |

---

### Task 1: `file` scheme branch in `target::to_url`

**Repo:** `/home/ubuntu/forward/default`

**Files:**
- Modify: `src/target.rs` (line 3 import; `to_url` at lines 29-43; the test module at lines 68-211 becomes a declaration)
- Create: `src/target/tests.rs`
- Test: `src/target/tests.rs`

**Interfaces:**
- Consumes: nothing new. `target::to_url(arg: &str, host: &str, files_port: u16) -> Result<Url, TargetError>` already exists and both callers (`src/main.rs:87` in `Command::Url`, `src/main.rs:135` in `open_target`) pass `&cfg.listen` and `FILES_PORT`. Neither call site changes.
- Produces: no signature change, no new public item. `to_url` accepts one more input shape. `encode_path` and `url_host` keep their current visibility.

**Before starting:** confirm the working copy holds only this plan's paperwork and sits on `main`.

```bash
cd /home/ubuntu/forward/default
jj st
```

Expected: `Parent commit (@-)` names `1ff2fd6b`, and the only working-copy changes are `docs/design/2026-08-05-file-url-targets.md`, `docs/plans/2026-08-05-file-url-targets.md`, and files under `.omo/` (session bookkeeping). No `src/` file is modified yet. If `@` holds anything else, stop and report — do not rewrite or revert someone else's work.

- [ ] **Step 1: Move the existing test module into `src/target/tests.rs`.**

This is a pure move and must run against the **unmodified** file — the line numbers below are `main` at `1ff2fd6b`, where line 67 is the blank line after `encode_path`, 68 is `#[cfg(test)]`, 69 is `mod tests {`, 70-210 is the module body, and 211 is its closing brace.

```bash
cd /home/ubuntu/forward/default
mkdir -p src/target
sed -n '70,210p' src/target.rs | sed 's/^    //' > src/target/tests.rs
head -n 67 src/target.rs > src/target.rs.tmp
printf '#[cfg(test)]\nmod tests;\n' >> src/target.rs.tmp
mv src/target.rs.tmp src/target.rs
```

`sed 's/^    //'` strips exactly one indent level and leaves blank lines alone. `src/target/tests.rs` now begins with the moved `use super::*;` and `use std::ffi::OsStr;`.

- [ ] **Step 2: Verify the move changed nothing.**

```bash
wc -l src/target.rs src/target/tests.rs
cargo test --lib target::tests
```

Expected: 69 and 141 lines; `test result: ok. 12 passed`, with the same twelve names as before (`url_passes_through`, `existing_file_maps_to_files_url`, `relative_path_is_canonicalized`, `missing_path_errors`, `not_found_error_has_forward_prefix`, `invalid_error_has_forward_prefix`, `opaque_url_scheme_is_not_openable`, `special_bytes_survive_roundtrip`, `non_utf8_path_components_are_percent_encoded`, `canonicalize_errors_other_than_not_found_are_invalid`, `preview_url_names_this_machine_not_the_counterpart`, `an_ipv6_listen_address_is_bracketed`). A failure here means the move was not faithful; fix the move rather than a test.

- [ ] **Step 3: Write the failing tests.**

Append to `src/target/tests.rs`. These name `Url`, which `use super::*;` brings in from the parent module's `use url::Url;` — parent imports are visible to descendant modules, so no import is added here. The non-UTF-8 test's `OsStr::from_bytes` likewise needs the parent's `use std::os::unix::ffi::OsStrExt;`, and `OsStr` itself came across with the move. `tempfile` is reached by full path, as the existing tests do.

**Every one of these six asserts that conversion happened**, normally with `assert_eq!(u.scheme(), "http")` as the first assertion. That is deliberate and load-bearing: an assertion like `u.path().ends_with("/a%20b.md")` or `u.fragment() == Some("anchor")` is **already true of the unconverted `file` URL**, so on its own it would pass before the implementation and prove nothing.

```rust
#[test]
fn file_url_maps_to_files_url() {
    // Given: a file URL naming an existing devbox file.
    let f = tempfile::NamedTempFile::new().unwrap();
    let file_url = Url::from_file_path(f.path()).unwrap();

    // When: it is turned into a target.
    let u = to_url(file_url.as_str(), "127.0.0.1", 12802).unwrap();

    // Then: it is the same preview URL the bare path would have minted.
    assert_eq!(u.scheme(), "http");
    assert_eq!(u.host_str(), Some("127.0.0.1"));
    assert_eq!(u.port(), Some(12802));
    let bare = to_url(f.path().to_str().unwrap(), "127.0.0.1", 12802).unwrap();
    assert_eq!(u.path(), bare.path());
}

#[test]
fn percent_encoded_file_url_roundtrips() {
    // Given: a file whose name needs percent-encoding in a URL.
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("a b.md");
    std::fs::write(&file, "x").unwrap();
    let arg = Url::from_file_path(&file).unwrap();
    assert!(arg.as_str().ends_with("/a%20b.md"));

    // When: the encoded file URL is turned into a target.
    let u = to_url(arg.as_str(), "127.0.0.1", 12802).unwrap();

    // Then: it converted, and the space survived one decode and one re-encode.
    assert_eq!(u.scheme(), "http");
    assert_eq!(u.port(), Some(12802));
    assert!(u.path().ends_with("/a%20b.md"));
}

#[test]
fn non_utf8_file_url_components_are_percent_encoded() {
    // Given: a file URL whose path bytes are not valid UTF-8, which
    // to_file_path decodes straight back into raw OsStr bytes.
    let dir = tempfile::tempdir().unwrap();
    let non_utf8_directory = dir.path().join(OsStr::from_bytes(b"caf\xe9"));
    std::fs::create_dir(&non_utf8_directory).unwrap();
    let target = non_utf8_directory.join("document.md");
    std::fs::write(&target, "x").unwrap();
    let arg = Url::from_file_path(&target).unwrap();

    // When: it is turned into a target.
    let u = to_url(arg.as_str(), "127.0.0.1", 12802).unwrap();

    // Then: it converted, and the raw bytes are encoded on the preview URL —
    // which is why the file branch never turns the path into a &str.
    assert_eq!(u.scheme(), "http");
    assert!(u.path().contains("/caf%E9/document.md"));
}

#[test]
fn file_url_with_a_remote_host_is_invalid() {
    // Given: a file URL whose authority names another machine.
    let error = to_url("file://otherhost/etc/hosts", "127.0.0.1", 12802).unwrap_err();

    // Then: it is refused, because this process can only serve local files.
    assert_eq!(
        error.to_string(),
        "forward: cannot use target: file://otherhost/etc/hosts is not a local file URL"
    );
}

#[test]
fn missing_file_url_errors_as_not_found() {
    assert!(matches!(
        to_url("file:///no/such/file", "127.0.0.1", 12802),
        Err(TargetError::NotFound(_))
    ));
}

#[test]
fn file_url_fragment_is_preserved() {
    // Given: a file URL carrying an anchor, as agent-emitted links do.
    let f = tempfile::NamedTempFile::new().unwrap();
    let arg = format!("{}#anchor", Url::from_file_path(f.path()).unwrap());

    // When: it is turned into a target.
    let u = to_url(&arg, "127.0.0.1", 12802).unwrap();

    // Then: the anchor rides along to the preview URL instead of being lost.
    let bare = to_url(f.path().to_str().unwrap(), "127.0.0.1", 12802).unwrap();
    assert_eq!(u.scheme(), "http");
    assert_eq!(u.path(), bare.path());
    assert_eq!(u.fragment(), Some("anchor"));
}
```

- [ ] **Step 4: Run the new tests and confirm they fail for the right reason.**

```bash
cargo test --lib target::tests
```

Expected: **`test result: FAILED. 12 passed; 6 failed`** — every new test fails, and all six failures are behavioural rather than compile errors, because `to_url` currently returns the `file` URL unchanged. **Verified empirically** against a temp copy of the crate at `1ff2fd6b` with these tests and no implementation:

| test | failure |
|---|---|
| `file_url_maps_to_files_url` | `assert_eq!(u.scheme(), "http")` — `left: "file"`, `right: "http"` |
| `percent_encoded_file_url_roundtrips` | same scheme assertion |
| `non_utf8_file_url_components_are_percent_encoded` | same scheme assertion |
| `file_url_fragment_is_preserved` | same scheme assertion |
| `file_url_with_a_remote_host_is_invalid` | `called Result::unwrap_err() on an Ok value: Url { scheme: "file", … host: Some(Domain("otherhost")), path: "/etc/hosts" … }` |
| `missing_file_url_errors_as_not_found` | `assertion failed: matches!(to_url("file:///no/such/file", …), Err(TargetError::NotFound(_)))` |

If any new test *passes* here, it is not asserting conversion — fix the test before writing the implementation.

- [ ] **Step 5: Add `PathBuf` to the imports.**

`src/target.rs` line 3 becomes:

```rust
use std::path::{Path, PathBuf};
```

`Path` stays in use by `encode_path`.

- [ ] **Step 6: Implement the branch.**

Replace `to_url` (lines 29-43 of the original file) in full:

```rust
pub fn to_url(arg: &str, host: &str, files_port: u16) -> Result<Url, TargetError> {
    let mut path = PathBuf::from(arg);
    let mut fragment = None;
    if let Ok(url) = Url::parse(arg) {
        if url.cannot_be_a_base() {
            return Err(TargetError::UnsupportedScheme(url.scheme().to_owned()));
        }
        if url.scheme() != "file" {
            return Ok(url);
        }
        // The file is on this machine, so a file URL is only another way of
        // naming a path: it takes the same route to the same preview URL, and
        // the laptop still never sees a scheme it would drop.
        path = url
            .to_file_path()
            .map_err(|()| TargetError::Invalid(format!("{arg} is not a local file URL")))?;
        fragment = url.fragment().map(str::to_owned);
    }
    let abs = std::fs::canonicalize(&path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => TargetError::NotFound(path.display().to_string()),
        _ => TargetError::Invalid(format!("{}: {e}", path.display())),
    })?;
    let encoded = encode_path(&abs);
    let mut preview = Url::parse(&format!("http://{}:{files_port}/{encoded}", url_host(host)))
        .map_err(|e| TargetError::Invalid(e.to_string()))?;
    preview.set_fragment(fragment.as_deref());
    Ok(preview)
}
```

Four things about this shape, so a reviewer does not have to rediscover them:

1. **The bare-path tail is reused, not duplicated.** `path` starts as the argument and is only reassigned in the `file` branch, so both routes reach one `canonicalize`, one `encode_path`, and one `Url::parse`. Extracting a helper function instead would cost eleven more lines for no behavioural gain.
2. **`arg` in the error messages becomes `path.display()`.** For a bare path the rendered string is identical (`Path::new(arg).display()` round-trips a `&str` exactly), so `NotFound(arg)` behaviour is preserved; for a file URL the message names the decoded path, which is the more useful half. `not_found_error_has_forward_prefix` builds its error directly and `canonicalize_errors_other_than_not_found_are_invalid` matches the variant, so neither is affected.
3. **`fragment` is captured as an owned `String` before `url` is dropped**, then applied with `set_fragment(fragment.as_deref())`. On the bare-path route it stays `None` and the call is a no-op.
4. **`map_err(|()| …)` matches the unit error type** `Url::to_file_path` returns; no `unwrap` is introduced, so the strict clippy pass stays clean.

- [ ] **Step 7: Run the tests and confirm they pass.**

```bash
cargo fmt --all
cargo test --lib target::tests
cargo test --all
```

Expected: `test result: ok. 18 passed` for the module (12 moved + 6 new), and the full suite green at **108 lib unit tests** (102 + 6), with `src/main.rs` at 7 and all nine integration binaries unchanged at 86 total. Both numbers were confirmed in the temp copy — `cargo fmt --all` is a no-op on the code as written above, so `--check` in Step 8 stays clean.

- [ ] **Step 8: Verify every gate, including the line limit.**

```bash
wc -l src/target.rs src/target/tests.rs
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo clippy --locked --lib --bins --all-features -- \
  -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic \
  -D clippy::indexing_slicing
bash scripts/check-source-line-limit.sh
jj diff --git --stat
```

Expected: `src/target.rs` at **82** lines and `src/target/tests.rs` at **232** — both under 249, and the script exits 0 silently. Both clippy passes clean. `jj diff --git --stat` lists `src/target.rs` and `src/target/tests.rs` as the only `src/` entries, alongside the plan and design docs already in the working copy; `Cargo.toml` is untouched.

All five figures in this step were verified in a temp copy of the crate: 82 / 232 lines, `cargo fmt --all -- --check` clean, `-D warnings` clean, the strict pass clean, and `check-source-line-limit.sh` exiting 0. **`src/target/tests.rs` has only 17 lines of headroom left at 232.** Do not add a seventh test to it as part of unrelated work — that file is now the constrained one, and the next addition needs its own split (a `src/target/tests/` directory with the module split by concern), not a squeeze.

- [ ] **Step 9: Prove it on the real surface.**

Unit tests are not acceptance. Run the actual CLI, which is how a human meets this feature. `--config` on a nonexistent path yields `Config` defaults, pinning `listen` to `127.0.0.1` so the expected output is exact:

```bash
mkdir -p /tmp/forward-file-url-check
echo hello > "/tmp/forward-file-url-check/a b.md"
cargo run --quiet -- url --config /no/such/config.toml 'file:///tmp/forward-file-url-check/a%20b.md'
cargo run --quiet -- url --config /no/such/config.toml 'file:///tmp/forward-file-url-check/a%20b.md#top'
cargo run --quiet -- url --config /no/such/config.toml 'file://otherhost/etc/hosts'; echo "exit=$?"
cargo run --quiet -- url --config /no/such/config.toml 'file:///no/such/file'; echo "exit=$?"
```

Expected, in order:

```
http://127.0.0.1:12802/tmp/forward-file-url-check/a%20b.md
http://127.0.0.1:12802/tmp/forward-file-url-check/a%20b.md#top
forward: cannot use target: file://otherhost/etc/hosts is not a local file URL
exit=1
forward: path not found: /no/such/file
exit=1
```

Then the end-to-end path the design asks for, using the live devbox config so the URL names this machine's tailnet address and the laptop can actually reach it:

```bash
cargo run --quiet -- open 'file:///tmp/forward-file-url-check/a b.md'
```

Expected: the preview opens in the laptop browser. If the URL channel is down the command instead prints the tunnel-down message and exits nonzero — that still proves the devbox-side conversion happened (a `file` scheme used to be accepted here and then silently dropped on the laptop), and the four `forward url` checks above are the deterministic evidence. Clean up with `rm -r /tmp/forward-file-url-check`.

- [ ] **Step 10: Leave the work in the working copy.**

Do **not** commit yet — one commit covers this plan, and Task 2 is a different repo. Shipping is at the end of the plan.

---

### Task 2: list file URLs in the tmux URL picker

**Repo:** `/home/ubuntu/.dotfiles` — a **separate repo with its own commit**, not part of the `forward` PR.

**Files:**
- Modify: `~/.dotfiles/scripts/tmux-urls` (the `grep -oE` line, currently line 43)

**Interfaces:**
- Consumes: Task 1. `forward open` must accept `file://` before the picker starts offering it; the script's `open` arm already calls `forward open "$url"` and falls back to the clipboard on failure.
- Produces: nothing programmatic. `scripts/` is on `PATH` directly (prepended in `.bashrc`), with no install step or symlink, so the edit is live the moment the file changes. The tmux bindings (`.tmux.conf:67-68`, `bind u` / `bind O`) pass `menu copy|open #{pane_id}` and are scheme-agnostic — they need no change.

- [ ] **Step 0: Confirm nobody else is mid-edit in this file.**

The dotfiles working copy is shared and was dirty when this plan was written, so Step 4 may have to carve your change out of `@` with `jj squash`. That carve-out moves **the whole file**, not your hunk — if someone else already has uncommitted edits in `scripts/tmux-urls`, it would drag them into your commit.

```bash
cd ~/.dotfiles
jj diff --git scripts/tmux-urls
```

Expected: **no output at all** (it was empty when this plan was written). If anything prints, stop and report what it is — do not edit the file, and do not carve anything out.

- [ ] **Step 1: Extend the URL pattern.**

In `~/.dotfiles/scripts/tmux-urls`, the capture pipeline currently reads:

```bash
    tmux capture-pane -p -J -S -200 -t "$pane" \
        | grep -oE '(https?|ftp)://[^[:space:]<>"'\''`]+' \
```

Add `file` to the scheme group, and one comment line saying why a scheme the laptop cannot resolve is nonetheless listed:

```bash
    # file:// is included because `forward open` converts it to a devbox preview
    # URL before the laptop ever sees it.
    tmux capture-pane -p -J -S -200 -t "$pane" \
        | grep -oE '(https?|ftp|file)://[^[:space:]<>"'\''`]+' \
```

The comment goes immediately above the `tmux capture-pane` line, inside the existing comment block that already describes the pipeline ("Visible pane + recent scrollback, wrapped lines joined, most recent first, deduplicated, trailing punctuation stripped."). That block itself stays as it is — it is still accurate.

**The rest of the pipeline needs no adjustment. Verified, not assumed:**

- **Trailing-punctuation `sed -e 's/[].,;:!?)'\'']*$//'`** strips `] . , ; : ! ? ) '` from the end of a match, which is what makes `(file:///x.md)` in prose come out as `file:///x.md`. Identical semantics for file URLs; a filename genuinely ending in one of those characters would be truncated, but that is pre-existing behaviour for `http` URLs and does not warrant a scheme-specific branch.
- **`tac | awk '!seen[$0]++' | head -30`** is scheme-agnostic.
- **`label=${label//'#'/'##'}`** already escapes `#` for `display-menu` format expansion, so a `file:///doc.md#anchor` label renders correctly — which matters now that Task 1 preserves fragments.
- **Unencoded spaces stay out of scope.** The character class stops at whitespace, so `file:///tmp/a b.md` is captured as `file:///tmp/a` and `forward open` reports it as not found. That is correct behaviour, not a defect to fix: a space is not legal in a URL, and matching past whitespace would swallow the rest of the sentence into every URL. Anything emitting a real `file://` link percent-encodes the space.

- [ ] **Step 2: Verify the extraction, through the script's own pipeline.**

```bash
cd ~/.dotfiles
jj diff --git scripts/tmux-urls
shellcheck scripts/tmux-urls
cd ~/.dotfiles
shellcheck scripts/tmux-urls
printf 'see file:///etc/hostname and https://x.test/a) plus file:///tmp/a%%20b.md#top\n' \
  | grep -oE '(https?|ftp|file)://[^[:space:]<>"'\''`]+' \
  | sed -e 's/[].,;:!?)'\'']*$//'
```

Expected: the diff shows **only** the two added comment lines and the one changed `grep -oE` line — nothing else in the file, and no other file. That is the same check as Step 0, now confirming your edit is the whole of it, because Step 4's carve-out moves the file wholesale. Then shellcheck silent (it is clean today, so any output is a regression), then exactly three lines:

```
file:///etc/hostname
https://x.test/a
file:///tmp/a%20b.md#top
```

- [ ] **Step 3: Verify through the real script in a real tmux pane.**

The script reads a pane and writes its cache before opening the menu; `display-menu` needs an attached client, so it fails after the cache is written, which is why the failure is tolerated here. This uses a throwaway named session — kill **only** that session, never the tmux server.

```bash
tmux new-session -d -s file-url-check -x 200 -y 50
tmux send-keys -t file-url-check 'printf "%s\n" "file:///etc/hostname" "file:///tmp/a%20b.md#top" "https://x.test/a"' Enter
sleep 1
pane=$(tmux list-panes -t file-url-check -F '#{pane_id}' | head -1)
~/.dotfiles/scripts/tmux-urls menu open "$pane" || true
cat "${TMUX_TMPDIR:-/tmp}/tmux-urls-$(id -u)"
tmux kill-session -t file-url-check
```

Expected: the cache contains exactly three lines — `https://x.test/a`, `file:///tmp/a%20b.md#top`, `file:///etc/hostname` (most recent first). Before this change the two `file://` entries were absent. Overwriting that cache is harmless — every menu invocation regenerates it.

The `printf "%s\n" "…" "…"` form matters and is not cosmetic: `tmux send-keys` echoes the command line into the pane, so the capture sees the URLs twice — once as output, once inside the echoed command. Written this way, each quoted argument is byte-identical to its output line (the character class excludes `"`, so the closing quote is not captured), and `awk '!seen[$0]++'` collapses the pair. An earlier draft used `printf "file:///etc/hostname\nfile:///tmp/a%%20b.md#top\n"`; run for real, that produced a bogus fourth entry, `file:///etc/hostname\nfile:///tmp/a%%20b.md#top\n`, because the echoed command line is one whitespace-free blob and neither `\` nor `%` is excluded by the character class. Both payloads were run through this exact pipeline to confirm the difference.

- [ ] **Step 4: Commit in the dotfiles repo.**

Check the state first, because this working copy is shared:

```bash
cd ~/.dotfiles
jj st
```

- **If `@` is empty apart from your edit**, describe it and move `main`:

  ```bash
  jj describe -m "feat(tmux-urls): list file:// URLs so forward open can convert them"
  jj bookmark set main -r @
  jj git push
  jj new
  ```

- **If `@` holds unrelated in-progress work** — which it did when this plan was written: twelve modified/added files under `.claude/`, `shims/`, `google/`, `openchamber/`, `mise.toml`, and `plugins/`, undescribed, two hours old — do **not** describe, abandon, restore, or revert any of it. Carve out only your file, without switching the working copy:

  ```bash
  jj new --no-edit main -m "feat(tmux-urls): list file:// URLs so forward open can convert them"
  # note the change id it prints, as CHANGE below
  jj squash --from @ --into CHANGE scripts/tmux-urls
  jj rebase -s @ -o CHANGE     # keeps your edit live on disk; the other work rides on top
  jj bookmark set main -r CHANGE
  jj git push
  ```

  Then re-run Step 2's shellcheck and the `grep` check to confirm the edit is still on disk. If `jj squash` refuses the move, stop and report — do not start rewriting a change you did not create.

---

## Shipping the `forward` repo

One commit, one PR. `gh` is available; Sami merges (squash-merge only, no admin merge).

```bash
cd /home/ubuntu/forward/default
jj describe -m "feat: convert file:// targets into devbox preview URLs"
jj bookmark set feat/file-url-targets
jj git push --bookmark feat/file-url-targets
gh pr create --fill
```

The PR body should say what the design says in one paragraph: `forward open file:///x` used to parse, pass through, and get dropped by the laptop's scheme whitelist; it now becomes the same preview URL a bare path does, fragment included, with no laptop-side or protocol change. Then watch CI and fix any failure:

```bash
gh pr checks --watch
```

After the PR is open or updated, run the `post-pr` skill's sweep before calling it merge-ready.
