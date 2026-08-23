# Browser Access Grants Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace ambient browser-relay access with per-session grants, so reaching the laptop's Chrome requires a YubiKey touch and is usable only by the agent session it was granted to.

**Architecture:** The laptop's relay channel stops accepting raw CDP and requires a `RELAY <token>` request line, which closes the direct-dial bypass. On the devbox, `forward serve` binds one ephemeral loopback port per grant, attributes every accepted connection to an omp session through `/proc`, and refuses anything that is not the granted session before prefixing the token and piping to the laptop.

**Tech Stack:** Rust 2021, std only for the new code (`base64` for token encoding is already a dependency), `thiserror` for errors, `parking_lot::Mutex` for shared state, `nix` only where already used (`Flock`, `SO_PEERCRED`).

**Spec:** `docs/design/2026-08-23-browser-access-grants.md`

## Global Constraints

- **250 lines per Rust source file**, enforced by `scripts/check-source-line-limit.sh` over `src/**/*.rs tests/**/*.rs`. Splitting a file is part of the task that would overflow it.
- **`cargo fmt --all -- --check` is a CI gate.** There is no `rustfmt.toml`, so `reorder_imports = true` applies and `crate::*` sorts before `forward::*`. Follow the formatter, not this document, if they disagree.
- **Errors use `thiserror`**, one enum per module, matching `BrowserError` and `BridgeError`.
- **New dependencies are permitted** but this plan adds none, because nothing here needs one: `/dev/urandom` is a CSPRNG, `base64` is already present, and constant-time comparison is a short XOR accumulate. Do not add a crate to accomplish these three things.
- **`Config::default_values_for_test()` is `#[doc(hidden)] pub` and unconditional** — integration tests call it, so it must never become `#[cfg(test)]`.
- **`Config` is `#[serde(deny_unknown_fields)]`** — every new key needs a `#[serde(default)]`.
- **Version control is jj, never git.** Commit with `jj describe -m "…"` then `jj new`. Never run a mutating git command.
- **Never print a real token value** in a log line, error, test snapshot, or `Debug` impl.

---

### Task 1: Laptop refuses untokened relay connections

Closes the direct-dial bypass. Until this lands the rest of the system is advisory.

**Files:**
- Create: `src/browser/token.rs`
- Modify: `src/browser.rs` (add `mod token;`, gate `handle_from`)
- Modify: `src/config.rs:22-24` (add `relay_token_file` beside `relay_port`)
- Test: `tests/browser.rs`

**Interfaces:**
- Consumes: nothing.
- Produces: `browser::token::constant_time_eq(&[u8], &[u8]) -> bool`, `browser::token::load(&Path) -> Option<Vec<u8>>`, `Config::relay_token_file: Option<PathBuf>`, refusal constant `TOKEN_REFUSAL = b"REFUSED TOKEN\n"`.

- [ ] **Step 1: Write the failing tests**

In `tests/browser.rs`, beside the existing peer tests:

```rust
fn cfg_with_token(peer: &str, token: &str) -> (forward::config::Config, tempfile::TempDir) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("relay.token");
    std::fs::write(&path, format!("{token}\n")).unwrap();
    let mut cfg = cfg_with_peer(peer);
    cfg.relay_token_file = Some(path);
    (cfg, directory)
}

#[test]
fn a_connection_without_a_relay_token_is_refused_and_never_reaches_the_upstream() {
    // Given: a relay whose upstream must never be dialed.
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_address = upstream.local_addr().unwrap();
    let (cfg, _directory) = cfg_with_token("127.0.0.1", "correct-horse");
    let port = spawn_relay(cfg, upstream_address);

    // When: a client sends CDP bytes with no request line.
    let mut client = TcpStream::connect(("127.0.0.1", port)).unwrap();
    client.write_all(b"GET /json/list HTTP/1.1\r\n\r\n").unwrap();

    // Then: it is refused, and the upstream saw no connection.
    assert_refused(&mut client, "REFUSED TOKEN\n");
    upstream.set_nonblocking(true).unwrap();
    assert!(matches!(upstream.accept(), Err(error) if error.kind() == ErrorKind::WouldBlock));
}

#[test]
fn a_connection_with_the_wrong_relay_token_is_refused() {
    // Given: a relay expecting one token.
    let (cfg, _directory) = cfg_with_token("127.0.0.1", "correct-horse");
    let port = spawn_relay(cfg, spawn_pong_upstream());

    // When: a client presents a different one.
    let mut client = TcpStream::connect(("127.0.0.1", port)).unwrap();
    client.write_all(b"RELAY battery-staple\nping").unwrap();

    // Then: it is refused.
    assert_refused(&mut client, "REFUSED TOKEN\n");
}

#[test]
fn a_connection_with_the_expected_relay_token_is_proxied() {
    // Given: a relay and an upstream that answers ping with pong.
    let (cfg, _directory) = cfg_with_token("127.0.0.1", "correct-horse");
    let port = spawn_relay(cfg, spawn_pong_upstream());

    // When: a client presents the expected token and speaks.
    let mut client = TcpStream::connect(("127.0.0.1", port)).unwrap();
    client.write_all(b"RELAY correct-horse\nping").unwrap();

    // Then: the payload after the request line reaches the upstream.
    read_pong(&mut client);
}

#[test]
fn a_relay_with_no_configured_token_file_refuses_every_connection() {
    // Given: a relay whose token file is absent, as on a half-provisioned laptop.
    let cfg = cfg_with_peer("127.0.0.1");
    let port = spawn_relay(cfg, spawn_pong_upstream());

    // When: a client presents any token.
    let mut client = TcpStream::connect(("127.0.0.1", port)).unwrap();
    client.write_all(b"RELAY correct-horse\nping").unwrap();

    // Then: it fails closed rather than open.
    assert_refused(&mut client, "REFUSED TOKEN\n");
}
```

Add `tempfile` to `[dev-dependencies]` only if it is not already there; check `Cargo.toml` first.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --test browser`
Expected: FAIL — `no field 'relay_token_file' on type 'Config'`.

- [ ] **Step 3: Add the config key**

In `src/config.rs`, directly after `relay_port`:

```rust
    /// Path to the file holding the expected relay token, laptop side. `0600`,
    /// never `config.toml`: that file is committed to dotfiles and symlinked
    /// into place, so a secret in it would be published.
    #[serde(default)]
    pub relay_token_file: Option<PathBuf>,
```

Add `relay_token_file: None` to both `default_values()` and `default_values_for_test()`.

- [ ] **Step 4: Write `src/browser/token.rs`**

```rust
use std::path::Path;

/// Compare without an early exit, so a wrong first byte costs what a wrong last
/// byte costs. Length is not secret: a token of the wrong size is already wrong.
pub(crate) fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0_u8;
    for (left_byte, right_byte) in left.iter().zip(right) {
        difference |= left_byte ^ right_byte;
    }
    difference == 0
}

/// The expected token, or `None` when it cannot be read.
///
/// A missing, unreadable, or empty file yields `None`, and every caller treats
/// `None` as "refuse everything". A half-provisioned laptop must not be an open
/// laptop.
pub(crate) fn load(path: &Path) -> Option<Vec<u8>> {
    let value = std::fs::read(path).ok()?;
    let trimmed = value.trim_ascii_end();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equal_values_compare_equal() {
        assert!(constant_time_eq(b"correct-horse", b"correct-horse"));
    }

    #[test]
    fn a_differing_final_byte_compares_unequal() {
        assert!(!constant_time_eq(b"correct-horse", b"correct-horsf"));
    }

    #[test]
    fn differing_lengths_compare_unequal() {
        assert!(!constant_time_eq(b"correct-horse", b"correct"));
    }

    #[test]
    fn an_empty_token_file_yields_no_token() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("relay.token");
        std::fs::write(&path, "\n").unwrap();
        assert_eq!(load(&path), None);
    }

    #[test]
    fn a_trailing_newline_is_not_part_of_the_token() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("relay.token");
        std::fs::write(&path, "correct-horse\n").unwrap();
        assert_eq!(load(&path).as_deref(), Some(b"correct-horse".as_slice()));
    }

    #[test]
    fn a_missing_token_file_yields_no_token() {
        assert_eq!(load(Path::new("/nonexistent/relay.token")), None);
    }
}
```

- [ ] **Step 5: Gate `handle_from` in `src/browser.rs`**

Add `mod token;` at the top. Add beside the other refusal constants:

```rust
const TOKEN_REFUSAL: &[u8] = b"REFUSED TOKEN\n";
/// How long a connection may take to send its request line.
const REQUEST_LINE_READ_TIMEOUT: Duration = Duration::from_secs(10);
/// `RELAY ` plus a base64 32-byte token is 50 bytes; 128 is generous.
const MAX_REQUEST_LINE: usize = 128;
```

Insert the gate into `handle_from` immediately after the `authorized` check and before `TcpStream::connect(upstream)`:

```rust
    let expected = cfg.relay_token_file.as_deref().and_then(token::load);
    let presented = read_relay_token(&mut stream, REQUEST_LINE_READ_TIMEOUT);
    let accepted = match (expected, presented) {
        (Some(expected), Some(presented)) => token::constant_time_eq(&expected, &presented),
        _ => false,
    };
    if !accepted {
        eprintln!("forward: browser relay refused an untokened connection from {remote}");
        refuse(&mut stream, TOKEN_REFUSAL);
        return;
    }
```

And the reader, mirroring `bridge::listener::read_port_with_timeout` — byte-at-a-time on the piped stream, never a buffered reader, because a buffered reader would swallow CDP bytes past the newline:

```rust
/// Read `RELAY <token>\n` one byte at a time from the piped stream.
fn read_relay_token(stream: &mut TcpStream, timeout: Duration) -> Option<Vec<u8>> {
    let deadline = Instant::now().checked_add(timeout)?;
    let mut line = Vec::with_capacity(MAX_REQUEST_LINE);
    let mut byte = [0_u8; 1];

    while line.len() < MAX_REQUEST_LINE {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() || stream.set_read_timeout(Some(remaining)).is_err() {
            return None;
        }
        match stream.read(&mut byte) {
            Ok(1) => {}
            Ok(_) => return None,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return None,
        }
        let [received] = byte;
        if received == b'\n' {
            return line.strip_prefix(b"RELAY ".as_slice()).map(<[u8]>::to_vec);
        }
        line.push(received);
    }
    None
}
```

Add `use std::io::Read;` and `use std::time::Instant;` to the imports.

- [ ] **Step 6: Run the tests to verify they pass**

Run: `cargo test --test browser && cargo test --lib browser::token`
Expected: PASS.

- [ ] **Step 7: Check the line budget and format**

Run: `./scripts/check-source-line-limit.sh && cargo fmt --all -- --check && cargo clippy --all-targets -- -D warnings`
Expected: all pass. If `src/browser.rs` exceeds 250 lines, move `read_relay_token` into `src/browser/token.rs` rather than trimming comments.

- [ ] **Step 8: Commit**

```bash
jj describe -m "feat(browser): require a relay token on the laptop channel

Raw CDP on the relay port let any devbox process reach the whole browser
profile. The channel now speaks the same request-line shape the callback
bridge uses, and fails closed when the token file is missing." && jj new
```

---

### Task 2: `forward browser init-token`

**Files:**
- Create: `src/browser/init.rs`
- Modify: `src/main.rs:26-65` (add the `Browser` subcommand), `src/main.rs:67-124` (dispatch)
- Modify: `src/browser.rs` (add `pub mod init;`)
- Test: `src/browser/init.rs` inline tests

**Interfaces:**
- Consumes: `Config::relay_token_file` from Task 1.
- Produces: `browser::init::write_token(&Path) -> Result<String, InitError>` — generates, writes `0600`, returns the value for printing. CLI verb `forward browser init-token [--config PATH]`.

- [ ] **Step 1: Write the failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    #[test]
    fn the_written_token_is_the_returned_token() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("relay.token");
        let value = write_token(&path).unwrap();
        let stored = std::fs::read_to_string(&path).unwrap();
        assert_eq!(stored.trim_end(), value);
    }

    #[test]
    fn the_token_file_is_readable_only_by_its_owner() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("relay.token");
        write_token(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn two_tokens_differ() {
        let directory = tempfile::tempdir().unwrap();
        let first = write_token(&directory.path().join("a")).unwrap();
        let second = write_token(&directory.path().join("b")).unwrap();
        assert_ne!(first, second);
    }

    #[test]
    fn rotating_replaces_the_previous_value() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("relay.token");
        let first = write_token(&path).unwrap();
        let second = write_token(&path).unwrap();
        assert_ne!(first, second);
        assert_eq!(std::fs::read_to_string(&path).unwrap().trim_end(), second);
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --lib browser::init`
Expected: FAIL — `cannot find function 'write_token'`.

- [ ] **Step 3: Write `src/browser/init.rs`**

```rust
use base64::Engine as _;
use std::fs::OpenOptions;
use std::io::{Read as _, Write as _};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;

/// Token entropy. 32 bytes is the usual symmetric-secret size and encodes to 43
/// base64 characters, comfortably inside the request-line cap.
const TOKEN_BYTES: usize = 32;

#[derive(Debug, thiserror::Error)]
pub enum InitError {
    #[error("failed to read /dev/urandom: {source}")]
    Entropy {
        #[source]
        source: std::io::Error,
    },
    #[error("failed to write token {path}: {source}")]
    Write {
        path: String,
        #[source]
        source: std::io::Error,
    },
}

/// Generate a relay token, store it at `path` with mode `0600`, and return it.
///
/// The value is returned rather than logged: its only legitimate destination is
/// the caller's stdout, on its way into `secrets edit-human`.
pub fn write_token(path: &Path) -> Result<String, InitError> {
    let mut raw = [0_u8; TOKEN_BYTES];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut source| source.read_exact(&mut raw))
        .map_err(|source| InitError::Entropy { source })?;
    let value = base64::engine::general_purpose::STANDARD_NO_PAD.encode(raw);

    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|source| InitError::Write {
            path: path.display().to_string(),
            source,
        })?;
    writeln!(file, "{value}").map_err(|source| InitError::Write {
        path: path.display().to_string(),
        source,
    })?;
    Ok(value)
}
```

`OpenOptions::mode` applies only at creation, so rotating an existing file keeps
its old mode. That is why the test rotates and the implementation truncates
rather than removing: an existing `0600` file stays `0600`.

- [ ] **Step 4: Wire the CLI**

In `src/main.rs`, add to `enum Command`:

```rust
    /// Manage browser access (laptop: init-token)
    Browser {
        #[command(subcommand)]
        action: BrowserCommand,
    },
```

and beside it:

```rust
#[derive(Subcommand)]
enum BrowserCommand {
    /// Generate the relay token, store it, and print it once (laptop side)
    InitToken {
        #[arg(long)]
        config: Option<std::path::PathBuf>,
    },
}
```

Dispatch in `main`:

```rust
        Command::Browser { action } => match action {
            BrowserCommand::InitToken { config } => {
                let (cfg, _) = load_config(config)?;
                let path = cfg
                    .relay_token_file
                    .ok_or_else(|| anyhow::anyhow!("forward: relay_token_file is not configured"))?;
                let value = forward::browser::init::write_token(&path)?;
                let mut stdout = std::io::stdout().lock();
                writeln!(stdout, "{value}")?;
                Ok(())
            }
        },
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test --lib browser::init && cargo build`
Expected: PASS, clean build.

- [ ] **Step 6: Verify the CLI by hand**

Run: `cargo run -- browser init-token --config /dev/null 2>&1 | head -2`
Expected: an error naming `relay_token_file`, not a panic and not a written file.

- [ ] **Step 7: Commit**

```bash
jj describe -m "feat(browser): generate the relay token with init-token

/dev/urandom is a CSPRNG and base64 is already a dependency, so provisioning
needs no new crate. The value is printed once, for a pipe into secrets." && jj new
```

---

### Task 3: Grant registry

**Files:**
- Create: `src/browser/grant.rs`
- Modify: `src/browser.rs` (add `pub mod grant;`)
- Test: `src/browser/grant.rs` inline tests

**Interfaces:**
- Consumes: nothing.
- Produces: `browser::grant::Grant { session: String, token: Vec<u8>, deadline: Instant }`, `browser::grant::Grants` with `Grants::new()`, `Grants::insert(port: u16, grant: Grant)`, `Grants::live(port: u16) -> Option<Grant>`, `Grants::expire(port: u16)`. `Grants` is `Clone` and shares one map, matching `bridge::Armed`.

- [ ] **Step 1: Write the failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn grant(session: &str, ttl: Duration) -> Grant {
        Grant {
            session: session.to_owned(),
            token: b"correct-horse".to_vec(),
            deadline: Instant::now() + ttl,
        }
    }

    #[test]
    fn a_live_grant_is_returned_for_its_port() {
        let grants = Grants::new();
        grants.insert(12811, grant("session-a", Duration::from_secs(60)));
        assert_eq!(grants.live(12811).unwrap().session, "session-a");
    }

    #[test]
    fn an_expired_grant_is_not_returned() {
        let grants = Grants::new();
        grants.insert(12811, grant("session-a", Duration::from_millis(1)));
        std::thread::sleep(Duration::from_millis(5));
        assert!(grants.live(12811).is_none());
    }

    #[test]
    fn an_unknown_port_has_no_grant() {
        assert!(Grants::new().live(12811).is_none());
    }

    #[test]
    fn expiring_one_grant_leaves_another_usable() {
        // The token is shared by every grant, so dropping one must not disarm
        // the other.
        let grants = Grants::new();
        grants.insert(12811, grant("session-a", Duration::from_secs(60)));
        grants.insert(12812, grant("session-b", Duration::from_secs(60)));
        grants.expire(12811);
        assert!(grants.live(12811).is_none());
        assert_eq!(grants.live(12812).unwrap().session, "session-b");
    }

    #[test]
    fn clones_share_one_registry() {
        let grants = Grants::new();
        let clone = grants.clone();
        grants.insert(12811, grant("session-a", Duration::from_secs(60)));
        assert!(clone.live(12811).is_some());
    }

    #[test]
    fn an_expired_grants_token_is_zeroed_in_place() {
        let grants = Grants::new();
        grants.insert(12811, grant("session-a", Duration::from_millis(1)));
        std::thread::sleep(Duration::from_millis(5));
        assert!(grants.live(12811).is_none());
        assert!(grants.tokens_held() == 0);
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --lib browser::grant`
Expected: FAIL — `cannot find type 'Grants'`.

- [ ] **Step 3: Write `src/browser/grant.rs`**

```rust
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

/// One session's authorisation to reach the laptop's browser.
#[derive(Clone)]
pub struct Grant {
    /// The omp session id every connection on this port must resolve to.
    pub session: String,
    /// The relay token, held only while the grant is live.
    pub token: Vec<u8>,
    pub deadline: Instant,
}

/// Live grants, keyed by the loopback port each one owns.
///
/// Clones share one map so the request socket and the proxy listeners can hold
/// a handle each, matching `bridge::Armed`. `Armed` is deliberately not reused:
/// it keys on port with a port-safety policy, and a grant keys on session.
#[derive(Clone, Default)]
pub struct Grants {
    ports: Arc<Mutex<HashMap<u16, Grant>>>,
}

impl Grants {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&self, port: u16, grant: Grant) {
        drop(self.ports.lock().insert(port, grant));
    }

    /// The grant for `port` if it has not expired. Expired entries are dropped
    /// here, so no reaper thread is needed.
    pub fn live(&self, port: u16) -> Option<Grant> {
        let mut ports = self.ports.lock();
        let expired = ports
            .get(&port)
            .is_some_and(|grant| grant.deadline <= Instant::now());
        if expired {
            zero(&mut ports, port);
            return None;
        }
        ports.get(&port).cloned()
    }

    /// Drop `port`'s grant now, zeroing its token.
    pub fn expire(&self, port: u16) {
        zero(&mut self.ports.lock(), port);
    }

    /// How many grants still hold a token. Test seam for the zeroing contract.
    #[doc(hidden)]
    pub fn tokens_held(&self) -> usize {
        self.ports.lock().len()
    }
}

/// Overwrite the token before releasing it, so an expired grant leaves no copy
/// in the allocator's free memory. Hand-rolled: `zeroize` would be a dependency
/// for six lines.
fn zero(ports: &mut HashMap<u16, Grant>, port: u16) {
    if let Some(mut grant) = ports.remove(&port) {
        for byte in &mut grant.token {
            *byte = 0;
        }
    }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --lib browser::grant`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
jj describe -m "feat(browser): add the grant registry

Keys on the loopback port a grant owns, carries the session every connection
must match, and zeroes the token on expiry so no copy outlives the window." && jj new
```

---

### Task 4: Peer attribution

The racy hop. Split so the `/proc` walk is testable without a fake `/proc`.

**Files:**
- Create: `src/browser/peer.rs`
- Modify: `src/browser.rs` (add `pub mod peer;`)
- Test: `src/browser/peer.rs` inline tests

**Interfaces:**
- Consumes: nothing.
- Produces: `browser::peer::pid_for_connection(peer: SocketAddrV4, local: SocketAddrV4) -> Option<u32>`, `browser::peer::session_for_pid(pid: u32) -> Option<String>`, and the test seam `browser::peer::session_for_pid_with(pid: u32, lookup: &mut dyn FnMut(u32) -> Option<Process>) -> Option<String>` with `pub struct Process { pub argv: Vec<String>, pub parent: u32 }`.

- [ ] **Step 1: Write the failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::net::{TcpListener, TcpStream};

    fn process(argv: &[&str], parent: u32) -> Process {
        Process {
            argv: argv.iter().map(|value| (*value).to_owned()).collect(),
            parent,
        }
    }

    fn table(entries: &[(u32, Process)]) -> impl FnMut(u32) -> Option<Process> + '_ {
        let map: HashMap<u32, Process> = entries.iter().cloned().collect();
        move |pid| map.get(&pid).cloned()
    }

    #[test]
    fn a_session_process_resolves_to_its_own_session() {
        let mut lookup = table(&[(
            10,
            process(&["/opt/omp", "--resume", "01a0223b-94d1-7000-bd0e-5038df7750b0"], 1),
        )]);
        assert_eq!(
            session_for_pid_with(10, &mut lookup).as_deref(),
            Some("01a0223b-94d1-7000-bd0e-5038df7750b0")
        );
    }

    #[test]
    fn a_descendant_resolves_through_its_ancestry() {
        let mut lookup = table(&[
            (12, process(&["python3", "browser-capture"], 11)),
            (11, process(&["bash", "-c", "…"], 10)),
            (
                10,
                process(&["/opt/omp", "--resume", "01a0223b-94d1-7000-bd0e-5038df7750b0"], 1),
            ),
        ]);
        assert_eq!(
            session_for_pid_with(12, &mut lookup).as_deref(),
            Some("01a0223b-94d1-7000-bd0e-5038df7750b0")
        );
    }

    #[test]
    fn a_process_outside_any_session_resolves_to_nothing() {
        let mut lookup = table(&[(10, process(&["curl", "http://127.0.0.1:12811"], 1))]);
        assert_eq!(session_for_pid_with(10, &mut lookup), None);
    }

    #[test]
    fn a_non_omp_resume_flag_is_not_a_session() {
        // Another program may take --resume; only omp's counts.
        let mut lookup = table(&[(
            10,
            process(&["/usr/bin/wget", "--resume", "01a0223b-94d1-7000-bd0e-5038df7750b0"], 1),
        )]);
        assert_eq!(session_for_pid_with(10, &mut lookup), None);
    }

    #[test]
    fn a_parent_cycle_terminates() {
        let mut lookup = table(&[
            (10, process(&["a"], 11)),
            (11, process(&["b"], 10)),
        ]);
        assert_eq!(session_for_pid_with(10, &mut lookup), None);
    }

    #[test]
    fn a_live_loopback_connection_resolves_to_this_process() {
        // Given: a loopback connection this test process owns both ends of.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let local = match listener.local_addr().unwrap() {
            std::net::SocketAddr::V4(address) => address,
            other => panic!("expected IPv4, got {other}"),
        };
        let client = TcpStream::connect(local).unwrap();
        let (_server, _) = listener.accept().unwrap();
        let peer = match client.local_addr().unwrap() {
            std::net::SocketAddr::V4(address) => address,
            other => panic!("expected IPv4, got {other}"),
        };

        // When/Then: the client socket resolves to this process.
        assert_eq!(pid_for_connection(peer, local), Some(std::process::id()));
    }
}
```

`Process` needs `#[derive(Clone)]` for the table helper.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --lib browser::peer`
Expected: FAIL — `cannot find function 'session_for_pid_with'`.

- [ ] **Step 3: Write `src/browser/peer.rs`**

```rust
use std::net::SocketAddrV4;
use std::path::Path;

/// Longest ancestry walk before giving up. A worker nested deeper than this is
/// not a session's child in any arrangement we run, and the cap makes a `PPID`
/// cycle terminate.
const MAX_ANCESTRY_HOPS: usize = 12;

/// One process as attribution needs it.
#[derive(Clone, Debug)]
pub struct Process {
    pub argv: Vec<String>,
    pub parent: u32,
}

/// The pid owning the loopback socket `peer` -> `local`, if one can be found.
///
/// Racy by construction: the pid is read after the fact and could in principle
/// be reused. Resolution happens at accept while the socket is live, which
/// bounds the window; a failure to resolve is refused, never allowed.
pub fn pid_for_connection(peer: SocketAddrV4, local: SocketAddrV4) -> Option<u32> {
    let inode = inode_for(peer, local)?;
    pid_for_inode(&inode)
}

fn endpoint(address: SocketAddrV4) -> String {
    format!(
        "{:08X}:{:04X}",
        u32::from_le_bytes(address.ip().octets()),
        address.port()
    )
}

/// The socket inode whose local/remote pair is the client's side of `peer` ->
/// `local`.
fn inode_for(peer: SocketAddrV4, local: SocketAddrV4) -> Option<String> {
    let (want_local, want_remote) = (endpoint(peer), endpoint(local));
    let table = std::fs::read_to_string("/proc/net/tcp").ok()?;
    table.lines().skip(1).find_map(|line| {
        let mut fields = line.split_whitespace().skip(1);
        let found_local = fields.next()?;
        let found_remote = fields.next()?;
        if found_local != want_local || found_remote != want_remote {
            return None;
        }
        fields.nth(6).map(str::to_owned)
    })
}

fn pid_for_inode(inode: &str) -> Option<u32> {
    let target = format!("socket:[{inode}]");
    for entry in std::fs::read_dir("/proc").ok()?.flatten() {
        let Some(pid) = entry.file_name().to_str().and_then(|name| name.parse().ok()) else {
            continue;
        };
        let Ok(descriptors) = std::fs::read_dir(entry.path().join("fd")) else {
            continue;
        };
        for descriptor in descriptors.flatten() {
            if std::fs::read_link(descriptor.path()).is_ok_and(|link| link == Path::new(&target)) {
                return Some(pid);
            }
        }
    }
    None
}

/// The omp session `pid` belongs to, walking ancestry for worker processes.
pub fn session_for_pid(pid: u32) -> Option<String> {
    session_for_pid_with(pid, &mut read_process)
}

/// Test seam: resolve against a caller-supplied process table.
#[doc(hidden)]
pub fn session_for_pid_with(
    pid: u32,
    lookup: &mut dyn FnMut(u32) -> Option<Process>,
) -> Option<String> {
    let mut current = pid;
    for _ in 0..MAX_ANCESTRY_HOPS {
        let process = lookup(current)?;
        if let Some(session) = session_of(&process) {
            return Some(session);
        }
        if process.parent <= 1 || process.parent == current {
            return None;
        }
        current = process.parent;
    }
    None
}

/// `omp --resume <uuid>` and nothing else. Another program taking `--resume`
/// must not be mistaken for a session.
fn session_of(process: &Process) -> Option<String> {
    let command = process.argv.first()?;
    if command != "omp" && !command.ends_with("/omp") {
        return None;
    }
    let mut arguments = process.argv.iter();
    while let Some(argument) = arguments.next() {
        if argument == "--resume" {
            return arguments.next().filter(|value| is_session_id(value)).cloned();
        }
    }
    None
}

fn is_session_id(value: &str) -> bool {
    let groups = [8, 4, 4, 4, 12];
    let mut parts = value.split('-');
    groups
        .iter()
        .all(|width| {
            parts.next().is_some_and(|part| {
                part.len() == *width && part.bytes().all(|byte| byte.is_ascii_hexdigit())
            })
        })
        && parts.next().is_none()
}

fn read_process(pid: u32) -> Option<Process> {
    let raw = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    let argv = raw
        .split(|byte| *byte == 0)
        .filter(|part| !part.is_empty())
        .map(|part| String::from_utf8_lossy(part).into_owned())
        .collect();
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // comm can contain spaces and parentheses, so PPID is located from the last
    // ')' rather than by splitting the whole line.
    let tail = stat.get(stat.rfind(')')? + 2..)?;
    let parent = tail.split_whitespace().nth(1)?.parse().ok()?;
    Some(Process { argv, parent })
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --lib browser::peer`
Expected: PASS, including `a_live_loopback_connection_resolves_to_this_process`.

- [ ] **Step 5: Check the line budget**

Run: `./scripts/check-source-line-limit.sh`
Expected: pass. If `peer.rs` exceeds 250 lines, split the `/proc/net/tcp` parsing into `src/browser/peer/socket.rs` and keep ancestry in `peer.rs`.

- [ ] **Step 6: Commit**

```bash
jj describe -m "feat(browser): attribute a loopback connection to an omp session

Two hops: socket inode from /proc/net/tcp, then the holding pid, then argv
ancestry to the omp --resume process. Unresolvable is refused, never allowed." && jj new
```

---

### Task 5: Per-grant proxy listener

**Files:**
- Create: `src/browser/proxy.rs`
- Modify: `src/browser.rs` (add `pub mod proxy;`)
- Test: `tests/browser_grant.rs`

**Interfaces:**
- Consumes: `grant::Grants`, `grant::Grant`, `peer::pid_for_connection`, `peer::session_for_pid`, `Config` (for `peer` and `relay_port`).
- Produces: `browser::proxy::spawn(cfg: &Config, grants: Grants, session: String, token: Vec<u8>, deadline: Instant) -> Result<u16, ProxyError>` returning the bound port, plus the test seam `browser::proxy::spawn_with_listener(cfg: Config, grants: Grants, listener: TcpListener, upstream: SocketAddr, resolver: Resolver)` where `pub type Resolver = Arc<dyn Fn(SocketAddrV4, SocketAddrV4) -> Option<String> + Send + Sync>`.

- [ ] **Step 1: Write the failing tests**

Create `tests/browser_grant.rs`:

```rust
use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn grant(session: &str) -> forward::browser::grant::Grant {
    forward::browser::grant::Grant {
        session: session.to_owned(),
        token: b"correct-horse".to_vec(),
        deadline: Instant::now() + Duration::from_secs(60),
    }
}

/// An upstream that asserts the request line and answers the payload.
fn spawn_relay_upstream(expected: &'static str) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut line = Vec::new();
        let mut byte = [0_u8; 1];
        while stream.read(&mut byte).unwrap() == 1 && byte[0] != b'\n' {
            line.push(byte[0]);
        }
        assert_eq!(String::from_utf8(line).unwrap(), expected);
        let mut payload = [0_u8; 4];
        stream.read_exact(&mut payload).unwrap();
        assert_eq!(&payload, b"ping");
        stream.write_all(b"pong").unwrap();
    });
    address
}

fn assert_refused(client: &mut TcpStream, expected: &str) {
    client.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut reply = String::new();
    client.read_to_string(&mut reply).unwrap();
    assert_eq!(reply, expected);
}

fn resolver(session: Option<&'static str>) -> forward::browser::proxy::Resolver {
    Arc::new(move |_peer: SocketAddrV4, _local: SocketAddrV4| session.map(str::to_owned))
}

fn spawn(
    grants: forward::browser::grant::Grants,
    upstream: SocketAddr,
    resolved: Option<&'static str>,
) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    forward::browser::proxy::spawn_with_listener(
        forward::config::Config::default_values_for_test(),
        grants,
        listener,
        upstream,
        resolver(resolved),
    );
    port
}

#[test]
fn the_granted_session_is_proxied_with_the_token_prefixed() {
    // Given: a grant for session-a on the proxy's port.
    let grants = forward::browser::grant::Grants::new();
    let upstream = spawn_relay_upstream("RELAY correct-horse");
    let port = spawn(grants.clone(), upstream, Some("session-a"));
    grants.insert(port, grant("session-a"));

    // When: session-a connects and speaks.
    let mut client = TcpStream::connect(("127.0.0.1", port)).unwrap();
    client.write_all(b"ping").unwrap();

    // Then: the upstream saw the request line, and the reply comes back.
    let mut reply = [0_u8; 4];
    client.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    client.read_exact(&mut reply).unwrap();
    assert_eq!(&reply, b"pong");
}

#[test]
fn another_session_is_refused_on_a_port_it_was_not_granted() {
    // Given: a grant for session-a.
    let grants = forward::browser::grant::Grants::new();
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = spawn(grants.clone(), upstream.local_addr().unwrap(), Some("session-b"));
    grants.insert(port, grant("session-a"));

    // When: session-b connects to session-a's port.
    let mut client = TcpStream::connect(("127.0.0.1", port)).unwrap();
    client.write_all(b"ping").unwrap();

    // Then: refused, and the laptop was never dialed.
    assert_refused(&mut client, "REFUSED SESSION\n");
    upstream.set_nonblocking(true).unwrap();
    assert!(upstream.accept().is_err());
}

#[test]
fn an_unresolvable_peer_is_refused() {
    // Given: a grant, and a connection whose pid cannot be resolved.
    let grants = forward::browser::grant::Grants::new();
    let port = spawn(grants.clone(), spawn_relay_upstream("unused"), None);
    grants.insert(port, grant("session-a"));

    // When/Then: failing to attribute fails closed.
    let mut client = TcpStream::connect(("127.0.0.1", port)).unwrap();
    client.write_all(b"ping").unwrap();
    assert_refused(&mut client, "REFUSED SESSION\n");
}

#[test]
fn a_port_with_no_live_grant_is_refused() {
    // Given: a proxy with nothing granted on its port.
    let grants = forward::browser::grant::Grants::new();
    let port = spawn(grants, spawn_relay_upstream("unused"), Some("session-a"));

    // When/Then: refused as ungranted rather than as a session mismatch.
    let mut client = TcpStream::connect(("127.0.0.1", port)).unwrap();
    client.write_all(b"ping").unwrap();
    assert_refused(&mut client, "REFUSED UNGRANTED\n");
}

#[test]
fn an_expired_grant_refuses_new_connections() {
    // Given: a grant that has already lapsed.
    let grants = forward::browser::grant::Grants::new();
    let port = spawn(grants.clone(), spawn_relay_upstream("unused"), Some("session-a"));
    grants.insert(
        port,
        forward::browser::grant::Grant {
            session: "session-a".to_owned(),
            token: b"correct-horse".to_vec(),
            deadline: Instant::now() - Duration::from_secs(1),
        },
    );

    // When/Then: the window governs new connections.
    let mut client = TcpStream::connect(("127.0.0.1", port)).unwrap();
    client.write_all(b"ping").unwrap();
    assert_refused(&mut client, "REFUSED UNGRANTED\n");
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --test browser_grant`
Expected: FAIL — `could not find 'proxy' in 'browser'`.

- [ ] **Step 3: Write `src/browser/proxy.rs`**

```rust
use crate::browser::grant::Grants;
use crate::bridge::limit::ConnectionLimit;
use crate::config::Config;
use crate::pipe::bidirectional;
use crate::refusal::refuse;
use std::io::Write as _;
use std::net::{SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

const PIPE_IDLE_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(50);
const GENERIC_REFUSAL: &[u8] = b"REFUSED\n";
const BUSY_REFUSAL: &[u8] = b"REFUSED BUSY\n";
const UNGRANTED_REFUSAL: &[u8] = b"REFUSED UNGRANTED\n";
const SESSION_REFUSAL: &[u8] = b"REFUSED SESSION\n";

/// Resolve a loopback connection to an omp session. Injectable so the accept
/// path can be tested without a real `/proc` walk.
pub type Resolver = Arc<dyn Fn(SocketAddrV4, SocketAddrV4) -> Option<String> + Send + Sync>;

#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("failed to bind a grant port: {source}")]
    Bind {
        #[source]
        source: std::io::Error,
    },
}

/// Bind a fresh loopback port for a grant and serve it. Returns the port.
pub fn spawn(cfg: &Config, grants: Grants, upstream: SocketAddr) -> Result<u16, ProxyError> {
    let listener =
        TcpListener::bind("127.0.0.1:0").map_err(|source| ProxyError::Bind { source })?;
    let port = listener
        .local_addr()
        .map_err(|source| ProxyError::Bind { source })?
        .port();
    spawn_with_listener(
        cfg.clone(),
        grants,
        listener,
        upstream,
        Arc::new(|peer, local| {
            crate::browser::peer::pid_for_connection(peer, local)
                .and_then(crate::browser::peer::session_for_pid)
        }),
    );
    Ok(port)
}

/// Test seam: serve a grant port on a listener the caller already bound.
#[doc(hidden)]
pub fn spawn_with_listener(
    cfg: Config,
    grants: Grants,
    listener: TcpListener,
    upstream: SocketAddr,
    resolver: Resolver,
) {
    drop(thread::spawn(move || {
        accept_loop(cfg, grants, listener, upstream, resolver);
    }));
}

fn accept_loop(
    _cfg: Config,
    grants: Grants,
    listener: TcpListener,
    upstream: SocketAddr,
    resolver: Resolver,
) {
    let limit = ConnectionLimit::standard();
    let port = listener.local_addr().map(|address| address.port());
    for connection in listener.incoming() {
        match connection {
            Ok(mut stream) => {
                let Some(permit) = limit.acquire() else {
                    refuse(&mut stream, BUSY_REFUSAL);
                    continue;
                };
                let (grants, resolver) = (grants.clone(), resolver.clone());
                let Ok(port) = port else { continue };
                drop(thread::spawn(move || {
                    let _permit = permit;
                    handle(&grants, port, upstream, &resolver, stream);
                }));
            }
            Err(error) => {
                eprintln!("forward: grant proxy accept failed: {error}");
                thread::sleep(ACCEPT_ERROR_BACKOFF);
            }
        }
    }
}

fn handle(
    grants: &Grants,
    port: u16,
    upstream: SocketAddr,
    resolver: &Resolver,
    mut stream: TcpStream,
) {
    let Some(grant) = grants.live(port) else {
        eprintln!("forward: grant proxy refused an ungranted connection on {port}");
        refuse(&mut stream, UNGRANTED_REFUSAL);
        return;
    };
    let (Ok(SocketAddr::V4(peer)), Ok(SocketAddr::V4(local))) =
        (stream.peer_addr(), stream.local_addr())
    else {
        refuse(&mut stream, SESSION_REFUSAL);
        return;
    };
    if resolver(peer, local).as_deref() != Some(grant.session.as_str()) {
        eprintln!("forward: grant proxy refused a connection outside session {}", grant.session);
        refuse(&mut stream, SESSION_REFUSAL);
        return;
    }

    let Ok(mut laptop) = TcpStream::connect(upstream) else {
        refuse(&mut stream, GENERIC_REFUSAL);
        return;
    };
    let mut request = Vec::with_capacity(grant.token.len() + 7);
    request.extend_from_slice(b"RELAY ");
    request.extend_from_slice(&grant.token);
    request.push(b'\n');
    if laptop.write_all(&request).is_err() {
        refuse(&mut stream, GENERIC_REFUSAL);
        return;
    }
    for socket in [&stream, &laptop] {
        if socket.set_read_timeout(Some(PIPE_IDLE_TIMEOUT)).is_err()
            || socket.set_write_timeout(Some(PIPE_IDLE_TIMEOUT)).is_err()
        {
            return;
        }
    }
    if let Err(error) = bidirectional(stream, laptop) {
        eprintln!("forward: grant proxy session on {port} ended: {error}");
    }
}
```

If `bridge::limit::ConnectionLimit` is not `pub(crate)`-visible from `browser`, widen its visibility in the same commit rather than duplicating the type.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --test browser_grant`
Expected: PASS, all five.

- [ ] **Step 5: Check the line budget, format, and lint**

Run: `./scripts/check-source-line-limit.sh && cargo fmt --all -- --check && cargo clippy --all-targets -- -D warnings`
Expected: all pass.

- [ ] **Step 6: Commit**

```bash
jj describe -m "feat(browser): serve one loopback port per grant

Every accepted connection is attributed to a session before the token is
prefixed, so another agent's endpoint is refused rather than shared." && jj new
```

---

### Task 6: `forward browser grant` and the request socket

**Files:**
- Create: `src/browser/request.rs`
- Modify: `src/browser.rs` (add `pub mod request;`), `src/main.rs` (add the `Grant` verb), `src/serve.rs` (start the request socket)
- Test: `src/browser/request.rs` inline tests, `tests/browser_grant.rs`

**Interfaces:**
- Consumes: `grant::Grants`, `proxy::spawn`.
- Produces: `browser::request::socket_path() -> PathBuf` (`$XDG_RUNTIME_DIR/forward-browser-grant.sock`), `browser::request::serve(grants: Grants, cfg: Config, path: PathBuf)`, `browser::request::request(path: &Path, ttl_secs: u64, token: &[u8]) -> Option<u16>`, and `browser::request::parse(line: &[u8]) -> Option<(u64, Vec<u8>)>`.

The wire format is `GRANT <ttl_secs> <token>\n`, answered with `<port>\n` or `REFUSED\n`. The caller's pid comes from `SO_PEERCRED` on the unix socket — exact, no `/proc/net/tcp` lookup — and is resolved with `peer::session_for_pid`.

- [ ] **Step 1: Write the failing parser tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_well_formed_request_parses() {
        assert_eq!(
            parse(b"GRANT 1800 correct-horse"),
            Some((1800, b"correct-horse".to_vec()))
        );
    }

    #[test]
    fn a_request_without_the_verb_is_rejected() {
        assert_eq!(parse(b"1800 correct-horse"), None);
    }

    #[test]
    fn a_non_numeric_ttl_is_rejected() {
        assert_eq!(parse(b"GRANT soon correct-horse"), None);
    }

    #[test]
    fn a_missing_token_is_rejected() {
        assert_eq!(parse(b"GRANT 1800"), None);
        assert_eq!(parse(b"GRANT 1800 "), None);
    }

    #[test]
    fn a_token_containing_a_space_is_rejected() {
        // The token is base64 without padding, so a space means a malformed
        // request rather than a token to be reassembled.
        assert_eq!(parse(b"GRANT 1800 correct horse"), None);
    }

    #[test]
    fn a_zero_ttl_is_rejected() {
        assert_eq!(parse(b"GRANT 0 correct-horse"), None);
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --lib browser::request`
Expected: FAIL — `cannot find function 'parse'`.

- [ ] **Step 3: Write the parser and the socket server**

```rust
use crate::browser::grant::{Grant, Grants};
use crate::browser::peer::session_for_pid;
use crate::browser::proxy;
use crate::config::Config;
use std::io::{BufRead as _, BufReader, Write as _};
use std::net::SocketAddr;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// `GRANT 4294967295 ` plus a 43-character token is well under this.
const MAX_REQUEST_LINE: usize = 128;
const LONGEST_TTL: Duration = Duration::from_secs(12 * 60 * 60);

/// Where `forward browser grant` reaches the local daemon.
///
/// A unix socket, never a TCP port: `SO_PEERCRED` on it yields the caller's pid
/// exactly, which is what binds a grant to the session that asked for it.
pub fn socket_path() -> PathBuf {
    crate::bridge::arming::arm_socket_path().with_file_name("forward-browser-grant.sock")
}

pub fn parse(line: &[u8]) -> Option<(u64, Vec<u8>)> {
    let text = std::str::from_utf8(line).ok()?.strip_prefix("GRANT ")?;
    let (ttl, token) = text.split_once(' ')?;
    let ttl: u64 = ttl.parse().ok()?;
    if ttl == 0 || ttl > LONGEST_TTL.as_secs() || token.is_empty() || token.contains(' ') {
        return None;
    }
    Some((ttl, token.as_bytes().to_vec()))
}
```

Serve requests, resolving the caller through `SO_PEERCRED`:

```rust
/// Serve grant requests for the life of the process.
pub fn serve(grants: Grants, cfg: Config, path: PathBuf) {
    let _ = std::fs::remove_file(&path);
    let Ok(listener) = UnixListener::bind(&path) else {
        eprintln!("forward: could not bind grant socket {}", path.display());
        return;
    };
    if std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o600)).is_err()
    {
        eprintln!("forward: could not restrict grant socket {}", path.display());
        return;
    }
    let upstream = laptop_relay(&cfg);
    for stream in listener.incoming().flatten() {
        handle(&grants, &cfg, upstream, stream);
    }
}

fn laptop_relay(cfg: &Config) -> SocketAddr {
    SocketAddr::new(
        cfg.peer.parse().expect("config validation rejects a non-literal peer"),
        cfg.relay_port,
    )
}

fn handle(grants: &Grants, cfg: &Config, upstream: SocketAddr, mut stream: UnixStream) {
    let Some(pid) = peer_pid(&stream) else {
        let _ = stream.write_all(b"REFUSED\n");
        return;
    };
    let Some(session) = session_for_pid(pid) else {
        eprintln!("forward: grant refused: pid {pid} is not inside an omp session");
        let _ = stream.write_all(b"REFUSED\n");
        return;
    };
    let mut line = Vec::new();
    let mut reader = BufReader::new(match stream.try_clone() {
        Ok(clone) => clone,
        Err(_) => return,
    })
    .take(MAX_REQUEST_LINE as u64);
    if reader.read_until(b'\n', &mut line).is_err() {
        let _ = stream.write_all(b"REFUSED\n");
        return;
    }
    while line.last().is_some_and(|byte| *byte == b'\n' || *byte == b'\r') {
        drop(line.pop());
    }
    let Some((ttl, token)) = parse(&line) else {
        let _ = stream.write_all(b"REFUSED\n");
        return;
    };
    let Ok(port) = proxy::spawn(cfg, grants.clone(), upstream) else {
        let _ = stream.write_all(b"REFUSED\n");
        return;
    };
    grants.insert(
        port,
        Grant {
            session: session.clone(),
            token,
            deadline: Instant::now() + Duration::from_secs(ttl),
        },
    );
    eprintln!("forward: granted browser access to session {session} on 127.0.0.1:{port} for {ttl}s");
    let _ = writeln!(stream, "{port}");
}

fn peer_pid(stream: &UnixStream) -> Option<u32> {
    let credentials = nix::sys::socket::getsockopt(stream, nix::sys::socket::sockopt::PeerCredentials).ok()?;
    u32::try_from(credentials.pid()).ok()
}
```

Check whether `nix` is already a dependency with the `socket` feature. If it is not, read the credentials with `libc::getsockopt` through the existing dependency set, or add the feature — do not hand-roll a `SO_PEERCRED` `unsafe` block if a dependency already exposes it.

The client half:

```rust
/// Ask the local daemon for a grant. Returns the bound loopback port.
pub fn request(path: &Path, ttl_secs: u64, token: &[u8]) -> Option<u16> {
    let mut stream = UnixStream::connect(path).ok()?;
    stream.write_all(b"GRANT ").ok()?;
    stream.write_all(ttl_secs.to_string().as_bytes()).ok()?;
    stream.write_all(b" ").ok()?;
    stream.write_all(token).ok()?;
    stream.write_all(b"\n").ok()?;
    let mut reply = String::new();
    BufReader::new(stream).read_line(&mut reply).ok()?;
    reply.trim_end().parse().ok()
}
```

- [ ] **Step 4: Wire the CLI verb**

Add to `BrowserCommand`:

```rust
    /// Request browser access for this session (devbox side)
    Grant {
        /// Grant lifetime, for example 30m or 2h
        #[arg(long, default_value = "30m")]
        ttl: String,
        #[arg(long)]
        config: Option<std::path::PathBuf>,
    },
```

Dispatch it: read the token from the `FORWARD_BROWSER_GRANT` environment variable that `secrets` injects, erroring clearly when it is absent, parse the TTL, call `request`, and print `http://127.0.0.1:<port>`. The error text when the variable is missing must name the command to run:

```
forward: FORWARD_BROWSER_GRANT is not set; run
  secrets FORWARD_BROWSER_GRANT -- forward browser grant --ttl 30m
```

- [ ] **Step 5: Start the socket from `forward serve`**

In `src/serve.rs`, alongside the existing arming socket, construct one `Grants`, spawn `request::serve(grants, cfg.clone(), request::socket_path())` on its own thread.

- [ ] **Step 6: Run the tests to verify they pass**

Run: `cargo test --lib browser::request && cargo test --test browser_grant && cargo build`
Expected: PASS.

- [ ] **Step 7: Verify the missing-token error by hand**

Run: `env -u FORWARD_BROWSER_GRANT cargo run -- browser grant --ttl 30m 2>&1 | head -3`
Expected: the error naming the `secrets` command, exit non-zero, no socket connection attempted.

- [ ] **Step 8: Commit**

```bash
jj describe -m "feat(browser): request a grant over a peer-credentialed socket

SO_PEERCRED binds the grant to the calling session exactly, so there is no
--session argument to forge." && jj new
```

---

### Task 7: Doctor reports the gate

**Files:**
- Modify: `src/doctor/browser.rs` (new evidence variant), `src/doctor.rs` (devbox grant row)
- Create: `src/doctor/browser/evidence.rs` (only if `browser.rs` would exceed 250 lines — it is at 235)
- Test: `tests/doctor.rs` or `tests/doctor/`

**Interfaces:**
- Consumes: `RelayEvidence`, `classify`, `grant::Grants`.
- Produces: `RelayEvidence::TokenRequired`, and a doctor row reading `browser relay: locked at <host>:<port> (no grant)`.

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn a_token_refusal_is_proof_the_laptop_channel_is_alive() {
    // Given: the laptop's refusal for a connection presenting no token.
    let body = b"REFUSED TOKEN\n";

    // When/Then: it is a distinct, healthy-but-locked state, not an error.
    assert_eq!(classify(body), Ok(RelayEvidence::TokenRequired));
}
```

Plus a report-level test asserting the rendered row says `locked` and mentions `no grant`, following whatever `tests/doctor` already does for the existing rows.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --test doctor`
Expected: FAIL — no variant `TokenRequired`.

- [ ] **Step 3: Add the variant and classification**

In `src/doctor/browser.rs`, add `TokenRequired` to `RelayEvidence` and, in `classify`, before the generic `REFUSED\n` arm because `starts_with` would otherwise mask it:

```rust
    if body.starts_with(b"REFUSED TOKEN") {
        return Ok(RelayEvidence::TokenRequired);
    }
```

Render it as alive-and-enforcing rather than as a failure: doctor holds no token and must not need one to report health.

- [ ] **Step 4: Add the devbox grant row**

Report whether the invoking session holds a live grant, resolving the session with `peer::session_for_pid(std::process::id())`. With no grant, say so and name the command:

```
browser grant: none for this session — secrets FORWARD_BROWSER_GRANT -- forward browser grant --ttl 30m
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test --test doctor && ./scripts/check-source-line-limit.sh`
Expected: PASS. If `src/doctor/browser.rs` crosses 250 lines, move `RelayEvidence` and `classify` into `src/doctor/browser/evidence.rs` as part of this task.

- [ ] **Step 6: Commit**

```bash
jj describe -m "feat(doctor): distinguish a locked relay from a broken one

A token refusal proves the listener is alive, peer-authorised and enforcing,
so doctor reports health without holding any secret." && jj new
```

---

### Task 8: Consumer cutover

Every current caller dials the laptop directly. Leaving one in place would reopen the bypass Task 1 closed, so this task removes all of them.

**Files (in `~/.dotfiles`, a separate repo — commit there):**
- Modify: `omp/config-serve.yml` (remove `browser.relayUrl`)
- Modify: `.bashrc:92-96` (remove the `BROWSER_RELAY_URL` export)
- Modify: `installers/forward.sh:14-30` (remove `install_relay_shell_environment` and its call), `installers/forward.sh:99` (update the printed guidance)
- Modify: `forward/config.toml` (add `relay_token_file`)
- Modify: `scripts/browser-capture` (make `--relay-url` required, drop the environment default)

- [ ] **Step 1: Confirm the current wiring before changing it**

Run: `grep -rn 'BROWSER_RELAY_URL\|relayUrl' ~/.dotfiles --include='*' | grep -v '\.git/\|transcripts/'`
Expected: the five sites listed above and nothing else. If there are more, cut them all.

- [ ] **Step 2: Remove the static relay URL**

Delete `browser.relayUrl` from `omp/config-serve.yml`. If that leaves the file empty, delete the file, remove the `omp_config_source` handling for the `serve` role in `installers/forward.sh`, and remove the `browser-relay.yml` symlink it created — a dangling symlink in `~/.config/omp` is a silent config-load failure later.

- [ ] **Step 3: Remove the shell export**

Delete the `BROWSER_RELAY_URL` block from `.bashrc` and `install_relay_shell_environment` from `installers/forward.sh`, including the `~/.config/environment.d/browser-relay.conf` it wrote. Remove the stale file on both machines:

```bash
rm -f ~/.config/environment.d/browser-relay.conf
ssh sami@sami rm -f '~/.config/environment.d/browser-relay.conf'
```

- [ ] **Step 4: Require `--relay-url` in `browser-capture`**

In `scripts/browser-capture`, change the argument to `required=True` and delete the `os.environ.get("BROWSER_RELAY_URL")` default, so a capture without a grant fails with an argparse error (exit 1) rather than silently dialling a relay that will refuse it.

- [ ] **Step 5: Configure the laptop token path**

Add to `forward/config.toml` (the laptop role):

```toml
# The relay token itself lives outside this file: config.toml is committed and
# symlinked into place, so a secret here would be published.
relay_token_file = "~/.config/forward/relay.token"
```

If `Config` does not expand `~`, use the literal path the installer creates and expand it in the installer instead — do not add tilde expansion to `Config` for one key.

- [ ] **Step 6: Verify no caller remains**

Run: `grep -rn 'BROWSER_RELAY_URL\|relayUrl\|100.100.92.97:12803' ~/.dotfiles --include='*' | grep -v '\.git/\|transcripts/'`
Expected: no matches outside documentation.

- [ ] **Step 7: Commit (in the dotfiles repo)**

```bash
cd ~/.dotfiles && jj describe -m "refactor(browser): route browser access through grants

The static relay URL let any process reach the laptop; agents now pass a
per-grant endpoint, so the ambient path is removed rather than deprecated." && jj new
```

---

### Task 9: End-to-end verification against the live browser

No new code. This is the spec's verification list, run for real, because three
bugs have shipped in this subsystem behind tests that asserted shapes the real
system never produces.

- [ ] **Step 1: Provision the token**

Run, as Sami, not as an agent:

```bash
ssh sami@sami forward browser init-token | secrets edit-human FORWARD_BROWSER_GRANT
```

Expected: `created …/secrets.human.d/…`. The value appears nowhere else.

- [ ] **Step 2: Deploy both roles**

```bash
~/.dotfiles/installers/forward.sh serve
ssh sami@sami '~/.dotfiles/installers/forward.sh daemon && systemctl --user restart forward-daemon.service'
systemctl --user restart forward-serve.service
```

- [ ] **Step 3: Confirm the bypass is closed**

Run: `curl -s --max-time 8 http://100.100.92.97:12803/json/version`
Expected: `REFUSED TOKEN`. A JSON body here means Task 1 did not deploy, and nothing below is meaningful.

- [ ] **Step 4: Take a grant**

Run: `secrets FORWARD_BROWSER_GRANT -- forward browser grant --ttl 30m`
Expected: the YubiKey blinks; after the touch, `http://127.0.0.1:<port>`.

- [ ] **Step 5: Confirm the endpoint works and keeps Puppeteer local**

Run: `curl -s http://127.0.0.1:<port>/json/version`
Expected: a `webSocketDebuggerUrl` of `ws://127.0.0.1:<port>/cdp` — the grant port, not `100.100.92.97:12803`.

- [ ] **Step 6: Drive a real tab**

Use the omp `browser` tool with `app.cdp_url` set to the grant endpoint; observe a live laptop tab.
Expected: the tab responds. This is the acceptance criterion; a passing test suite is not.

- [ ] **Step 7: Confirm another session is refused**

From a *different* omp session, connect to the first session's port:
Run: `curl -s http://127.0.0.1:<first session's port>/json/version`
Expected: `REFUSED SESSION`.

- [ ] **Step 8: Confirm expiry closes new connections only**

Take a 1-minute grant, open a CDP connection, wait past expiry, then confirm the established connection still works while a new `curl` gets `REFUSED UNGRANTED`.

- [ ] **Step 9: Confirm doctor reads correctly in both states**

Run: `forward doctor`
Expected: with no grant, a `locked` relay row and a `browser grant: none for this session` row; with a grant, a healthy row.

- [ ] **Step 10: Record the results in the spec**

Append the observed outputs to the spec's Verification section, replacing the predicted ones. Commit.

---

## Self-Review

**Spec coverage.** Security model → Tasks 1, 4, 5. Architecture and the
devbox-local endpoint → Tasks 5, 9. Grant lifecycle → Tasks 3, 6. Wire protocol
→ Tasks 1, 5. Token provisioning → Task 2, Task 9 Step 1. Peer attribution →
Task 4. Configuration and health checks → Tasks 1, 7. Consumer cutover → Task 8.
Module layout → Tasks 1–5. Failure modes → Tasks 1 (missing token file), 3
(expiry), 4 (unresolvable pid), 5 (ungranted, wrong session). Verification →
Task 9. No section is unimplemented.

**Placeholder scan.** Every code step carries real code. Three steps
deliberately defer a decision to the implementer with a stated rule rather than
a value: the `ConnectionLimit` visibility widening in Task 5, the `nix`
`SO_PEERCRED` feature check in Task 6, and the `~` expansion in Task 8. Each
names the acceptable resolutions, so none is a "figure it out".

**Type consistency.** `Grant { session, token, deadline }` is constructed
identically in Tasks 3, 5, and 6. `Grants::live(port)` is the only read path,
used in Task 5. `Resolver` is defined in Task 5 and used only there.
`session_for_pid(pid) -> Option<String>` is produced in Task 4 and consumed in
Tasks 5, 6, and 7 with that exact signature. `write_token(&Path) -> Result<String, InitError>`
is produced in Task 2 and called in Task 9. Refusal strings are the same six
byte-strings across Tasks 1, 5, and 7: `REFUSED TOKEN`, `REFUSED UNGRANTED`,
`REFUSED SESSION`, plus the inherited `REFUSED`, `REFUSED PEER`, `REFUSED BUSY`.
