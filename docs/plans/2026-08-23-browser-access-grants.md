# Browser Access Grants Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace ambient browser-relay access with per-session grants, so reaching the laptop's Chrome requires a YubiKey touch and is usable only by the agent session it was granted to.

**Architecture:** The laptop's relay channel stops accepting raw CDP and requires a `RELAY <token>` request line, which closes the direct-dial bypass. On the devbox, `forward serve` binds one ephemeral loopback port per grant, attributes every accepted connection to an omp session through `/proc`, and refuses anything that is not the granted session before prefixing the token and piping to the laptop. A per-grant reaper thread closes the endpoint's listener at its deadline, so an expired grant leaves neither a bound port nor a registry-held token behind.

**Tech Stack:** Rust (edition 2024, rust-version 1.88), `thiserror` for errors, `parking_lot::Mutex` for shared state, `base64` (already a dependency) for token encoding, and `nix` 0.31 — added by Task 6, feature `socket` — for `SO_PEERCRED`.

**Spec:** `docs/design/2026-08-23-browser-access-grants.md`

## Global Constraints

- **250 lines per Rust source file**, enforced by `scripts/check-source-line-limit.sh` over `src/**/*.rs tests/**/*.rs`. Splitting a file is part of the task that would overflow it. Watch the two files already near the cap: `tests/browser.rs` is at 248 (Task 1 splits it) and `src/config/tests.rs` is at 221 (Task 1 puts its new config tests in a second test module).
- **`cargo fmt --all -- --check` is a CI gate.** There is no `rustfmt.toml`, so `reorder_imports = true` applies and `crate::*` sorts before `forward::*`. Follow the formatter, not this document, if they disagree.
- **Errors use `thiserror`**, one enum per module, matching `BrowserError` and `BridgeError`.
- **This plan adds exactly one dependency:** `nix = { version = "0.31", features = ["socket"] }`, added by Task 6 for `SO_PEERCRED`. `UnixStream::peer_cred` is unstable on rustc 1.97.1, neither `nix` nor `libc` is currently a dependency, and hand-rolling `unsafe` FFI for a solved problem is out. Verified available: nix 0.31.3, whose `getsockopt<F: AsFd, O: GetSockOpt>(fd: &F, opt: O)` accepts `&UnixStream` directly. **No other dependency is added:** `/dev/urandom` is a CSPRNG, `base64` is already present, and constant-time comparison is a short XOR accumulate. Do not add a crate for those three things.
- **This plan lands as two PRs, not a gh-stack:** Tasks 1–7 and 9 in `forward`, Task 8 in `~/.dotfiles` — gh-stack stacks branches within one repo, and this work spans two. They must land close together: deploying Task 1 without Task 8 breaks `browser-capture`'s environment contract and leaves the omp relay overlay pointing at a channel that now refuses it.
- **`Config::default_values_for_test()` is `#[doc(hidden)] pub` and unconditional** — integration tests call it, so it must never become `#[cfg(test)]`.
- **`Config` is `#[serde(deny_unknown_fields)]`** — every new key needs a `#[serde(default)]`.
- **Version control is jj, never git.** Commit with `jj describe -m "…"` then `jj new`. Never run a mutating git command.
- **Never print a real token value** in a log line, error, test snapshot, or `Debug` impl.

---

### Task 1: Laptop refuses untokened relay connections

Closes the direct-dial bypass. Until this lands the rest of the system is advisory.

**Files:**
- Create: `src/browser/token.rs`, `src/config/token_path_tests.rs`, `tests/browser_token.rs`, `tests/browser_peer.rs`
- Modify: `src/browser.rs` (add `mod token;`, gate `handle_from`)
- Modify: `src/config.rs:22-24` (add `relay_token_file` beside `relay_port`, add `relay_token_path()`)
- Modify: `tests/browser.rs` (migrate the success-path tests to the token protocol; move the flooding peer test out for the line cap)

**Interfaces:**
- Consumes: nothing.
- Produces: `browser::token::constant_time_eq(&[u8], &[u8]) -> bool`, `browser::token::load(&Path) -> Option<Vec<u8>>`, `Config::relay_token_file: Option<PathBuf>` (an override, never set by committed config), `Config::relay_token_path() -> Option<PathBuf>` (override, else `$XDG_CONFIG_HOME/forward/relay.token`, else `$HOME/.config/forward/relay.token`), refusal constant `TOKEN_REFUSAL = b"REFUSED TOKEN\n"`.

- [ ] **Step 1: Write the failing tests**

`tempfile` is already in `[dev-dependencies]` (`Cargo.toml`), so nothing is added there.

**1a.** Create `tests/browser_token.rs` — the token-gate tests. Both fail-closed tests assert the upstream was never dialled, using the same nonblocking-listener pattern as the absent-request-line test:

```rust
use std::io::{ErrorKind, Read as _, Write as _};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

fn cfg_with_peer(peer: &str) -> forward::config::Config {
    let mut cfg = forward::config::Config::default_values_for_test();
    cfg.peer = peer.to_owned();
    cfg
}

fn cfg_with_token(peer: &str, token: &str) -> (forward::config::Config, tempfile::TempDir) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("relay.token");
    std::fs::write(&path, format!("{token}\n")).unwrap();
    let mut cfg = cfg_with_peer(peer);
    cfg.relay_token_file = Some(path);
    (cfg, directory)
}

fn assert_refused(client: &mut TcpStream, expected: &str) {
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut reply = String::new();
    client
        .read_to_string(&mut reply)
        .expect("the relay must write its refusal before closing");
    assert_eq!(reply, expected);
}

fn assert_never_dialed(upstream: &TcpListener) {
    upstream.set_nonblocking(true).unwrap();
    assert!(matches!(
        upstream.accept(),
        Err(error) if error.kind() == ErrorKind::WouldBlock
    ));
}

fn spawn_pong(listener: TcpListener) -> SocketAddr {
    let address = listener.local_addr().unwrap();
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = [0_u8; 4];
        stream.read_exact(&mut request).unwrap();
        assert_eq!(&request, b"ping");
        stream.write_all(b"pong").unwrap();
    });
    address
}

fn spawn_pong_upstream() -> SocketAddr {
    spawn_pong(TcpListener::bind("127.0.0.1:0").unwrap())
}

fn spawn_relay(cfg: forward::config::Config, upstream: SocketAddr) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    forward::browser::spawn_with_listener(cfg, listener, upstream).unwrap();
    port
}

fn read_pong(client: &mut TcpStream) {
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut reply = [0_u8; 4];
    client.read_exact(&mut reply).unwrap();
    assert_eq!(&reply, b"pong");
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
    assert_never_dialed(&upstream);
}

#[test]
fn a_connection_with_the_wrong_relay_token_is_refused_and_never_reaches_the_upstream() {
    // Given: a relay expecting one token, and an upstream that must stay silent.
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let (cfg, _directory) = cfg_with_token("127.0.0.1", "correct-horse");
    let port = spawn_relay(cfg, upstream.local_addr().unwrap());

    // When: a client presents a different token.
    let mut client = TcpStream::connect(("127.0.0.1", port)).unwrap();
    client.write_all(b"RELAY battery-staple\nping").unwrap();

    // Then: it is refused before the upstream is ever dialed.
    assert_refused(&mut client, "REFUSED TOKEN\n");
    assert_never_dialed(&upstream);
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
fn a_relay_whose_token_file_is_missing_refuses_without_dialing_the_upstream() {
    // Given: a token path with no file behind it, as on a half-provisioned
    // laptop. The override keeps the test hermetic: the fallback path under
    // $HOME may hold a real token on a deployed machine.
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let directory = tempfile::tempdir().unwrap();
    let mut cfg = cfg_with_peer("127.0.0.1");
    cfg.relay_token_file = Some(directory.path().join("absent.token"));
    let port = spawn_relay(cfg, upstream.local_addr().unwrap());

    // When: a client presents any token.
    let mut client = TcpStream::connect(("127.0.0.1", port)).unwrap();
    client.write_all(b"RELAY correct-horse\nping").unwrap();

    // Then: it fails closed rather than open, and the upstream stays silent.
    assert_refused(&mut client, "REFUSED TOKEN\n");
    assert_never_dialed(&upstream);
}
```

**1b.** Migrate every success-path test in `tests/browser.rs` to the token protocol. The file holds seven tests; they split three ways:

| Test | Disposition |
| --- | --- |
| `an_unauthorized_peer_is_refused_and_its_payload_never_reaches_the_upstream` | stays as a pre-token check — the peer gate refuses before the token gate reads anything |
| `a_flooding_unauthorized_peer_still_gets_the_refusal_and_frees_its_slot` | stays as a pre-token check, but moves to `tests/browser_peer.rs`: the file is at 248 lines against the 250 cap and cannot absorb the migration edits |
| `the_configured_peer_is_proxied_bidirectionally` | migrated: presents `RELAY correct-horse\n` |
| `a_mapped_ipv6_peer_matches_the_configured_ipv4_peer` | migrated: presents `RELAY correct-horse\n` |
| `a_loopback_client_stays_authorized_for_local_tooling` | migrated: presents `RELAY correct-horse\n` |
| `half_close_propagates_in_each_direction` | migrated: request line precedes the payload |
| `an_absent_upstream_closes_the_connection_without_killing_the_accept_loop` | migrated: both clients must pass the token gate, because it now sits before the upstream dial |

In `tests/browser.rs`: delete `wait_for_exit` and the flooding test (they move to `tests/browser_peer.rs`), shrink the `std::sync` import to `use std::sync::mpsc;`, drop the now-unused `Instant` import, add `cfg_with_token` (same body as in `tests/browser_token.rs`), and replace the five migrated tests with:

```rust
#[test]
fn the_configured_peer_is_proxied_bidirectionally() {
    // Given: the configured, non-loopback peer and a pong upstream.
    let (mut client, server) = socket_pair();
    let (cfg, _directory) = cfg_with_token("100.64.0.9", "correct-horse");
    let handler = thread::spawn(move || {
        forward::browser::handle_from(
            &cfg,
            spawn_pong_upstream(),
            "100.64.0.9".parse().unwrap(),
            server,
        );
    });

    // When: that peer presents the token and sends four bytes.
    client.write_all(b"RELAY correct-horse\nping").unwrap();

    // Then: the upstream receives them and returns its reply through the channel.
    read_pong(&mut client);
    drop(client);
    handler.join().unwrap();
}

#[test]
fn a_mapped_ipv6_peer_matches_the_configured_ipv4_peer() {
    // Given: an IPv4 configured peer represented as a mapped IPv6 remote.
    let (mut client, server) = socket_pair();
    let (cfg, _directory) = cfg_with_token("100.64.0.9", "correct-horse");
    let handler = thread::spawn(move || {
        forward::browser::handle_from(
            &cfg,
            spawn_pong_upstream(),
            "::ffff:100.64.0.9".parse::<IpAddr>().unwrap(),
            server,
        );
    });

    // When/Then: canonical authorization allows the complete tokened exchange.
    client.write_all(b"RELAY correct-horse\nping").unwrap();
    read_pong(&mut client);
    drop(client);
    handler.join().unwrap();
}

#[test]
fn a_loopback_client_stays_authorized_for_local_tooling() {
    // Given: a real listener and a configuration naming only a remote peer.
    let (cfg, _directory) = cfg_with_token("100.64.0.9", "correct-horse");
    let relay = spawn_relay(cfg, spawn_pong_upstream());
    let mut client = TcpStream::connect(("127.0.0.1", relay)).unwrap();

    // When/Then: the local doctor-style client is still proxied end to end.
    client.write_all(b"RELAY correct-horse\nping").unwrap();
    read_pong(&mut client);
}

#[test]
fn half_close_propagates_in_each_direction() {
    // Given: a listener whose upstream sends a reply only after receiving EOF.
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_address = upstream.local_addr().unwrap();
    let (sender, receiver) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let (mut stream, _) = upstream.accept().unwrap();
        let mut request = String::new();
        stream.read_to_string(&mut request).unwrap();
        sender.send(request).unwrap();
        stream.write_all(b"gone").unwrap();
        stream.shutdown(Shutdown::Write).unwrap();
    });
    let (cfg, _directory) = cfg_with_token("100.64.0.9", "correct-horse");
    let relay = spawn_relay(cfg, upstream_address);
    let mut client = TcpStream::connect(("127.0.0.1", relay)).unwrap();

    // When: the client half-closes after its tokened request.
    client.write_all(b"RELAY correct-horse\ndata").unwrap();
    client.shutdown(Shutdown::Write).unwrap();

    // Then: the upstream sees EOF and can still return a final reply and EOF.
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut reply = String::new();
    client.read_to_string(&mut reply).unwrap();
    assert_eq!(
        receiver.recv_timeout(Duration::from_secs(5)).unwrap(),
        "data"
    );
    assert_eq!(reply, "gone");
}

#[test]
fn an_absent_upstream_closes_the_connection_without_killing_the_accept_loop() {
    // Given: a relay pointing to an ephemeral port with no current upstream.
    let probe = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream = probe.local_addr().unwrap();
    drop(probe);
    let (cfg, _directory) = cfg_with_token("100.64.0.9", "correct-horse");
    let relay = spawn_relay(cfg, upstream);

    // When: the first tokened client reaches the absent upstream. The token
    // gate now precedes the dial, so an untokened client would see
    // REFUSED TOKEN instead of exercising this path.
    let mut first = TcpStream::connect(("127.0.0.1", relay)).unwrap();
    first.write_all(b"RELAY correct-horse\n").unwrap();
    assert_refused(&mut first, "REFUSED\n");

    // Then: a later upstream and client prove the accept loop survived.
    spawn_pong(TcpListener::bind(upstream).unwrap());
    let mut second = TcpStream::connect(("127.0.0.1", relay)).unwrap();
    second.write_all(b"RELAY correct-horse\nping").unwrap();
    read_pong(&mut second);
}
```

**1c.** Create `tests/browser_peer.rs` with the flooding test moved verbatim, plus the helpers it needs:

```rust
use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::{Duration, Instant};

fn cfg_with_peer(peer: &str) -> forward::config::Config {
    let mut cfg = forward::config::Config::default_values_for_test();
    cfg.peer = peer.to_owned();
    cfg
}

fn socket_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (server, _) = listener.accept().unwrap();
    (client, server)
}

fn wait_for_exit(handle: &thread::JoinHandle<()>) -> bool {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !handle.is_finished() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(20));
    }
    handle.is_finished()
}

#[test]
fn a_flooding_unauthorized_peer_still_gets_the_refusal_and_frees_its_slot() {
    // Given: a foreign peer that never stops flooding its socket.
    let (client, server) = socket_pair();
    let mut reader = client.try_clone().unwrap();
    reader
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let writer_stop = Arc::clone(&stop);
    let writer = thread::spawn(move || {
        while !writer_stop.load(Ordering::Relaxed) {
            let _ = (&client).write_all(&[0_u8; 4096]);
        }
    });
    let cfg = cfg_with_peer("100.64.0.9");
    let handler = thread::spawn(move || {
        forward::browser::handle_from(
            &cfg,
            upstream.local_addr().unwrap(),
            "100.64.0.7".parse().unwrap(),
            server,
        );
    });

    // When: the bounded drain refuses the connection despite the continuous writes.
    let mut reply = Vec::new();
    while !reply.ends_with(b"REFUSED PEER\n") {
        let mut chunk = [0_u8; 32];
        let count = reader.read(&mut chunk).unwrap();
        assert_ne!(count, 0, "relay closed before sending its refusal");
        reply.extend_from_slice(&chunk[..count]);
    }

    // Then: the refusal survived and the handler returned without waiting for the peer.
    assert_eq!(reply, b"REFUSED PEER\n");
    assert!(wait_for_exit(&handler), "flooding peer pinned the handler");
    stop.store(true, Ordering::Relaxed);
    writer.join().unwrap();
    handler.join().unwrap();
}
```

**1d.** Create `src/config/token_path_tests.rs` — a second test module beside `src/config/tests.rs`, which is at 221 lines and cannot absorb these under the 250 cap (precedent: `src/doctor.rs` carries both `tests` and `browser_tests`):

```rust
use super::*;
use std::path::PathBuf;

#[test]
fn relay_token_path_prefers_the_configured_override() {
    let mut cfg = Config::default_values_for_test();
    cfg.relay_token_file = Some(PathBuf::from("/etc/forward/relay.token"));
    assert_eq!(
        cfg.relay_token_path(),
        Some(PathBuf::from("/etc/forward/relay.token"))
    );
}

#[test]
fn relay_token_path_falls_back_from_xdg_to_home() {
    assert_eq!(
        relay_token_path_from(None, Some(PathBuf::from("/xdg")), Some(PathBuf::from("/home/u"))),
        Some(PathBuf::from("/xdg/forward/relay.token"))
    );
    assert_eq!(
        relay_token_path_from(None, None, Some(PathBuf::from("/home/u"))),
        Some(PathBuf::from("/home/u/.config/forward/relay.token"))
    );
    // A relative or empty variable does not name a usable directory.
    assert_eq!(
        relay_token_path_from(None, Some(PathBuf::from("relative")), Some(PathBuf::from("/home/u"))),
        Some(PathBuf::from("/home/u/.config/forward/relay.token"))
    );
    assert_eq!(relay_token_path_from(None, None, None), None);
}

#[test]
fn relay_token_file_parses_and_defaults_to_none() {
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(&file, "relay_token_file = \"/tmp/relay.token\"\n").unwrap();
    assert_eq!(
        load(file.path()).unwrap().relay_token_file,
        Some(PathBuf::from("/tmp/relay.token"))
    );
    assert_eq!(Config::default_values_for_test().relay_token_file, None);
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --test browser --test browser_token --test browser_peer`
Expected: FAIL — `no field 'relay_token_file' on type 'forward::config::Config'`.

- [ ] **Step 3: Add the config key and the token path derivation**

In `src/config.rs`, directly after `relay_port`:

```rust
    /// Override for the laptop's relay token file. Normally unset: the token
    /// lives at the derived per-machine path (see [`Config::relay_token_path`]),
    /// never in `config.toml`, which is committed to dotfiles and symlinked
    /// into place — a secret or a machine-local path in it would be published.
    #[serde(default)]
    pub relay_token_file: Option<PathBuf>,
```

Add `relay_token_file: None` to `default_values()` (`default_values_for_test()` delegates to it, so it needs no edit of its own). In `impl Config`, add:

```rust
    /// Where the laptop's relay token lives: the `relay_token_file` override
    /// if set, else `$XDG_CONFIG_HOME/forward/relay.token`, else
    /// `$HOME/.config/forward/relay.token` — the same derivation the binary
    /// already uses for `config.toml` itself. `None` when no override is set
    /// and neither variable is an absolute path; every caller treats `None`
    /// as "no token", which refuses every relay connection.
    pub fn relay_token_path(&self) -> Option<PathBuf> {
        relay_token_path_from(
            self.relay_token_file.clone(),
            std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from),
            std::env::var_os("HOME").map(PathBuf::from),
        )
    }
```

And beside the other free functions, the pure helper the unit tests drive (no
environment mutation in tests, which would race parallel test threads):

```rust
fn relay_token_path_from(
    override_path: Option<PathBuf>,
    xdg_config_home: Option<PathBuf>,
    home: Option<PathBuf>,
) -> Option<PathBuf> {
    if let Some(path) = override_path {
        return Some(path);
    }
    if let Some(config_home) = xdg_config_home.filter(|path| path.is_absolute()) {
        return Some(config_home.join("forward/relay.token"));
    }
    home.filter(|path| path.is_absolute())
        .map(|home| home.join(".config/forward/relay.token"))
}
```

Register the new test module at the bottom of `src/config.rs`, beside the existing one:

```rust
#[cfg(test)]
mod token_path_tests;
```

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
    let expected = cfg.relay_token_path().and_then(|path| token::load(&path));
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

Run: `cargo test --test browser --test browser_token --test browser_peer && cargo test --lib browser::token && cargo test --lib config::`
Expected: PASS.

- [ ] **Step 7: Check the line budget and format**

Run: `./scripts/check-source-line-limit.sh && cargo fmt --all -- --check && cargo clippy --all-targets -- -D warnings`
Expected: all pass. If `src/browser.rs` exceeds 250 lines, move `read_relay_token` into `src/browser/token.rs` rather than trimming comments. If `tests/browser.rs` still exceeds 250 after the flooding test moved out, move `an_absent_upstream_closes_the_connection_without_killing_the_accept_loop` into `tests/browser_token.rs`, which has roughly 100 lines of headroom.

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
- Consumes: `Config::relay_token_path` from Task 1.
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
    fn rotating_a_world_readable_file_restores_owner_only_permissions() {
        // Given: a token file someone loosened to 0644.
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("relay.token");
        std::fs::write(&path, "old\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        // When: the token is rotated in place.
        write_token(&path).unwrap();

        // Then: the file is 0600 again. `OpenOptions::mode` alone cannot make
        // this pass — it applies only at creation — so this test pins the
        // explicit `set_permissions` call.
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn a_missing_parent_directory_is_created() {
        // The default path is $XDG_CONFIG_HOME/forward/relay.token; a fresh
        // machine may not have the directory yet.
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("forward/relay.token");
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
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
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
    #[error("failed to restrict token {path} to 0600: {source}")]
    Restrict {
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

    let write_error = |source| InitError::Write {
        path: path.display().to_string(),
        source,
    };
    if let Some(parent) = path.parent().filter(|parent| !parent.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent).map_err(write_error)?;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(write_error)?;
    // `OpenOptions::mode` applies only at creation. Rotating an existing file
    // keeps whatever mode it had, so restrict it explicitly every time, and
    // propagate a failure: a token the group can read is not provisioned.
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(|source| InitError::Restrict {
            path: path.display().to_string(),
            source,
        })?;
    writeln!(file, "{value}").map_err(write_error)?;
    Ok(value)
}
```

The permissions are corrected after opening and before the value is written, so
at no instant does a readable-by-others file hold a token. The rotation test
above fails against an implementation that relies on `OpenOptions::mode` alone.

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
                let path = cfg.relay_token_path().ok_or_else(|| {
                    anyhow::anyhow!(
                        "forward: cannot resolve the relay token path: relay_token_file is unset and neither XDG_CONFIG_HOME nor HOME is an absolute path"
                    )
                })?;
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

The default path derivation would write into the real `~/.config/forward` on
this machine, so exercise the override instead, in a scratch directory:

```bash
tmp="$(mktemp -d)" \
  && printf 'relay_token_file = "%s/relay.token"\n' "$tmp" > "$tmp/config.toml" \
  && cargo run --quiet -- browser init-token --config "$tmp/config.toml" | wc -c \
  && stat -c '%a' "$tmp/relay.token"
```

Expected: `44` (43 base64 characters plus the newline) and `600`. The value
itself never appears in the transcript.

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
- Produces: `browser::grant::Grant { session: String, token: Vec<u8>, deadline: Instant }` (`Clone`), `browser::grant::Grants` with `Grants::new()`, `Grants::insert(port: u16, grant: Grant)`, `Grants::live(port: u16) -> Option<Grant>`, `Grants::expire(port: u16)`, and the `#[doc(hidden)]` test seams `Grants::take_scrubbed(port: u16) -> Option<Vec<u8>>` and `Grants::tokens_held() -> usize`. `Grants` is `Clone` and shares one map, matching `bridge::Armed`.

**What zeroing does and does not cover.** `Grant` is `Clone`, and `live()` hands
callers a clone: the proxy's connection handler keeps its own copy of the token
for as long as its connection lives, and nothing zeroes that copy — established
connections outliving the deadline is exactly the spec's behaviour. Expiry
zeroes only the **registry's** copy, in place, before the entry is dropped, so
once no grant is live the daemon's registry holds no token. The spec sentence
"that grant's copy of the token is zeroed" is precisely this narrow claim; the
coordinator is amending the spec's wording, not this plan.

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
        assert_eq!(grants.tokens_held(), 0);
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
    fn expiring_a_grant_zeroes_its_token_in_place() {
        // Given: a live grant holding a 13-byte token.
        let grants = Grants::new();
        grants.insert(12811, grant("session-a", Duration::from_secs(60)));

        // When: it is expired through the same scrub path `expire` uses,
        // keeping the registry's own buffer observable. `take_scrubbed` moves
        // the Vec out, so this is the very allocation the registry held.
        let scrubbed = grants.take_scrubbed(12811).unwrap();

        // Then: the buffer keeps the token's length and every byte is zero.
        // An implementation that removes without zeroing fails here, which is
        // the bug this test exists to name.
        assert_eq!(scrubbed.len(), b"correct-horse".len());
        assert!(scrubbed.iter().all(|byte| *byte == 0));
        assert_eq!(grants.tokens_held(), 0);
        assert!(grants.live(12811).is_none());
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
///
/// `Clone` on purpose: `Grants::live` hands the proxy a copy whose token lives
/// as long as the connection handler that took it. Expiry zeroes only the
/// registry's copy — established connections are never guillotined.
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

    /// The grant for `port` if it has not expired.
    ///
    /// The returned `Grant` is a clone; see the type docs for what expiry
    /// does and does not zero. Expired entries are scrubbed here as a
    /// backstop — the proxy's reaper normally beats this path.
    pub fn live(&self, port: u16) -> Option<Grant> {
        let mut ports = self.ports.lock();
        let expired = ports
            .get(&port)
            .is_some_and(|grant| grant.deadline <= Instant::now());
        if expired {
            drop(scrub(&mut ports, port));
            return None;
        }
        ports.get(&port).cloned()
    }

    /// Drop `port`'s grant now, zeroing the registry's token copy in place.
    pub fn expire(&self, port: u16) {
        drop(self.take_scrubbed(port));
    }

    /// Test seam: expire `port` and hand back the scrubbed buffer, so a test
    /// can prove the registry's bytes were zeroed rather than merely dropped.
    #[doc(hidden)]
    pub fn take_scrubbed(&self, port: u16) -> Option<Vec<u8>> {
        scrub(&mut self.ports.lock(), port)
    }

    /// How many grants still hold a token. Test seam for the zeroing contract.
    #[doc(hidden)]
    pub fn tokens_held(&self) -> usize {
        self.ports.lock().len()
    }
}

/// Remove `port`'s grant, overwriting its token before the buffer is released,
/// so an expired grant leaves no copy in the allocator's free memory.
/// Hand-rolled: `zeroize` would be a dependency for six lines. Returns the
/// scrubbed buffer so the test seam can observe it.
fn scrub(ports: &mut HashMap<u16, Grant>, port: u16) -> Option<Vec<u8>> {
    let mut grant = ports.remove(&port)?;
    for byte in &mut grant.token {
        *byte = 0;
    }
    Some(std::mem::take(&mut grant.token))
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --lib browser::grant`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
jj describe -m "feat(browser): add the grant registry

Keys on the loopback port a grant owns, carries the session every connection
must match, and zeroes its own token copy on expiry. live() hands out clones
that last as long as their connection, by design." && jj new
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
- Consumes: `grant::Grants`, `grant::Grant`, `peer::pid_for_connection`, `peer::session_for_pid`, `Config` (accepted at the `spawn` boundary; see below).
- Produces: `browser::proxy::spawn(&Config, Grants, SocketAddr) -> Result<u16, ProxyError>` returning the bound port; `browser::proxy::reap_at(grants: Grants, port: u16, deadline: Instant)` — the deadline-driven shutdown; the test seam `browser::proxy::spawn_with_listener(grants: Grants, listener: TcpListener, upstream: SocketAddr, resolver: Resolver)` where `pub type Resolver = Arc<dyn Fn(SocketAddrV4, SocketAddrV4) -> Option<String> + Send + Sync>`.

**Shutdown design.** A grant's listener must close at the deadline, not linger
bound forever answering `REFUSED UNGRANTED`. The accept loop only observes
state between accepts, so expiry alone would leave it parked in `accept()`
holding a dead port. `reap_at` spawns one thread per grant (bounded by live
grants) that sleeps to the deadline, calls `Grants::expire(port)` — zeroing the
registry's token — and then wakes the blocked accept loop with a loopback
self-connect. The loop answers any connection on a grantless port with
`REFUSED UNGRANTED` and returns, dropping the listener. The request handler
(Task 6) inserts the grant before the port is ever revealed to a caller, so
the only connection that can land on a never-granted port is a guess at an
ephemeral port inside a microseconds-wide window — and it fails closed, taking
the unused listener with it.

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
    forward::browser::proxy::spawn_with_listener(grants, listener, upstream, resolver(resolved));
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

    // When/Then: refused as ungranted rather than as a session mismatch. The
    // refusal also retires the listener; that is asserted separately below.
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

#[test]
fn expiry_closes_the_listener_and_zeroes_the_token_without_a_client_connection() {
    // Given: a served grant with an imminent deadline and its reaper armed.
    let grants = forward::browser::grant::Grants::new();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    forward::browser::proxy::spawn_with_listener(
        grants.clone(),
        listener,
        spawn_relay_upstream("unused"),
        resolver(Some("session-a")),
    );
    let deadline = Instant::now() + Duration::from_millis(50);
    grants.insert(
        port,
        forward::browser::grant::Grant {
            session: "session-a".to_owned(),
            token: b"correct-horse".to_vec(),
            deadline,
        },
    );
    forward::browser::proxy::reap_at(grants.clone(), port, deadline);

    // When: the deadline passes with no client ever connecting. The margin is
    // generous: the reaper needs only a sleep, a lock, and a self-connect.
    std::thread::sleep(Duration::from_secs(3));

    // Then: the reaper alone closed the listener — this first-ever client
    // connect is refused outright instead of being accepted and answered —
    // and the registry holds no token. If the shutdown depended on a client
    // connection, this connect would succeed and fail the assertion.
    assert!(
        TcpStream::connect(("127.0.0.1", port)).is_err(),
        "listener still accepting after expiry"
    );
    assert_eq!(grants.tokens_held(), 0);
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --test browser_grant`
Expected: FAIL — `could not find 'proxy' in 'browser'`.

- [ ] **Step 3: Write `src/browser/proxy.rs`**

`bridge::limit` is `pub(crate)` (`src/bridge.rs:3`) and `src/browser.rs` already
imports `ConnectionLimit` from it, so `browser::proxy` can too — no visibility
change is needed. The `port` binding is computed **once, before the accept
loop**, as a `u16` (`Copy`), exactly as `bridge::listener::accept_loop` does
with `listener_port` — a `Result` consumed inside the loop would move on the
first iteration and not compile.

```rust
use crate::browser::grant::{Grant, Grants};
use crate::bridge::limit::ConnectionLimit;
use crate::config::Config;
use crate::pipe::bidirectional;
use crate::refusal::refuse;
use std::io::Write as _;
use std::net::{SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

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
///
/// `_cfg` is accepted to keep the reviewed Task-6 interface — the request
/// handler holds a `&Config` at the callsite — but the proxy currently derives
/// everything from its other arguments: the upstream is already resolved and
/// the listener is always loopback.
pub fn spawn(_cfg: &Config, grants: Grants, upstream: SocketAddr) -> Result<u16, ProxyError> {
    let listener =
        TcpListener::bind("127.0.0.1:0").map_err(|source| ProxyError::Bind { source })?;
    let port = listener
        .local_addr()
        .map_err(|source| ProxyError::Bind { source })?
        .port();
    spawn_with_listener(
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

/// Expire `port` at `deadline`, then wake its accept loop so the listener
/// closes. The wake is a loopback self-connect: the loop only observes state
/// between accepts, so expiry alone would leave it parked holding a dead port.
/// One thread per live grant, bounded by how many grants exist at once.
pub fn reap_at(grants: Grants, port: u16, deadline: Instant) {
    drop(thread::spawn(move || {
        thread::sleep(deadline.saturating_duration_since(Instant::now()));
        grants.expire(port);
        drop(TcpStream::connect(("127.0.0.1", port)));
    }));
}

/// Test seam: serve a grant port on a listener the caller already bound.
#[doc(hidden)]
pub fn spawn_with_listener(
    grants: Grants,
    listener: TcpListener,
    upstream: SocketAddr,
    resolver: Resolver,
) {
    drop(thread::spawn(move || {
        accept_loop(grants, listener, upstream, resolver);
    }));
}

fn accept_loop(grants: Grants, listener: TcpListener, upstream: SocketAddr, resolver: Resolver) {
    let limit = ConnectionLimit::standard();
    let Ok(port) = listener.local_addr().map(|address| address.port()) else {
        eprintln!("forward: grant proxy could not determine its listener port");
        return;
    };
    for connection in listener.incoming() {
        match connection {
            Ok(mut stream) => {
                let Some(grant) = grants.live(port) else {
                    // Expired — the reaper's wake-up lands here — or never
                    // granted. Either way the only honest answer is a refusal,
                    // and returning drops the listener so the port closes.
                    eprintln!("forward: grant proxy on {port} retired");
                    refuse(&mut stream, UNGRANTED_REFUSAL);
                    return;
                };
                let Some(permit) = limit.acquire() else {
                    refuse(&mut stream, BUSY_REFUSAL);
                    continue;
                };
                let resolver = resolver.clone();
                drop(thread::spawn(move || {
                    let _permit = permit;
                    handle(grant, port, upstream, &resolver, stream);
                }));
            }
            Err(error) => {
                eprintln!("forward: grant proxy accept failed: {error}");
                thread::sleep(ACCEPT_ERROR_BACKOFF);
            }
        }
    }
}

fn handle(grant: Grant, port: u16, upstream: SocketAddr, resolver: &Resolver, mut stream: TcpStream) {
    let (Ok(SocketAddr::V4(peer)), Ok(SocketAddr::V4(local))) =
        (stream.peer_addr(), stream.local_addr())
    else {
        refuse(&mut stream, SESSION_REFUSAL);
        return;
    };
    if resolver(peer, local).as_deref() != Some(grant.session.as_str()) {
        eprintln!(
            "forward: grant proxy refused a connection outside session {}",
            grant.session
        );
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

The `grants.live(port)` read sits in the accept loop, not the handler thread:
the loop must observe a dead grant to know to exit, and the handler receives
the resulting `Grant` clone, which is the copy that legitimately outlives the
deadline for an established connection (Task 3's contract).

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --test browser_grant`
Expected: PASS, all six.

- [ ] **Step 5: Check the line budget, format, and lint**

Run: `./scripts/check-source-line-limit.sh && cargo fmt --all -- --check && cargo clippy --all-targets -- -D warnings`
Expected: all pass.

- [ ] **Step 6: Commit**

```bash
jj describe -m "feat(browser): serve one loopback port per grant

Every accepted connection is attributed to a session before the token is
prefixed, and a per-grant reaper closes the listener at the deadline, so an
expired grant leaves neither port nor registry token behind." && jj new
```

---

### Task 6: `forward browser grant` and the request socket

**Files:**
- Create: `src/browser/request.rs`, `tests/browser_request.rs`
- Modify: `Cargo.toml` (add `nix`), `src/browser.rs` (add `pub mod request;`), `src/browser/grant.rs` (add `live_for_session`), `src/main.rs` (add the `Grant` verb; start the request socket in the `Serve` arm — the arming socket is started there too, in `main.rs`, not in `src/serve.rs`, which is the file server)
- Test: `tests/browser_request.rs`, `src/browser/grant.rs` inline tests

**Interfaces:**
- Consumes: `grant::Grants`, `grant::Grant`, `proxy::spawn`, `proxy::reap_at`, `peer::session_for_pid`, `Config::{peer_ip, relay_port}`, `bridge::arm_socket_path` (the public re-export in `src/bridge.rs:9` — `bridge::arming` itself is a private module).
- Produces: `browser::request::socket_path() -> PathBuf`, `browser::request::serve(grants, cfg, path)`, the test seam `browser::request::serve_with_resolver(grants, cfg, path, resolver)` with `pub type SessionResolver = Arc<dyn Fn(u32) -> Option<String> + Send + Sync>`, `browser::request::parse(&[u8]) -> Option<(u64, Vec<u8>)>`, `browser::request::parse_ttl(&str) -> Option<u64>`, `browser::request::request(&Path, u64, &[u8]) -> Option<u16>`, `browser::request::status(&Path) -> GrantStatus` with `pub enum GrantStatus { Unreachable, None, Live { port: u16, remaining_secs: u64 } }` and the seam `parse_status(&str) -> GrantStatus`, `Grants::live_for_session(&str) -> Option<(u16, Grant)>`, and the CLI verb `forward browser grant --ttl 30m`.

The wire format has two verbs, both credentialed by `SO_PEERCRED` before the
line is even read:

| Request | Reply |
| --- | --- |
| `GRANT <ttl_secs> <token>\n` | `<port>\n` or `REFUSED\n` |
| `STATUS\n` | `LIVE <port> <remaining_secs>\n` or `NONE\n` |

The caller's pid comes from `SO_PEERCRED` on the unix socket — exact, no
`/proc/net/tcp` lookup — and is resolved with `peer::session_for_pid`. `STATUS`
exists because `forward doctor` runs in a separate process from `forward
serve`, which owns the registry: the doctor row (Task 7) can only learn about
grants over this socket.

**The `nix` dependency, verified.** Add to `Cargo.toml` `[dependencies]`,
between `mime_guess` and `parking_lot` (the list is alphabetical):

```toml
nix = { version = "0.31", features = ["socket"] }
```

Confirmed against nix 0.31.3 (the resolving version): `nix::sys::socket::getsockopt`
is `pub fn getsockopt<F: AsFd, O: GetSockOpt>(fd: &F, opt: O) -> Result<O::Val>`,
`std::os::unix::net::UnixStream` implements `AsFd`, `sockopt::PeerCredentials`
(feature `socket`) yields `UnixCredentials`, and `UnixCredentials::pid` returns
`libc::pid_t` (an `i32`, hence the `u32::try_from`). This is not a guess; do not
substitute `libc` or hand-rolled FFI.

- [ ] **Step 1: Write the failing tests**

Create `tests/browser_request.rs`. The wire parsers are plain functions tested
directly, and the credential path is exercised over a real unix socket with an
injected resolver that records the pid `SO_PEERCRED` produced:

```rust
use forward::browser::request::{
    GrantStatus, parse, parse_status, parse_ttl, request, serve_with_resolver, status,
};
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

fn await_socket(path: &std::path::Path) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while UnixStream::connect(path).is_err() {
        assert!(Instant::now() < deadline, "request socket never came up");
        thread::sleep(Duration::from_millis(10));
    }
}

fn spawn_server(
    grants: forward::browser::grant::Grants,
    path: std::path::PathBuf,
    resolver: forward::browser::request::SessionResolver,
) {
    let mut cfg = forward::config::Config::default_values_for_test();
    cfg.peer = "127.0.0.1".to_owned();
    thread::spawn(move || serve_with_resolver(grants, cfg, path, resolver));
}

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
    assert_eq!(parse(b"STATUS"), None);
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
fn a_zero_or_overlong_ttl_is_rejected() {
    assert_eq!(parse(b"GRANT 0 correct-horse"), None);
    // 12h is the cap; one second past it is refused.
    assert_eq!(parse(b"GRANT 43201 correct-horse"), None);
}

#[test]
fn ttl_shorthand_parses() {
    assert_eq!(parse_ttl("45s"), Some(45));
    assert_eq!(parse_ttl("30m"), Some(1_800));
    assert_eq!(parse_ttl("2h"), Some(7_200));
    assert_eq!(parse_ttl("0m"), None);
    assert_eq!(parse_ttl("5x"), None);
    assert_eq!(parse_ttl("m"), None);
    assert_eq!(parse_ttl(""), None);
}

#[test]
fn a_status_reply_parses() {
    assert_eq!(parse_status("NONE"), GrantStatus::None);
    assert_eq!(
        parse_status("LIVE 12811 1799"),
        GrantStatus::Live { port: 12_811, remaining_secs: 1_799 }
    );
    // A malformed reply must not invent a grant.
    assert_eq!(parse_status("LIVE nonsense"), GrantStatus::Unreachable);
}

#[test]
fn the_request_socket_attributes_the_caller_through_peer_credentials() {
    // Given: a server whose session resolver records every pid SO_PEERCRED
    // hands it. Sender is not Sync, so it rides inside a Mutex.
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("grant.sock");
    let grants = forward::browser::grant::Grants::new();
    let (sender, receiver) = mpsc::channel();
    let sender = Mutex::new(sender);
    let resolver: forward::browser::request::SessionResolver = Arc::new(move |pid| {
        sender.lock().unwrap().send(pid).unwrap();
        Some("session-a".to_owned())
    });
    spawn_server(grants.clone(), path.clone(), resolver);
    await_socket(&path);

    // When: this very process asks for a grant over the socket.
    let port = request(&path, 60, b"correct-horse").expect("the grant request must succeed");

    // Then: the grant names the resolved session, and every credentialed
    // connection (the readiness probes included) resolved to this process.
    assert_eq!(grants.live(port).unwrap().session, "session-a");
    let pids: Vec<u32> = receiver.try_iter().collect();
    assert!(!pids.is_empty());
    assert!(pids.iter().all(|pid| *pid == std::process::id()));
}

#[test]
fn status_reports_the_calling_sessions_grant_over_the_socket() {
    // Given: no socket at all — status is Unreachable, not a panic.
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("grant.sock");
    assert_eq!(status(&path), GrantStatus::Unreachable);

    // And: a server resolving this caller to session-a.
    let grants = forward::browser::grant::Grants::new();
    let resolver: forward::browser::request::SessionResolver =
        Arc::new(|_pid| Some("session-a".to_owned()));
    spawn_server(grants, path.clone(), resolver);
    await_socket(&path);

    // When/Then: before any grant, the daemon answers NONE; after one, it
    // answers LIVE with that grant's port and a remaining TTL inside the ask.
    assert_eq!(status(&path), GrantStatus::None);
    let port = request(&path, 60, b"correct-horse").expect("the grant request must succeed");
    match status(&path) {
        GrantStatus::Live { port: live_port, remaining_secs } => {
            assert_eq!(live_port, port);
            assert!(remaining_secs <= 60);
        }
        other => panic!("expected a live grant, got {other:?}"),
    }
}
```

Add a `live_for_session` test to `src/browser/grant.rs`'s inline test module:

```rust
    #[test]
    fn a_sessions_own_live_grant_is_found_by_session() {
        let grants = Grants::new();
        grants.insert(12811, grant("session-a", Duration::from_secs(60)));
        grants.insert(12812, grant("session-b", Duration::from_secs(60)));
        let (port, found) = grants.live_for_session("session-b").unwrap();
        assert_eq!((port, found.session.as_str()), (12812, "session-b"));
        assert!(grants.live_for_session("session-c").is_none());
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --test browser_request`
Expected: FAIL — `could not find 'request' in 'browser'`.

- [ ] **Step 3: Write `src/browser/request.rs`, add the dependency, extend the registry**

Add the `nix` line to `Cargo.toml` as specified above. Add to `src/browser/grant.rs`'s `impl Grants`:

```rust
    /// The port and grant `session` holds right now, if any. Used by the
    /// STATUS verb; a session with several grants gets an arbitrary live one.
    pub fn live_for_session(&self, session: &str) -> Option<(u16, Grant)> {
        let now = Instant::now();
        self.ports
            .lock()
            .iter()
            .find(|(_, grant)| grant.session == session && grant.deadline > now)
            .map(|(port, grant)| (*port, grant.clone()))
    }
```

Then `src/browser/request.rs`:

```rust
use crate::browser::grant::{Grant, Grants};
use crate::browser::peer::session_for_pid;
use crate::browser::proxy;
use crate::config::Config;
use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// `GRANT 43200 ` plus a 43-character token is well under this.
const MAX_REQUEST_LINE: u64 = 128;
const LONGEST_TTL: Duration = Duration::from_secs(12 * 60 * 60);
/// A request is one short line, and the serve loop is serial, so a stalled
/// client must not be able to pin it.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
/// The daemon answers immediately — the YubiKey touch already happened inside
/// `secrets`, before this process even started.
const REPLY_TIMEOUT: Duration = Duration::from_secs(10);

/// Resolve a pid to its omp session. Injectable so a test can observe the pid
/// `SO_PEERCRED` produced without running inside a real session.
pub type SessionResolver = Arc<dyn Fn(u32) -> Option<String> + Send + Sync>;

/// Whether the calling session holds a live grant, as the daemon reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrantStatus {
    /// No daemon answered the request socket's protocol.
    Unreachable,
    /// The daemon answered: the calling session holds no live grant.
    None,
    /// The calling session's grant: its loopback port and remaining seconds.
    Live { port: u16, remaining_secs: u64 },
}

/// Where `forward browser grant` reaches the local daemon.
///
/// A unix socket, never a TCP port: `SO_PEERCRED` on it yields the caller's pid
/// exactly, which is what binds a grant to the session that asked for it.
pub fn socket_path() -> PathBuf {
    crate::bridge::arm_socket_path().with_file_name("forward-browser-grant.sock")
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

/// `45s`, `30m`, or `2h` to seconds, for the CLI's `--ttl`.
pub fn parse_ttl(value: &str) -> Option<u64> {
    if !value.is_ascii() || value.len() < 2 {
        return None;
    }
    let (number, unit) = value.split_at(value.len() - 1);
    let multiplier = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3_600,
        _ => return None,
    };
    number
        .parse::<u64>()
        .ok()?
        .checked_mul(multiplier)
        .filter(|ttl| *ttl > 0)
}

/// Serve grant requests for the life of the process.
///
/// Serial on purpose: a grant is a rare, human-gated event, every request is
/// one line under a read deadline, and serialising removes any window where
/// two requests race the registry.
pub fn serve(grants: Grants, cfg: Config, path: PathBuf) {
    serve_with_resolver(grants, cfg, path, Arc::new(session_for_pid));
}

/// Test seam: serve with an injected pid-to-session resolver.
#[doc(hidden)]
pub fn serve_with_resolver(grants: Grants, cfg: Config, path: PathBuf, resolver: SessionResolver) {
    let _ = std::fs::remove_file(&path);
    let Ok(listener) = UnixListener::bind(&path) else {
        eprintln!("forward: could not bind grant socket {}", path.display());
        return;
    };
    // Restrict the socket rather than inheriting the process umask.
    if let Err(error) = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)) {
        eprintln!(
            "forward: could not restrict grant socket {}: {error}",
            path.display()
        );
        let _ = std::fs::remove_file(&path);
        return;
    }
    // No peer configured means no laptop to relay to: STATUS still answers,
    // GRANT refuses, nothing panics.
    let upstream = cfg
        .peer_ip()
        .ok()
        .flatten()
        .map(|ip| SocketAddr::new(ip, cfg.relay_port));
    for stream in listener.incoming().flatten() {
        handle(&grants, &cfg, upstream, &resolver, stream);
    }
}

fn handle(
    grants: &Grants,
    cfg: &Config,
    upstream: Option<SocketAddr>,
    resolver: &SessionResolver,
    mut stream: UnixStream,
) {
    if stream.set_read_timeout(Some(REQUEST_TIMEOUT)).is_err()
        || stream.set_write_timeout(Some(REQUEST_TIMEOUT)).is_err()
    {
        return;
    }
    let Some(pid) = peer_pid(&stream) else {
        let _ = stream.write_all(b"REFUSED\n");
        return;
    };
    let session = resolver(pid);
    let mut line = Vec::new();
    let mut reader = BufReader::new(match stream.try_clone() {
        Ok(clone) => clone,
        Err(_) => return,
    })
    .take(MAX_REQUEST_LINE);
    if reader.read_until(b'\n', &mut line).is_err() {
        let _ = stream.write_all(b"REFUSED\n");
        return;
    }
    while line.last().is_some_and(|byte| *byte == b'\n' || *byte == b'\r') {
        drop(line.pop());
    }
    if line == b"STATUS" {
        answer_status(grants, session, stream);
        return;
    }
    let Some((ttl, token)) = parse(&line) else {
        let _ = stream.write_all(b"REFUSED\n");
        return;
    };
    let Some(session) = session else {
        eprintln!("forward: grant refused: pid {pid} is not inside an omp session");
        let _ = stream.write_all(b"REFUSED\n");
        return;
    };
    let Some(upstream) = upstream else {
        eprintln!("forward: grant refused: no peer configured to relay to");
        let _ = stream.write_all(b"REFUSED\n");
        return;
    };
    let Ok(port) = proxy::spawn(cfg, grants.clone(), upstream) else {
        let _ = stream.write_all(b"REFUSED\n");
        return;
    };
    let deadline = Instant::now() + Duration::from_secs(ttl);
    grants.insert(
        port,
        Grant {
            session: session.clone(),
            token,
            deadline,
        },
    );
    proxy::reap_at(grants.clone(), port, deadline);
    eprintln!(
        "forward: granted browser access to session {session} on 127.0.0.1:{port} for {ttl}s"
    );
    let _ = writeln!(stream, "{port}");
}

fn answer_status(grants: &Grants, session: Option<String>, mut stream: UnixStream) {
    // A caller outside any session holds no grant by definition.
    let reply = session
        .and_then(|session| grants.live_for_session(&session))
        .map(|(port, grant)| {
            let remaining = grant
                .deadline
                .saturating_duration_since(Instant::now())
                .as_secs();
            format!("LIVE {port} {remaining}\n")
        })
        .unwrap_or_else(|| "NONE\n".to_owned());
    let _ = stream.write_all(reply.as_bytes());
}

/// The caller's pid from `SO_PEERCRED` — exact, with no lookup and no race.
fn peer_pid(stream: &UnixStream) -> Option<u32> {
    let credentials =
        nix::sys::socket::getsockopt(stream, nix::sys::socket::sockopt::PeerCredentials).ok()?;
    u32::try_from(credentials.pid()).ok()
}

/// Ask the local daemon for a grant. Returns the bound loopback port.
pub fn request(path: &Path, ttl_secs: u64, token: &[u8]) -> Option<u16> {
    let mut stream = UnixStream::connect(path).ok()?;
    stream.set_read_timeout(Some(REPLY_TIMEOUT)).ok()?;
    stream.write_all(b"GRANT ").ok()?;
    stream.write_all(ttl_secs.to_string().as_bytes()).ok()?;
    stream.write_all(b" ").ok()?;
    stream.write_all(token).ok()?;
    stream.write_all(b"\n").ok()?;
    let mut reply = String::new();
    BufReader::new(stream).read_line(&mut reply).ok()?;
    reply.trim_end().parse().ok()
}

/// Ask the local daemon whether the calling session holds a live grant.
pub fn status(path: &Path) -> GrantStatus {
    let Ok(mut stream) = UnixStream::connect(path) else {
        return GrantStatus::Unreachable;
    };
    if stream.set_read_timeout(Some(REPLY_TIMEOUT)).is_err()
        || stream.write_all(b"STATUS\n").is_err()
    {
        return GrantStatus::Unreachable;
    }
    let mut reply = String::new();
    if BufReader::new(stream).read_line(&mut reply).is_err() {
        return GrantStatus::Unreachable;
    }
    parse_status(reply.trim_end())
}

/// Test seam: a malformed reply reports as unreachable rather than inventing
/// a grant.
#[doc(hidden)]
pub fn parse_status(reply: &str) -> GrantStatus {
    if reply == "NONE" {
        return GrantStatus::None;
    }
    let Some(rest) = reply.strip_prefix("LIVE ") else {
        return GrantStatus::Unreachable;
    };
    let parsed = rest
        .split_once(' ')
        .and_then(|(port, secs)| Some((port.parse().ok()?, secs.parse().ok()?)));
    match parsed {
        Some((port, remaining_secs)) => GrantStatus::Live { port, remaining_secs },
        None => GrantStatus::Unreachable,
    }
}
```

Add `pub mod request;` to `src/browser.rs`. Note the imports: `Read as _` is
required — `.take(…)` on the `BufReader` is `Read::take` — alongside
`BufRead as _` for `read_until`/`read_line`.

- [ ] **Step 4: Wire the CLI verb**

Add to `BrowserCommand` in `src/main.rs`:

```rust
    /// Request browser access for this session (devbox side)
    Grant {
        /// Grant lifetime, for example 45s, 30m, or 2h
        #[arg(long, default_value = "30m")]
        ttl: String,
    },
```

No `--config`: the verb needs only the socket path, which is derived from the
runtime directory, never from configuration. Dispatch, inside the existing
`Command::Browser` match:

```rust
            BrowserCommand::Grant { ttl } => {
                let Ok(token) = std::env::var("FORWARD_BROWSER_GRANT") else {
                    eprintln!("forward: FORWARD_BROWSER_GRANT is not set; run");
                    eprintln!("  secrets FORWARD_BROWSER_GRANT -- forward browser grant --ttl 30m");
                    std::process::exit(1);
                };
                let Some(ttl_secs) = forward::browser::request::parse_ttl(&ttl) else {
                    eprintln!("forward: invalid --ttl {ttl:?}; use 45s, 30m, or 2h");
                    std::process::exit(1);
                };
                let socket = forward::browser::request::socket_path();
                let Some(port) =
                    forward::browser::request::request(&socket, ttl_secs, token.as_bytes())
                else {
                    eprintln!(
                        "forward: grant refused, or no forward serve at {}",
                        socket.display()
                    );
                    std::process::exit(1);
                };
                let mut stdout = std::io::stdout().lock();
                writeln!(stdout, "http://127.0.0.1:{port}")?;
                Ok(())
            }
```

- [ ] **Step 5: Start the request socket from the `Serve` arm of `src/main.rs`**

The devbox orchestration lives in `main.rs`'s `Command::Serve` arm — that is
where `bridge::serve_arming` already starts the arming socket (`src/serve.rs`
is the file server and stays untouched). Directly after the
`bridge::serve_arming(...)` line, add:

```rust
            let grants = forward::browser::grant::Grants::new();
            let grant_cfg = cfg.clone();
            drop(std::thread::spawn(move || {
                forward::browser::request::serve(
                    grants,
                    grant_cfg,
                    forward::browser::request::socket_path(),
                );
            }));
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `cargo test --test browser_request && cargo test --lib browser::grant && cargo build`
Expected: PASS, clean build.

- [ ] **Step 7: Verify the missing-token error by hand**

Run: `env -u FORWARD_BROWSER_GRANT cargo run --quiet -- browser grant --ttl 30m; echo "exit: $?"`
Expected: the two-line error naming the `secrets` command, `exit: 1`, and no
socket connection attempted.

- [ ] **Step 8: Check the line budget, format, and lint**

Run: `./scripts/check-source-line-limit.sh && cargo fmt --all -- --check && cargo clippy --all-targets -- -D warnings`
Expected: all pass. If `src/browser/request.rs` exceeds 250 lines, move the
client half (`request`, `status`, `parse_status`, `GrantStatus`,
`REPLY_TIMEOUT`) into `src/browser/request/client.rs` re-exported from
`request.rs`, keeping every public path spelled `browser::request::…`.

- [ ] **Step 9: Commit**

```bash
jj describe -m "feat(browser): request a grant over a peer-credentialed socket

SO_PEERCRED binds the grant to the calling session exactly, so there is no
--session argument to forge. STATUS reports the caller's live grant, which is
the only way a separate process (doctor) can see the registry. Adds nix 0.31
(socket) for the credential read; UnixStream::peer_cred is still unstable." && jj new
```

---

### Task 7: Doctor reports the gate

**Files:**
- Create: `src/doctor/grant.rs`
- Modify: `src/doctor/browser.rs` (new evidence variant + its `report_probe` arm), `src/doctor.rs` (add `mod grant;` and the row call), `src/doctor/browser_tests.rs` (classification tests), `tests/doctor/browser.rs` (CLI-level rows)
- Test: `src/doctor/browser_tests.rs`, `src/doctor/grant.rs` inline tests, `tests/doctor/browser.rs`

**Interfaces:**
- Consumes: `RelayEvidence`, `classify` (both `pub(super)` in `doctor::browser` — visible to sibling test modules inside `doctor`, which is where the unit tests live), `browser::request::{socket_path, status, GrantStatus}` from Task 6.
- Produces: `RelayEvidence::TokenRequired`; a relay row reading `browser relay: locked at <host>:<port> (no grant)`; an informational devbox row `browser grant: …` that never decides overall health, like the pcsc row.

`forward doctor` is a separate process from `forward serve`, which owns the
`Grants` registry, so the grant row is answered over the request socket's
`STATUS` verb — the server resolves the doctor process's own ancestry through
the same `SO_PEERCRED` path a `GRANT` uses. Doctor holds no secret and needs no
touch for any of this.

- [ ] **Step 1: Write the failing tests**

**1a.** In `src/doctor/browser_tests.rs`, the classification test:

```rust
#[test]
fn a_token_refusal_is_proof_the_laptop_channel_is_alive() {
    // Given: the laptop's refusal for a connection presenting no token.
    let body = b"REFUSED TOKEN\n";

    // When/Then: it is a distinct, healthy-but-locked state, not an error.
    assert_eq!(
        super::browser::classify(body),
        Ok(super::browser::RelayEvidence::TokenRequired)
    );
}
```

(That file currently imports only `evaluate_with`; extend the `use` line as
needed.)

**1b.** In `tests/doctor/browser.rs`, the CLI-level rows, following the
existing `run_doctor_with` + fake-relay pattern in that file:

```rust
fn spawn_token_refusal_relay() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = [0_u8; 512];
        let _ = stream.read(&mut request);
        stream.write_all(b"REFUSED TOKEN\n").unwrap();
    });
    port
}

#[test]
fn a_token_refusal_reports_locked_but_healthy() {
    let output = run_doctor_with(
        healthy_ports(),
        &format!("relay_port = {}\n", spawn_token_refusal_relay()),
    );
    let text = super::output_text(&output);

    // A refusal proves the listener is alive, peer-authorised, and enforcing,
    // so the verdict stays healthy and the row says locked.
    assert!(output.status.success(), "got {text}");
    assert!(text.contains("browser relay: locked"), "got {text}");
    assert!(text.contains("(no grant)"), "got {text}");
    // The devbox grant row always renders; its state depends on whether a
    // forward serve runs on this machine, so only its presence is asserted.
    assert!(text.contains("browser grant:"), "got {text}");
}
```

**1c.** The grant row rendering is a pure function with inline tests, written in
Step 3 below alongside its implementation (`src/doctor/grant.rs`).

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --lib doctor && cargo test --test doctor`
Expected: FAIL — no variant `TokenRequired`.

- [ ] **Step 3: Add the variant, its classification, and the grant row**

In `src/doctor/browser.rs`, add `TokenRequired` to `RelayEvidence`, and in
`classify`, beside the other refusal arms (position among them is free — the
generic arm is an equality test on `REFUSED\n` and the others match different
prefixes, so nothing can shadow this):

```rust
    if body.starts_with(b"REFUSED TOKEN") {
        return Ok(RelayEvidence::TokenRequired);
    }
```

`report_probe` matches on `RelayEvidence`, so the new variant needs an arm
there or the match no longer compiles. It renders as alive-and-enforcing,
healthy, because doctor holds no token and must not need one to report health:

```rust
        Ok(RelayEvidence::TokenRequired) => (
            true,
            format!("browser relay: locked at {host}:{port} (no grant)"),
        ),
```

Create `src/doctor/grant.rs` — the devbox row, answered over the `STATUS` verb:

```rust
use crate::browser::request::{self, GrantStatus};

/// Report whether the invoking session holds a live grant. Informational,
/// like the pcsc row: holding no grant is not ill health.
pub(super) fn report() {
    super::print_line(line(request::status(&request::socket_path())));
}

fn line(status: GrantStatus) -> String {
    match status {
        GrantStatus::Unreachable => {
            "browser grant: info — no request socket answered; forward serve is not running here (grants are devbox-side)"
                .to_owned()
        }
        GrantStatus::None => {
            "browser grant: none for this session — secrets FORWARD_BROWSER_GRANT -- forward browser grant --ttl 30m"
                .to_owned()
        }
        GrantStatus::Live { port, remaining_secs } => format!(
            "browser grant: live for this session at http://127.0.0.1:{port} ({remaining_secs}s left)"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_grant_state_renders_its_own_row() {
        assert!(line(GrantStatus::Unreachable).contains("forward serve is not running"));
        let none = line(GrantStatus::None);
        assert!(none.contains("none for this session"));
        assert!(none.contains("forward browser grant --ttl 30m"));
        let live = line(GrantStatus::Live { port: 12_811, remaining_secs: 900 });
        assert!(live.contains("http://127.0.0.1:12811"));
        assert!(live.contains("900s left"));
    }
}
```

In `src/doctor.rs`: add `mod grant;` beside `mod browser;`, and call
`grant::report();` next to `report_pcsc();` in `run` — deliberately outside the
`url && preview && bridge && relay` conjunction.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --lib doctor && cargo test --test doctor && ./scripts/check-source-line-limit.sh`
Expected: PASS. If `src/doctor/browser.rs` crosses 250 lines, move
`RelayEvidence` and `classify` into `src/doctor/browser/evidence.rs` as part of
this task.

- [ ] **Step 5: Commit**

```bash
jj describe -m "feat(doctor): distinguish a locked relay from a broken one

A token refusal proves the listener is alive, peer-authorised and enforcing,
so doctor reports health without holding any secret. The grant row asks the
serve process over the request socket's STATUS verb, because the registry
lives in that process, not in doctor's." && jj new
```

---

### Task 8: Consumer cutover

Every current caller dials the laptop directly. Leaving one in place would reopen the bypass Task 1 closed, so this task removes all of them, and replaces the three dotfiles tests that assert the removed contract.

**Files (in `~/.dotfiles`, a separate repo — commit there; this is the second PR):**
- Delete: `omp/config-serve.yml`
- Modify: `.bashrc:89-98` (remove the `BROWSER_RELAY_URL` sourcing block)
- Modify: `installers/forward.sh` (delete `install_relay_shell_environment` at :12-31, the `omp_config_source` assignments at :36 and :41, the overlay block at :60-67; add stale-artifact cleanup; update the printed guidance at :99)
- Modify: `shims/omp:16-22` (remove the `browser-relay.yml` → `PI_CONFIG_FILES` block)
- Modify: `scripts/browser-capture` (make `--relay-url` required, drop the environment default, update the usage comment)
- Modify: `scripts/tests/test_browser_capture.py`, `scripts/tests/test_forward_environment.py`, `shims/tests/test_omp_relay_config.py` (replace the tests that assert the removed contract)

`forward/config.toml` is deliberately **not** touched: the token lives at the
derived path `~/.config/forward/relay.token` (Task 1's `relay_token_path`), so
no committed configuration carries a machine-local path and there is no tilde
for `Config` to expand.

- [ ] **Step 1: Confirm the current wiring before changing it**

Run: `grep -rn 'BROWSER_RELAY_URL\|relayUrl\|browser-relay\.\(yml\|conf\)' ~/.dotfiles --include='*' | grep -v '\.git/'`
Expected: exactly the files listed above — `.bashrc`, `installers/forward.sh`, `omp/config-serve.yml`, `shims/omp`, `scripts/browser-capture`, and the three test files. If there are more, cut them all.

- [ ] **Step 2: Remove the OMP overlay and the installer's environment plumbing**

Delete `omp/config-serve.yml`. In `installers/forward.sh`:

- Delete the whole `install_relay_shell_environment()` function (lines 12-31).
- Delete `omp_config_source=config-serve.yml` from the `serve` case and the empty `omp_config_source=` from the `daemon` case.
- Delete the `if [ -n "$omp_config_source" ]; then … fi` block (lines 60-67), which symlinked `browser-relay.yml` and wrote the environment file.
- In their place, after the config symlink line, add cleanup so a rerun removes what earlier installs wrote — a dangling `browser-relay.yml` symlink would otherwise be a silent config-load failure later:

```bash
# Earlier releases wrote an ambient relay endpoint; remove it wherever it
# still exists so no machine keeps a bypass-era configuration.
config_home="${XDG_CONFIG_HOME:-$HOME/.config}"
rm -f "${config_home}/omp/browser-relay.yml" "${config_home}/environment.d/browser-relay.conf"
```

- Replace the final guidance line (line 99) with:

```bash
    echo "Browser access is per-session: secrets FORWARD_BROWSER_GRANT -- forward browser grant --ttl 30m, then pass the printed URL as app.cdp_url. browser.relay intentionally stays false."
```

In `shims/omp`, delete the relay overlay block (lines 16-22): the
`_relay_config=…` assignment and its `if [ -f … ] … fi`, plus the comment above
them. The shim must not re-enter a stray `browser-relay.yml` into
`PI_CONFIG_FILES`.

- [ ] **Step 3: Remove the shell export**

Delete the `.bashrc` block at lines 89-98: the three comment lines, the
`_browser_relay_environment=` assignment, the `if [ -r … ] … fi` that sourced
it and exported `BROWSER_RELAY_URL`, and the trailing `unset`. Machines get
clean on the next installer run (Step 2's `rm -f`); the laptop never had these
files, because only the `serve` role wrote them.

- [ ] **Step 4: Require `--relay-url` in `browser-capture`**

In `scripts/browser-capture`, change the argument definition to:

```python
    argument_parser.add_argument(
        "--relay-url",
        required=True,
        metavar="URL",
    )
```

`CaptureArgumentParser.error` already exits `1` (it overrides argparse's
default of 2 so invocation failures do not collide with relay failures), so an
unconfigured capture now fails with exit 1 and argparse's
`the following arguments are required: --relay-url` before any secrets or
relay I/O. Update the guard in `run()` — it still catches an explicit empty
string — to stop naming the dead variable:

```python
    if not args.relay_url:
        raise CaptureError(
            1,
            "browser-capture: relay URL is required; pass --relay-url "
            "http://127.0.0.1:<grant port> from the session holding the grant",
        )
```

And in the `─── How to run ───` header comment, change
`[--relay-url URL]` to `--relay-url URL` (it is no longer optional).

- [ ] **Step 5: Replace the three tests that assert the removed contract**

**5a.** `scripts/tests/test_browser_capture.py` — replace
`test_relay_environment_supplies_the_relay_url` and
`test_missing_relay_url_stops_before_secrets_or_relay_access` with:

```python
    def test_environment_variable_no_longer_supplies_the_relay_url(self) -> None:
        """BROWSER_RELAY_URL is retired; only an explicit --relay-url reaches a relay."""
        secrets_called = self.stub_dir / "secrets-called"
        write_stub(
            self.stub_dir,
            "secrets",
            f"from pathlib import Path\nPath({str(secrets_called)!r}).touch()",
        )

        result = self.run_capture(
            extra_env={"BROWSER_RELAY_URL": "http://127.0.0.1:10"}
        )

        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn(
            "the following arguments are required: --relay-url", result.stderr
        )
        self.assertFalse(secrets_called.exists())

    def test_missing_relay_url_stops_before_secrets_or_relay_access(self) -> None:
        """Argparse rejects an unconfigured capture before any secrets or relay I/O."""
        secrets_called = self.stub_dir / "secrets-called"
        write_stub(
            self.stub_dir,
            "secrets",
            f"from pathlib import Path\nPath({str(secrets_called)!r}).touch()",
        )

        result = self.run_capture()

        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn(
            "the following arguments are required: --relay-url", result.stderr
        )
        self.assertFalse(secrets_called.exists())
```

`test_relay_flag_supplies_the_relay_url` stays: the flag path is the surviving
contract. The `run_capture` helper's `env.pop("BROWSER_RELAY_URL", None)` also
stays — it keeps a deployed machine's stray environment from leaking into the
suite.

**5b.** `scripts/tests/test_forward_environment.py` — in `setUp`, delete the
`(self.dotfiles / "omp").mkdir()` line, the `omp/config-serve.yml` fixture
write, and the module-level `RELAY_URL` constant. Replace both tests with:

```python
    def test_serve_role_installs_no_relay_environment_or_overlay(self) -> None:
        """The ambient relay endpoint is gone; grants supply per-session endpoints."""
        install = self.install("serve")

        self.assertEqual(install.returncode, 0, install.stderr)
        self.assertFalse(
            (self.config_home / "environment.d" / "browser-relay.conf").exists()
        )
        self.assertFalse((self.config_home / "omp" / "browser-relay.yml").exists())
        shell = self.shell_relay_url()
        self.assertEqual(shell.returncode, 0, shell.stderr)
        self.assertEqual(shell.stdout, "")

    def test_serve_role_removes_a_stale_relay_environment_and_overlay(self) -> None:
        """Reinstalling cleans up what bypass-era installs wrote."""
        environment_dir = self.config_home / "environment.d"
        environment_dir.mkdir(parents=True)
        (environment_dir / "browser-relay.conf").write_text(
            "BROWSER_RELAY_URL=http://stale.test\n", encoding="utf-8"
        )
        omp_dir = self.config_home / "omp"
        omp_dir.mkdir(parents=True)
        (omp_dir / "browser-relay.yml").symlink_to(self.dotfiles / "gone.yml")

        install = self.install("serve")

        self.assertEqual(install.returncode, 0, install.stderr)
        self.assertFalse((environment_dir / "browser-relay.conf").exists())
        self.assertFalse((omp_dir / "browser-relay.yml").is_symlink())

    def test_daemon_role_installs_no_relay_environment(self) -> None:
        """The laptop role never had the ambient endpoint and must not gain one."""
        install = self.install("daemon")

        self.assertEqual(install.returncode, 0, install.stderr)
        self.assertFalse(
            (self.config_home / "environment.d" / "browser-relay.conf").exists()
        )
        self.assertFalse((self.config_home / "omp" / "browser-relay.yml").exists())
```

Update the module docstring to match ("the forward roles install no ambient
relay environment").

**5c.** `shims/tests/test_omp_relay_config.py` — keep
`test_omits_relay_url_without_the_devbox_overlay` (it still holds: no overlay,
no config), and replace
`test_loads_the_devbox_overlay_without_discarding_caller_overlays` with:

```python
    def test_ignores_a_stray_relay_overlay(self) -> None:
        """The overlay contract is retired; a leftover file must not re-enter config."""
        relay_config = self.config_home / "omp" / "browser-relay.yml"
        relay_config.write_text(
            "browser:\n  relayUrl: http://100.100.92.97:12803\n", encoding="utf-8"
        )

        result = self.run_shim({"PI_CONFIG_FILES": "/tmp/caller.yml"})

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "/tmp/caller.yml\n")
```

- [ ] **Step 6: Run the dotfiles tests and verify no caller remains**

Run:
```bash
cd ~/.dotfiles \
  && python3 scripts/tests/test_browser_capture.py \
  && python3 scripts/tests/test_forward_environment.py \
  && python3 shims/tests/test_omp_relay_config.py \
  && grep -rn 'BROWSER_RELAY_URL\|relayUrl' ~/.dotfiles --include='*' | grep -v '\.git/'
```
Expected: all three suites pass, and the remaining matches are only the three
test files (asserting the contract is dead) and the installer's cleanup
comment and `rm -f` line. Nothing consumes the variable or the overlay.

- [ ] **Step 7: Commit (in the dotfiles repo)**

```bash
cd ~/.dotfiles && jj describe -m "refactor(browser): route browser access through grants

The static relay URL let any process reach the laptop; agents now pass a
per-grant endpoint, so the ambient path is removed rather than deprecated,
and the installer cleans bypass-era files off deployed machines." && jj new
```

---

### Task 9: End-to-end verification against the live browser

No new code. This is the spec's verification list, run for real, because three
bugs have shipped in this subsystem behind tests that asserted shapes the real
system never produces. The order matters: `init-token` ships in the new binary,
so the binary is installed everywhere first, while the running daemons — which
hold their old code in memory — keep serving until the deliberate restart.

- [ ] **Step 1: Install the new binary on both machines, restarting nothing**

```bash
mise install forward@latest && ssh sami@sami mise install forward@latest
```

Expected: the new version lands on disk on both machines. The laptop daemon and
devbox serve keep running their old in-memory code, so browser access is
uninterrupted and the relay is still (for now) open.

- [ ] **Step 2: Provision the token while the OLD laptop daemon still serves**

Run, as Sami, not as an agent:

```bash
ssh sami@sami forward browser init-token | secrets edit-human FORWARD_BROWSER_GRANT
```

Expected: `created …/secrets.human.d/…`. `init-token` runs the newly installed
binary on the laptop, writes `~/.config/forward/relay.token` at `0600` (a file
the old daemon never reads, so nothing changes yet), and the value flows
straight into the devbox's human-tier secret without touching any agent
context. The value appears nowhere else.

- [ ] **Step 3: Deploy the dotfiles cutover and restart both roles together**

```bash
~/.dotfiles/installers/forward.sh serve \
  && ssh sami@sami '~/.dotfiles/installers/forward.sh daemon' \
  && ssh sami@sami systemctl --user restart forward-daemon.service \
  && systemctl --user restart forward-serve.service
```

Expected: the installers relink units, remove the bypass-era
`browser-relay.yml` and `environment.d/browser-relay.conf` from the devbox, and
the two restarts land within seconds of each other — this is the cutover
moment. From here the laptop refuses untokened connections and the devbox
serves grants.

**Rollback, stated in full:** the gate lives in the laptop binary, not in
configuration — no committed config key enables it (`relay_token_file` is an
optional override nothing sets). To roll back: reinstall the previous forward
release on the laptop and restart its daemon
(`ssh sami@sami mise install forward@<last-good> && ssh sami@sami systemctl --user restart forward-daemon.service`),
then revert the dotfiles cutover commit in `~/.dotfiles` and rerun both
installers to restore the ambient relay URL. The token file and the
`FORWARD_BROWSER_GRANT` secret may stay: the old binary reads neither.

- [ ] **Step 4: Confirm the bypass is closed**

Run: `curl -s --max-time 8 http://100.100.92.97:12803/json/version`
Expected: `REFUSED TOKEN`. A JSON body here means Task 1 did not deploy, and nothing below is meaningful.

- [ ] **Step 5: Take a grant**

Run: `secrets FORWARD_BROWSER_GRANT -- forward browser grant --ttl 30m`
Expected: the YubiKey blinks; after the touch, `http://127.0.0.1:<port>`.

- [ ] **Step 6: Confirm the endpoint works and keeps Puppeteer local**

Run: `curl -s http://127.0.0.1:<port>/json/version`
Expected: a `webSocketDebuggerUrl` of `ws://127.0.0.1:<port>/cdp` — the grant port, not `100.100.92.97:12803`.

- [ ] **Step 7: Drive a real tab**

Use the omp `browser` tool with `app.cdp_url` set to the grant endpoint; observe a live laptop tab.
Expected: the tab responds. This is the acceptance criterion; a passing test suite is not.

- [ ] **Step 8: Confirm another session is refused**

From a *different* omp session, connect to the first session's port:
Run: `curl -s http://127.0.0.1:<first session's port>/json/version`
Expected: `REFUSED SESSION`.

- [ ] **Step 9: Confirm expiry closes the port for new connections only**

Take a 1-minute grant, open a CDP connection, wait past expiry, then confirm
the established connection still works while a new
`curl http://127.0.0.1:<port>/json/version` fails to connect at all — the
reaper closed the listener, so the refusal is now the kernel's
`Connection refused`, not a protocol string.

- [ ] **Step 10: Confirm doctor reads correctly in both states**

Run: `forward doctor` on the devbox, without and then with a grant.
Expected without: `browser relay: locked at 100.100.92.97:12803 (no grant)` and
`browser grant: none for this session — secrets FORWARD_BROWSER_GRANT -- forward browser grant --ttl 30m`.
Expected with: the relay row still reads `locked` (doctor probes untokened, by
design) and the grant row reads `browser grant: live for this session at
http://127.0.0.1:<port> (<n>s left)`.

- [ ] **Step 11: Record the results in the spec**

Append the observed outputs to the spec's Verification section, replacing the predicted ones. Commit.

---

## Self-Review

**Spec coverage.** Security model → Tasks 1 (token gate, fail closed), 4
(attribution), 5 (session refusal), 6 (`SO_PEERCRED`, no `--session` to
forge). Architecture and the devbox-local endpoint → Tasks 5, 9. Grant
lifecycle, including "on expiry the listener closes" → Tasks 3 (registry
zeroing), 5 (`reap_at` closes the listener), 6 (deadline set at grant time);
the lifecycle's Clone-copy narrowing is stated in Task 3 and the spec wording
is the coordinator's to amend. Wire protocol → Tasks 1, 5 (`RELAY <token>`),
6 (`GRANT`/`STATUS`). Token provisioning → Task 2, Task 9 Steps 1-2. Peer
attribution → Task 4. Configuration and health checks → Tasks 1
(`relay_token_path`), 6 (`STATUS`), 7 (locked row, grant row). Consumer
cutover → Task 8. Module layout → Tasks 1-6 (`token`, `init`, `grant`, `peer`,
`proxy`, `request` under `browser/`). Failure modes → Tasks 1 (missing token
file refuses), 3/5 (expiry), 4 (unresolvable pid refused), 5 (ungranted, wrong
session), 6 (no peer configured refuses grants). Verification → Task 9. No
section is unimplemented.

**Placeholder scan.** Every code step carries real code. The three decisions
earlier drafts deferred are now resolved by inspection, not left to the
implementer: `bridge::limit` is already `pub(crate)` (`src/bridge.rs:3`) so
Task 5 imports it with no visibility change; the `SO_PEERCRED` path is pinned
to `nix` 0.31.3's verified `getsockopt<F: AsFd, O: GetSockOpt>` +
`sockopt::PeerCredentials` + `UnixCredentials::pid`, added in Task 6; and
tilde expansion is moot because no committed file carries a token path —
`Config::relay_token_path()` derives it per machine. The only conditional
instructions left are line-cap escape hatches, each naming the exact move.

**Type consistency.** `Grant { session: String, token: Vec<u8>, deadline:
Instant }` is constructed identically in Tasks 3, 5, and 6. `Grants::live`,
`insert`, `expire`, `take_scrubbed`, `tokens_held` are produced in Task 3;
`live_for_session` is added in Task 6; consumers are Tasks 5 and 6 with those
exact signatures. `proxy::spawn(&Config, Grants, SocketAddr) ->
Result<u16, ProxyError>` is produced in Task 5 and called in Task 6, which
holds a `&Config` at the callsite; `spawn_with_listener(Grants, TcpListener,
SocketAddr, Resolver)` and `reap_at(Grants, u16, Instant)` are produced in
Task 5 and consumed by Task 5's tests and Task 6. `session_for_pid(u32) ->
Option<String>` is produced in Task 4 and consumed by Task 5's default
resolver and Task 6's default `SessionResolver`. `Config::relay_token_path()
-> Option<PathBuf>` is produced in Task 1 and consumed by Task 1's gate and
Task 2's dispatch. The request wire — `GRANT <ttl> <token>\n` →
`<port>\n`/`REFUSED\n`, `STATUS\n` → `LIVE <port> <secs>\n`/`NONE\n` — is
produced and consumed inside Task 6, and `GrantStatus` is consumed by Task 7's
row. `write_token(&Path) -> Result<String, InitError>` is produced in Task 2
and exercised in Task 9 Step 2. Refusal strings are the same byte-strings
across Tasks 1, 5, and 7: `REFUSED TOKEN`, `REFUSED UNGRANTED`,
`REFUSED SESSION`, plus the inherited `REFUSED`, `REFUSED PEER`,
`REFUSED BUSY`.

---

## Hardening ledger

Shortcuts taken to get the feature working, logged the moment they are taken.
Every entry is paid off before the PR opens.

_(empty)_
