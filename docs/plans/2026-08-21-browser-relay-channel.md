# Browser relay channel — implementation plan

Spec (binding authority): `docs/design/2026-08-21-browser-relay-channel.md` (jj `ookrvtmy`)
Date: 2026-08-21

Three phases across four repositories. Phase 1 is the transport in `forward`; Phase 2 is
group-scope enforcement plus the remote-endpoint fix in the `oh-my-pi` fork; Phase 3 is the
capture script, the `secretsd` write path, and all deployment wiring.

## Global Constraints

These bind every task. A task that violates one is defective even if it works.

### Cross-repo

- **Version control is jj, not git.** `jj describe -m` then `jj new`; `jj st`, `jj diff --git`,
  `jj log`. Read-only `git log`/`git diff` is fine. Never run a mutating git command.
- **One PR per repo**, never a stack of per-phase PRs. `.dotfiles` and `.secrets` ship by
  direct commit, not PR.
- Do not run project-wide formatters, linters, or full test suites — targeted verification only.
- **Never print, log, or paste a real secret value**, anywhere, for any reason.

### Locked decisions — do not reopen

Everyday Chrome scoped to the `omp` tab group. Group membership is the only gate: no arming,
no TTL, no idle eviction (offered twice, declined twice). The relay runs on the laptop and
`forward` fronts it. Capture is a plumbed primitive whose value never enters model context.
No new `omp` CLI subcommand (user-vetoed). Agents may create new tabs that start in the group,
but must never be able to pull an existing tab into it.

### Fixed values

| Thing | Value |
|---|---|
| Laptop `sami` tailnet address | `100.100.92.97` (runs `forward daemon`) |
| Devbox `sami-agents` tailnet address | `100.113.243.90` (runs `forward serve`) |
| New browser relay channel port | `12803` |
| Relay upstream on the laptop | `127.0.0.1:9224` |
| Devbox omp setting | `browser.relayUrl = "http://100.100.92.97:12803"` |
| `browser.relay` | stays `false`; agents opt in per call with `app.relay: true` |
| Existing ports (do not disturb) | 12799 PC/SC, 12800 URL, 12801 callback bridge, 12802 files |

### `forward` (`/home/ubuntu/forward/default`)

- Hard **250-line limit per Rust source file**, enforced by `scripts/check-source-line-limit.sh`.
- **No new dependencies.** Errors use `thiserror`.
- The new module is **`src/browser.rs`** — `relay` is already taken by `src/callback/relay.rs`.
- Not knives-managed. Work on a bookmark, not directly on `main`.

### `oh-my-pi` (`/home/ubuntu/oh-my-pi/default`)

- **Knives-managed and shared with other agents.** You MUST `knives start <branch>` and work in
  the workspace knives gives you. Never edit the checkout directly; never use jj or git there.
- Follow its `AGENTS.md`: Bun over Node, no `any`, `#private` fields, namespace imports for
  `node:*`, centralized `logger` (never `console.*`) in shared code, never `mock.module()`,
  contract-level tests only, changelog entry under `## [Unreleased]`.

### `.dotfiles` (`/home/ubuntu/.dotfiles`)

- Placement map: `scripts/` for utilities invoked by name (no extension), `installers/<tool>.sh`
  for setup, config dirs symlinked into place by installers.
- **No committed absolute paths** — use `$HOME` / `$DOTFILES_DIR`.
- Consolidate into 1–2 described commits.

### `secretsd` (`/home/ubuntu/secretsd/default`)

- jj-colocated clone of `github.com/sjawhar/secretsd`, `main` tracked. Not knives-managed.
- Releases are plain semver via mise, so a change reaches this machine only after a release.
- `.secrets` is a **separate git repo**.

## Ordering hazards

Two sequencing constraints are load-bearing. Violating either breaks a running system.

1. **`relay_port` in the deployed TOMLs must not land before the new `forward` binary is
   installed on both machines.** `Config` is `#[serde(deny_unknown_fields)]`, and
   `~/.dotfiles/forward/config.toml` and `config-serve.toml` are live symlinks into
   `~/.config/forward/`. An old binary reading a config with `relay_port` fails to parse and
   crash-loops on the next restart — including an unattended reboot.
2. **`run_doctor`'s test config template must gain `relay_port = 0`** in the same change that
   introduces the field, or the entire pre-existing doctor suite breaks under the new default.

## Hardening ledger

Empty at the start. Implementers: take the shortcut if it gets the feature working, but log it
here the moment you take it, and return your ledger entries with your report. An unpaid entry
blocks the PR — the coordinator empties this ledger before opening one. Hiding a shortcut
instead of logging it breaks the contract.

| Task | Shortcut taken | Why | What paying it off requires |
|---|---|---|---|

## Tasks

## Task 1 — Config: `relay_port` field defaulting to 12803, `0` disables

**Files:** `src/config.rs`, `src/config/tests.rs`
**Depends on:** nothing. **Parallel-safe with:** Task 2.

In `src/config.rs`, inside `pub struct Config` immediately after the `bridge_port` field (follow the existing serde default pattern exactly, e.g. `#[serde(default = "default_bridge_port")]`):

```rust
/// Port for the browser relay channel on the laptop's tailnet address.
#[serde(default = "default_relay_port")]
pub relay_port: u16,
```

- Add `relay_port: default_relay_port(),` to `Config::default_values()` (after the `bridge_port: default_bridge_port(),` line).
- Beside `fn default_bridge_port()` add:

```rust
pub(crate) fn default_relay_port() -> u16 {
    12_803
}
```

`pub(crate)` is a deliberate deviation from the other private `default_*` fns: `src/doctor/browser.rs` (Task 7) probes the peer's channel at this well-known port when the local `relay_port` is `0`, and a duplicated literal would drift. No `validate()` change: `0` is a legal value meaning "channel disabled, bind nothing" — the daemon (Task 4) and doctor (Task 7) interpret it; config does not.

In `src/config/tests.rs`:
- Extend `parses_transport_fields` (or add a sibling `parses_relay_port` in the same style) to assert: a TOML with `relay_port = 12811` parses to `cfg.relay_port == 12811`; `relay_port = 0` parses to `0`; a TOML without the field yields `12_803`.
- Add `relay_port = 12803` to the TOML in `parses_full_config` so the full-config fixture keeps covering every field.
- `test_constructor_matches_file_defaults` and `missing_file_gives_defaults` must stay green (both paths flow through `default_relay_port()`); if either enumerates fields explicitly, extend it with `relay_port`.

Note `Config` carries `#[serde(deny_unknown_fields)]` (`src/config.rs:4`): the dotfiles config edits (owned by the Phase 3 section) must not be deployed before the forward release containing this field, or the current daemon/serve fails to parse its config on restart.

**Verify:** `cargo test --lib config` — new assertions pass; `unknown_field_errors` and `config_with_retired_ssh_fields_is_refused` still pass.

## Task 2 — `RELAY_TARGET_PORT` constant and `ConnectionLimit` visibility

**Files:** `src/callback.rs`, `src/bridge.rs`, `src/bridge/limit.rs`
**Depends on:** nothing. **Parallel-safe with:** Task 1.

In `src/callback.rs`, beside the existing port constants (`PCSC_PORT` 12_799, `CHANNEL_PORT` 12_800, `FILES_PORT` 12_802), exactly where the spec places it:

```rust
/// Laptop-loopback port where `omp browser-relay` listens; the browser
/// channel's constant upstream (the relay's own default).
pub const RELAY_TARGET_PORT: u16 = 9_224;
```

Do NOT add it to `STATIC_TUNNEL_PORTS` — that array gates callback-port leasing, which the spec's non-goals leave unchanged.

`src/browser.rs` (Task 3) is a sibling of `bridge`, so the bridge's connection cap must become crate-visible:
- `src/bridge.rs`: change `mod limit;` to `pub(crate) mod limit;`.
- `src/bridge/limit.rs`: change `pub(super)` to `pub(crate)` on exactly four items: `struct ConnectionLimit`, `struct ConnectionPermit`, `fn standard`, `fn acquire`. `MAX_CONCURRENT_CONNECTIONS` and `fn new` stay private.

**Verify:** `cargo build` succeeds and `cargo test --lib bridge` still passes (`connection_limit_refuses_work_above_its_cap`).

## Task 3 — New module `src/browser.rs`: the byte proxy

**Files:** `src/browser.rs` (new), `src/lib.rs`
**Depends on:** Tasks 1, 2. **Parallel-safe with:** nothing (both prerequisites feed it; everything later feeds off it).

Register the module in `src/lib.rs`: insert `pub mod browser;` between `pub mod bridge;` and `pub mod callback;` (list is alphabetical). The module is named `browser` because `relay` is already taken by `src/callback/relay.rs`.

`src/browser.rs` is the callback bridge minus the request line, the port policy, and the arming check: no HTTP parsing anywhere — the payload is an HTTP upgrade followed by a WebSocket stream, and forward has no business interpreting CDP. Model the accept loop on `src/bridge/listener.rs::accept_loop`/`handle` and the upstream hop on `src/callback/relay.rs::relay`. Contents:

```rust
use crate::bridge::limit::ConnectionLimit;
use crate::callback::RELAY_TARGET_PORT;
use crate::config::Config;
use crate::peer::authorized;
use crate::pipe::bidirectional;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

/// The maximum idle read or blocked-write interval for a proxied CDP session.
/// The relay sends websocket keepalives every 30s, so this only reaps dead peers.
const PIPE_IDLE_TIMEOUT: Duration = Duration::from_secs(15 * 60);
/// Waiting after a failed accept avoids a tight EMFILE error loop.
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(50);
const GENERIC_REFUSAL: &[u8] = b"REFUSED\n";
const PEER_REFUSAL: &[u8] = b"REFUSED PEER\n";
const BUSY_REFUSAL: &[u8] = b"REFUSED BUSY\n";

#[derive(Debug, thiserror::Error)]
pub enum BrowserError {
    #[error("forward: failed to bind browser relay channel on {address}: {source}")]
    Bind {
        address: String,
        #[source]
        source: std::io::Error,
    },
}
```

(`PIPE_IDLE_TIMEOUT` is deliberately a third private copy — `src/bridge/listener.rs` and `src/callback.rs` each already keep their own; likewise replicate `configure_pipe_timeouts` from `src/callback/relay.rs` as a private fn setting read+write timeouts on both streams.)

Public API, mirrored on `bridge::serve` / `bridge::spawn_with_listener`:

- `pub fn spawn(cfg: &Config) -> Result<(), BrowserError>` — if `cfg.relay_port == 0`: `eprintln!("forward: browser relay channel disabled (relay_port = 0)")` and return `Ok(())`. Otherwise `cfg.validate()` then `cfg.listen_ip()` (map both errors into `BrowserError::Bind` with `address: format!("{}:{}", cfg.listen, cfg.relay_port)` and `std::io::Error::other(source)`, exactly as `bridge::serve` maps them), `TcpListener::bind((ip, cfg.relay_port))` (map to `Bind { address: format!("{ip}:{}", cfg.relay_port), source }`), `eprintln!("forward: browser relay channel on {ip}:{}", cfg.relay_port)`, then `spawn_with_listener(cfg.clone(), listener, SocketAddr::from(([127, 0, 0, 1], RELAY_TARGET_PORT)))`. Binding happens on the caller's thread so a bind failure is fatal to the daemon (Task 4); only the accept loop moves to a thread.
- `#[doc(hidden)] pub fn spawn_with_listener(cfg: Config, listener: TcpListener, upstream: SocketAddr)` — test seam and production path: `drop(thread::spawn(move || accept_loop(cfg, listener, upstream)))`. The `upstream` parameter exists so tests can stand a stub in for the relay; production passes `127.0.0.1:RELAY_TARGET_PORT`.
- `fn accept_loop(cfg: Config, listener: TcpListener, upstream: SocketAddr)` — clone of `bridge::listener::accept_loop` without `Armed`/listener-port: per connection acquire `ConnectionLimit::standard()` permit (held across the handler thread via `let _permit = permit;`), refuse with `BUSY_REFUSAL` + `eprintln!("forward: browser relay refused connection: concurrency limit reached")` when exhausted; on accept error `eprintln!("forward: browser relay accept failed: {error}")` + `thread::sleep(ACCEPT_ERROR_BACKOFF)`. A per-connection error kills only that connection: the loop `continue`s.
- `fn handle(cfg: &Config, upstream: SocketAddr, mut stream: TcpStream)` — `stream.peer_addr()`; on error refuse `GENERIC_REFUSAL` and return; else delegate to `handle_from(cfg, upstream, remote.ip(), stream)`.
- `#[doc(hidden)] pub fn handle_from(cfg: &Config, upstream: SocketAddr, remote: IpAddr, mut stream: TcpStream)` — the per-connection path with the remote address supplied by the caller. This seam exists because an integration test cannot originate a connection from a foreign address — the doctrine already written down in `tests/daemon/peer.rs`. Body, in order:
  1. `if !authorized(cfg, remote)` → `eprintln!("forward: browser relay refused peer {remote}")`, `refuse(&mut stream, PEER_REFUSAL)`, return. The authorization decision is made before any payload byte is read; `refuse` (copy the fn from `src/bridge/listener.rs` verbatim: nonblocking drain of pending bytes, then `write_all(response)`) drains only so the refusal survives TCP RST semantics — pending bytes never influence the decision and never reach the upstream.
  2. `TcpStream::connect(upstream)`; on error `eprintln!("forward: browser relay could not reach {upstream}: {error}")`, `refuse(&mut stream, GENERIC_REFUSAL)`, return — this is the "relay process down" wire signal Task 7's doctor reads.
  3. `configure_pipe_timeouts(&stream, &upstream_stream, PIPE_IDLE_TIMEOUT)`; on error log and return.
  4. `bidirectional(stream, upstream_stream)`; on error `eprintln!("forward: browser relay session for {remote} ended: {error}")` — errors carry the peer address, per the spec's failure-handling split.

No new dependencies (std + the existing `thiserror` only); errors use `thiserror`. Keep the file well under 250 lines — no `#[cfg(test)]` module here; behavior tests live in `tests/browser.rs` (Task 5).

**Verify:** `cargo build && bash scripts/check-source-line-limit.sh` (script must list no file, including the new one) and `cargo test --lib` (existing unit tests unaffected).

## Task 4 — Wire the channel into `forward daemon`, bind failure fatal

**Files:** `src/daemon.rs`
**Depends on:** Task 3. **Parallel-safe with:** Tasks 5, 7.

`src/daemon.rs` is 194 lines against the 250 cap, so it gains only the spawn and one error variant; all logic stays in `src/browser.rs`.

- Add to `enum DaemonError` (after the existing `Bind` variant):

```rust
#[error(transparent)]
BrowserRelay(#[from] forward::browser::BrowserError),
```

- In `run(cfg, config_path, port)`, immediately after `spawn_reaper(leases.clone());` and before the `for connection in listener.incoming()` loop, add the single line:

```rust
forward::browser::spawn(&cfg)?;
```

That ordering keeps the URL channel unchanged (it binds first, exactly as today) and makes a relay bind failure fatal at startup with the address in the error — `exit_with_error` in `main.rs` already prints `DaemonError` via `Display`, so the process dies with `forward: failed to bind browser relay channel on <ip>:<port>: <oserror>`. A daemon that silently ran without the channel would be the silent-fallback pattern. `relay_port = 0` is not a failure: `browser::spawn` returns `Ok` after logging `forward: browser relay channel disabled (relay_port = 0)`. No change to `src/main.rs` or the `Daemon` subcommand args.

**Verify (devbox smoke, no laptop needed — loopback is authorized by `peer::authorized`):**

```sh
cargo build
printf 'listen = "127.0.0.1"\nrelay_port = 12811\n' > /tmp/relay-smoke.toml
timeout 3 target/debug/forward daemon --port 12810 --config /tmp/relay-smoke.toml &
sleep 0.5
printf 'GET /json/version HTTP/1.0\r\n\r\n' | timeout 2 nc 127.0.0.1 12811
wait
```

stderr shows `forward: browser relay channel on 127.0.0.1:12811`; `nc` prints `REFUSED` (upstream `127.0.0.1:9224` absent on the devbox — the connection died without killing the daemon). Then rerun with `relay_port = 0` in the config and observe the `disabled (relay_port = 0)` stderr line and that `nc 127.0.0.1 12811` cannot connect.

## Task 5 — Channel behavior tests: `tests/browser.rs`

**Files:** `tests/browser.rs` (new)
**Depends on:** Task 3. **Parallel-safe with:** Tasks 4, 7.

New integration-test crate mirroring `tests/bridge.rs` style: Given/When/Then comments, helpers first (`fn cfg_with_peer(peer: &str)` via `forward::config::Config::default_values_for_test()`, `fn assert_refused(client, expected)` copied from `tests/bridge.rs`, a pong upstream mirroring `spawn_echo_upstream` — replies `pong` once it has received four bytes, so a reply proves the payload arrived intact). All listeners bind `127.0.0.1:0` (ephemeral); the channel comes up via the `forward::browser::spawn_with_listener(cfg, listener, upstream)` seam. Stay under 250 lines (`scripts/check-source-line-limit.sh` covers `tests/**`).

Four tests, matching the spec's Testing list:

1. `an_unauthorized_peer_is_refused_before_its_payload_is_read` — build a loopback socket pair (bind, connect, accept); write a payload from the client FIRST; bind a nonblocking upstream stub listener that never accepts; call `forward::browser::handle_from(&cfg_with_peer("100.64.0.9"), upstream_addr, "100.64.0.7".parse().unwrap(), server_side)`. Assert the client reads exactly `REFUSED PEER\n` then EOF, and the upstream listener's `accept()` returns `WouldBlock` — no upstream connection was ever attempted, so the payload could not have been read or forwarded. (Foreign source injection via the seam, per the `tests/daemon/peer.rs` doctrine; the address-equality logic itself is covered by `src/peer.rs` unit tests.)
2. `the_configured_peer_is_proxied_bidirectionally` — channel via `spawn_with_listener` with `cfg_with_peer("100.64.0.9")` and a pong upstream; loopback client (the always-authorized branch of `peer::authorized`, standing in for the peer) writes `ping`, reads `pong`.
3. `half_close_propagates_in_each_direction` — upstream stub: accept, `read_to_end`, then write `gone` and shutdown write. Client: write `data`, `shutdown(Shutdown::Write)`. Assert the upstream's `read_to_end` returned `data` (client→upstream EOF propagated) and the client's `read_to_string` returns `gone` then EOF (upstream could still send after the client's half-close, and its own EOF propagated back) — the property `src/pipe.rs` exists to preserve, asserted through the listener.
4. `an_absent_upstream_closes_the_connection_without_killing_the_accept_loop` — reserve an ephemeral port by bind-then-drop; spawn the channel with that dead upstream address; client 1 gets `REFUSED\n` then EOF. Rebind the same port with the pong stub; client 2 completes `ping`→`pong` — the accept loop survived.

**Verify:** `cargo test --test browser` — all four pass; `bash scripts/check-source-line-limit.sh` stays clean.

## Task 6 — Daemon-level tests: fatal bind, `relay_port = 0`, banner

**Files:** `tests/daemon.rs`, `tests/daemon/browser.rs` (new)
**Depends on:** Task 4 (and Task 5's seam conventions, but no shared files). **Parallel-safe with:** Tasks 7, 8.

Add `#[path = "daemon/browser.rs"] mod browser;` to `tests/daemon.rs` (alphabetical position, after `boundary`). New `tests/daemon/browser.rs` using the existing `daemon_support` helpers (`start`, `start_expecting_failure`, `test_port`, `connection_is_refused`, `Daemon::wait_for_log`):

1. `a_bind_failure_is_fatal_and_names_the_address` — `let port = test_port();`, hold `TcpListener::bind(("127.0.0.1", port)).unwrap()` alive as the squatter; then `start_expecting_failure(dir, &format!("relay_port = {port}\n"))`; assert the returned stderr contains `failed to bind browser relay channel on 127.0.0.1:` and the port string. This is the spec's "bind failure surfaces as a fatal daemon error naming the address".
2. `relay_port_zero_skips_the_spawn_and_logs_disabled` — `start(dir, "relay_port = 0\n")`; `daemon.wait_for_log("browser relay channel disabled (relay_port = 0)")`; then assert `TcpListener::bind(("127.0.0.1", 12_803)).is_ok()` — the default channel port was never bound (binds nothing) — and the URL channel port still accepts (`daemon_support::connect(port)`), proving the URL channel is unchanged.
3. `the_daemon_serves_the_channel_it_announces` — `let relay_port = test_port();` `start(dir, &format!("relay_port = {relay_port}\n"))`; `daemon.wait_for_log(&format!("browser relay channel on 127.0.0.1:{relay_port}"))`; connect to it and assert `REFUSED\n` + EOF (loopback authorized, upstream `127.0.0.1:9224` absent in the test environment) — the spawn is wired through the real binary, and a dead upstream kills only the connection: the daemon's URL port still accepts afterwards.

**Verify:** `cargo test --test daemon browser` — the three new tests pass; `cargo test --test daemon startup` still green.

## Task 7 — Doctor: browser relay row with role-split reporting

**Files:** `src/doctor.rs`, `src/doctor/browser.rs` (new)
**Depends on:** Tasks 1, 2 (compiles without Task 3; its wire conventions come from Task 3's refusals). **Parallel-safe with:** Tasks 4, 5.

`src/doctor.rs` is 212 lines, so the row lives in a child module. In `src/doctor.rs`: add `mod browser;` beside the existing `#[cfg(test)] mod tests;`, and in `run()` add `let relay = browser::report(cfg);` after the bridge report and before `report_pcsc();`, returning `url && preview && bridge && relay`. Child modules can use the parent's private `connect`, `print_line`, and `PROBE_TIMEOUT` via `super::`; no visibility changes in doctor.rs.

`src/doctor/browser.rs` — `pub(super) fn report(cfg: &Config) -> bool`, plus a pure `fn classify(body: &[u8]) -> Result<RelayEvidence, String>` over a module-local `enum RelayEvidence { PeerRefused, UpstreamDown, Busy, ExtensionDisconnected, Healthy }`:

- Probe = `super::connect(host, port)`, write `format!("GET /json/version HTTP/1.0\r\nHost: {}:{port}\r\nConnection: close\r\n\r\n", url_host(host))` (mirror `probe_file_preview`; `use crate::target::url_host;`), `read_to_end`, classify: body starting `REFUSED PEER` → `PeerRefused`; exactly `REFUSED\n` → `UpstreamDown`; starting `REFUSED BUSY` → `Busy`; an HTTP status line carrying ` 200` → `Healthy`; ` 503` → `ExtensionDisconnected`; anything else → `Err` with the bytes, like `probe_bridge`'s unexpected-response arm.
- Role split, exactly the spec's: **the devbox probes the channel end to end; the laptop probes the listener bind plus `127.0.0.1:9224` directly; a laptop cannot probe its own tailnet listener because the source address of that connection is the tailnet address, not loopback, and the peer check correctly refuses it — that refusal IS the bind evidence** (same rule `evidence_is_healthy` already applies to `BridgePeerRefused` at `host == cfg.listen`).
  - `cfg.relay_port == 0 && cfg.peer.is_empty()` → `print_line("browser relay: disabled (relay_port = 0)")`, return `true` (not a failure — mirrors the daemon).
  - `cfg.relay_port == 0`, peer set (devbox role): probe `(cfg.peer, crate::config::default_relay_port())` — the local `0` means "this machine binds nothing"; the channel's well-known port comes from the config default so it cannot drift.
  - `cfg.relay_port != 0` (laptop role): probe `(cfg.listen, cfg.relay_port)` first. `PeerRefused` from that self-vantage (only when `cfg.listen_ip()` is non-loopback) is positive bind evidence — continue to the second leg, `("127.0.0.1", RELAY_TARGET_PORT)`. An HTTP answer on the first leg (loopback-listen dev config, where the self-probe is authorized and proxied) is already end-to-end; report it and skip the second leg.
- Report lines (`print_line`), carrying the spec's messages verbatim; returns in parentheses:
  - connect error on the channel leg → `browser relay: FAIL — {host}:{port} ({error}); relay channel down — is forward daemon running?` (false)
  - `PeerRefused` from the peer vantage → `browser relay: FAIL — {host}:{port}: not the configured peer — check peer on the laptop` (false)
  - `UpstreamDown`, or connect error on `127.0.0.1:9224` → `browser relay: FAIL — relay process down — start omp-browser-relay (via {host}:{port})` (false)
  - `Busy` → `browser relay: FAIL — {host}:{port} at its connection limit` (false)
  - `ExtensionDisconnected` → `browser relay: relay up, extension not connected — check the badge (at {host}:{port})` (**true** — every forward-owned hop provably delivered an HTTP response; the missing piece is the human's browser state, informational like the PC/SC row)
  - `Healthy` → issue a second request `GET /json/list` the same way, count occurrences of the substring `"webSocketDebuggerUrl"` (one per target, no JSON parsing, no new deps) → `browser relay: healthy at {host}:{port} ({n} targets)` (true)
- `#[cfg(test)] mod tests` in-file: unit-test `classify` on exactly `b"REFUSED PEER\n"`, `b"REFUSED\n"`, `b"REFUSED BUSY\n"`, `b"HTTP/1.1 200 OK\r\n\r\n{}"`, `b"HTTP/1.1 503 Service Unavailable\r\n\r\n"`, and garbage → `Err`. Keep the file under 250 lines.

**Verify:** `cargo test --lib doctor` (new classify tests + existing `probe_targets_cover_both_roles_without_duplicates` etc. pass) and `bash scripts/check-source-line-limit.sh`.

## Task 8 — Doctor tests: keep the rig green, prove both roles

**Files:** `tests/doctor.rs`, `tests/doctor/browser.rs` (new)
**Depends on:** Task 7. **Parallel-safe with:** Tasks 4, 5, 6.

`tests/doctor.rs` must change or every existing doctor test breaks: `run_doctor` writes a config of only `bridge_port = {}`, so the new field would default to 12803 and put every run in laptop role against unbound ports. Change the template to `format!("bridge_port = {}\nrelay_port = 0\n", ports.bridge)` — peer stays empty, so the row prints `disabled` and stays healthy for the whole existing suite. Also add `#[path = "doctor/browser.rs"] mod browser;` at the top (file is 223 lines; these two edits keep it under 250 — new tests go in the new file).

New `tests/doctor/browser.rs`, reusing the crate-root helpers (`run_doctor`, `DoctorPorts`, `output_text`, and the stub spawners are crate-private, which makes them visible to a child module via `super::`). Define one local helper in the new file: `fn run_doctor_with(ports: super::DoctorPorts, relay_lines: &str) -> std::process::Output` — a copy of `run_doctor` whose config is `format!("bridge_port = {}\n{relay_lines}", ports.bridge)`; the root `run_doctor` stays single-purpose with its baked-in `relay_port = 0`. Tests:

1. `the_disabled_row_reports_and_never_fails` — healthy stubs for the three channels, `relay_port = 0`, no peer: exit 0 and output contains `browser relay: disabled (relay_port = 0)`.
2. `laptop_role_reports_relay_channel_down_when_nothing_is_bound` — healthy stubs, config `relay_port = <reserved-and-dropped ephemeral port>`: exit 1, output contains `browser relay: FAIL` and `relay channel down — is forward daemon running?`.
3. `loopback_listen_answers_end_to_end_on_the_listen_leg` — bind a stub HTTP listener on an ephemeral port answering `/json/version` with `HTTP/1.0 200 OK` and (second connection) `/json/list` with a one-target body containing one `"webSocketDebuggerUrl"`; config `relay_port = <that port>`: exit 0, output contains `browser relay: healthy` and `(1 targets)`.
4. `devbox_role_classifies_the_peer_channel_end_to_end` — ONE sequential test (fixed port, so phases must not run as parallel sibling tests): config `relay_port = 0`, `peer = "127.0.0.1"` (dedup keeps `probe_hosts` = `[127.0.0.1]`, so the other channel stubs are unaffected). Sequentially bind `127.0.0.1:12803` (the well-known default the devbox leg probes — this test owns that port, in the spirit of `daemon_support`'s fixed 20000+ range) with, in turn: (a) a 200+list stub → exit 0, `browser relay: healthy`; (b) a 503 stub → exit 0 AND output contains `relay up, extension not connected — check the badge` (the informational-503 decision is itself under test); (c) a stub replying `REFUSED PEER\n` (mirror `spawn_bridge_refusal`, bound to 12803) → exit 1, `not the configured peer — check peer on the laptop`; (d) a stub replying `REFUSED\n` → exit 1, `relay process down — start omp-browser-relay`. Join each stub thread before rebinding.

**Laptop-in-the-loop flag:** the laptop-role bind-evidence path (`REFUSED PEER` at own `listen:12803`, then the `127.0.0.1:9224` leg) requires a non-loopback listen address and cannot execute on the devbox. Devbox proxies: the `classify` unit tests (Task 7) cover the byte-level decisions, test 3 covers the listen-leg HTTP path, and phase (d) covers the upstream-down message. The real check happens post-deploy: `forward doctor` on the laptop with the daemon and relay running.

**Verify:** `cargo test --test doctor` — all pre-existing tests plus the four new ones pass.

## Task 9 — End-to-end devbox smoke, line-limit sweep, commit

**Files:** none new (verification + jj commit)
**Depends on:** Tasks 1–8. **Parallel-safe with:** nothing.

1. Full gate: `cargo test` and `bash scripts/check-source-line-limit.sh` (must print nothing and exit 0).
2. End-to-end transport smoke on the devbox alone — a stub relay on the REAL upstream port `9224` (free on the devbox; the genuine relay runs only on the laptop), the daemon's channel in front, HTTP passing through both hops:

```sh
python3 -c '
import http.server, json
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({"Browser": "stub", "webSocketDebuggerUrl": "ws://127.0.0.1:9224/cdp"}).encode()
        self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers()
        self.wfile.write(body)
http.server.HTTPServer(("127.0.0.1", 9224), H).serve_forever()
' & STUB=$!
printf 'listen = "127.0.0.1"\nrelay_port = 12811\n' > /tmp/relay-e2e.toml
target/debug/forward daemon --port 12810 --config /tmp/relay-e2e.toml & DAEMON=$!
sleep 0.5
curl -sS --max-time 3 http://127.0.0.1:12811/json/version
kill $STUB $DAEMON
```

Expected: the stub's JSON printed by curl — proving bind, loopback authorization, upstream connect to `127.0.0.1:9224`, pipe timeouts, and `pipe::bidirectional` carrying a full HTTP round trip. Also run `target/debug/forward doctor --config /tmp/relay-e2e.toml` while both are up and observe `browser relay: healthy at 127.0.0.1:12811 (1 targets)` (the three legacy channels will FAIL in this ad-hoc config — only the relay row is under observation; exit code 1 is expected here).

**Laptop-in-the-loop flag:** the true tailnet path — devbox → `100.100.92.97:12803` with the peer check accepting exactly `100.113.243.90` and refusing everything else — needs the laptop running the released binary with its Phase 3 config. Devbox proxy: this smoke (loopback vantage) plus Task 5's `handle_from` foreign-address refusal test. Post-deploy check from the devbox: `curl --max-time 3 http://100.100.92.97:12803/json/version`.

3. Commit with jj (no git mutation commands):

```sh
jj describe -m "forward: browser relay channel (devbox -> laptop byte proxy on 12803)

New src/browser.rs listener bound to listen:relay_port, peer-checked
fail-closed, proxying to 127.0.0.1:9224 via pipe::bidirectional.
relay_port config field (default 12803, 0 disables). Fatal bind at
daemon startup; per-connection errors kill only the connection.
Doctor grows a role-split browser relay row."
jj new
```

Then `jj st` shows an empty working copy and `jj diff --git -r @-` shows exactly the files named in Tasks 1–8.
## Task 10 — Claim the branch with knives and establish the green baseline

**Repo:** `/home/ubuntu/oh-my-pi/default` — **knives-managed and shared with other agents. Never edit that checkout directly, and never run jj or git mutations in it.** All Phase 2 work happens in the workspace knives creates.

**Steps**
1. From `/home/ubuntu/oh-my-pi/default`: run `knives status` and `knives notch` — confirm no other agent holds a branch touching `packages/browser-relay` or `packages/coding-agent/src/tools/browser/relay/`.
2. `knives start browser-relay-group-acl --why "Phase 2 of browser relay channel: enforce the omp tab group as the ACL"` — this claims the branch and prints the jj workspace path. **Every subsequent task in this phase runs inside that workspace path**; all `cd packages/...` below are relative to it. Commits inside the workspace use `jj describe -m "..."` / `jj new` only — never raw git, never `jj op restore`.
3. In the workspace root: `bun install` (fresh workspace has no `node_modules`).
4. Baseline: `cd packages/coding-agent && bun test test/tools/browser-relay-bridge.test.ts` — must be green before any edit.
5. Also baseline `cd packages/browser-relay && bun run check` (biome + tsgo, package-scoped).

**Verify:** `knives status` lists `browser-relay-group-acl` as claimed by this agent; step 4 prints `0 fail`; step 5 exits 0.
**Depends on:** nothing. Everything else depends on this task.

## Task 11 — Remote endpoint fix: derive `/json/version` URL from a validated `Host` header

Standalone, upstreamable fix — **commit it on its own** (`jj describe -m "fix(browser-relay): derive /json/version webSocketDebuggerUrl from the Host header"` then `jj new`) so it can be cherry-picked into an upstream PR later.

**File:** `packages/coding-agent/src/tools/browser/relay/server.ts` — inside `startRelayServer`, the `fetch` handler's `/json/version` branch (currently line 86):

```ts
// before
return Response.json(bridge.versionInfo(`ws://127.0.0.1:${opts.port}/cdp`));
// after — the spec snippet, hardened so a present-but-empty or malformed Host
// still yields the documented loopback fallback instead of an unusable URL
const rawHost = req.headers.get("host")?.trim();
const fallback = `127.0.0.1:${opts.port}`;
const host = rawHost && isWsAuthority(rawHost) ? rawHost : fallback;
return Response.json(bridge.versionInfo(`ws://${host}/cdp`));
```

with one module-level helper next to the other server.ts constants:

```ts
/** True when `raw` can serve as the authority of a `ws://` URL: no whitespace,
 *  slashes, userinfo, fragments, or control characters, and URL-parseable. */
function isWsAuthority(raw: string): boolean {
	if (/[\s/\\@#?]|[\x00-\x1f]/.test(raw)) return false;
	try {
		return new URL(`ws://${raw}`).host.length > 0;
	} catch {
		return false;
	}
}
```

`RelayBridge.versionInfo(wsUrl)` (bridge.ts:188) already takes the URL as a parameter — no bridge change. Reflecting the header is safe: it only changes which URL a client that already chose that host is told to dial; `/cdp` still rejects `Origin`-bearing upgrades (server.ts:64-66) and `forward`'s peer check stands in front.

**New test file:** `packages/coding-agent/test/tools/browser-relay-server.test.ts`
- Imports: `startRelayServer` from `@oh-my-pi/pi-coding-agent/tools/browser/relay/server`, `findFreeCdpPort` from `@oh-my-pi/pi-coding-agent/tools/browser/attach` (matches the import style of `browser-relay-bridge.test.ts`).
- Setup per test: `const port = await findFreeCdpPort(); const relay = startRelayServer({ port });` then connect a real `new WebSocket(\`ws://127.0.0.1:${port}/ext\`)` and on open send the hello JSON `{"t":"hello","userAgent":"test","browserVersion":"Chrome/151.0.0.0","tabs":[],"attachedTabIds":[]}` (same shape the bridge test's `connect()` helper uses). Poll `fetch(\`http://127.0.0.1:${port}/json/version\`)` until 200 with a bounded deadline. Tear down with `relay.stop()` and `ws.close()` in `finally`/`afterEach`.
- Use raw TCP via `Bun.connect` (not fetch) for the header-controlled requests, with a small `rawGet(port, requestBytes): Promise<string>` helper using `Promise.withResolvers()` (AGENTS.md rule), accumulating `data` and resolving on `close`:
  1. **Host reflection** (consumer contract: Puppeteer dials `webSocketDebuggerUrl` verbatim): send `GET /json/version HTTP/1.1\r\nHost: 100.100.92.97:12803\r\nConnection: close\r\n\r\n`; assert status line contains `200` and the JSON body's `webSocketDebuggerUrl` is exactly `ws://100.100.92.97:12803/cdp`.
  2. **Loopback fallback when Host absent**: send `GET /json/version HTTP/1.0\r\n\r\n` (HTTP/1.0 = no Host, connection closes by default); assert `webSocketDebuggerUrl` is exactly `ws://127.0.0.1:${port}/cdp`.
  3. **Loopback fallback when Host is empty**: `GET /json/version HTTP/1.1\r\nHost: \r\nConnection: close\r\n\r\n` → `ws://127.0.0.1:${port}/cdp`.
  4. **Loopback fallback when Host is malformed** (failure mode: an unusable `webSocketDebuggerUrl` bricks every remote client): `Host: bad/host@evil` → `ws://127.0.0.1:${port}/cdp`.
  5. **503 before the extension handshakes** (consumer contract: `probeRelayServer` in relay/daemon.ts treats 503 as "server present, extension pending"): plain `fetch` before opening the `/ext` socket returns status 503.
- Body parsing: split on `\r\n\r\n`; if the response headers declare `Transfer-Encoding: chunked`, strip the chunk framing before `JSON.parse`; otherwise parse the remainder directly.

**Verify:** `cd packages/coding-agent && bun test test/tools/browser-relay-server.test.ts` → all pass. Fully devbox-verifiable (no browser needed — the test fakes the extension over the real `/ext` websocket).
**Depends on:** 10. **Parallel-safe with:** 12, 15.

## Task 12 — Extension becomes the authoritative ACL (`protocol.ts` + `background.ts` + `chrome.d.ts` + asset rebuild)

The extension is authoritative; the bridge is defence in depth. All enforcement below lives in `packages/browser-relay/extension/background.ts`. Protocol changes land here because the extension is their first consumer; `packages/coding-agent` will not typecheck until Task 13 lands — expected and confined to this branch.

**File: `packages/coding-agent/src/tools/browser/relay/protocol.ts`**
1. Delete the `group` RPC variant `| { op: "group"; tabIds: number[]; title: string; color: string }` and its doc comment from `RelayRpcRequest`. **`ungroup` stays** (releasing is always safe).
2. Add a scope-config message to `RelayToExtMessage`:
```ts
export type RelayToExtMessage =
	| ({ t: "rpc"; id: number } & RelayRpcRequest)
	| { t: "pong" }
	/** Relay scope; sent once per extension connection. Absent (old relay) means group-scoped. */
	| { t: "config"; allTabs: boolean };
```
Decision (needed because enforcement lives in the extension but `--all-tabs` is a relay CLI flag): the relay tells the extension its scope with this message. The extension defaults to **scoped** on every new connection, so an old relay that never sends `config` gets the safe behavior.

**File: `packages/browser-relay/extension/chrome.d.ts`** (hand-written ambient types; the new listeners will not typecheck without this)
3. Add `interface ChromeTabGroup { id: number; windowId: number; title?: string; color?: string; collapsed?: boolean }`; retype `tabGroups.query` to return `Promise<ChromeTabGroup[]>`. Add event declarations:
   - `tabs.onMoved: ChromeEvent<(tabId: number, moveInfo: { windowId: number; fromIndex: number; toIndex: number }) => void>`
   - `tabs.onDetached: ChromeEvent<(tabId: number, detachInfo: { oldWindowId: number; oldPosition: number }) => void>`
   - `tabs.onAttached: ChromeEvent<(tabId: number, attachInfo: { newWindowId: number; newPosition: number }) => void>`
   - `tabGroups.onCreated: ChromeEvent<(group: ChromeTabGroup) => void>`, `tabGroups.onUpdated: ChromeEvent<(group: ChromeTabGroup) => void>`, `tabGroups.onRemoved: ChromeEvent<(group: ChromeTabGroup) => void>`

**File: `packages/browser-relay/extension/background.ts`**
4. Constants/state: add `const OMP_GROUP = { title: "omp", color: "cyan" } as const;` (moves the group identity here — server.ts's `DEFAULT_GROUP` dies in Task 13), `let allTabs = false;`, `const announced = new Set<number>();` (tab ids currently announced to the relay; worker-local is fine — a service-worker restart drops the socket and the next hello rebuilds it).
5. Delete `ompGroupTitle`, the `chrome.storage.session` mirror, `groupTabs`, and `restoreGroups` entirely. In `connect()`'s `socket.onclose`, **delete `void restoreGroups();`** — the group is now the user's ACL and must survive relay restarts (today's dissolve-on-disconnect would wipe the ACL). Keep `enqueueGroupOp` (still serializes Chrome's non-atomic query→group→set-title sequence for `createTab`).
6. Membership helpers — **exact title equality, never the query's pattern semantics** (`chrome.tabGroups.query({ title })` matches titles against a *pattern*, so filter the result):
   - `async function ompGroupIds(): Promise<Set<number>>` — `(await chrome.tabGroups.query({ title: OMP_GROUP.title })).filter(g => g.title === OMP_GROUP.title)` → set of ids (all windows); errors → empty set.
   - `async function tabInScope(tabId: number): Promise<boolean>` — `allTabs` → true; else `chrome.tabs.get(tabId)` + `(await ompGroupIds()).has(tab.groupId)`; missing tab → false. Color is ignored; any window counts.
7. **Announce** — `buildHello()`: after querying tabs and targets, compute `const ids = await ompGroupIds();`; unless `allTabs`, keep only snapshots with `ids.has(snap.groupId)`; reset `announced` to exactly that set. **Re-derive attachments**: for each `chrome.debugger` target that is attached to a tab *not* in scope, `await chrome.debugger.detach({ tabId }).catch(() => {})` and exclude it from `attachedTabIds` — never trust a previously attached set across reconnects.
8. **Scope is checked at execution time for every operation that can drive or observe a tab** — in `runRpc`:
   - `attach`, `removeTab`, `activateTab`: guard first with `if (!(await tabInScope(msg.tabId))) throw new Error(\`tab ${msg.tabId} is not in the omp tab group\`);`.
   - `send` (the actual drive path — every CDP command flows through it): guard with the same `tabInScope` check before `chrome.debugger.sendCommand`. On a miss, revoke rather than merely refuse: `await chrome.debugger.detach({ tabId: msg.tabId }).catch(() => {})`; `if (announced.delete(msg.tabId)) post({ t: "tabRemoved", tabId: msg.tabId });` then `throw new Error(\`tab ${msg.tabId} is not in the omp tab group\`)`. This closes the race where a stale pre-existing attachment (or a not-yet-evicted tab) could still be driven between leaving the group and the async eviction landing.
   - Leave `detach` and `ungroup` unguarded — both only shrink access.
9. **Filter `chrome.debugger.onEvent`** so events from out-of-scope or stale attachments never reach the relay: at the top of the listener, `if (!allTabs && source.tabId !== undefined && !announced.has(source.tabId)) return;` (`announced` is the extension's live scope view, kept current by hello and the eviction paths; a synchronous set check avoids reordering event delivery). Keep `chrome.debugger.onDetach` unfiltered — a detach notification only shrinks access and the bridge must always hear it.
10. **`createTab` joins the group atomically**: `chrome.tabs.create({ url: msg.url })`; if `tab.id === undefined` throw as today; when not `allTabs`, `await enqueueGroupOp(() => joinOmpGroup(tab.id, tab.windowId))` — new helper containing today's per-window reuse-or-create + duplicate-group-healing logic from `groupTabs`, specialized to one tab, **with the same exact-title filter from step 6 applied to its per-window `tabGroups.query` result before reusing or merging groups**, ending with `chrome.tabGroups.update(groupId, OMP_GROUP)`. If grouping throws: `await chrome.tabs.remove(tab.id).catch(() => {})` then `throw new Error("created tab could not join the omp tab group")` — never leave an ungrouped-but-controllable tab. On success re-fetch (`chrome.tabs.get(tab.id)`) so the returned snapshot carries the real `groupId`, add the id to `announced`, return `{ tab: snapshot(fresh) }`.
11. Delete the `case "group":` arm from `runRpc` (compile error until removed, since the protocol variant is gone).
12. **Config handling** — in `handleRelayMessage`, after the `pong` early-return: `if (msg.t === "config") { const changed = allTabs !== msg.allTabs; allTabs = msg.allTabs; if (changed) void buildHello().then(hello => post(hello)); return; }`. In `connect()`'s `socket.onopen`, reset `allTabs = false` before sending hello (scoped default per connection). The re-hello on change is safe: the bridge's `#onHello` fully reconciles seen/unseen tabs.
13. **Evict immediately** — replace the bare `tabCreated`/`tabUpdated` posts with one transition routine and wire the full listener set (same-window drags, cross-window drags, and group retitles all revoke):
    - `async function announceTransition(tab: chrome.tabs.Tab): Promise<void>`: build `snapshot(tab)`; if null return. When `allTabs`: post `tabUpdated` if `announced.has(id)` else add + post `tabCreated`. Otherwise compute membership via `ompGroupIds()`: member+announced → post `tabUpdated`; member+new → add to `announced`, post `tabCreated` (a tab dragged *into* the group becomes drivable); non-member+announced → delete from `announced`, `await chrome.debugger.detach({ tabId }).catch(() => {})`, post `{ t: "tabRemoved", tabId }` — dragging a tab out revokes access mid-session; non-member+unknown → nothing (ungrouped tabs are never announced).
    - `chrome.tabs.onCreated` → `void announceTransition(tab)`. `chrome.tabs.onUpdated` → `void announceTransition(tab)` (Chrome reports `groupId` changes through this event). `chrome.tabs.onMoved` → `chrome.tabs.get(tabId)` then `announceTransition` (same-window drags). `chrome.tabs.onRemoved` → `announced.delete(tabId)` + post `tabRemoved` unconditionally (bridge no-ops unknown ids).
    - **Cross-window moves fire `onDetached`/`onAttached`, not `onMoved`**: `chrome.tabs.onDetached` → if `announced.has(tabId)`, evict conservatively (best-effort `chrome.debugger.detach({ tabId })`, `announced.delete(tabId)`, post `tabRemoved` — a tab detached from its window has left its group); `chrome.tabs.onAttached` → `chrome.tabs.get(tabId)` then `announceTransition` (re-announces it if it landed inside an omp group in the new window).
    - `chrome.tabGroups.onUpdated`, `chrome.tabGroups.onCreated`, `chrome.tabGroups.onRemoved` → `void reconcileScope()` where `reconcileScope()` = `chrome.tabs.query({})` then `announceTransition` per tab — covers a group being retitled to/from `"omp"`, which fires no per-tab events.
14. `manifest.json` already grants `tabGroups`; no manifest change.

**Rebuild the committed assets**: `cd packages/browser-relay && bun run build` (runs `scripts/build-extension.ts`; needs the `zip` binary) and include the regenerated `packages/coding-agent/src/tools/browser/relay/extension-assets/*.txt` in this task's commit — the CLI embeds them.

**Verify (devbox):** `cd packages/browser-relay && bun run check` exits 0 (tsgo typechecks `background.ts` and the extended `chrome.d.ts` against the new protocol) and `bun run build` prints the three `built:` lines; `jj st` in the workspace shows `extension-assets/background.js.txt` modified. **Needs the laptop for behavioral proof** (real Chrome + drag gestures); devbox proxies are this typecheck/build plus Task 13's bridge-side contract tests of the same wire protocol. The end-to-end laptop checklist lands in Task 17.
**Depends on:** 10. **Parallel-safe with:** 11, 15.

## Task 13 — Bridge: excise grouping, send scope config, close the unknown-target and stale-cache holes, rework the tests

**File: `packages/coding-agent/src/tools/browser/relay/bridge.ts`**
1. Constructor options `{ log?, group? }` → `{ log?, allTabs? }`; replace `#group` with `#allTabs: boolean` (`opts.allTabs === true`). The bridge stays group-agnostic — it never sees group ids; its only use of `#allTabs` is step 2.
2. `extConnected` (bridge.ts:213): after `this.#ext = socket;` send the scope config so the extension knows its mode before answering hello-follow-ups: `socket.send(JSON.stringify({ t: "config", allTabs: this.#allTabs } satisfies RelayToExtMessage));`.
3. Delete the entire `// ---- tab grouping ----` section (`#groupWorthy`, `#syncGrouping`, `#syncTabGrouping`, `#requestGroup`, `#drainGroupQueue`, bridge.ts:723-801) and the fields `#groupQueue`, `#groupDraining`. On `TabState`, delete `grouped`, `grouping`, `ompGroupId`, `groupOptOut` (keep `groupId` — it is still in `TabSnapshot`).
4. Delete the grouping call sites: `extClosed`'s grouping resets + comment (:233-241, keep the `attached`/`attaching` resets) and `this.#groupQueue.length = 0`; `#onHello`'s `this.#syncGrouping()`; `#onTabUpsert`'s opt-out branch (:684-689) and `this.#syncTabGrouping(tab)` (:694); `#onTabDetached`'s `this.#syncTabGrouping(tab)` (:665) and its stale comment; `cdpClosed`'s claims→`#syncTabGrouping` loop (:331-338).
5. Claims are now weightless (they existed only to drive grouping): delete `CdpConnection.claims`, `#claimTab`, `#claimed`, the `conn.claims.delete(tabId)` in `#onTabRemoved` (:674), and the `this.#claimTab(...)` call in `Target.createTarget` (:557). Keep the `OMP.claimTarget` handler in `#forwardToTab` (:404-408) replying `{}` — `tab-worker.ts:936` still sends it; update its comment to say it is a compatibility no-op.
6. **Defence in depth — unknown ids**: present only extension-announced targets and reject unknown ids:
   - `Target.attachToTarget` (:528) already rejects unknown ids (`No target with id …`) — keep.
   - `Target.closeTarget` (:565-570): also look up `this.#tabs.get(parsed.tabId)`; unknown → `#replyError(conn, msg, \`No target with id ${String(msg.params?.targetId)}\`)` instead of forwarding `removeTab`.
   - `Target.activateTarget` (:571-576): same gate — today it forwards any well-formed id to the extension; unknown must get the same `#replyError`, no `activateTab` RPC.
7. **Defence in depth — stale cache across extension disconnect**: `#tabs` survives `extClosed` by design (session restoration across MV3 worker restarts, bridge.ts:299-310 — see note below), but stale tabs must be invisible until a fresh hello. Use the existing `ready` getter (`#extInfo` is nulled in `extClosed` and restored only by `#onHello` — it *is* the epoch):
   - `listTargets()` (:201): first line `if (!this.ready) return [];`.
   - `Target.setDiscoverTargets` (:501): always set `conn.discover = true`; when `!this.ready`, set a new `CdpConnection` field `discoverPending = true` (declare it next to `discover`/`autoAttach`, :54-55) and reply `{}` **without announcing anything**; when ready, announce as today.
   - `Target.setAutoAttach` (:512): when `!this.ready`, set `conn.autoAttach = true` and reply `{}` **without running the attach loop** — today that loop would `#retractTab` every tab whose gap-time attach fails, destroying live targets as a side effect of a probe.
   - `Target.attachToTarget` (:528): when `!this.ready`, `#replyError(conn, msg, "relay extension is not connected")` before the `#tabs` lookup.
   - `#onHello` (:287): after the existing reconciliation (which already retracts tabs missing from the fresh hello via `#onTabRemoved` → `#retractTab`, handling "user dragged a tab out while disconnected"), flush pending discoverers: for each conn with `discoverPending`, run the same announce loop `setDiscoverTargets` uses (eligible tabs → `tab.announced = true`, emit `Target.targetCreated` for tab + page infos), then clear `discoverPending`.
   - Note for the implementer: do **not** take the alternative of clearing `#tabs`/retracting in `extClosed` — `#retractTab` (:806-828) deletes minted sessions and emits `Target.detachedFromTarget`/`targetDestroyed`, so eager teardown would kill every live agent session on each routine MV3 service-worker suspension, which the bridge's header contract ("a service-worker restart only has to re-handshake") exists to prevent.

**File: `packages/coding-agent/src/tools/browser/relay/server.ts`**
8. Delete `DEFAULT_GROUP` and the `group` resolution line (:50-51). `RelayServerOptions.group?: boolean | { title; color }` → `allTabs?: boolean` with doc `/** Expose every tab instead of only the 'omp' tab group (default false: group-scoped). */`. Construct `new RelayBridge({ log, allTabs: opts.allTabs === true })`. (The `browser-relay-cli.ts` caller breaks until Task 14 — expected.)

**File: `packages/coding-agent/test/tools/browser-relay-bridge.test.ts`**
9. Delete the `describe("RelayBridge tab grouping")` block wholesale — every test in it asserts the removed `group` RPC. Keep `FakeExtSocket`, `FakeCdpSocket`, `tab()`, `connect()`, `ack()`, `flush()`, `attachPage()`; keep `claimTab()` only if a kept test uses it, otherwise delete it too. Note: `connect()` sends hello before the bridge's config message exists on the wire — fine, order is not part of the contract.
10. New `describe("RelayBridge scope enforcement")` (contract-level per AGENTS.md; each names its failure mode):
    - **config wire contract** (extension consumes this exact shape): `new RelayBridge({ allTabs: true })` + `extConnected(ext)` → `ext.messages[0]` deep-equals `{ t: "config", allTabs: true }`; a default-constructed bridge sends `{ t: "config", allTabs: false }`. Regression = extension silently falls back to scoped/unscoped mismatch.
    - **unknown-target attach rejected** (defence in depth): connect with `[tab({ tabId: 1 })]`; `Target.attachToTarget` for `PAGE7` → error reply containing `No target with id PAGE7`; `ext.rpcs("attach")` stays empty.
    - **unknown-target close/activate rejected** (regression: `activateTarget` used to forward blindly): `Target.closeTarget`/`Target.activateTarget` for `PAGE7` → error replies; `ext.rpcs("removeTab")` and `ext.rpcs("activateTab")` stay empty.
    - **retraction destroys targets** (bridge half of drag-out revocation): connect `[tab({ tabId: 1 })]`, cdp connection + `Target.setDiscoverTargets`, then ext sends `{ t: "tabRemoved", tabId: 1 }` → cdp socket received `Target.targetDestroyed` for both `PAGE1` and `TAB1`, and `bridge.listTargets()` returns `[]`.
    - **revoked tab: stale session commands fail without reaching Chrome** (the oracle's mid-session revocation contract, bridge side): connect `[tab({ tabId: 1 })]`; `attachPage(...)` to get a minted session; ext sends `{ t: "tabRemoved", tabId: 1 }` (what the extension now emits when a tab leaves the group); then a `Runtime.evaluate` through the old `sessionId` → error reply containing `Unknown session id`, **and `ext.rpcs("send")` is still empty** — `#retractTab` deleted the session, so nothing is forwarded to the extension.
    - **stale cache invisible across extension disconnect** (reconnect race): connect `[tab({ tabId: 1 })]`; `bridge.extClosed(ext)` → `bridge.listTargets()` equals `[]`; a new cdp conn sending `Target.setDiscoverTargets` gets a reply but **zero `Target.targetCreated`** emissions; `Target.attachToTarget` for `PAGE1` → error reply `relay extension is not connected`; then reconnect (`connect(bridge, ext2, [tab({ tabId: 1 })])`) → the pending discoverer now receives `Target.targetCreated` for `PAGE1` and `TAB1`, and `listTargets()` shows `PAGE1` again.
    - **createTarget round-trip** (reworked from the old auto-claim test, minus group assertions): `Target.createTarget` → `ack(bridge, ext, "createTab", { tab: tab({ tabId: 9, groupId: 42 }) })` → reply carries `targetId: "PAGE9"` and `bridge.listTargets()` now includes it.

**Verify:** `cd packages/coding-agent && bun test test/tools/browser-relay-bridge.test.ts` → green (the test file's import graph does not include the still-broken CLI). Fully devbox-verifiable.
**Depends on:** 11 and 12 (shares `server.ts` with 11; consumes 12's protocol). **Parallel-safe with:** 15.

## Task 14 — Flag cutover: remove `--no-group`, add `--all-tabs`; update help and README

Clean cutover, no deprecated alias. Scoping is the default; opting out is explicit.

1. `packages/coding-agent/src/commands/browser-relay.ts`: delete the `"no-group"` flag block (:29-32); add
```ts
"all-tabs": Flags.boolean({
	description: "Expose every tab to the agent instead of only the 'omp' tab group",
	default: false,
}),
```
   In `run()`, replace `group: !flags["no-group"]` with `allTabs: flags["all-tabs"]`.
2. `packages/coding-agent/src/cli/browser-relay-cli.ts`: `BrowserRelayCommandArgs.group?: boolean` → `allTabs?: boolean` with doc `/** Expose every tab instead of only the 'omp' tab group (default false). */`; in `runServe`, `startRelayServer({ port: args.port, token: args.token, group: args.group !== false, log })` (:73) → `startRelayServer({ port: args.port, token: args.token, allTabs: args.allTabs === true, log })`; install help line (:61) → `console.log("run \`omp browser-relay\` yourself only for --token or --all-tabs.");`.
3. `packages/browser-relay/README.md`: rewrite the two stale paragraphs (:12 and :14) for the ACL model — the `omp` tab group is the shared set: drag a tab in to share it, drag it out to revoke access mid-session; agents can open new tabs, which join the group automatically, but can never pull an existing tab in; the group persists across relay restarts. Replace the `--no-group` mention with `--all-tabs` ("restores unscoped access to every tab"). Delete the "released when omp lets go / dissolved on disconnect" claims — both behaviors are gone.
4. The broker auto-start needs no change: `ensureRelayDaemon` (relay/daemon.ts) spawns with `args: [..., "--port", port]` only, so it inherits the scoped default.

**Verify (devbox, from `packages/coding-agent`):**
- `bun src/cli.ts browser-relay --help` output lists `--all-tabs` and does not list `--no-group`.
- `bun src/cli.ts browser-relay --no-group` exits non-zero with an unknown-flag error.
- Smoke: `bun src/cli.ts browser-relay --port 9333` prints `omp browser relay listening on http://127.0.0.1:9333`; in a second shell `curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:9333/json/version` prints `503` (server up, extension absent — the correct devbox observable); Ctrl-C stops it.
- `cd packages/coding-agent && bun run check` now exits 0 (the package compiles end-to-end again).
`--all-tabs` end-to-end behavior needs the laptop; the devbox proxy is the Task 13 config-message test plus this smoke.
**Depends on:** 13. **Parallel-safe with:** 15.

## Task 15 — Relay-specific empty-group failure message

An empty group currently surfaces as the generic `No page targets available on the attached browser` (`packages/coding-agent/src/tools/browser/attach.ts:206`, inside `pickElectronTarget`, whose only caller is `tab-supervisor.ts:715`).

1. `packages/coding-agent/src/tools/browser/attach.ts`: extend `pickElectronTarget`'s options to `{ matcher?: string; preferVisible?: boolean; noTargetsMessage?: string }`; change the throw at :206 to `throw new ToolError(options.noTargetsMessage ?? "No page targets available on the attached browser");`.
2. `packages/coding-agent/src/tools/browser/tab-supervisor.ts`: add a module-level constant near the other top-level constants:
```ts
/** Relay mode with an empty omp tab group: name the fix, not the symptom. */
const RELAY_NO_TABS_MESSAGE = 'No tabs are shared with omp: drag a tab into the "omp" tab group in Chrome to share it.';
```
   and at the `pickElectronTarget` call (:715-718) pass `noTargetsMessage: browser.kind.kind === "relay" ? RELAY_NO_TABS_MESSAGE : undefined` (the `userDriven` const two lines above already proves `browser.kind.kind` is in scope here).
3. Test in the existing `packages/coding-agent/test/tools/browser-attach.test.ts`, following its current conventions (error-mapping contract: relay users lose the actionable hint if this regresses). Minimal fake, since `pickElectronTarget` only calls `targets()` and `pages()` on the empty path: `const browser = { targets: () => [], pages: async () => [] } as unknown as Browser;` — two cases: with `noTargetsMessage` set the `ToolError` message is exactly the override; without it, exactly the generic string (both strings are agent-visible output that downstream flows and users read).

**Verify:** `cd packages/coding-agent && bun test test/tools/browser-attach.test.ts` → green, including the two new cases. Devbox-verifiable; the real empty-group UX (relay + connected extension + empty group) is on the Task 17 laptop checklist.
**Depends on:** 10 only. **Parallel-safe with:** 11, 12, 13, 14.

## Task 16 — Changelog entries in both packages

Per the repo's changelog rules (`## [Unreleased]` sections; never touch released sections; `bun run release` normalizes formatting later — do not run it).

1. `packages/coding-agent/CHANGELOG.md`, under `## [Unreleased]`:
   - `### Breaking Changes`: `omp browser-relay` now scopes agents to the `omp` Chrome tab group by default and enforces it in the extension; `--no-group` is removed, `--all-tabs` restores unscoped access.
   - `### Added`: relay browser mode reports a specific error when no tabs are in the `omp` tab group instead of the generic no-targets message.
   - `### Fixed`: the relay's `/json/version` now derives `webSocketDebuggerUrl` from a validated request `Host` header (falling back to loopback), so remote clients reached through a port forward are told to dial back through the same channel; the relay bridge no longer lists or attaches stale targets between an extension disconnect and the next handshake.
   - `### Removed`: the `group` RPC from the relay↔extension protocol — agents can create tabs inside the group but can never add an existing tab to it.
2. `packages/browser-relay/CHANGELOG.md`, under `## [Unreleased]` (create the section if the file lacks one):
   - `### Changed`: the extension now enforces the `omp` tab group as the access-control list — it announces only grouped tabs, re-derives membership on reconnect, checks scope on every attach/send/remove/activate at execution time, filters debugger events to in-scope tabs, force-detaches and retracts tabs that leave the group (including cross-window drags), and closes a created tab it fails to group; the group is no longer dissolved when the relay disconnects.

**Verify:** read both files and confirm each entry sits under `## [Unreleased]` in the correct subsection and describes behavior delivered by Tasks 11-15 (no invented scope); `cd packages/coding-agent && bun run lint` and `cd packages/browser-relay && bun run lint` exit 0.
**Depends on:** 11, 12, 13, 14, 15.

## Task 17 — Final verification sweep and branch handoff

All commands from the knives workspace root.

1. `cd packages/browser-relay && bun run check && bun run build` — exit 0; confirm via `jj st` that the regenerated `packages/coding-agent/src/tools/browser/relay/extension-assets/*.txt` are part of the branch (Task 12 committed them; a second build must be a no-op diff).
2. `cd packages/coding-agent && bun run check` — exit 0 (biome + tsgo across the package catches any missed `group` reference).
3. Targeted test net (not the full suite): `cd packages/coding-agent && bun test test/tools/browser-relay-bridge.test.ts test/tools/browser-relay-server.test.ts test/tools/browser-attach.test.ts test/tools/browser-relay-daemon.test.ts test/tools/browser-relay-kind.test.ts` — daemon/kind files are untouched but sit on the changed module graph; all green.
4. Re-run the Task 14 CLI smoke once on the final tree (`bun src/cli.ts browser-relay --port 9333` → banner, `curl` → 503, Ctrl-C).
5. Commit hygiene: Task 11 stands as its own commit (upstreamable); remaining work in logically separate commits via `jj describe -m` / `jj new` (extension+protocol, bridge+tests, CLI cutover+docs, failure message, changelogs is a reasonable split). Do **not** run `knives finish` and do not open a PR — the branch stays claimed for review and the cross-phase rollout; record a notch: `knives notch browser-relay-group-acl -m "Phase 2 complete: group ACL enforced in extension, Host-header fix, --all-tabs cutover; laptop verification pending" --evidence <tip-commit>`.
6. Write the **laptop verification checklist** into the branch's notch/PR description material (these cannot run on the devbox; devbox proxies were delivered in Tasks 11-15): load the rebuilt unpacked extension → badge `on`; with an empty group, a relay browser call fails with the exact `No tabs are shared with omp: …` message; drag a tab in → attach succeeds and the debugger infobar appears; drag it out mid-run → infobar drops **and a command issued immediately through the pre-existing session fails without reaching the page** (the send-guard revocation — verify the page shows no effect); repeat the drag-out with a cross-window drag into another Chrome window (the `onDetached`/`onAttached` path); agent-created tab lands inside the cyan `omp` group and is closed if grouping fails; a group retitled away from `omp` revokes its tabs; `omp browser-relay --all-tabs` restores today's every-tab behavior; relay restart leaves the group intact.

**Verify:** steps 1-4 outputs as stated; `knives status` still shows the claim; `jj log` shows the standalone Host-fix commit.
**Depends on:** 16 (and transitively all).
## Task 20 — secretsd: implement `secrets set-human KEY [--source NAME]`

**Where work happens:** `/home/ubuntu/secretsd/default` (jj-colocated clone of `github:sjawhar/secretsd`, `main` tracked — NOT the `/tmp/secretsd-plan-read` grounding clone). Version control is jj. Before editing, read `AGENTS.md` and `src/client/AGENTS.md`; the non-negotiables bind every line below (no plaintext at rest, fail closed, never render a secret or any prefix of it into an error or output).

**Depends:** none. **Parallel-safe with:** 24, 25, 27.

**Files:** `src/client/cli.rs`, `src/client/edit.rs`, `src/client/edit/new.rs`, `src/client/error.rs`; doc rows in `AGENTS.md`, `src/client/AGENTS.md`, `docs/design.md`.

1. `src/client/cli.rs` — in `run()`'s `match command.as_os_str()`, directly after the `edit-human` arm, add:
   ```rust
   value if value == OsStr::new("set-human") => {
       super::edit::set_human(&context.sources, &context.human, &arguments)
   }
   ```
2. `src/client/edit.rs` — add:
   ```rust
   /// Store a human-tier key non-interactively from stdin, creating or rotating it.
   pub(super) fn set_human(
       sources: &Sources,
       human: &HumanNames,
       arguments: &[OsString],
   ) -> Result<(), CliError> {
       let name = parse_name(argument_at(arguments, 1)?)?;
       let flags = edit_arguments(arguments, 2, false)?;
       if let Some(location) = human.location(&name) {
           let path = existing_human_path(sources, &ExistingHumanEdit { name: &name, location, flags })?;
           new::set_human(&path, &name, true)
       } else {
           let path = new_human_path(sources, &name, EditArguments { source: flags.source, local: true })?;
           new::set_human(&path, &name, false)
       }
   }
   ```
   Decisions locked in: `edit_arguments(_, 2, false)` accepts only `--source` (`--local` is rejected — a new key is always the `.local.env` variant, matching the per-key layout `DEEL_SESSION_COOKIE.local.env` / `ZIP_SESSION_COOKIE.local.env` already use, via `name.local_file_name()` inside `new_human_path`). An existing key rotates **its actual file** wherever it lives; reusing `existing_human_path` keeps the `--source`-vs-actual-root `EditConflict` check. Ambiguous keys are already refused upstream by `HumanNames::load` (`DuplicateHumanKey`).
3. `src/client/edit/new.rs` — the non-interactive path writes **no plaintext temp file at all** (stronger than the editor flow; the runtime dir is never touched):
   - `pub(super) fn set_human(path: &Path, name: &SecretName, rotate: bool) -> Result<(), CliError>`: build the assignment from stdin, encrypt, persist, then print exactly one line to stdout — `created {path}` or `rotated {path}` (`path.display()`). No VCS interaction: the command commits nothing by design.
   - `fn read_piped_assignment(name: &SecretName) -> Result<SecretBytes, CliError>`: refuse a terminal stdin (`use std::io::IsTerminal;` → `CliError::SetHumanTerminalStdin`) so a bare interactive run can never hang or capture typed scrollback; `read_to_end` into a `Vec<u8>` (on failure zeroize the partial buffer, return `CliError::SetHumanRead(e)`); strip exactly one trailing `\n` (and a preceding `\r` if present); empty after strip → `CliError::EmptyPipedHumanSecret(name)`; build `KEY=<value>\n`, wrap in `SecretBytes` immediately and zeroize intermediates (mirror `PlaintextTemp::read`); validate with `parse_single_assignment(bytes, name)` — an embedded newline or malformed bytes fail it → `CliError::InvalidPipedHumanSecret(name)`.
   - Refactor: extract the sops argv from `encrypt()` into `fn sops_encrypt_command(directory: &Path, target: &Path) -> Command` (`sops encrypt --filename-override <target> --input-type dotenv --output-type dotenv`, `.current_dir(directory)`); `encrypt()` keeps `Stdio::from(file)` + `persist_noclobber` unchanged. New `fn encrypt_bytes(plaintext: &SecretBytes, target: &Path) -> Result<(), CliError>`: `Builder::new().prefix(".secretsd-ciphertext-").tempfile_in(parent)`, spawn with `Stdio::piped()` stdin, `write_all` the bytes, drop the stdin handle (sops consumes stdin fully before writing output — child stdout is a `File`, so a sequential write cannot deadlock), drain stderr to sink, `wait()`, then `ciphertext.persist(target)` — **clobber, not `persist_noclobber`**: rotation is the point. Tempfile-in-target-dir + rename is atomic (never a torn ciphertext, addressing the scout's atomic-write flag); concurrent same-key writers are last-writer-wins with no lock — say so in the doc comment ("one writer per key at a time; capture flows are single-writer by construction").
   - Daemon cache invalidation needs **no daemon change** — record this in the doc comment: rotation replaces the inode, and the daemon snapshots `FileIdentity { device, inode, size, modified, changed }` (`src/store.rs:45-50`) via `HumanStore::identity` (`src/store.rs:166`), which `resolve_access` (`src/server/approval.rs`) compares to invalidate stale grants.
4. `src/client/error.rs` — four new variants; the exhaustive `Display`/`source()` matches force arms for each: `SetHumanTerminalStdin` ("set-human reads the secret value from stdin; pipe it in — the value must never appear in argv"), `SetHumanRead(std::io::Error)`, `EmptyPipedHumanSecret(SecretName)`, `InvalidPipedHumanSecret(SecretName)` ("piped secret '{}' must be one single-line assignment value"). Never render the value. Extend the `Usage` string to insert `secrets set-human KEY [--source NAME]` after the `edit-human` clause — the literal substring `set-human` in `secrets --help` output is the availability-detection contract Task 24 greps.
5. Docs (same commit): root `AGENTS.md` "Where to look" row "Change human-secret creation" gains the set-human symbols; `src/client/AGENTS.md` file-table row for `edit/new.rs`; `docs/design.md` creation-flow section gains a set-human paragraph (stdin never argv, public-age-recipient encrypt so storing needs no YubiKey touch, no plaintext at rest, reading stays touch-gated).

**Verify (devbox):**
```
cd /home/ubuntu/secretsd/default && cargo build
./target/debug/secrets set-human 2>&1 | grep -o 'set-human KEY \[--source NAME\]'   # usage names the new subcommand
./target/debug/secrets --help 2>&1 | grep -c 'set-human'                            # prints 1 — Task 24's detection surface
```
Behavioral coverage lands in Tasks 21–22 (scratch roots; never run set-human against the real store from a test).

---

## Task 21 — secretsd: integration tests for set-human

**Where:** `/home/ubuntu/secretsd/default`. **Depends:** 20. **Parallel-safe with:** 22.

**Files:** `tests/client/set_human.rs` (new), `tests/client/fixture.rs`, `tests/client.rs`, `tests/AGENTS.md`.

1. `tests/client/fixture.rs` — beside `run_minimal`, add `fn run_with_stdin<I, S>(&self, arguments: I, stdin: &[u8]) -> Output` built on the existing `command()` helper: spawn with `Stdio::piped()` stdin, write `stdin`, drop the handle, `wait_with_output()`.
2. `tests/client.rs` — wire the new module the way siblings are wired: `#[path = "client/set_human.rs"] mod set_human;`. Add the file to the table in `tests/AGENTS.md`.
3. `tests/client/set_human.rs` — contract tests against the fake sops fixtures (`tests/fixtures/fake-sops-ok`, `fake-sops-fail`), reusing `Fixture::agent`/`Fixture::human`, `write_human_name_in`, `sops_log`/`sops_arguments`/`sops_calls`, `runtime_dir`, and edit.rs's assertion-helper patterns (`assert_sops_encrypt_command`, `assert_runtime_is_empty`, `assert_ciphertext_contains`, `FAKE_SOPS_CIPHERTEXT_MARKER`):
   - `set_human_creates_a_local_file_for_a_new_key_from_stdin` — stdin `b"swordfish-0123"`; asserts the file lands at `<root>/secrets.human.d/KEY.local.env`, sops argv is the encrypt form with `--filename-override`, stdout is exactly `created <path>\n`.
   - `set_human_rotates_an_existing_keys_actual_file_and_reports_it` — seed `KEY.env` via `write_human_name_in`; a second value overwrites **that** path (not a new `.local.env`), stdout is `rotated <path>\n`.
   - `set_human_rejects_a_source_other_than_an_existing_keys_actual_root` — `EditConflict`; `sops_calls() == 0`.
   - `set_human_requires_a_source_when_multiple_roots_are_configured` — `add_root` a second root; new key without `--source` fails with the EditSourceRequired message; nothing created.
   - `set_human_refuses_an_empty_stdin_value_and_creates_nothing` — empty stdin; stderr names the key; no file; `sops_calls() == 0`.
   - `set_human_refuses_a_multiline_value_and_creates_nothing` — stdin `b"a\nb"`.
   - `set_human_strips_exactly_one_trailing_newline` — stdin `b"value\n"`; `assert_ciphertext_contains` the assignment `KEY=value\n`.
   - `set_human_never_echoes_the_value_to_stdout_or_stderr` — assert the value bytes appear in neither stream (repo convention: tests assert absence of secret bytes).
   - `set_human_leaves_the_runtime_dir_empty` — `assert_runtime_is_empty` (no plaintext temp file exists at any point; the piped path never creates one).
   - `set_human_usage_error_names_the_subcommand` — no KEY argument → usage string contains `set-human`.
   These are `tests/` integration tests, not miri-covered unit tests — no `#[cfg_attr(miri, ignore)]` dance needed (miri runs `src/` unit tests only).

**Verify (devbox):**
```
cd /home/ubuntu/secretsd/default && cargo nextest run --all-features -E 'test(/set_human/)'   # all new tests pass
cargo nextest run --all-features -E 'test(/edit/)'                                            # editor-flow tests still pass (refactor did not drift encrypt())
```

---

## Task 22 — secretsd: extend the real-sops e2e harness

**Where:** `/home/ubuntu/secretsd/default`. **Depends:** 20. **Parallel-safe with:** 21.

**Files:** `tests/e2e-client-harness.sh` (driven by `tests/e2e_client.rs`; exit 0 or 77).

Mirror the existing step "6/13 creating a human secret through the real client and real sops": after it, add a set-human step run from `$operator_dir` (the config-less CWD that proves the child CWD reset):
```
printf '%s' "$set_human_value" | run_client_from "$operator_dir" set-human "$SET_HUMAN_KEY" --source dotfiles
```
Assert: the command's stdout is `created $human_dir/$SET_HUMAN_KEY.local.env`; the file exists; it carries the human-rule recipient and not the agent recipient (same greps as step 6); the agent age key cannot decrypt it; `assert_sops_counts` advances by exactly one client-side sops call and zero daemon calls. Then rotate: pipe a different value to the same key, assert stdout begins `rotated `, and the ciphertext bytes changed (`cmp` against a pre-rotation copy fails). Declare `set_human_value`/`SET_HUMAN_KEY` readonly at the top beside the existing key/value constants, and renumber every `report 'n/13 ...'` label for the new step count.

**Verify (devbox):**
```
cd /home/ubuntu/secretsd/default && cargo nextest run --all-features -E 'test(e2e_client)'
```
Exit 0 (or a reported skip 77 if the disk-resident age key is unavailable on the machine — the test self-reports which; on this devbox sops and age are mise-pinned and the harness has been passing, so expect 0).

---

## Task 23 — secretsd: gate, PR, release, and devbox arrival

**Where:** `/home/ubuntu/secretsd/default`. **Depends:** 20, 21, 22. Not parallel with them.

1. Run the repo's full gate exactly as `AGENTS.md` § Development lists it:
   ```
   cargo +nightly fmt --all -- --check
   cargo clippy --all-targets --all-features -- -D warnings
   cargo nextest run --all-targets --all-features --workspace
   cargo +nightly miri nextest run --all-features -E 'test(/^(secret|grants|requests|proto|client|config)::tests::/)'
   cargo machete && cargo deny check all
   ```
   (Known flakes listed in `tests/AGENTS.md` rerun in isolation. The bun plugin suites are untouched by this change but are part of the gate; run them.)
2. Commit with jj using a conventional-commit subject — this is load-bearing: releases are automatic on push to `main`, `feat:` derives the minor bump, and hand-tagging is forbidden. `jj describe -m "feat(client): add non-interactive secrets set-human write path"`, `jj bookmark set <branch> -r @`, `jj git push`, open the PR with `gh pr create`. No wire-protocol change is involved (set-human never contacts the daemon), so `PROTOCOL_VERSION` stays put.
3. After merge, CI tags/builds/publishes the release. On the devbox: `~/.dotfiles/bin/mise upgrade "github:sjawhar/secretsd"` (equivalently `mise install "github:sjawhar/secretsd@latest"`), then `bash ~/.dotfiles/installers/secretsd.sh` (re-links `~/.local/bin/secrets` to the mise `latest` symlink and refreshes the plugin pin/units; restarts the daemon only if something changed).

**Verify (devbox, after merge):**
```
gh release list --repo sjawhar/secretsd --limit 1        # new semver, minor bumped over v2.5.2's line
secrets --help 2>&1 | grep -c 'set-human'                # prints 1 — the installed binary ships the subcommand
```
**Cannot be fully verified without the release existing** (a merge to main by Sami). Devbox proxy until then: `./target/debug/secrets --help` from the branch build (Task 20's verify) — flag the release-arrival check as pending in the PR body.

---

## Task 24 — dotfiles: `scripts/browser-capture`

**Where:** `~/.dotfiles` (jj repo). **Depends:** none (works end to end only after 23 + Phases 1–2 are deployed, by design: its exit-7 path names the missing secretsd release). **Parallel-safe with:** 20, 25, 27.

**File:** `~/.dotfiles/scripts/browser-capture` — new, executable (`chmod +x`; `scripts/` is on PATH, invoked by name, no extension, per the placement map and `scripts/AGENTS.md`).

Shape: match `scripts/oc` — `#!/usr/bin/env -S uv run --script`, PEP 723 block (`requires-python = ">=3.12"`, `dependencies = ["websockets>=13"]`), a `─── How to run ───` header comment listing usage and the exit-code table, then a module docstring, `from __future__ import annotations`, argparse, `main() -> int`, `sys.exit(main())`.

Interface (spec-verbatim plus two operational flags with correct defaults, so the spec form works unmodified):
```
browser-capture --domain DOMAIN --cookie NAME --secret KEY [--tab SUBSTRING]
                [--relay-url URL] [--source NAME]
```
- `--relay-url` defaults to `os.environ.get("BROWSER_RELAY_URL", "http://100.100.92.97:12803")` (the `ENVOY_URL` pattern from `oc`). The CDP endpoint is derived from it — scheme swapped to `ws`, path `/cdp` — never taken from the advertised `webSocketDebuggerUrl`, so the script works whether or not Phase 2's Host-header fix is deployed.
- `--source` defaults to `private`: this devbox has two secretsd roots (`secrets sources`: `dotfiles` + `private`), human-tier session cookies live in `private` (= `~/.dotfiles/.secrets`, the spec's `.secrets/secrets.human.d/KEY.local.env` path), and `secrets set-human` without `--source` on a multi-root machine fails with EditSourceRequired. Passed through as `secrets set-human KEY --source NAME`.
- Subclass `argparse.ArgumentParser.error` to exit **1** — argparse's default usage-exit of 2 would collide with the spec's exit 2.

Flow (all errors to stderr; the only stdout ever is the final status line):
1. Preflight `secrets` availability before touching the browser: run `secrets --help`, capture combined output; if the substring `set-human` is absent → exit 7: "secrets set-human is unavailable — the installed secretsd predates it; run: mise upgrade github:sjawhar/secretsd && bash ~/.dotfiles/installers/secretsd.sh". A missing `secrets` binary (FileNotFoundError) → the same exit 7, loudly.
2. `urllib.request.urlopen(f"{relay_url}/json/version", timeout=5)`: connection error → exit 2 "browser relay unreachable at {url} — laptop asleep, forward daemon down, or the channel is not deployed"; HTTP 503 → exit 2 "relay is up but the extension is not connected — check the omp extension badge in Chrome".
3. `websockets.sync.client.connect(ws_url, open_timeout=10, max_size=None)` — no `Origin` header (the relay rejects Origin-bearing upgrades; the sync client sends none by default). Send `Target.getTargets` (incrementing ids; match responses by id, skipping interleaved events). Keep targets with `type == "page"` whose URL hostname equals DOMAIN or ends with `"." + DOMAIN`; the relay announces only `omp`-grouped tabs once Phase 2 is live, so announced == grouped. If `--tab` given, keep targets whose URL or title contains it case-insensitively. Zero → exit 3 "no grouped tab matches DOMAIN — drag the tab into the omp tab group". More than one → exit 4, list their URLs, "pass --tab SUBSTRING".
4. `Target.attachToTarget {"targetId": ..., "flatten": true}` → `sessionId`; then `Network.getCookies` with that `sessionId` (per-tab CDP deliberately — the bridge emulates the browser target but genuinely proxies per-tab commands through `chrome.debugger`).
5. Exact `name == NAME` match, then scope to DOMAIN: strip the cookie domain's leading dot to `d`; keep when `DOMAIN == d` or `DOMAIN.endswith("." + d)`. Zero name-matches → exit 5 listing the distinct cookie **names** present on that domain (sorted). Multiple survivors → exit 6 listing their `(domain, path)` pairs. Names only, never values.
6. `subprocess.run(["secrets", "set-human", KEY, "--source", SOURCE], input=value.encode(), capture_output=True)`; nonzero → exit 7, relay `secrets`' stderr verbatim (secretsd's own convention guarantees it never contains value bytes).
7. Print exactly one status line and exit 0: `stored KEY (domain .example.com, expires 2026-09-14)` — expiry from the cookie's `expires` epoch seconds formatted `YYYY-MM-DD` UTC; a session cookie (`expires == -1`) prints `session cookie` in place of the expiry clause.

**The value never leaves the process**: not printed, not logged, no temp file, no `--print` flag, never in argv or env — stdin to `secrets set-human` is the only egress.

**Verify (devbox):**
```
~/.dotfiles/scripts/browser-capture --help; echo "exit=$?"                      # usage on stdout, exit 0 (also proves uv resolves websockets)
~/.dotfiles/scripts/browser-capture --domain x.test --cookie a --secret K \
    --relay-url http://127.0.0.1:1 2>&1; echo "exit=$?"                         # exit 2, "browser relay unreachable"
d=$(mktemp -d) && printf '#!/bin/sh\necho "secrets: usage: secrets get ..." >&2\nexit 1\n' > "$d/secrets" \
  && chmod +x "$d/secrets" && PATH="$d:$PATH" ~/.dotfiles/scripts/browser-capture \
     --domain x.test --cookie a --secret K 2>&1; echo "exit=$?"                 # exit 7, names mise upgrade (old-binary detection)
```
**Laptop-required:** exit paths 3–6 and the success path need a live relay with a grouped tab — deliberately not mocked (the spec verifies this script end to end, not against fakes). That is Task 29. The three commands above are the devbox proxy.

---

## Task 25 — dotfiles: `omp-browser-relay.service` + wrapper

**Where:** `~/.dotfiles/forward/`. **Depends:** none. **Parallel-safe with:** 20, 24, 27.

**Files (new):** `forward/omp-browser-relay` (mode 755), `forward/omp-browser-relay.service`. Committed paths use `%h` / `$HOME` / `$DOTFILES_DIR` only — no absolute paths.

`forward/omp-browser-relay` (wrapper, mirroring `forward/forward-daemon`'s mise pattern minus the Wayland discovery it doesn't need):
```bash
#!/bin/bash
set -euo pipefail

MISE="${DOTFILES_DIR:-$HOME/.dotfiles}/bin/mise"
export MISE_AUTO_INSTALL=0
export MISE_DATA_DIR="${MISE_DATA_DIR:-$HOME/.mise}"

# Loopback CDP facade for the 'omp' tab group. forward's :12803 channel is the
# only remote way in; the extension dials ws://127.0.0.1:9224/ext itself.
# Scoped by default (no --all-tabs): the tab group is the ACL.
exec "$MISE" exec "github:sjawhar/oh-my-pi" -- omp browser-relay --port 9224
```

`forward/omp-browser-relay.service` (mirroring `forward-serve.service`, the simple unit — not `forward-daemon.service`, whose `graphical-session.target` coupling exists only for wl-copy; the relay has no compositor dependency because the extension connects inward):
```ini
[Unit]
Description=omp browser relay (loopback :9224; CDP facade for the omp tab group)

[Service]
ExecStart=%h/.dotfiles/forward/omp-browser-relay
Restart=always
RestartSec=2

[Install]
WantedBy=default.target
```
`Restart=always` per the spec: the relay holds no state and the extension reconnects with exponential backoff.

**Verify (devbox):**
```
test -x ~/.dotfiles/forward/omp-browser-relay && bash -n ~/.dotfiles/forward/omp-browser-relay && shellcheck ~/.dotfiles/forward/omp-browser-relay
systemd-analyze --user verify ~/.dotfiles/forward/omp-browser-relay.service; echo "exit=$?"   # exit 0, no output (calibrated: forward-serve.service verifies clean the same way)
```
**Laptop-required:** enablement and the running process (`systemctl --user status omp-browser-relay`, `curl -s 127.0.0.1:9224/json/version`) — covered in Task 29. The syntax/verify pass above is the devbox proxy.

---

## Task 26 — dotfiles: `installers/forward.sh` takes a unit list; daemon role installs the extension

**Where:** `~/.dotfiles/installers/forward.sh`. **Depends:** 25 (symlink-resolution check below needs the unit file to exist). **Parallel-safe with:** 20, 24, 27 (disjoint files).

Keep the script standalone (it does not source `lib.sh` today; stay consistent within the file). Replace the single `service`/`unit_source` pair with a per-role unit list, leaving `serve` behavior identical:
```bash
case "${1:-}" in
    serve)
        units=(forward-serve.service)
        config_source=config-serve.toml
        ;;
    daemon)
        units=(forward-daemon.service omp-browser-relay.service)
        config_source=config.toml
        ;;
    *)
        usage
        exit 1
        ;;
esac
```
- The forward-binary guard stays. Add, in the daemon branch only (the new unit execs omp immediately): `"$MISE" which omp >/dev/null 2>&1 || "$MISE" install "github:sjawhar/oh-my-pi@latest"`.
- The config symlink becomes `ln -sfn "${DOTFILES_DIR}/forward/${config_source}" "${HOME}/.config/forward/config.toml"` (replaces the role if/else; same well-known path, unchanged comment).
- Unit symlinks and activation loop over the list: one `systemctl --user daemon-reload` (existing `|| echo NOTE` fallback), then per unit `service="${unit%.service}"` with the existing `enable --now` and `try-restart` lines and their NOTE fallbacks.
- Daemon branch, after activation — materialize the Chrome extension and print the one step that cannot be automated:
  ```bash
  "$MISE" exec "github:sjawhar/oh-my-pi" -- omp browser-relay install
  echo "Chrome (manual, once): chrome://extensions -> enable Developer mode -> Load unpacked -> ~/.omp/browser-relay/extension"
  ```
  `omp browser-relay install` writes the extension to `~/.omp/browser-relay/extension` (its `--dir` default, confirmed from `omp browser-relay --help`) and prints its own setup steps; re-running is idempotent. Placement rationale: `laptop/install.sh` already delegates this whole role via `bash "${DOTFILES_DIR}/installers/forward.sh" daemon`, so the laptop needs no separate edit and the browser-relay deployment has one entry point.

**Verify (devbox, fully sandboxed — never run the daemon role against the real HOME here, and do not re-run the live serve role: this box's `forward-serve` carries live preview/callback traffic):**
```
tmp=$(mktemp -d) && mkdir -p "$tmp/bin" && printf '#!/bin/sh\nexit 0\n' > "$tmp/bin/systemctl" && chmod +x "$tmp/bin/systemctl"
HOME="$tmp" PATH="$tmp/bin:$PATH" DOTFILES_DIR="/home/ubuntu/.dotfiles" bash /home/ubuntu/.dotfiles/installers/forward.sh daemon
readlink -e "$tmp/.config/systemd/user/forward-daemon.service" "$tmp/.config/systemd/user/omp-browser-relay.service"   # both resolve into $DOTFILES_DIR/forward/
readlink "$tmp/.config/forward/config.toml"                    # .../forward/config.toml
test -f "$tmp/.omp/browser-relay/extension/manifest.json" && echo extension-ok
HOME="$tmp" PATH="$tmp/bin:$PATH" DOTFILES_DIR="/home/ubuntu/.dotfiles" bash /home/ubuntu/.dotfiles/installers/forward.sh serve
readlink "$tmp/.config/forward/config.toml"                    # now .../forward/config-serve.toml — serve role unchanged
shellcheck /home/ubuntu/.dotfiles/installers/forward.sh
```
**Laptop-required:** the real `daemon` activation (units actually enabled under the laptop's user systemd) — Task 29.

---

## Task 27 — dotfiles: config edits (forward relay_port, omp relayUrl) with the deployment gate

**Where:** `~/.dotfiles`. **Depends:** file edits none; the two forward TOML edits are **gated on the Phase-1 forward release being installed on both machines** (see below). **Parallel-safe with:** 20, 24, 25 (disjoint files).

1. `forward/config.toml` (laptop role) — after `bridge_port = 12801`:
   ```toml
   # Browser relay channel: devbox agents reach this machine's everyday Chrome
   # through the loopback relay (omp-browser-relay.service). 0 disables.
   relay_port = 12803
   ```
2. `forward/config-serve.toml` (devbox role) — after `forward_ttl_secs = 300`:
   ```toml
   # Browser relay listener is laptop-only; 0 disables the bind on this role.
   relay_port = 0
   ```
3. `omp/config.yml` — add a top-level mapping (no YAML comment: the file is machine-written — its `key: ` trailing-space style shows a serializer owns it, so a comment would not survive the next omp settings write; the rationale lives in commit B's message and here):
   ```yaml
   browser:
     relayUrl: http://100.100.92.97:12803
   ```
   `browser.relay` stays **absent** (= false, the locked decision): agents opt in per call with `app.relay: true`, and the non-loopback URL keeps omp's relay auto-start off.

   **Per-machine note (required):** `relayUrl` is devbox-only in effect but the repo cannot vary this file per machine — `installers/omp.sh` `ensure_link`s the single committed `omp/config.yml` to `~/.omp/agent/config.yml` everywhere. The repo expresses the asymmetry the same way the two forward TOMLs do, by role-side enforcement rather than file divergence: on the laptop the value is inert (relay stays false there too, and any laptop process opting in dials the laptop's own tailnet listener, whose Phase-1 `peer::authorized` accepts only the devbox's literal `peer` address and refuses before a byte). Fail-closed by construction; no overlay mechanism invented.

**Deployment gate (hard):** forward's `Config` is `#[serde(deny_unknown_fields)]` (confirmed against `src/config.rs` by the Phase-1 planner, with a `config_with_retired_ssh_fields_is_refused` test pinning the stance), and these TOMLs are live via symlink the moment they change on disk. Committing `relay_port` while either machine still runs the pre-Phase-1 binary arms a crash-loop on that machine's next `forward` restart. Therefore the two TOML edits land only in gated commit B (Task 28), after `mise upgrade "github:sjawhar/forward"` has installed the Phase-1 release on **both** machines. Gate check, devbox: `~/.dotfiles/bin/mise x -- forward doctor 2>&1 | grep -i relay` prints the new relay row (row presence proves the new binary; the row may still report the channel down). The same check on the laptop is **laptop-required** — do not land commit B on the laptop's behalf without it. The `omp/config.yml` edit is ungated (the `browser.relayUrl` setting exists in current omp releases; only Phase 2's scoping/Host fix is new) and ships in commit A.

**Verify (devbox, after edits):**
```
yq -p toml '.relay_port' ~/.dotfiles/forward/config.toml         # 12803  (calibrated: yq -p toml reads these files; WARN about output format is noise)
yq -p toml '.relay_port' ~/.dotfiles/forward/config-serve.toml   # 0
yq -r '.browser.relayUrl' ~/.omp/agent/config.yml                # http://100.100.92.97:12803 — read through the exact symlink omp consumes
timeout 30 ~/.dotfiles/bin/mise x "github:sjawhar/oh-my-pi" -- omp --version   # exits 0 printing omp/<ver> (baseline today: omp/17.3.8) — the consumer still parses its config
```
Post-gate consumer check: `forward doctor` relay row on each machine (devbox command above; laptop flagged).

---

## Task 28 — dotfiles: commits and push (direct to main, no PR)

**Where:** `~/.dotfiles` (jj; dotfiles ships by direct commit per repo convention — 1-2 described commits, never per-step fragments). **Depends:** commit A on 24, 25, 26 + the omp edit of 27; commit B on 27's TOML edits **and its external gate** (Phase-1 forward release installed on both machines).

- **Commit A (ungated):** `scripts/browser-capture`, `forward/omp-browser-relay`, `forward/omp-browser-relay.service`, `installers/forward.sh`, `omp/config.yml`. Describe: what the capture utility does (cookie → `secrets set-human`, value never printed), that the daemon role now installs two units plus the Chrome extension, and the relayUrl per-machine note from Task 27 (shared file, inert off-devbox, fail-closed by the peer check). `jj describe -m ...` then `jj new`.
- **Commit B (gated):** `forward/config.toml` (+`relay_port = 12803`), `forward/config-serve.toml` (+`relay_port = 0`). Describe the gate that was satisfied (forward release version seen on both machines) so the history shows why the edits trailed commit A.
- Push: `jj bookmark set main -r <commit>` and `jj git push` per the repo's flow — commit A may push immediately; commit B pushes only once its gate holds. If Sami is actively working in the dotfiles repo, leave the changes described in the working copy and say so instead of pushing (repo rule).

**Verify (devbox):**
```
cd ~/.dotfiles && jj log -r 'main | @' --no-graph -T 'commit_id.short() ++ " " ++ description.first_line() ++ "\n"'   # both described commits present in the intended order
jj diff --git -r <commitA> --stat                                                   # exactly the five commit-A paths
jj st                                                                               # no stray uncommitted phase-3 files left behind
```

---

## Task 29 — end-to-end capture verification and store commit (spec Rollout step 3)

**Where:** laptop + devbox + `~/.dotfiles/.secrets` (a separate git repo — NOT part of dotfiles; remote is the private sami repo). **Depends:** 23 (secretsd release installed on devbox), 28 commit A+B deployed, and Phases 1–2 rolled out (channel live, scoped relay release on the laptop). **LAPTOP-REQUIRED — this task cannot run from the devbox alone.** Devbox proxies already banked: Task 24's exit-2/exit-7 checks, Task 26's sandboxed extension install, Task 25's unit verify.

1. **Laptop:** `bash ~/.dotfiles/installers/forward.sh daemon` (installs/enables both units, writes the extension). Human, once, in Chrome: `chrome://extensions` → enable Developer mode → Load unpacked → `~/.omp/browser-relay/extension`. Confirm `systemctl --user status omp-browser-relay` active and `curl -s http://127.0.0.1:9224/json/version` answers (503 until the extension connects; 200 after). Log into a throwaway-suitable real service and drag that tab into the `omp` tab group.
2. **Devbox:** `~/.dotfiles/bin/mise x -- forward doctor` — relay row healthy (extension connected, target count ≥ 1).
3. **Devbox, the capture itself:**
   ```
   ~/.dotfiles/scripts/browser-capture --domain <service-domain> --cookie <cookie-name> --secret TEST_CAPTURE_COOKIE
   ```
   Expected stdout: exactly one line, `stored TEST_CAPTURE_COOKIE (domain ..., expires ...)`; expected file: `~/.dotfiles/.secrets/secrets.human.d/TEST_CAPTURE_COOKIE.local.env` (sops ciphertext, mode 0600). Confirm nothing but the status line reached stdout and the value appears nowhere: `grep -rF '<a distinctive substring the human reads from devtools>' ~/.omp/logs` must not be run — instead compare **hashes** so the value is never displayed at all: devbox `secrets TEST_CAPTURE_COOKIE -- sh -c 'printf %s "$TEST_CAPTURE_COOKIE" | sha256sum'` (this first read costs one YubiKey touch — the deliberate store-unattended/read-gated asymmetry the rollout step names) vs. the human computing the same sha256 over the cookie value shown in the laptop's devtools. Hashes match ⇒ the store decrypts to the browser's value.
   Rotation check: re-run the same capture command; it must succeed again (set-human reports `rotated`), and a fresh `secrets get TEST_CAPTURE_COOKIE --no-request` still reports the key (stale-grant invalidation is the daemon's FileIdentity mechanism — no restart needed).
4. **Store commit (set-human commits nothing by design):** `cd ~/.dotfiles/.secrets && git add secrets.human.d/TEST_CAPTURE_COOKIE.local.env && git commit -m "Add TEST_CAPTURE_COOKIE (browser-capture e2e)"`. If the key was purely a test, instead `git rm` it after verification and commit the removal; drag the tab back out of the `omp` group either way (revocation is immediate).

**Verify:** the outputs of steps 2–3 are the verification (doctor row, single status line, matching hashes, `rotated` on re-run); step 4's `git -C ~/.dotfiles/.secrets log -1 --stat` shows exactly the one ciphertext path.
