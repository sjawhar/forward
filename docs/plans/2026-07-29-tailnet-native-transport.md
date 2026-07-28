# Tailnet-Native Transport Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move the URL channel, the file preview, and OAuth callback forwarding off SSH port forwarding onto direct tailnet connections, so no `ssh -O cancel` can destroy them and the browser channel shares the terminal's transport.

**Architecture:** Each role binds a configured address instead of hardcoded loopback and authorizes inbound connections by comparing the peer address against a configured counterpart. OAuth callbacks keep a loopback listener on the laptop — the provider dictates `localhost` — but its back half becomes an in-process tailnet connection to a single devbox bridge port, which makes the final loopback hop that sshd used to make. `src/forwards.rs` and every `ssh` invocation from the daemon are deleted.

**Tech Stack:** Rust 2024, `std::net` only for transport, `tiny_http` for the file server, `clap` derive for the CLI, `thiserror` in modules, `anyhow` in `main.rs` only.

**Design document:** `docs/design/2026-07-28-tailnet-native-transport.md`. Read it before starting — it carries the threat model and the reasoning behind the devbox hop.

**Why this work exists, verified rather than theorised:** `ssh -O cancel` cancels the forwardings in its effective *configuration*, not just the port named on the command line. The daemon's reaper cancelled expired callback forwards against a host whose ssh_config block declared all three static forwards, so every expiry destroyed the whole tunnel — including the forward carrying the laptop's hardware token — while the master stayed alive and `ssh -O check` still reported success. Reproduced deliberately; a config-only mitigation is deployed and proven. This plan is the structural fix.

## Global Constraints

- Every file under `src/**` and `tests/**` must be **strictly fewer than 250 raw lines** (`wc -l`). CI gate: `scripts/check-source-line-limit.sh`.
- No `unwrap`, `expect`, or `panic!` in non-test code. CI runs a second clippy pass with `-D clippy::unwrap_used -D clippy::expect_used -D clippy::panic`.
- `cargo clippy --all-targets --all-features -- -D warnings` must pass.
- MSRV is 1.88. Let-chains in `if let … &&` form **are** available and already used here (`src/localhost.rs:22`, `src/main.rs:95`).
- Errors: `thiserror` enums inside modules, `anyhow` only in `src/main.rs`.
- **No new runtime dependencies.** `Cargo.toml` `[dependencies]` must not grow.
- Defaults reproduce today's loopback behaviour exactly, so an unconfigured install never opens a tailnet port.
- Peer identity is always a **literal IP address**, never a hostname.
- Tests follow the Given/When/Then comment style in `tests/daemon/builtin_notifier.rs`.
- **One commit per PR.** Each task ends leaving the work in a reviewable working-copy state; there is no per-task commit. The dotfiles changes in Task 12 are a separate repo and do get their own commit.

## Settled decisions — do not relitigate

- **The URL channel port is an explicit parameter**, not a config field: `send::send_url(cfg, url, channel_port)`. This preserves the existing CLI `--port` test seam.
- **No hostname field of any kind.** Always dial the literal `peer` address; self URLs use `listen`. An earlier draft overloaded one `peer_host` field as both counterpart and self, which would have made the devbox mint preview URLs pointing at the laptop.
- **`Config::default_values_for_test()` is `#[doc(hidden)] pub` and unconditional**, never `#[cfg(test)]` — integration-test crates call it, and `#[cfg(test)]` items are not exported to them.
- **Capability tokens and preview sharing are cut.** The mandatory two-node tailnet ACL and phone sharing are mutually exclusive: with the ACL in force a phone cannot reach the port; without it the token becomes the only authorization control for a server that reads any file the user can read, which needs a CSPRNG the no-new-dependencies constraint forbids. Preview is laptop-only. Sharing needs its own plan.
- **The PC/SC forward (12799) stays on SSH** and is out of scope. On the devbox, loopback 12799 is the far end of the tunnel carrying the laptop's hardware token, so the bridge denylist must refuse it above all else.

## Coordinator notes — cross-task seams resolved after review

These resolve conflicts between tasks written independently. They override the task text where they disagree.

1. **The port constants have exactly one owner: Task 7.** `PCSC_PORT`, `CHANNEL_PORT` and `FILES_PORT` live in `src/forwards.rs` today (binary-private) and are relocated to `pub const` items in the library module `callback` by **Task 7**. Task 11's Interfaces block also lists them under Produces; that is wrong and is superseded by this note — Task 11 **consumes** them.
2. **Task 7 deletes `src/forwards.rs` outright**, rather than leaving it for Task 11. Task 7 replaces everything in it: the lease tracker becomes `callback::Leases`, the reaper becomes `callback::spawn_reaper`, and the constants move to `callback`. Leaving the file in place would leave unused `pub const` items and an unused `ForwardTracker` in a binary-private module, which `-D warnings` rejects as dead code and would fail CI at the end of Task 7. Task 11 therefore covers only: removing any remaining `ssh` invocation, keeping `ssh` and `tunnel_host` as deprecated ignored config fields, and proving with a grep that no `ssh` invocation survives. Its "delete `src/forwards.rs`" step is satisfied by Task 7 — verify and move on rather than re-deleting.
3. **`src/main.rs`'s clap defaults follow the constants.** Task 0 records that `main.rs` uses `CHANNEL_PORT` and `FILES_PORT` from `forwards` for its defaults; Task 7 must repoint those to `callback::CHANNEL_PORT` and `callback::FILES_PORT` in the same task that relocates them, or the build breaks between tasks.
4. **Task 10 consumes the constants from `callback`** (Task 7), not from `forwards`.
5. **Line-limit headroom is tighter than it looks, and the gate counts raw lines.** `scripts/check-source-line-limit.sh` uses `wc -l` and fails at `>= 250`. Measured after Task 0: `src/serve.rs` **217/250 (33 lines left)**, `tests/serve.rs` **227/250 (23 left)**, `src/main.rs` 156, `tests/open.rs` 72, `src/lib.rs` 7. Tasks 5, 6, 8 and 9 all add code or tests into `serve.rs` and `tests/serve.rs` specifically — budget against those raw numbers, not against a non-blank count, and split into a submodule the moment you would exceed them. Task 9 already plans `src/serve/security.rs` for exactly this reason.
6. **Do not "restore" the brief snippets' import order.** There is no `rustfmt.toml`, so `reorder_imports = true` applies and `crate::*` sorts before `forward::*`. Several task snippets show the opposite order. The formatter is right and the snippets are wrong: `cargo fmt --all -- --check` is a CI gate, so follow rustfmt and let the snippet differ. Same for where rustfmt chooses to break a long `let`.
7. **Adding a module to `src/lib.rs`:** insert `pub mod <name>;` alphabetically **among the `pub mod` entries only**. `mod render;` is private and stays between `policy` and `send` where it is — do not treat it as part of the alphabetical run, and do not make it public. Tasks 2, 3, 4, 7 and 10 each add one module this way.
9. **`pipe::bidirectional` has no liveness bound — Tasks 5 and 7 must supply one.** Established by review of Task 3, and it needs no change there. When one direction finishes, `shutdown(dest, Write)` sends FIN but does **not** wake a reader already parked on the *other* socket. So if the caller's direction completes while the spawned direction is blocked on a read that never returns, the spawned thread stays parked and the caller then blocks forever in `join()` — two stuck threads per connection. This is reachable in normal operation: an upstream that replies and closes while the client holds its write half open and idle. It cannot be fixed inside `bidirectional`, because forcing `Shutdown::Read` on the surviving socket would truncate a legitimate in-flight transfer.

   **Therefore, before either task hands a pair of sockets to `pipe::bidirectional`, set a read timeout on both** (`TcpStream::set_read_timeout`) or arm an equivalent deadline, so a parked read fails instead of hanging. Task 5's bridge already sets a read timeout for parsing the `CONNECT` line and then clears it with `set_read_timeout(None)` before piping — that clear is exactly the mistake: replace it with a generous per-connection deadline rather than no deadline. This project has already lost a tunnel and a callback port to leaked resources twice; an unbounded thread per connection in a long-lived daemon is the same failure wearing a different hat.

8. **Task 9 must rename `spawn_serve`'s `root_marker` parameter to `config_root`** in `tests/serve.rs`, and give the serve tests a config directory separate from the directory they serve over HTTP. After Task 0 that one tempdir is both the process's config root *and* the tree the tests list and fetch, so writing a `forward/config.toml` into it would make the config file itself a served, listed entry and break the directory-listing assertions in `serves_files_dirs_and_markdown`. Nothing is broken today because no test creates a `forward/` subdirectory; Task 9 is the first task that needs a serve test with a real config, so it closes this.

---

### Task 0: Library target extraction

The crate is binary-only: `src/main.rs` declares every module and there is no
`src/lib.rs`, so `cargo test --lib` matches no target and integration tests cannot
`use forward::…`. Every later task depends on the library existing, and Tasks 5, 6, 8
and 9 need a `Config` on the `serve`/`open` code paths that today have no `--config`
flag. This task creates the library target, settles the public module list, and threads
config into `open_target` and `serve::run`. It changes no behaviour.

**Files:**

- Create: `src/lib.rs`
- Modify: `src/main.rs` (module list → `use forward::…`; `--config` on `Serve` and
  `Open`; `load_config` helper; `&Config` into `open_target`)
- Modify: `src/serve.rs` (`run` takes `&Config`)
- Modify: `src/daemon.rs`, `src/daemon/notification.rs`, `src/forwards.rs`
  (`use crate::…` → `use forward::…` for modules that moved into the library)
- Modify: `.github/workflows/ci.yml` (strict clippy pass must keep covering the moved
  modules)
- Test: `tests/open.rs` (new `--config` seam test; pin the config root of the existing
  re-entry test)
- Test: `tests/serve.rs` (pin the config root in `spawn_serve`)

**Interfaces:**

Consumes: nothing. This is the first task.

Produces:

- **Library crate `forward`** (`src/lib.rs`), auto-discovered by cargo — no
  `Cargo.toml` change, no new dependency. Public modules, reachable from integration
  tests and from the binary as `forward::<name>`:

  ```rust
  pub mod config;
  pub mod localhost;
  pub mod policy;
  mod render;
  pub mod send;
  pub mod serve;
  pub mod target;
  ```

  `render` is deliberately private to the library: only `serve` uses it, and its items
  are `pub(crate)`.

- **How later tasks add a module to the library:** add `pub mod <name>;` to
  `src/lib.rs` in the task that creates it, keeping the list alphabetical among the
  `pub mod` entries. Library code refers to siblings as `crate::<name>`; binary code
  (`src/main.rs`, `src/daemon.rs`, `src/daemon/notification.rs`, `src/forwards.rs`)
  refers to them as `forward::<name>`. Tasks 2, 3, 4 and 7 create `peer`, `pipe`,
  `bridge` and `callback` this way.

- **Public library signatures available after this task** (unchanged from today except
  `serve::run`):

  ```rust
  forward::config::Config                  // struct, serde::Deserialize + Debug + Clone
  forward::config::Mode                     // enum { Allowlist, Auto }
  forward::config::ConfigError              // enum { Read { .. }, Parse { .. } }
  forward::config::load(path: &std::path::Path) -> Result<Config, ConfigError>
  forward::localhost::forward_ports(url: &url::Url) -> Vec<u16>
  forward::policy::Decision                 // enum { Open, Notify }
  forward::policy::decide(cfg: &Config, url: &url::Url) -> Decision
  forward::policy::allow_matches(pattern: &str, url: &url::Url) -> bool
  forward::send::SendError                  // enum { TunnelDown, Io(..) }
  forward::send::send_url(url: &url::Url, channel_port: u16) -> Result<(), SendError>
  forward::send::osc52_copy(text: &str) -> std::io::Result<()>
  forward::serve::ServeError                // enum { Bind { .. }, ListenerClosed }
  forward::serve::run(_cfg: &Config, port: u16) -> Result<(), ServeError>
  forward::target::TargetError              // enum { NotFound, Invalid, UnsupportedScheme }
  forward::target::to_url(arg: &str, files_port: u16) -> Result<url::Url, TargetError>
  ```

- **Binary-private modules** (declared in `src/main.rs`, *not* in the library, not
  reachable from integration tests): `daemon` and its submodule `daemon::notification`,
  plus `forwards`, `process`, `ratelimit` and `request`. `tests/daemon/*` drives the
  daemon through `env!("CARGO_BIN_EXE_forward")` as a subprocess
  (`tests/daemon/daemon_support.rs:65`) and no test file names `forward::`, so nothing
  needs the daemon in the library.

- **Binary-private port constants** stay in `src/forwards.rs`:
  `pub const PCSC_PORT: u16 = 12_799;`, `pub const CHANNEL_PORT: u16 = 12_800;`,
  `pub const FILES_PORT: u16 = 12_802;`. The task that replaces `src/forwards.rs` must
  relocate whichever of these still have callers; `src/main.rs` uses `CHANNEL_PORT` and
  `FILES_PORT` for its clap defaults.

- **`src/main.rs` items** later tasks extend:

  ```rust
  fn open_target(
      _cfg: &Config,
      target: &str,
      channel_port: u16,
      opener_reentry: bool,
  ) -> anyhow::Result<()>

  fn load_config(path: Option<std::path::PathBuf>) -> anyhow::Result<(Config, std::path::PathBuf)>
  fn default_config_path() -> anyhow::Result<std::path::PathBuf>
  fn exit_with_error(error: impl std::fmt::Display) -> !
  ```

  `_cfg` in `open_target` and in `serve::run` is underscore-prefixed **because nothing
  reads it yet** and `-D warnings` rejects an unused non-underscore binding. The first
  task to read a field renames the parameter to `cfg`.

- **CLI surface:** `--config <PATH>` is an optional flag on `open`, `serve` and
  `daemon`. Omitted, it resolves through `default_config_path()`
  (`$XDG_CONFIG_HOME/forward/config.toml`, else `$HOME/.config/forward/config.toml`);
  a missing file yields `Config` defaults, a malformed file exits 1.

- **CI:** the strict no-unwrap clippy pass is `--lib --bins` (was `--bins`).

**Steps:**

- [ ] **Step 1: Record the baseline the refactor must preserve.** This is a pure
  refactor, so the existing suite is the test. Capture the counts before touching
  anything:

  ```bash
  cargo test --all
  ```

  Expected: four test binaries, all green, **97 tests total** —
  `unittests src/main.rs` 58 passed, `tests/daemon.rs` 28 passed, `tests/open.rs`
  2 passed, `tests/serve.rs` 9 passed. There is no `Doc-tests` section, because there
  is no library target yet. Write these five numbers down; Step 9 compares against
  them.

- [ ] **Step 2: Write the failing test for the one seam this task introduces.** The
  module move is proven by the unchanged suite, but `--config` on `serve` and `open` is
  new behaviour with no coverage. Append to `tests/open.rs`:

  ```rust
  #[test]
  fn config_flag_loads_the_named_file_for_serve_and_open() {
      // Given: two rejectable config files — one named explicitly, one at the default path.
      let config_root = tempfile::tempdir().unwrap();
      let named = config_root.path().join("named.toml");
      std::fs::write(&named, "named_file_is_not_a_setting = true\n").unwrap();
      let default_dir = config_root.path().join("forward");
      std::fs::create_dir(&default_dir).unwrap();
      std::fs::write(
          default_dir.join("config.toml"),
          "default_file_is_not_a_setting = true\n",
      )
      .unwrap();

      // When: serve and open are pointed at the named file with --config.
      let serve = Command::new(env!("CARGO_BIN_EXE_forward"))
          .args(["serve", "--port", "0", "--config"])
          .arg(&named)
          .env("XDG_CONFIG_HOME", config_root.path())
          .output()
          .unwrap();
      let open = Command::new(env!("CARGO_BIN_EXE_forward"))
          .args(["open", "https://example.com/x", "--config"])
          .arg(&named)
          .env("XDG_CONFIG_HOME", config_root.path())
          .output()
          .unwrap();

      // Then: both refuse to start and name the file from --config, not the default one.
      for output in [serve, open] {
          assert!(!output.status.success());
          let stderr = String::from_utf8_lossy(&output.stderr);
          assert!(stderr.contains("failed to parse config"));
          assert!(stderr.contains(named.to_str().unwrap()));
          assert!(!stderr.contains("forward/config.toml"));
      }
  }
  ```

  Both files are malformed on purpose: whichever one gets loaded, the process exits
  immediately, so a wrong implementation fails the assertion instead of hanging on a
  bound `serve`. The path in the error message is what discriminates.

- [ ] **Step 3: Run the new test and confirm the expected failure.**

  ```bash
  cargo test --test open config_flag_loads_the_named_file_for_serve_and_open
  ```

  Expected: `test result: FAILED. 0 passed; 1 failed`. It panics on
  `assert!(stderr.contains("failed to parse config"))`, because clap does not yet know
  the flag and exits 2 with
  `error: unexpected argument '--config' found`.

- [ ] **Step 4: Create `src/lib.rs`.** Cargo auto-discovers it as the `forward` library
  target; no `Cargo.toml` change.

  ```rust
  pub mod config;
  pub mod localhost;
  pub mod policy;
  mod render;
  pub mod send;
  pub mod serve;
  pub mod target;
  ```

  `render` stays private: `src/serve.rs:3` is its only consumer and its items are
  `pub(crate)`, which now means library-crate-visible. `src/policy.rs` keeps
  `#[cfg(test)] mod tests;` and `src/policy/tests.rs` keeps its `crate::config::…`
  paths — both are inside the library now, so `crate::` still resolves. `src/serve.rs`
  keeps `mod file_handler;` and `src/serve/file_handler.rs` keeps its `use super::…`.

- [ ] **Step 5: Rewrite `src/main.rs`.** It stops declaring the moved modules, imports
  them from the library, gains `--config` on `Serve` and `Open`, and grows one
  `load_config` helper that is exactly the sequence the `Daemon` arm used inline, so
  daemon behaviour is byte-identical. Full file:

  ```rust
  use clap::{Parser, Subcommand};
  use forward::config::{self, Config};
  use forward::{send, serve, target};
  use std::io::Write as _;

  mod daemon;
  mod forwards;
  mod process;
  mod ratelimit;
  mod request;

  use forwards::CHANNEL_PORT;
  pub(crate) use forwards::FILES_PORT;
  const OPENER_REENTRY_ERROR: &str = "forward: refusing to open URL because the configured opener is routing back into forward open; set opener to an absolute path such as /usr/bin/xdg-open";

  #[derive(Parser)]
  #[command(
      name = "forward",
      version,
      about = "Open devbox URLs and files in the laptop browser"
  )]
  struct Cli {
      #[command(subcommand)]
      command: Command,
  }

  #[derive(Subcommand)]
  enum Command {
      /// Open a URL or file path in the laptop browser
      Open {
          target: String,
          #[arg(long)]
          config: Option<std::path::PathBuf>,
      },
      /// Print (and OSC 52 copy) the laptop-clickable URL for a file path
      Url { target: String },
      /// Serve devbox files read-only on loopback (devbox side)
      Serve {
          #[arg(long, default_value_t = FILES_PORT)]
          port: u16,
          #[arg(long)]
          config: Option<std::path::PathBuf>,
      },
      /// Receive URLs from the devbox and open them (laptop side)
      Daemon {
          #[arg(long, default_value_t = CHANNEL_PORT)]
          port: u16,
          #[arg(long)]
          config: Option<std::path::PathBuf>,
      },
  }

  fn main() -> anyhow::Result<()> {
      let cli = Cli::parse();
      match cli.command {
          Command::Open { target, config } => {
              let (cfg, _) = load_config(config)?;
              open_target(
                  &cfg,
                  &target,
                  CHANNEL_PORT,
                  std::env::var_os("FORWARD_OPENER_REENTRY").is_some(),
              )
              .unwrap_or_else(|error| exit_with_error(error));
              Ok(())
          }
          Command::Url { target } => {
              let url = target::to_url(&target, FILES_PORT).unwrap_or_else(|e| exit_with_error(e));
              let _ = writeln!(std::io::stdout(), "{url}");
              let _ = send::osc52_copy(url.as_str());
              Ok(())
          }
          Command::Serve { port, config } => {
              let (cfg, _) = load_config(config)?;
              serve::run(&cfg, port).unwrap_or_else(|error| exit_with_error(error));
              Ok(())
          }
          Command::Daemon { port, config } => {
              let (cfg, config_path) = load_config(config)?;
              daemon::run(cfg, &config_path, port).unwrap_or_else(|error| exit_with_error(error));
              Ok(())
          }
      }
  }

  fn open_target(
      _cfg: &Config,
      target: &str,
      channel_port: u16,
      opener_reentry: bool,
  ) -> anyhow::Result<()> {
      if opener_reentry {
          anyhow::bail!(OPENER_REENTRY_ERROR);
      }
      let url = target::to_url(target, FILES_PORT)?;
      send::send_url(&url, channel_port)?;
      Ok(())
  }

  fn load_config(path: Option<std::path::PathBuf>) -> anyhow::Result<(Config, std::path::PathBuf)> {
      let config_path = std::path::absolute(path.unwrap_or_else(|| {
          default_config_path().unwrap_or_else(|error| exit_with_error(error))
      }))?;
      let cfg = config::load(&config_path).unwrap_or_else(|error| exit_with_error(error));
      Ok((cfg, config_path))
  }

  fn default_config_path() -> anyhow::Result<std::path::PathBuf> {
      if let Some(path) = std::env::var_os("XDG_CONFIG_HOME").map(std::path::PathBuf::from)
          && !path.as_os_str().is_empty()
          && path.is_absolute()
      {
          return Ok(path.join("forward/config.toml"));
      }
      if let Some(path) = std::env::var_os("HOME").map(std::path::PathBuf::from)
          && !path.as_os_str().is_empty()
          && path.is_absolute()
      {
          return Ok(path.join(".config/forward/config.toml"));
      }
      anyhow::bail!(
          "forward: cannot resolve config path: XDG_CONFIG_HOME and HOME are unset or not an absolute path"
      )
  }

  fn exit_with_error(error: impl std::fmt::Display) -> ! {
      eprintln!("{error}");
      std::process::exit(1)
  }

  #[cfg(test)]
  mod tests {
      use super::{config, open_target};
      use std::io::Read as _;

      #[test]
      fn open_sends_url_when_opener_reentry_is_unset() {
          // Given: a default configuration and a listener for the opener channel.
          let cfg = config::load(std::path::Path::new("/no/such/config.toml")).unwrap();
          let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
          let port = listener.local_addr().unwrap().port();
          let receiver = std::thread::spawn(move || {
              let (mut stream, _) = listener.accept().unwrap();
              let mut received = String::new();
              stream.read_to_string(&mut received).unwrap();
              received
          });

          // When: open runs without the re-entry marker.
          open_target(&cfg, "https://example.com/redirect", port, false).unwrap();

          // Then: it sends the URL through the opener channel.
          assert_eq!(receiver.join().unwrap(), "https://example.com/redirect\n");
      }
  }
  ```

  The unit test gets its `Config` from `config::load` on a deliberately absent path,
  which returns defaults — no new constructor, so this does not preempt the
  `default_values_for_test()` interface a later task adds.

- [ ] **Step 6: Repoint the binary-private modules at the library.** Five `use` lines,
  three files; every other line in these files is untouched.

  `src/daemon.rs` — lines 1, 3 and 4 change; lines 2, 5 and 6 keep `crate::` because
  `forwards`, `ratelimit` and `request` are still binary modules:

  ```rust
  use forward::config::Config;
  use crate::forwards::{ForwardTracker, is_dynamic_port, request_forward, spawn_reaper};
  use forward::localhost::forward_ports;
  use forward::policy::{Decision, decide};
  use crate::ratelimit::{OpenDecision, RecentOpens};
  use crate::request::read_url;
  ```

  `src/daemon/notification.rs` — line 1 changes, line 2 keeps `crate::process`:

  ```rust
  use forward::config::Config;
  use crate::process::{WaitResult, run_command, stderr};
  ```

  `src/forwards.rs` — line 1 changes, line 2 keeps `crate::process`:

  ```rust
  use forward::config::Config;
  use crate::process::{WaitResult, run_command, stderr};
  ```

- [ ] **Step 7: Thread `&Config` into `serve::run`.** In `src/serve.rs`, add the import
  after `mod file_handler;` and its blank line, above the existing `crate::render`
  import:

  ```rust
  use crate::config::Config;
  ```

  and change the signature at what is currently line 93 from
  `pub fn run(port: u16) -> Result<(), ServeError> {` to:

  ```rust
  pub fn run(_cfg: &Config, port: u16) -> Result<(), ServeError> {
  ```

  The body is unchanged: it still binds `("127.0.0.1", port)` and still logs
  `forward: loopback server listening on {}`, which `tests/serve.rs:46` parses.

- [ ] **Step 8: Pin the config root of the two integration tests that now load
  config.** `forward open` and `forward serve` previously read no config file; they do
  now, so tests exercising them must not depend on the developer's real
  `~/.config/forward/config.toml`.

  In `tests/serve.rs`, `spawn_serve` already receives the caller's tempdir but discards
  it. Use it as the config root and delete the discard — replace
  `let _ = root_marker;` (line 49) by removing that line, and add the env var to the
  spawn (lines 20-24 become):

  ```rust
      let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_forward"))
          .args(["serve", "--port", "0"])
          .env("XDG_CONFIG_HOME", root_marker)
          .stderr(Stdio::piped())
          .spawn()
          .unwrap();
  ```

  The tempdir contains no `forward/config.toml`, so `serve` gets `Config` defaults
  silently and the startup line is unchanged. All nine serve tests, including those in
  `tests/serve/host.rs` and `tests/serve/limits.rs`, go through `spawn_serve`, so this
  is the only place to change.

  In `tests/open.rs`, `open_refuses_opener_reentry_before_connecting` asserts
  `stderr.lines().count() == 1`; give it an empty config root so no parse error can
  join that line:

  ```rust
  #[test]
  fn open_refuses_opener_reentry_before_connecting() {
      // Given: an opener child launched by the daemon, with an empty config root.
      let config_root = tempfile::tempdir().unwrap();
      let mut command = Command::new(env!("CARGO_BIN_EXE_forward"));
      command
          .args(["open", "https://example.com/redirect"])
          .env("XDG_CONFIG_HOME", config_root.path())
          .env("FORWARD_OPENER_REENTRY", "1");
  ```

  The rest of that test is unchanged. `tests/daemon/*` needs nothing: it already passes
  `--config` explicitly, and its opener stub loops back over `/dev/tcp` rather than
  invoking `forward open`.

- [ ] **Step 9: Keep the strict clippy pass covering the moved modules.**
  `.github/workflows/ci.yml:32` runs the no-unwrap pass with `--bins`, which lints only
  binary targets. Extracting the library would silently drop `config`, `localhost`,
  `policy`, `render`, `send`, `serve` and `target` from that pass. Change lines 31-34
  to:

  ```yaml
        - run: >-
            cargo clippy --locked --lib --bins --all-features --
            -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic
            -D clippy::indexing_slicing
  ```

  Neither `--lib` nor `--bins` compiles under `cfg(test)`, so `#[cfg(test)] mod tests`
  blocks stay exempt, exactly as before.

- [ ] **Step 10: Run the suite and confirm the baseline is preserved.**

  ```bash
  cargo fmt --all
  cargo test --all
  ```

  Expected: **98 tests total**, all green — Step 1's 97 plus the one new test.
  The pre-existing 58 unit tests are now split across two binaries by where their module
  landed, and their sum is unchanged:

  ```
  Running unittests src/lib.rs   → test result: ok. 51 passed  (config 5, localhost 9,
                                    policy 23, send 4, target 10)
  Running unittests src/main.rs  → test result: ok. 7 passed   (main 1, process 3,
                                    ratelimit 2, daemon::notification 1)
  Running tests/daemon.rs        → test result: ok. 28 passed
  Running tests/open.rs          → test result: ok. 3 passed
  Running tests/serve.rs         → test result: ok. 9 passed
  Doc-tests forward              → test result: ok. 0 passed
  ```

  `51 + 7 = 58` matches Step 1's single `unittests src/main.rs` count, and
  `28 + 3 + 9 = 40` is Step 1's 39 integration tests plus the new one. The
  `Doc-tests forward` section is new and empty: it appears because a library target now
  exists, and no doc comment in the crate contains a code fence. If any count differs,
  a module landed on the wrong side of the split — fix the split, do not adjust a test.

- [ ] **Step 11: Verify the constraints.**

  ```bash
  cargo clippy --all-targets --all-features -- -D warnings
  cargo clippy --locked --lib --bins --all-features -- \
    -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic \
    -D clippy::indexing_slicing
  cargo fmt --all -- --check
  bash scripts/check-source-line-limit.sh
  ```

  All four must exit 0 with no output beyond cargo's progress lines. The line-limit
  script fails at 250; after this task `src/lib.rs` is 7 lines, `src/main.rs` 155,
  `src/serve.rs` 217, `tests/open.rs` 72, and `tests/serve.rs` stays at 227 (one line
  removed, one added). `Cargo.toml` `[dependencies]` is untouched.

---

### Task 1: Configuration surface

**Files:**
- Modify: `src/config.rs`
- Create: `src/config/tests.rs` (the existing `mod tests` block moves here)
- Create: `tests/config_visibility.rs`
- Test: `src/config/tests.rs`, `tests/config_visibility.rs`

**Interfaces:**

- Consumes:
  - Task 0: `src/lib.rs` exists and declares `pub mod config;`, so `cargo test --lib config` discovers these tests and the integration crate can name `forward::config::Config`.
- Produces:
  - New `Config` fields, all `pub`, all with serde defaults, `deny_unknown_fields` retained:
    - `pub listen: String` — this machine's bind address. Default `"127.0.0.1"`.
    - `pub peer: String` — the counterpart's literal tailnet address. Default `""`, meaning loopback only.
    - `pub bridge_port: u16` — the devbox callback-bridge port. Default `12801`.
  - Pre-existing and unchanged: `pub forward_ttl_secs: u64` (default `300`), `pub mode: Mode`, `pub opener`, `pub notifier`, `pub clipboard`, `pub ssh`, `pub tunnel_host`, `pub allow`.
  - `Config::listen_ip(&self) -> Result<std::net::IpAddr, ConfigError>`
  - `Config::peer_ip(&self) -> Result<Option<std::net::IpAddr>, ConfigError>`
  - `Config::validate(&self) -> Result<(), ConfigError>`
  - `Config::default_values_for_test() -> Config` — **`#[doc(hidden)] pub` and unconditional, never `#[cfg(test)]`.** Task 2 onward, including integration tests under `tests/`, build a `Config` with this and then assign fields.
  - `ConfigError::Address { field: &'static str, value: String }`
  - `ConfigError::PeerRequired`
- Produces deliberately **not** in this task — later tasks must not reach for them:
  - **No `channel_port` field, and no `channel_port_for_test`.** The URL channel port stays an explicit parameter: `send::send_url(cfg: &Config, url: &Url, channel_port: u16)` in Task 8. That preserves the existing CLI `--port` seam, which is how tests already point `forward open` at a stub listener. A test that writes `cfg.channel_port_for_test` will not compile; pass the port as the third argument instead.
  - **No hostname field of any kind — no `peer_host`, no `listen_host`.** Two rules make one unnecessary. Outbound: always dial the literal `peer` address, so no name is ever resolved for a connection. Self-referential: a URL naming *this* machine is built from `listen`, so `forward url` on the devbox and the `Host` check in `serve` both read `listen` and never a peer field. A field that is neither dialled nor displayed is dead config, and under `deny_unknown_fields` a field nobody sets is also a config-compat liability, so it is not added.

- [ ] **Step 1: Move the existing tests into a submodule so the file stays under the line limit**

`src/config.rs` is 152 raw lines today, 55 of them the `#[cfg(test)] mod tests` block at lines 98-152. The transport fields, error variants, accessors, `validate`, and the test constructor added below come to roughly 60 more lines of non-test code, and the new tests to roughly 60 more. Left in one file that lands near 270 raw lines, over the 250 limit enforced by `scripts/check-source-line-limit.sh`. Split first, so no later step has to.

Delete the whole `#[cfg(test)] mod tests { … }` block from the end of `src/config.rs` and put this in its place:

```rust
#[cfg(test)]
mod tests;
```

Create `src/config/tests.rs` with the five moved tests, dedented one level. `super::*` still resolves to the `config` module, so nothing else changes. This mirrors the existing `src/policy.rs` + `src/policy/tests.rs` pair.

```rust
use super::*;

#[test]
fn missing_file_gives_defaults() {
    let cfg = load(std::path::Path::new("/no/such/config.toml")).unwrap();
    assert_eq!(cfg.mode, Mode::Allowlist);
    assert_eq!(cfg.opener, vec!["xdg-open".to_string()]);
    assert!(cfg.allow.is_empty());
}

#[test]
fn parses_full_config() {
    let f = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(
        &f,
        r#"
mode = "auto"
opener = ["firefox"]
allow = ["localhost", "*.awsapps.com"]
"#,
    )
    .unwrap();
    let cfg = load(f.path()).unwrap();
    assert_eq!(cfg.mode, Mode::Auto);
    assert_eq!(cfg.opener, vec!["firefox".to_string()]);
    assert!(cfg.notifier.is_empty());
    assert_eq!(cfg.ssh, vec!["ssh".to_string()]);
    assert_eq!(cfg.tunnel_host, "devbox-tunnel");
    assert_eq!(cfg.forward_ttl_secs, 300);
    assert_eq!(cfg.allow.len(), 2);
}

#[test]
fn unknown_field_errors() {
    let f = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(&f, "moed = \"auto\"\n").unwrap();
    assert!(load(f.path()).is_err());
}

#[test]
fn malformed_toml_errors() {
    let f = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(&f, "mode = [\n").unwrap();
    assert!(load(f.path()).is_err());
}

#[test]
fn directory_errors_as_read() {
    let directory = tempfile::tempdir().unwrap();
    let err = load(directory.path()).unwrap_err();
    assert!(matches!(err, ConfigError::Read { .. }));
}
```

Run: `cargo test --lib config`
Expected: PASS, 5 tests. This step is a pure move; a failure here means the move was not faithful.

- [ ] **Step 2: Write the failing tests**

Append to `src/config/tests.rs`:

```rust
#[test]
fn defaults_are_loopback() {
    // Given: no configuration file.
    let cfg = load(std::path::Path::new("/no/such/config.toml")).unwrap();

    // When: the transport addresses are resolved.
    // Then: they reproduce today's loopback-only behaviour, so an
    // unconfigured install never opens a tailnet port.
    assert_eq!(cfg.listen, "127.0.0.1");
    assert!(cfg.peer.is_empty());
    assert_eq!(cfg.bridge_port, 12_801);
    assert_eq!(cfg.listen_ip().unwrap().to_string(), "127.0.0.1");
    assert_eq!(cfg.peer_ip().unwrap(), None);
}

#[test]
fn parses_transport_fields() {
    // Given: both addresses written as literal tailnet addresses.
    let f = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(
        &f,
        "listen = \"100.64.0.1\"\npeer = \"100.64.0.2\"\nbridge_port = 12345\n",
    )
    .unwrap();

    // When: the file is loaded.
    let cfg = load(f.path()).unwrap();

    // Then: each address parses and the bridge port is honoured.
    assert_eq!(cfg.listen_ip().unwrap().to_string(), "100.64.0.1");
    assert_eq!(cfg.peer_ip().unwrap().unwrap().to_string(), "100.64.0.2");
    assert_eq!(cfg.bridge_port, 12_345);
}

#[test]
fn non_literal_peer_is_rejected() {
    // Given: a peer given as a name rather than a literal address.
    let f = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(&f, "peer = \"box.example.ts.net\"\n").unwrap();

    // When: the peer address is resolved.
    let cfg = load(f.path()).unwrap();

    // Then: it is refused, because a name is mutable from the Tailscale admin
    // console and must never sit inside an identity check.
    assert!(matches!(
        cfg.peer_ip(),
        Err(ConfigError::Address { field: "peer", .. })
    ));
}

#[test]
fn non_loopback_listen_requires_a_peer() {
    // Given: a tailnet listen address with no counterpart configured.
    let f = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(&f, "listen = \"100.64.0.1\"\n").unwrap();

    // When: the configuration is validated.
    let cfg = load(f.path()).unwrap();

    // Then: it fails closed rather than exposing an unauthenticated port.
    assert!(matches!(cfg.validate(), Err(ConfigError::PeerRequired)));
}

#[test]
fn loopback_listen_needs_no_peer() {
    // Given: the default, loopback-only configuration.
    let cfg = load(std::path::Path::new("/no/such/config.toml")).unwrap();

    // When: it is validated.
    // Then: it is accepted — loopback confinement needs no counterpart.
    assert!(cfg.validate().is_ok());
}

#[test]
fn test_constructor_matches_file_defaults() {
    // Given: nothing on disk.
    // When: the constructor later tasks' tests build a Config with is called.
    let cfg = Config::default_values_for_test();

    // Then: it agrees with the on-disk defaults, so a test starting from it
    // exercises the same fail-closed configuration a real install gets.
    assert_eq!(cfg.listen, "127.0.0.1");
    assert!(cfg.peer.is_empty());
    assert_eq!(cfg.bridge_port, 12_801);
    assert_eq!(cfg.forward_ttl_secs, 300);
    assert!(cfg.validate().is_ok());
}
```

The unit test above cannot catch the visibility mistake this task exists to prevent — a `#[cfg(test)]` constructor resolves fine from inside the crate's own test build and only fails from a separate test crate. So create `tests/config_visibility.rs`, which is compiled as its own crate and is the real regression test:

```rust
#[test]
fn test_constructor_is_visible_to_integration_tests() {
    // Given: an integration-test crate, which links the library normally and
    // therefore cannot see any `#[cfg(test)]` item inside it.

    // When: it builds a Config through the doc-hidden constructor.
    let cfg = forward::config::Config::default_values_for_test();

    // Then: it compiles and yields the fail-closed defaults. If someone marks
    // the constructor `#[cfg(test)]`, this file stops compiling, which is the
    // point: Tasks 2 and 5 onward call it from exactly here.
    assert_eq!(cfg.listen, "127.0.0.1");
    assert!(cfg.peer.is_empty());
    assert!(cfg.validate().is_ok());
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test --lib config`
Expected: FAIL to compile — `error[E0609]: no field 'listen' on type 'Config'`, and `error[E0599]: no function or associated item named 'default_values_for_test' found for struct 'Config'`.

Run: `cargo test --test config_visibility`
Expected: FAIL to compile — `error[E0599]: no function or associated item named 'default_values_for_test' found for struct 'Config'`.

- [ ] **Step 4: Implement**

Add the three transport fields to the `Config` struct in `src/config.rs`, after `forward_ttl_secs` and before `allow`. Keep `#[serde(deny_unknown_fields)]` on the struct: a typo in a transport address must be an error, not a silent loopback fallback.

```rust
    #[serde(default = "default_listen")]
    pub listen: String,
    #[serde(default)]
    pub peer: String,
    #[serde(default = "default_bridge_port")]
    pub bridge_port: u16,
```

Add two variants to `ConfigError`:

```rust
    #[error("forward: {field} must be a literal IP address, got {value:?}")]
    Address { field: &'static str, value: String },
    #[error("forward: a non-loopback listen address requires an explicit peer")]
    PeerRequired,
```

Add the defaults and the shared parser next to the existing `default_*` functions:

```rust
fn default_listen() -> String {
    "127.0.0.1".to_owned()
}

fn default_bridge_port() -> u16 {
    12_801
}

fn parse_ip(field: &'static str, value: &str) -> Result<std::net::IpAddr, ConfigError> {
    value.parse().map_err(|_| ConfigError::Address {
        field,
        value: value.to_owned(),
    })
}
```

Extend the existing `impl Config` block:

```rust
    pub fn listen_ip(&self) -> Result<std::net::IpAddr, ConfigError> {
        parse_ip("listen", &self.listen)
    }

    /// The counterpart's address, or `None` when none is configured.
    ///
    /// Always a literal address. There is no hostname counterpart to this
    /// field: every outbound connection dials this literal value, so no name
    /// is ever resolved and no DNS or admin-console state can move the
    /// identity the inbound check in `peer::authorized` compares against.
    pub fn peer_ip(&self) -> Result<Option<std::net::IpAddr>, ConfigError> {
        if self.peer.is_empty() {
            return Ok(None);
        }
        parse_ip("peer", &self.peer).map(Some)
    }

    /// Fail closed: a routable listen address without a named counterpart
    /// would accept anything that can reach it.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let listen = self.listen_ip()?;
        let peer = self.peer_ip()?;
        if !listen.is_loopback() && peer.is_none() {
            return Err(ConfigError::PeerRequired);
        }
        Ok(())
    }

    /// Build the on-disk defaults without touching the filesystem.
    ///
    /// `#[doc(hidden)] pub` and deliberately **not** `#[cfg(test)]`: the
    /// integration tests under `tests/` are separate crates that link this one
    /// normally, so a `#[cfg(test)]` item compiles here and then fails to
    /// resolve there. Hidden from the rendered docs, not from the linker.
    #[doc(hidden)]
    pub fn default_values_for_test() -> Self {
        Self::default_values()
    }
```

Add the three new fields to `default_values()`, so a missing config file and a `Config` built in a test stay identical:

```rust
            listen: default_listen(),
            peer: String::new(),
            bridge_port: default_bridge_port(),
```

`load()` is unchanged and still does **not** call `validate()`. Parsing and policy stay separable: each entry point validates when it is about to bind or dial, which is what lets `non_loopback_listen_requires_a_peer` load a bad file and then assert on `validate()`.

Two notes for later tasks, both deliberate departures from the design document:

- **`validate()` is stricter than the design.** The design refuses startup only when `listen` is non-loopback **and** `mode = "auto"` **and** no `peer` is set (design:273-275). This rule drops the mode condition: any non-loopback `listen` without a `peer` is refused, whatever the mode. It therefore subsumes the design's rule while also closing the allowlist-mode case, where a reachable listener still exposes the callback bridge and the file preview — neither of which `mode` governs. Nothing needs the weaker form.
- **The design's name-resolution rule is dropped.** The design allows dialling a `peer_host` name provided it resolves to the configured literal `peer`, refusing otherwise (design:241-245). Always dialling the literal `peer` instead is simpler and exactly as secure: the resolution rule's only guarantee is that the dialled address equals `peer`, which dialling `peer` gives unconditionally, with no resolver in the path and no failure mode when DNS is slow, split-horizon, or stale. That is why no hostname field exists.

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test --lib config`
Expected: PASS, 12 tests — the 5 moved plus the 7 added.

Run: `cargo test --test config_visibility`
Expected: PASS, 1 test.

- [ ] **Step 6: Verify constraints**

```bash
wc -l src/config.rs src/config/tests.rs tests/config_visibility.rs
cargo clippy --all-targets --all-features -- -D warnings
cargo clippy --bins --all-features -- -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic -D clippy::indexing_slicing
./scripts/check-source-line-limit.sh
```

Expected: every file under 250 raw lines — roughly 160 for `src/config.rs`, 110 for `src/config/tests.rs`, 15 for `tests/config_visibility.rs`. Both clippy passes clean; the non-test code added here has no `unwrap`, `expect`, or `panic!`, and `parse_ip` maps the parse error rather than unwrapping it. The line-limit script exits 0.

Leave the work in the working copy. Do not commit — one commit covers the whole plan.

---

### Task 2: Peer authorization

**Files:**
- Create: `src/peer.rs`
- Modify: `src/lib.rs` (add `pub mod peer;`)
- Test: `src/peer.rs` (`mod tests`)

**Interfaces:**

- Consumes:
  - Task 0: `src/lib.rs`. Add `pub mod peer;` alongside the other module declarations. It must be `pub`, not private: Tasks 5, 7, and 9 call `authorized` from the bridge, the callback relay, and the file preview.
  - Task 1: `crate::config::Config`, with:
    - `pub peer: String` — the counterpart's literal tailnet address, empty when unset.
    - `Config::peer_ip(&self) -> Result<Option<std::net::IpAddr>, ConfigError>`
    - `Config::default_values_for_test() -> Config` — `#[doc(hidden)] pub`, unconditional. **Task 1 adds this constructor; this task only calls it.** Do not add or redefine it here, and do not wrap it in `#[cfg(test)]` anywhere: the integration tests in Tasks 5 and 6 are separate crates and would not see it.
- Produces:
  - `peer::authorized(cfg: &Config, remote: std::net::IpAddr) -> bool`

- [ ] **Step 1: Write the failing tests**

Create `src/peer.rs` containing only this test module, and add `pub mod peer;` to `src/lib.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn cfg_with_peer(peer: &str) -> Config {
        let mut cfg = Config::default_values_for_test();
        cfg.peer = peer.to_owned();
        cfg
    }

    #[test]
    fn loopback_is_always_allowed() {
        // Given: any configuration, including one naming a remote peer.
        let cfg = cfg_with_peer("100.64.0.2");

        // When: a same-machine connection arrives.
        // Then: it is allowed, so local tooling and `forward doctor` keep
        // working, and the bridge's own loopback hop is never refused.
        assert!(authorized(&cfg, "127.0.0.1".parse().unwrap()));
        assert!(authorized(&cfg, "::1".parse().unwrap()));
    }

    #[test]
    fn configured_peer_is_allowed() {
        // Given: a configuration naming the counterpart.
        let cfg = cfg_with_peer("100.64.0.2");

        // When: the counterpart connects.
        // Then: it is allowed.
        assert!(authorized(&cfg, "100.64.0.2".parse().unwrap()));
    }

    #[test]
    fn other_addresses_are_refused() {
        // Given: a configuration naming one counterpart.
        let cfg = cfg_with_peer("100.64.0.2");

        // When: a different tailnet node, or an off-tailnet address, connects.
        // Then: it is refused — a phone or a tagged service node is not the
        // counterpart, and a personal tailnet routinely holds both.
        assert!(!authorized(&cfg, "100.64.0.9".parse().unwrap()));
        assert!(!authorized(&cfg, "10.0.0.5".parse().unwrap()));
    }

    #[test]
    fn no_peer_means_loopback_only() {
        // Given: no peer configured, which is the default.
        let cfg = cfg_with_peer("");

        // When: a non-loopback address connects.
        // Then: it is refused, and loopback still is not.
        assert!(!authorized(&cfg, "100.64.0.2".parse().unwrap()));
        assert!(authorized(&cfg, "127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn unparseable_peer_denies_everything_remote() {
        // Given: a malformed peer, which Config::validate would have rejected.
        let cfg = cfg_with_peer("not-an-address");

        // When: a remote address connects.
        // Then: it is refused rather than defaulting open.
        assert!(!authorized(&cfg, "100.64.0.2".parse().unwrap()));
        assert!(authorized(&cfg, "127.0.0.1".parse().unwrap()));
    }
}
```

All five cases are required, and this unit module is the only place they can live. An integration test cannot originate a TCP connection from a foreign source address without root and a second interface, so the later integration tests in Tasks 5, 6, and 9 can only ever exercise the loopback-allowed path. Refusal — the half that carries the security property — is testable only by calling `authorized` directly with a synthesized address. Do not thin this module out on the grounds that later tasks cover it; they do not.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --lib peer`
Expected: FAIL to compile — `error[E0425]: cannot find function 'authorized' in this scope`, five times.

- [ ] **Step 3: Implement**

Prepend to `src/peer.rs`, above the test module:

```rust
use crate::config::Config;
use std::net::IpAddr;

/// Whether an inbound connection may be served.
///
/// Loopback is always allowed: it is the same machine, and refusing it would
/// break `forward doctor`, local tooling, and the bridge's own final hop to a
/// loopback-bound callback listener. Anything else must equal the configured
/// counterpart exactly. A missing or malformed `peer` denies every remote
/// address rather than defaulting open — `Config::validate` refuses that
/// combination at startup, and this is the second line of defence for a
/// process that reached a listener some other way.
///
/// Comparing a source address is meaningful here, which is not true on the
/// open internet: WireGuard decrypts and authenticates every inbound packet
/// against a specific peer's key and then drops it unless the plaintext source
/// address falls within that peer's `AllowedIPs`, and Tailscale gives each
/// device a unique address inside the tailnet. A tailnet node therefore cannot
/// present another node's address, so address equality is an identity check.
pub fn authorized(cfg: &Config, remote: IpAddr) -> bool {
    if remote.is_loopback() {
        return true;
    }
    matches!(cfg.peer_ip(), Ok(Some(peer)) if peer == remote)
}
```

The `matches!` guard is what makes the malformed and unset cases deny: `peer_ip()` returns `Err` for a non-literal `peer` and `Ok(None)` for an empty one, and neither matches `Ok(Some(peer))`. Written as an `if let` with an `else` returning `true`, or with an `unwrap_or_default` on the address, the same code would fail open — which is why `unparseable_peer_denies_everything_remote` exists.

Note that `authorized` takes an already-extracted `IpAddr`, not a `TcpStream` or `SocketAddr`. Callers in Tasks 5, 7, and 9 pass `stream.peer_addr()?.ip()`, so the port is discarded before the check and this function needs no I/O, which is what makes all five cases unit-testable.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --lib peer`
Expected: PASS, 5 tests.

- [ ] **Step 5: Verify constraints**

```bash
wc -l src/peer.rs
cargo clippy --all-targets --all-features -- -D warnings
cargo clippy --bins --all-features -- -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic -D clippy::indexing_slicing
./scripts/check-source-line-limit.sh
```

Expected: `src/peer.rs` around 85 raw lines, under 250. Both clippy passes clean — the `unwrap` calls are all inside `#[cfg(test)]`, and the strict pass runs `--bins` only. The line-limit script exits 0.

Leave the work in the working copy. Do not commit — one commit covers the whole plan.

---

### Task 3: Bidirectional pipe with half-close

**Files:**
- Create: `src/pipe.rs`
- Modify: `src/lib.rs` (add `pub mod pipe;`)
- Test: `tests/pipe.rs`

**Interfaces:**
- Consumes: the library crate `forward` rooted at `src/lib.rs` (Task 0), whose body is an
  alphabetically ordered list of `pub mod` declarations, one per module under `src/`.
  No functions or types from earlier tasks are used.
- Produces: `forward::pipe::bidirectional(left: TcpStream, right: TcpStream) -> std::io::Result<()>`
  — copies bytes both ways until each direction reaches EOF, propagating half-close;
  returns the first copy error instead of swallowing it.

- [ ] **Step 1: Write the failing tests**

Create `tests/pipe.rs`:

```rust
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::mpsc;
use std::time::Duration;

/// An echo-then-close upstream: reads until EOF, writes the reply, closes.
fn spawn_upstream() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = Vec::new();
        stream.read_to_end(&mut request).unwrap();
        stream.write_all(b"HTTP/1.1 200 OK\r\n\r\nok").unwrap();
    });
    port
}

/// A greet-then-half-close upstream: writes, shuts down its own write half, then
/// reads the client's answer to EOF and reports what it received.
fn spawn_greeting_upstream() -> (u16, mpsc::Receiver<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (answers, answered) = mpsc::channel();
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream.write_all(b"HELLO\n").unwrap();
        stream.shutdown(Shutdown::Write).unwrap();
        let mut answer = Vec::new();
        stream.read_to_end(&mut answer).unwrap();
        let _ = answers.send(answer);
    });
    (port, answered)
}

/// An upstream that accepts and immediately resets, the way a callback tool that
/// crashed mid-request does.
fn spawn_resetting_upstream() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let stream = socket2::Socket::from(stream);
        stream.set_linger(Some(Duration::ZERO)).unwrap();
        drop(stream);
    });
    port
}

/// The front door: accepts one connection, dials `upstream_port`, pipes the two
/// together, and reports what `bidirectional` returned.
fn spawn_pipe(upstream_port: u16) -> (u16, mpsc::Receiver<std::io::Result<()>>) {
    let front = TcpListener::bind("127.0.0.1:0").unwrap();
    let front_port = front.local_addr().unwrap().port();
    let (outcomes, outcome) = mpsc::channel();
    std::thread::spawn(move || {
        let (client, _) = front.accept().unwrap();
        let up = TcpStream::connect(("127.0.0.1", upstream_port)).unwrap();
        let _ = outcomes.send(forward::pipe::bidirectional(client, up));
    });
    (front_port, outcome)
}

#[test]
fn half_close_lets_the_reply_through() {
    // Given: an upstream that only replies after it sees EOF on the request.
    let (front_port, _outcome) = spawn_pipe(spawn_upstream());

    // When: a client sends a request and shuts down its write half.
    let mut client = TcpStream::connect(("127.0.0.1", front_port)).unwrap();
    client.write_all(b"GET / HTTP/1.1\r\n\r\n").unwrap();
    client.shutdown(Shutdown::Write).unwrap();

    // Then: EOF is propagated upstream, so the reply comes back instead of
    // both sides waiting forever.
    let mut reply = String::new();
    client.read_to_string(&mut reply).unwrap();
    assert!(reply.ends_with("ok"), "got {reply:?}");
}

#[test]
fn half_close_from_the_upstream_reaches_the_client() {
    // Given: an upstream that greets, half-closes, then waits to be answered.
    let (upstream_port, answered) = spawn_greeting_upstream();
    let (front_port, _outcome) = spawn_pipe(upstream_port);

    // When: the client reads to EOF and only then sends its answer.
    let mut client = TcpStream::connect(("127.0.0.1", front_port)).unwrap();
    let mut reader = client.try_clone().unwrap();
    let mut greeting = Vec::new();
    reader.read_to_end(&mut greeting).unwrap();
    client.write_all(b"ANSWER\n").unwrap();
    client.shutdown(Shutdown::Write).unwrap();

    // Then: the upstream's EOF reached the client, and shutting down only that
    // one write half left the client-to-upstream direction alive to carry the
    // answer sent after it.
    assert_eq!(greeting, b"HELLO\n");
    assert_eq!(
        answered.recv_timeout(Duration::from_secs(5)).unwrap(),
        b"ANSWER\n"
    );
}

#[test]
fn a_mid_copy_reset_surfaces_as_an_error() {
    // Given: an upstream that resets, and a client that stays idle, so the
    // client-to-upstream copy is parked on a read that will never complete.
    let (front_port, outcome) = spawn_pipe(spawn_resetting_upstream());
    let _client = TcpStream::connect(("127.0.0.1", front_port)).unwrap();

    // When: the reset lands mid-copy.
    let outcome = outcome.recv_timeout(Duration::from_secs(5));

    // Then: the failing direction wakes its idle sibling and the error is
    // returned; a timeout here means the pipe hung instead.
    let outcome = outcome.expect("bidirectional never returned");
    assert!(outcome.is_err(), "expected an error, got {outcome:?}");
}
```

`socket2` and the zero linger reset it forces are already how `tests/serve.rs:163`
provokes an abrupt client disconnect, so this stays in the repo's existing idiom.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --test pipe`
Expected: FAIL to compile — `error[E0433]: failed to resolve: could not find 'pipe' in 'forward'`
at the `forward::pipe::bidirectional` call in `spawn_pipe`, so none of the three tests run.

- [ ] **Step 3: Implement `src/pipe.rs` and export it**

Create `src/pipe.rs`:

```rust
use std::io::copy;
use std::net::{Shutdown, TcpStream};
use std::thread;

/// Copy bytes both ways until each direction reaches EOF.
///
/// On normal EOF a direction shuts down only the *destination's* write half.
/// Without that, an HTTP callback client that finished its request and is waiting
/// for a reply never gets one: the upstream is still blocked waiting for an EOF
/// that never arrives. This is the behaviour `ssh -L` provided for free, and it
/// is easy to lose.
///
/// A copy error is different. The sibling direction may be parked on a read that
/// will never complete because the other side is simply idle, so the failing
/// direction shuts down *both* sockets to wake it, and the error is returned
/// rather than swallowed. When both directions fail, the error from the
/// `left` -> `right` copy is the one reported.
pub fn bidirectional(left: TcpStream, right: TcpStream) -> std::io::Result<()> {
    let left_reverse = left.try_clone()?;
    let right_reverse = right.try_clone()?;
    let outbound = thread::spawn(move || half(left, right));
    let inbound = half(right_reverse, left_reverse);
    let outbound = match outbound.join() {
        Ok(result) => result,
        Err(_) => Err(std::io::Error::other("pipe thread panicked")),
    };
    outbound.and(inbound)
}

/// Copy one direction, then leave both sockets in the state the other direction
/// needs: half-closed on EOF, fully shut down on error.
fn half(mut from: TcpStream, mut to: TcpStream) -> std::io::Result<()> {
    match copy(&mut from, &mut to) {
        Ok(_) => {
            let _ = to.shutdown(Shutdown::Write);
            Ok(())
        }
        Err(error) => {
            let _ = from.shutdown(Shutdown::Both);
            let _ = to.shutdown(Shutdown::Both);
            Err(error)
        }
    }
}
```

Add the module to `src/lib.rs`, in alphabetical position — immediately before
`pub mod policy;`:

```rust
pub mod pipe;
```

`try_clone` failures now propagate with `?` instead of returning silently, and
`Shutdown::Both` on a socket both threads hold (a `try_clone` duplicates the
descriptor, so all clones name one socket) is what unblocks a parked read.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --test pipe`
Expected: PASS — `test result: ok. 3 passed; 0 failed`.

- [ ] **Step 5: Verify constraints**

```bash
wc -l src/pipe.rs src/lib.rs tests/pipe.rs
cargo clippy --all-targets --all-features -- -D warnings
cargo clippy --locked --bins --all-features -- \
  -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic \
  -D clippy::indexing_slicing
```

Expected: every file well under 250 lines (`src/pipe.rs` about 40, `tests/pipe.rs`
about 135); both clippy passes clean. `src/pipe.rs` contains no `unwrap`,
`expect`, `panic!` or indexing; the `unwrap`s are confined to `tests/pipe.rs`,
which the second pass does not lint because it is scoped to `--bins`.

---

### Task 4: Armed callback ports

**Files:**
- Create: `src/bridge.rs` (the `bridge` module root)
- Create: `src/bridge/armed.rs`
- Modify: `src/lib.rs` (add `pub mod bridge;`)
- Test: `src/bridge/armed.rs` (`mod tests`)

**Interfaces:**
- Consumes: the library crate `forward` rooted at `src/lib.rs` (Task 0), whose body is an
  alphabetically ordered list of `pub mod` declarations, one per module under `src/`.
  No functions or types from earlier tasks are used.
- Produces:
  - `src/bridge.rs` as the module root for everything bridge-related, containing
    `mod armed;` and `pub use armed::Armed;`. Later tasks add the rest of the bridge
    (its listener, its denylist, its arming socket) to *this* file.
  - `pub mod bridge;` in `src/lib.rs`, so `forward::bridge` is reachable from
    integration tests and from `src/main.rs`.
  - `forward::bridge::Armed`, a cheaply clonable handle to one shared set:
    - `Armed::new() -> Self`
    - `impl Default for Armed` (derived)
    - `impl Clone for Armed` (derived) — clones share one set
    - `Armed::arm(&self, port: u16, ttl: Duration)`
    - `Armed::is_armed(&self, port: u16) -> bool`

- [ ] **Step 1: Write the failing tests**

The tests are unit tests inside the module, so the module has to be declared and
exported for `cargo test --lib` to discover them at all. Create all three pieces
now, with `armed.rs` holding only its tests.

Create `src/bridge.rs`:

```rust
mod armed;

pub use armed::Armed;
```

Add the module to `src/lib.rs`, in alphabetical position — immediately before
`pub mod config;`:

```rust
pub mod bridge;
```

Create `src/bridge/armed.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn an_armed_port_is_reachable_until_it_expires() {
        // Given: a port armed for a very short window.
        let armed = Armed::new();
        armed.arm(8400, Duration::from_millis(80));

        // When: it is checked inside and then outside that window.
        assert!(armed.is_armed(8400));
        std::thread::sleep(Duration::from_millis(140));

        // Then: it stops being reachable on its own.
        assert!(!armed.is_armed(8400));
    }

    #[test]
    fn an_unarmed_port_is_never_reachable() {
        // Given: one armed port.
        let armed = Armed::new();
        armed.arm(8400, Duration::from_secs(60));

        // When/Then: a port nobody armed is not reachable through it.
        assert!(!armed.is_armed(9999));
    }

    #[test]
    fn arming_again_extends_the_window() {
        // Given: a port armed for a window about to close.
        let armed = Armed::new();
        armed.arm(8400, Duration::from_millis(60));
        std::thread::sleep(Duration::from_millis(40));

        // When: a second `forward open` arms the same port for longer.
        armed.arm(8400, Duration::from_secs(30));
        std::thread::sleep(Duration::from_millis(40));

        // Then: the longer lease wins instead of the first one expiring.
        assert!(armed.is_armed(8400));
    }

    #[test]
    fn clones_share_one_set() {
        // Given: a handle cloned for another thread.
        let armed = Armed::new();
        let other = armed.clone();

        // When: one clone arms a port.
        other.arm(8400, Duration::from_secs(30));

        // Then: the original sees it.
        assert!(armed.is_armed(8400));
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --lib armed`
Expected: FAIL to compile — `error[E0432]: unresolved import 'armed::Armed'` from
`src/bridge.rs`, plus `error[E0433]: failed to resolve: use of undeclared type 'Armed'`
in each of the four tests.

- [ ] **Step 3: Implement `Armed`**

Insert above the `mod tests` block in `src/bridge/armed.rs`:

```rust
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Callback ports the devbox will hop to, and until when.
///
/// The bridge is a service that connects to loopback ports on request, which is
/// the shape of a confinement bypass. This set is what stops a reachable peer
/// from choosing a port: only ports a local `forward open` armed — from a URL
/// that actually named them — are reachable, and only until the lease expires.
///
/// Clones share one set, so the arming socket and the bridge listener can hold a
/// handle each.
#[derive(Clone, Default)]
pub struct Armed {
    ports: Arc<Mutex<HashMap<u16, Instant>>>,
}

impl Armed {
    pub fn new() -> Self {
        Self::default()
    }

    /// Arm `port` for `ttl`. A longer lease replaces a shorter one; a shorter one
    /// never shortens a lease already granted.
    pub fn arm(&self, port: u16, ttl: Duration) {
        let deadline = Instant::now() + ttl;
        let mut ports = self.ports.lock();
        let entry = ports.entry(port).or_insert(deadline);
        if *entry < deadline {
            *entry = deadline;
        }
    }

    /// Whether `port` is armed right now. Expired entries are dropped here, so no
    /// reaper thread is needed for this set.
    pub fn is_armed(&self, port: u16) -> bool {
        let now = Instant::now();
        let mut ports = self.ports.lock();
        ports.retain(|_, deadline| *deadline > now);
        ports.contains_key(&port)
    }
}
```

`Default` is derived rather than hand-written — `Arc<Mutex<HashMap<..>>>` is
already `Default` — and `new()` delegates to it, because clippy's
`new_without_default` is a default-on `style` lint and the constraint pass runs
with `-D warnings`. `parking_lot::Mutex` is the existing dependency this repo
already uses for shared state (`src/forwards.rs:3`), so no new dependency.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --lib armed`
Expected: PASS — four `test bridge::armed::tests::... ok` lines and
`test result: ok. 4 passed; 0 failed`.

- [ ] **Step 5: Verify constraints**

```bash
wc -l src/bridge.rs src/bridge/armed.rs src/lib.rs
cargo clippy --all-targets --all-features -- -D warnings
cargo clippy --locked --bins --all-features -- \
  -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic \
  -D clippy::indexing_slicing
```

Expected: every file well under 250 lines (`src/bridge.rs` 3, `src/bridge/armed.rs`
about 105); both clippy passes clean. The `assert!` macros are test-only and live
in the lib target, which the second pass does not lint because it is scoped to
`--bins`.

---

### Task 5: The devbox callback bridge

**Files:**
- Modify: `src/bridge.rs` (Task 4 created it holding only `mod armed;` and `pub use armed::Armed;`)
- Test: `tests/bridge.rs`

**Interfaces:**
- Consumes:
  - `crate::config::Config` with `pub listen: String` and `pub bridge_port: u16`, plus `Config::listen_ip(&self) -> Result<std::net::IpAddr, ConfigError>` and `#[doc(hidden)] pub fn Config::default_values_for_test() -> Config` (Task 1).
  - `crate::peer::authorized(cfg: &Config, remote: std::net::IpAddr) -> bool` (Task 2).
  - `crate::pipe::bidirectional(left: TcpStream, right: TcpStream) -> std::io::Result<()>` (Task 3).
  - `src/bridge.rs` already containing `mod armed;` and `pub use armed::Armed;`, with `pub mod bridge;` already in `src/lib.rs`; `Armed::new()`, `Armed::arm(&self, port: u16, ttl: std::time::Duration)`, `Armed::is_armed(&self, port: u16) -> bool`, and `Armed: Clone` (Task 4).
- Produces:
  - `bridge::serve(cfg: Config, armed: Armed) -> Result<(), BridgeError>` — binds `cfg.listen_ip()` and `cfg.bridge_port`, then blocks in the accept loop.
  - `bridge::spawn_with_listener(cfg: Config, armed: Armed, listener: TcpListener)` — test seam that runs the accept loop on a listener the caller already bound.
  - `bridge::denied_port(cfg: &Config, port: u16) -> bool`.
  - `bridge::BridgeError` — `thiserror` enum, one variant `Bind { address: String, source: std::io::Error }`.

This task does not touch `src/main.rs` or `src/lib.rs`: `pub mod bridge;` landed in Task 4, `--config` on `Serve` landed in Task 0, and the `Command::Serve` wiring that constructs one `Armed`, starts the arming socket and then starts this bridge belongs to Task 6, which owns that block.

Wire protocol, one line, ASCII, newline-terminated: `CONNECT <port>\n` — exactly one space, decimal digits, then `\n`. On success the bridge sends nothing and begins piping. On refusal it closes immediately.

- [ ] **Step 1: Write the failing tests**

Create `tests/bridge.rs`:

```rust
use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

fn cfg(bridge_port: u16) -> forward::config::Config {
    let mut cfg = forward::config::Config::default_values_for_test();
    cfg.bridge_port = bridge_port;
    cfg
}

/// Start a bridge on an ephemeral port and return the port.
fn spawn_bridge(armed: forward::bridge::Armed) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let bridge_port = listener.local_addr().unwrap().port();
    forward::bridge::spawn_with_listener(cfg(bridge_port), armed, listener);
    bridge_port
}

/// An upstream bound ONLY to loopback — the case a tailnet dial cannot reach
/// directly, and the reason this bridge exists. It replies `pong` once it has
/// received four bytes, so a reply proves the payload arrived intact.
fn spawn_echo_upstream() -> u16 {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = upstream.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let (mut stream, _) = upstream.accept().unwrap();
        let mut request = [0_u8; 4];
        stream.read_exact(&mut request).unwrap();
        assert_eq!(&request, b"ping");
        stream.write_all(b"pong").unwrap();
    });
    port
}

/// Read to EOF under a deadline, so a bug that loses bytes fails the test
/// instead of hanging it.
fn read_reply(client: &mut TcpStream) -> String {
    client.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut reply = String::new();
    client
        .read_to_string(&mut reply)
        .expect("the bridge must relay a reply, not hang or reset");
    reply
}

/// A refusal yields no bytes. The bridge may close while unread bytes are still
/// queued on its side, which Linux answers with RST, so a connection reset is a
/// refusal too. What must never happen is payload coming back.
fn assert_refused(client: &mut TcpStream) {
    client.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut reply = String::new();
    match client.read_to_string(&mut reply) {
        Ok(_) => assert!(reply.is_empty(), "got {reply:?}"),
        Err(error) => assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset),
    }
}

#[test]
fn hops_to_an_armed_loopback_port() {
    // Given: a loopback-only upstream, armed on the bridge.
    let upstream_port = spawn_echo_upstream();
    let armed = forward::bridge::Armed::new();
    armed.arm(upstream_port, Duration::from_secs(30));
    let bridge_port = spawn_bridge(armed);

    // When: a client asks the bridge for that port, then sends payload in a
    // second write, so the request line arrives on its own.
    let mut client = TcpStream::connect(("127.0.0.1", bridge_port)).unwrap();
    client
        .write_all(format!("CONNECT {upstream_port}\n").as_bytes())
        .unwrap();
    client.write_all(b"ping").unwrap();

    // Then: bytes reach the loopback-only upstream and come back.
    assert_eq!(read_reply(&mut client), "pong");
}

#[test]
fn payload_in_the_same_packet_as_the_request_line_still_reaches_the_upstream() {
    // Given: the same armed loopback-only upstream.
    let upstream_port = spawn_echo_upstream();
    let armed = forward::bridge::Armed::new();
    armed.arm(upstream_port, Duration::from_secs(30));
    let bridge_port = spawn_bridge(armed);

    // When: the request line and the first payload bytes arrive in ONE write,
    // so they land in one segment — what a real OAuth callback client does, its
    // GET following the line immediately.
    let mut client = TcpStream::connect(("127.0.0.1", bridge_port)).unwrap();
    client.set_nodelay(true).unwrap();
    client
        .write_all(format!("CONNECT {upstream_port}\nping").as_bytes())
        .unwrap();

    // Then: the payload still reaches the upstream. Parsing the request line
    // with a buffered reader would have pulled "ping" into a buffer that is
    // dropped with the reader, hanging this connection forever.
    assert_eq!(read_reply(&mut client), "pong");
}

#[test]
fn refuses_an_unarmed_port() {
    // Given: a bridge with nothing armed.
    let bridge_port = spawn_bridge(forward::bridge::Armed::new());

    // When: a client asks for a port anyway.
    let mut client = TcpStream::connect(("127.0.0.1", bridge_port)).unwrap();
    client.write_all(b"CONNECT 8400\n").unwrap();

    // Then: the connection closes with no data — a reachable peer cannot pick a
    // port, only use one a login flow legitimately requested.
    assert_refused(&mut client);
}

#[test]
fn refuses_denylisted_ports_even_when_armed() {
    // Given: the PC/SC port armed by mistake. Devbox loopback 12799 is the far
    // end of the SSH tunnel carrying the laptop's hardware token.
    let armed = forward::bridge::Armed::new();
    armed.arm(12_799, Duration::from_secs(30));
    let bridge_port = spawn_bridge(armed);

    // When: a client asks for it.
    let mut client = TcpStream::connect(("127.0.0.1", bridge_port)).unwrap();
    client.write_all(b"CONNECT 12799\n").unwrap();

    // Then: the denylist refuses it regardless of the armed set, so an arming
    // mistake cannot expose the token.
    assert_refused(&mut client);
}

#[test]
fn denylist_covers_forwards_own_ports() {
    // Given: a bridge configured on its default port.
    let cfg = cfg(12_801);

    // When/Then: the token socket, the URL channel, the file preview and the
    // bridge itself are all refused; an ordinary callback port is not.
    assert!(forward::bridge::denied_port(&cfg, 12_799));
    assert!(forward::bridge::denied_port(&cfg, 12_800));
    assert!(forward::bridge::denied_port(&cfg, 12_801));
    assert!(forward::bridge::denied_port(&cfg, 12_802));
    assert!(!forward::bridge::denied_port(&cfg, 8_400));
}

#[test]
fn refuses_a_malformed_request_line() {
    // Given: an armed port and a client that speaks HTTP at the bridge.
    let armed = forward::bridge::Armed::new();
    armed.arm(8_400, Duration::from_secs(30));
    let bridge_port = spawn_bridge(armed);

    // When: the first line is not `CONNECT <port>`.
    let mut client = TcpStream::connect(("127.0.0.1", bridge_port)).unwrap();
    client.write_all(b"GET / HTTP/1.1\r\n\r\n").unwrap();

    // Then: it is refused.
    assert_refused(&mut client);
}

#[test]
fn refuses_a_request_line_with_no_newline() {
    // Given: an armed port, so only the missing newline can refuse the request.
    let armed = forward::bridge::Armed::new();
    armed.arm(8_400, Duration::from_secs(30));
    let bridge_port = spawn_bridge(armed);

    // When: the line is otherwise valid but ends at EOF instead of a newline.
    let mut client = TcpStream::connect(("127.0.0.1", bridge_port)).unwrap();
    client.write_all(b"CONNECT 8400").unwrap();
    client.shutdown(std::net::Shutdown::Write).unwrap();

    // Then: it is refused — the protocol says newline-terminated.
    assert_refused(&mut client);

    // When: a peer sends a long line and never terminates it.
    let mut flooder = TcpStream::connect(("127.0.0.1", bridge_port)).unwrap();
    flooder.write_all(&[b'A'; 100]).unwrap();

    // Then: the read is bounded and the connection is refused, not buffered.
    assert_refused(&mut flooder);
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --test bridge`

Expected: FAIL to compile — `error[E0425]: cannot find function \`spawn_with_listener\` in module \`forward::bridge\``, and the same for `denied_port`. `forward::bridge::Armed` already resolves, because Task 4 created `src/bridge.rs` and exported it.

- [ ] **Step 3: Implement the bridge in `src/bridge.rs`**

Keep the existing `mod armed;` and `pub use armed::Armed;` at the top and add the rest, so the file reads:

```rust
mod armed;

pub use armed::Armed;

use crate::config::Config;
use crate::peer::authorized;
use crate::pipe::bidirectional;
use std::io::Read;
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

/// How long a connection may take to send its request line.
const READ_TIMEOUT: Duration = Duration::from_secs(10);
/// Longest request line accepted, newline excluded. `CONNECT 65535` is 13 bytes.
const MAX_REQUEST_LINE: usize = 64;

#[derive(Debug, thiserror::Error)]
pub enum BridgeError {
    #[error("forward: could not bind callback bridge on {address}: {source}")]
    Bind {
        address: String,
        #[source]
        source: std::io::Error,
    },
}

/// Ports the bridge will never hop to, whatever the armed set says.
///
/// 12799 above all: on the devbox that is the far end of the SSH tunnel carrying
/// the laptop's PC/SC socket, so hopping to it would expose a plugged-in
/// hardware token to anything that can reach the bridge. The rest are forward's
/// own services — the URL channel, the file preview, and the bridge itself —
/// which would otherwise allow a loop or a confused-deputy chain back through
/// forward.
///
/// Checked separately from the armed set on purpose: a port armed by mistake
/// must not defeat this list.
pub fn denied_port(cfg: &Config, port: u16) -> bool {
    port == 12_799 || port == 12_800 || port == 12_802 || port == cfg.bridge_port
}

/// Serve the callback bridge on the configured address. Blocks.
pub fn serve(cfg: Config, armed: Armed) -> Result<(), BridgeError> {
    let ip = cfg.listen_ip().map_err(|source| BridgeError::Bind {
        address: cfg.listen.clone(),
        source: std::io::Error::other(source.to_string()),
    })?;
    let listener = TcpListener::bind((ip, cfg.bridge_port)).map_err(|source| BridgeError::Bind {
        address: format!("{ip}:{}", cfg.bridge_port),
        source,
    })?;
    eprintln!("forward: callback bridge on {ip}:{}", cfg.bridge_port);
    accept_loop(cfg, armed, listener);
    Ok(())
}

/// Test seam: run the accept loop on a listener the caller already bound.
pub fn spawn_with_listener(cfg: Config, armed: Armed, listener: TcpListener) {
    drop(thread::spawn(move || accept_loop(cfg, armed, listener)));
}

fn accept_loop(cfg: Config, armed: Armed, listener: TcpListener) {
    for connection in listener.incoming() {
        match connection {
            Ok(stream) => {
                let cfg = cfg.clone();
                let armed = armed.clone();
                drop(thread::spawn(move || handle(&cfg, &armed, stream)));
            }
            Err(error) => eprintln!("forward: bridge accept failed: {error}"),
        }
    }
}

fn handle(cfg: &Config, armed: &Armed, mut stream: TcpStream) {
    let Ok(remote) = stream.peer_addr() else {
        return;
    };
    // The peer check runs here, before a single byte is read or parsed.
    if !authorized(cfg, remote.ip()) {
        eprintln!("forward: bridge refused peer {}", remote.ip());
        return;
    }
    let Some(port) = read_port(&mut stream) else {
        eprintln!("forward: bridge refused a malformed request line");
        return;
    };
    // Two separate gates: the denylist holds even if the armed set says yes.
    if denied_port(cfg, port) {
        eprintln!("forward: bridge refused denylisted port {port}");
        return;
    }
    if !armed.is_armed(port) {
        eprintln!("forward: bridge refused unarmed port {port}");
        return;
    }
    match TcpStream::connect(("127.0.0.1", port)) {
        Ok(upstream) => {
            let _ = stream.set_read_timeout(None);
            if let Err(error) = bidirectional(stream, upstream) {
                eprintln!("forward: bridge relay for port {port} ended: {error}");
            }
        }
        Err(error) => eprintln!("forward: bridge could not reach 127.0.0.1:{port}: {error}"),
    }
}

/// Read `CONNECT <port>\n` one byte at a time, directly off the stream.
///
/// Byte-at-a-time is the whole point, not a style choice. A buffered reader
/// would pull in whatever else is already in the socket — a callback client
/// sends its request in the same segment as this line — and those bytes are
/// silently discarded when the reader is dropped, so the connection this bridge
/// exists to relay hangs or receives a truncated request. Reading a byte at a
/// time leaves the stream positioned exactly after the newline, and the stream
/// itself, never a clone, is what gets handed to `bidirectional`.
///
/// The newline is required: EOF, a read error, or `MAX_REQUEST_LINE` bytes
/// without one is a refusal, not a request. Nothing is trimmed, so the accepted
/// form is exactly one space and decimal digits — `u16::from_str` rejects
/// surrounding whitespace on its own.
fn read_port(stream: &mut TcpStream) -> Option<u16> {
    let _ = stream.set_read_timeout(Some(READ_TIMEOUT));
    let mut line = Vec::with_capacity(MAX_REQUEST_LINE);
    let mut byte = [0_u8; 1];
    while line.len() < MAX_REQUEST_LINE {
        match stream.read(&mut byte) {
            Ok(1) => {}
            Ok(_) => return None,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return None,
        }
        let [received] = byte;
        if received == b'\n' {
            let text = std::str::from_utf8(&line).ok()?;
            return text.strip_prefix("CONNECT ")?.parse().ok();
        }
        line.push(received);
    }
    None
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --test bridge`

Expected: PASS, 7 tests — `hops_to_an_armed_loopback_port`, `payload_in_the_same_packet_as_the_request_line_still_reaches_the_upstream`, `refuses_an_unarmed_port`, `refuses_denylisted_ports_even_when_armed`, `denylist_covers_forwards_own_ports`, `refuses_a_malformed_request_line`, `refuses_a_request_line_with_no_newline`.

Also run the unit tests Task 4 left in place, to confirm the new module code did not disturb them:

Run: `cargo test --lib armed`
Expected: PASS, 4 tests.

- [ ] **Step 5: Check the line limits and lint**

```bash
wc -l src/bridge.rs src/bridge/armed.rs tests/bridge.rs
cargo clippy --all-targets --all-features -- -D warnings
cargo clippy --lib --bins --all-features -- \
  -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic \
  -D clippy::indexing_slicing
```

Expected: every `wc -l` count strictly under 250 — `src/bridge.rs` 142 lines, `tests/bridge.rs` 182 lines. Both clippy passes exit 0. The second pass adds `--lib` to the flag set CI uses, because after the library extraction `--bins` alone no longer lints `src/bridge.rs`; `read_port` is written with `Vec::push` and a destructuring `let [received] = byte;` precisely so it holds no indexing, slicing, `unwrap`, `expect` or `panic!`.

Leave the work uncommitted in a reviewable state.

---

---

### Task 6: The local arming socket

**Files:**
- Create: `tests/bridge/arming.rs`
- Modify: `src/bridge/armed.rs` (the socket, alongside the `Armed` set), `src/bridge.rs` (re-exports), `src/main.rs` (`Serve` starts the arming socket and the bridge), `tests/bridge.rs` (declare the new test module), `tests/serve.rs` (`spawn_serve` tolerates the new startup lines and gets its own runtime directory)
- Test: `tests/bridge/arming.rs`

**Interfaces:**

- Consumes:
  - Task 0: the crate is a library named `forward` with `src/lib.rs`; `Command::Serve { port: u16, config: Option<std::path::PathBuf> }`; `load_config(path: Option<std::path::PathBuf>) -> anyhow::Result<config::Config>` in `src/main.rs`, which loads the file (or the defaults when absent) and calls `validate()`; `serve::run(cfg: &Config, port: u16) -> Result<(), ServeError>`.
  - Task 1: `Config` derives `Clone`; `pub bridge_port: u16` (TOML key `bridge_port`, default `12801`); `pub listen: String` (default `"127.0.0.1"`); `Config::validate() -> Result<(), ConfigError>`, which accepts a loopback `listen` with no `peer`.
  - Task 4: `src/bridge/armed.rs` already defines `#[derive(Clone)] pub struct Armed` with `Armed::new() -> Self`, `Armed::arm(&self, port: u16, ttl: Duration)`, `Armed::is_armed(&self, port: u16) -> bool`, and **already has `use std::time::{Duration, Instant};` at the top of the file** — do not import `Duration` a second time.
  - Task 5: `bridge::serve(cfg: Config, armed: Armed) -> Result<(), BridgeError>`, which binds `cfg.listen_ip():cfg.bridge_port`, prints `forward: callback bridge on <ip>:<port>` and then blocks in its accept loop; `src/bridge.rs` contains `mod armed;` and `pub use armed::Armed;`; `src/lib.rs` contains `pub mod bridge;`; `tests/bridge.rs` exists with five tests.

- Produces:
  - `bridge::arm_socket_path() -> std::path::PathBuf`
  - `bridge::serve_arming(armed: Armed, path: std::path::PathBuf)` — binds, restricts and serves the socket on its own thread; returns immediately.
  - `bridge::arm(path: &std::path::Path, ports: &[u16], ttl_secs: u64) -> bool` — `true` only when **every** requested port was armed. An empty slice is `false`, so a caller with nothing to arm must skip the call rather than treat the result as a failure. Task 8 (`forward open`) calls this.
  - `forward serve` creates exactly one `Armed` and shares it between the arming socket and the callback bridge, and starts both before the file server. Task 8's arming and Task 12's hardware proof depend on this.
  - `tests/serve.rs`: `spawn_serve` skips startup lines that are not the file server's own, and gives the child process its own `XDG_RUNTIME_DIR` and an explicit `--config` so it cannot pick up the developer's real configuration.

Wire protocol, one line, ASCII, newline-terminated: `ARM <port> <ttl_secs>\n`, replying `ok\n`. A request that is not a single newline-terminated line is refused with no reply.

- [ ] **Step 1: Write the failing tests**

Add the module declaration to the top of `tests/bridge.rs`, below its existing `use` lines, matching the `#[path]` convention in `tests/daemon.rs` and `tests/serve.rs`:

```rust
#[path = "bridge/arming.rs"]
mod arming;
```

Create `tests/bridge/arming.rs`:

```rust
use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

struct Kill(std::process::Child);

impl Drop for Kill {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn wait_for_socket(path: &Path) {
    for _ in 0..100 {
        if path.exists() {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("arming socket never appeared at {}", path.display());
}

fn wait_for_bridge(port: u16) {
    for _ in 0..100 {
        // A probe connection sends no CONNECT line, so the bridge refuses it.
        // All this proves is that the listener is bound.
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("callback bridge never bound port {port}");
}

#[test]
fn arming_over_the_local_socket_makes_a_port_reachable() {
    // Given: a bridge with an arming socket in a temporary directory.
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("arm.sock");
    let armed = forward::bridge::Armed::new();
    forward::bridge::serve_arming(armed.clone(), socket.clone());
    wait_for_socket(&socket);

    // When: a local process arms two ports, as `forward open` does.
    assert!(forward::bridge::arm(&socket, &[8400, 9000], 300));

    // Then: both are reachable and nothing else is.
    assert!(armed.is_armed(8400));
    assert!(armed.is_armed(9000));
    assert!(!armed.is_armed(8401));
}

#[test]
fn arming_a_missing_socket_reports_failure_without_panicking() {
    // Given: no bridge running, which is the case on the laptop.
    let missing = Path::new("/nonexistent/forward-arm.sock");

    // When: arming is attempted.
    // Then: it reports failure rather than aborting the caller, because
    // `forward open` must still send and open the URL.
    assert!(!forward::bridge::arm(missing, &[8400], 300));
}

#[test]
fn an_overlong_unterminated_arm_line_is_refused_without_arming() {
    // Given: a bridge with an arming socket.
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("arm.sock");
    let armed = forward::bridge::Armed::new();
    forward::bridge::serve_arming(armed.clone(), socket.clone());
    wait_for_socket(&socket);

    // When: a local process sends a long ARM line and never terminates it.
    let mut hostile = UnixStream::connect(&socket).unwrap();
    let padding = " ".repeat(4096);
    hostile
        .write_all(format!("ARM 8400 300{padding}").as_bytes())
        .unwrap();
    hostile.flush().unwrap();

    // Then: it is refused with no reply and nothing is armed. The read is
    // tolerated rather than unwrapped: a refusal closes the connection, and
    // whether that arrives as a clean EOF or a reset is kernel timing.
    let mut reply = String::new();
    let _ = hostile.read_to_string(&mut reply);
    assert!(reply.is_empty(), "got {reply:?}");
    assert!(!armed.is_armed(8400));

    // And: the socket still serves, so the bounded read released the handler
    // instead of pinning it on a line that never ends.
    assert!(forward::bridge::arm(&socket, &[9100], 300));
    assert!(armed.is_armed(9100));
}

#[test]
fn serve_shares_one_armed_set_between_the_socket_and_the_bridge() {
    // Given: an upstream bound ONLY to loopback, the shape an OAuth CLI binds.
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_port = upstream.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let (mut stream, _) = upstream.accept().unwrap();
        let mut buf = [0_u8; 4];
        stream.read_exact(&mut buf).unwrap();
        stream.write_all(b"pong").unwrap();
    });

    // And: a real `forward serve`, given its own runtime directory and a bridge
    // port the kernel chose, so parallel tests and a real devbox daemon cannot
    // collide with it. The probe listener is released before the child binds.
    let probe = TcpListener::bind("127.0.0.1:0").unwrap();
    let bridge_port = probe.local_addr().unwrap().port();
    drop(probe);
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.toml");
    std::fs::write(&config, format!("bridge_port = {bridge_port}\n")).unwrap();
    let child = std::process::Command::new(env!("CARGO_BIN_EXE_forward"))
        .args(["serve", "--port", "0"])
        .arg("--config")
        .arg(&config)
        .env("XDG_RUNTIME_DIR", dir.path())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let _guard = Kill(child);
    let socket = dir.path().join("forward-arm.sock");
    wait_for_socket(&socket);
    wait_for_bridge(bridge_port);

    // When: a local process arms the callback port over the socket, as
    // `forward open` does, and a peer then asks the bridge for that port.
    assert!(forward::bridge::arm(&socket, &[upstream_port], 300));
    let mut client = TcpStream::connect(("127.0.0.1", bridge_port)).unwrap();
    writeln!(client, "CONNECT {upstream_port}").unwrap();
    client.write_all(b"ping").unwrap();

    // Then: the hop happens, which it can only do if `serve` handed the socket
    // and the bridge the same armed set.
    let mut reply = String::new();
    client.read_to_string(&mut reply).unwrap();
    assert_eq!(reply, "pong");
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --test bridge arming`

Expected: FAIL to compile —
`error[E0425]: cannot find function 'serve_arming' in module 'forward::bridge'`, and the same for `arm` and `arm_socket_path`.

- [ ] **Step 3: Implement the socket in `src/bridge/armed.rs`**

Add these four lines to the file's existing `use` block. `Duration` is already imported by Task 4; importing it again is a compile error:

```rust
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
```

Insert the rest **after `impl Armed { … }` and before the `#[cfg(test)] mod tests` block**:

```rust
/// The longest arming request accepted, in bytes.
///
/// `ARM 65535 4294967295\n` is 21 bytes, so 64 is generous. The cap is what
/// stops a hostile or broken local process making this handler allocate without
/// limit; the timeout is what stops it holding the handler open instead.
const MAX_ARM_LINE: u64 = 64;
const ARM_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Where `forward open` reaches the local bridge.
///
/// A unix socket in the runtime directory, never a TCP port: only local
/// processes can reach it, and filesystem permissions scope it. Arming grants a
/// local process nothing it could not already do by connecting to loopback
/// directly; the gate exists to constrain the *remote* peer.
pub fn arm_socket_path() -> PathBuf {
    let dir = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    dir.join("forward-arm.sock")
}

/// Serve arming requests on `path` for the life of the process.
pub fn serve_arming(armed: Armed, path: PathBuf) {
    let _ = std::fs::remove_file(&path);
    let Ok(listener) = UnixListener::bind(&path) else {
        eprintln!("forward: could not bind arming socket {}", path.display());
        return;
    };
    // The doc comment above promises filesystem permissions scope this socket.
    // $XDG_RUNTIME_DIR is already private, but the temp_dir fallback is not, so
    // set the mode rather than inherit a umask, and refuse to serve if that
    // cannot be enforced.
    let owner_only = std::fs::Permissions::from_mode(0o600);
    if let Err(error) = std::fs::set_permissions(&path, owner_only) {
        eprintln!(
            "forward: could not restrict arming socket {}: {error}",
            path.display()
        );
        return;
    }
    drop(std::thread::spawn(move || {
        // One request at a time: arming is rare, and a bounded handler cannot
        // be held open long enough for a queue to matter.
        for connection in listener.incoming().flatten() {
            handle_arming(&armed, connection);
        }
    }));
}

fn handle_arming(armed: &Armed, stream: UnixStream) {
    let _ = stream.set_read_timeout(Some(ARM_READ_TIMEOUT));
    let Ok(mut write_half) = stream.try_clone() else {
        return;
    };
    // Bounded read. A BufReader is safe here only because nothing is piped
    // afterwards, so bytes read past the line cannot be lost from a payload the
    // way they could in the bridge's CONNECT parse.
    let mut reader = BufReader::new(stream).take(MAX_ARM_LINE);
    let mut line = String::new();
    if reader.read_line(&mut line).is_err() {
        return;
    }
    // A line that hit the cap without a terminator is a refusal, not a
    // truncated request to parse.
    if !line.ends_with('\n') {
        eprintln!("forward: refused an unterminated arming request");
        return;
    }
    let mut fields = line.trim().split(' ');
    if fields.next() != Some("ARM") {
        return;
    }
    let (Some(Ok(port)), Some(Ok(ttl))) = (
        fields.next().map(str::parse::<u16>),
        fields.next().map(str::parse::<u64>),
    ) else {
        return;
    };
    armed.arm(port, Duration::from_secs(ttl));
    eprintln!("forward: armed callback port {port} for {ttl}s");
    let _ = writeln!(write_half, "ok");
}

/// Arm `ports` on the local bridge, true only if every one was armed.
///
/// An empty slice is not a success: a caller with nothing to arm must skip this
/// call rather than read the result as a failure.
pub fn arm(path: &Path, ports: &[u16], ttl_secs: u64) -> bool {
    let mut armed_all = !ports.is_empty();
    for port in ports {
        armed_all &= arm_one(path, *port, ttl_secs);
    }
    armed_all
}

fn arm_one(path: &Path, port: u16, ttl_secs: u64) -> bool {
    let Ok(mut stream) = UnixStream::connect(path) else {
        eprintln!(
            "forward: no local bridge at {} — callback port {port} will not be reachable",
            path.display()
        );
        return false;
    };
    // `forward open` must never hang on a wedged bridge.
    let _ = stream.set_read_timeout(Some(ARM_READ_TIMEOUT));
    if writeln!(stream, "ARM {port} {ttl_secs}").is_err() {
        return false;
    }
    let mut reply = String::new();
    let read = BufReader::new(stream)
        .take(MAX_ARM_LINE)
        .read_line(&mut reply);
    read.is_ok() && reply.trim() == "ok"
}
```

Then widen the re-export in `src/bridge.rs`, replacing `pub use armed::Armed;`:

```rust
pub use armed::{Armed, arm, arm_socket_path, serve_arming};
```

- [ ] **Step 4: Run tests to confirm three pass and the fourth exposes the missing wiring**

Run: `cargo test --test bridge arming`

Expected: 3 passed, 1 failed. `arming_over_the_local_socket_makes_a_port_reachable`,
`arming_a_missing_socket_reports_failure_without_panicking` and
`an_overlong_unterminated_arm_line_is_refused_without_arming` pass.
`serve_shares_one_armed_set_between_the_socket_and_the_bridge` fails with
`panicked at 'arming socket never appeared at …/forward-arm.sock'`, because
nothing starts the socket yet. That is the whole point of the next step: without
it `forward open` can never arm a port and the devbox bridge refuses every
callback, so the callback path is dead on arrival.

- [ ] **Step 5: Start the arming socket and the bridge from `forward serve` in `src/main.rs`**

Add `bridge` to the library imports `main.rs` already has — `use forward::bridge;` if it imports modules one per line, otherwise add `bridge` to the existing `use forward::{…};` group.

Replace the body of the `Serve` arm so it reads exactly:

```rust
        Command::Serve { port, config } => {
            let cfg = load_config(config)?;
            let armed = bridge::Armed::new();
            bridge::serve_arming(armed.clone(), bridge::arm_socket_path());
            let bridge_cfg = cfg.clone();
            drop(std::thread::spawn(move || {
                if let Err(error) = bridge::serve(bridge_cfg, armed) {
                    eprintln!("{error}");
                }
            }));
            serve::run(&cfg, port).unwrap_or_else(|error| exit_with_error(error));
            Ok(())
        }
```

Four things this must get right:

1. **One `Armed`.** `serve_arming` takes a clone and the bridge thread takes the original; both are handles onto the same `Arc`. If Task 5 already left a bridge start in this arm, replace it with this version — two `Armed::new()` calls would mean `forward open` arms a set the bridge never reads, which fails silently.
2. **The bridge runs on its own thread**, because `bridge::serve` blocks in its accept loop and `serve::run` must still get the main thread.
3. **A bridge failure logs and continues.** Binding is best-effort: the file server is useful on its own, and `forward serve` must not exit because port `bridge_port` is taken.
4. **No gate on `listen`.** With the defaults, `listen` is `127.0.0.1`, so the bridge binds loopback and an unconfigured install still opens no tailnet port. Nothing extra is needed to preserve that.

If Task 0 loaded the config inline in this arm instead of through a `load_config`
helper, keep its exact loading lines and add only the `Armed`, `serve_arming`
and bridge-thread lines between the load and `serve::run`.

- [ ] **Step 6: Make `spawn_serve` in `tests/serve.rs` tolerate the new startup lines**

`spawn_serve` reads exactly one stderr line and requires it to be the file
server's. The bridge announces itself from another thread, so which line lands
first is a race — the existing four tests will pass sometimes and fail
sometimes. Do not skip this step because a run happened to be green.

Replace the inline prefix literal with a constant, placed below the `use` lines
at the top of the file:

```rust
const SERVE_STARTUP_PREFIX: &str = "forward: loopback server listening on 127.0.0.1:";
```

Isolate the child from the machine it runs on. Two things bite once `Serve` loads
a config and starts the bridge: with no `--config` the child picks up the
developer's real `~/.config/forward/config.toml`, so it would bind that file's
`listen` address rather than loopback — the prefix below would never match, and
the child's bridge would collide with the real devbox one; and with the real
`XDG_RUNTIME_DIR` the child unlinks and rebinds the arming socket of a running
`forward serve`, silently killing callbacks for the real daemon. Pointing
`--config` at a path that does not exist loads the defaults, which is exactly
what these tests want. `root_marker` is the test's temporary directory and was
previously discarded, so delete the `let _ = root_marker;` line further down:

```rust
        .args(["serve", "--port", "0"])
        .arg("--config")
        .arg(root_marker.join("no-config.toml"))
        .env("XDG_RUNTIME_DIR", root_marker)
```

Replace the reader thread with one that reads past anything that is not the file
server's line:

```rust
    let reader = std::thread::spawn(move || {
        let mut reader = std::io::BufReader::new(stderr);
        let mut line = String::new();
        // The callback bridge announces itself from another thread, so the file
        // server's line is not reliably first; skip anything that is not it.
        let result = loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(count) if count > 0 && !line.starts_with(SERVE_STARTUP_PREFIX) => continue,
                other => break other,
            }
        };
        let _ = sender.send((result, line));
        let _ = std::io::copy(&mut reader, &mut std::io::sink());
    });
```

And use the constant where the port is parsed:

```rust
        .strip_prefix(SERVE_STARTUP_PREFIX)
```

- [ ] **Step 7: Run the tests to verify they pass**

Run: `cargo test --test bridge && cargo test --test serve && cargo test --lib armed`

Expected: PASS — 9 tests in `tests/bridge.rs` (Task 5's 5 plus the 4 here), 4 in
`tests/serve.rs`, 4 unit tests in `src/bridge/armed.rs`.

- [ ] **Step 8: Verify the gates**

```bash
wc -l src/bridge/armed.rs src/bridge.rs src/main.rs tests/bridge.rs tests/bridge/arming.rs tests/serve.rs
bash scripts/check-source-line-limit.sh
cargo clippy --all-targets --all-features -- -D warnings
cargo clippy --lib --bins --all-features -- -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic -D clippy::indexing_slicing
```

Expected: the line-limit script prints nothing and exits 0; both clippy passes
are clean. Expected sizes: `src/bridge/armed.rs` about 208 lines (39 for Task 4's
`Armed` and its imports, 4 more imports and 114 for the socket added here, 49 for
Task 4's unit tests, plus separators), `tests/bridge/arming.rs` 145, and
`tests/serve.rs` about 239 — all under the 250 gate, which fails at `>= 250`.
`tests/serve.rs` has only ~11 lines of headroom left afterwards, so a later task
that adds to it must move `spawn_serve`, `raw_status` and `Guard` into a
`tests/serve/serve_support.rs` module, the way `tests/daemon/daemon_support.rs`
already does.

The second clippy pass uses `--lib --bins`, not `--all-targets`: the strict
no-unwrap rules must cover `src/bridge/armed.rs`, which lives in the library
after Task 0, while the test targets keep their `unwrap` and `panic!`.

**If `wc -l` reports 250 or more for `src/bridge/armed.rs`**, split it rather
than trimming comments:

- Create `src/bridge/arming.rs` and move into it, unchanged: the four `use` lines added in Step 3, `MAX_ARM_LINE`, `ARM_READ_TIMEOUT`, `arm_socket_path`, `serve_arming`, `handle_arming`, `arm` and `arm_one`.
- Add `use super::armed::Armed;` and `use std::time::Duration;` at the top of the new file — it no longer inherits `armed.rs`'s imports.
- Leave `src/bridge/armed.rs` holding only the `Armed` type, its `impl`, its original imports and its `mod tests`.
- In `src/bridge.rs`, declare `mod arming;` beside `mod armed;` and re-export both: `pub use armed::Armed;` and `pub use arming::{arm, arm_socket_path, serve_arming};`.

Nothing outside `src/bridge.rs` changes: every caller and both test files already
reach these through `forward::bridge::…`.

This task leaves the work in a reviewable working-copy state. Do not commit —
this plan lands as one commit per PR.

---

### Task 7: Laptop callback listeners, replacing the SSH reaper

**Files:**
- Create: `src/callback.rs`, `tests/callback.rs`
- Modify: `src/lib.rs` (add `pub mod callback;`), `src/main.rs` (drop `mod forwards;`, take the port constants from `callback`), `src/daemon.rs` (use `Leases` instead of `ForwardTracker`)
- Test: `tests/callback.rs`, `tests/daemon/daemon_support.rs` (add `spawn_bridge` and `Daemon::log`), `tests/daemon/forwarding.rs`, `tests/daemon/forward_lifecycle.rs`, `tests/daemon/opening.rs`, `tests/daemon/custom_notifier.rs`

`src/forwards.rs` is left on disk but is no longer named by any `mod` declaration after this task, so it stops being compiled. Task 11 deletes the file.

**Interfaces:**
- Consumes:
  - `pipe::bidirectional(left: TcpStream, right: TcpStream) -> std::io::Result<()>` (Task 3).
  - `Config` with `peer: String`, `bridge_port: u16`, `forward_ttl_secs: u64`; `Config::peer_ip(&self) -> Result<Option<std::net::IpAddr>, ConfigError>`; `#[doc(hidden)] pub fn Config::default_values_for_test() -> Config` (Task 1).
  - `src/lib.rs` exists and `src/main.rs` reaches library modules as `forward::<module>` (Task 0).
  - Existing, unchanged: `localhost::forward_ports(&Url) -> Vec<u16>`, `daemon_support::{send, start, stub, wait_for}`, `Daemon::wait_for_log`.
- Produces:
  - `callback::Leases` — `#[derive(Clone, Default)] pub struct Leases`, plus `Leases::new() -> Leases`.
  - `callback::request(cfg: &Config, leases: &Leases, port: u16)`.
  - `callback::request_on(cfg: &Config, leases: &Leases, port: u16) -> Option<u16>` — port `0` binds an ephemeral port and returns the number chosen.
  - `callback::spawn_reaper(leases: Leases)`.
  - `callback::is_dynamic_port(port: u16) -> bool`.
  - `pub const callback::MAX_DYNAMIC_FORWARDS: usize = 4;`
  - `pub const callback::PCSC_PORT: u16 = 12_799;`, `pub const callback::CHANNEL_PORT: u16 = 12_800;`, `pub const callback::FILES_PORT: u16 = 12_802;`
  - `pub mod callback;` in `src/lib.rs`.
  - Test support: `daemon_support::spawn_bridge(record: &Path) -> u16`, `Daemon::log(&self) -> String`.

Lease semantics carry over from `ForwardTracker` unchanged: the same `forward_ttl_secs`, the same refresh-on-reuse, the same `MAX_DYNAMIC_FORWARDS` cap of 4. What changes is that release is "drop the listener", not "shell out to `ssh -O cancel`". The old plan's test-only `request_ephemeral` is gone: `request_on(cfg, leases, 0)` covers it, so there is one entry point instead of two.

**Two decisions this task settles, because the code depends on them:**

1. **A lease is one logical port served by one or two listener threads.** Bind `127.0.0.1:port` first, take the bound number from it, then bind `[::1]:bound`. Both listeners share one `Arc<AtomicBool>` stop flag and one map entry, so expiry closes both at once. Both families are required: `localhost::forward_ports` deliberately recognises `[::1]` (`src/localhost.rs:3`), and a browser may resolve `localhost` to either family.
2. **An IPv4 bind failure fails the request; an IPv6 bind failure is tolerated with a log.** IPv4 is the leg that must work — `ssh -L 127.0.0.1:N:127.0.0.1:N` only ever provided that one, so failing closed on it loses nothing and refusing to bind keeps us from squatting a port we cannot serve. IPv6 is additive coverage, and hosts with IPv6 disabled at the kernel (`net.ipv6.conf.all.disable_ipv6=1`, common in containers) return `EADDRNOTAVAIL` for `[::1]`. Failing the whole lease there would break OAuth entirely on a machine where today's SSH forward works, which is strictly worse than the status quo.

- [ ] **Step 1: Write the failing tests in `tests/callback.rs`**

```rust
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::Duration;

const CALLBACK_REQUEST: &str = "GET /cb?code=1 HTTP/1.1\r\n\r\n";

/// Stands in for the devbox bridge: reports the `CONNECT <port>` line it was
/// asked for, then echoes everything after it.
fn spawn_fake_bridge() -> (u16, Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = channel();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let tx = tx.clone();
            std::thread::spawn(move || echo(stream, &tx));
        }
    });
    (port, rx)
}

/// Reads the request line a byte at a time: a `BufReader` would swallow the
/// payload that follows it.
fn echo(mut stream: TcpStream, tx: &Sender<String>) {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    while stream.read(&mut byte).unwrap_or(0) == 1 && byte[0] != b'\n' {
        line.push(byte[0]);
    }
    tx.send(String::from_utf8_lossy(&line).trim().to_owned())
        .unwrap();
    let mut chunk = [0u8; 512];
    while let Ok(read) = stream.read(&mut chunk) {
        if read == 0 || stream.write_all(&chunk[..read]).is_err() {
            return;
        }
    }
}

fn cfg(bridge_port: u16) -> forward::config::Config {
    let mut cfg = forward::config::Config::default_values_for_test();
    cfg.bridge_port = bridge_port;
    cfg.peer = "127.0.0.1".to_owned();
    cfg.forward_ttl_secs = 30;
    cfg
}

fn connect(address: &str, port: u16) -> TcpStream {
    let stream = TcpStream::connect((address, port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream
}

fn read_back(stream: &mut TcpStream, expected: &str) -> String {
    let mut buffer = vec![0u8; expected.len()];
    stream.read_exact(&mut buffer).unwrap();
    String::from_utf8(buffer).unwrap()
}

fn asked_for(requests: &Receiver<String>) -> String {
    requests.recv_timeout(Duration::from_secs(5)).unwrap()
}

#[test]
fn a_callback_port_is_served_on_loopback_and_relayed_to_the_bridge() {
    // Given: a fake devbox bridge.
    let (bridge_port, requests) = spawn_fake_bridge();
    let leases = forward::callback::Leases::new();

    // When: the daemon is asked for a callback port and a browser connects to it.
    let port = forward::callback::request_on(&cfg(bridge_port), &leases, 0).unwrap();
    let mut browser = connect("127.0.0.1", port);
    browser.write_all(CALLBACK_REQUEST.as_bytes()).unwrap();

    // Then: the bridge is asked for exactly that port, and bytes flow back.
    assert_eq!(asked_for(&requests), format!("CONNECT {port}"));
    assert_eq!(read_back(&mut browser, CALLBACK_REQUEST), CALLBACK_REQUEST);
}

#[test]
fn both_loopback_families_are_served() {
    // Given: a leased callback port. `forward_ports` recognises `[::1]`, and a
    // browser may resolve `localhost` to either family.
    if TcpListener::bind("[::1]:0").is_err() {
        eprintln!("skipping: no IPv6 loopback on this host, where the bind is tolerated");
        return;
    }
    let (bridge_port, requests) = spawn_fake_bridge();
    let leases = forward::callback::Leases::new();
    let port = forward::callback::request_on(&cfg(bridge_port), &leases, 0).unwrap();

    for address in ["127.0.0.1", "::1"] {
        // When: a browser connects over that family.
        let mut browser = connect(address, port);
        browser.write_all(CALLBACK_REQUEST.as_bytes()).unwrap();

        // Then: it reaches the bridge asking for the same single logical port.
        assert_eq!(
            asked_for(&requests),
            format!("CONNECT {port}"),
            "no bridge request for a browser on {address}"
        );
        assert_eq!(read_back(&mut browser, CALLBACK_REQUEST), CALLBACK_REQUEST);
    }
}

#[test]
fn the_lease_is_released_when_it_expires() {
    // Given: a callback port leased for a very short window.
    let (bridge_port, _requests) = spawn_fake_bridge();
    let mut cfg = cfg(bridge_port);
    cfg.forward_ttl_secs = 1;
    let leases = forward::callback::Leases::new();
    let port = forward::callback::request_on(&cfg, &leases, 0).unwrap();
    forward::callback::spawn_reaper(leases);

    // When: the deadline passes.
    for _ in 0..60 {
        if TcpStream::connect(("127.0.0.1", port)).is_err() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    // Then: the listener is gone, so the port is free for other tools — released
    // by dropping it, with no wake-up connection needed.
    assert!(
        TcpStream::connect(("127.0.0.1", port)).is_err(),
        "port {port} still listening after its lease expired"
    );
}

#[test]
fn an_expiring_lease_lets_an_open_transfer_finish() {
    // Given: an open callback connection on a one-second lease.
    let (bridge_port, requests) = spawn_fake_bridge();
    let mut cfg = cfg(bridge_port);
    cfg.forward_ttl_secs = 1;
    let leases = forward::callback::Leases::new();
    let port = forward::callback::request_on(&cfg, &leases, 0).unwrap();
    forward::callback::spawn_reaper(leases);
    let mut browser = connect("127.0.0.1", port);
    browser.write_all(b"first\n").unwrap();
    assert_eq!(asked_for(&requests), format!("CONNECT {port}"));
    assert_eq!(read_back(&mut browser, "first\n"), "first\n");

    // When: the lease expires while that connection is still open.
    std::thread::sleep(Duration::from_millis(2_500));

    // Then: a new connection is refused, the listener having closed...
    assert!(
        TcpStream::connect(("127.0.0.1", port)).is_err(),
        "port {port} still accepting after its lease expired"
    );
    // ...while the connection already accepted keeps carrying bytes.
    browser.write_all(b"second\n").unwrap();
    assert_eq!(read_back(&mut browser, "second\n"), "second\n");
}

#[test]
fn requesting_the_same_port_twice_does_not_bind_twice() {
    // Given: a port already leased.
    let (bridge_port, _requests) = spawn_fake_bridge();
    let cfg = cfg(bridge_port);
    let leases = forward::callback::Leases::new();
    let port = forward::callback::request_on(&cfg, &leases, 0).unwrap();

    // When: it is requested again, as a repeated login does.
    forward::callback::request(&cfg, &leases, port);

    // Then: the lease was refreshed and the listener still works, rather than a
    // second bind failing on an address already in use.
    assert!(TcpStream::connect(("127.0.0.1", port)).is_ok());
}

#[test]
fn a_port_already_held_by_another_tool_is_reported_not_fatal() {
    // Given: an unrelated tool holding the callback port — the case that locked
    // a separate tool out of its own callback port.
    let squatter = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = squatter.local_addr().unwrap().port();
    let (bridge_port, _requests) = spawn_fake_bridge();
    let leases = forward::callback::Leases::new();

    // When: the daemon tries to serve that port.
    let served = forward::callback::request_on(&cfg(bridge_port), &leases, port);

    // Then: the request is refused instead of aborting the daemon, and the
    // squatter still owns the port.
    assert_eq!(served, None);
    assert!(TcpStream::connect(("127.0.0.1", port)).is_ok());
    assert!(squatter.accept().is_ok());
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --test callback`
Expected: FAIL to compile — `error[E0433]: failed to resolve: could not find 'callback' in 'forward'`, once per use.

- [ ] **Step 3: Implement `src/callback.rs`**

`request_on` resolves the peer *before* it binds anything. That ordering is the point: a port bound with no reachable bridge is a port squatted on another tool for a whole TTL, which is the failure this whole plan exists to remove.

```rust
use crate::config::Config;
use crate::pipe::bidirectional;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::io::{ErrorKind, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

const REAPER_INTERVAL: Duration = Duration::from_millis(100);
/// How long an idle accept loop waits before re-checking its stop flag.
const ACCEPT_POLL: Duration = Duration::from_millis(20);
pub const MAX_DYNAMIC_FORWARDS: usize = 4;
pub const PCSC_PORT: u16 = 12_799;
pub const CHANNEL_PORT: u16 = 12_800;
pub const FILES_PORT: u16 = 12_802;
const STATIC_TUNNEL_PORTS: [u16; 3] = [PCSC_PORT, CHANNEL_PORT, FILES_PORT];

/// Ports carried by the SSH tunnel or served by forward itself, never leased.
pub fn is_dynamic_port(port: u16) -> bool {
    !STATIC_TUNNEL_PORTS.contains(&port)
}

struct Lease {
    deadline: Instant,
    stop: Arc<AtomicBool>,
}

/// One logical lease per callback port, however many listeners serve it.
#[derive(Clone, Default)]
pub struct Leases {
    inner: Arc<Mutex<HashMap<u16, Lease>>>,
}

impl Leases {
    pub fn new() -> Self {
        Self::default()
    }

    /// True when a live lease was extended, so no new listener is needed.
    fn refresh(&self, port: u16, ttl: Duration) -> bool {
        let mut leases = self.inner.lock();
        match leases.get_mut(&port) {
            Some(lease) => {
                lease.deadline = Instant::now() + ttl;
                true
            }
            None => false,
        }
    }

    fn insert(&self, port: u16, ttl: Duration, stop: Arc<AtomicBool>) {
        self.inner.lock().insert(
            port,
            Lease {
                deadline: Instant::now() + ttl,
                stop,
            },
        );
    }

    /// Flip the stop flag of every expired lease and forget it.
    fn expire(&self) -> Vec<u16> {
        let now = Instant::now();
        let mut expired = Vec::new();
        self.inner.lock().retain(|port, lease| {
            if lease.deadline <= now {
                lease.stop.store(true, Ordering::Relaxed);
                expired.push(*port);
                return false;
            }
            true
        });
        expired
    }
}

pub fn request(cfg: &Config, leases: &Leases, port: u16) {
    drop(request_on(cfg, leases, port));
}

/// Serve `port` on laptop loopback, relaying each connection to the devbox
/// bridge. Port `0` binds an ephemeral port and returns the number chosen.
pub fn request_on(cfg: &Config, leases: &Leases, port: u16) -> Option<u16> {
    let ttl = Duration::from_secs(cfg.forward_ttl_secs);
    if port != 0 && leases.refresh(port, ttl) {
        eprintln!("forward: refreshed callback lease for port {port}");
        return Some(port);
    }
    // Fail closed before binding: a port we cannot relay is a port squatted on
    // some other tool for a whole TTL.
    let Ok(Some(peer)) = cfg.peer_ip() else {
        eprintln!("forward: no literal peer address; not serving callback port {port}");
        return None;
    };
    let bridge = SocketAddr::new(peer, cfg.bridge_port);
    let listener = match bind_polling(Ipv4Addr::LOCALHOST.into(), port) {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!("forward: cannot serve callback port {port}: {error}");
            return None;
        }
    };
    let bound = listener.local_addr().ok()?.port();
    let stop = Arc::new(AtomicBool::new(false));
    leases.insert(bound, ttl, Arc::clone(&stop));
    spawn_accept_loop(listener, bridge, bound, Arc::clone(&stop));
    // Tolerated rather than fatal: a host with IPv6 disabled must still get
    // callbacks, which is all `ssh -L 127.0.0.1:N` ever delivered.
    match bind_polling(Ipv6Addr::LOCALHOST.into(), bound) {
        Ok(listener) => spawn_accept_loop(listener, bridge, bound, stop),
        Err(error) => eprintln!("forward: callback port {bound} has no [::1] listener: {error}"),
    }
    eprintln!("forward: callback port {bound} served on loopback");
    Some(bound)
}

fn bind_polling(ip: IpAddr, port: u16) -> std::io::Result<TcpListener> {
    let listener = TcpListener::bind((ip, port))?;
    listener.set_nonblocking(true)?;
    Ok(listener)
}

fn spawn_accept_loop(listener: TcpListener, bridge: SocketAddr, port: u16, stop: Arc<AtomicBool>) {
    // The listener drops when the loop returns, and that drop is the entire
    // release mechanism: nothing has to connect to the port to free it.
    drop(thread::spawn(move || {
        accept_loop(&listener, bridge, port, &stop)
    }));
}

fn accept_loop(listener: &TcpListener, bridge: SocketAddr, port: u16, stop: &AtomicBool) {
    while !stop.load(Ordering::Relaxed) {
        match listener.accept() {
            // Detached on purpose: a transfer already accepted runs to completion
            // even after the lease expires and the listener closes.
            Ok((browser, _)) => drop(thread::spawn(move || relay(bridge, browser, port))),
            Err(error) if error.kind() == ErrorKind::WouldBlock => thread::sleep(ACCEPT_POLL),
            Err(error) => {
                eprintln!("forward: callback accept failed on {port}: {error}");
                return;
            }
        }
    }
}

fn relay(bridge: SocketAddr, browser: TcpStream, port: u16) {
    let mut upstream = match TcpStream::connect(bridge) {
        Ok(upstream) => upstream,
        Err(error) => {
            eprintln!("forward: cannot reach callback bridge at {bridge}: {error}");
            return;
        }
    };
    if let Err(error) = writeln!(upstream, "CONNECT {port}") {
        eprintln!("forward: cannot ask the bridge for callback port {port}: {error}");
        return;
    }
    if let Err(error) = bidirectional(browser, upstream) {
        eprintln!("forward: callback relay for port {port} ended: {error}");
    }
}

pub fn spawn_reaper(leases: Leases) {
    if let Err(error) = thread::Builder::new()
        .name("forward-reaper".to_owned())
        .spawn(move || {
            loop {
                thread::sleep(REAPER_INTERVAL);
                for port in leases.expire() {
                    // The accept loops poll `stop`, so the listeners close
                    // themselves; no wake-up connection is involved.
                    eprintln!("forward: callback port {port} released");
                }
            }
        })
    {
        eprintln!("forward: failed to start the callback reaper: {error}");
    }
}
```

Three things in that code are load-bearing and must not be "simplified" back:

- **`set_nonblocking(true)` plus an `ACCEPT_POLL` sleep on `WouldBlock`, not `listener.incoming()`.** A blocking accept loop can only observe the stop flag when a connection arrives, so the previous shape had the reaper best-effort connect to its own port to wake it. If that connect fails, the listener survives and the port stays claimed — which is the exact failure that previously locked an unrelated tool out of its own callback port. Polling means the loop returns within `ACCEPT_POLL` of expiry with no cooperation from anyone.
- **`relay` dials `bridge`, a `SocketAddr` built from `cfg.peer_ip()`.** It is a resolved literal by construction, so no hostname can enter the dial path. `cfg.peer_host` is display-only and is never read here.
- **Relay threads are detached and hold no reference to the listener or the flag.** A connection accepted before expiry runs to completion after the listener closes, which the design requires.

In `src/lib.rs`, add `pub mod callback;` in alphabetical position (before `pub mod config;`). `src/callback.rs` is declared **only** there — do not also add `mod callback;` to `src/main.rs`, or the module would be compiled twice.

In `src/main.rs`, delete the `mod forwards;` line and repoint the two port constants:

```rust
use forward::callback::CHANNEL_PORT;
pub(crate) use forward::callback::FILES_PORT;
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --test callback`
Expected: PASS, 6 tests. On a host without IPv6 loopback, `both_loopback_families_are_served` still passes and prints `skipping: no IPv6 loopback on this host, where the bind is tolerated`.

- [ ] **Step 5: Port `src/daemon.rs` from `ForwardTracker` to `Leases`**

`src/daemon.rs` lives in the binary crate while `callback` lives in the library, so the new import is `forward::callback::…`. Match the prefix the neighbouring import lines in this file already use: if they read `use forward::config::Config;` use `forward::callback::…` as written below; if they still read `use crate::config::Config;` use `crate::callback::…` instead. Every edit below is a one-line replacement, so the file's length changes only by the one deletion.

| Line | Replace | With |
|---|---|---|
| 2 | `use crate::forwards::{ForwardTracker, is_dynamic_port, request_forward, spawn_reaper};` | `use forward::callback::{Leases, MAX_DYNAMIC_FORWARDS, is_dynamic_port, request, spawn_reaper};` |
| 18 | `const MAX_DYNAMIC_FORWARDS: usize = 4;` | *(delete the line — the constant now lives in `callback`, where Task 8 can also reach it)* |
| 40 | `    let forwards = ForwardTracker::new();` | `    let leases = Leases::new();` |
| 41 | `    spawn_reaper(cfg.clone(), forwards.clone());` | `    spawn_reaper(leases.clone());` |
| 51 | `                let connection_forwards = forwards.clone();` | `                let connection_leases = leases.clone();` |
| 59 | `                            connection_forwards,` | `                            connection_leases,` |
| 75 | `    forwards: ForwardTracker,` | `    leases: Leases,` |
| 83 | `            open_permitted_url(&cfg, &url, &recent_opens, &forwards);` | `            open_permitted_url(&cfg, &url, &recent_opens, &leases);` |
| 89 | `                open_permitted_url(&cfg, &url, &recent_opens, &forwards);` | `                open_permitted_url(&cfg, &url, &recent_opens, &leases);` |
| 99 | `    forwards: &ForwardTracker,` | `    leases: &Leases,` |
| 107 | `            forward_url(cfg, url, forwards);` | `            forward_url(cfg, url, leases);` |
| 116 | `fn forward_url(cfg: &Config, url: &Url, forwards: &ForwardTracker) {` | `fn forward_url(cfg: &Config, url: &Url, leases: &Leases) {` |
| 127 | `        request_forward(cfg, forwards, port);` | `        request(cfg, leases, port);` |

The body of `forward_url` is otherwise untouched: it still skips static ports with `is_dynamic_port`, still stops leasing at `MAX_DYNAMIC_FORWARDS`, and still logs `dynamic forward limit reached; dropped {dropped} port(s)`.

- [ ] **Step 6: Rewrite the SSH-stub expectations in the daemon suite**

Four daemon test files assert against an `ssh` stub. Nothing shells out to `ssh` any more, so `opening.rs`'s and the two forwarding files' positive assertions break outright, and the negative ones (`!sshed.exists()`) would start passing for the wrong reason — they would hold even if callback forwarding were completely broken. Both kinds get repointed at the new observables: the daemon's own log, and a fake bridge that records the `CONNECT <port>` line it is asked for.

**6a. `tests/daemon/daemon_support.rs`** — change line 1 to `use std::io::{Read, Write};`, add a method to `impl Daemon`, and add one free function:

```rust
    pub fn log(&self) -> String {
        std::fs::read_to_string(&self.stderr_log).unwrap_or_default()
    }
```

```rust
/// Stands in for the devbox callback bridge: records the `CONNECT <port>` line
/// of each connection, read a byte at a time so no payload is swallowed.
pub fn spawn_bridge(record: &Path) -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let record = record.to_path_buf();
    thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            let mut line = Vec::new();
            let mut byte = [0u8; 1];
            while stream.read(&mut byte).unwrap_or(0) == 1 && byte[0] != b'\n' {
                line.push(byte[0]);
            }
            let mut log = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&record)
                .unwrap();
            writeln!(log, "{}", String::from_utf8_lossy(&line).trim()).unwrap();
        }
    });
    port
}
```

**6b. `tests/daemon/forwarding.rs`** — replace the whole file. What changes: every `ssh` stub and `sshed` path is gone; configs gain `peer = "127.0.0.1"` and `bridge_port`; the ports move into the 19xxx range the lifecycle tests already use, because the daemon now really binds them on the test host; and because nothing is dialled until a browser arrives, the first test connects to the leased port to observe the relay. `ssh_failure_still_opens_url` becomes `callback_setup_failure_still_opens_url` — the "forwarding failed but the URL still opens" path is now an unconfigured peer.

```rust
use super::daemon_support::{send, spawn_bridge, start, stub, wait_for};
use std::io::Write;
use std::net::TcpStream;

#[test]
fn redirect_uri_port_is_forwarded() {
    // Given: a daemon whose peer is a fake devbox bridge.
    let dir = tempfile::tempdir().unwrap();
    let bridged = dir.path().join("bridged");
    let bridge_port = spawn_bridge(&bridged);
    let opener = stub(dir.path(), "opener", "true");
    let (daemon, port) = start(
        dir.path(),
        &format!(
            r#"
mode = "auto"
opener = ["{opener}"]
peer = "127.0.0.1"
bridge_port = {bridge_port}
"#
        ),
    );

    // When: a URL carrying a loopback redirect_uri arrives and a browser then
    // connects to the port it named.
    send(
        port,
        "https://accounts.google.com/auth?redirect_uri=http%3A%2F%2Flocalhost%3A19005%2F",
    );
    daemon.wait_for_log("callback port 19005 served on loopback");
    let mut browser = TcpStream::connect(("127.0.0.1", 19_005)).unwrap();
    browser.write_all(b"GET /cb HTTP/1.1\r\n\r\n").unwrap();

    // Then: the daemon asks the bridge for exactly that port.
    assert_eq!(wait_for(&bridged).trim(), "CONNECT 19005");
}

#[test]
fn callback_setup_failure_still_opens_url() {
    // Given: a daemon with no peer, so no callback port can be served at all.
    let dir = tempfile::tempdir().unwrap();
    let opened = dir.path().join("opened");
    let opener = stub(
        dir.path(),
        "opener",
        &format!("echo \"$@\" >> {}", opened.display()),
    );
    let (daemon, port) = start(
        dir.path(),
        &format!(
            r#"
mode = "auto"
opener = ["{opener}"]
"#
        ),
    );

    // When: a URL naming a loopback callback port arrives.
    send(port, "http://localhost:19006/cb");

    // Then: the URL still opens, as it did when an SSH forward failed.
    assert!(wait_for(&opened).contains("http://localhost:19006/cb"));
    daemon.wait_for_log("no literal peer address; not serving callback port 19006");
}

#[test]
fn file_server_port_not_dynamically_forwarded() {
    // Given: a daemon that could serve callback ports, so a static port being
    // skipped is the only reason nothing is leased.
    let dir = tempfile::tempdir().unwrap();
    let bridged = dir.path().join("bridged");
    let bridge_port = spawn_bridge(&bridged);
    let opened = dir.path().join("opened");
    let opener = stub(
        dir.path(),
        "opener",
        &format!("echo \"$@\" >> {}", opened.display()),
    );
    let (daemon, port) = start(
        dir.path(),
        &format!(
            r#"
mode = "auto"
opener = ["{opener}"]
peer = "127.0.0.1"
bridge_port = {bridge_port}
"#
        ),
    );

    // When: a file-preview URL on the static port arrives.
    send(port, "http://localhost:12802/home/ubuntu/x.md");

    // Then: it opens without the daemon leasing the static file-server port.
    assert!(wait_for(&opened).contains("http://localhost:12802/home/ubuntu/x.md"));
    assert!(
        !daemon.log().contains("callback port 12802"),
        "must not lease the static file-server port"
    );
    assert!(!bridged.exists(), "must not dial the bridge for 12802");
}

#[test]
fn redirect_uri_forwards_are_capped_at_four() {
    // Given: a daemon that can serve callback ports.
    let dir = tempfile::tempdir().unwrap();
    let bridged = dir.path().join("bridged");
    let bridge_port = spawn_bridge(&bridged);
    let opener = stub(dir.path(), "opener", "true");
    let (daemon, port) = start(
        dir.path(),
        &format!(
            r#"
mode = "auto"
opener = ["{opener}"]
peer = "127.0.0.1"
bridge_port = {bridge_port}
"#
        ),
    );

    // When: one URL names six loopback callback ports.
    send(
        port,
        "https://example.com/auth?redirect_uri=http%3A%2F%2Flocalhost%3A19011%2F&redirect_uri=http%3A%2F%2Flocalhost%3A19012%2F&redirect_uri=http%3A%2F%2Flocalhost%3A19013%2F&redirect_uri=http%3A%2F%2Flocalhost%3A19014%2F&redirect_uri=http%3A%2F%2Flocalhost%3A19015%2F&redirect_uri=http%3A%2F%2Flocalhost%3A19016%2F",
    );

    // Then: only four are leased and the rest are dropped.
    daemon.wait_for_log("dynamic forward limit reached; dropped 2 port(s)");
    assert_eq!(daemon.log().matches("served on loopback").count(), 4);
}
```

**6c. `tests/daemon/forward_lifecycle.rs`** — replace the whole file. What changes: the `wait_for_lines` helper and its `panic!("expected {count} SSH invocations")` are deleted along with the `stub`, `Path`-for-`wait_for_lines`, `thread` and `Duration` imports, because every wait is now a daemon log line rather than a count of lines in an SSH stub file. `expires_with_the_exact_local_forward_cancel_spec` becomes `an_expired_lease_stops_listening`: there is no cancel spec to get exactly right any more, which is the entire point of the change, so the assertion is that the port stops accepting. `failed_cancel_is_logged_without_stopping_later_urls` becomes `an_unreachable_bridge_does_not_stop_later_urls`, preserving the property under test — a failure in the forwarding path is logged and does not poison later URLs — against the mechanism that now exists.

```rust
use super::daemon_support::{send, spawn_bridge, start};
use std::net::{TcpListener, TcpStream};
use std::path::Path;

fn config(bridge_port: u16, ttl_secs: u64) -> String {
    format!(
        r#"
mode = "auto"
opener = ["true"]
peer = "127.0.0.1"
bridge_port = {bridge_port}
forward_ttl_secs = {ttl_secs}
"#
    )
}

/// A port nothing is listening on: bound to learn the number, then released.
fn closed_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn bridge(dir: &Path) -> u16 {
    spawn_bridge(&dir.join("bridged"))
}

#[test]
fn an_expired_lease_stops_listening() {
    // Given: a callback port leased for one second.
    let dir = tempfile::tempdir().unwrap();
    let (daemon, port) = start(dir.path(), &config(bridge(dir.path()), 1));
    send(port, "http://localhost:19001/callback");
    daemon.wait_for_log("callback port 19001 served on loopback");
    assert!(TcpStream::connect(("127.0.0.1", 19_001)).is_ok());

    // When: the lease expires.
    daemon.wait_for_log("callback port 19001 released");

    // Then: release is the listener closing, not an `ssh -O cancel` that could
    // take unrelated forwards with it.
    assert!(
        TcpStream::connect(("127.0.0.1", 19_001)).is_err(),
        "port 19001 still listening after its lease expired"
    );
}

#[test]
fn static_tunnel_ports_are_never_leased() {
    // Given: a daemon that can serve callback ports.
    let dir = tempfile::tempdir().unwrap();
    let bridged = dir.path().join("bridged");
    let bridge_port = spawn_bridge(&bridged);
    let (daemon, port) = start(dir.path(), &config(bridge_port, 1));

    // When: URLs naming each static tunnel port arrive.
    for static_port in [12_799, 12_800, 12_802] {
        send(port, &format!("http://localhost:{static_port}/callback"));
        daemon.wait_for_log(&format!(
            "opener spawned for http://localhost:{static_port}/callback"
        ));
    }

    // Then: none of them is ever leased or relayed. 12799 above all: on the
    // devbox that port is the far end of the PC/SC tunnel.
    assert!(
        !daemon.log().contains("served on loopback"),
        "static tunnel ports must never be leased"
    );
    assert!(
        !bridged.exists(),
        "static tunnel ports must never be dialled"
    );
}

#[test]
fn re_request_refreshes_a_live_lease_without_a_second_listener() {
    // Given: a live lease on a callback port, with a TTL long enough that the
    // second request lands inside it.
    let dir = tempfile::tempdir().unwrap();
    let (daemon, port) = start(dir.path(), &config(bridge(dir.path()), 30));
    send(port, "http://localhost:19002/first");
    daemon.wait_for_log("callback port 19002 served on loopback");

    // When: the same port is requested again.
    send(port, "http://localhost:19002/second");

    // Then: the lease is refreshed, and no second bind is attempted.
    daemon.wait_for_log("refreshed callback lease for port 19002");
    assert_eq!(daemon.log().matches("served on loopback").count(), 1);
    assert!(TcpStream::connect(("127.0.0.1", 19_002)).is_ok());
}

#[test]
fn an_unreachable_bridge_does_not_stop_later_urls() {
    // Given: a daemon whose bridge port has nothing behind it.
    let dir = tempfile::tempdir().unwrap();
    let (daemon, port) = start(dir.path(), &config(closed_port(), 30));
    send(port, "http://localhost:19003/callback");
    daemon.wait_for_log("callback port 19003 served on loopback");

    // When: a browser connects and the relay cannot reach the bridge.
    drop(TcpStream::connect(("127.0.0.1", 19_003)).unwrap());
    daemon.wait_for_log("cannot reach callback bridge");

    // Then: the failure is logged and later URLs are still served.
    send(port, "http://localhost:19004/callback");
    daemon.wait_for_log("callback port 19004 served on loopback");
}
```

**6d. `tests/daemon/opening.rs`** — two of its five tests carry SSH stubs. Change line 1 to `use super::daemon_support::{send, spawn_bridge, start, stub, wait_for};` and add `use std::net::TcpStream;`. Replace the first two tests; leave `opener_receives_reentry_marker`, `auto_mode_rejects_non_web_scheme` and `opener_with_lingering_grandchild_does_not_block_its_handler` untouched.

```rust
#[test]
fn allowlist_hit_opens_and_forwards_localhost() {
    // Given: an allowlisted loopback URL and a fake devbox bridge.
    let dir = tempfile::tempdir().unwrap();
    let opened = dir.path().join("opened");
    let bridged = dir.path().join("bridged");
    let bridge_port = spawn_bridge(&bridged);
    let opener = stub(
        dir.path(),
        "opener",
        &format!("echo \"$@\" >> {}", opened.display()),
    );
    let (daemon, port) = start(
        dir.path(),
        &format!(
            r#"
mode = "allowlist"
opener = ["{opener}"]
peer = "127.0.0.1"
bridge_port = {bridge_port}
allow = ["localhost", "github.com/login"]
"#
        ),
    );

    // When: the URL arrives and a browser connects to the port it named.
    send(port, "http://localhost:19021/cb?code=abc");
    assert!(wait_for(&opened).contains("http://localhost:19021/cb?code=abc"));
    daemon.wait_for_log("callback port 19021 served on loopback");
    drop(TcpStream::connect(("127.0.0.1", 19_021)).unwrap());

    // Then: it opens and the callback port is relayed to the bridge.
    assert_eq!(wait_for(&bridged).trim(), "CONNECT 19021");
}

#[test]
fn auto_mode_opens_everything_without_leasing_for_remote() {
    // Given: a daemon that could lease callback ports, so a remote URL having
    // none is the only reason nothing is leased.
    let dir = tempfile::tempdir().unwrap();
    let opened = dir.path().join("opened");
    let bridged = dir.path().join("bridged");
    let bridge_port = spawn_bridge(&bridged);
    let opener = stub(
        dir.path(),
        "opener",
        &format!("echo \"$@\" >> {}", opened.display()),
    );
    let (daemon, port) = start(
        dir.path(),
        &format!(
            r#"
mode = "auto"
opener = ["{opener}"]
peer = "127.0.0.1"
bridge_port = {bridge_port}
"#
        ),
    );

    // When: a URL with no loopback port arrives.
    send(port, "https://random.example/x");

    // Then: it opens and no callback port is leased.
    assert!(wait_for(&opened).contains("https://random.example/x"));
    assert!(!daemon.log().contains("served on loopback"));
    assert!(!bridged.exists());
}
```

**6e. `tests/daemon/custom_notifier.rs`** — one test, `declined_notification_does_not_forward_or_open`. Change line 1 to `use super::daemon_support::{send, spawn_bridge, start, stub, wait_for};` and replace that test. Its config gains a peer and a bridge for the same reason as above: without them the assertion would pass whether or not the decline was respected.

```rust
#[test]
fn declined_notification_does_not_forward_or_open() {
    let dir = tempfile::tempdir().unwrap();
    let opened = dir.path().join("opened");
    let notified = dir.path().join("notified");
    let bridged = dir.path().join("bridged");
    let bridge_port = spawn_bridge(&bridged);
    let opener = stub(
        dir.path(),
        "opener",
        &format!("echo \"$@\" >> {}", opened.display()),
    );
    let notifier = stub(
        dir.path(),
        "notifier",
        &format!("echo \"$@\" >> {}", notified.display()),
    );
    let (daemon, port) = start(
        dir.path(),
        &format!(
            r#"
opener = ["{opener}"]
notifier = ["{notifier}"]
peer = "127.0.0.1"
bridge_port = {bridge_port}
"#
        ),
    );
    send(port, "http://localhost:19031/declined");
    assert!(wait_for(&notified).contains("http://localhost:19031/declined"));
    daemon.wait_for_log("notification declined: http://localhost:19031/declined");
    assert!(
        !daemon.log().contains("callback port 19031"),
        "declined URLs must not lease callback ports"
    );
    assert!(!bridged.exists(), "declined URLs must not dial the bridge");
    assert!(!opened.exists(), "declined URLs must not open");
}
```

- [ ] **Step 7: Run the daemon suite to verify it passes**

Run: `cargo test --test daemon`
Expected: PASS, every test in the suite. The daemon tests are serialized by `DAEMON_TEST_LOCK`, and `Daemon::drop` kills and reaps the child before releasing that lock, so the fixed ports (19001-19006, 19011-19016, 19021, 19031) are free again before the next test binds them.

- [ ] **Step 8: Verify the constraints**

```bash
wc -l src/callback.rs src/daemon.rs src/main.rs tests/callback.rs \
      tests/daemon/daemon_support.rs tests/daemon/forwarding.rs \
      tests/daemon/forward_lifecycle.rs tests/daemon/opening.rs \
      tests/daemon/custom_notifier.rs
cargo clippy --all-targets --all-features -- -D warnings
cargo clippy --lib --bins --all-features -- -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic -D clippy::indexing_slicing
```

Expected: every file strictly under 250 lines — `src/callback.rs` 183, `src/daemon.rs` 161 (162 today, one line deleted), `tests/callback.rs` 197, `tests/daemon/forwarding.rs` ~135, `tests/daemon/forward_lifecycle.rs` ~112, `tests/daemon/daemon_support.rs` ~148, `tests/daemon/opening.rs` ~155, `tests/daemon/custom_notifier.rs` ~170. Both clippy passes clean.

The second command is target-scoped, not `--all-targets`, and that is deliberate: restricting it to `--lib --bins` is exactly what keeps the no-panic rule on shipped code while letting test code use `unwrap`, which every existing test file already does. `--lib` is included because `src/callback.rs` lives in the library after Task 0's split, so CI's `--bins`-only invocation (`.github/workflows/ci.yml:32`) would not otherwise lint it. `src/callback.rs` contains no `unwrap`, `expect`, `panic!` or slice indexing; if the pass flags anything there, fix the code rather than the command.

Leave the working copy uncommitted; the plan lands as one commit after every task is accepted.

---

**Unresolved, and why:**

1. **`src/forwards.rs`'s fate straddles this task and Task 11.** The fixed numbering gives Task 7 "replaces `src/forwards.rs`" and Task 11 "deletes `src/forwards.rs`", but the file cannot simply sit there once `daemon.rs` stops calling it: `forwards` is binary-private, so its now-unreachable `pub` items become `dead_code` and `-D warnings` fails. I resolved it by having Task 7 remove `mod forwards;` from `main.rs` and move the port constants to `callback`, which leaves the file on disk and uncompiled for Task 11 to `rm`. Both task rows stay true and the build stays clean at every point, but Task 11's implementer must not be surprised to find the file already orphaned — the coordinator should make sure Task 11's text says "delete the now-unreferenced `src/forwards.rs`" rather than implying it is still wired in.

2. **`src/daemon.rs`'s import prefix depends on Task 0's library split.** Whether `daemon.rs` reaches library modules as `crate::` or `forward::` is settled by Task 0, which I cannot see. Step 5 gives the exact line for both cases and tells the implementer to match the neighbouring imports, so it is executable either way — but it is the one instruction in this task that reads a fact off the file instead of stating it outright.

3. **This task touches two test files beyond the two I was asked to rewrite.** `tests/daemon/opening.rs::allowlist_hit_opens_and_forwards_localhost` asserts an exact `ssh -O forward -L …` invocation and would fail outright; `opening.rs::auto_mode_opens_everything_no_ssh_for_remote` and `custom_notifier.rs::declined_notification_does_not_forward_or_open` would keep passing but only vacuously, since nothing invokes `ssh` any more. Leaving either state would mean shipping a red suite or a test that cannot fail, so both files are in scope here.

4. **The daemon tests still depend on fixed ports being free on the test host.** They did before too, but the daemon only *recorded* those port numbers via an SSH stub; now it really binds them. I moved every newly-bound port into the 19xxx range the lifecycle tests already used and relied on `DAEMON_TEST_LOCK` for intra-suite serialization, but a host with something on 19005 or 19021 will see a failure the old suite would not have produced. Removing that dependency entirely would mean teaching `daemon_support::start` to hand the daemon a URL built from an ephemeral port, which changes the shape of the support helper for every daemon test — more churn than this task should carry, and worth its own pass if it ever bites.

5. **`is_dynamic_port` still uses only the three static tunnel ports**, per the task's instruction to keep the same list, so the laptop will happily lease its own configured `bridge_port` (12801 by default) if a URL names it. That is contained rather than fixed: the devbox bridge's `denied_port` (Task 5) refuses `cfg.bridge_port`, so such a lease relays to a bridge that closes on it immediately. Widening the laptop-side list to include `bridge_port` would be a one-line change but it is a scope decision, not a bug I was asked to fix.

6. **CI's strict clippy pass stops covering `src/` once the library exists, and only the coordinator can fix that.** `.github/workflows/ci.yml:32` runs `cargo clippy --locked --bins --all-features -- -D clippy::unwrap_used …`. Before Task 0 every source file was part of the binary, so `--bins` covered all of `src/`; afterwards most of `src/` — including `src/callback.rs` — is the library, which `--bins` builds but does not lint. Step 8 uses `--lib --bins` so this task is genuinely checked, but the workflow itself needs the same widening or the no-panic rule silently stops being enforced for the whole library. That edit belongs to Task 0 or Task 12, not here, since it is a CI change rather than a callback change.

---

### Task 8: URL channel over the tailnet

**Files:**
- Create: `src/bridge/ports.rs` (callback-port selection and arming for the devbox `open` path), `tests/daemon/peer.rs`, `tests/daemon/open_command.rs`
- Modify: `src/daemon.rs` (validate, bind `listen`, authorize peers, log both ends), `src/send.rs` (dial the peer, name the target), `src/main.rs` (`--port` on `Open`, arm before sending, degrade instead of losing the URL), `src/localhost.rs` (home `MAX_DYNAMIC_FORWARDS` next to `forward_ports`), `src/bridge.rs` (declare `mod ports`), `tests/daemon.rs` (register the two new modules)
- Test: `src/send.rs` (`mod tests`), `src/bridge/ports.rs` (`mod tests`), `tests/daemon/daemon_support.rs` (add `start_expecting_failure`), `tests/daemon/startup.rs`, `tests/daemon/peer.rs`, `tests/daemon/open_command.rs`, `tests/open.rs`, `tests/bridge/arming.rs`

**Interfaces:**

- Consumes:
  - `forward::config::Config` with `pub listen: String`, `pub peer: String`, `pub forward_ttl_secs: u64`; `Config::validate(&self) -> Result<(), ConfigError>`; `Config::listen_ip(&self) -> Result<std::net::IpAddr, ConfigError>`; `Config::peer_ip(&self) -> Result<Option<std::net::IpAddr>, ConfigError>`; `ConfigError::PeerRequired` (raised by `validate` when `listen` is not loopback and `peer` is empty); `#[doc(hidden)] pub fn Config::default_values_for_test() -> Config` (unconditional, callable from integration-test crates).
  - `forward::peer::authorized(cfg: &Config, remote: std::net::IpAddr) -> bool` — loopback is always allowed; any other address must equal `peer_ip()`.
  - `forward::bridge::arm(path: &std::path::Path, ports: &[u16], ttl_secs: u64) -> bool`; `forward::bridge::arm_socket_path() -> std::path::PathBuf`; `forward::bridge::serve_arming(armed: Armed, path: std::path::PathBuf)`; `forward::bridge::Armed::new()` and `Armed::is_armed(&self, port: u16) -> bool`.
  - `forward::callback::is_dynamic_port(port: u16) -> bool` — false for the static tunnel ports 12799, 12800, 12802.
  - `forward::localhost::forward_ports(url: &url::Url) -> Vec<u16>`.
  - `src/lib.rs` exposing `pub mod bridge; pub mod callback; pub mod config; pub mod localhost; pub mod peer; pub mod send;`, with `daemon` and its submodules binary-private.
  - `src/main.rs` with `Command::Open { target: String, config: Option<std::path::PathBuf> }` and `fn open_target(cfg: &Config, target: &str, channel_port: u16, opener_reentry: bool) -> anyhow::Result<()>`, plus whatever config-loading expression that arm already uses.
  - `CHANNEL_PORT` (12800) and `FILES_PORT` (12802), already in scope in `src/main.rs`.

- Produces:
  - `send::send_url(cfg: &Config, url: &url::Url, channel_port: u16) -> Result<(), SendError>`.
  - `SendError::Config { source: crate::config::ConfigError }`, `SendError::Unreachable { target: String, source: std::io::Error }`, `SendError::Io(std::io::Error)`. **`SendError::TunnelDown` is removed** — its message tells the user to run `devbox`, which is wrong advice once the URL channel no longer rides SSH.
  - `bridge::callback_ports(url: &url::Url) -> Vec<u16>` — dynamic devbox loopback ports for a URL, capped.
  - `bridge::arm_for_url(cfg: &Config, url: &url::Url, socket: &std::path::Path) -> usize` — arms those ports, returns how many were armed.
  - `localhost::MAX_DYNAMIC_FORWARDS: usize = 4` (`pub const`, moved out of `src/daemon.rs`; both sides of the callback path read the one constant).
  - `DaemonError::Config { source: crate::config::ConfigError }`.
  - CLI: `forward open [--port <u16>]`, defaulting to `CHANNEL_PORT`.
  - Daemon startup log line: `forward: daemon config=<path> listen=<addr>:<port> peer=<quoted> mode=<Mode> opener=<list> allow_entries=<n>`.
  - Test support: `daemon_support::start_expecting_failure(dir: &Path, config_body: &str) -> String`.

**Decisions folded in, with their reasons:**

1. **A bare filesystem path mints a preview URL; the silence is what gets fixed.** Verified on the devbox: `forward open /tmp/opencode/p2-5-probe.txt` (an existing file) exits **0** printing nothing at all, while `forward url` on the same path prints `http://localhost:12802/tmp/opencode/p2-5-probe.txt`. So `target::to_url` already mints the preview URL inside `open_target` — the URL is simply never shown to the user and never confirmed. It looks like a success because something accepts on the channel port and swallows the bytes: `127.0.0.1:12800` is currently held by `tailscaled`, not the laptop daemon, so `connect()` and `write()` both succeed and the URL is discarded. An SSH local forward behaves the same way — it accepts before the far-side connect resolves.
   **Choice: keep minting the preview URL, and make the outcome always observable.** Justification: `forward url <path>` already defines what a path means, and two sibling commands must not disagree; refusing paths in `open` would delete a feature the user was actively trying to use. Minting is not the bug — discarding the minted URL is. So on *any* send failure `open` now prints the URL on stdout, OSC 52 copies it, and exits non-zero. Nothing is silent afterwards: delivered, or printed with a reason.
   Dialling the peer directly also removes the middleman that faked success, so a dead laptop daemon now yields a real `ConnectionRefused` rather than exit 0.
2. **The degradation is honest but bounded.** Printing and copying the URL rescues the case where the laptop *daemon* is down while the tailnet is up. If the tailnet itself is down, mosh is frozen too, so the user will not see the printed line until connectivity returns — at which point the URL is still on their clipboard. It is a real improvement over losing the URL, not a fix for a partitioned network.
3. **A malformed `peer` fails loudly.** `send_url` maps a `peer_ip()` parse error to `SendError::Config` rather than falling back to loopback, which would silently send the laptop's URL to the devbox's own daemon. An *empty* `peer` still means loopback: that is the documented default and today's behaviour, not a fallback.
4. **`MAX_DYNAMIC_FORWARDS` moves to `src/localhost.rs`.** The cap is a property of the shared port derivation both machines run, and both the laptop's lease request and the devbox's arming must use the same number. Two `= 4` constants in two modules would drift. `src/localhost.rs` is the neutral home next to `forward_ports`, and it is untouched by the callback-listener work.
5. **`bridge::arm_for_url` takes the socket path as a parameter**, mirroring the channel port. `arm_socket_path()` derives from `$XDG_RUNTIME_DIR`; a parameter lets the test point at a tempdir socket without mutating process environment, which is unsound in edition 2024 and races the parallel harness.
6. **`the_daemon_refuses_a_connection_from_an_unexpected_peer` is renamed**, not kept. Its body asserts that *loopback is still served*, because an integration test cannot originate a connection from a foreign address. Refusal is covered directly by the `peer::authorized` unit tests. The renamed test still earns its place: it pins that configuring a `peer` **adds** an allowed address rather than replacing loopback, which is what keeps `forward doctor` and same-machine use working.

- [ ] **Step 1: Add the test support the new tests need**

Append to `tests/daemon/daemon_support.rs`. `start` hands back a live `Daemon` whose `Drop` kills the child and joins the stderr reader, and holds `DAEMON_TEST_LOCK` for the caller's lifetime; a startup-failure probe instead has to *wait* for the process to exit, so it is a separate helper that collects output with `Command::output()` and holds the lock only for its own duration. Bind the guard to `_lock`, not `_`, or it drops immediately and the probe races a concurrent daemon test for the port.

```rust
/// Runs the daemon expecting it to refuse to start, and returns all of its
/// stderr. Unlike `start`, this waits for the process to exit rather than
/// returning a live child, so there is no `Daemon` and no `Drop` to kill.
pub fn start_expecting_failure(dir: &Path, config_body: &str) -> String {
    let _lock = DAEMON_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let config = dir.join("config.toml");
    std::fs::write(&config, config_body).unwrap();
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let output = Command::new(env!("CARGO_BIN_EXE_forward"))
        .args([
            "daemon",
            "--port",
            &port.to_string(),
            "--config",
            config.to_str().unwrap(),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "daemon started when it should have refused"
    );
    String::from_utf8_lossy(&output.stderr).into_owned()
}
```

Register the two new test modules in `tests/daemon.rs`, keeping the file's alphabetical `#[path]` order — `open_command` between `forwarding` and `opening`, `peer` between `opening` and `reentry`:

```rust
#[path = "daemon/open_command.rs"]
mod open_command;
#[path = "daemon/peer.rs"]
mod peer;
```

- [ ] **Step 2: Write the failing tests**

`tests/daemon/peer.rs` (new). Imports `send` — the helper `daemon_support` actually exposes — and the renamed test says what it verifies:

```rust
use super::daemon_support::{send, start, stub, wait_for};

#[test]
fn a_configured_peer_does_not_displace_loopback_acceptance() {
    // Given: a daemon configured with a counterpart that is not this machine.
    let dir = tempfile::tempdir().unwrap();
    let opened = dir.path().join("opened");
    let opener = stub(
        dir.path(),
        "opener",
        &format!("echo \"$@\" > {}", opened.display()),
    );
    let (daemon, port) = start(
        dir.path(),
        &format!("opener = [\"{opener}\"]\nmode = \"auto\"\npeer = \"100.64.0.99\"\n"),
    );

    // When: a URL arrives from loopback. An integration test cannot originate a
    // connection from a foreign address, so refusal is covered by the
    // peer::authorized unit tests; what is testable here is the inverse.
    send(port, "https://example.com/from-loopback");

    // Then: configuring a peer added an allowed address rather than replacing
    // loopback, so same-machine tooling and doctor keep working.
    daemon.wait_for_log("decision=open");
    assert!(wait_for(&opened).contains("from-loopback"));
}
```

`tests/daemon/startup.rs` — update the existing assertion for the new log format (`_port` becomes `port`, and `peer` renders as a quoted empty string by default), then add the two new tests:

```rust
use super::daemon_support::{start, start_expecting_failure, stub};

#[test]
fn startup_logs_effective_config() {
    // Given: a daemon config with an explicit mode, opener, and allowlist.
    let dir = tempfile::tempdir().unwrap();
    let opener = stub(dir.path(), "opener", "true");
    let config_path = dir.path().join("config.toml");

    // When: the daemon starts from that config.
    let (daemon, port) = start(
        dir.path(),
        &format!(
            r#"
mode = "auto"
opener = ["{opener}"]
allow = ["localhost", "example.com"]
"#
        ),
    );

    // Then: the journal includes the effective config summary.
    daemon.wait_for_log(&format!(
        "daemon config={} listen=127.0.0.1:{port} peer=\"\" mode=Auto opener=[\"{opener}\"] allow_entries=2",
        config_path.display()
    ));
}

#[test]
fn startup_logs_the_bound_address_and_the_configured_peer() {
    // Given: a daemon with a tailnet counterpart configured.
    let dir = tempfile::tempdir().unwrap();
    let opener = stub(dir.path(), "opener", "true");

    // When: it starts.
    let (daemon, port) = start(
        dir.path(),
        &format!("opener = [\"{opener}\"]\npeer = \"100.64.0.2\"\n"),
    );

    // Then: the journal names both ends, so a misconfigured listen or peer is
    // visible without reading the config file.
    daemon.wait_for_log(&format!("listen=127.0.0.1:{port} peer=\"100.64.0.2\""));
}

#[test]
fn a_non_loopback_listen_without_a_peer_refuses_to_start() {
    // Given: a daemon told to listen on a routable address with no counterpart,
    // which would open the URL channel to the whole tailnet.
    let dir = tempfile::tempdir().unwrap();

    // When: it starts.
    let output = start_expecting_failure(dir.path(), "listen = \"100.64.0.1\"\n");

    // Then: it fails closed and the journal carries the reason. The exact
    // wording belongs to ConfigError::PeerRequired, so this asserts only that
    // the daemon refused and named the missing setting.
    assert!(output.contains("refusing to start"), "got {output:?}");
    assert!(output.contains("peer"), "got {output:?}");
}
```

`tests/daemon/open_command.rs` (new) — the bare path really becomes a preview URL the opener receives:

```rust
use super::daemon_support::{start, stub, wait_for};

#[test]
fn open_of_a_bare_path_delivers_the_generated_preview_url() {
    // Given: a running daemon, and a file on the devbox side.
    let dir = tempfile::tempdir().unwrap();
    let opened = dir.path().join("opened");
    let opener = stub(
        dir.path(),
        "opener",
        &format!("echo \"$@\" > {}", opened.display()),
    );
    let (_daemon, port) = start(
        dir.path(),
        &format!("mode = \"auto\"\nopener = [\"{opener}\"]\n"),
    );
    let file = dir.path().join("notes.md");
    std::fs::write(&file, "# notes\n").unwrap();
    // An explicit empty config keeps the test off the developer's real config,
    // which may name a peer. No arming socket is needed: the preview URL's only
    // loopback port is the static file-server port, which is never armed.
    // which may name a peer.
    let open_config = dir.path().join("open.toml");
    std::fs::write(&open_config, "").unwrap();

    // When: `forward open` is given the bare path rather than a URL.
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_forward"))
        .args([
            "open",
            file.to_str().unwrap(),
            "--port",
            &port.to_string(),
            "--config",
            open_config.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    // Then: it succeeds, and the opener receives the file-server URL for that
    // path. The host is deliberately not asserted — it is configuration-driven —
    // so this pins the port and path that identify the preview.
    assert!(
        output.status.success(),
        "stderr {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let recorded = wait_for(&opened);
    assert!(recorded.contains(":12802/"), "opened {recorded:?}");
    assert!(recorded.trim().ends_with("notes.md"), "opened {recorded:?}");
}
```

`tests/open.rs` — the fallback. First, in the existing `open_refuses_opener_reentry_before_connecting`, replace the line `assert!(!stderr.contains("opener tunnel down"));`, which named the removed `TunnelDown` message, with the new one — it must keep proving that the re-entry guard fires before any connection is attempted:

```rust
    assert!(!stderr.contains("cannot reach the laptop daemon"));
```

Then add the fallback test:

```rust
#[test]
fn open_of_a_bare_path_prints_the_preview_url_when_the_send_fails() {
    // Given: an existing file and no daemon. Port 9 (discard) is outside the
    // ephemeral range, so nothing binds it during tests.
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("notes.md");
    std::fs::write(&file, "# notes\n").unwrap();
    let config = dir.path().join("config.toml");
    std::fs::write(&config, "").unwrap();

    // When: the bare path is opened.
    let output = Command::new(env!("CARGO_BIN_EXE_forward"))
        .args([
            "open",
            file.to_str().unwrap(),
            "--port",
            "9",
            "--config",
            config.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Then: it fails loudly and hands the URL back on stdout, instead of
    // exiting 0 having silently dropped it.
    assert!(!output.status.success());
    assert!(stdout.contains(":12802/"), "stdout {stdout:?}");
    assert!(stdout.trim().ends_with("notes.md"), "stdout {stdout:?}");
    assert!(stderr.contains("cannot reach"), "stderr {stderr:?}");
    // The OSC 52 copy is not observable here: osc52_copy writes to /dev/tty by
    // design, not to stdout, and a piped child has no controlling terminal. The
    // escape sequence itself is covered by the osc52_sequence unit tests.
}
```

`src/send.rs` `mod tests` — replace `refused_connection_is_tunnel_down` with these two, and give `sends_newline_terminated_url` a config:

```rust
    #[test]
    fn sends_newline_terminated_url() {
        // Given: an opener-channel listener, and a config with no peer, which
        // means loopback.
        let cfg = Config::default_values_for_test();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut received = String::new();
            stream.read_to_string(&mut received).unwrap();
            received
        });

        // When: a URL is sent to the listener.
        send_url(&cfg, &url::Url::parse("https://example.com/a").unwrap(), port).unwrap();

        // Then: the listener receives one newline-terminated URL.
        assert_eq!(handle.join().unwrap(), "https://example.com/a\n");
    }

    #[test]
    fn unreachable_peer_is_reported_with_its_target() {
        // Given: a peer with nothing listening. Port 9 (discard) is outside the
        // ephemeral range, so nothing binds it in tests.
        let mut cfg = Config::default_values_for_test();
        cfg.peer = "127.0.0.1".to_owned();

        // When: a URL is sent.
        let result = send_url(&cfg, &url::Url::parse("https://example.com").unwrap(), 9);

        // Then: the error names what could not be reached, so the caller can
        // print and OSC 52 copy the URL instead of losing it.
        match result {
            Err(SendError::Unreachable { target, .. }) => assert_eq!(target, "127.0.0.1:9"),
            other => panic!("expected Unreachable, got {other:?}"),
        }
    }

    #[test]
    fn malformed_peer_is_reported_rather_than_falling_back_to_loopback() {
        // Given: a peer that is not an address, which Config::validate rejects.
        let mut cfg = Config::default_values_for_test();
        cfg.peer = "not-an-address".to_owned();

        // When: a URL is sent.
        let result = send_url(&cfg, &url::Url::parse("https://example.com").unwrap(), 9);

        // Then: it fails loudly rather than silently sending to this machine.
        assert!(matches!(result, Err(SendError::Config { .. })));
    }
```

`Config` reaches these tests through the existing `use super::*;` once Step 4 adds `use crate::config::{Config, ConfigError};` to the outer module, so `mod tests` needs no new import.

Create `src/bridge/ports.rs` holding only this `mod tests` block for now, and add a bare `mod ports;` to `src/bridge.rs` so it compiles into the crate — the implementation and the `pub use` arrive in Step 5. These cover the port selection, including the case every `forward open <path>` hits:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn u(value: &str) -> Url {
        url::Url::parse(value).unwrap()
    }

    #[test]
    fn the_file_preview_port_is_never_armed() {
        // Given: the preview URL `forward open <path>` mints, on the static
        // file-server port.
        let url = u("http://localhost:12802/tmp/notes.md");

        // When: its callback ports are computed.
        // Then: none — arming a static tunnel port would be a bridge escape.
        assert!(callback_ports(&url).is_empty());
    }

    #[test]
    fn an_oauth_callback_port_is_selected() {
        // Given: a provider URL whose redirect_uri is devbox loopback 8400.
        let url = u(
            "https://accounts.google.com/o/oauth2/auth?client_id=x&redirect_uri=http%3A%2F%2Flocalhost%3A8400%2F",
        );

        // When: its callback ports are computed.
        // Then: the callback port is armed and nothing else is.
        assert_eq!(callback_ports(&url), vec![8400]);
    }

    #[test]
    fn more_ports_than_the_cap_are_truncated() {
        // Given: a URL naming five distinct loopback ports.
        let url = u(
            "http://localhost:8400/?redirect_uri=http%3A%2F%2F127.0.0.1%3A9001%2F&redirect_uri=http%3A%2F%2F127.0.0.1%3A9002%2F&redirect_uri=http%3A%2F%2F127.0.0.1%3A9003%2F&redirect_uri=http%3A%2F%2F127.0.0.1%3A9004%2F",
        );

        // When: its callback ports are computed.
        // Then: the cap holds and first-seen order is preserved, matching the
        // laptop's own cap so both sides agree on the set.
        assert_eq!(callback_ports(&url), vec![8400, 9001, 9002, 9003]);
    }
}
```

Append to `tests/bridge/arming.rs` — arming end to end, as `forward open` does it. Paths are fully qualified so the test does not depend on that file's existing imports:

```rust
#[test]
fn open_arms_only_the_dynamic_callback_ports_of_a_url() {
    // Given: a bridge arming socket, as `forward serve` provides.
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("arm.sock");
    let armed = forward::bridge::Armed::new();
    forward::bridge::serve_arming(armed.clone(), socket.clone());
    for _ in 0..50 {
        if socket.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let cfg = forward::config::Config::default_values_for_test();

    // When: `forward open` arms the ports of a URL carrying both a callback on
    // devbox loopback 8400 and the static file-preview port.
    let url = url::Url::parse(
        "http://localhost:12802/?redirect_uri=http%3A%2F%2F127.0.0.1%3A8400%2Fcb",
    )
    .unwrap();
    let count = forward::bridge::arm_for_url(&cfg, &url, &socket);

    // Then: the callback port is reachable through the bridge and the static
    // port is not.
    assert_eq!(count, 1);
    assert!(armed.is_armed(8400));
    assert!(!armed.is_armed(12_802));
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cargo test --lib send && cargo test --lib ports && cargo test --test daemon && cargo test --test open && cargo test --test bridge arming`

Expected failures, in order:
- `cargo test --lib send`: compile error — `send_url` takes `(&Url, u16)`, called with `(&Config, &Url, u16)`; `SendError::Unreachable` and `SendError::Config` do not exist.
- `cargo test --lib ports`: compile error — `cannot find type 'Url' in this scope` and `cannot find function 'callback_ports' in this scope`, because `src/bridge/ports.rs` holds only its tests.
- `cargo test --test daemon`: compiles (Step 1 supplied `start_expecting_failure`) and fails at runtime. `startup_logs_effective_config` and `startup_logs_the_bound_address_and_the_configured_peer` panic with `no daemon stderr line containing "...listen=127.0.0.1:..."`, because the log line has no `listen=` or `peer=`. `a_non_loopback_listen_without_a_peer_refuses_to_start` fails `daemon started when it should have refused`, because the daemon ignores `listen` and always binds loopback. `open_of_a_bare_path_delivers_the_generated_preview_url` fails its `output.status.success()` assertion, with `unexpected argument '--port' found` in the captured stderr.
- `cargo test --test open`: `open_of_a_bare_path_prints_the_preview_url_when_the_send_fails` fails its `stdout.contains(":12802/")` assertion — clap rejects `--port` before `forward open` runs, so stdout is empty. `open_refuses_opener_reentry_before_connecting` still passes.
- `cargo test --test bridge arming`: compile error — `cannot find function 'arm_for_url' in module 'forward::bridge'`.

- [ ] **Step 4: Dial the peer and stop losing the URL**

In `src/send.rs`, replace the imports, the error enum, and `send_url`:

```rust
use base64::{Engine as _, engine::general_purpose::STANDARD};
use crate::config::{Config, ConfigError};
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};

#[derive(Debug, thiserror::Error)]
pub enum SendError {
    #[error("forward: invalid configuration: {source}")]
    Config {
        #[source]
        source: ConfigError,
    },
    #[error("forward: cannot reach the laptop daemon at {target}: {source}")]
    Unreachable {
        target: String,
        #[source]
        source: std::io::Error,
    },
    #[error("forward: send failed: {0}")]
    Io(#[from] std::io::Error),
}

/// Sends one newline-terminated URL to the counterpart's URL channel.
///
/// The literal `peer` address is dialled, never a name: a name would put DNS and
/// the Tailscale admin console inside the decision. An empty `peer` means
/// loopback, which is the default and reproduces today's behaviour. A `peer`
/// that will not parse is an error rather than a quiet fall back to loopback,
/// which would deliver the laptop's URL to this machine instead.
pub fn send_url(cfg: &Config, url: &url::Url, channel_port: u16) -> Result<(), SendError> {
    let ip = cfg
        .peer_ip()
        .map_err(|source| SendError::Config { source })?
        .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));
    let target = SocketAddr::new(ip, channel_port);
    let mut stream = TcpStream::connect(target).map_err(|source| SendError::Unreachable {
        target: target.to_string(),
        source,
    })?;
    writeln!(stream, "{url}")?;
    stream.flush()?;
    Ok(())
}
```

In `src/main.rs`, add the `--port` seam to `Command::Open`, mirroring `Daemon`:

```rust
    /// Open a URL or file path in the laptop browser
    Open {
        target: String,
        #[arg(long, default_value_t = CHANNEL_PORT)]
        port: u16,
        #[arg(long)]
        config: Option<std::path::PathBuf>,
    },
```

In the `Command::Open` arm, destructure `port` and pass it where `CHANNEL_PORT` is passed today. Leave the existing config-loading expression in that arm untouched.

Then `open_target` mints the URL, and on any send failure prints and copies it before returning the error — the same two lines the `Command::Url` arm uses, so the fallback is byte-identical to what `forward url` prints. Write `Config` and `bridge` with whatever path `src/main.rs` already uses for them after the library extraction (`crate::config::Config` and `crate::bridge` if those modules are still declared in the binary, `forward::config::Config` and `forward::bridge` if they come from the library); the `Serve` arm already refers to `bridge`, so match it and add no new import style:

```rust
fn open_target(
    cfg: &Config,
    target: &str,
    channel_port: u16,
    opener_reentry: bool,
) -> anyhow::Result<()> {
    if opener_reentry {
        anyhow::bail!(OPENER_REENTRY_ERROR);
    }
    let url = target::to_url(target, FILES_PORT)?;
    bridge::arm_for_url(cfg, &url, &bridge::arm_socket_path());
    if let Err(error) = send::send_url(cfg, &url, channel_port) {
        // A URL that cannot be delivered is handed back rather than dropped.
        let _ = writeln!(std::io::stdout(), "{url}");
        let _ = send::osc52_copy(url.as_str());
        return Err(error.into());
    }
    Ok(())
}
```

Update the `main.rs` `mod tests` call site, which now needs a config. Import `Config` the same way the rest of the file does:

```rust
        // When: open runs without the re-entry marker.
        let cfg = Config::default_values_for_test();
        open_target(&cfg, "https://example.com/redirect", port, false).unwrap();
```

- [ ] **Step 5: Arm the callback ports before the URL leaves**

The laptop's relay refuses any port the devbox bridge has not armed, so `forward open` must arm before it sends or every callback is dead on arrival.

In `src/localhost.rs`, add the cap next to `forward_ports`:

```rust
/// How many dynamic callback ports one URL may claim. Both machines apply the
/// same cap, so the devbox's armed set and the laptop's listeners agree.
pub const MAX_DYNAMIC_FORWARDS: usize = 4;
```

In `src/daemon.rs`, delete `const MAX_DYNAMIC_FORWARDS: usize = 4;` and take it from its new home instead:

```rust
use crate::localhost::{MAX_DYNAMIC_FORWARDS, forward_ports};
```

In `src/bridge.rs`, declare and re-export the new submodule alongside the existing declarations:

```rust
mod ports;
pub use ports::{arm_for_url, callback_ports};
```

Create `src/bridge/ports.rs`, replacing the tests-only stub from Step 2 (keep its `mod tests` block at the bottom). This is library code, so `crate::` paths are correct here:

```rust
use crate::callback::is_dynamic_port;
use crate::config::Config;
use crate::localhost::{MAX_DYNAMIC_FORWARDS, forward_ports};
use std::path::Path;
use url::Url;

/// Devbox loopback ports an OAuth callback for this URL may arrive on.
///
/// Derived from the same `forward_ports` the laptop uses, so there is no port
/// negotiation. Static tunnel ports are excluded: arming 12799 would expose the
/// PC/SC socket carrying the laptop's hardware token.
pub fn callback_ports(url: &Url) -> Vec<u16> {
    let mut ports: Vec<u16> = forward_ports(url)
        .into_iter()
        .filter(|port| is_dynamic_port(*port))
        .collect();
    if ports.len() > MAX_DYNAMIC_FORWARDS {
        eprintln!(
            "forward: dynamic forward limit reached; dropped {} port(s)",
            ports.len() - MAX_DYNAMIC_FORWARDS
        );
        ports.truncate(MAX_DYNAMIC_FORWARDS);
    }
    ports
}

/// Arms this URL's callback ports on the local `forward serve` bridge, before
/// the URL is sent, so the laptop's relay is not refused when the browser
/// follows the redirect. Returns how many ports were armed.
///
/// A failure warns and returns 0 rather than aborting: `forward serve` may not
/// be running, and losing the browser open would be worse than losing the
/// callback. This matches today's behaviour, where a failed forward still opens
/// the URL.
pub fn arm_for_url(cfg: &Config, url: &Url, socket: &Path) -> usize {
    let ports = callback_ports(url);
    if ports.is_empty() {
        return 0;
    }
    if !super::arm(socket, &ports, cfg.forward_ttl_secs) {
        eprintln!(
            "forward: could not arm callback port(s) {ports:?} on the local bridge; \
             is 'forward serve' running? sending the URL anyway"
        );
        return 0;
    }
    ports.len()
}
```

- [ ] **Step 6: Serve the URL channel on `listen`, authorized**

`src/daemon.rs` is binary-private, so its module paths depend on what the library extraction left in place: `crate::…` while a module is still declared in the binary, `forward::…` once it moved to the library. Match the `use` lines already in the file rather than the literal paths below.

In `src/daemon.rs`, add the config-failure variant to `DaemonError`:

```rust
    #[error("forward: refusing to start: {source}")]
    Config {
        #[source]
        source: crate::config::ConfigError,
    },
```

Replace the head of `run` so an unsafe configuration never reaches `bind`, and the journal names both ends:

```rust
pub fn run(cfg: Config, config_path: &Path, port: u16) -> Result<(), DaemonError> {
    cfg.validate().map_err(|source| DaemonError::Config { source })?;
    let ip = cfg
        .listen_ip()
        .map_err(|source| DaemonError::Config { source })?;
    let address = SocketAddr::new(ip, port);
    let listener =
        TcpListener::bind(address).map_err(|source| DaemonError::Bind { port, source })?;
    eprintln!(
        "forward: daemon config={} listen={address} peer={:?} mode={:?} opener={:?} allow_entries={}",
        config_path.display(),
        cfg.peer,
        cfg.mode,
        cfg.opener,
        cfg.allow.len()
    );
```

Add `SocketAddr` to the net import and bring in the peer check:

```rust
use crate::peer::authorized;
use std::net::{SocketAddr, TcpListener, TcpStream};
```

In the accept loop, gate on the peer immediately after accept, before any byte is read. This replaces the existing `peer_port` computation, which used `unwrap_or_default()` on a missing address:

```rust
            Ok(stream) => {
                let Ok(remote) = stream.peer_addr() else {
                    eprintln!("forward: dropping daemon connection with no peer address");
                    continue;
                };
                if !authorized(&cfg, remote.ip()) {
                    eprintln!("forward: refused URL channel peer {}", remote.ip());
                    continue;
                }
                let peer_port = remote.port();
```

- [ ] **Step 7: Run the tests to verify they pass**

Run: `cargo test`

Expected: PASS, no failures. Specifically `send::tests::unreachable_peer_is_reported_with_its_target`, `send::tests::malformed_peer_is_reported_rather_than_falling_back_to_loopback`, the three `bridge::ports::tests`, `daemon::startup::a_non_loopback_listen_without_a_peer_refuses_to_start`, `daemon::startup::startup_logs_the_bound_address_and_the_configured_peer`, `daemon::peer::a_configured_peer_does_not_displace_loopback_acceptance`, `daemon::open_command::open_of_a_bare_path_delivers_the_generated_preview_url`, `open::open_of_a_bare_path_prints_the_preview_url_when_the_send_fails`, and `bridge::arming::open_arms_only_the_dynamic_callback_ports_of_a_url`.

- [ ] **Step 8: Verify the constraints**

Run: `cargo clippy --all-targets --all-features -- -D warnings`
Expected: no output.

Run: `cargo clippy --all-targets --all-features -- -D warnings -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic`
Expected: no output. `unwrap` and `panic!` appear only in `mod tests` and under `tests/`, which the lints do not reach.

Run: `wc -l src/daemon.rs src/send.rs src/main.rs src/localhost.rs src/bridge.rs src/bridge/ports.rs tests/daemon.rs tests/daemon/daemon_support.rs tests/daemon/startup.rs tests/daemon/peer.rs tests/daemon/open_command.rs tests/open.rs tests/bridge/arming.rs`

Expected: every file strictly under 250. The two files with the least headroom:

- `src/daemon.rs` starts at 162. This task removes 1 line (the `MAX_DYNAMIC_FORWARDS` const) and adds 17: 5 for `DaemonError::Config`, 1 for the `peer` import, 4 for `validate` and `address`, 3 for the `listen_ip` call, 1 for the widened `eprintln!` argument list, and a net 5 for the accept-loop gate replacing the old four-line `peer_port` computation. That lands near **178**, roughly 72 lines of headroom.
- `src/send.rs` starts at 101 and gains about 41: 9 for the two new error variants net of the removed `TunnelDown`, 1 for the widened net import, 7 for the doc comment, 3 for the rewritten `send_url`, and 21 for the two new unit tests and the config added to `sends_newline_terminated_url`. That lands near **142**, roughly 108 lines of headroom.

Neither needs splitting, so nothing moves. If a later change does push `src/daemon.rs` over, the split is: move `open_permitted_url`, `forward_url` and `open_url` (the last 68 lines of the file, everything from `fn open_permitted_url` down) into `src/daemon/open.rs`, add `mod open;` and `use open::open_permitted_url;` beside the existing `mod notification;`, and make the three functions `pub(super)`. That leaves `src/daemon.rs` holding only `run` and `handle_connection`.

---

### Task 9: File preview over the tailnet — laptop only

**Files:**
- Create: `src/serve/security.rs`
- Modify: `src/serve.rs`, `src/target.rs`, `src/main.rs`
- Test: `src/serve/security.rs` (`mod tests`), `tests/serve.rs` (spawn helper takes a config), `tests/serve/host.rs` (extend)
- Must not exist: `src/tokens.rs`

**Interfaces:**
- Consumes: `Config { listen: String, peer: String, .. }`, `Config::listen_ip() -> Result<IpAddr, ConfigError>`, `Config::default_values_for_test() -> Config` (Task 1); `peer::authorized(cfg: &Config, remote: IpAddr) -> bool` (Task 2); `serve::run(cfg: &Config, port: u16) -> Result<(), ServeError>` and `--config` on `Command::Serve` (Task 0).
- Produces: `serve::run(cfg: &Config, port: u16) -> Result<(), ServeError>` binding `cfg.listen_ip()`; `ServeError::Bind { address: String, source: Box<dyn std::error::Error + Send + Sync> }`; `serve::security::peer_allowed(cfg: &Config, request: &Request) -> bool`; `serve::security::host_allowed(cfg: &Config, request: &Request) -> bool`; `target::to_url(arg: &str, host: &str, files_port: u16) -> Result<Url, TargetError>`; `target::url_host(host: &str) -> String`; `Command::Url { target, config }` gains `--config`.

**This task replaces an earlier draft that built capability tokens so a phone could open a shared preview. That feature is cut, and it must not be reinstated.** The argument, so nobody has to rediscover it:

- The tailnet ACL applied in Task 12 is **mandatory, not recommended** — this port reads any file the serving user can read, including private keys and credential caches, and `src/serve.rs` has no root directory. With that ACL in force a phone cannot reach the preview port at all, so a token in the URL changes nothing. **The ACL and phone sharing are mutually exclusive.**
- Drop the ACL and the token becomes the *sole* authorization control on that same file server. A sole authorization control must be CSPRNG-backed. The only in-tree source of randomness is time plus a counter plus a path hash, which is guessable, and a real CSPRNG means a new entry in `[dependencies]`, which the Global Constraints forbid.

Either way the feature is unbuildable here, so it is cut rather than weakened. **Deferred:** sharing a preview with a third device needs its own plan, starting with a real CSPRNG dependency and a path root, not a bolt-on to this one.

What remains is the laptop-only preview: `serve` binds `cfg.listen`, refuses any peer that is neither loopback nor the configured counterpart, keeps `Host` validation (now following the configured address), and `src/target.rs` mints preview URLs against `listen`.

- [ ] **Step 1: Confirm no token machinery exists**

```bash
rg -n 'tokens|Gate::|--share|capability token' src/ tests/
ls src/tokens.rs 2>&1
```
Expected: `rg` prints nothing and exits 1; `ls` prints `ls: cannot access 'src/tokens.rs': No such file or directory`. If either shows otherwise, a previous attempt at this task leaked in — delete `src/tokens.rs`, the `Gate` enum, the `--share` flag and every token test before continuing.

- [ ] **Step 2: Write the failing unit tests for `src/serve/security.rs`**

The peer refusal path can only be unit-tested: an integration test can connect from loopback only, and loopback is always authorized, so no subprocess test can produce a refused source address. These unit tests are therefore where the 403 is proven.

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_listening_on(listen: &str, peer: &str) -> Config {
        let mut cfg = Config::default_values_for_test();
        cfg.listen = listen.to_owned();
        cfg.peer = peer.to_owned();
        cfg
    }

    #[test]
    fn loopback_defaults_accept_every_host_value_they_did_before() {
        // Given: the default loopback configuration, which an unconfigured
        // install still gets.
        let cfg = cfg_listening_on("127.0.0.1", "");

        // When: a browser sends each Host value that worked before this change.
        // Then: all of them still work, so defaults behave exactly as today.
        assert!(host_value_allowed(&cfg, Some("localhost")));
        assert!(host_value_allowed(&cfg, Some("LocalHost:12802")));
        assert!(host_value_allowed(&cfg, Some("127.0.0.1:12802")));
        assert!(host_value_allowed(&cfg, Some("[::1]:12802")));
    }

    #[test]
    fn the_configured_listen_address_is_accepted() {
        // Given: a file server configured to listen on a tailnet address.
        let cfg = cfg_listening_on("100.64.0.1", "100.64.0.2");

        // When: the browser sends that address as its Host, with and without a
        // port.
        // Then: both are accepted, because the check follows configuration
        // instead of a hardcoded loopback list.
        assert!(host_value_allowed(&cfg, Some("100.64.0.1")));
        assert!(host_value_allowed(&cfg, Some("100.64.0.1:12802")));
    }

    #[test]
    fn a_mismatched_host_is_refused() {
        // Given: a file server configured to listen on a tailnet address.
        let cfg = cfg_listening_on("100.64.0.1", "100.64.0.2");

        // When: the Host names anything else — including the loopback names a
        // loopback-bound server still accepts, and the counterpart's address.
        // Then: every one is refused. This is the DNS-rebinding protection the
        // check exists for; only the accepted value changed.
        assert!(!host_value_allowed(&cfg, Some("evil.example")));
        assert!(!host_value_allowed(&cfg, Some("localhost:12802")));
        assert!(!host_value_allowed(&cfg, Some("100.64.0.2:12802")));
    }

    #[test]
    fn a_missing_or_unparseable_host_is_refused() {
        // Given: any configuration.
        let cfg = cfg_listening_on("127.0.0.1", "");

        // When: the Host header is absent, empty, or carries a junk port.
        // Then: each is refused rather than defaulting open. Refusing a missing
        // Host is already correct on this branch and stays.
        assert!(!host_value_allowed(&cfg, None));
        assert!(!host_value_allowed(&cfg, Some("")));
        assert!(!host_value_allowed(&cfg, Some("localhost:not-a-port")));
    }

    #[test]
    fn only_loopback_and_the_configured_peer_are_served() {
        // Given: a file server whose counterpart is one tailnet node.
        let cfg = cfg_listening_on("100.64.0.1", "100.64.0.2");
        let loopback: SocketAddr = "127.0.0.1:1024".parse().unwrap();
        let counterpart: SocketAddr = "100.64.0.2:1024".parse().unwrap();
        let stranger: SocketAddr = "100.64.0.9:1024".parse().unwrap();

        // When: connections arrive from loopback, the counterpart, and a third
        // tailnet node — a phone, say.
        // Then: only the first two are served. This port can read any file the
        // serving user can read, so a non-counterpart gets 403 and nothing else.
        assert!(peer_addr_allowed(&cfg, Some(&loopback)));
        assert!(peer_addr_allowed(&cfg, Some(&counterpart)));
        assert!(!peer_addr_allowed(&cfg, Some(&stranger)));
    }

    #[test]
    fn a_connection_with_no_source_address_is_refused() {
        // Given: any configuration.
        let cfg = cfg_listening_on("100.64.0.1", "100.64.0.2");

        // When: the server cannot report a source address, which tiny_http only
        // does for a unix-socket listener forward never builds.
        // Then: it fails closed instead of being treated as local.
        assert!(!peer_addr_allowed(&cfg, None));
    }
}
```

- [ ] **Step 3: Write the failing integration tests**

`tests/serve.rs` grows a config-aware spawn helper, and `raw_status` learns which address to dial, because a server bound to a configured address is not reachable at `127.0.0.1`. Replace `raw_status` and `spawn_serve` with:

```rust
fn raw_status(host: &str, port: u16, request: &[u8]) -> [u8; 12] {
    let mut connection = std::net::TcpStream::connect((host, port)).unwrap();
    connection.write_all(request).unwrap();
    let mut status = [0_u8; 12];
    std::io::Read::read_exact(&mut connection, &mut status).unwrap();
    status
}

fn spawn_serve(root_marker: &std::path::Path) -> (std::process::Child, u16) {
    spawn_serve_with_config(root_marker, "")
}

fn spawn_serve_with_config(
    root_marker: &std::path::Path,
    config_body: &str,
) -> (std::process::Child, u16) {
    let config = root_marker.join(".forward-config.toml");
    std::fs::write(&config, config_body).unwrap();
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_forward"))
        .args(["serve", "--port", "0", "--config"])
        .arg(&config)
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stderr = child.stderr.take().unwrap();
    let (sender, receiver) = mpsc::sync_channel(1);
    let reader = std::thread::spawn(move || {
        let mut line = String::new();
        let mut reader = std::io::BufReader::new(stderr);
        let result = reader.read_line(&mut line);
        let _ = sender.send((result, line));
        let _ = std::io::copy(&mut reader, &mut std::io::sink());
    });
    let (result, line) = match receiver.recv_timeout(Duration::from_secs(1)) {
        Ok(value) => value,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            let _ = reader.join();
            panic!("forward serve did not announce its listener: {error}");
        }
    };
    result.unwrap();
    drop(reader);
    let port = line
        .strip_prefix("forward: file server listening on ")
        .map(str::trim)
        .and_then(|value| value.rsplit_once(':'))
        .and_then(|(_, port)| port.parse().ok())
        .unwrap_or_else(|| panic!("unexpected forward serve startup message: {line:?}"));
    (child, port)
}
```

Then update the one `raw_status` call already in `tests/serve.rs` (in `serves_files_dirs_and_markdown`) to pass the address:

```rust
    assert_eq!(
        raw_status(
            "127.0.0.1",
            port,
            b"GET relative HTTP/1.1\r\nHost: localhost\r\n\r\n"
        ),
        *b"HTTP/1.1 400"
    );
```

In `tests/serve/host.rs`, widen the import and pass `"127.0.0.1"` to the three existing `raw_status` calls:

```rust
use super::{Guard, raw_status, spawn_serve, spawn_serve_with_config};
```

Then append the new test:

```rust
#[test]
fn accepts_the_configured_listen_address_and_refuses_a_mismatch() {
    // Given: a file server told to listen on a specific address rather than the
    // default, standing in for the devbox's tailnet address, with a counterpart
    // configured. 127.0.0.2 is a loopback address, so no peer is required to
    // validate and the test can genuinely bind it.
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("file.txt"), "alive").unwrap();
    let (child, port) = spawn_serve_with_config(
        dir.path(),
        "listen = \"127.0.0.2\"\npeer = \"100.64.0.2\"\n",
    );
    let _guard = Guard(child);

    // When: a request arrives from loopback naming the configured address.
    let configured = format!(
        "GET {}/file.txt HTTP/1.1\r\nHost: 127.0.0.2:{port}\r\n\r\n",
        dir.path().display()
    );

    // Then: it is served — Host validation follows the configured address, and
    // naming a counterpart does not replace loopback acceptance.
    assert_eq!(
        raw_status("127.0.0.2", port, configured.as_bytes()),
        *b"HTTP/1.1 200"
    );

    // When: a request names a different address instead.
    let mismatch = format!(
        "GET {}/file.txt HTTP/1.1\r\nHost: 127.0.0.3:{port}\r\n\r\n",
        dir.path().display()
    );

    // Then: it is refused, because 127.0.0.3 is neither the configured address
    // nor a loopback name.
    assert_eq!(
        raw_status("127.0.0.2", port, mismatch.as_bytes()),
        *b"HTTP/1.1 403"
    );
}
```

- [ ] **Step 4: Run tests to verify they fail**

Run: `cargo test --lib serve && cargo test --test serve`
Expected: FAIL — `cannot find function 'host_value_allowed'` from the unit tests, and `cannot find function 'spawn_serve_with_config'` from the integration tests.

- [ ] **Step 5: Create `src/serve/security.rs`**

This is the P2-4 pre-split. **What moves out of `src/serve.rs`:** the whole `host_is_loopback` function (its hardcoded name list becomes configuration-driven `host_value_allowed`, its header lookup becomes `host_allowed`, and its ad-hoc port-suffix prefix matching becomes `host_part`). **What lands here instead of in `serve.rs`:** the new peer gate, both halves. Nothing else moves; `Reply`, `respond`, `request_path`, `markdown_reply` and `directory_reply` stay where they are.

```rust
use crate::config::Config;
use crate::peer::authorized;
use std::net::SocketAddr;
use tiny_http::Request;

/// Whether an inbound connection's source address may be served at all.
///
/// `tiny_http` parses the request before `respond` can run any check, so a
/// refused peer still reaches the HTTP parser. That residual exposure is
/// accepted; the mandatory tailnet ACL is the control that closes it.
pub(super) fn peer_allowed(cfg: &Config, request: &Request) -> bool {
    peer_addr_allowed(cfg, request.remote_addr())
}

/// Whether the `Host` header names the address this server was configured to
/// listen on.
///
/// The check exists to stop DNS rebinding, so a missing `Host` stays refused and
/// only the accepted value changes: the configured `listen` address, plus the
/// loopback names when `listen` is itself loopback — which is the default, and
/// therefore today's behaviour exactly.
pub(super) fn host_allowed(cfg: &Config, request: &Request) -> bool {
    let header = request
        .headers()
        .iter()
        .find(|header| header.field.equiv("Host"));
    host_value_allowed(cfg, header.map(|header| header.value.as_str()))
}

fn peer_addr_allowed(cfg: &Config, remote: Option<&SocketAddr>) -> bool {
    // `None` means tiny_http could not report a source address, which only
    // happens for a unix-socket listener forward never builds. Refusing is the
    // fail-closed reading of "we do not know who this is".
    remote.is_some_and(|remote| authorized(cfg, remote.ip()))
}

fn host_value_allowed(cfg: &Config, value: Option<&str>) -> bool {
    let Some(value) = value else {
        return false;
    };
    let value = value.to_ascii_lowercase();
    let Some(host) = host_part(&value) else {
        return false;
    };
    if host == cfg.listen.to_ascii_lowercase() {
        return true;
    }
    matches!(cfg.listen_ip(), Ok(listen) if listen.is_loopback())
        && matches!(host, "localhost" | "127.0.0.1" | "::1")
}

/// The host part of a `Host` header value, with IPv6 brackets removed so it can
/// be compared against a literal `listen` address, which carries none.
///
/// Returns `None` when the value carries something that is not a port, so a
/// malformed header is refused rather than silently truncated to a host.
fn host_part(value: &str) -> Option<&str> {
    if let Some(rest) = value.strip_prefix('[') {
        let (host, tail) = rest.split_once(']')?;
        if tail.is_empty()
            || tail
                .strip_prefix(':')
                .is_some_and(|port| port.parse::<u16>().is_ok())
        {
            return Some(host);
        }
        return None;
    }
    match value.split_once(':') {
        Some((host, port)) if port.parse::<u16>().is_ok() => Some(host),
        Some(_) => None,
        None => Some(value),
    }
}
```

Append the `mod tests` block from Step 2 to this file.

- [ ] **Step 6: Rewrite the bind, the log line and the gate order in `src/serve.rs`**

Declare the new module next to the existing one and import what it produces:

```rust
mod file_handler;
mod security;

use crate::config::Config;
use crate::render::{MARKDOWN_HEAD, MARKDOWN_STYLE, MARKDOWN_TAIL, encode_path, escape_html};
use security::{host_allowed, peer_allowed};
```

The bind is no longer loopback, so the error carries the address rather than only a port:

```rust
#[derive(Debug, thiserror::Error)]
pub enum ServeError {
    #[error("forward: could not bind file server on {address}: {source}")]
    Bind {
        address: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    #[error("forward: file server listener closed")]
    ListenerClosed,
}
```

Replace `run`:

```rust
pub fn run(cfg: &Config, port: u16) -> Result<(), ServeError> {
    let ip = cfg.listen_ip().map_err(|source| ServeError::Bind {
        address: cfg.listen.clone(),
        source: Box::new(source),
    })?;
    let server = Server::http((ip, port)).map_err(|source| ServeError::Bind {
        address: format!("{ip}:{port}"),
        source,
    })?;
    eprintln!(
        "forward: file server listening on {}",
        server.server_addr()
    );
    for request in server.incoming_requests() {
        let response = respond(cfg, &request).into_response();
        if let Err(error) = request.respond(response) {
            eprintln!("forward: client disconnected before response completed: {error}");
        }
    }
    Err(ServeError::ListenerClosed)
}
```

Give `respond` the config and put the peer gate first — the design wants it as early as the library permits, and a refused peer should not even learn which methods are allowed. Delete `host_is_loopback` entirely and call `host_allowed` in its place:

```rust
fn respond(cfg: &Config, request: &Request) -> Reply {
    if !peer_allowed(cfg, request) {
        eprintln!(
            "forward: file server refused peer {:?}",
            request.remote_addr()
        );
        return Reply::new(403, TEXT_CONTENT_TYPE, "Forbidden\n");
    }

    if request.method() != &Method::Get && request.method() != &Method::Head {
        let reply = Reply::new(405, TEXT_CONTENT_TYPE, "Method Not Allowed\n");
        return match Header::from_bytes(b"Allow", b"GET, HEAD") {
            Ok(header) => reply.with_header(header),
            Err(()) => reply,
        };
    }

    if !host_allowed(cfg, request) {
        return Reply::new(403, TEXT_CONTENT_TYPE, "Forbidden\n");
    }

    let (path, raw) = match request_path(request) {
        Ok(path) => path,
        Err(()) => return Reply::new(400, TEXT_CONTENT_TYPE, "Bad Request\n"),
    };
    // ... the fs::metadata match below is unchanged.
}
```

- [ ] **Step 7: Mint preview URLs against `listen` in `src/target.rs`**

`peer_host` is the *counterpart*. On the devbox the counterpart is the laptop, so minting a preview URL against it points the browser at the machine that does not have the file. Self URLs use `listen`, always.

```rust
pub fn to_url(arg: &str, host: &str, files_port: u16) -> Result<Url, TargetError> {
    if let Ok(url) = Url::parse(arg) {
        if url.cannot_be_a_base() {
            return Err(TargetError::UnsupportedScheme(url.scheme().to_owned()));
        }
        return Ok(url);
    }
    let abs = std::fs::canonicalize(arg).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => TargetError::NotFound(arg.to_string()),
        _ => TargetError::Invalid(format!("{arg}: {e}")),
    })?;
    let encoded = encode_path(&abs);
    Url::parse(&format!("http://{}:{files_port}/{encoded}", url_host(host)))
        .map_err(|e| TargetError::Invalid(e.to_string()))
}

/// A configured `listen` address rendered as a URL authority.
///
/// `listen` holds a bare literal address, so an IPv6 one has to be bracketed
/// before a URL will parse. Anything else passes through untouched. Public
/// because `doctor` builds `Host` headers from the same addresses.
pub fn url_host(host: &str) -> String {
    if host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{host}]")
    } else {
        host.to_owned()
    }
}
```

In `src/target.rs`'s `mod tests`, insert `"127.0.0.1"` as the second argument of all eight existing `to_url(...)` calls, change `existing_file_maps_to_files_url` to assert the address rather than the old hardcoded name:

```rust
        assert_eq!(u.host_str(), Some("127.0.0.1"));
```

and add two tests:

```rust
    #[test]
    fn preview_url_names_this_machine_not_the_counterpart() {
        // Given: a devbox serving previews on its own tailnet address.
        let f = tempfile::NamedTempFile::new().unwrap();

        // When: a path is minted for the laptop to open.
        let u = to_url(f.path().to_str().unwrap(), "100.64.0.1", 12802).unwrap();

        // Then: the URL names the machine holding the file. The counterpart is
        // where the browser is, never where the file is.
        assert_eq!(u.host_str(), Some("100.64.0.1"));
        assert_eq!(u.port(), Some(12802));
    }

    #[test]
    fn an_ipv6_listen_address_is_bracketed() {
        // Given: a listen address held as a bare IPv6 literal, which is how
        // Config stores it.
        let f = tempfile::NamedTempFile::new().unwrap();

        // When: a preview URL is minted against it.
        let u = to_url(f.path().to_str().unwrap(), "::1", 12802).unwrap();

        // Then: it parses, because the authority was bracketed first.
        assert_eq!(u.host_str(), Some("[::1]"));
    }
```

- [ ] **Step 8: Give `forward url` a config in `src/main.rs`**

`forward url` mints a preview URL, so it needs `listen` just as `open` does. Add the flag:

```rust
    /// Print (and OSC 52 copy) the laptop-clickable URL for a file path
    Url {
        target: String,
        #[arg(long)]
        config: Option<std::path::PathBuf>,
    },
```

Load it the same way `Serve` and `Open` do after Task 0. If Task 0 left the loading inline in each arm, extract it once and call it from all three; if Task 0 already added an equivalent helper, call that one instead of adding a second:

```rust
fn load_config(path: Option<std::path::PathBuf>) -> anyhow::Result<config::Config> {
    let path = std::path::absolute(path.unwrap_or_else(|| {
        default_config_path().unwrap_or_else(|error| exit_with_error(error))
    }))?;
    let cfg = config::load(&path).unwrap_or_else(|error| exit_with_error(error));
    cfg.validate().unwrap_or_else(|error| exit_with_error(error));
    Ok(cfg)
}
```

Then the arm, and the `to_url` call inside `open_target`:

```rust
        Command::Url { target, config } => {
            let cfg = load_config(config)?;
            let url = target::to_url(&target, &cfg.listen, FILES_PORT)
                .unwrap_or_else(|e| exit_with_error(e));
            let _ = writeln!(std::io::stdout(), "{url}");
            let _ = send::osc52_copy(url.as_str());
            Ok(())
        }
```

```rust
    let url = target::to_url(target, &cfg.listen, FILES_PORT)?;
```

Leave the `FILES_PORT` expression exactly as earlier tasks left it — only the host argument is new. A devbox with no config file installed loads defaults, so `listen` is `127.0.0.1` and `forward url` keeps printing today's URL until Task 12 installs a real config.

- [ ] **Step 9: Run tests to verify they pass**

Run: `cargo test --lib serve && cargo test --lib target && cargo test --test serve && cargo test --test open`
Expected: PASS. `tests/serve/host.rs` runs 4 tests, `src/serve/security.rs` runs 6.

- [ ] **Step 10: Verify the gates and leave the work reviewable**

```bash
wc -l src/serve.rs src/serve/security.rs src/target.rs src/main.rs tests/serve.rs tests/serve/host.rs
bash scripts/check-source-line-limit.sh
cargo clippy --all-targets --all-features -- -D warnings
cargo clippy --all-targets --all-features -- -D warnings -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic
rg -n 'tokens|Gate::|--share' src/ tests/
jj status
```
Expected: every file under 250 lines, `check-source-line-limit.sh` silent with exit 0, both clippy passes clean, the `rg` printing nothing, and `jj status` showing only the files named in this task's **Files** block. Do not commit — this repo lands one commit per PR, and the integration commit happens after every task is accepted.

---

### Task 10: `forward doctor`

**Files:**
- Create: `src/doctor.rs`
- Modify: `src/main.rs` (add the `Doctor` subcommand), `src/lib.rs` (`pub mod doctor;`)
- Test: `src/doctor.rs` (`mod tests`), `tests/doctor.rs`

**Interfaces:**
- Consumes: `Config { listen: String, peer: String, bridge_port: u16, .. }`, `Config::default_values_for_test()` (Task 1); `bridge::denied_port(cfg: &Config, port: u16) -> bool` (Task 5); `target::url_host(host: &str) -> String` (Task 9); `CHANNEL_PORT` and `FILES_PORT` as `main.rs` already imports them.
- Produces: `doctor::run(cfg: &Config, channel_port: u16, files_port: u16) -> bool`; `Command::Doctor { config, channel_port, files_port }`.

The ports are parameters rather than `Config` fields so this task invents no configuration surface: `main.rs` passes the same constants the other subcommands default to, and `--channel-port` / `--files-port` exist for the same reason `serve --port` does — the test needs to point them somewhere dead.

**The PC/SC line is informational and must never affect the verdict.** The design only asks doctor to report the bridge socket's presence and to say plainly that end-to-end token health belongs to the secrets broker. An earlier draft probed `~/.pcscd/pcscd.comm`, a path the design does not commit to; worse, a live TCP forward with a silently dead token looks identical from here, so a pass would be misleading and a fail would be noise on the laptop, where nothing listens on 12799 at all.

- [ ] **Step 1: Write the failing tests**

```rust
// tests/doctor.rs
use std::io::{Read as _, Write as _};
use std::net::TcpListener;

/// Accepts a connection and drops it, like the URL channel receiving a
/// zero-byte liveness probe.
fn spawn_accept_and_close() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            drop(stream);
        }
    });
    port
}

/// Reads the request line and then closes, like the callback bridge refusing a
/// denylisted port. It must drain the line before closing, or the close arrives
/// as a reset and the probe cannot tell refusal from breakage.
fn spawn_read_then_close() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            let mut line = [0_u8; 64];
            let _ = stream.read(&mut line);
            drop(stream);
        }
    });
    port
}

/// Answers one request with a bare 200, like the file preview server.
fn spawn_file_preview() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            let mut request = [0_u8; 512];
            let _ = stream.read(&mut request);
            let _ = stream.write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n");
        }
    });
    port
}

#[test]
fn doctor_names_every_channel_and_exits_non_zero_when_one_is_down() {
    // Given: a config pointing every channel at a dead port. Port 9 (discard)
    // sits outside the ephemeral range and is never bound in tests, and
    // 127.0.0.2 is a second loopback address so both probe candidates are tried.
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.toml");
    std::fs::write(&config, "peer = \"127.0.0.2\"\nbridge_port = 9\n").unwrap();

    // When: doctor runs.
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_forward"))
        .args([
            "doctor",
            "--channel-port",
            "9",
            "--files-port",
            "9",
            "--config",
        ])
        .arg(&config)
        .output()
        .unwrap();

    // Then: it names each channel, marks the dead ones, keeps the PC/SC line
    // informational, and exits non-zero so a wrapper can act on it.
    let text = String::from_utf8_lossy(&output.stdout).to_string()
        + &String::from_utf8_lossy(&output.stderr);
    assert!(text.contains("url channel: FAIL"), "got {text}");
    assert!(text.contains("file preview: FAIL"), "got {text}");
    assert!(text.contains("callback bridge: FAIL"), "got {text}");
    assert!(text.contains("pcsc: info"), "got {text}");
    assert!(text.contains("belongs to the secrets broker"), "got {text}");
    assert!(!output.status.success());
}

#[test]
fn the_pcsc_line_never_decides_overall_health() {
    // Given: all three channels forward owns answering the way doctor expects,
    // and no assumption whatsoever about the PC/SC forward, which stays on SSH
    // and may or may not have a listener on this machine.
    let channel_port = spawn_accept_and_close();
    let bridge_port = spawn_read_then_close();
    let files_port = spawn_file_preview();
    let mut cfg = forward::config::Config::default_values_for_test();
    cfg.bridge_port = bridge_port;

    // When: doctor reports.
    let healthy = forward::doctor::run(&cfg, channel_port, files_port);

    // Then: the verdict is healthy. The PC/SC line is informational, so whether
    // 12799 answers here cannot change it.
    assert!(healthy);
}
```

```rust
// src/doctor.rs mod tests
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_bridge_probe_asks_for_a_permanently_denylisted_port() {
        // Given: the default configuration.
        let cfg = Config::default_values_for_test();

        // When: the port the bridge probe requests is put through the gate.
        // Then: it is denylisted, so the probe can never reach anything. If the
        // denylist ever stops covering it, this fails loudly instead of the
        // probe quietly becoming a real connection request for a hardware token.
        assert!(denied_port(&cfg, PCSC_PORT));
    }

    #[test]
    fn probe_targets_cover_both_roles_without_duplicates() {
        // Given: a devbox-shaped configuration.
        let mut cfg = Config::default_values_for_test();
        cfg.listen = "100.64.0.1".to_owned();
        cfg.peer = "100.64.0.2".to_owned();

        // When: the probe targets are computed.
        // Then: this machine's own address comes first, so the role that owns a
        // channel finds it locally, and the counterpart comes last, so the role
        // that must cross the tailnet finds it there.
        assert_eq!(
            probe_hosts(&cfg),
            vec![
                "100.64.0.1".to_owned(),
                "127.0.0.1".to_owned(),
                "100.64.0.2".to_owned(),
            ]
        );

        // And: the loopback default is not tried twice.
        let cfg = Config::default_values_for_test();
        assert_eq!(probe_hosts(&cfg), vec!["127.0.0.1".to_owned()]);
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --test doctor`
Expected: FAIL — `unrecognized subcommand 'doctor'` from the first test and `unresolved import 'forward::doctor'` from the second.

- [ ] **Step 3: Implement `src/doctor.rs`**

```rust
use crate::bridge::denied_port;
use crate::config::Config;
use crate::target::url_host;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

const PROBE_TIMEOUT: Duration = Duration::from_secs(3);
/// A path every Linux host has, so the preview probe needs no fixture.
const PREVIEW_PROBE_PATH: &str = "/etc/hostname";
/// Devbox loopback 12799 is the far end of the SSH tunnel carrying the laptop's
/// PC/SC socket. It is therefore permanently on the bridge denylist, which makes
/// it the safest thing to ask the bridge for — and it is also the address the
/// informational PC/SC line reports on.
const PCSC_PORT: u16 = 12_799;

type Probe = fn(&str, u16) -> Result<(), String>;

/// Report every channel forward owns, and return whether all of them are healthy.
///
/// Read-only throughout: nothing here arms a port, opens a URL, leases anything,
/// or writes a file.
pub fn run(cfg: &Config, channel_port: u16, files_port: u16) -> bool {
    let hosts = probe_hosts(cfg);
    let url = report("url channel", &hosts, channel_port, probe_url_channel);
    let preview = report("file preview", &hosts, files_port, probe_file_preview);
    let bridge = report("callback bridge", &hosts, cfg.bridge_port, probe_bridge);
    report_pcsc();
    url && preview && bridge
}

/// Addresses to try for each channel, in order, with duplicates removed.
///
/// Each channel is served by one role and reached across the tailnet by the
/// other, and doctor is not told which role it is running as. This machine's own
/// `listen` address first, then loopback, then the counterpart covers both roles
/// for all three channels: the devbox finds its own file preview and bridge on
/// `listen` and finds the URL channel on the peer, and the laptop finds the
/// mirror image.
fn probe_hosts(cfg: &Config) -> Vec<String> {
    let mut hosts: Vec<String> = Vec::new();
    for host in [cfg.listen.as_str(), "127.0.0.1", cfg.peer.as_str()] {
        if !host.is_empty() && !hosts.iter().any(|existing| existing == host) {
            hosts.push(host.to_owned());
        }
    }
    hosts
}

fn report(channel: &str, hosts: &[String], port: u16, probe: Probe) -> bool {
    let mut failures = Vec::new();
    for host in hosts {
        match probe(host, port) {
            Ok(()) => {
                println!("{channel}: ok at {host}:{port}");
                return true;
            }
            Err(reason) => failures.push(format!("{host}:{port} ({reason})")),
        }
    }
    println!("{channel}: FAIL — tried {}", failures.join(", "));
    false
}

fn connect(host: &str, port: u16) -> Result<TcpStream, String> {
    let address = (host, port)
        .to_socket_addrs()
        .map_err(|error| error.to_string())?
        .next()
        .ok_or_else(|| "no address".to_owned())?;
    let stream =
        TcpStream::connect_timeout(&address, PROBE_TIMEOUT).map_err(|error| error.to_string())?;
    stream
        .set_read_timeout(Some(PROBE_TIMEOUT))
        .map_err(|error| error.to_string())?;
    Ok(stream)
}

/// Connect and close, sending nothing. A zero-byte connection makes the daemon's
/// `read_url` return `None` and discard it, so this probe cannot open a browser.
fn probe_url_channel(host: &str, port: u16) -> Result<(), String> {
    connect(host, port).map(drop)
}

/// Fetch a known path and require a 200.
///
/// HTTP/1.0 with an explicit `Host`, because the file server refuses a missing
/// one — and the address dialled is exactly the address that server is
/// configured to listen on, so the header matches by construction.
fn probe_file_preview(host: &str, port: u16) -> Result<(), String> {
    let mut stream = connect(host, port)?;
    let request = format!(
        "GET {PREVIEW_PROBE_PATH} HTTP/1.0\r\nHost: {}\r\nConnection: close\r\n\r\n",
        url_host(host)
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|error| error.to_string())?;
    let mut status = [0_u8; 12];
    stream
        .read_exact(&mut status)
        .map_err(|error| error.to_string())?;
    let line = String::from_utf8_lossy(&status).into_owned();
    if line.ends_with(" 200") {
        Ok(())
    } else {
        Err(format!("{PREVIEW_PROBE_PATH} answered {line:?}"))
    }
}

/// Ask the bridge for a denylisted port and require a clean refusal: the bridge
/// closes without sending a byte. That proves the listener and the gate are both
/// alive without arming anything, which is the whole point of probing this way.
fn probe_bridge(host: &str, port: u16) -> Result<(), String> {
    let mut stream = connect(host, port)?;
    stream
        .write_all(format!("CONNECT {PCSC_PORT}\n").as_bytes())
        .map_err(|error| error.to_string())?;
    let mut body = Vec::new();
    match stream.read_to_end(&mut body) {
        Ok(0) => Ok(()),
        Ok(count) => Err(format!("sent {count} bytes instead of refusing")),
        Err(error) => Err(error.to_string()),
    }
}

/// Informational only, and deliberately excluded from the verdict.
///
/// The PC/SC forward stays on SSH and is not forward's to own. All that can be
/// said from here is whether devbox loopback 12799 has a listener at all: a live
/// forward with a silently dead token looks identical, which is exactly why this
/// line must not decide overall health.
fn report_pcsc() {
    let state = match connect("127.0.0.1", PCSC_PORT) {
        Ok(_) => "a listener answers",
        Err(_) => "no listener",
    };
    println!(
        "pcsc: info — 127.0.0.1:{PCSC_PORT} {state}; end-to-end token health belongs to the secrets broker, not forward"
    );
}
```

Append the `mod tests` block from Step 1 to this file, and add `pub mod doctor;` to `src/lib.rs`.

- [ ] **Step 4: Wire the subcommand in `src/main.rs`**

```rust
    /// Report the health of every channel forward owns
    Doctor {
        #[arg(long)]
        config: Option<std::path::PathBuf>,
        #[arg(long, default_value_t = CHANNEL_PORT)]
        channel_port: u16,
        #[arg(long, default_value_t = FILES_PORT)]
        files_port: u16,
    },
```

```rust
        Command::Doctor {
            config,
            channel_port,
            files_port,
        } => {
            let cfg = load_config(config)?;
            if doctor::run(&cfg, channel_port, files_port) {
                Ok(())
            } else {
                std::process::exit(1)
            }
        }
```

Import it alongside the other library modules `main.rs` already uses (`use forward::doctor;` or via the existing grouped import).

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test --lib doctor && cargo test --test doctor`
Expected: PASS, 2 unit tests and 2 integration tests.

- [ ] **Step 6: Verify the gates and leave the work reviewable**

```bash
wc -l src/doctor.rs src/main.rs src/lib.rs tests/doctor.rs
bash scripts/check-source-line-limit.sh
cargo clippy --all-targets --all-features -- -D warnings
cargo clippy --all-targets --all-features -- -D warnings -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic
jj status
```
Expected: every file under 250 lines, the line-limit script silent with exit 0, both clippy passes clean, and `jj status` showing only `src/doctor.rs`, `src/main.rs`, `src/lib.rs` and `tests/doctor.rs`. Do not commit.

---

### Task 11: Delete the SSH forwarding machinery

**Files:**
- Delete: `src/forwards.rs`
- Modify: `src/callback.rs` (home for the port constants), `src/config.rs` (mark `ssh` and `tunnel_host` deprecated and ignored), `src/main.rs`, `src/daemon.rs` (only if a `forwards` reference survived Task 7)
- Test: `src/config.rs` (`mod tests`), `tests/daemon/opening.rs`, `tests/daemon/custom_notifier.rs`

**Interfaces:**
- Consumes: `callback::is_dynamic_port(port: u16) -> bool` and `callback::Leases` (Task 7); `bridge::denied_port(cfg: &Config, port: u16) -> bool` (Task 5).
- Produces: `callback::PCSC_PORT: u16`, `callback::CHANNEL_PORT: u16`, `callback::FILES_PORT: u16`; `Config` retaining `ssh: Vec<String>` and `tunnel_host: String` as deprecated, ignored fields.

**Do not remove the two config fields in this task.** `Config` carries `#[serde(deny_unknown_fields)]` (`src/config.rs:4`), and the deployed laptop config names `tunnel_host` (`~/.dotfiles/forward/config.toml:21`). Removing the field here would make every deployed daemon fail at startup the moment the new binary lands, before Task 12 has touched the deployment — a self-inflicted outage in the middle of a migration whose entire purpose is to stop outages. The fields therefore survive as deprecated and ignored, and **Task 13 removes them once Task 12 has taken them out of the deployed configs.** `ssh` is kept alongside `tunnel_host` for symmetry: it costs nothing, and a machine-local override this task cannot see may still name it.

- [ ] **Step 1: Confirm the deployed config still names the field**

```bash
rg -n 'tunnel_host|^ssh' ~/.dotfiles/forward/config.toml
```
Expected: one match, `21:tunnel_host = "devbox-tunnel-ctl"`. This is read-only inspection of a separate repository — do not edit anything under `~/.dotfiles` in this task. The match is the reason for the two-step field removal.

- [ ] **Step 2: Give the port constants a home in `src/callback.rs`**

`src/forwards.rs` owns `PCSC_PORT`, `CHANNEL_PORT`, `FILES_PORT` and `STATIC_TUNNEL_PORTS`; deleting the file requires them to live somewhere first. `callback.rs` is the right home because `is_dynamic_port` is the only consumer of the static list. Add at the top of `src/callback.rs`:

```rust
/// Devbox loopback 12799 is the far end of the SSH tunnel carrying the laptop's
/// PC/SC socket. That tunnel stays on SSH and is not forward's to move; the port
/// is named here so the static-port list and `bridge::denied_port` agree on it.
pub const PCSC_PORT: u16 = 12_799;
pub const CHANNEL_PORT: u16 = 12_800;
pub const FILES_PORT: u16 = 12_802;
const STATIC_PORTS: [u16; 3] = [PCSC_PORT, CHANNEL_PORT, FILES_PORT];

/// Whether a port may be leased as a callback port at all.
///
/// forward's own three ports never can: leasing one would put a relay in front
/// of a service that is already listening there.
pub fn is_dynamic_port(port: u16) -> bool {
    !STATIC_PORTS.contains(&port)
}
```

If Task 7 already declared `is_dynamic_port` or any of these constants in `callback.rs`, keep the existing definition and add only what is missing. There must be exactly one definition of each — a duplicate is a compile error, which is the failure you want here rather than two lists drifting apart.

- [ ] **Step 3: Delete `src/forwards.rs` and every `ssh` invocation**

```bash
rm src/forwards.rs
```

In `src/main.rs`, delete `mod forwards;` and replace the two re-exports with an import from the library. `pub(crate)` is no longer needed: both constants are used only inside `main.rs`.

```rust
use forward::callback::{CHANNEL_PORT, FILES_PORT};
```

If `src/daemon.rs` still names `crate::forwards::…`, repoint it at `forward::callback::…` — `daemon` is a binary-private module while `callback` lives in the library, so `crate::callback` does not resolve from there.

- [ ] **Step 4: Mark the two config fields deprecated and ignored**

In `src/config.rs`, keep both fields and both default functions, and replace nothing but the comments:

```rust
    /// Deprecated and ignored. forward no longer invokes `ssh`: OAuth callbacks
    /// ride the tailnet bridge instead. Kept only so a deployed config that
    /// still names it keeps loading, because `Config` denies unknown fields.
    /// Task 13 removes this and `tunnel_host` once no deployment names them.
    #[serde(default = "default_ssh")]
    pub ssh: Vec<String>,
    /// Deprecated and ignored. See `ssh`.
    #[serde(default = "default_tunnel")]
    pub tunnel_host: String,
```

Do **not** add `#[deprecated]`. `Config::default_values()` constructs both fields, so the attribute would fire a `deprecated` warning at that construction site and `-D warnings` would fail the build. A doc comment is the whole mechanism, and Step 6's grep is what proves the fields are genuinely unread.

Add the compatibility test to `src/config.rs`'s `mod tests`:

```rust
    #[test]
    fn a_config_still_naming_the_ssh_fields_keeps_loading() {
        // Given: a config written before the tailnet transport, which still
        // carries the SSH forwarding fields — the state every deployed machine
        // is in the moment this binary lands.
        let f = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(
            &f,
            "ssh = [\"ssh\"]\ntunnel_host = \"devbox-tunnel-ctl\"\nmode = \"allowlist\"\n",
        )
        .unwrap();

        // When: it is loaded.
        let cfg = load(f.path()).unwrap();

        // Then: it loads. deny_unknown_fields would otherwise stop the daemon at
        // startup, so the fields are carried and ignored until Task 12 has taken
        // them out of the deployments.
        assert_eq!(cfg.mode, Mode::Allowlist);
        assert_eq!(cfg.tunnel_host, "devbox-tunnel-ctl");
    }
```

- [ ] **Step 5: Strip the last `ssh` stubs from the daemon tests**

Task 7 rewrote `tests/daemon/forwarding.rs` and `tests/daemon/forward_lifecycle.rs`. Two more files still stub `ssh`.

`tests/daemon/opening.rs`, first test — drop the `sshed` path, the `ssh` stub, the `ssh` and `tunnel_host` config lines and the invocation assertion, and assert the callback port instead. The property being tested is unchanged: an allowlist hit both opens the URL and prepares its loopback callback port.

```rust
#[test]
fn allowlist_hit_opens_and_serves_the_callback_port() {
    let dir = tempfile::tempdir().unwrap();
    let opened = dir.path().join("opened");
    let opener = stub(
        dir.path(),
        "opener",
        &format!("echo \"$@\" >> {}", opened.display()),
    );
    let (daemon, port) = start(
        dir.path(),
        &format!(
            r#"
mode = "allowlist"
opener = ["{opener}"]
allow = ["localhost", "github.com/login"]
"#
        ),
    );
    send(port, "http://localhost:8400/cb?code=abc");
    assert!(wait_for(&opened).contains("http://localhost:8400/cb?code=abc"));
    daemon.wait_for_log("callback port 8400");
}
```

`tests/daemon/opening.rs`, second test — rename it `auto_mode_opens_a_remote_url`, and delete the `sshed` path, the `ssh` stub, the `ssh` config line and the trailing `assert!(!sshed.exists())`. That assertion is now vacuous — a remote URL yields no loopback ports, so there is nothing to lease — and the global property it stood for is proved once, for the whole binary, by Step 6.

```rust
#[test]
fn auto_mode_opens_a_remote_url() {
    let dir = tempfile::tempdir().unwrap();
    let opened = dir.path().join("opened");
    let opener = stub(
        dir.path(),
        "opener",
        &format!("echo \"$@\" >> {}", opened.display()),
    );
    let (_daemon, port) = start(
        dir.path(),
        &format!(
            r#"
mode = "auto"
opener = ["{opener}"]
"#
        ),
    );
    send(port, "https://random.example/x");
    assert!(wait_for(&opened).contains("https://random.example/x"));
}
```

`tests/daemon/custom_notifier.rs`, `declined_notification_does_not_forward_or_open` — rename it `declined_notification_does_not_open`, and delete the `sshed` path, the `ssh` stub, the `ssh` config line and the `!sshed.exists()` assertion with its `"declined URLs must not create SSH forwards"` message. Keep the notifier assertions, the `wait_for_log("notification declined: …")` and `assert!(!opened.exists(), "declined URLs must not open")` exactly as they are.

- [ ] **Step 6: Prove nothing invokes ssh**

```bash
rg -n 'forwards|ForwardTracker|request_forward|tunnel_host' src/ tests/ --glob '!src/config.rs'
rg -n -- '-O forward|-O cancel' src/ tests/
rg -n 'ssh' src/ tests/ --glob '!src/config.rs'
rg -c 'Command' src/config.rs
```
Expected: all four print nothing and exit 1. The first three are the substantive proof — no SSH invocation, no forward tracker, no `-O` spec anywhere outside `src/config.rs`. The fourth is why excluding `src/config.rs` is safe: config never spawns a process, so the two fields it still carries cannot be doing anything. `rg` is case-sensitive by default, so prose comments spelling it "SSH" do not match.

- [ ] **Step 7: Verify the gates and leave the work reviewable**

```bash
cargo test
wc -l src/callback.rs src/config.rs src/daemon.rs src/main.rs
bash scripts/check-source-line-limit.sh
cargo clippy --all-targets --all-features -- -D warnings
cargo clippy --all-targets --all-features -- -D warnings -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic
jj status
```
Expected: the full suite passes, every file under 250 lines, the line-limit script silent with exit 0, both clippy passes clean, and `jj status` showing `src/forwards.rs` deleted plus the files named in this task's **Files** block and nothing else. Do not commit.

---

### Task 12: Deploy and prove it on hardware

**Files (all in `~/.dotfiles`, a separate repository — commit only these paths):**
- Modify: `forward/config.toml` (the laptop daemon config)
- Create: `forward/config-serve.toml` (the devbox serve config)
- Modify: `installers/forward.sh` (link a config for the serve role too)
- Modify: `laptop/ssh-config` (drop the two TCP forwards and the now-dead control alias)
- Modify: `forward/forward-serve.service`, `forward/forward-daemon.service` (descriptions that no longer claim loopback via the tunnel)

**Interfaces:**
- Consumes: `Config { listen, peer, bridge_port, forward_ttl_secs, .. }` (Task 1); `forward doctor` (Task 10); the deprecated-but-accepted `tunnel_host` field (Task 11).
- Produces: deployed configs naming neither `ssh` nor `tunnel_host`, which is Task 13's precondition.

Ordered so a working path exists at every step. **Do not reorder.**

**Blocking note.** Every laptop-side step needs a terminal on the laptop, and laptop access may be blocked on Tailscale SSH re-authentication. That blocks Steps 1, 3 and 4 and the laptop half of Step 2. It does **not** block the devbox half of Step 2 (writing `forward/config-serve.toml`, editing `installers/forward.sh`, installing the serve config and restarting `forward-serve`), nor Step 5's commit of the devbox-side files. Do the devbox work while waiting; do not sit on the blocked half.

- [ ] **Step 1: Capture addresses. (The mandatory tailnet ACL that used to be this step is withdrawn.)**

An earlier revision made a two-node tailnet ACL mandatory before anything binds a
routable address. That requirement is withdrawn: the peer address check in the binary
is the file-read authorization control — it refuses any non-counterpart with a 403
before path resolution, and a test locks the ordering — so a stranger on the tailnet
reads nothing with or without an ACL. An ACL restricting 12800–12802 to the two nodes
remains welcome as optional, org-owned hardening that narrows who can reach the HTTP
parser; nothing below depends on it. See the design's "Who owns each control".

Capture the two literal addresses — they become `listen` and `peer` in Step 2:

```bash
tailscale ip -4          # on each machine
```

- [ ] **Step 2: Configure both machines and verify end to end**

The devbox has no forward config installed today: `installers/forward.sh` links `forward/config.toml` only for the `daemon` role. `serve`, `url` and `open` all now need `listen` and `peer`, so the serve role needs its own config at the same well-known path. The two roles run on different machines, so both can use `~/.config/forward/config.toml` and neither wrapper nor unit `ExecStart` has to change.

Create `forward/config-serve.toml`:

```toml
# Devbox role: forward serve (file preview + callback bridge), forward url, forward open.
#
# listen is this machine's literal tailnet address, and it is what preview URLs
# are minted against — never peer, which is the laptop, where the browser is
# rather than where the file is. peer is the laptop's literal tailnet address:
# dialled for the URL channel, and compared against for every inbound
# connection. Literal addresses only; a MagicDNS name is mutable from the admin
# console and must never sit inside a security decision.
listen = "100.64.0.1"
peer = "100.64.0.2"

# The single tailnet port the laptop asks for OAuth callback hops on. Only ports
# a local `forward open` armed, from a URL that actually named them, are
# reachable through it, and only until the lease expires.
bridge_port = 12801
forward_ttl_secs = 300
```

In `forward/config.toml` (the laptop daemon), add the transport fields, **delete the `tunnel_host` line and the comment block above it** — it documents `ssh -O cancel` spec matching, machinery that no longer exists — and move the allowlist entry:

```toml
# Laptop role: forward daemon. listen is this machine's literal tailnet address,
# peer is the devbox's. Literal addresses only.
listen = "100.64.0.2"
peer = "100.64.0.1"
bridge_port = 12801
```

Replace the first entry of `allow` — `"localhost:12802"` on line 26 — and leave the other eight entries (`d-9267c4f5db.awsapps.com` through `*.anthropic.com`) untouched:

```toml
  "100.64.0.1:12802",              # Devbox file-preview server; must match the devbox's `listen`
```

**The allowlist entry has to move.** Preview URLs are now minted against the devbox's `listen`, so the old `localhost:12802` entry no longer matches anything and `forward open <path>` starts being refused by policy — it would fire a notification and a clipboard copy instead of opening. `allow_matches` compares the pattern's host and port against the URL's, so the entry must be the devbox's `listen` value verbatim, whatever it is set to.

In `installers/forward.sh`, link a config for the serve role as well:

```bash
mkdir -p "${HOME}/.config/systemd/user"
mkdir -p "${HOME}/.config/forward"
if [ "$service" = forward-daemon ]; then
    ln -sfn "${DOTFILES_DIR}/forward/config.toml" "${HOME}/.config/forward/config.toml"
else
    ln -sfn "${DOTFILES_DIR}/forward/config-serve.toml" "${HOME}/.config/forward/config.toml"
fi
```

Update both unit descriptions, which currently promise loopback over the tunnel:

```ini
Description=forward file server and callback bridge (tailnet :12802 and :12801, read-only preview)
```

```ini
Description=forward opener daemon (tailnet :12800; receives URLs from the devbox)
```

Then install and restart, devbox first:

```bash
# devbox
~/.dotfiles/installers/forward.sh serve
systemctl --user restart forward-serve
systemctl --user is-active forward-serve
journalctl --user -u forward-serve -n 20 --no-pager
```
Expected: `active`, and journal lines `forward: file server listening on 100.64.0.1:12802` and `forward: callback bridge on 100.64.0.1:12801`.

```bash
# laptop
~/.dotfiles/installers/forward.sh daemon
systemctl --user restart forward-daemon
journalctl --user -u forward-daemon -n 20 --no-pager
```
Expected: `active`, and a journal line whose `listen=100.64.0.2:12800 peer="100.64.0.1"` confirms the daemon bound the tailnet address with a counterpart configured.

Verify on both machines:

```bash
forward doctor
```
Expected on the devbox, exit 0 — doctor states evidence, not verdicts. The URL channel
is accepted at the *peer* (the laptop hosts it), and the two devbox listeners prove
themselves by correctly refusing a self-probe, whose source address is neither
loopback nor the peer:
```
url channel: accepted TCP at <laptop>:12800; delivery unverified
file preview: reachable and correctly refused self-probe at <devbox>:12802 (HTTP 403)
callback bridge: reachable and correctly refused self-probe at <devbox>:12801; active relay delivery unverified
pcsc: info — 127.0.0.1:12799 a listener answers; end-to-end token health belongs to the secrets broker, not forward
```
Expected on the laptop, exit 0: `url channel: accepted TCP at <laptop>:12800` (its own
daemon), `file preview: served probe file at <devbox>:12802` — the laptop is the peer,
so it is actually served — and `callback bridge: confirmed denied-port refusal at
<devbox>:12801`. Then prove the preview end to end from the laptop browser:

```bash
# devbox
forward url ~/.dotfiles/README.md
```
Expected: a `http://100.64.0.1:12802/...` URL. Open it on the laptop; the rendered markdown must appear. A 403 here means the `Host` check saw an address other than the devbox's `listen`.

- [ ] **Step 3: Remove the forwards from ssh_config and rebuild the tunnel from a terminal on the laptop**

In `laptop/ssh-config`, under `Host devbox-tunnel`, delete these two lines and the comment above them, keeping the PC/SC line:

```
  # forward: URL channel (devbox → laptop daemon) and file preview (laptop → devbox serve)
  RemoteForward 127.0.0.1:12800 127.0.0.1:12800
  LocalForward  127.0.0.1:12802 127.0.0.1:12802
```

Also delete the whole `Host devbox-tunnel-ctl` block and its comment. That alias existed for exactly one reason — giving forward's `-O cancel` a forward-free configuration to act against — and nothing else uses it: `laptop/devbox` checks and builds `devbox-tunnel`, not `-ctl`.

Then rebuild, **from a terminal on the laptop**:

```bash
ssh -O exit devbox-tunnel
devbox
```

**This must not be run from a non-interactive session, including an agent over SSH.** polkit's `access_pcsc` is `allow_active=yes, allow_inactive=no`, so a tunnel created outside an active logind session yields working TCP forwards and a silently dead hardware token — the failure looks like nothing at all until a decryption fails. Verify both halves separately, because the TCP half passing proves nothing about the token:

```bash
# laptop
ssh -O check devbox-tunnel
# devbox
ss -lnt 'sport = :12799'
ss -lnt 'sport = :12800'
secrets get <a human-tier key>
```
Expected: `Master running (pid NNNN)`; one `LISTEN` line for 12799; **no** listener for 12800, since the URL channel no longer arrives over SSH; and `secrets get` completing after a YubiKey touch. That last command is the only end-to-end proof the token is alive.

- [ ] **Step 4: Prove it on hardware**

Run a real SSO login start to finish, from the devbox:

```bash
aws sso login
```
Expected: the authorize URL is delivered devbox → laptop, the laptop browser opens it, and the callback completes so the CLI reports success. Capture both journals:

```bash
# devbox
journalctl --user -u forward-serve -n 50 --no-pager | rg 'armed callback port|bridge'
# laptop
journalctl --user -u forward-daemon -n 50 --no-pager | rg 'callback port'
```
Expected: on the devbox, `forward: armed callback port <N> for 300s`; on the laptop, `forward: callback port <N> served on loopback` and, later, `forward: callback port <N> released`. Record both lines.

Then confirm the property this whole change exists for:

```bash
sleep 360
# laptop
ssh -O check devbox-tunnel
# devbox
ss -lnt 'sport = :12799'
secrets get <a human-tier key>
```
Expected: still `Master running`, still one `LISTEN` line for 12799, and `secrets get` still completing. **Under the old design a callback lease expiring tore down every static forward in the tunnel's configuration, the PC/SC one included, while `ssh -O check` kept reporting healthy.** Waiting past `forward_ttl_secs` and finding the PC/SC forward alive is the acceptance test for this entire plan; the sleep must exceed `forward_ttl_secs`, which is 300.

- [ ] **Step 5: Commit the deployment, only the named paths**

`~/.dotfiles` is a separate repository and pushes directly to main.

```bash
cd ~/.dotfiles
jj status
jj commit -m "feat(forward): move the URL channel and file preview onto the tailnet" \
  forward/config.toml forward/config-serve.toml forward/forward-serve.service \
  forward/forward-daemon.service installers/forward.sh laptop/ssh-config
jj bookmark set main -r @- && jj git push --bookmark main
```
Expected: `jj status` shows the six paths above (plus any unrelated changes, which the pathspec leaves in the working copy); `jj commit` reports one new commit containing exactly those files; the push reports the bookmark moved. Verify with `jj diff --stat -r @-` that no seventh file was swept in.

- [ ] **Step 6: Confirm Task 13's precondition**

```bash
rg -n 'ssh|tunnel_host' ~/.dotfiles/forward/config.toml ~/.dotfiles/forward/config-serve.toml
```
Expected: no matches, exit 1. Task 13 removes the deprecated fields from `Config` and needs this to be true first.

---

### Task 13: Remove the deprecated config fields

**Files:**
- Modify: `src/config.rs`
- Test: `src/config.rs` (`mod tests`)

**Interfaces:**
- Consumes: `Config { ssh: Vec<String>, tunnel_host: String, .. }` as Task 11 left them, deprecated and ignored; the deployed configs Task 12 updated.
- Produces: `Config` without `ssh` or `tunnel_host`. `ConfigError` and every other field unchanged.

This closes the loop Task 11 opened. Task 11 kept the fields so a deployed config naming them would still load; Task 12 removed them from the deployments. Now they go, and a config still naming one fails loudly rather than carrying a field its author believes is doing something.

**Executed out of order, deliberately.** The fields came out of the code *before* Task
12's deployment, folded into the same PR, because with `deny_unknown_fields` the binary
and its config have to move together anyway: each machine gets the new binary, the new
config (no `ssh`, no `tunnel_host`), and a unit restart as one atomic update. The
"deployed configs first" precondition below described a staged rollout that no longer
exists; the test landed as `config_with_retired_ssh_fields_is_refused`.

- [ ] **Step 1: Prove no deployed config names either field**

```bash
rg -n 'ssh|tunnel_host' ~/.dotfiles/forward/config.toml ~/.dotfiles/forward/config-serve.toml
rg -n 'ssh|tunnel_host' src/ tests/ --glob '!src/config.rs'
```
Expected: both print nothing and exit 1. This is read-only inspection of a separate repository — do not edit anything under `~/.dotfiles`. If the first grep matches, Task 12 Step 2 is incomplete: stop and finish it, because removing the fields now would stop the deployed daemon at startup.

- [ ] **Step 2: Write the failing test**

In `src/config.rs`'s `mod tests`, replace `a_config_still_naming_the_ssh_fields_keeps_loading` (added by Task 11) with its inverse:

```rust
    #[test]
    fn the_removed_ssh_fields_are_now_refused() {
        // Given: a config still naming the SSH forwarding fields Task 11 kept
        // as deprecated. Task 12 took them out of every deployment, so a config
        // that still carries one is stale rather than in service.
        let f = tempfile::NamedTempFile::new().unwrap();

        // When: each field is loaded on its own.
        std::fs::write(&f, "tunnel_host = \"devbox-tunnel-ctl\"\n").unwrap();
        let tunnel = load(f.path());
        std::fs::write(&f, "ssh = [\"ssh\"]\n").unwrap();
        let ssh = load(f.path());

        // Then: deny_unknown_fields refuses both loudly, instead of silently
        // ignoring a field whose author still believes it does something.
        assert!(matches!(tunnel, Err(ConfigError::Parse { .. })));
        assert!(matches!(ssh, Err(ConfigError::Parse { .. })));
    }
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test --lib config`
Expected: FAIL — `assertion failed: matches!(tunnel, Err(ConfigError::Parse { .. }))`, because the fields still exist and the config still parses.

- [ ] **Step 4: Remove the fields, their defaults and their assertions**

In `src/config.rs`, delete:

- the two field declarations with their doc comments and `#[serde(default = …)]` attributes:
  ```rust
      #[serde(default = "default_ssh")]
      pub ssh: Vec<String>,
      #[serde(default = "default_tunnel")]
      pub tunnel_host: String,
  ```
- the two initialisers in `Config::default_values()`:
  ```rust
              ssh: default_ssh(),
              tunnel_host: default_tunnel(),
  ```
- both default functions, in full. They become unreachable private items, and `-D warnings` fails on dead code, so leaving them behind breaks the build:
  ```rust
  fn default_ssh() -> Vec<String> {
      vec!["ssh".to_owned()]
  }

  fn default_tunnel() -> String {
      "devbox-tunnel".to_owned()
  }
  ```
- the two assertions in `parses_full_config`:
  ```rust
          assert_eq!(cfg.ssh, vec!["ssh".to_string()]);
          assert_eq!(cfg.tunnel_host, "devbox-tunnel");
  ```

Leave `mode`, `opener`, `notifier`, `clipboard`, `forward_ttl_secs`, `allow` and every transport field Task 1 added exactly as they are.

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test --lib config && cargo test`
Expected: PASS — `the_removed_ssh_fields_are_now_refused` passes, and the whole suite stays green.

- [ ] **Step 6: Verify the gates and leave the work reviewable**

```bash
rg -n 'ssh|tunnel_host|default_ssh|default_tunnel' src/ tests/
wc -l src/config.rs
bash scripts/check-source-line-limit.sh
cargo clippy --all-targets --all-features -- -D warnings
cargo clippy --all-targets --all-features -- -D warnings -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic
jj status
```
Expected: the `rg` matches only the test that proves the fields are refused (its name and the two TOML literals it writes); `src/config.rs` under 250 lines; the line-limit script silent with exit 0; both clippy passes clean; and `jj status` showing `src/config.rs` and nothing else. Do not commit — the integration commit lands once every task is accepted.

---
