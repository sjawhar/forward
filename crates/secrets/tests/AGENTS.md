# tests

Integration tests. Unit tests live beside their module as `src/<mod>/tests.rs`.

## Wiring

There is no `tests/lib.rs`. Each root test file pulls in its helpers explicitly:

```rust
#[path = "broker/grants.rs"] mod grants;   // a module
include!("broker/support.rs");             // inlined harness
```

`#[path]` for real modules, `include!` for shared harness code that needs the
parent's imports. A new helper follows whichever the sibling files use — adding
a `mod.rs` would change how every existing file resolves.

| File | Covers |
|---|---|
| `broker.rs` | socket activation, dispatch, audit output, protocol errors |
| `broker/sources.rs` | source-root configuration, multi-source resolution, and ambiguity coverage |
| `client.rs` | CLI surface end to end against a fake broker |
| `client/broker_transport.rs` | frame-level transport, scope frames, no-`GET` guarantees |
| `client/edit.rs` | edit command flags, source selection, and local human-file paths |
| `client/edit_human.rs` | non-interactive human-secret writes from stdin, including leak, hardening, locking, and failed-encryption defenses |
| `client/multi_source.rs` | root precedence, human-key routing, and ambiguity coverage |
| `client/sources.rs` | source inspection output and malformed-file reporting |
| `hardening.rs` | `mlockall` / dumpability / `RLIMIT_CORE`, spawning the real binary |
| `e2e_client.rs` | drives `e2e-client-harness.sh` with real sops; exit 0 or 77 |
| `e2e_sysbox_peer.rs` | drives `e2e-sysbox-peer.sh`: a container peer across the uid/pid namespace boundary; exit 0 or 77 |
| `e2e_register_displacement.rs` | drives `e2e-register-displacement.sh`: an outsider claiming a live session's identifier; exit 0 or 77 |

## No real hardware

Nothing here may need a YubiKey. Point the daemon at a fixture instead:

- `SECRETSD_SOPS_BIN=tests/fixtures/fake-sops-ok` — succeeds, emits dotenv
- `…/fake-sops-fail` — non-zero, writes to stderr
- `…/fake-sops-stdin-fail` — consumes stdin, returns it on stderr, and exits non-zero to test that client errors do not disclose piped values
- `…/fake-sops-hang` — sleeps, for timeout and process-group kill

Also set `SECRETSD_CONFIG` to a scratch source-root configuration and
`SECRETSD_SOCKET` to a scratch path.
All are read from the **daemon's own** environment; a client cannot supply them.

## Known flakes

`stalled_connections_are_bounded_and_do_not_block_requests`,
`serves_lock_when_slow_connections_exceed_admission_capacity`, and
`serves_lock_when_complete_immediate_connections_flood_the_backlog` can flake
under full-suite parallel contention. Rerun the affected test; all pass in
isolation.

## Ancestry affects test shape

The daemon grants only to callers descended from the process that registered the
session, and holds `REGISTER` and `UNREGISTER` to the same rule once a live
process holds the session. A test that registers from a short-lived helper and
then requests from a sibling gets `FOREIGN_CALLER` — correctly.
`e2e-client-harness.sh` therefore `exec`s its continuation from the registering
process, mirroring how the plugin registers from the long-lived OpenCode server.

What the `REGISTER`/`UNREGISTER` rule needs is a caller that does not descend
from the registered holder, which is a direction rather than a second tree. An
in-process harness registers itself and everything it spawns is beneath it, so
a helper it starts is inside the session, not outside it. The unit tests
invert that: `src/peer.rs`'s `ChildPeer` registers a *child* as the holder and
calls from this process, which the child does not contain.
`e2e-register-displacement.sh` arranges the deployed shape instead — the
registrant and the outsider are siblings, both children of the harness.

## Miri

CI runs miri over `secret|grants|requests|proto|client|config` unit tests only. Any test
that touches a socket, `/proc`, or the filesystem must carry
`#[cfg_attr(miri, ignore)]` — miri cannot emulate `getsockopt`, and an unmarked
test breaks the miri job, not the test job.
