# Browser relay channel

Status: proposed
Date: 2026-08-21
Scope: three repositories — `forward` (transport), `sjawhar/oh-my-pi` (relay scoping and
remote-endpoint fix), `~/.dotfiles` plus `sjawhar/secretsd` (credential capture).

## What this gets you

Today an agent on the devbox gets a headless browser with no logins. Anything gated behind
a session — a vendor portal with no API, a console that only issues credentials to a
signed-in human, a flow with a device check — either cannot be automated at all or costs
you a manual copy-paste into `secrets` every time the session expires.

After this change you drag a tab into a Chrome tab group named `omp`, and agents on the
devbox can drive exactly that tab in your real browser, with your real session. Drag it out
and their access ends immediately. When a flow only needs the credential your login
produced, one command moves it into your secret store without the value ever passing
through an agent's context or your clipboard.

Two properties make this safe enough to leave running. The group is the whole access-control
list, and an agent can never pull an *existing* tab into it — only you do that. Agents do add
tabs, but only ones they create themselves, which start in the group and carry no history,
no scroll position, and no state you were relying on. So the set of your tabs that agents can
reach is exactly the set you dragged in, and it never grows on its own.

## Problem

Every piece needed for this already exists, and no two of them can reach each other.

The omp browser relay is a working CDP facade: an MV3 extension proxies `chrome.debugger`
to a local server, and the browser tool attaches to it with Puppeteer. But the extension
dials `ws://127.0.0.1:${port}/ext` with the host hardcoded (`background.js:175`; the options
page exposes only port and token), so the relay must run on the same machine as Chrome. The
relay in turn binds loopback only — `Bun.serve({ hostname: "127.0.0.1" })`
(`relay/server.ts:56`), with the comment "anything that can reach this port can drive the
user's logged-in browser". The laptop's Chrome and the devbox's agents are therefore
separated by a gap nothing in either project crosses.

Three further facts shape the design:

- **The relay's authentication is asymmetric.** `--token` gates only `/ext`
  (`relay/server.ts:74`). `/cdp` and `/json/*` have no authentication at all; `/cdp` merely
  rejects requests carrying an `Origin` header, which stops a web page but not a process.
  Exposing the relay directly on the tailnet would hand full control of logged-in tabs to
  every tailnet device, and this tailnet includes phones and two subnet routers.
- **Tab scoping is currently cosmetic.** The extension answers `chrome.tabs.query({})` and
  announces every non-internal tab. The `omp` group is visual feedback; it restricts nothing,
  and there is no per-tab consent.
- **The discovery endpoint advertises its own loopback address.** `/json/version` returns
  `webSocketDebuggerUrl: ws://127.0.0.1:${port}/cdp` (`relay/server.ts:86`), and the browser
  tool connects with `puppeteer.connect({ browserURL: cdpUrl })` (`browser/registry.ts:241`),
  which follows that URL. A remote client is therefore told to connect to its own loopback.
  Remote relay endpoints are nominally supported but cannot actually work today.

Meanwhile `forward` already owns exactly this problem shape. It runs on both machines, holds
literal tailnet addresses for each (`listen`, `peer`), authorises inbound connections
fail-closed (`src/peer.rs`), and already proxies a stream between the two for OAuth callbacks
(`src/bridge/listener.rs`, `src/pipe.rs`). The browser channel is the callback bridge with
the direction reversed and the dynamic parts removed.

## Goals

- Let a devbox agent drive tabs in the laptop's everyday Chrome, with its existing sessions.
- Make the `omp` tab group a real access-control list, enforced where it cannot be bypassed.
- Revoke access the instant a tab leaves the group.
- Move a session credential from the browser into `secrets` without its value entering an
  agent's context, a transcript, a log, or the clipboard.
- Add no new authentication secret, and no new always-open network surface.

## Non-goals

- **No URL policy on the channel.** `forward`'s `allow` list gates `forward open` into your
  everyday browsing. Agents driving a tab you handed them navigate freely; restricting
  navigation would break redirects, OAuth hops, and ordinary link-following.
- **No arming or TTL.** Group membership is the only gate. Deliberate: see Security model.
- **No expiry sidecar or staleness index.** Capture reports expiry when it runs.
- **No change to the PC/SC tunnel, policy evaluation, file preview, or URL channel.**
- **No second browser profile.** The everyday profile is the point.

## Decisions

| Decision | Choice | Consequence |
|---|---|---|
| Which browser | Everyday Chrome, scoped to the `omp` tab group | No re-login; scoping must be enforced in the fork |
| Gate | Group membership alone; always available | No timers, no arming; exposure is what you leave grouped |
| Topology | Relay on the laptop, `forward` fronts it | Browser's trusted counterparty stays local |
| Capture | Plumbed primitive; value never enters model context | Needs a script plus a non-interactive `secrets` write |
| Process layout | Folded into `forward daemon` | One unit; proxy lives in its own module |

Rejected, with reasons, so they are not re-proposed:

- **Relay binds the tailnet itself (no `forward`).** Simplest topology, but publishes an
  unauthenticated CDP surface to every tailnet device. Would require adding authentication to
  the CDP side, reimplementing the per-host check `forward` already has and deploys.
- **Relay on the devbox, laptop forwards into it.** Costs the same to build — the relay binds
  loopback wherever it runs, so either direction needs one tailnet listener and one loopback
  hop. Rejected on trust direction: the extension dials outward and obeys whatever answers,
  so this makes a port on the multi-tenant box the thing your browser trusts. A process that
  binds `9224` there before the relay does — a container, a CI job, a postinstall script —
  becomes the channel rather than merely using it. It also puts omp's auto-start and a
  managed relay in contention for one socket.
- **Idle eviction from the group.** Offered twice and declined twice. The group stays manual.

## Architecture

| Channel | Direction | Port | Status |
|---|---|---|---|
| PC/SC socket | laptop → devbox | 12799 | unchanged (SSH) |
| URL channel | devbox → laptop | 12800 | unchanged |
| Callback bridge | laptop → devbox | 12801 | unchanged |
| File preview | laptop → devbox | 12802 | unchanged |
| **Browser relay** | **devbox → laptop** | **12803** | **new** |

```
devbox agent                      laptop
  browser tool                      forward daemon
    app.relay: true                   relay listener  :12803  (tailnet, peer-checked)
    browser.relayUrl ──────────────→        │
    http://100.100.92.97:12803              ↓
                                      127.0.0.1:9224  omp browser-relay
                                            ↕ ws /ext (loopback)
                                      Chrome extension → tabs in group "omp" only
```

The relay's unauthenticated `/cdp` never leaves laptop loopback. The only way in is
`forward`'s listener, which accepts one literal peer address.

## Phase 1 — Transport (`forward`)

### New module `src/relay.rs`

The callback bridge reads a `CONNECT <port>` request line and consults the armed set because
its destination is dynamic per login. The browser channel's destination is constant, so it
drops the request line, the port policy, and the arming check, keeping the rest of
`src/bridge/listener.rs`:

1. `cfg.validate()`, resolve `cfg.listen_ip()`, bind `(ip, cfg.relay_port)`.
2. Per connection: acquire a `ConnectionLimit` permit; refuse with `REFUSED BUSY\n` when the
   limit is reached.
3. `crate::peer::authorized(&cfg, remote_ip)`; refuse with `REFUSED PEER\n` before reading a
   byte. Loopback is allowed (this is what lets `forward doctor` probe the channel); every
   other address must equal `cfg.peer_ip()` exactly.
4. `TcpStream::connect(("127.0.0.1", RELAY_TARGET_PORT))`, then
   `crate::pipe::bidirectional(inbound, upstream)`.

A byte proxy, with no HTTP parsing: the payload is an HTTP upgrade followed by a WebSocket
stream, and `forward` has no business interpreting CDP.

`RELAY_TARGET_PORT` is `9224`, the relay's default (`relay/kind.ts:18`), defined as a
constant in `src/callback.rs` beside the existing port constants.

### Idle timeout

Reuse the bridge's `PIPE_IDLE_TIMEOUT` (15 minutes) unchanged. The relay sends websocket
keepalives every 30 seconds (`WS_KEEPALIVE_MS`, `relay/server.ts:41`), so bytes cross the
proxy continuously on a healthy session and the bound never fires during legitimate use. It
functions purely as a dead-peer reaper, which is what it is for.

### Config

One new field in `src/config.rs`:

```rust
/// Port for the browser relay channel on the laptop's tailnet address.
#[serde(default = "default_relay_port")]
pub relay_port: u16,   // default 12803
```

No new address fields: `listen` and `peer` already carry the laptop and devbox addresses.
Setting `relay_port = 0` disables the channel, so machines that are not the laptop (and the
devbox's `config-serve.toml`) do not bind it.

### Wiring into `forward daemon`

`forward daemon` spawns the relay accept loop on a thread and continues serving the URL
channel. `src/daemon.rs` is 194 lines against a hard 250-line limit
(`scripts/check-source-line-limit.sh`), so the logic lives in `src/relay.rs` and the daemon
gains only the spawn.

Failure handling splits deliberately:

- **Bind failure at startup is fatal.** A daemon that silently runs without the channel is
  the silent-fallback pattern; it must die loudly with the address in the error.
- **A per-connection proxy error kills only that connection**, matching the bridge's accept
  loop. Errors are logged with the peer address.

`relay_port = 0` is not a failure; it skips the spawn and logs that the channel is disabled.

### `forward doctor`

The relay row reports differently by role, because neither machine can observe the whole
path alone. On the **devbox** it probes the channel end to end at
`http://<peer>:12803/json/version`, which is authorised because the devbox is the laptop's
configured peer. On the **laptop** it checks that the listener is bound on `listen:12803`
and probes the relay directly at `127.0.0.1:9224`, which is allowed by the loopback branch
of `peer::authorized`. A laptop cannot usefully probe its own tailnet listener: the source
address of such a connection is the tailnet address itself, not loopback, and the peer check
correctly refuses it.

| Observation | Report |
|---|---|
| listener not bound on `listen:12803` (laptop) | relay channel down — is `forward daemon` running? |
| channel refuses from the devbox | not the configured peer — check `peer` on the laptop |
| `127.0.0.1:9224` refuses | relay process down — start `omp-browser-relay` |
| `/json/version` returns 503 | relay up, extension not connected — check the badge |
| `/json/version` returns 200 | healthy, with the target count from `/json/list` |

### Laptop deployment

A new systemd user unit `omp-browser-relay.service` in `~/.dotfiles/forward/`, running
`omp browser-relay --port 9224` under `mise x "github:sjawhar/oh-my-pi"`. Not `--all-tabs`
(see Phase 2). `Restart=always`; it holds no state, and the extension reconnects on its own
with exponential backoff.

`installers/forward.sh` currently symlinks exactly one unit per role. The `daemon` role now
installs two — `forward-daemon.service` and `omp-browser-relay.service` — so the installer
takes a unit list rather than a single `unit_source`, leaving the `serve` role unchanged.

`~/.dotfiles/forward/config.toml` gains `relay_port = 12803`; `config-serve.toml` gains
`relay_port = 0`.

## Phase 2 — Group enforcement (`oh-my-pi` fork)

`oh-my-pi` is knives-managed and shared with other agents: take a branch with
`knives start <branch>` rather than editing the checkout directly.

### Remote endpoints must actually work

`relay/server.ts:86` builds the discovery response from a hardcoded loopback URL. Derive it
from the request's `Host` header instead, which is what Chrome's own CDP discovery endpoint
does, falling back to `127.0.0.1:${opts.port}` when the header is absent:

```ts
const host = req.headers.get("host") ?? `127.0.0.1:${opts.port}`;
return Response.json(bridge.versionInfo(`ws://${host}/cdp`));
```

Through `forward` the header is `100.100.92.97:12803`, so Puppeteer is told to dial back
through the channel. This is a general fix — it makes every remote relay endpoint work, not
only this one — and is upstreamable on its own.

Reflecting the header is safe here: it changes only which URL a client that already chose
that host is told to use; `/cdp` still rejects `Origin`-bearing requests, and `forward`'s
peer check stands in front.

### The group becomes the ACL

All enforcement lives in the extension. The relay must not be able to widen scope beyond what
the extension permits, so the extension is authoritative and the bridge is defence in depth.

In `background.js`:

- **Announce**: `hello` reports only tabs whose `groupId` is the `omp` group. On reconnect,
  re-derive membership rather than trusting a previously attached set.
- **Attach**: refuse any `tabId` outside the group. This is the gate; everything else is
  convenience.
- **Evict immediately**: on `tabs.onUpdated`, `tabs.onMoved`, `tabs.onRemoved` and
  `tabGroups` changes, a tab that has left the group gets a forced
  `chrome.debugger.detach` and a target-removed announcement, so dragging a tab out revokes
  access mid-session rather than at the next attach.
- **`createTab` joins the group atomically**, so an agent can open a login page for you and
  drive it. If grouping fails the tab is closed rather than left ungrouped but controllable.
- **`removeTab` and `activateTab`** apply only to group members.

**Remove the `group` RPC.** This is the change that makes the rest mean anything: an agent
that can call `group(tabId)` on an arbitrary tab adds it to the ACL and self-authorises,
collapsing the model back to "all tabs". The extension groups tabs it created itself;
agents get no way to enlarge their own scope. `ungroup` stays — releasing is always safe.

In `relay/bridge.ts`: `/json/list` and the emulated `Target` domain present only
extension-announced targets, and attach to an unknown target id is rejected.

### Flag cutover

`--no-group` becomes incoherent once the group is the ACL, so it is removed and replaced by
`--all-tabs`, which restores today's unscoped behaviour. Scoping is the default; opting out
is explicit. No deprecated alias.

### Failure message

An empty group is the most common state, and it currently surfaces as the generic
`No page targets available on the attached browser`. Relay mode gets a specific message
naming the fix: no tabs are shared — drag a tab into the `omp` tab group.

### Devbox settings

`browser.relay` stays `false`. A global default would send every headless job to the laptop
and fail whenever the group is empty. Agents opt in per call with `app.relay: true`, and the
endpoint comes from one setting:

```
browser.relayUrl = "http://100.100.92.97:12803"
```

Non-loopback, so `isLoopbackRelayUrl` (`relay/daemon.ts:39`) is false and omp's auto-start
stays off. That matters: on a loopback URL that is not currently serving, omp starts a local
relay no extension will ever reach, turning "the laptop is asleep" into a 35-second handshake
timeout and a squatted port.

This setting belongs on the devbox only. It is per-machine state in the same way
`config.toml` and `config-serve.toml` differ by role: on the laptop the same value would
point Chrome's own host at its own tailnet listener, which the peer check refuses.

## Phase 3 — Capture (`~/.dotfiles`, `sjawhar/secretsd`)

### `scripts/browser-capture`

A utility invoked by name, no extension, per the dotfiles placement map. Python with PEP 723
inline dependencies under `#!/usr/bin/env -S uv run --script`, matching `scripts/oc`;
`websockets` is the one dependency.

```
browser-capture --domain DOMAIN --cookie NAME --secret KEY [--tab SUBSTRING]
```

1. `GET {relayUrl}/json/version`; a 503 means the extension is not connected and is reported
   as such.
2. Connect `/cdp` and find a grouped target whose URL matches `DOMAIN`, narrowing with
   `--tab` when more than one does, then attach to it.
3. `Network.getCookies` for that target, selecting an exact `name` match scoped to `DOMAIN`.
   Per-tab CDP is used deliberately: the relay's browser target is emulated by the bridge,
   while per-tab commands are genuinely proxied through `chrome.debugger`.
4. Pipe the value to `secrets set-human KEY` on stdin.
5. Print one status line: `stored KEY (domain .example.com, expires 2026-09-14)`.

**The value never leaves the process.** It is not printed, not logged, not written to a temp
file, and there is no `--print` flag. If you need to see it, you have the browser.

Errors name cookie *names* only, never values, and carry distinct exit codes:

| Exit | Condition |
|---|---|
| 2 | relay unreachable, or extension not connected |
| 3 | no grouped tab matches `DOMAIN` |
| 4 | several grouped tabs match — lists their URLs; pass `--tab` |
| 5 | no cookie named `NAME` — lists the names present on that domain |
| 6 | several cookies match — lists their domains and paths |
| 7 | `secrets set-human` failed |

### `secrets set-human KEY`

New non-interactive write path in `sjawhar/secretsd`, reading the value from **stdin, never
argv** (argv is world-readable in `/proc`). It encrypts with the public age recipients from
`.sops.yaml`, so **storing requires no YubiKey touch** — which is what makes unattended
capture possible at all. It writes `.secrets/secrets.human.d/KEY.local.env`, matching the
per-key layout `DEEL_SESSION_COOKIE` and `ZIP_SESSION_COOKIE` already use, prints the changed
path, and commits nothing.

Rotation overwrites an existing key and reports it. Reading stays exactly as it is: the key
is human-tier, so first use in a session costs one YubiKey touch. Storing is unattended,
using is gated — the asymmetry is deliberate, and it follows the tier your existing session
cookies already use rather than inventing a second convention.

## Security model

State plainly what this does and does not bound, because one property is easy to assume and
false.

**Group membership scopes which tabs, not which credentials.** A grouped tab carries the
everyday profile's entire cookie jar, and navigation is unrestricted, so an agent holding one
grouped tab can navigate it anywhere you are logged in and act as you. The group is isolation
of attention, not of authority. Exposure is therefore bounded by the group being empty when
you are not using it — a habit, not a mechanism, because idle eviction was considered and
declined.

**Peer authorisation is per host, not per process.** Any process on the devbox that can dial
`100.100.92.97:12803` gets the same access an agent has. This is inherent to the feature:
agents are ordinary processes there. It is why the channel's value is bounded by the group
rather than by the network check.

| Threat | Mitigation |
|---|---|
| Another tailnet device (phone, subnet-routed host) drives the browser | `peer::authorized` accepts one literal address; everything else refused before a byte is read |
| A web page reaches the relay | `/cdp` rejects `Origin`-bearing upgrades; the laptop's own source address is not the peer, so the tailnet port refuses it too |
| A laptop process impersonates the relay to the extension | `/ext` is loopback-only; the counterparty is local by construction |
| An agent widens its scope to one of your tabs | `group` RPC removed; agents can create new tabs in the group but can never add an existing one |
| A stale grouped tab is driven later | Manual — un-group when done (accepted risk) |
| A captured value leaks into a transcript | Capture is a script that never prints values; agents have no sanctioned path that returns one |
| The value is exposed while being stored | stdin, never argv; no temp file |

Chrome's own "being debugged" infobar on each attached tab provides unfakeable visual
confirmation of what is live, which no part of this system can suppress.

## Failure modes

| Situation | Behaviour |
|---|---|
| Laptop asleep or off | Connection refused immediately; the browser tool reports an unreachable endpoint rather than waiting |
| `omp browser-relay` down | `forward`'s listener accepts, then fails to connect upstream; the connection closes and `forward doctor` names the cause |
| Extension disconnected | `/json/version` returns 503; the browser tool already waits up to 35s for the handshake, which covers a service worker reviving on its keepalive alarm |
| Group empty | Specific error naming the fix, not the generic no-targets message |
| Tab dragged out mid-run | Forced detach; the agent's next command fails against a target that no longer exists |
| `forward daemon` restarted | Live CDP sessions drop; the browser tool reopens on the next call |
| Captured credential expired | Unchanged from today — the consuming flow fails to authenticate and capture is re-run |

## Testing

Follow each repo's conventions: `forward` tests live in `tests/` mirroring
`tests/bridge.rs` and `tests/open_arming.rs`; fork tests follow the contract-level rules in
its `AGENTS.md`.

`forward`, integration tests against a bound listener via the existing `spawn_with_listener`
seam, with a stub upstream standing in for the relay:

- A connection from an unauthorised address is refused with `REFUSED PEER` before any payload
  is read.
- A connection from the configured peer is proxied bidirectionally, and a half-close in each
  direction propagates — the property `src/pipe.rs` exists to preserve.
- The upstream being absent closes the inbound connection without killing the accept loop.
- `relay_port = 0` binds nothing.
- Bind failure surfaces as a fatal daemon error naming the address.

Fork:

- `/json/version` reflects the `Host` header, and falls back to loopback when it is absent.
- An attach to a tab outside the group is refused, and one inside succeeds.
- A tab leaving the group produces a detach and a target-removed announcement.
- `createTab` yields a tab inside the group.
- `/json/list` omits ungrouped tabs.

`browser-capture` is verified end to end against a real grouped tab rather than unit-tested
against mocks: capture a cookie from a throwaway login, confirm the store now decrypts to a
value matching the browser's, and confirm nothing appeared on stdout but the status line.

## Rollout

Each phase is independently useful and independently revertable.

1. **Phase 1 + the `Host` header fix.** The channel works end to end against the stock relay
   with unscoped tabs. Verify by driving a tab from the devbox; the browser tool reports the
   laptop's Chrome. At this point every tab is reachable, so keep Chrome's shared surface
   limited until Phase 2 lands.
2. **Phase 2.** Scoping becomes real. Verify that an ungrouped tab is invisible and
   un-attachable, and that dragging a tab out mid-session revokes access.
3. **Phase 3.** Capture. Verify with one real service, end to end, including the first-use
   YubiKey touch on the stored key.
