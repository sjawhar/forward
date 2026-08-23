# Tailnet-native transport

Status: proposed (revised twice after review)
Date: 2026-07-28
Written against: the `fix/opener-reentry-loop` branch, which adds `src/forwards.rs`
and `src/ratelimit.rs`. Line references below are to that tree, not to `main`.

## What this gets you

Today the browser channel is a set of forwards inside an SSH tunnel, and a single
`ssh -O cancel` can silently remove all of them while the tunnel keeps reporting
healthy. That has taken the channel down three times in one day, and it takes the
YubiKey forward with it. You find out when a login quietly fails, or when secrets
decryption stops working, and the repair path refuses to run because the tunnel
looks fine.

After this change there are no forwards to lose. Each channel is a direct
connection over a mesh both machines are already on — the same one your terminal
and your SSH already ride. **If you can type in your terminal, opening a URL and
completing a login work**, because there is no longer a second, separately
destroyable thing between them. Nothing has to be cancelled, so nothing can be
cancelled by mistake.

One channel is excluded and stays on SSH: the tunnel carrying the laptop's hardware
token to the devbox. It keeps today's failure mode for reasons given under "What
stays on SSH", and after this change it is the only silent-death surface left.

That is the point. Everything below is how.

## Problem

Every channel `forward` uses rides one SSH master (`Host devbox-tunnel`):

| Channel | Direction | Mechanism today |
|---|---|---|
| URL channel `:12800` | devbox → laptop | `RemoteForward` |
| File preview `:12802` | laptop → devbox | `LocalForward` |
| PC/SC socket `:12799` | laptop → devbox | `RemoteForward`, for the secrets broker |
| OAuth callback `:N` | laptop → devbox | `ssh -O forward -L` per request |

The observed failure is not the tunnel dying. It is `forward` destroying it.

`ssh -O cancel` cancels the forwardings in its effective **configuration**, not
only the port named on the command line. The daemon's reaper cancelled each
expired OAuth callback forward against `devbox-tunnel`, whose block declares
`RemoteForward 12799`, `RemoteForward 12800` and `LocalForward 12802` — so every
expiry tore down all three static forwards along with the dynamic one. Each login
armed a five-minute fuse under the whole tunnel, the YubiKey channel included.

Reproduced deliberately: cancelling one dynamic forward against a `Host` that
declares two static forwards removes all three, while `ssh -O check` still reports
`Master running`. Against a forward-free alias sharing the same ControlPath, the
same cancel removes only the named port. That alias is now the immediate fix
(`tunnel_host`), and it is configuration-only.

Repair is worse than the fault. The wrapper that owns the tunnel gates on `ssh -O
check`, which reports only whether the master *process* is alive and knows nothing
about any individual forward. A master that has lost every forward looks healthy
and refuses to rebuild — three outages in one day presented as a live connection
with nothing flowing through it.

A second, milder failure mode is plausible but unverified: a laptop sleep or
network change outlasting `ServerAliveInterval 15` × `ServerAliveCountMax 3` would
kill the master while mosh, which survives exactly those events, keeps the session
alive and hides it. Every outage actually diagnosed traced to the cancel above, so
this design is not justified by the sleep story.

Meanwhile both machines are on a WireGuard mesh, and SSH and mosh already ride it.
The SSH layer is not providing reach; the reach exists underneath it. It provides
authentication and loopback confinement, and charges fragility for them.

## Goals

- Deliver URLs devbox → laptop, and reach devbox services from the laptop, without
  an SSH tunnel.
- Preserve today's behaviour exactly: a URL opens in the laptop browser, an OAuth
  callback completes, a file preview renders.
- Introduce no secret at rest.
- Expose neither the file server, the URL channel, nor the callback path beyond the
  two machines.
- Remove the daemon's dependence on the `ssh` binary.

## Non-goals

- Replacing the PC/SC tunnel. It stays on SSH and belongs to the secrets broker's
  deployment. See "What stays on SSH".
- Merging `forward` with the secrets broker. After this change they share no
  transport, which is what made them look adjacent.
- Any change to policy evaluation, allowlist matching, markdown rendering, or
  notification behaviour.
- A `forward tunnel` subcommand. This design retires the need for it.

## Architecture

| Channel | After |
|---|---|
| URL channel `:12800` | daemon listens on the laptop's tailnet address; `forward open` connects to it directly |
| File preview `:12802` | `forward serve` listens on the devbox's tailnet address; the laptop's browser fetches it directly |
| OAuth callback `:N` | laptop-side listener plus a devbox-side hop, both in-process — see below |
| PC/SC socket `:12799` | unchanged |

### URL channel

`src/daemon.rs:30` hardcodes `TcpListener::bind(("127.0.0.1", port))` and
`src/send.rs:14` hardcodes `TcpStream::connect(("127.0.0.1", channel_port))`. Both
become configurable: the daemon listens on `listen`, `forward open` connects to
`peer`. Defaults stay loopback, so an unconfigured install behaves exactly as
today. Nothing else in the path changes — `read_url`, `decide`, the rate limiter,
and the opener are untouched.

`SendError::TunnelDown` says "run 'devbox' on your laptop", which stops being
true. On a failed connection `forward open` degrades to what `forward url` already
does: print the URL and copy it with OSC 52. Today a failed send loses the URL
entirely (`src/send.rs:7`, and `main.rs` prints the error without the URL), so this
is a real improvement — but see Failure modes for an honest account of when it
actually helps.

### File preview

`src/serve.rs:95` hardcodes the loopback bind, and `is_loopback_host` at
`src/serve.rs:150` accepts only `127.0.0.1`, `localhost`, and `[::1]` in the `Host`
header. Both follow the configured address: serve listens on `listen`, and the
`Host` check accepts exactly the configured host name and address. Keeping the
check preserves the DNS-rebinding protection it exists for; only the accepted
value changes. Rejection of a missing `Host` is already correct on this branch and
stays.

`forward url <path>` and `src/target.rs` mint `http://localhost:12802/<path>`,
which resolves only on the laptop and only because of the `LocalForward`. Both move
to the devbox host. **The laptop's allowlist entry `localhost:12802` must move with
them**, or `forward open <path>` starts being refused by policy.

The port has no root: the server resolves any absolute path, so reaching it
means authority over every file the serving user can read. What bounds that
authority is the **peer address check** — the same user-owned control the URL
channel and the bridge use. `forward serve` refuses any source that is neither
loopback nor the configured `peer` with a 403 *before* it resolves a path, so a
stranger on the tailnet — a phone, a tagged service node — reads nothing,
whether or not any ACL exists. The check is the first thing `respond()` does,
and a test locks the ordering: a non-counterpart presenting a valid `Host`
header is refused before method, `Host`, or path handling runs.

A consequence stated plainly: a preview URL does **not** open on a phone. The
preview is laptop-only, and that is a trade made knowingly — see "Capability
URLs: considered twice, not built" for the design that would have allowed
sharing and why it lost.

### Capability URLs: considered twice, not built

Two revisions of this document disagreed about per-invocation capability tokens
(`http://<devbox>:12802/t/<token>/<path>`), and both arguments failed on their
premises, which is worth recording so the question is not re-litigated from
scratch.

The first revision cut tokens because the tailnet ACL was mandatory — with it,
a token authorizes nothing the network has not already authorized — and because
a CSPRNG seemed to need a new dependency (false: `/dev/urandom` is a CSPRNG and
needs only `std::fs::File`). The second revision reinstated them because the
file server supposedly had ambient authority any tailnet device could reach —
also false against the code as built: the peer check already refuses every
non-counterpart before path resolution, so the user-owned control that "Who
owns each control" demands already exists and already is the file-read
authorization.

What tokens would buy over that check: opening a deliberately shared link on a
phone (raised once, as a shrug), and hardening against other local users on a
multi-user devbox. What they cost: every preview URL grows by roughly 67
characters — guaranteeing the tmux line-wrap this tool exists to remove — every
link dies at TTL expiry and on `forward serve` restart, and `forward url` gains
a mint-time failure mode where today it cannot fail. And they do not close the
one residual the ACL covered: a tokenless request still reaches the HTTP parser
before its refusal. Not proportionate; not built. If sharing ever becomes a
want rather than a shrug, the additive path is `forward url --share` minting a
capability for one path, while bare `forward url` stays exactly as today.

### OAuth callback

This replaces `src/forwards.rs`, and it is the part the first draft of this design
got wrong. The correction is the substance of this revision.

**Why a laptop-side listener is unavoidable.** The provider dictates the callback
address. It redirects the browser to `http://localhost:N/...` built from a
pre-registered `redirect_uri`, and the browser resolves `localhost` on the laptop.
So something must listen on the laptop's own loopback `:N`. That is true in every
design, including today's.

**Why a devbox-side hop is also unavoidable.** The tool waiting for that callback
binds `127.0.0.1:N` on the devbox — loopback only, which is what RFC 8252 tells
these tools to do and what the AWS, GitHub, and Google CLIs all actually do. A
socket bound to loopback cannot be reached at the machine's tailnet address. The
first draft had the laptop connect straight to `<devbox>:N` and would have been
refused every time.

Today's `ssh -L N:127.0.0.1:N` works because sshd is an agent *on the devbox* that
makes the final loopback connection. Removing SSH means `forward` must supply that
agent itself.

**The design.** A single callback port on the devbox — `12801` by default, the one
gap in the existing scheme, and configurable — served by the already-running
`forward serve` process, rather than one tailnet port per callback:

1. `forward open` on the devbox computes `forward_ports(url)` — the same function
   the daemon uses, `src/localhost.rs:14` — and, over a unix socket in
   `$XDG_RUNTIME_DIR`, asks the local `forward serve` process to **arm** those
   ports for `forward_ttl_secs`. Then it sends the URL to the laptop as usual.
2. The laptop daemon computes the same port list from the same URL and listens on
   `127.0.0.1:N` **and `[::1]:N`** — both, because `forward_ports` deliberately
   recognises `[::1]` and browsers may resolve `localhost` to either.
3. For each connection it accepts, the daemon connects to the devbox's callback
   port, sends a single line naming the port it wants, and then pipes bytes.
4. `forward serve` checks the requested port against the armed set and the
   denylist, connects to `127.0.0.1:N` on the devbox, and pipes bytes.
5. Lease semantics are unchanged from `ForwardTracker`: same `forward_ttl_secs`,
   same refresh-on-reuse, same `MAX_DYNAMIC_FORWARDS` cap of 4 (`src/daemon.rs:18`).
   On expiry each side drops its listener and its armed entry. Connections already
   in flight run to completion.

Both sides derive the port from the same URL through the same function, so there is
no port-negotiation protocol beyond that one line, and no state to reconcile.

**Only one devbox port is ever exposed**, which is why this shape beats a
tailnet-listening socket per callback: nothing is dynamically bound on the devbox,
so there is no per-port lifecycle to get wrong, and one listener to reason about
instead of a changing set.

**Byte piping must propagate half-close.** A naive two-way copy hangs: an HTTP
callback client finishes its request and waits, and if EOF in one direction is not
turned into `shutdown(Write)` on the other socket, the peer waits forever. Each
direction copies to EOF and then shuts down the write half of its destination,
while the opposite direction keeps draining.

**What this actually removes and adds.** It removes SSH subprocess management, the
`-O cancel` spec matching and the class of bug that wiped the forward table, and
the `ssh`/`tunnel_host` config. It adds two in-process proxies and an arming
control socket. This is not a pure deletion, and the earlier draft's claim that it
was is retracted. What it buys is that release is "close a socket" — a failure mode
that cannot take down unrelated channels.

### What stays on SSH

`RemoteForward 127.0.0.1:12799 /run/pcscd/pcscd.comm` remains, and the `12800` and
`12802` lines come out of `Host devbox-tunnel`. It stays for two reasons:

1. It forwards a **unix socket**, not a TCP port. There is nothing on the tailnet
   to connect to.
2. Loopback-over-SSH is doing real security work. Exposing a PC/SC socket — the
   interface to a plugged-in hardware token — to a routed overlay is a materially
   worse trade than exposing a file server, and not one this change needs to make.

The laptop wrapper that ensures the tunnel keeps its active-seat requirement:
polkit's `access_pcsc` is `allow_active=yes, allow_inactive=no`, so a tunnel created
from a non-interactive SSH session yields working TCP forwards and a silently dead
token.

**Stated plainly, because it is the residual cost of this design:** after this
change the PC/SC tunnel is the *only* remaining silent-death surface. It will still
die on sleep and still need a manual re-run, and no supervisor can fix that,
because a systemd user unit is not an active logind session and polkit will refuse
it. Its health check belongs to the secrets broker's wrapper, which should probe the
forward end-to-end rather than calling `ssh -O check` — the flaw described in the
Problem section applies to it just as much, and narrowing SSH to one forward does
not repair it.

## Security

Today, loopback binding plus SSH authentication means only the two machines can
reach these ports, and `forward` performs no authentication of its own. Listening
on a tailnet address gives that up. Three exposures:

- **File preview.** `src/serve.rs:164` checks only `path.is_absolute()`; there is no
  root directory. Any reachable peer can read any file the serving user can read,
  including private keys and credential caches.
- **URL channel.** Any reachable peer can cause a browser to open on the laptop —
  in `auto` mode, on any URL (`src/policy.rs`).
- **Callback port.** Any reachable peer can ask the devbox to connect to a devbox
  loopback port. This component did not exist in the first draft and is the most
  sensitive of the three.

None is acceptable at tailnet-wide scope; a personal tailnet routinely holds phones,
tagged service nodes, and subnet routers.

### Who owns each control

An earlier revision closed the file-preview exposure with a **mandatory** tailnet
ACL. Requiring it was a design error, not a deployment inconvenience, and the
distinction matters enough to state plainly.

A Tailscale ACL is org-controlled. The author of this tool happens to administer the
org he runs it on, which is exactly what made the mistake easy to miss: a
user-installed tool was made to depend on an org-level control it cannot read,
cannot test, and does not own. Sorting the controls by owner shows what that buys:

| Control | Owned by | Failure mode when it is wrong |
|---|---|---|
| Peer address check | the user, in `Config` | a channel refuses its counterpart; loudly broken |
| Listen address | the user, in `Config` | startup fails with the address in the message |
| Tailnet ACL | the org's admin console | strangers reach the HTTP parser; file reads stay refused by the peer check |

Every user-owned control fails closed and fails visibly. The org-owned one fails
open and silently, and the tool cannot detect that it has. Depending on it inverts
the dependency: a personal tool's security posture must not be delegated upward to a
control whose state it cannot observe.

So no org-owned control may be load-bearing — and none is. The peer address
check is user-owned and is the authorization control on every channel, the file
server included. What an ACL adds on top is narrowing who can reach the HTTP
parser at all: welcome where the org permits it, and what it should have been
all along — optional hardening.

### Identity

Peer identity is a **literal tailnet address**, never a MagicDNS name. Machine names
are mutable from the admin console and derived from hostnames, so using one for an
equality check puts DNS and console state inside the security decision. There is
**no hostname field of any kind**: every outbound connection dials the literal
`peer`, and a URL naming this machine is built from `listen`, so no name is ever
resolved and no resolver sits in any dial path. An earlier draft allowed a
display name that had to resolve back to `peer`; always dialling the literal is
simpler and exactly as secure, with no failure mode when DNS is slow, split, or
stale.

**Verified assumption:** the address check is meaningful because WireGuard decrypts
and authenticates each inbound packet to a peer and then drops it unless the
plaintext source address is within that peer's `AllowedIPs`, and Tailscale assigns
each device a unique address. A peer therefore cannot present another node's
address. This was checked against Tailscale and WireGuard documentation during
review. It does **not** authenticate anything that reaches the socket by some path
other than the tailnet interface, which is why the checks below are not optional.

### Controls

1. **Peer address check, applied as early as the library permits.** The whole
   authorization decision on all three channels. For the URL channel and the
   callback port it runs immediately after accept, before any byte is parsed.
   For the file server it is the first check in `respond()` — before method,
   `Host`, and path resolution, an ordering a test locks in place. `tiny_http`
   parses the request before `respond()` can run any check (`src/serve.rs`), so
   a refused peer still reaches the HTTP parser; that residual exposure is
   accepted, and it is parser exposure, not file-read exposure.
2. **Listen on the specific tailnet address, not `0.0.0.0`.** Exposure reduction,
   *not* authentication — a local process or an unusual route can still reach a socket
   bound to a local address. Cheap, and easily forgotten.
3. **Tailnet ACL restricting these ports to the two nodes — optional hardening.**
   Worth applying where the org permits it, and worth policy tests if so. Nothing in
   this design depends on it, no default is unsafe without it, and `forward` must
   never require it.

Controls 1–2 are entirely user-owned. Control 3 is not, which is why it is last
and optional instead of first and mandatory.

**`auto` mode requires enforcement.** The daemon refuses to start when `listen` is
non-loopback, `mode = "auto"`, and no literal `peer` is configured. Loopback
confinement is what made unattended `auto` defensible; without it the mode must
fail closed rather than silently accept.

### What passing the peer check grants, and the residuals

The file server resolves any absolute path and applies no root, so an allowed
peer reads every file the serving user can — private keys and credential caches
included. For the counterpart that is deliberate: `forward url` exists to
preview arbitrary paths, and the laptop already holds SSH to the devbox, so the
channel grants it nothing new.

Two residuals, stated rather than discovered later. First, the parser residual
above: a refused peer still exercises `tiny_http`'s request parsing. The
optional ACL narrows that; a capability token would not, since a tokenless
request is parsed too. Second, a local one: `peer::authorized` always allows
loopback, and a local process can forge any `Host` header over raw TCP, so on a
multi-user devbox **any** local user can read the serving user's files through
this port, mode 0600 included. The loopback-only bind of the SSH era had the
same property; this machine is single-user, and its agents run as that same
user. If that ever changes, the honest fix is an additive capability
(`forward url --share`), not a quiet narrowing of loopback — dropping the
unconditional loopback allowance would break `forward doctor` and the bridge's
own final hop.

Adding a shared secret to any channel would put a credential at rest — the
property the goals exclude, and the one the machine's secrets broker exists to
avoid — to solve smaller problems than that cost.

### The callback port specifically

The callback hop is a service that connects to loopback ports on request, which is
the shape of a confinement bypass. Four constraints, all required:

- **Peer check** immediately after accept, before the request line is read.
- **Armed-set gate.** Only ports armed by a local `forward open` invocation, from a
  URL that actually named them, and only until the lease expires. A reachable peer
  cannot pick a port; it can only use one a login flow legitimately requested.
- **Denylist, enforced independently of the armed set:** `12799` above all, because
  devbox loopback `12799` is the far end of the tunnel to the laptop's hardware
  token; plus `12800`, `12802`, and the callback port itself, to prevent loops and
  confused-deputy chains through `forward`'s own services.
- **Local-only arming.** The arming socket is a unix socket in `$XDG_RUNTIME_DIR`,
  reachable only by local processes and scoped by filesystem permissions. It is
  never exposed on the tailnet. Note that a local devbox process could already
  connect to devbox loopback ports directly, so arming grants it nothing new; the
  gate exists to constrain the *remote* peer.

### Rejected

- **Shared token at rest.** A long-lived secret held on disk by both machines,
  precisely the property the machine's secrets broker exists to avoid.
- **Per-invocation capability URLs.** See "Capability URLs: considered twice,
  not built".
- **Per-connection identity lookup via the tailscale CLI.** A subprocess and its
  latency on every connection, to learn what the source address already tells us.

Residual risk, unchanged from today: authentication is per-node, not per-process, so
any process on the peer machine can use these channels. The SSH tunnel had the same
property.

## Configuration

Added to `Config`, which uses `deny_unknown_fields`, so both machines must be
updated together — the migration order below accounts for that:

- `listen` — address this role listens on. Default loopback.
- `peer` — the counterpart's literal tailnet address: connected to for outbound,
  compared for inbound. Default empty, meaning loopback only. There is no
  `peer_host` or any other hostname field — see Identity.

Removed after migration: `ssh`, `tunnel_host`. Retained: `forward_ttl_secs`, and all
policy, opener, notifier, and clipboard fields.

Defaults must reproduce today's behaviour exactly, so a partially configured install
fails closed to loopback rather than opening a tailnet port.

## Failure modes

| Condition | Behaviour |
|---|---|
| Laptop daemon down, tailnet up | `forward open` prints and OSC-52 copies the URL, exits non-zero. **This is the case the fallback actually helps.** |
| Tailnet down | `forward open` prints and copies, but mosh is frozen too, so nothing reaches the laptop until the tailnet returns — at which point a retry would have worked. Better than today, which loses the URL, but it is not a working path. |
| Connection from an unexpected peer | closed, peer address logged |
| Callback port already in use on the laptop | logged; the browser still opens; that login fails, as today |
| Requested callback port not armed, or on the denylist | refused, logged with the port |
| `listen` names an address the host does not hold | startup fails with the address in the message |
| `auto` mode with non-loopback `listen` and no `peer` | startup refused |

## Observability

`forward doctor` — read-only, exits non-zero if any channel is unhealthy, and names
what it could not check rather than passing silently:

- URL channel: connect and close. A zero-byte connection makes `read_url` return
  `None` and the daemon discards it, so this is a safe liveness probe.
- File preview: fetch a known path over HTTP and classify the evidence rather
  than convert it into a verdict. A 200 from a served vantage proves delivery.
  A 403 from the listener's own tailnet address is *also* healthy — the
  self-probe's source is neither loopback nor the peer, so the refusal is the
  peer gate working, and doctor reports exactly that ("reachable and correctly
  refused self-probe"). A 403 from a vantage that should be served stays a
  failure.
- Callback hop: connect to the callback port and request a denylisted port, expect a
  clean refusal — proves the listener and the gate are both alive without arming
  anything.
- PC/SC: report the bridge socket's presence and say explicitly that end-to-end
  token health belongs to the secrets broker.
- Browser relay: connect without a token and classify `REFUSED TOKEN` as healthy;
  it proves the listener, peer check, and token gate without presenting a
  credential. A grant row queries the devbox request socket and reports whether
  the invoking session has a live loopback grant.

This replaces the health-checking that motivated the retired `forward tunnel`
subcommand, for the channels `forward` still owns.

## Testing

- Peer check: accepts the configured peer, rejects others, rejects all non-loopback
  when `peer` is unset.
- `auto` mode with non-loopback `listen` and no `peer` fails startup.
- Callback hop: **upstream bound only to `127.0.0.1`** — the case the first draft
  would have failed — plus armed-set accept, unarmed refuse, denylist refuse for
  `12799`, and refusal after lease expiry.
- Piping: half-close propagation in both directions; a refused upstream is logged
  and does not poison the lease; an in-flight connection survives lease expiry.
- Callback listener reachable at both `127.0.0.1:N` and `[::1]:N`.
- `Host` header: configured name and address accepted, mismatch and missing rejected.
- Config: unset `listen`/`peer` reproduces loopback behaviour.
- End-to-end on hardware once, after the single SSH-removal step: an SSO login start to
  finish, a file preview, and a plain URL open, with `12800` and `12802`
  gone from `Host devbox-tunnel` and no `ssh` invocation left in the binary. There is no
  second run, because there is no longer a staged removal to verify separately.

Every touched file stays under the 250-line CI limit; the proxy and the callback hop
are their own modules.

## Migration

Ordered so a working path exists at every step. Nothing here waits on the org: there
is no ACL to apply, no deprecation window, and no period in which both transports
carry traffic.

1. Land the code with loopback defaults. No behavioural change, nothing exposed.
2. Configure `listen`, `peer`, and the allowlist change from `localhost:12802` to the
   devbox host, on both machines. `Config` uses `deny_unknown_fields`, so the two are
   updated together. Verify end-to-end.
3. In one step: remove the `12800` and `12802` lines from `Host devbox-tunnel`, delete
   `src/forwards.rs`, delete the `ssh` and `tunnel_host` config fields, and confirm no
   `ssh` invocation remains in the daemon. The fields go outright rather than through a
   deprecation window — `deny_unknown_fields` already forces both machines to move
   together, so carrying them buys nothing, and a field read by nothing is a trap for
   the next reader. Backwards compatibility is not worth its overhead here.
4. Rebuild the tunnel and verify on hardware.

**Rebuilding the tunnel is manual and local, and cannot be automated away.** It has to
be run from a terminal on the laptop, inside a real login session. polkit's
`access_pcsc` is `allow_active=yes, allow_inactive=no`, so a tunnel created from a
non-interactive session — an agent over SSH, a systemd user unit — yields working TCP
forwards and a silently dead hardware token. The TCP half passing proves nothing about
the token, so verify the two halves separately.

**The hardware proof** is a real SSO login, start to finish, from the devbox — and then
confirming the PC/SC forward is *still up* past `forward_ttl_secs`. That second half is
the whole point: the lease expiry is what the `-O cancel` bug used to fire under the
tunnel five minutes after every login, and nothing short of watching a lease expire
with the token still working demonstrates that it is gone.

This one run supersedes the two the Testing section asks for. Two runs existed only
because removing the ssh_config lines and removing the code were separate steps; with
step 3 atomic, the absence of the lines and the absence of the `ssh` call are proven by
the same login.

Reverting is a config change through step 2. After step 3 it is a downgrade of both
binaries, which is the accepted cost of carrying no compatibility path.

## Alternatives considered

**Supervise the SSH master with a systemd user unit or autossh.** Pure config, and
it would shrink the invisible-death window to seconds after the network returns.
Rejected because it is not actually pure config here: the laptop routes all SSH auth
through the 1Password agent (`Host *` → `IdentityAgent`), so unattended reconnects
either fail until 1Password is unlocked or need a dedicated passwordless key — a
secret at rest, which this design's goals exclude and which the tailnet does not
need, since node identity already exists. It also cannot cover the PC/SC forward at
all, because polkit rejects processes outside an active seat, so `devbox-tunnel`
would have to be split anyway. And it keeps everything this design removes: the
lease tracker, the reaper, the subprocess handling, and the `-O cancel` spec bug.

**Drop mosh; plain SSH with inline forwards plus tmux.** This makes death visible
rather than silent, and there is only ever one connection. Rejected because it
reimposes manual reconnection after every sleep and network change — the friction
mosh exists to remove — many times a week, permanently. The split between mosh and
SSH is indeed the root cause; the fix is to remove the SSH half, not the half that
works.

**`tailscale serve`.** Verified to support raw TCP to a local backend. For the file
preview it would work with no Rust at all, but it is tailnet-wide by default, and
connections arrive from the local tailscale daemon, so the application loses the
peer address and control 1 becomes impossible. For the callback hop it would need
per-login mutation of daemon state with a matching teardown — reintroducing exactly
the "release must match creation" pattern this design exists to remove. Rejected for
both, though it remains proof that the devbox-side hop is a real and unavoidable
component.

**Keep callbacks on SSH, move only the URL channel and file preview.** The smallest
change that fixes something. Rejected because logins would still depend on the
tunnel, and logins are the reason this exists.

**Require a tailnet ACL and keep the file server rootless.** An earlier
revision of this design. Rejected on separation of concerns: the ACL is an
org-owned control and this is a user-installed tool, so making it a
prerequisite means the tool cannot enforce its own security posture, cannot
test it, and cannot even observe whether it holds. The user-owned peer check
carries the authorization instead, and the ACL remains welcome as defence in
depth that costs nothing when absent — narrowing who can reach the HTTP parser,
which is the one exposure the peer check cannot prevent.

## Open questions

1. **Is `auto` mode still the right default** once the URL channel is authenticated
   by peer address rather than by loopback confinement? The refusal-to-start rule
   above makes it safe; the question is whether it is still *wanted*.

Settled since the previous revision:

- **Restrict the file preview to the laptop only?** Yes. The peer check serves
  loopback and the configured counterpart, nothing else, so a preview URL on a
  phone is refused. If sharing is ever wanted it arrives as an additive
  `forward url --share`, not by weakening the default.
- **Must a tailnet ACL be applied before this ships?** No. See "Who owns each
  control".
