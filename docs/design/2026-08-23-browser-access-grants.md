# Browser access grants

Browser access is available through `forward` only. A session receives a
short-lived loopback endpoint after a human-authorized capability flow; the
endpoint is then the only route from that session to the laptop relay. If the
grant path, feed, or relay is unavailable, the implementation refuses access
rather than offering a direct connection.

## What an access grant means

The session runs `forward browser grant --ttl 30m`. The command performs
capability authorization before it contacts the devbox daemon, then binds its
own ephemeral loopback listener and tells the daemon which port it bound. On
success the CLI prints `http://127.0.0.1:<port>` for the session to pass as
`app.cdp_url`. The command accepts seconds, minutes, or hours; its default is
30 minutes, and the daemon rejects a requested lifetime above 12 hours.

### Where the endpoint lives, and why

The endpoint is bound by the caller, in the caller's own network namespace,
and served by a detached child of the grant CLI. `forward serve` binds nothing
for a grant. It used to, and that was wrong in two ways at once for any caller
inside an agent box (issue #51, measured 2026-09-25):

- **The address was not the caller's.** `forward serve` runs in the host's
  network namespace, so its `127.0.0.1:<port>` is not the loopback a box can
  reach. The command printed an endpoint with no listener behind it.
- **The check could not have passed anyway.** Attribution needs
  `/proc/<pid>/exe` (to confirm an argv-selected `omp` ancestor) and
  `/proc/<pid>/fd` plus `/proc/net/tcp` (to resolve a loopback connection to
  its owner). From the host, a box process's `stat` and `cmdline` are
  readable, but `exe` is denied, `fd` is `Permission denied`, and the box's
  connection is absent from the host's TCP table. So the anchor silently fell
  back to the CLI's parent shell, and no box client could ever have been
  attributed to it. Inside the box, all of those reads work.

So the parts that need the caller's `/proc` and the caller's loopback moved
there, and the parts the caller must never hold stayed in `forward serve`: the
receipt, its redemption, the relay token, and the connection to the laptop.
A file descriptor crosses a network namespace; an address does not.

### The two halves and the channel between them

The CLI derives the anchor itself — its own ancestry is intact and its
`/proc/<pid>/exe` entries are readable — and refuses before the ceremony if it
cannot. After the ceremony it binds `127.0.0.1:0`, sends
`GRANT <ttl> <receipt> <port>` on the request socket, and on `OK` keeps that
connection open as the grant's **control channel**. It hands the listener and
the control channel to a detached child (`forward browser relay`, a hidden
subcommand) as inherited descriptors, prints the URL, and exits.

The relay child accepts CDP clients, applies the ownership check where `/proc`
is readable, and passes each admitted socket to `forward serve` over the
control channel with `SCM_RIGHTS`. `forward serve` checks that what arrived is
a connected loopback INET stream, re-checks that the grant is still live,
connects to the laptop, presents `RELAY <token>`, and pipes.

The control channel is authenticated by being the connection on which the
receipt was redeemed, so no socket arriving on it has to be identified again.
It is also the grant's lifeline in both directions: closing it ends the grant
in `forward serve`, and `forward serve` closing it ends the endpoint.

### Containment

Each grant identifies an `omp --resume` session and anchors it to that session
root's kernel PID plus process start time. The short-lived grant CLI is not the
anchor: it exits immediately, so making it the boundary would refuse every
later browser connection. The relay resolves each loopback client's owning
process and requires that it descend from the enclosing session root. Every
descendant of that root, including a sibling process in the same agent session,
may use the endpoint; a process outside that tree may not. The session
identifier is for reporting, while the PID-and-start-time anchor is the
authorization value.

There are two anchors, derived separately and used for different things. The
relay enforces the one the CLI derived in the caller's namespace. `forward
serve` records the one it derives from the request connection's `SO_PEERCRED`
pid, and uses it only for log lines and for answering `STATUS` — so `STATUS`
from inside a box answers for the subtree the *host* can see, which is the
shell that ran the grant and its descendants.

An expiry reaper removes the grant and closes its control channel, which
retires the endpoint even when no client ever connected. A connection already
being piped retains its cloned grant state and is not killed solely because the
deadline passes; it is killed by any revocation, which severs registered pipes.

Grants are keyed by an id the registry mints, not by port: an endpoint port
belongs to its caller's namespace, so two live grants may carry the same one.

## Capability ceremony and receipt

The capability is not a pure ceremony. The expected secretsd contract backs
each capability with a real `CAP_<NAME>` human key. Its sops/age decrypt is the
operation that can require the YubiKey touch; the key's plaintext remains in
secretsd and is never returned to `forward`. The browser client requests the
`browser` capability. This is deliberately a yes-or-no authorization interface,
not a secret-fetch interface.

`forward` implements the client side of secretsd protocol v3. It opens a
separate `HELLO` connection that requires protocol version 3 before each
operation. The session-resident CLI sends `AUTHORIZE` with `cap=browser` and
either the session token or its terminal path as scope. It validates request
fields and caps that frame at 4096 bytes. A successful reply must contain exactly
`status=authorized` and a 64-character lowercase-hex `receipt`; replies are
bounded to 256 bytes and checked for their expected schema.

The CLI hands that receipt to the devbox `forward serve` request socket, which
is mode 0600. The daemon sends `REDEEM` directly to secretsd and accepts only a
reply with `status=redeemed` and `cap=browser`. This division keeps
authorization in the session-resident process while allowing the daemon to
verify it before it creates a browser endpoint.

The expected broker contract is a receipt that can be redeemed once and expires
after 60 seconds. That server-side enforcement is pending outside this Task:
`forward` checks receipt shape and presents it, but does not timestamp or
consume receipts locally. A same-uid process able to inspect the CLI's memory
can copy a receipt and redeem it first. The legitimate request then receives a
receipt refusal rather than silent shared access, but the first redemption can
still create a grant for the competing session. This is an accepted
same-uid-local-attacker residual, not a property the receipt removes.

After successful redemption, the daemon performs this order: it mints a fresh
relay token, rechecks broker authority, pushes the token to the laptop,
rechecks authority again, records the grant, schedules expiry, answers `OK`,
and only then begins reading the control channel for connections. It does not
serve a connection before its grant exists, and it does not sell a grant when
the laptop has not acknowledged the token. The caller's endpoint is bound
before the request and accepts nothing until its relay child starts, which
happens only after `OK`.

## Grant feed and relay

The laptop daemon dials `peer:grant_port` and holds one persistent feed
connection. The devbox feed listener accepts only an authorized peer whose
first line is `FEED`. A successful attachment replaces any earlier feed
connection and replays each live devbox grant. For a new grant, the devbox
relay token, sends `TOKEN <token> <ttl>`, and waits up to five seconds for
the exact three-byte acknowledgement `OK\n`.

The laptop parses a bounded feed line, registers the token until its supplied
TTL, and replies with the exact acknowledgement `OK\n`. Its registry uses
`CLOCK_BOOTTIME`, so time spent suspended counts toward expiry.
A timerfd reaper removes expired entries, and
entry removal overwrites the registry's token bytes. The registry keeps at
most 64 entries, evicting the oldest before inserting another. A relay request
is accepted only when its bounded `RELAY <token>` prefix matches a live entry;
the comparison scans every live token without an early match exit.

The laptop browser listener checks the peer address before it parses that
prefix. A tokened connection is piped to the local relay at `127.0.0.1:9224`.
An authorized but untokened connection receives `REFUSED FEED` when no feed is
attached. With a feed attached, an absent or mismatched token receives
`REFUSED TOKEN UPSTREAM 200` or `REFUSED TOKEN UPSTREAM 503`, reflecting only
the fixed local relay status probe.

Per-grant tokens are strictly stronger than a static bearer credential: copying
one can authorize only connections during that grant's bounded lifetime, rather
than every session indefinitely. They are still bearer values on the
peer-authenticated path and in the two daemon registries; they are not a
signature scheme.

## Security model

The laptop trusts four things. It trusts the configured literal peer address
only on a specific non-wildcard tailnet listener, where WireGuard identity and
AllowedIPs make the address meaningful. It trusts the devbox process that owns
the feed port because the laptop initiated the connection and the kernel permits
only one binder. It trusts the fresh relay token for per-connection access, and
it delegates session-gating and the hardware ceremony to the devbox grant
machinery and secretsd.

This is not a same-uid isolation boundary. Every agent runs as `ubuntu`; a
process with ptrace-level access can read another process's memory, observe its
loopback endpoint, or race the receipt as described above. PID attribution
stops accidental and opportunistic reuse, such as a different session reading a
URL from a transcript. It does not defend against a determined local process.
Likewise, a grant is not per action: after the gate opens, the bytes are piped
to the browser relay and nothing interprets browser semantics.

Moving admission into the caller's namespace does not lower that bar, and the
reason is worth stating plainly: the enforcing process is now the caller's own
child, so a caller could in principle hand it a wider anchor than the one it
derived. That widens only what the caller can already do — it holds the
endpoint and could proxy for anything it likes regardless. What the caller
still never holds is the receipt's redemption, the relay token, or the route to
the laptop. Against the same-uid attacker the model already declines to defend
against, nothing changed; against the namespace boundary, the check now runs
somewhere it can actually read the answer, where before it always failed.

The browser and smartcard channels share the same cost: `forward` is their
single path. There is no direct browser route and no alternate PC/SC bridge in
this implementation. A daemon, feed, or socket outage removes the corresponding
capability until the supervised service recovers.

## Failure modes

| Condition | Behaviour |
| --- | --- |
| secretsd is unreachable, denies the request, times out, reports an unavailable YubiKey, or is too old for the capability operation | `forward browser grant` fails before it contacts the devbox request socket. Existing grants retain their own deadlines. |
| The request socket receives a malformed receipt, or a request with no usable endpoint port | The daemon returns `REFUSED`; it does not mint a token or record a grant, and it never reaches the broker. |
| secretsd rejects a well-formed receipt during redemption | The daemon returns `REFUSED RECEIPT`; it does not mint a token or record a grant. |
| No laptop feed is attached | A new grant is refused with `REFUSED LAPTOP`. Live laptop tokens remain usable until their own `CLOCK_BOOTTIME` deadlines, but no new token can be delivered. |
| A feed connection fails, or closes or becomes malformed before it proves useful | The laptop worker keeps one 30-second unhealthy budget. A parsed token or an otherwise idle feed that stays attached for the full budget resets it; a greeting-and-close flapper does not. An exhausted budget slows the dial cadence from 5 to 60 seconds without exiting, so the daemon's other channels keep serving through a peer outage. The devbox listener exits for systemd after 30 seconds of persistent accept errors. |
| A grant expires, or is revoked by `secrets lock` or a broker change | The registry removes the grant, severs its established pipes, and closes its control channel; the caller's relay then closes its listener and exits, so the endpoint stops accepting rather than refusing. |
| The caller's relay dies, or the machine it ran on stops | `forward serve` sees the control channel close and expires the grant, so no live grant or renewable laptop token outlives the caller. |
| The relay hands over a descriptor that is not a connected loopback INET stream | The daemon logs it, drops the descriptor, and keeps serving the grant. |
| The local browser relay is unavailable | A tokened request cannot reach its upstream and is refused. An untokened status probe reports the unavailable upstream without exposing browser targets. |
| A required `forward` daemon, feed, or PC/SC socket is down | The affected browser or smartcard route is unavailable. The implementation has no direct fallback path. |

## Health checks

`forward doctor` reports `browser relay`, `browser feed`, and `browser grant`
alongside the PC/SC rows. `browser grant` is session-relative: no grant is
informational rather than unhealthy, and its no-grant row prints the exact
command `forward browser grant --ttl 30m`. A recorded grant is not a usable
one — the endpoint is a separate process in the caller's namespace — so the row
probes `GET /json/version` on the reported endpoint and says when it does not
answer. Reporting the registry record alone is how `doctor` came to read green
against an endpoint that refused every connection. The browser relay row can
report a locked relay without disclosing the target list; the feed row is a
reachability probe, not evidence that a particular token is present.

## Verification

Run `forward doctor` from the session that will use the browser endpoint. Then
run `forward browser grant --ttl 30m`, complete the broker's touch ceremony,
and use the printed loopback URL as that session's `app.cdp_url`. `doctor` must
then report the grant as live *and* answering. A second session must not be
treated as the owner of that endpoint, and a new connection after the grant
deadline must be refused. Run it once from a host session and once from inside
an agent box: the box is where the two namespace failures above were, and a
host-only check is exactly what missed them. These checks exercise the
capability request, receipt redemption, feed acknowledgment, process
attribution, and relay gate as one path.
