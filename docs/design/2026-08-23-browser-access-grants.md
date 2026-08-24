# Browser access grants

Browser access is available through `forward` only. A session receives a
short-lived loopback endpoint after a human-authorized capability flow; the
endpoint is then the only route from that session to the laptop relay. If the
grant path, feed, or relay is unavailable, the implementation refuses access
rather than offering a direct connection.

## What an access grant means

The session runs `forward browser grant --ttl 30m`. The command performs
capability authorization before it contacts the devbox daemon. On success the
daemon returns a numeric ephemeral-listener port over its request socket, and
the CLI prints `http://127.0.0.1:<port>` for the session to pass as
`app.cdp_url`. The command accepts seconds, minutes, or hours; its default is
30 minutes, and the daemon rejects a requested lifetime above 12 hours.

Each grant identifies an `omp --resume` session and anchors it to that session
root's kernel PID plus process start time. The short-lived grant CLI is not the
anchor: it exits immediately, so making it the boundary would refuse every
later browser connection. The grant proxy resolves each loopback client's owning
process and requires that it descend from the enclosing session root. Every
descendant of that root, including a sibling process in the same agent session,
may use the endpoint; a process outside that tree may not. The session
identifier is for reporting, while the PID-and-start-time anchor is the
authorization value. An expiry reaper removes the grant and wakes its listener.
A connection already being proxied retains its cloned grant state and is not
killed solely because the deadline passes.

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
relay token, binds the loopback proxy, pushes the token to the laptop, inserts
the grant, schedules expiry, and starts accepting on the proxy. It does not
serve the bound port before its grant exists, and it does not sell a grant when
the laptop has not acknowledged the token.

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
Likewise, a grant is not per action: after the gate opens, the proxy pipes the
session's CDP bytes to the browser relay and does not interpret browser
semantics.

The browser and smartcard channels share the same cost: `forward` is their
single path. There is no direct browser route and no alternate PC/SC bridge in
this implementation. A daemon, feed, or socket outage removes the corresponding
capability until the supervised service recovers.

## Failure modes

| Condition | Behaviour |
| --- | --- |
| secretsd is unreachable, denies the request, times out, reports an unavailable YubiKey, or is too old for the capability operation | `forward browser grant` fails before it contacts the devbox request socket. Existing grants retain their own deadlines. |
| The request socket receives a malformed receipt | The daemon returns `REFUSED`; it does not mint a token, bind a usable grant, or start a proxy. |
| secretsd rejects a well-formed receipt during redemption | The daemon returns `REFUSED RECEIPT`; it does not mint a token, bind a usable grant, or start a proxy. |
| No laptop feed is attached | A new grant is refused with `REFUSED LAPTOP`. Live laptop tokens remain usable until their own `CLOCK_BOOTTIME` deadlines, but no new token can be delivered. |
| A feed connection fails, or closes or becomes malformed before it proves useful | The laptop worker keeps one 30-second unhealthy budget. A parsed token or an otherwise idle feed that stays attached for the full budget resets it; a greeting-and-close flapper does not. An exhausted budget slows the dial cadence from 5 to 60 seconds without exiting, so the daemon's other channels keep serving through a peer outage. The devbox listener exits for systemd after 30 seconds of persistent accept errors. |
| A grant expires | The devbox registry removes the grant and stops its listener. New connections are refused; a handler already piping a connection continues until its I/O ends or reaches its 15-minute pipe timeout. |
| The local browser relay is unavailable | A tokened request cannot reach its upstream and is refused. An untokened status probe reports the unavailable upstream without exposing browser targets. |
| A required `forward` daemon, feed, or PC/SC socket is down | The affected browser or smartcard route is unavailable. The implementation has no direct fallback path. |

## Health checks

`forward doctor` reports `browser relay`, `browser feed`, and `browser grant`
alongside the PC/SC rows. `browser grant` is session-relative: no grant is
informational rather than unhealthy, and its no-grant row prints the exact
command `forward browser grant --ttl 30m`. The browser relay row can report a
locked relay without disclosing the target list; the feed row is a reachability
probe, not evidence that a particular token is present.

## Verification

Run `forward doctor` from the session that will use the browser endpoint. Then
run `forward browser grant --ttl 30m`, complete the broker's touch ceremony,
and use the printed loopback URL as that session's `app.cdp_url`. A second
session must not be treated as the owner of that endpoint, and a new connection
after the grant deadline must be refused. These checks exercise the capability
request, receipt redemption, feed acknowledgment, process attribution, and
relay gate as one path.
