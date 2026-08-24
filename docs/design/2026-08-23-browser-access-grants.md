# Browser access grants

The browser relay channel gives any process on the devbox the whole browser
profile, at any time, with no human in the loop. That was the accepted property
when the channel shipped, and it is the property this document replaces.

Access becomes a **grant**: one agent session, authorised by a physical YubiKey
touch, reachable on an endpoint of its own, expiring on its own deadline. An
agent holding no grant has nothing to connect to.

## What this gets you

- Browser access requires a deliberate physical gesture. Nothing reaches Chrome
  while nobody is at the laptop.
- A grant names one session. Another agent cannot use it, and no agent can
  request one on another's behalf.
- Access lapses by itself. Forgetting to revoke is not a failure mode.
- No changes to oh-my-pi. Agents use the existing `app.cdp_url` tool argument,
  which `tools/browser.ts:94` already maps to a `connected` browser.

## Security model

What is enforced:

- **Nothing reaches the laptop untokened.** The relay channel refuses any
  connection that does not present the shared bearer token. A rogue process
  dialling `100.100.92.97:12803` directly is refused, which is what makes the
  grant system non-optional rather than advisory.
- **Only the granted session may use a grant's endpoint.** Every accepted
  loopback connection is attributed to a PID whose ancestry must reach the
  grant's kernel-identified session anchor; a mismatch is refused and logged.
- **A grant cannot be requested for another session.** The request arrives over
  a unix socket, so the caller's PID comes from `SO_PEERCRED` — exact, with no
  lookup and no race. There is no `--session` argument to forge.

What is **not** enforced, stated plainly because a security document that
overclaims is worse than one that admits a gap:

- **Same-uid isolation is not a boundary.** Every agent runs as `ubuntu`. A
  process determined to steal browser access can ptrace the granted process,
  read its memory, or drive it directly, and no gate at this layer prevents
  that. Peer attribution stops accidental and opportunistic reuse — an agent
  reading another's endpoint URL out of a transcript or handoff file, which is
  the realistic case with LLM-driven agents — not a hostile local attacker.
  A real boundary needs a uid or namespace per agent, which is out of scope.
- **A grant is not per-action.** Within its window the granted session drives
  the entire profile: every tab, every cookie, every logged-in session. The
  byte proxy cannot see CDP semantics and does not try to.
- **The token is a bearer credential, by choice.** It is a shared secret
  compared in constant time, not a signature. A signed challenge-response would
  stop replay by an observer, but the wire is WireGuard-encrypted to a
  peer-restricted listener, so anything positioned to replay the token is
  already the devbox and already holds it. The gain against this threat model
  is zero, so it does not justify a cryptographic dependency. Constant-time
  comparison is a short XOR accumulate and needs no crate.

## Architecture

```
agent session
  │  app.cdp_url: http://127.0.0.1:<grant port>
  ▼
devbox forward serve
  │  · accept on the grant's loopback port
  │  · resolve peer PID and verify its ancestry reaches the grant anchor
  │  · prefix "RELAY <token>"
  ▼  tailnet
laptop forward daemon :12803
  │  · peer check (unchanged)
  │  · constant-time token compare; refuse otherwise
  ▼
omp browser relay 127.0.0.1:9224 → extension → Chrome
```

The devbox already knows the laptop's address as `peer`, and the relay port as
`relay_port`, so the proxy needs no new configuration to find its upstream.

### Why the endpoint must be devbox-local

Puppeteer bootstraps from `GET /json/version` and then dials the
`webSocketDebuggerUrl` it is given. Because the relay derives that URL from the
request `Host`, a client reaching the relay through a devbox loopback port is
told `ws://127.0.0.1:<port>/cdp` and stays on that port. Measured before the
token gate existed, when the laptop could still be dialled directly: a direct
dial then returned `ws://100.100.92.97:12803/cdp`, while the same relay reached
through a devbox loopback forwarder returned `ws://127.0.0.1:12811/cdp` and
listed 9 targets. That direct dial is now refused, which is the point — but the
`Host`-derived behaviour it demonstrated is what makes a per-grant endpoint hold.

Without that behaviour a per-grant endpoint would be cosmetic, because every
client would be redirected onto the shared laptop address on its second request.

## Grant lifecycle

```
secrets FORWARD_BROWSER_GRANT -- forward browser grant --ttl 30m
```

The key blinks; a touch authorises, ignoring it denies. `secrets` injects the
token into the short-lived CLI's environment; the CLI hands it to the daemon
over the unix socket, and the daemon holds it only in memory. On success the
daemon binds an ephemeral loopback port and records `{session, anchor, port,
token, deadline}`. It anchors the grant to the nearest `omp --resume <uuid>`
ancestor of the request CLI's `SO_PEERCRED` PID. A grant therefore requires an
enclosing agent session: a request from a plain shell is refused rather than
anchored to the shell, because a transient wrapper is not a stable owner and
anchoring to one would recreate the dead-anchor failure this design exists to
avoid. The anchor pairs that
process's PID with its kernel start time; the session id is retained for display
and logging, not authorization. The daemon prints the endpoint URL for the
agent to pass as `app.cdp_url`.

The default TTL is 30 minutes: long enough not to interrupt a working session,
short enough that walking away from the desk closes the door.

On expiry a reaper closes the listener and zeroes the registry's copy of the
token, without waiting for a connection to notice. The value itself is shared by
every grant, so expiring one never invalidates another. A connection handler
already running holds its own copy for the life of that connection, so "the
daemon holds no token" is true once no grant is live *and* no session is open.
**Established connections are not killed** — the deadline governs when sessions
may start, so a lapsing window never guillotines an agent mid-workflow. There is
no revoke verb; expiry is the whole lifecycle until a need for one appears.

The callback bridge's `Armed` set is deliberately not reused. It keys on port
with a port-safety policy, and a grant binds one endpoint to one process anchor;
sharing the type would blur two different units of authority.

## Wire protocol

The devbox proxy writes `RELAY <token>\n` before piping, exactly the shape
`bridge/listener.rs` already uses for `CONNECT <port>\n`, read byte-at-a-time
under a deadline against a length cap. No byte-replay machinery is needed,
because the line is written by our own proxy rather than sniffed out of a
client's stream.

The refusal vocabulary is:

| Refusal | Meaning |
| --- | --- |
| `REFUSED FEED` | laptop: no grant-feed connection is attached; emitted only after the peer check |
| `REFUSED TOKEN UPSTREAM 200` | laptop: token absent or non-matching while the feed is attached; its fixed status probe found the extension healthy |
| `REFUSED TOKEN UPSTREAM 503` | laptop: token absent or non-matching while the feed is attached; its fixed status probe found the extension unavailable |
| `REFUSED UNGRANTED` | devbox: no live grant for this endpoint |
| `REFUSED SESSION` | devbox: connection did not come from the granted session |

## Grant feed

The laptop dials the devbox's configured `grant_port` and keeps that feed
connection open. It sends `FEED\n`; the devbox pushes
`TOKEN <token> <ttl>\n` for each live browser grant and waits for the laptop's
`OK\n` acknowledgment.

The laptop keeps each received token in an in-memory registry until its
deadline. Relay connections are accepted only when their `RELAY <token>\n`
prefix matches a live registry entry. Entries are zeroized when they leave the
registry. The dial direction and the devbox's port binding establish process
identity, so browser authorization needs no provisioned bearer secret or
machine-local token path.

## Peer attribution

Grant authorization and proxy authorization both rely on the kernel-maintained
process tree:

1. **Grant request → anchor.** `SO_PEERCRED` identifies the grant CLI exactly.
   The daemon walks its parents to the nearest `omp --resume <uuid>` process and
   refuses the grant when there is none. Process arguments only select an
   existing parent-chain link, so they cannot extend authority outside the
   requester's real subtree. The immediate-parent fallback in the resolver
   serves `STATUS` and test harnesses, never a production grant.
2. **Loopback connection → authorization.** The proxy matches the client's
   address pair in `/proc/net/tcp` to get its socket inode, then finds the
   owning PID under `/proc/*/fd`. It authorizes that PID only when its ancestry
   reaches the grant's exact PID-and-start-time anchor. `STATUS` applies the
   same rule to its Unix-socket caller.

Resolution happens while each socket is live, which bounds but does not
eliminate PID-reuse risk. Failure to resolve is refused, never allowed.

## Configuration and health checks

The feed uses `grant_port`; configuration contains neither a relay secret nor a
machine-local token path.

`forward doctor` reports the relay row without holding any secret. A
`REFUSED FEED` response means the probe observed no attached grant feed. An
authorized untokened probe with an attached feed receives only a refusal and
the result of the laptop's fixed `/json/version` status probe:
`REFUSED TOKEN UPSTREAM 200` means locked but healthy, while `REFUSED TOKEN
UPSTREAM 503` reports a disconnected extension. A connection failure remains
distinct from these refusals, and none requires a touch or exposes targets,
URLs, titles, or counts.

The devbox row reports whether the invoking session holds a live grant. It
cannot read the registry directly — `forward doctor` is a separate process from
the `forward serve` daemon that owns it — so it asks over the grant socket with
a `STATUS` verb, credentialed by the same `SO_PEERCRED` path as `GRANT`. A row
that guessed instead of asking would be a row that lies.

## Consumer cutover

Every existing caller dials the laptop directly and must move behind a grant.
No shims are kept, because a surviving direct path would reopen the bypass.

- `omp/config-serve.yml` drops `browser.relayUrl`; agents pass `app.cdp_url`.
- `.bashrc` drops the `BROWSER_RELAY_URL` export, and `installers/forward.sh`
  drops the derivation that writes it.
- `browser-capture` is given `--relay-url http://127.0.0.1:<grant port>` by the
  agent that holds the grant.

## Module layout

The laptop feed and relay gate stay separate from the devbox grant plumbing:

| File | Responsibility |
| --- | --- |
| `browser/feed.rs` | laptop feed client and live relay-token registry |
| `browser/grant.rs` | grant registry: session, process anchor, port, token, deadline |
| `browser/proxy.rs` | per-grant loopback listener and process-anchor refusals |
| `browser/peer.rs` | connection → PID → process ancestry resolution |
| `browser.rs` | laptop relay listener and registry gate |

## Failure modes

| Condition | Behaviour |
| --- | --- |
| secretsd down, or YubiKey absent | no new grants; existing grants keep working |
| laptop grant feed unavailable | every relay connection receives `REFUSED FEED`; doctor identifies the missing feed |
| grant expires mid-session | new connections refused, established ones survive |
| peer PID unresolvable | refused and logged, never allowed |
| relay extension disconnected | tokened traffic receives the relay's 503; doctor reports the disconnected extension from its restricted untokened status probe |
| grant proxy down | no browser access at all; there is no direct fallback |

That last row is the real cost of this design: `forward` becomes the mandatory
path, where today a direct dial works. It is accepted because exactly one way in
is what makes the property checkable.

## Verification

Against the live browser, never fixtures:

1. Without a grant, `curl http://100.100.92.97:12803/json/version` is refused.
2. With a grant, `curl http://127.0.0.1:<port>/json/version` returns a
   `webSocketDebuggerUrl` bearing that same loopback port.
3. The omp `browser` tool with `app.cdp_url` set to the grant endpoint drives a
   real laptop tab.
4. A second session connecting to the first session's port is refused.
5. After the TTL lapses, a new connection is refused while an established
   session continues.
