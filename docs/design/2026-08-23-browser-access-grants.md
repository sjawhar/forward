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
  loopback connection is attributed to a PID, the PID to an omp session, and a
  mismatch is refused and logged.
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
  │  · resolve peer PID → omp session; refuse on mismatch
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
told `ws://127.0.0.1:<port>/cdp` and stays on that port. Verified against the
live browser: dialling the laptop directly returns
`ws://100.100.92.97:12803/cdp`, while the same relay reached through a devbox
loopback forwarder returns `ws://127.0.0.1:12811/cdp` and lists 9 targets.

Without that behaviour a per-grant endpoint would be cosmetic, because every
client would be redirected onto the shared laptop address on its second request.

## Grant lifecycle

```
secrets FORWARD_BROWSER_GRANT -- forward browser grant --ttl 30m
```

The key blinks; a touch authorises, ignoring it denies. `secrets` injects the
token into the short-lived CLI's environment; the CLI hands it to the daemon
over the unix socket, and the daemon holds it only in memory. On success the
daemon binds an ephemeral loopback port, records `{session, port, token,
deadline}`, and prints the endpoint URL for the agent to pass as `app.cdp_url`.

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
with a port-safety policy, and a grant keys on session with an endpoint of its
own; sharing the type would blur two different units of authority.

## Wire protocol

The devbox proxy writes `RELAY <token>\n` before piping, exactly the shape
`bridge/listener.rs` already uses for `CONNECT <port>\n`, read byte-at-a-time
under a deadline against a length cap. No byte-replay machinery is needed,
because the line is written by our own proxy rather than sniffed out of a
client's stream.

New refusals join the existing `REFUSED PEER` / `REFUSED BUSY` vocabulary:

| Refusal | Meaning |
| --- | --- |
| `REFUSED TOKEN` | laptop: absent or non-matching token |
| `REFUSED UNGRANTED` | devbox: no live grant for this endpoint |
| `REFUSED SESSION` | devbox: connection did not come from the granted session |

## Token provisioning

The laptop holds the expected value in a `0600` file at
`$XDG_CONFIG_HOME/forward/relay.token`, falling back to
`$HOME/.config/forward/relay.token`, with an optional `relay_token_file`
override for anyone who wants it elsewhere. The path is derived rather than
configured because `config.toml` is committed to dotfiles and symlinked into
place: it can hold neither the secret nor a machine-specific absolute path.

The devbox holds the same value as a human-tier secretsd secret, so reading it
requires the touch and the grant is scoped to the requesting session for that
session's lifetime.

Provisioned once, by hand, without the value passing through any agent context:

```
ssh sami@sami forward browser init-token | secrets edit-human FORWARD_BROWSER_GRANT
```

`init-token` reads 32 bytes from `/dev/urandom` — a CSPRNG, needing no crate —
encodes them with the `base64` dependency the crate already carries, writes the
laptop file at `0600`, and prints the value to stdout exactly once.
`edit-human` reads stdin whenever stdin is not a TTY,
takes the bare value and builds the `NAME=value` assignment itself, and rejects
empty or multi-line input. Creating a key that does not yet exist through a
pipe forces a *local* human secret, so the token stays machine-local and never
reaches shared or committed storage.

## Peer attribution

Resolving a loopback TCP connection to a session is two hops:

1. **Connection → PID.** Match the client's address pair in `/proc/net/tcp` to
   get the socket inode, then find the process holding `socket:[inode]` under
   `/proc/*/fd`. Measured at 44 ms on this machine, once per CDP connection,
   never per byte.
2. **PID → session.** Each agent session is its own process, `omp --resume
   <uuid>`, so the session id comes from the process's own argv. A subagent's
   worker process resolves by walking `PPID` until that process is found.

Resolution happens at accept while the socket is live, which bounds but does not
eliminate PID-reuse risk. Failure to resolve is refused, never allowed.

## Configuration and health checks

Neither machine gains a required config key: the laptop derives its token path,
and `relay_token_file` exists only as an override.

`forward doctor` reports the relay row without holding any secret: it connects
to the laptop channel and treats `REFUSED TOKEN` as proof of life, because a
refusal proves the listener is alive, peer-authorised, and enforcing. A
connection failure and a refusal are therefore distinguishable, and neither
requires a touch.

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

`browser.rs` is at 160 lines against a 250-line cap, and the natural neighbours
are nearly full (`doctor/browser.rs` 235, `bridge/arming.rs` 225), so the devbox
side becomes a directory:

| File | Responsibility |
| --- | --- |
| `browser/grant.rs` | grant registry: session, port, token, deadline |
| `browser/proxy.rs` | per-grant loopback listener and refusals |
| `browser/peer.rs` | connection → PID → session resolution |
| `browser.rs` | laptop-side channel, now with the token check |

## Failure modes

| Condition | Behaviour |
| --- | --- |
| secretsd down, or YubiKey absent | no new grants; existing grants keep working |
| laptop token file missing | every connection refused; doctor names it |
| grant expires mid-session | new connections refused, established ones survive |
| peer PID unresolvable | refused and logged, never allowed |
| relay extension disconnected | unchanged: relay answers 503, doctor reports it |
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
