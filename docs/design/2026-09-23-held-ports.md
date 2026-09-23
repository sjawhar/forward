# Held ports

`forward port <port>...` makes the laptop's `localhost:<port>` reach
`127.0.0.1:<port>` (or `[::1]:<port>`) on the machine where the command runs,
for as long as the command runs. The ports keep their numbers and the bytes are
not interpreted, so an app that insists on a `localhost` origin, a `__Host-`
cookie, or its own self-signed localhost certificate works unchanged in the
laptop browser. "The machine where the command runs" includes an agent box: a
Sysbox container with its own network namespace, whose loopback nothing outside
it can reach.

It reuses the OAuth callback bridge from the tailnet transport design
(`2026-07-28-tailnet-native-transport.md`, "OAuth callback") and closes the two
ways that bridge falls short for viewing a web app:

- **The last hop is the serve's own loopback.** `forward serve` runs on the host
  and connects to the host's `127.0.0.1:N`. A server inside a box listens on the
  box's loopback, and the serve cannot enter that namespace without privilege
  over the box's user namespace.
- **The laptop lease is a login window.** The laptop listens for
  `forward_ttl_secs` from the last URL naming the port. Traffic does not extend
  it, and extending it means sending the URL again, which opens a tab.

## Topology

```
laptop browser ── https://localhost:5173 ──► forward daemon (laptop loopback :5173)
    │ TCP: peer:bridge_port, "CONNECT 5173"
    ▼
forward serve (host) ── holder for 5173? ──► "DIAL" on the holder's unix connection
    ▲                                            │
    │ connected socket, SCM_RIGHTS               ▼
    └──────────────────────────────── forward port (host, or inside a box)
                                          connects to its own 127.0.0.1:5173
```

1. **Hold on the devbox side.** `forward port N` connects to the bridge's arming
   socket (`$XDG_RUNTIME_DIR/forward/arm.sock`, in the directory the agentbox
   launcher already bind-mounts into every box) and sends `HOLD N`. The serve answers
   `ok` and keeps the connection as the port's holder, or answers `busy` if a
   live holder already has the port, or `unsafe` for a port the bridge must
   never dial.
2. **Dial per connection.** When a bridge connection asks for a held port, the
   serve writes `DIAL` on the holder's connection. The holder connects to its
   own loopback, IPv4 then IPv6, and answers one byte: `+` with the connected
   socket attached as an `SCM_RIGHTS` descriptor, or `-` when nothing accepted.
   The serve checks the descriptor is a stream socket and pipes the bridge
   connection to it exactly as it pipes to loopback for an armed port. Dials on
   one holder are serialised under its lock; each is a loopback connect.
3. **Hold on the laptop side.** The URL channel accepts a second request shape,
   `HOLD <port> <secs>`. The daemon serves laptop loopback for the port through
   the same lease machinery `forward open` uses, opens nothing, and answers
   `held` or `refused <reason>`. `forward port` renews every 60 seconds with a
   180-second lease, and the daemon caps any hold at 600 seconds, so a devbox
   that vanishes frees its laptop ports within minutes.

A descriptor crosses a network namespace where an address cannot, so the same
code serves the plain devbox and a box, with no in-box listener, no container
runtime involvement, and nothing added to the agentbox launcher.

## Lifetime

A hold lasts exactly as long as the holder's connection. The serve notices a
dead holder when a dial to it fails, when another process asks to hold the
same port (which it then gets at once), or when `forward open` arms it. There
is no devbox-side timer. On the laptop, a hold outlives its devbox side by at
most one lease: connections in that window reach the serve and are refused.

A held port has exactly one route, its holder. Taking a hold deletes any timed
arming of that port, and arming a port whose holder is alive succeeds without
recording anything, since the port is already reachable. So when a holder dies
the port is unreachable until something holds or arms it again. It never falls
through to whatever this host serves on the same number, which would switch the
laptop's `localhost:<port>` origin to a different service without warning. For
a port nobody holds, `forward open`'s timed arming is unchanged, including its
dial to the serve's own loopback, so browser logins on the devbox take exactly
today's path.

A login started inside a box is the one case this does not fix on its own.
`forward open` still arms its callback port on the host's serve, which dials
the host's loopback, so a box-local callback server is not reached. Holding the
callback port first (`forward port <port>`, then the login) does work: the
arm records nothing under the live hold and the redirect reaches the box.
Making `forward open` hold automatically would need a background helper with
its own lifetime, which this design deliberately does not add.

## Security model

The bridge's existing gates apply to holds unchanged: the peer check on every
bridge connection before its request line, the denylist enforced at
connection time (forward's own ports, the laptop hardware-token port, the
listener port), and `can_arm` at hold time (privileged ports and the
development ports that grant code execution). The arming socket stays
local-only (`0600` in a directory only this uid can write), so holding grants a
local process nothing it could not already reach. What a hold controls is which
ports the remote peer may use, and only while its holder runs.

A holder dials only its own loopback. The serve never learns an address to
dial, so there is no target for a confused-deputy request to name.

On the laptop, a hold lets the devbox make the daemon listen on a loopback
port, which a devbox URL naming that port could already do. The port must be
dynamic (not one of forward's own), and the lease is capped.

## Failure modes

| Condition | Behaviour |
|---|---|
| No arming socket (serve down, or not mounted in the box) | `forward port` exits non-zero naming the socket path |
| Port privileged, denylisted, or already held by a live holder | `forward port` exits non-zero naming the port and which it was |
| Laptop daemon older than holds | it reads `HOLD` as a malformed URL and hangs up; `forward port` exits non-zero telling you to upgrade forward on the laptop |
| Devbox `forward serve` older than holds | it closes on `HOLD` without answering, where a current serve answers `unsafe` for a refused port; `forward port` exits non-zero telling you to upgrade forward on the devbox and restart its serve |
| Laptop cannot bind the port (in use there) | `refused <reason>`; `forward port` exits non-zero with it |
| Laptop unreachable after start | warned once per outage per port; the devbox hold stays; renewal resumes |
| Nothing listening on the held port | the holder answers `-` and logs the port; the browser connection is refused; the hold stays |
| Holder killed | the next dial, hold, or arm for the port frees it; the port is then unreachable, never routed to this host's loopback |
| Serve restarts | every holder's connection closes; `forward port` exits non-zero so its supervisor sees it |

## Verification

Unit tests cover strict parsing of the arming socket's `ARM` and `HOLD`
requests, and that reading a `HOLD` consumes nothing past its newline.
Integration tests drive a real bridge and arming socket: a held port with
nothing armed is reached only through its holder; a held port never falls
back to this host's loopback, whether it was armed before the hold or during
it; a live hold is never taken over, while a dead one or one that answers
garbage is replaced at once; unsafe ports are refused; a connection with no
server behind the port is refused while the hold survives for a server that
starts later. Daemon tests run the real binary: a hold serves the laptop port
and opens nothing even in allowlist mode, an oversized lease is capped rather
than refused, a port in use on either laptop loopback family is refused with
its reason, a daemon that predates holds is reported as needing an upgrade,
and `forward port` exits non-zero when the bridge ends its hold.

Those tests run the holder and the bridge in one network namespace. The
cross-namespace case is checked by hand. It needs an agent box `<box>` (IP
`<box-ip>`) running a server on its loopback, and host ports 22800-22805 free.

1. Write the host config, used by both the serve and the daemon, to
   `/tmp/held-ports-check/host.toml`:

   ```toml
   listen = "127.0.0.1"
   peer = "127.0.0.1"
   bridge_port = 22801
   relay_port = 22803
   grant_port = 22805
   pcsc_port = 0
   pulse_port = 0
   ```

   `pcsc_port = 0` and `pulse_port = 0` keep the test serve off the live
   hardware-token and audio sockets. Copy the release binary and a `box.toml`,
   identical except `peer = "172.31.0.1"` (the `agentbox` network's gateway),
   into `~/boxes/<box>/.forward-check/`, which the box sees at the same path.
2. `mkdir -m 700 /run/user/$UID/forward/held-ports-check`. Boxes bind-mount
   `/run/user/$UID/forward` at the same path, so this is where both sides
   find the test serve's arming socket.
3. On the host, under a supervisor, each with
   `XDG_RUNTIME_DIR=/run/user/$UID/forward/held-ports-check`:

   ```sh
   forward serve --port 22802 --config /tmp/held-ports-check/host.toml
   forward daemon --port 22800 --config /tmp/held-ports-check/host.toml
   socat TCP4-LISTEN:22800,bind=172.31.0.1,reuseaddr,fork,range=<box-ip>/32 TCP4:127.0.0.1:22800
   ```

   The relay stands in for the NAT a box's traffic takes to the laptop: the
   daemon then sees the box's hold requests arriving from its configured
   `peer`. Both processes report pcsc and pulse disabled, and the serve logs
   failed broker-authority subscriptions because the test runtime directory
   has no secretsd socket; both are expected.
4. Inside the box:

   ```sh
   docker exec -i --user 1000:1000 -e HOME=$HOME \
     -e XDG_RUNTIME_DIR=/run/user/$UID/forward/held-ports-check <box> \
     ~/boxes/<box>/.forward-check/forward port <ports> \
     --channel-port 22800 --config ~/boxes/<box>/.forward-check/box.toml
   ```

   `--channel-port` must match the daemon's `--port`.
5. On the host, `curl -sk https://localhost:<port>/` (or a browser) must reach
   the box's server; a port nobody holds must reach nothing.
6. Tear down: stop the three host processes. Stopping the `docker exec` client
   does not stop the process inside the box, so also run
   `docker exec <box> pkill -f '.forward-check/forward port'`. Remove
   `/tmp/held-ports-check`, the runtime directory, and
   `~/boxes/<box>/.forward-check`.

The run on 2026-09-23, against a local web app stack in an agent box, is
recorded in the pull request that introduced this document.
