# Pulse channel

`forward` is the only transport path between a PulseAudio client on the devbox
and the laptop's pipewire-pulse server. It carries opaque native-protocol
bytes; it does not interpret audio streams, negotiate formats, or manage
latency. Losing this path removes remote audio rather than falling back to an
SSH forward. The channel is audio-specific, not omp-specific: any PulseAudio
client on the devbox reaches the laptop through it via `PULSE_SERVER`, and the
coding-agent integration is a single environment variable, not code.

## Channel topology

The devbox end belongs to `forward serve`. With a configured peer and a nonzero
`pulse_port`, it creates the socket `$XDG_RUNTIME_DIR/forward/pulse.sock`
(directory mode `0700`, socket mode `0600`). For each local PulseAudio client,
the server dials `peer:pulse_port` and pipes that Unix stream to the laptop.

The laptop end belongs to `forward daemon`. It listens at `listen:pulse_port`,
authorizes the TCP peer, and pipes an accepted stream to
`$XDG_RUNTIME_DIR/pulse/native`. The default `pulse_port` is 12806; setting it
to zero disables the channel. The laptop socket is mode 0666 on the supported
deployment, so `forward-daemon` connects without a helper or group membership.
pipewire-pulse remains responsible for handling its client.

```
devbox PulseAudio client
    │ Unix: $XDG_RUNTIME_DIR/forward/pulse.sock (0600)
    ▼
forward serve
    │ TCP: peer:pulse_port (default 12806)
    ▼
forward daemon
    │ Unix: $XDG_RUNTIME_DIR/pulse/native
    ▼
laptop pipewire-pulse → speakers / microphone
```

The devbox socket path is intentionally not configurable, and it is
deliberately **not** PulseAudio's default socket path. Clients must opt in with
an explicit `PULSE_SERVER=unix:$XDG_RUNTIME_DIR/forward/pulse.sock`: consumers
size their buffers for a network round trip when and only when `PULSE_SERVER`
is set (pi-voice defaults to 200 ms buffer targets in that case, overridable
via `PULSE_LATENCY_MSEC`). A socket planted at the default path would make
clients auto-select the remote server while sizing buffers for local shared
memory, reintroducing the underrun stutter the explicit variable exists to
prevent.

`pulse_port` joins the same effective-configuration service-port set as the
URL, callback, browser-relay, grant-feed, and PC/SC services, so the callback
bridge cannot be armed to dial it. Moving the configured port moves its denial
with it.

## Protocol and liveness

PulseAudio native-protocol frames are raw bytes. Neither side adds a request
header, status line, or refusal text. An unauthorized peer, a full connection
budget, an unavailable upstream socket, and a failed dial all get a bare
close: injecting diagnostic bytes would corrupt the client's protocol stream.
Authentication and negotiation happen end to end between the client and
pipewire-pulse, exactly as they would over a local socket.

The pipe copies in both directions and propagates EOF by half-closing the
opposite write side. It has no application idle timeout: a connected but
silent pulse context (a client holding a stream open between utterances) is
legitimate and may stay quiet indefinitely. Each TCP leg enables the shared
keepalive tuning — 60 seconds before probing, six probes, ten seconds between
probes — finding a dead peer in roughly two minutes without terminating a
quiet live session. Both TCP legs additionally set `TCP_NODELAY`: the native
protocol is a chatty request/reply exchange during stream setup and a steady
sequence of small writes during playback and capture, and Nagle coupling
either to the round-trip time adds avoidable latency to an interactive audio
path. A new devbox-to-laptop connection has a five-second dial timeout and is
then closed on failure, so a sleeping or unreachable laptop fails promptly —
the same connection-refused surface clients saw when the old tunnel was down.

## Security model

The laptop endpoint is served only when a peer is configured, and permits a
TCP connection only when its source address equals that configured peer;
loopback has no exemption. This identity check relies on a specific,
non-wildcard tailnet listener and the tailnet's WireGuard identity. It does
not authenticate a PulseAudio request. The devbox Unix leg is
filesystem-scoped to the same uid through its `0600` socket and `0700` parent
directory. pipewire-pulse performs no client authorization of its own — the
runtime-directory mode is its only gate — unlike pcscd's polkit check.

Same-uid isolation is not a boundary. Every devbox agent runs as the same
user, and a process with ptrace-level access can interfere with another
same-uid process or its socket. The `0600` path prevents accidental use and
access by other uids; it does not create a hostile-local-process boundary.
What the channel exposes is the laptop's audio devices: a devbox process that
can open the socket can play sound on and record audio from the laptop. That
is the channel's purpose, and the blast radius equals what the retired SSH
tunnel already granted; the tailnet identity check keeps that surface scoped
to the configured devbox rather than any network peer.

## Supervision

Both deployed user units use `Restart=always` with a two-second restart delay:
`forward-daemon` owns the laptop listener and `forward-serve` owns the devbox
socket. The process treats listener termination and listener-thread panics as
fatal, so a service manager rather than an orphaned helper owns recovery.

The laptop unit is part of `graphical-session.target`. Before GUI login, that
unit and the pulse channel are unavailable — an acceptable constraint, since
pipewire itself runs in the user session. As with the PC/SC channel, a
persistent laptop bind failure causes the whole daemon to exit after it has
already started its other channels, and the bounded restart policy then stops
recovery for every channel. A bad port configuration is loud, not isolated.

## Consumer rollout

After the channel ships, the devbox dotfiles export one global line:

```
PULSE_SERVER=unix:$XDG_RUNTIME_DIR/forward/pulse.sock
```

Every PulseAudio-speaking process on the devbox — the coding agent's `/live`
mode, `paplay`, `parecord`, `ffmpeg` — then routes to the laptop with no
per-tool wiring. The devbox is headless, so there is no local audio server to
shadow. When the channel is down, audio tools see a connection failure rather
than "no audio system", which is the more honest error.

The rollout retires the interim transport: the ad-hoc SSH tunnel
(`ssh -L /tmp/pulse-laptop.sock:/run/user/1000/pulse/native`) and its
supervisor entry are removed once the channel passes acceptance.

## Failure modes

| Condition | Behaviour |
| --- | --- |
| `pulse_port` is zero, or either machine has no peer | The corresponding pulse endpoint is not served. No alternate transport is started. |
| A live process owns `$XDG_RUNTIME_DIR/forward/pulse.sock` | The devbox refuses to replace it. It does not unlink a socket that accepted a connection. |
| A stale socket is found | The devbox rechecks that it is still an unserved socket before unlinking it, which refuses a live socket or non-socket path observed by that check. The recheck narrows but cannot eliminate the final race before `remove_file`. |
| The laptop is unreachable | A new devbox-side client sees its stream close after the five-second dial timeout; existing TCP sessions rely on keepalive or their client timeout. |
| Laptop pipewire-pulse is unavailable | The laptop closes the authorized TCP stream without writing a protocol response. |
| The pulse listener cannot bind persistently | The relevant `forward` process exits for systemd to restart. On the laptop, the bounded restart policy eventually stops the whole daemon and its other channels. |

## Verification

`forward doctor` prints two separate rows. `pulse channel` is a TCP acceptance
probe for the configured port. `pulse socket` probes whether
`$XDG_RUNTIME_DIR/forward/pulse.sock` accepts a Unix connection. Neither row
proves that audio plays or records; end-to-end verification belongs to the
consumer. The acceptance check for the rollout is a live session on the devbox
with the SSH tunnel absent: smooth playback and capture against the laptop.
