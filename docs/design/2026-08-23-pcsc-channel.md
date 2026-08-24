# PC/SC channel

`forward` is the only transport path between a PC/SC client on the devbox and
the laptop's `pcscd`. It carries opaque protocol bytes; it does not interpret
smartcard requests, broker secrets, or YubiKey state. Losing this path therefore
removes smartcard access rather than falling back to an SSH forward or a local
bridge.

## Channel topology

The devbox end belongs to `forward serve`. With a configured peer and a nonzero
`pcsc_port`, it creates the fixed compatibility socket
`~/.pcscd/pcscd.comm`, the path configured for `PCSCLITE_CSOCK_NAME`. The socket
is created with mode `0600`. For each local PC/SC client, the server dials
`peer:pcsc_port` and pipes that Unix stream to the laptop.

The laptop end belongs to `forward daemon`. It listens at
`listen:pcsc_port`, authorizes the TCP peer, and pipes an accepted stream to
`/run/pcscd/pcscd.comm`. The default `pcsc_port` is 12804; setting it to zero
disables the channel. The laptop socket is mode 0666 on the supported Debian
and Ubuntu deployment, so `forward-daemon` connects without root, a helper, or
group membership. `pcscd` remains responsible for authorizing its client
process.

```
devbox PC/SC client
    │ Unix: ~/.pcscd/pcscd.comm (0600)
    ▼
forward serve
    │ TCP: peer:pcsc_port (default 12804)
    ▼
forward daemon
    │ Unix: /run/pcscd/pcscd.comm (0666)
    ▼
laptop pcscd → smartcard reader
```

The devbox socket is intentionally not configurable. It is a compatibility
contract with the existing PC/SC consumers, not a general-purpose socket
forwarder. The channel replaces the devbox-pair RemoteForward plus `socat`
bridge; it does not reserve or serve the former tunnel port. `pcsc_port` joins
the same effective-configuration service-port set as the URL, callback,
browser-relay, and grant-feed services, so the callback bridge cannot be armed
to dial it. Moving the configured port moves its denial with it.

## Protocol and liveness

PC/SC frames are raw bytes. Neither side adds a request header, status line, or
refusal text. An unauthorized peer, a full connection budget, an unavailable
upstream socket, and a failed dial all get a bare close: injecting diagnostic
bytes would corrupt the client's pcscd protocol stream.

The pipe copies in both directions and propagates EOF by half-closing the
opposite write side. It has no application idle timeout. A PC/SC client may
legitimately wait for a card-status change or a touch for much longer than a
browser protocol's normal idle period. Instead, each TCP leg enables keepalive:
60 seconds before probing, six probes, and ten seconds between probes. That
finds a dead peer in roughly two minutes without terminating a quiet live
session. A new devbox-to-laptop connection has a five-second dial timeout and
is then closed on failure, which lets a sleeping or unreachable laptop fail
promptly instead of queueing a smartcard request indefinitely.

## Security model

The laptop permits a remote TCP connection only when its address equals the
configured peer; loopback is also allowed for local tooling. This identity
check relies on a specific, non-wildcard tailnet listener and the tailnet's
WireGuard identity. It does not authenticate a PC/SC request. The devbox Unix
leg is filesystem-scoped to the same uid through its `0600` socket, while the
laptop delegates authorization to `pcscd` and its polkit check.

The laptop deployment verified that its user-manager process can use
`access_pcsc`: a sessionless `systemd --user` invocation completed a real PC/SC
read. A raw SSH-session process was refused by the same check. No custom polkit
rule is installed. If a supported deployment later rejects the user-manager
process, a narrowly scoped `rules.d` policy is the contingency after verifying
that it grants only the intended daemon identity; it is not a substitute for
that verification and is not part of this channel.

Same-uid isolation is not a boundary. Every devbox agent can run as `ubuntu`,
and a process with ptrace-level access can interfere with another same-uid
process or its socket. The `0600` path prevents accidental use and access by
other uids; it does not create a hostile-local-process boundary. The channel
also does not prove that a reader is present, that a token was touched, or that
a smartcard operation succeeded. It provides the byte path to `pcscd`; the
reader, token policy, and secrets broker enforce the hardware ceremony.

## Supervision

Both deployed user units use `Restart=always` with a two-second restart delay:
`forward-daemon` owns the laptop listener and `forward-serve` owns the devbox
socket. The process treats listener termination and listener-thread panics as
fatal, so a service manager rather than an orphaned helper owns recovery.

The laptop unit is part of `graphical-session.target`. Before GUI login, that
unit and the PC/SC channel are unavailable. This is an operating constraint,
not a fallback condition. A persistent laptop PC/SC bind failure causes the
whole daemon to exit after it has already started its other channels. With the
system manager's default start limit of five attempts in ten seconds, recovery
then stops; the URL channel and browser relay stop with it. This makes a bad
port configuration loud, but it also means a PC/SC misconfiguration is not
isolated to smartcard traffic.

## Failure modes

| Condition | Behaviour |
| --- | --- |
| `pcsc_port` is zero, or the devbox has no peer | The corresponding PC/SC endpoint is not served. No alternate transport is started. |
| A live process owns `~/.pcscd/pcscd.comm` | The devbox refuses to replace it. It does not unlink a socket that accepted a connection. |
| A stale socket is found | The devbox rechecks that it is still an unserved socket before unlinking it. It never unlinks a live socket or a non-socket path. |
| The laptop is unreachable | A new devbox-side client sees its stream close after the five-second dial timeout; existing TCP sessions rely on keepalive or their client timeout. |
| Laptop `pcscd` is unavailable | The laptop closes the authorized TCP stream without writing a protocol response. |
| The PC/SC listener cannot bind persistently | The relevant `forward` process exits for systemd to restart. On the laptop, the bounded restart policy eventually stops the whole daemon and its other channels. |

## Verification

`forward doctor` prints two separate rows. `pcsc channel` is a TCP acceptance
probe for the configured port. `pcsc socket` probes whether
`~/.pcscd/pcscd.comm` accepts a Unix connection on a machine where that path's
parent exists. The second row deliberately does not identify the listener or
assert its relay target, and neither row proves that a reader, token, or
smartcard operation works. End-to-end hardware verification belongs to the
PC/SC consumer and secrets broker.
