# Browser relay channel

Status: shipped
Date: 2026-08-21
Scope: `forward` transports the relay, `sjawhar/oh-my-pi` provides the loopback
CDP facade and remote discovery URL, and `~/.dotfiles` plus `sjawhar/secretsd`
capture selected browser cookies into the human secret store.

## What this gets you

An agent on the devbox can use the laptop's everyday Chrome profile through the
browser relay. That makes a signed-in session, device check, or portal with no
API automatable without copying a value through an agent transcript or the
clipboard. When a workflow needs a browser cookie rather than an interactive
browser session, `browser-capture` writes it to the human secret store through
`secrets edit-human` on stdin.

## Security model

The browser relay has **no tab scoping**. A Chrome tab group named `omp` is not
an access-control list and changing group membership has no effect on relay
access. Any process that passes `forward`'s peer check can drive every tab in
the Chrome profile, including existing tabs and their logged-in sessions. It
can also navigate those tabs freely, so controlling one session is not a
meaningful reduction in authority.

The only network boundary is per-host peer authorisation:

- The CDP facade listens on laptop loopback at `127.0.0.1:9224`.
- `forward daemon` exposes `:12803` on the laptop's configured tailnet
  `listen` address.
- `forward` accepts loopback and exactly the configured `peer` address; it
  refuses every other source before reading payload bytes or connecting to the
  loopback relay.

This identifies a machine, not a process. Every process on the authorised
devbox host has the same full-profile access. The browser's debugging infobar
remains the human-visible indication that a tab is attached; it is not an
access control.

| Threat | Mitigation or accepted risk |
|---|---|
| Another tailnet device drives Chrome | The `forward` peer check admits only one literal counterpart address. |
| A web page reaches the relay | `/cdp` rejects `Origin`-bearing upgrades, and the CDP server is loopback-only. |
| An authorised devbox process drives an existing tab | Accepted risk: the relay grants full-profile access, with no tab or process ACL. |
| A captured cookie reaches an agent transcript | `browser-capture` does not print values and pipes them only to `secrets edit-human`. |
| A cookie appears in argv or a temporary file | `edit-human` receives the value on stdin and encrypts it without a plaintext staging file. |

## Architecture

| Channel | Direction | Port | Status |
|---|---|---:|---|
| PC/SC socket | laptop → devbox | 12799 | unchanged |
| URL channel | devbox → laptop | 12800 | unchanged |
| Callback bridge | laptop → devbox | 12801 | unchanged |
| File preview | laptop → devbox | 12802 | unchanged |
| Browser relay | devbox → laptop | 12803 | shipped |

```text
devbox agent                         laptop
  browser tool                          forward daemon
    app.relay: true                       :12803, peer-checked
    browser.relayUrl ───────────────────→ │
    http://100.100.92.97:12803            ↓
                                      127.0.0.1:9224 omp browser relay
                                                   ↕ /ext on loopback
                                      Chrome extension → every profile tab
```

The relay is a byte proxy, not an HTTP or CDP parser. Its fixed upstream is
`127.0.0.1:9224`; after authorising a connection, `forward` pipes the stream in
both directions. Connection limits, idle timeouts, and the bounded refusal
drain protect the proxy without interpreting browser traffic.

The relay's `/cdp` and `/json/*` endpoints are unauthenticated. They never
leave loopback directly. A remote client reaches them only through the
peer-authorised `forward` channel.

## Configuration and health checks

`Config.relay_port` defaults to `12803`. `relay_port = 0` explicitly disables
the laptop relay listener, but the deployed devbox `config-serve.toml` omits
the field while the rollout remains compatible with older binaries. `forward
serve` does not spawn the browser listener.

`forward doctor` does not infer its role from `relay_port`. It first probes the
configured local relay address:

1. A `REFUSED PEER` response from a routable local listener proves the laptop
   listener is up, so doctor checks the loopback CDP relay at `127.0.0.1:9224`.
2. When that local listener is absent, doctor probes the configured peer at the
   well-known `12803` endpoint. This is the devbox path and works when
   `relay_port` is absent from `config-serve.toml`.
3. If neither endpoint answers, doctor reports both failed probes rather than
   treating a defaulted configuration value as a role signal.

This keeps the health check correct for the deployed devbox configuration and
still distinguishes a missing laptop CDP relay from a failed browser channel.

## Remote discovery URL

The relay extension must connect to a server on the same machine as Chrome, but
a remote browser client must dial the `forward` endpoint rather than its own
loopback. `/json/version` therefore builds `webSocketDebuggerUrl` from a
validated request `Host` header and falls back to the loopback authority when
that header is absent or invalid. The change affects only the advertised URL;
the `/cdp` `Origin` check and the `forward` peer check remain in force.

## Credential capture

`browser-capture --domain DOMAIN --cookie NAME --secret KEY [--tab SUBSTRING]`
connects to the relay, selects a profile tab by domain and optional title
substring, and extracts one exact cookie match. It never prints the value.

The final write is equivalent to:

```text
cookie value → stdin → secrets edit-human KEY [--source NAME]
```

`secrets edit-human` detects non-terminal stdin and uses its non-interactive
human-secret write path. It reads a single-line value, disables core dumps
before reading it, encrypts to the human recipients, and reports only the
created or rotated path. Storing requires no YubiKey touch; reading the
human-tier secret keeps its normal touch-gated behaviour.

## Superseded tab-group ACL proposal

The proposed extension-enforced `omp` tab-group ACL, including immediate
revocation when a tab left the group and the restriction against agents adding
existing tabs, is superseded. It was deliberately removed rather than shipped.
The archived proposal is retained at the `browser-relay-group-acl-archive`
bookmark in the oh-my-pi workspace; it is historical design material, not the
security model of this relay.

## Failure modes

| Situation | Behaviour |
|---|---|
| Laptop is off or the channel is unavailable | The browser tool reports an unreachable relay endpoint. |
| `forward daemon` is not listening | Doctor reports the local relay listener failure. |
| `omp browser-relay` is down | The channel accepts then reports that the loopback relay process is unavailable. |
| Extension is disconnected | `/json/version` returns 503 and doctor reports that the relay is up but the extension is not connected. |
| A caller is not the configured peer | `forward` returns `REFUSED PEER` without dialing the upstream relay. |
| Several profile tabs match a capture request | `browser-capture` asks for `--tab` rather than selecting one implicitly. |

## Verification

The transport is covered by `forward` listener and doctor tests, including a
configuration that omits `relay_port` and exercises the devbox peer probe.
The remote discovery endpoint has contract tests for validated Host reflection
and loopback fallback. Credential capture is verified through the non-terminal
`edit-human` stdin path; the value is absent from status output and error
output.
