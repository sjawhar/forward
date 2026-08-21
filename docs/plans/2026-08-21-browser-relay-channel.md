# Browser relay channel — implementation record

Status: shipped
Design: `docs/design/2026-08-21-browser-relay-channel.md`
Date: 2026-08-21

## Shipped topology

The laptop runs the loopback-only CDP facade at `127.0.0.1:9224`. `forward
daemon` accepts the devbox at the laptop tailnet address on port `12803` and
proxies the byte stream to that facade. The devbox browser tool opts into the
remote endpoint with:

```text
browser.relayUrl = "http://100.100.92.97:12803"
app.relay: true
```

`/json/version` derives the advertised CDP WebSocket authority from a validated
`Host` header, so a browser client reached through `forward` dials the same
relay endpoint rather than its own loopback address.

## Shipped security boundary

There is no tab-group access control. The `omp` tab group does not restrict
target enumeration, attachment, navigation, or cookie access. Anything that
gets through `forward`'s per-host peer check has full access to every tab in
the Chrome profile, including existing logged-in tabs.

The channel is bounded only by this peer check:

- the facade and extension `/ext` endpoint remain loopback-only on the laptop;
- `forward` accepts loopback and its one configured literal `peer` address;
- unauthorised sources receive `REFUSED PEER` before an upstream connection is
  made;
- authorisation identifies a host, not an individual process.

This is the weaker, actual security model. The debugging infobar is useful
human-visible evidence of attachment, but it does not limit an authorised
devbox process.

## Transport and doctor behaviour

`relay_port` defaults to `12803`; `relay_port = 0` explicitly disables the
browser listener. The deployed devbox `config-serve.toml` omits this field so
it remains compatible with older `forward` binaries, and `forward serve` never
starts the browser listener.

Doctor does not treat that default as a role indicator. It probes the configured
local relay address first:

1. A routable local `REFUSED PEER` proves the laptop listener is running, then
   doctor checks the loopback CDP facade.
2. If the local listener is absent, doctor probes the configured peer at the
   well-known relay port. This is the devbox path and is exercised with a
   config that omits `relay_port`.
3. If both endpoints fail, doctor reports both failures instead of selecting a
   role from a defaulted configuration value.

## Credential capture

`browser-capture` selects a matching profile tab and cookie without printing the
cookie value. It passes that value on stdin to:

```text
secrets edit-human KEY [--source NAME]
```

When standard input is not a terminal, `edit-human` uses its non-interactive
human-secret write path. It disables core dumps before reading, accepts one
single-line value, encrypts it to the human recipients, and reports only the
created or rotated path. Writing needs no YubiKey touch; subsequent
human-secret reads retain their normal touch requirement.

## Superseded tab-group ACL work

The extension-enforced `omp` tab-group ACL plan was removed before shipment.
The proposed rules that dragging a tab out revoked access and that an agent
could not add an existing tab to scope do not apply. The historical proposal is
preserved by the `browser-relay-group-acl-archive` bookmark in the oh-my-pi
workspace; it must not be used as an operator or security reference.

## Verification

The maintained `forward` verification for this work is:

```text
cargo test
cargo fmt
bash scripts/check-source-line-limit.sh
```

The doctor regression test loads a devbox-shaped TOML with no `relay_port`,
observes the defaulted port, and proves doctor continues from its unavailable
local listener to the laptop peer's relay endpoint.
