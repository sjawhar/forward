---
name: using-forward
description: Use for anything crossing the laptop-devbox boundary through `forward`. BEFORE any `browser` tool call meant to reach Sami's own Chrome, whenever `browser open` times out, and before asking Sami to connect his browser: the relay is locked per session until `forward browser grant` is approved on his YubiKey, and the grant prints a CDP endpoint for `app.cdp_url` (`app.relay: true` times out even with a live grant). When Sami needs to see a web app or TCP service running on the devbox or inside an agent box: `forward port <ports>...` makes his laptop's localhost:<port> reach this machine's loopback while it runs. Also before a login inside a box whose redirect targets a localhost callback port known in advance. Triggers - browser relay, drive Sami's Chrome, real login, `Browser open timed out`, `forward doctor`, `forward browser grant`, `app.cdp_url`, forward port, port forward, ssh -L, box loopback, show Sami the app, preview a local UI, dev server in a box, laptop localhost, localhost link for Sami.
---

# Using forward

Two procedures: driving Sami's Chrome from the devbox, and showing Sami a local port.

## Driving Sami's Chrome

Sami's Chrome is reachable from this devbox through `forward`, the CLI that owns every
laptop↔devbox channel (URL opening, file preview, YubiKey, audio, and the browser relay).
The relay is **gated**: it stays locked for a session until Sami approves a grant on his
YubiKey. The `browser` tool does not know this. When the relay is locked it waits for an
extension handshake that can never arrive and reports a bare `Browser open timed out after
30000ms`, which reads exactly like "Chrome is not connected". It is not that.

### Not for our own applications

The relay is for third-party sites only a person is logged into. **Our own deployed apps never
need it, and asking Sami for a screenshot of one is a red flag that the wrong path was taken.** The Trajectory Labs Platform signs a headless Chromium
in with a bearer the `tl` CLI mints (`tl platform bearer --as svc-proof --stack production` for a
surface's shape; the operator's own `tl platform bearer --platform <url>` for gated content),
added to `platform.trajectorylabs.com/api/*` requests only. The recipe and its failure modes:
`docs/solutions/2026-09-18-render-production-platform-without-a-human-browser.md` in agent-c.
Reach for a grant only after that path cannot render the surface, and say why in the ask.

### The rule

**Never diagnose a relay timeout by retrying it, and never ask Sami to connect his
browser.** Run `forward doctor` first. It names the state of every channel in one line each:

```
browser relay: locked at 100.100.92.97:12803 (no grant)
browser grant: none for this session — forward browser grant --ttl 30m
```

That pair means: the relay is fine, this session has no grant. Ask for one:

```bash
forward browser grant --ttl 30m
```

It blinks Sami's key and blocks until he taps it (about 20 seconds before it gives up with
`authorization timed out waiting for the YubiKey touch`). On success it prints the
session-local endpoint, e.g. `http://127.0.0.1:38987`. `forward doctor` then reads
`browser grant: live for this session at http://127.0.0.1:38987 (1779s left)`.

**That endpoint is a CDP discovery URL** (`/json/version` answers with Sami's Chrome and a
`webSocketDebuggerUrl`). Hand it to the `browser` tool as `app.cdp_url`; do not use
`app.relay: true`, which targets the OMP relay's own default port and times out even with a
live grant:

```json
{"action": "open", "name": "dash", "app": {"cdp_url": "http://127.0.0.1:38987", "target": "some-tab-substring"}}
```

`app.target` must match an existing tab's URL or title; the error lists every open tab when
it does not. To work in a tab of your own, adopt any tab and `browser.newPage()` inside `run`
rather than navigating Sami's visible tab. If `open` still times out, run `doctor` again, not
`grant` again: the next line down tells you which channel is at fault.

### Etiquette

- **The grant is a YubiKey touch, so it is a wait you never automate.** Ask once. If it
  times out, say so and stop; Sami taps when he is at the laptop. A key blinking for nobody
  is noise. Do not loop, poll, or re-issue on a timer.
- **Grants are per session and expire** (default 30 minutes). A timeout after an earlier
  success means the grant lapsed; `doctor` will say so. Ask for the TTL you actually need.
- **Asking Sami to act is the last step**, after `doctor` names a channel only he can fix
  (the laptop daemon down, the extension badge red). Present what `doctor` printed, not a
  guess.
- **You are inside his real, logged-in browser.** Name a target (`app.target`) or create
  your own tab; never navigate his visible tab uninvited; `close` when done.

### Reading `forward doctor`

| Line | Meaning | Do |
|---|---|---|
| `browser relay: locked … (no grant)` + `browser grant: none` | Normal locked state | `forward browser grant --ttl 30m` |
| `browser grant: live at http://127.0.0.1:<port> (Ns left)` | Ready | `browser open` with `app.cdp_url` = that URL |
| `browser relay:` unreachable / refused | Laptop daemon or Tailscale path down | Tell Sami what the line says |
| `url channel` / `callback bridge` / `pcsc` lines | Other channels; unrelated to browser access | Ignore for this purpose |

### Why this section exists

A coordinator hit `Browser open timed out` four times over fifty minutes, decided Chrome
was not on the relay, and asked Sami to fix his browser — while `forward doctor` would have
printed `no grant` on the first try. The tool's own error names `omp browser-relay
install`, which is the wrong remedy on this machine. The fix was one command and one tap.

## Showing Sami a local port

`forward port <port>...` makes the laptop's `localhost:<port>` reach `127.0.0.1:<port>` (or `[::1]:<port>`) on the machine where the command runs, until the command stops. Inside an agent box that is the box's own loopback. Port numbers stay the same and the bytes are untouched, so a `localhost` origin, a `__Host-` cookie, or the app's own self-signed localhost certificate works unchanged in his browser. Nothing else reaches a box's loopback: `ssh -L`, published docker ports and binding the app to the box's network address are all dead ends.

### Do it

1. Start the app listening on loopback (`127.0.0.1`, `::1`, `localhost`, or all interfaces).
2. Hold every port the browser will touch - the app, plus any login, fixture or API server it redirects to or calls from the page - in one supervised process beside the app:

   ```json
   {"op": "start", "name": "fwd-app", "application": "forward", "args": ["port", "5173", "41575"], "restart": "on-failure", "ready": {"log": "holding until stopped", "timeout": 30}}
   ```

   It prints `forward: laptop localhost:5173 -> 127.0.0.1:5173 here` for each port, then `forward: holding until stopped`. Keep `restart: on-failure`: a restart of the host's `forward serve` ends every hold, and `forward port` exits 1 so its supervisor brings it back.
3. Send Sami the URL the app serves, e.g. `https://localhost:5173/`. Not a `forward url` link: that is the file preview.
4. Stop the process when he is done. Nothing lingers: the devbox side ends with the process, and the laptop frees the port within three minutes.

A port you did not hold is refused, never routed to whatever else uses that number. Two sessions cannot hold one port; the second is refused.

### When it fails

| Output | Meaning | Do |
|---|---|---|
| `no local bridge at /run/user/1000/forward/arm.sock` | The host's `forward serve` is down, or the box does not mount `/run/user/1000/forward` | On the host: `systemctl --user status forward-serve`. In a box: report it; a new box gets the mount |
| `the bridge refused port N: it is privileged, reserved by forward, or unsafe to expose` | Ports below 1024, forward's own 128xx ports, and 2345, 2375, 2376, 3306, 5432, 5678, 6379, 8001, 9229 are never forwarded | Serve the app on another port |
| `port N is already held by another process on this devbox` | Another session holds it | Another port |
| `the laptop refused port N: ...` | Something on Sami's laptop already uses that port | Another port |
| `the laptop daemon at ... did not answer a port hold: it predates forward port` | Sami's laptop runs a `forward` older than 3.4.0 | Tell him that line; the upgrade is his |
| `the local bridge at ... did not answer a hold; it predates forward port` | The host's `forward serve` is older than 3.4.0 | Upgrade forward on the devbox, restart `forward-serve` |
| `the bridge ended the hold on port N` | The host's `forward serve` restarted | Nothing, if it runs under `restart: on-failure` |
| `a laptop connection for port N found nothing listening on 127.0.0.1:N or [::1]:N here` (the browser gets connection refused) | The app is not listening on loopback | Fix the app's bind address; the hold stays |
| `...; the devbox side stays held, retrying every minute` | The laptop is asleep or off the tailnet | Nothing; renewal resumes when it is back |

### Logins inside a box

A CLI login inside a box that sends Sami's browser to `http://localhost:<port>/...` for its callback fails by default: `forward open` arms that port on the host, and the host's loopback is not where the box's callback server listens. When the callback port is known before the login starts, hold it first (`forward port <port>`), then run the login; the redirect then reaches the box. A login that picks a random port at run time cannot be fixed this way.

### Not this section

- A file on the devbox: `forward url <path>`.
- Driving Sami's own Chrome from the devbox: the section above.
