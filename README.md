# forward

`forward` connects a laptop to remote Linux devboxes. It runs as two daemons:

- **`forward daemon`** on the laptop: opens URLs the devbox sends in the laptop
  browser, fronts the browser relay so devbox agents can drive the laptop's Chrome
  (after a YubiKey-approved grant), and relays the laptop's `pcscd` (YubiKey) and
  PulseAudio to the devbox.
- **`forward serve`** on each devbox: serves devbox files read-only for
  preview (markdown is rendered), runs the OAuth callback bridge, and serves the
  YubiKey socket `~/.pcscd/pcscd.comm` for local PC/SC clients such as
  [`secrets`](crates/secrets/README.md) and `age-plugin-yubikey`.

What you get on the devbox:

| Command | What it does |
|---|---|
| `forward open <url>` | Opens the URL in the laptop browser. A browser login whose redirect goes to `http://localhost:<port>/…` works without a device-code flow: the callback port is carried back to the devbox for the lease time. |
| `forward url <path>` | Prints (and copies with OSC 52) a laptop-clickable preview URL for a devbox file. |
| `forward port <port>…` | Makes the laptop's `localhost:<port>` reach this machine's loopback until the command stops. |
| `forward browser grant --ttl 30m` | Asks for a YubiKey touch, then prints a CDP endpoint for the laptop's Chrome. |
| `forward doctor` | Prints one health line per channel. |

Architecture and threat model: [`docs/design.md`](docs/design.md) and
[`docs/design/`](docs/design/). Agent usage: [`skills/using-forward/SKILL.md`](skills/using-forward/SKILL.md).

The same release ships the `secrets` broker; its guide is
[`crates/secrets/README.md`](crates/secrets/README.md).

## Requirements

- A Linux devbox and a Linux laptop (releases ship Linux binaries only: x86_64
  and aarch64, statically linked).
- Tailscale connectivity between the laptop and devboxes, or ssh access for a
  single-peer tunnel.
- A systemd user session on both machines.
- `curl` (`sudo apt-get install -y ca-certificates curl`).
- For the YubiKey channel: `pcscd` running on the laptop (`sudo apt-get install -y pcscd`).
- For browser grants (`forward browser grant`): the omp browser relay running on the
  laptop. Without it, `forward doctor` reports the browser relay rows as failing;
  every other channel works.

## Install the binary (both machines)

Run this on the devbox and on the laptop. It downloads the latest release, checks
its SHA256 sum and installs `forward` to `~/.local/bin`.

```bash
arch="$(uname -m)"   # x86_64 or aarch64
asset="forward-${arch}-unknown-linux-musl.tar.gz"
base="https://github.com/sjawhar/forward/releases/latest/download"
tmp="$(mktemp -d)" && cd "$tmp"
curl -fsSLO "$base/$asset"
curl -fsSLO "$base/SHA256SUMS"
sha256sum -c --ignore-missing SHA256SUMS &&
  tar xzf "$asset" &&
  install -Dm755 forward "$HOME/.local/bin/forward"
cd - >/dev/null && rm -rf "$tmp"
export PATH="$HOME/.local/bin:$PATH"   # add this line to ~/.bashrc too
forward --version
```

The archive is extracted only when its checksum matches.

## Connect the two machines

`forward` accepts only literal peer IP addresses. The laptop daemon can trust a
list of devboxes; each devbox trusts the laptop. Sources outside that list are
refused before the daemon reads a request.

**Tailnet (recommended).** Each daemon listens on its own Tailscale IP. Configure
the laptop with `peers = ["100.x.y.z", "100.a.b.c"]`, and each devbox with
`peer = "<laptop-ip>"`. All devboxes use the default ports. Callbacks return to
the devbox that sent the request, and each peer's preview is allowed automatically.
No tunnel is needed. Resolve names when writing the config, not at runtime.

**ssh tunnel (single-user devbox only).** Through a tunnel, sshd makes each far-end
connection from `127.0.0.1`, so `peer` is `127.0.0.1` and every local process on
either machine looks like the peer. On a devbox other people log in to, they could
read your files through the preview and take over your browser grants. Use the tunnel
only on a devbox where you are the only user.

### ssh tunnel

The tunnel carries every channel over one ssh connection, with both
daemons on loopback. Each port is forwarded to the same port on the other side:

| Port | Listens on | Channel |
|---|---|---|
| 12800 | laptop | URL channel (`forward open`) |
| 12803 | laptop | browser relay |
| 12804 | laptop | PC/SC (YubiKey) |
| 12806 | laptop | PulseAudio |
| 12801 | devbox | OAuth callback bridge |
| 12802 | devbox | file preview |
| 12805 | devbox | browser grant feed |

Add a host entry to the laptop's `~/.ssh/config`. Replace `devbox.example.com` and
`you` with your devbox's address and user:

```sshconfig
Host devbox-tunnel
    HostName devbox.example.com
    User you
    # laptop listeners, reached from the devbox
    RemoteForward 127.0.0.1:12800 127.0.0.1:12800
    RemoteForward 127.0.0.1:12803 127.0.0.1:12803
    RemoteForward 127.0.0.1:12804 127.0.0.1:12804
    RemoteForward 127.0.0.1:12806 127.0.0.1:12806
    # devbox listeners, reached from the laptop
    LocalForward 127.0.0.1:12801 127.0.0.1:12801
    LocalForward 127.0.0.1:12802 127.0.0.1:12802
    LocalForward 127.0.0.1:12805 127.0.0.1:12805
    ExitOnForwardFailure yes
    ServerAliveInterval 15
    ServerAliveCountMax 3
    ConnectTimeout 30
```

Use a key without a passphrase prompt for this host (`IdentityFile`), so the
tunnel can reconnect unattended.

## Configure

Both daemons read `~/.config/forward/config.toml` (or `--config <path>`). A missing
file means the defaults: `listen = "127.0.0.1"`, no peer, the ports above,
`mode = "allowlist"`, `opener = ["xdg-open"]`.

The examples below show the single-peer ssh tunnel. For a single-peer tailnet
pair, replace `listen` with this machine's tailnet IP, `peer` with the other
machine's IP, and the laptop's `127.0.0.1:12802` allow entry with
`<devbox-tailnet-ip>:12802`.
On a laptop serving several devboxes, replace `peer` with `peers`:

```toml
listen = "100.64.0.1"   # laptop's own address
peers = ["100.64.0.2", "100.64.0.3"]
```

Keep the URL policy settings below. In `peers` mode only, preview permission is
derived from each request's source, so no per-devbox preview entries are needed.

Devbox, `~/.config/forward/config.toml`:

```toml
listen = "127.0.0.1"
peer = "127.0.0.1"
```

Laptop, `~/.config/forward/config.toml`:

```toml
listen = "127.0.0.1"
peer = "127.0.0.1"

# Hosts in `allow` open directly. Every other URL is copied to the clipboard
# (with a notification) and does not open by itself.
mode = "allowlist"
# Use the full path: a bare `xdg-open` that resolves to a shim calling
# `forward open` makes a loop.
opener = ["/usr/bin/xdg-open"]
clipboard = ["wl-copy"]          # or ["xclip", "-selection", "clipboard"] on X11
allow = [
  "127.0.0.1:12802",             # the devbox file preview
  "github.com",
  "accounts.google.com",
]
```

A non-loopback `listen` without `peer` or a nonempty `peers` list is refused.
The existing single `peer` setting remains valid, including custom ports used by
ssh pairs. `forward doctor` reports each peer separately for a multi-peer config.

Use either `peer` or `peers`, not both; an empty `peers` list is refused. In list
mode even loopback sources must be listed. Duplicate IPs share one grant-feed
client. Each browser grant belongs to its source peer, and a peer's preview is
automatically allowed only for requests from that same peer.

`peers` is a laptop-daemon setting. `forward serve` rejects it before starting
any VM service; each VM uses a single `peer` naming the laptop. The list-mode
pre-read admission rule applies to the laptop's URL, browser, PC/SC and audio
listeners. VM filesystem previews still use the single-peer admission rule.

A laptop localhost port can serve only one VM at a time. Another VM's hold or
OAuth callback request for that live port is refused rather than rerouted.
Multi-peer OAuth requests are also refused if a callback port cannot be served.

## Migrate existing dotfiles pairs

This procedure uses the generated configs and units in Sami's dotfiles. Do not
start it until the multi-peer release is available through the pinned installer
and the reviewed dotfiles change has been published. Keep existing pair files
and units until step 4.

1. Release `forward` with `peers` support and update the installed version on
   both sides. Single-`peer` configs keep working during the rollout.
2. On the laptop, update the published dotfiles, then run this one command:

   ```bash
   bash ~/.dotfiles/installers/forward.sh daemon
   ```

   The installer resolves the committed VM-name list with `tailscale ip -4`,
   writes literal peer IPs and enables one `forward-daemon.service`. It disables
   the old per-pair daemon and tunnel instances, but retains their files.
3. On each listed VM, run `bash ~/.dotfiles/installers/forward.sh serve`, then
   `forward doctor`. The generated config listens on that VM's tailnet IP and
   trusts the laptop. Check both peers together before removing the old path.
4. Remove the per-pair TOMLs, `forward-tunnel@.service`, installer tunnel branch,
   ssh tunnel host blocks, sshd's port-443 drop-in and the dedicated tunnel key's
   `authorized_keys` entry. Remove the old per-pair daemon units and drop-ins too.
   This cleanup is a separate migration step, not part of generating the config.
5. Optionally restrict tailnet TCP ports 12800–12806 to the laptop and these VMs
   with a Tailscale ACL. Source-IP authorization is still enforced by `forward`.

## Run under systemd

Devbox, `~/.config/systemd/user/forward-serve.service`:

```ini
[Unit]
Description=forward file server and callback bridge (devbox side)

[Service]
ExecStart=%h/.local/bin/forward serve
Restart=always
RestartSec=2

[Install]
WantedBy=default.target
```

```bash
systemctl --user daemon-reload
systemctl --user enable --now forward-serve.service
loginctl enable-linger "$USER"   # keep it running after you log out
```

Laptop, `~/.config/systemd/user/forward-daemon.service` and, for the ssh tunnel only,
`~/.config/systemd/user/forward-tunnel.service`:

```ini
[Unit]
Description=forward opener daemon (laptop side)
# It opens the browser and uses the clipboard, so it needs the graphical session.
After=graphical-session.target
PartOf=graphical-session.target

[Service]
ExecStart=%h/.local/bin/forward daemon
Restart=always
RestartSec=2

[Install]
WantedBy=graphical-session.target
```

```ini
[Unit]
Description=ssh tunnel carrying forward's channels to the devbox
After=graphical-session.target
PartOf=graphical-session.target

[Service]
ExecStart=/usr/bin/ssh -N devbox-tunnel
Restart=always
RestartSec=10

[Install]
WantedBy=graphical-session.target
```

```bash
systemctl --user daemon-reload
systemctl --user enable --now forward-daemon.service
systemctl --user enable --now forward-tunnel.service   # ssh tunnel only
```

Run `forward daemon` as this user unit, not from an ssh shell: Ubuntu's polkit
policy refuses `pcscd` access to ssh-session processes but permits `systemd --user`
services.

## Check it

On the devbox:

```bash
forward doctor
forward open https://github.com
forward url ./README.md
```

`forward doctor` prints one line per channel (URL channel, file preview, callback
bridge, browser relay, grant and feed, pcsc channel and socket, pulse channel and
socket). Each unhealthy line says what is wrong. The preview probe requests
`/.well-known/forward/health` and checks the exact fixed body from `forward serve`;
no host file is needed. Any loopback client can read this constant body regardless
of Host. It reads no file or secret and does not open a URL. Ordinary previews on
a tailnet listener still require the configured laptop peer and correct Host.

## Upgrade

Upgrade the VMs before or together with the laptop: a new doctor expects the
synthetic health response, which older serve versions do not provide. Run the
install step again on each machine, then restart `forward-serve` on each VM and
`forward-daemon` on the laptop.
