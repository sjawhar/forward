# forward

`forward` connects a laptop to a remote Linux devbox you work on over ssh. It runs as
two daemons:

- **`forward daemon`** on the laptop: opens URLs the devbox sends in the laptop
  browser, fronts the browser relay so devbox agents can drive the laptop's Chrome
  (after a YubiKey-approved grant), and relays the laptop's `pcscd` (YubiKey) and
  PulseAudio to the devbox.
- **`forward serve`** on the devbox: serves devbox files read-only on loopback for
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
- ssh access from the laptop to the devbox.
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

`forward` trusts exactly one peer address per daemon and accepts only literal IP
addresses. Pick one of two transports.

**Tailnet (recommended).** When both machines are on one Tailscale tailnet, each
daemon listens on its own tailnet IP and accepts only the other's. No tunnel is
needed. Use the two configs under [Configure](#configure) with
`listen` = this machine's tailnet IP (`tailscale ip -4`) and `peer` = the other
machine's.

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

The examples use the ssh tunnel's loopback addresses. For the tailnet, put the
tailnet IPs in `listen` and `peer` and add the devbox's tailnet IP and port
(`"100.x.y.z:12802"`) to the laptop's `allow` list in place of `127.0.0.1:12802`.

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

A non-loopback `listen` without a `peer` is refused.

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
forward url /etc/hostname
```

`forward doctor` prints one line per channel (URL channel, file preview, callback
bridge, browser relay, grant and feed, pcsc channel and socket, pulse channel and
socket). Each line that is not healthy
names what is wrong.

## Upgrade

Run the install step again on both machines, then restart the units
(`systemctl --user restart forward-serve` on the devbox,
`systemctl --user restart forward-daemon` on the laptop).
