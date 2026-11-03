# secretsd

Session-scoped secrets broker with hardware-gated grants.

`secretsd` gives an AI coding agent access to a sensitive secret only after a
human physically approves it with a YubiKey touch — and then keeps that access
available to *that one session* for as long as the session lives, so approval
happens once per session instead of once every few minutes.

- **Presence is proven at grant time**, not continuously. One touch per
  (session, key).
- **Per-session scope.** A grant belongs to the session that asked for it. A
  sibling session in the same process gets its own request, not a free ride.
- **No plaintext at rest.** Values live only in the daemon's locked memory,
  zeroized when the grant dies.
- **Unattended secrets stay unattended.** Keys that agents legitimately need
  overnight never touch this daemon; they keep decrypting with a disk-resident
  key, exactly as before.
- **Every answer names its store.** A status object, an injection and every
  refusal say which tier, which source root and which file or socket answered,
  so a machine running more than one `secrets`-style CLI can never be read as
  one store when another replied.

See [`docs/design.md`](../../docs/design.md) for the current architecture.

## Install

`secrets` is released from [sjawhar/forward](https://github.com/sjawhar/forward/releases)
together with `forward`. One binary is both the daemon (`secrets serve`) and the
client (every other command).

### Prerequisites

- Linux x86_64 with a systemd user session (`systemctl --user` works).
- A YubiKey holding the age identity your human-tier files are encrypted to, and
  `~/.config/sops/age/keys.txt` holding your disk age key (agent tier) and the
  YubiKey's `AGE-PLUGIN-YUBIKEY-...` identity line (human tier): the daemon gives
  sops only that file. After the tools below are installed and the YubiKey is
  reachable, append the identity:

  ```bash
  PCSCLITE_CSOCK_NAME="$HOME/.pcscd/pcscd.comm" age-plugin-yubikey --identity >> "$HOME/.config/sops/age/keys.txt"
  ```

  Omit `PCSCLITE_CSOCK_NAME=...` when the YubiKey is plugged into this machine.
- `pcscd`: local, or the laptop's reached through [`forward`](../../README.md)'s
  PC/SC channel at `~/.pcscd/pcscd.comm`.

Install the tools (Ubuntu 24.04). `sops` resolves its latest release.
`age-plugin-yubikey` is pinned to v0.5.0 because its latest release (v0.5.1) ships
no Linux build.

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl pcscd libpcsclite1

tmp="$(mktemp -d)" && cd "$tmp"
tag="$(curl -fsSLI -o /dev/null -w '%{url_effective}' https://github.com/getsops/sops/releases/latest)"
tag="${tag##*/}"
curl -fsSLO "https://github.com/getsops/sops/releases/download/$tag/sops-$tag.linux.amd64"
curl -fsSLO "https://github.com/getsops/sops/releases/download/$tag/sops-$tag.checksums.txt"
sha256sum -c --ignore-missing "sops-$tag.checksums.txt" &&
  sudo install -m755 "sops-$tag.linux.amd64" /usr/local/bin/sops

curl -fsSLO https://github.com/str4d/age-plugin-yubikey/releases/download/v0.5.0/age-plugin-yubikey_0.5.0-1_amd64.deb
sudo apt-get install -y ./age-plugin-yubikey_0.5.0-1_amd64.deb
cd - >/dev/null && rm -rf "$tmp"
sops --version
command -v age-plugin-yubikey
```

### 1. Download and check the release

Each archive is extracted only when its checksum matches.

```bash
asset=secrets-x86_64-unknown-linux-gnu.tar.gz
base=https://github.com/sjawhar/forward/releases/latest/download
tmp="$(mktemp -d)" && cd "$tmp"
curl -fsSLO "$base/$asset"
curl -fsSLO "$base/SHA256SUMS"
sha256sum -c --ignore-missing SHA256SUMS &&
  tar xzf "$asset" &&
  cd secrets-x86_64-unknown-linux-gnu
```

### 2. Install the binary, units, plugin and skill

Do not link units to a source checkout or to this directory: the installed
configuration must stay valid after it is removed.

```bash
install -Dm755 bin/secrets "$HOME/.local/bin/secrets"
install -Dm644 systemd/secretsd.socket "$HOME/.config/systemd/user/secretsd.socket"
install -Dm644 systemd/secretsd.service "$HOME/.config/systemd/user/secretsd.service"
install -Dm644 share/secretsd/opencode/plugins/secretsd.ts \
    "$HOME/.local/share/secretsd/opencode/plugins/secretsd.ts"
install -Dm644 share/secretsd/skills/using-secrets/SKILL.md \
    "$HOME/.local/share/secretsd/skills/using-secrets/SKILL.md"
cd - >/dev/null && rm -rf "$tmp"
export PATH="$HOME/.local/bin:$PATH"   # add this line to ~/.bashrc too
secrets --version
```

### 3. Declare the source roots

Write `~/.config/secretsd/config.toml` before the daemon starts; without it every
command fails with `secrets: no secretsd config at <path>`. Each
`[source.<name>]` table names one directory, which must exist. Replace the path
below with the directory that holds your secrets files (for example a clone of your
private secrets repository):

```bash
mkdir -p "$HOME/.config/secretsd"
cat > "$HOME/.config/secretsd/config.toml" <<'EOF'
[source.private]
path = "~/src/secrets-private"
EOF
secrets sources
```

Each root may contain `secrets.env` and `secrets.local.env` (agent tier: sops
files the client decrypts with your disk age key, never through the daemon) and
`secrets.human.d/` (human tier: one sops file per key, decrypted by the daemon
only after a YubiKey touch). Add one `[source.<name>]` table per root.
`SECRETSD_CONFIG` overrides the config path. `secrets sources` lists each root and
which of those files it found.

### 4. Write the systemd drop-in

The packaged unit runs `%h/.local/bin/secrets serve` with
`SOPS_AGE_KEY_FILE=%h/.config/sops/age/keys.txt`. The machine-specific settings go
in a drop-in. Use absolute paths: the unit does not see your shell's `PATH`. The
paths below are where the prerequisites step installed `sops` and
`age-plugin-yubikey`; if yours differ, use `command -v sops age-plugin-yubikey`.

```bash
mkdir -p "$HOME/.config/systemd/user/secretsd.service.d"
cat > "$HOME/.config/systemd/user/secretsd.service.d/local.conf" <<'EOF'
[Service]
# sops binary the daemon runs for human-tier decrypts (default: `sops` on PATH).
Environment=SECRETSD_SOPS_BIN=/usr/local/bin/sops
# PATH for the daemon's children: must include the directory holding age-plugin-yubikey.
Environment=PATH=%h/.local/bin:/usr/local/bin:/usr/bin
# pcscd socket. Keep this line when the YubiKey is on your laptop and reached
# through forward; delete it when the YubiKey is plugged into this machine.
Environment=PCSCLITE_CSOCK_NAME=%h/.pcscd/pcscd.comm
# Optional: command that checks a YubiKey is present before a decrypt.
Environment="SECRETSD_YUBIKEY_PROBE_CMD=/usr/bin/age-plugin-yubikey --list"
Environment=SECRETSD_YUBIKEY_PROBE_TIMEOUT_SECS=10
EOF
```

Other settings the daemon reads from its environment:

| Variable | Default | Meaning |
|---|---|---|
| `SECRETSD_CONFIG` | `~/.config/secretsd/config.toml` | Source-root config file |
| `SECRETSD_TOUCH_POLICY` | `cached` | `always` only for a YubiKey whose touch policy is Always; it permits a cooldown under 15 s |
| `SECRETSD_COOLDOWN_SECS` | `16` | Wait between two YubiKey decrypts |
| `SECRETSD_MAX_GRANT_SECS` | `43200` | Grant lifetime when the client asks for none |
| `SECRETSD_MAX_REQUESTED_GRANT_SECS` | `86400` | Cap on a lifetime a client asks for; an empty or invalid value stops the daemon from starting |
| `SECRETSD_REQUEST_TTL_SECS` | `90` | How long a request waits for a touch |
| `SECRETSD_MAX_PENDING` | `3` | Pending requests per session |
| `SECRETSD_MEMLOCK` | `require` | Never set `optional` in production: plaintext could swap |
| `SECRETSD_SOCKET` | `$XDG_RUNTIME_DIR/secretsd.sock` | Listener for a daemon started without the socket unit; not used under socket activation |

### 5. Enable the socket

Enable the **socket**, not the service. The first client connection to
`$XDG_RUNTIME_DIR/secretsd.sock` makes systemd start the daemon.

```bash
systemctl --user daemon-reload
systemctl --user enable --now secretsd.socket
secrets grants                              # first broker request: starts the daemon
systemctl --user is-active secretsd.service
```

If either fails, read `journalctl --user -u secretsd.service -n 50`.

On a machine you drive over ssh, enable lingering as well:

```bash
loginctl enable-linger "$USER"
```

Without it, `logind` removes `$XDG_RUNTIME_DIR` when your last login ends, taking
the socket, the daemon, every grant, and every session token file with it — even
though a tmux server and the agent sessions inside it keep running. Check it with
`loginctl show-user "$USER" -p Linger`.

Grants exist only in daemon memory. Any daemon restart—including a release
upgrade or a drop-in change—removes every grant and requires a fresh YubiKey
touch before a human-tier secret can be used again.

### Plugin version

The plugin speaks a versioned wire protocol to the daemon, so the two must come
from the same release: load the packaged plugin from
`~/.local/share/secretsd/opencode/plugins/secretsd.ts`, or, if OpenCode loads it
from a git pin, use the installed version's tag:
`secretsd@git+https://github.com/sjawhar/forward.git#v<VERSION>` (`secrets --version`
prints it). Restart OpenCode after upgrading the daemon. A stale plugin fails
loudly at the version handshake.

## Why not an off-the-shelf secrets manager?

Vault/OpenBao + GatePlane, Infisical Access Requests, 1Password, and Teleport
all implement request/approve/expire flows, and all were evaluated. None bind a
grant to an *ephemeral agent session*, and none speak "YubiKey touch" as the
approval primitive. Vault additionally needs an unseal key on disk, which
recreates the plaintext-at-rest problem this exists to avoid. Details in
[`docs/design.md`](../../docs/design.md).

## License

Apache-2.0 OR MIT.
