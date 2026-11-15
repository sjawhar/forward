#!/usr/bin/env bash
# Runs e2e-pane-grant.sh with a broker whose every sops call first waits two
# seconds, as a person reaching for the key does. The pane grant must still
# print its endpoint: the scratch laptop side has to keep its grant feed open
# however long the touch takes. Like that script, it needs a pane below omp and
# systemd-run --user, so it is not wired into CI. Exit 77 means skipped.
set -euo pipefail

if (($# != 2)); then
  printf 'usage: %s <forward binary> <secrets binary>\n' "$0" >&2
  exit 1
fi

here="$(cd -- "$(dirname -- "$0")" && pwd)"
sops_path="$(command -v sops)" || {
  printf 'SKIP: sops is unavailable\n'
  exit 77
}
if [[ "$sops_path" == */.mise/shims/* ]] && command -v mise >/dev/null 2>&1; then
  sops_bin="$(mise which sops)"
else
  sops_bin="$(readlink -f "$sops_path")"
fi
if [[ "$2" == /* ]]; then
  secrets_bin="$2"
else
  secrets_bin="$PWD/$2"
fi
secrets_bin="$(readlink -f "$secrets_bin")"
[[ -x "$secrets_bin" ]] || {
  printf 'the secrets binary must be executable\n' >&2
  exit 1
}

wrappers="$(mktemp -d)"
trap 'rm -r -- "$wrappers"' EXIT
cat > "$wrappers/sops" <<EOF
#!/bin/sh
sleep 2
exec "$sops_bin" "\$@"
EOF
cat > "$wrappers/secrets" <<EOF
#!/bin/sh
SECRETSD_SOPS_BIN="$wrappers/sops" exec "$secrets_bin" "\$@"
EOF
chmod 700 "$wrappers/sops" "$wrappers/secrets"

bash "$here/e2e-pane-grant.sh" "$1" "$wrappers/secrets"
