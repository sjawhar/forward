#!/usr/bin/env bash
# Proves the daemon serves a same-uid client that connects from a sysbox
# container, across these namespace boundaries:
#
#   - the daemon runs socket-activated as a transient systemd *user* unit with
#     the shipped mount protections (ProtectKernelTunables, PrivateTmp), which
#     put it in a private user namespace mapping only its own uid;
#   - the client runs inside a sysbox container, whose uid 1000 is a
#     subordinate uid on the host, so SO_PEERCRED reports it to the daemon as
#     the overflow uid (65534).
#
# The socket node is 0600 (SocketMode, as in the shipped unit), so the kernel
# admits only this uid in the peer's own namespace; the daemon refuses to adopt
# a node in any other shape. The registered session's ancestry check applies
# across the boundary unchanged: the container's pids are host pids and
# /proc/<pid>/stat is world-readable.
#
# Needs: systemd --user, docker with the sysbox-runc runtime. Exits 77 when
# either runtime is absent; the cargo wrapper treats that as "not exercised".
set -euo pipefail

readonly skip_status=77
readonly token='bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
readonly session='e2e-sysbox-peer'
readonly human_key='BOX_KEY'
readonly human_value='value-for-box-peer'
readonly overflow_uid=65534

report() { printf 'e2e-sysbox-peer: %s\n' "$1"; }
fail() { printf 'e2e-sysbox-peer: FAIL: %s\n' "$1" >&2; exit 1; }
skip() { report "SKIP: $1"; exit "$skip_status"; }

if (($# != 1)); then
  printf 'usage: %s PATH/TO/secrets\n' "$0" >&2
  exit 64
fi
secrets_bin="$1"
[[ "$secrets_bin" == /* ]] || secrets_bin="$PWD/$secrets_bin"
readonly secrets_bin
[[ -x "$secrets_bin" ]] || fail "not executable: $secrets_bin"

command -v systemd-run >/dev/null 2>&1 || skip 'systemd-run not available'
systemctl --user is-system-running --quiet 2>/dev/null || [[ "$(systemctl --user is-system-running 2>/dev/null)" == degraded ]] || skip 'no systemd user manager'
command -v docker >/dev/null 2>&1 || skip 'docker not available'
docker info --format '{{json .Runtimes}}' 2>/dev/null | grep -q sysbox-runc || skip 'sysbox-runc runtime not registered'
docker image inspect ubuntu:24.04 >/dev/null 2>&1 || docker pull -q ubuntu:24.04 >/dev/null 2>&1 || skip 'cannot pull ubuntu:24.04'

uid="$(id -u)"
readonly uid
readonly runtime_dir="${XDG_RUNTIME_DIR:-/run/user/$uid}"
[[ -d "$runtime_dir" ]] || skip "no runtime directory $runtime_dir"
# The daemon's socket must sit on a path the container can bind-mount and the
# daemon's private mount namespace still sees: the runtime dir is both.
scratch="$(mktemp -d "$runtime_dir/e2e-sysbox-peer.XXXXXX")"
readonly scratch
readonly unit="e2e-sysbox-peer-$$"
readonly container="e2e-sysbox-peer-$$"
here="$(cd "$(dirname "$0")" && pwd)"
readonly here

cleanup() {
  systemctl --user stop "$unit.socket" "$unit.service" >/dev/null 2>&1 || true
  docker rm -f "$container" >/dev/null 2>&1 || true
  rm -rf "$scratch"
}
trap cleanup EXIT

journal() { journalctl --user -u "$unit.service" --no-pager -o cat 2>/dev/null; }

report '1/6 laying out a source root with one human-tier key and the fake sops fixture'
mkdir -p "$scratch/root/secrets.human.d" "$scratch/bin" "$scratch/home" "$scratch/out"
: > "$scratch/root/secrets.env"
# tests/fixtures/fake-sops-ok in passthrough mode emits each file's own
# plaintext, so the empty agent tier stays empty and the human file yields the
# key. Copied, not linked: the scratch dir is mounted into the container.
printf '%s=%s\n' "$human_key" "$human_value" > "$scratch/root/secrets.human.d/$human_key.env"
cp "$here/fixtures/fake-sops-ok" "$scratch/bin/sops"
chmod +x "$scratch/bin/sops"
cat > "$scratch/config.toml" <<EOF
[source.e2e]
path = "$scratch/root"
EOF
readonly socket="$scratch/secretsd.sock"
readonly token_dir="$scratch/tokens"
mkdir -m 0700 "$token_dir"
printf '%s' "$token" > "$token_dir/$session.token"
chmod 0600 "$token_dir/$session.token"

report '2/6 starting the daemon socket-activated as a mount-protected user unit'
# The shipped unit's shape: systemd owns the 0600 node and hands the daemon the
# listening descriptor; the service itself starts on the first connection.
systemd-run --user --unit "$unit" --quiet --collect \
  --socket-property=ListenStream="$socket" --socket-property=SocketMode=0600 \
  --property=ProtectKernelTunables=yes --property=ProtectControlGroups=yes --property=PrivateTmp=yes \
  --property=NoNewPrivileges=yes --property=RestrictSUIDSGID=yes \
  --setenv=HOME="$scratch/home" --setenv=SECRETSD_MEMLOCK=optional \
  --setenv=SECRETSD_CONFIG="$scratch/config.toml" \
  --setenv=SECRETSD_SOPS_BIN="$scratch/bin/sops" --setenv=FAKE_SOPS_PASSTHROUGH=1 \
  "$secrets_bin" serve
[[ -S "$socket" ]] || fail 'systemd did not create the listening socket'
node="$(stat -c '%a %u' "$socket")"
[[ "$node" == "600 $uid" ]] || fail "socket node is [$node], expected [600 $uid]; the premise under test is gone"
# A host-side control request wakes the service; `grants` needs no scope.
SECRETSD_SOCK="$socket" "$secrets_bin" grants >/dev/null 2>&1 || true
for _ in {1..100}; do
  daemon_pid="$(systemctl --user show -p MainPID --value "$unit.service")"
  [[ "$daemon_pid" != 0 ]] && break
  sleep 0.05
done
[[ "$daemon_pid" != 0 ]] || fail "daemon did not start on the first connection: $(journal | tail -n 5)"
uid_map="$(tr -s ' ' <"/proc/$daemon_pid/uid_map")"
[[ "$uid_map" == " $uid $uid 1" || "$uid_map" == "$uid $uid 1" ]] || fail "daemon is not in a private user namespace (uid_map: $uid_map); the shape under test is gone"
report "   daemon pid $daemon_pid, uid_map [$uid_map], socket node [$node]"

report '3/6 starting a sysbox container that mounts the socket, the token, and the client'
docker run -d --rm --runtime sysbox-runc --name "$container" \
  -v "$socket:$socket" -v "$token_dir:$token_dir:ro" -v "$secrets_bin:/usr/local/bin/secrets:ro" \
  -v "$scratch/config.toml:$scratch/config.toml:ro" -v "$scratch/root:$scratch/root:ro" \
  -v "$scratch/bin:$scratch/bin:ro" -v "$scratch/out:$scratch/out" \
  ubuntu:24.04 sleep 300 >/dev/null
box_pid="$(docker inspect -f '{{.State.Pid}}' "$container")"
box_owner="$(stat -c %u "/proc/$box_pid")"
[[ "$box_owner" != "$uid" ]] || fail "container init runs as the host uid ($box_owner); sysbox did not remap, the shape under test is gone"
report "   container init host pid $box_pid runs as host uid $box_owner"

# in_box [-d] COMMAND...: run COMMAND in the container as the box user with the
# client's environment.
in_box() {
  local detach=()
  [[ "$1" == -d ]] && { detach=(-d); shift; }
  docker exec "${detach[@]}" --user 1000:1000 -e HOME=/tmp -e "PATH=$scratch/bin:/usr/local/bin:/usr/bin:/bin" \
    -e FAKE_SOPS_PASSTHROUGH=1 -e "SECRETSD_SOCK=$socket" -e "SECRETSD_CONFIG=$scratch/config.toml" \
    -e "SECRETSD_SESSION_TOKEN_FILE=$token_dir/$session.token" "$container" "$@"
}

report '4/6 registering from a long-lived process inside the container, then requesting as its child'
# REGISTER binds the token to the registering peer's pid (kernel-pinned), and
# every later request must descend from it - omp's shape: the harness registers
# once and its tool subprocesses are its children. perl (in the base image;
# python is not) is that registrant: it registers, spawns the client beneath
# itself via the shell, writes the client's output, and then stays alive as the
# registered root until released, so the outsider check below runs against a
# live root. The daemon walks host /proc from the client to the registrant
# across the container boundary.
# shellcheck disable=SC2016  # perl source: its $variables are perl's, not the shell's
in_box -d perl -MIO::Socket::UNIX -e '
  my ($sock, $token, $session, $key, $out) = @ARGV;
  my $s = IO::Socket::UNIX->new(Type => SOCK_STREAM, Peer => $sock) or die "connect: $!";
  print $s "REGISTER\ttoken=$token\tsession=$session\tpid=$$\n";
  my $reply = <$s>;
  $reply = "[no reply]\n" unless defined $reply;
  open(my $r, ">", "$out/register") or die; print $r $reply; close $r;
  exit 1 unless $reply eq "OK\n";
  my $value = qx(secrets $key -- sh -c "printf %s \\"\\\$$key\\"" 2>&1);
  open(my $c, ">", "$out/child.tmp") or die; print $c $value; close $c;
  rename "$out/child.tmp", "$out/child";
  sleep 1 until -e "$out/release";
' "$socket" "$token" "$session" "$human_key" "$scratch/out"
for _ in {1..200}; do
  [[ -e "$scratch/out/child" ]] && break
  if [[ -e "$scratch/out/register" && "$(<"$scratch/out/register")" != OK ]]; then
    fail "REGISTER from the container was answered with [$(<"$scratch/out/register")]"
  fi
  sleep 0.05
done
[[ -e "$scratch/out/child" ]] || fail "client inside the container produced no output: $(journal | tail -n 5)"
value="$(<"$scratch/out/child")"
[[ "$value" == "$human_value" ]] || fail "client inside the container got [$value], expected [$human_value]"
registrant_pid="$(docker top "$container" -o pid,comm | awk '$2 == "perl" { print $1 }')"
[[ -n "$registrant_pid" && -d "/proc/$registrant_pid" ]] || fail 'the registrant is not alive after serving its child'

report '5/6 an outsider presenting the same token is refused while the registrant is alive'
# A second docker exec is not a descendant of the registrant, so the token
# alone must not authorize the request.
if in_box secrets "$human_key" -- true >/dev/null 2>"$scratch/outsider.err"; then
  fail 'an outsider with the token was served; the ancestry check no longer holds'
fi
grep -q 'outside that session' "$scratch/outsider.err" || fail "outsider refused for the wrong reason: $(<"$scratch/outsider.err")"
[[ -d "/proc/$registrant_pid" ]] || fail 'the registrant died before the outsider was refused; the refusal proves nothing'
touch "$scratch/out/release"

report "6/6 checking the daemon served the child as the overflow uid ($overflow_uid) and refused no connection"
# The audit line carries the uid the kernel reported for the served peer; a
# child served as this uid, with a verified session scope, is the whole claim.
served="request handled.*key=$human_key.*peer_uid=$overflow_uid.*scope_kind=Some(VerifiedSession).*decision=\"ok\""
for _ in {1..40}; do
  audit="$(journal)"
  grep -q "$served" <<<"$audit" && break
  sleep 0.05
done
grep -q "$served" <<<"$audit" \
  || fail "no audit line shows the child served as the overflow uid: $(grep 'request handled' <<<"$audit" | tail -n 3)"
if grep -q 'rejected for foreign uid' <<<"$audit"; then
  fail "daemon refused a connection: $(grep 'foreign uid' <<<"$audit" | tail -n 1)"
fi
report 'PASS'
