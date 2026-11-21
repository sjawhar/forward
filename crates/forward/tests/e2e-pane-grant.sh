#!/usr/bin/env bash
# This end-to-end proof needs a pane below omp and a systemd user manager, so it
# is intentionally not wired into CI. It shows a pane grant through scratch
# secretsd and forward processes, with the scratch secretsd run as a transient
# user unit under the sandbox settings of systemd/secretsd.service. It does not
# show a YubiKey or Chrome. Exit 77 means skipped.
set -euo pipefail

readonly skip_status=77
readonly no_scope_refusal='forward: grant refused before any touch: no omp process runs above this command, and it has no session token and no terminal; run it from an omp session or an interactive terminal'

scratch=''
failed=false
live_sockets_verified=false
scratch_processes_verified=false
test_units_verified=false
started_units=()
still_loaded_units=()
declare -A process_pid=()
declare -A process_start=()

pass() {
  printf 'PASS: %s\n' "$1"
}

fail() {
  failed=true
  printf 'FAIL: %s\n' "$1" >&2
  exit 1
}

skip() {
  printf 'SKIP: %s\n' "$1"
  exit "$skip_status"
}

# shellcheck disable=SC2317,SC2329
on_error() {
  local status="$1" line="$2"
  if [[ "$failed" != true ]]; then
    failed=true
    printf 'FAIL: unexpected command failure at line %s\n' "$line" >&2
  fi
  exit "$status"
}

stat_tail() {
  local record
  record="$(cat "/proc/$1/stat" 2>/dev/null)" || return 1
  printf '%s\n' "${record##*) }"
}

proc_parent() {
  local -a fields
  read -r -a fields <<< "$(stat_tail "$1")" || return 1
  (( ${#fields[@]} >= 2 )) || return 1
  [[ "${fields[1]}" =~ ^[0-9]+$ ]] || return 1
  printf '%s\n' "${fields[1]}"
}

proc_start() {
  local -a fields
  read -r -a fields <<< "$(stat_tail "$1")" || return 1
  (( ${#fields[@]} >= 20 )) || return 1
  [[ "${fields[19]}" =~ ^[0-9]+$ ]] || return 1
  printf '%s\n' "${fields[19]}"
}

nearest_omp_ancestor() {
  local pid next record name hop
  pid="$(proc_parent "$1")" || return 1
  for ((hop = 0; hop < 12; hop++)); do
    [[ "$pid" =~ ^[0-9]+$ ]] && ((pid > 1)) || return 1
    # A process is omp when the name in its stat, the text between the first
    # ( and the last ), is exactly omp: the rule of forward's own walk and of
    # the broker's. Without a readable stat there is neither a name nor a
    # parent pid to carry on to.
    record="$(cat "/proc/$pid/stat" 2>/dev/null)" || return 1
    [[ "$record" == *'('*')'* ]] || return 1
    name="${record#*\(}"
    name="${name%\)*}"
    if [[ "$name" == omp ]]; then
      printf '%s\n' "$pid"
      return 0
    fi
    next="$(proc_parent "$pid")" || return 1
    [[ "$next" != "$pid" ]] || return 1
    pid="$next"
  done
  return 1
}

track_process() {
  local name="$1" pid="$2" start
  start="$(proc_start "$pid")" || fail "$name did not start a readable process"
  process_pid["$name"]="$pid"
  process_start["$name"]="$start"
}

tracked_process_is_alive() {
  local name pid expected current
  name="$1"
  pid="${process_pid[$name]:-}"
  expected="${process_start[$name]:-}"
  [[ -n "$pid" && -n "$expected" ]] || return 1
  current="$(proc_start "$pid")" || return 1
  [[ "$current" == "$expected" ]]
}

stop_tracked_process() {
  local name pid expected current attempt
  name="$1"
  pid="${process_pid[$name]:-}"
  expected="${process_start[$name]:-}"
  [[ -n "$pid" && -n "$expected" ]] || return 0
  current="$(proc_start "$pid")" || return 0
  [[ "$current" == "$expected" ]] || return 0
  kill "$pid" 2>/dev/null || return 0
  if [[ "$name" != relay ]]; then
    wait "$pid" 2>/dev/null || true
  fi
  for ((attempt = 0; attempt < 100; attempt++)); do
    if ! tracked_process_is_alive "$name"; then
      return 0
    fi
    sleep 0.05
  done
  current="$(proc_start "$pid")" || return 0
  [[ "$current" == "$expected" ]] || return 0
  kill -KILL "$pid" 2>/dev/null || true
  for ((attempt = 0; attempt < 100; attempt++)); do
    if ! tracked_process_is_alive "$name"; then
      return 0
    fi
    sleep 0.05
  done
  return 1
}

# Prints the uid_map of a process with its whitespace collapsed. The broker
# makes itself not dumpable, so its ns/user link is unreadable from here, but
# its uid_map stays readable.
uid_map_of() {
  local map
  local -a fields
  map="$(cat "/proc/$1/uid_map" 2>/dev/null)" || return 1
  read -r -d '' -a fields <<< "$map" || true
  (( ${#fields[@]} >= 3 )) || return 1
  printf '%s\n' "${fields[*]}"
}

# Prints each given unit that systemctl still lists; an error counts as listed.
units_still_loaded() {
  local unit listed
  for unit in "$@"; do
    if ! listed="$(systemctl --user list-units --all --no-legend "$unit" 2>&1)" || [[ -n "$listed" ]]; then
      printf '%s\n' "$unit"
    fi
  done
}

# Polls for up to 5 s until systemctl lists none of the given units, and leaves
# the units it still lists in still_loaded_units.
wait_for_units_unloaded() {
  local attempt
  for ((attempt = 0; attempt < 100; attempt++)); do
    mapfile -t still_loaded_units < <(units_still_loaded "$@")
    (( ${#still_loaded_units[@]} == 0 )) && return 0
    sleep 0.05
  done
  return 1
}

# shellcheck disable=SC2317,SC2329
cleanup() {
  local status=$? unit
  trap - ERR EXIT
  trap '' INT TERM HUP
  stop_tracked_process stub || true
  stop_tracked_process grant || true
  stop_tracked_process relay || true
  stop_tracked_process forward || true
  if (( ${#started_units[@]} > 0 )); then
    for unit in "${started_units[@]}"; do
      systemctl --user stop "$unit" >/dev/null 2>&1 || true
    done
    if ! wait_for_units_unloaded "${started_units[@]}"; then
      printf 'FAIL: a test unit stays loaded: %s\n' "${still_loaded_units[*]}" >&2
      status=1
    elif [[ "$test_units_verified" != true ]]; then
      pass "no test unit stays loaded: ${started_units[*]}"
    fi
  fi
  if [[ -n "$scratch" && -d "$scratch" && -f "$scratch/live-sockets.before" ]]; then
    if ! capture_live_socket_inodes "$scratch/live-sockets.after"; then
      printf 'FAIL: could not record live socket inodes during cleanup\n' >&2
      status=1
    elif ! cmp -s "$scratch/live-sockets.before" "$scratch/live-sockets.after"; then
      printf 'FAIL: live socket inodes changed during the scratch run\n' >&2
      status=1
    elif [[ "$live_sockets_verified" != true ]]; then
      pass 'live socket inodes are unchanged'
    fi
    if pgrep -f -- "$scratch" >/dev/null 2>&1; then
      printf 'FAIL: a scratch process remained after shutdown\n' >&2
      status=1
    elif [[ "$scratch_processes_verified" != true ]]; then
      pass 'no scratch process remains running'
    fi
  fi
  if ((status != 0)); then
    if (( ${#started_units[@]} > 0 )); then
      printf 'test units this run started: %s\n' "${started_units[*]}" >&2 || true
    fi
    if [[ -n "$scratch" && -f "$scratch/broker.log" ]]; then
      printf 'scratch broker log:\n' >&2 || true
      cat -- "$scratch/broker.log" >&2 || true
    fi
  fi
  if [[ -n "$scratch" && -d "$scratch" ]]; then
    rm -r -- "$scratch" || true
  fi
  exit "$status"
}

capture_live_socket_inodes() {
  local output="$1" socket
  : > "$output"
  if [[ -S "$live_runtime/secretsd.sock" ]]; then
    stat -c '%n %i' "$live_runtime/secretsd.sock" >> "$output"
  fi
  if [[ -d "$live_runtime/forward" ]]; then
    while IFS= read -r -d '' socket; do
      stat -c '%n %i' "$socket" >> "$output"
    done < <(find "$live_runtime/forward" -type s -print0)
  fi
}

wait_for_socket() {
  local name="$1" socket="$2" attempt
  for ((attempt = 0; attempt < 200; attempt++)); do
    [[ -S "$socket" ]] && return 0
    tracked_process_is_alive "$name" || return 1
    sleep 0.05
  done
  return 1
}

wait_for_log_line() {
  local name="$1" log="$2" line="$3" attempt
  for ((attempt = 0; attempt < 200; attempt++)); do
    grep -F --quiet "$line" "$log" && return 0
    tracked_process_is_alive "$name" || return 1
    sleep 0.05
  done
  return 1
}

broker_hello() {
  env -i \
    PATH="$scratch_path" \
    HOME="$scratch/home" \
    XDG_RUNTIME_DIR="$scratch/runtime" \
    XDG_CONFIG_HOME="$scratch/config" \
    "$python_bin" - "$broker_socket" <<'PY'
import socket
import sys

sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.settimeout(5)
sock.connect(sys.argv[1])
sock.sendall(b"HELLO\tversion=4\n")
reply = sock.makefile("rb").readline()
if not reply.startswith(b"OK\tversion=4 "):
    raise SystemExit(f"unexpected HELLO response: {reply!r}")
PY
}

allocate_ports() {
  env -i \
    PATH="$scratch_path" \
    HOME="$scratch/home" \
    XDG_RUNTIME_DIR="$scratch/runtime" \
    XDG_CONFIG_HOME="$scratch/config" \
    "$python_bin" - <<'PY'
import socket

sockets = []
for _ in range(4):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    sockets.append(sock)
print(" ".join(str(sock.getsockname()[1]) for sock in sockets))
PY
}

http_json_version() {
  env -i \
    PATH="$scratch_path" \
    HOME="$scratch/home" \
    XDG_RUNTIME_DIR="$scratch/runtime" \
    XDG_CONFIG_HOME="$scratch/config" \
    "$python_bin" - "$1" <<'PY'
import socket
import sys

sock = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=5)
sock.sendall(b"GET /json/version HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
reply = bytearray()
while True:
    chunk = sock.recv(4096)
    if not chunk:
        break
    reply.extend(chunk)
head, separator, body = bytes(reply).partition(b"\r\n\r\n")
if not separator or not head.startswith(b"HTTP/1.1 200 OK") or b'"Browser":"scratch"' not in body:
    raise SystemExit("scratch laptop did not answer /json/version")
sys.stdout.buffer.write(body)
PY
}

endpoint_stopped_answering() {
  env -i \
    PATH="$scratch_path" \
    HOME="$scratch/home" \
    XDG_RUNTIME_DIR="$scratch/runtime" \
    XDG_CONFIG_HOME="$scratch/config" \
    "$python_bin" - "$1" <<'PY'
import socket
import sys

try:
    sock = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=1)
    sock.sendall(b"GET /json/version HTTP/1.1\r\nHost: localhost\r\n\r\n")
    sock.settimeout(1)
    if sock.recv(1):
        raise SystemExit("relay endpoint still answered")
except OSError:
    pass
PY
}

find_relay_for_endpoint() {
  local process pid arguments start
  for process in /proc/[0-9]*; do
    [[ -r "$process/cmdline" ]] || continue
    if ! arguments="$( { tr '\0' ' ' < "$process/cmdline"; } 2>/dev/null)"; then
      continue
    fi
    [[ "$arguments" == "$forward_bin browser relay --anchor-pid $omp_pid --anchor-start $omp_start "* ]] ||
      continue
    pid="${process##*/}"
    start="$(proc_start "$pid")" || continue
    ((start >= process_start[grant])) || continue
    printf '%s\n' "$pid"
  done
}

run_as_manager() {
  local unit="$1"
  shift
  systemd-run --user --pipe --wait --quiet --collect --unit "$unit" -p RuntimeMaxSec=120 \
    --setenv=PATH="$scratch_path" \
    --setenv=HOME="$scratch/home" \
    --setenv=XDG_RUNTIME_DIR="$scratch/runtime" \
    --setenv=XDG_CONFIG_HOME="$scratch/config" \
    --setenv=SECRETSD_SOCK="$broker_socket" \
    --setenv=FORWARD_BIN="$forward_bin" \
    --setenv=FORWARD_CONFIG="$forward_config" \
    --setenv=FORWARD_STDERR="$systemd_forward_stderr" \
    env -i \
      PATH="$scratch_path" \
      HOME="$scratch/home" \
      XDG_RUNTIME_DIR="$scratch/runtime" \
      XDG_CONFIG_HOME="$scratch/config" \
      SECRETSD_SOCK="$broker_socket" \
      FORWARD_BIN="$forward_bin" \
      FORWARD_CONFIG="$forward_config" \
      FORWARD_STDERR="$systemd_forward_stderr" \
      "$@"
}

resolve_tool() {
  local tool path
  tool="$1"
  path="$(command -v "$tool")" || return 1
  if [[ "$path" == */.mise/shims/* ]] && command -v mise >/dev/null 2>&1; then
    mise which "$tool"
  else
    readlink -f "$path"
  fi
}

if (($# != 2)); then
  printf 'usage: %s <forward binary> <secrets binary>\n' "$0" >&2
  exit 1
fi

if ! command -v sops >/dev/null 2>&1; then
  skip 'sops is unavailable'
fi
if ! command -v age-keygen >/dev/null 2>&1; then
  skip 'age-keygen is unavailable'
fi
if ! command -v python3 >/dev/null 2>&1; then
  skip 'python3 is unavailable'
fi
if ! command -v systemd-run >/dev/null 2>&1; then
  skip 'systemd-run is unavailable'
fi
if ! command -v systemctl >/dev/null 2>&1; then
  skip 'systemctl is unavailable'
fi
manager_state="$(systemctl --user is-system-running 2>/dev/null)" || true
if [[ "$manager_state" != running && "$manager_state" != degraded ]]; then
  skip 'no systemd user manager answers'
fi
sops_bin="$(resolve_tool sops)" || fail 'sops binary path could not be resolved'
age_keygen_bin="$(resolve_tool age-keygen)" || fail 'age-keygen binary path could not be resolved'
python_bin="$(resolve_tool python3)" || fail 'python3 binary path could not be resolved'
env_bin="$(command -v env)" || fail 'env binary path could not be resolved'
[[ "$env_bin" == /* ]] || fail 'env binary path is not absolute'
scratch_path="${sops_bin%/*}:${age_keygen_bin%/*}:${python_bin%/*}:$PATH"


if [[ "$1" == /* ]]; then
  forward_bin="$1"
else
  forward_bin="$PWD/$1"
fi
if [[ "$2" == /* ]]; then
  secrets_bin="$2"
else
  secrets_bin="$PWD/$2"
fi
forward_bin="$(readlink -f "$forward_bin")" || fail 'forward binary path could not be resolved'
secrets_bin="$(readlink -f "$secrets_bin")" || fail 'secrets binary path could not be resolved'
[[ -x "$forward_bin" ]] || fail 'the forward binary must be executable'
[[ -x "$secrets_bin" ]] || fail 'the secrets binary must be executable'

live_runtime="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
if [[ ! -d "$live_runtime" ]]; then
  skip "no runtime directory $live_runtime"
fi

here="$(cd -- "$(dirname -- "$0")" && pwd)" || fail 'the directory of this script could not be resolved'
unit_file="$here/../../../systemd/secretsd.service"
[[ -f "$unit_file" ]] || fail 'systemd/secretsd.service is missing'
sandbox_settings=()
while IFS= read -r line || [[ -n "$line" ]]; do
  if [[ "$line" =~ ^(NoNewPrivileges|Private[[:alpha:]]+|Protect[[:alpha:]]+|Restrict[[:alpha:]]+)=.+$ ]]; then
    sandbox_settings+=("$line")
  fi
done < "$unit_file"
(( ${#sandbox_settings[@]} > 0 )) || fail 'systemd/secretsd.service holds no sandbox setting'

broker_unit="e2e-pane-grant-$$-broker.service"
http_unit="e2e-pane-grant-$$-http.service"
grant_unit="e2e-pane-grant-$$-grant.service"
# PrivateTmp gives the scratch broker its own /tmp, so everything it reads lives
# under the runtime directory, beside the live sockets it must leave alone.
scratch="$(mktemp -d "$live_runtime/e2e-pane-grant.XXXXXX")"
trap cleanup EXIT
trap 'on_error $? $LINENO' ERR
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
umask 077

capture_live_socket_inodes "$scratch/live-sockets.before"
pass 'recorded live socket inodes before scratch processes started'

mkdir -p "$scratch/home" "$scratch/runtime" "$scratch/config" "$scratch/source/secrets.human.d"
chmod 700 "$scratch/home" "$scratch/runtime" "$scratch/config" "$scratch/source"
age_key="$scratch/age.key"
if ! env -i \
  PATH="$scratch_path" \
  HOME="$scratch/home" \
  XDG_RUNTIME_DIR="$scratch/runtime" \
  XDG_CONFIG_HOME="$scratch/config" \
  "$age_keygen_bin" -o "$age_key" > "$scratch/age-keygen.stdout" 2> "$scratch/age-keygen.stderr"; then
  fail 'age-keygen could not create the scratch key'
fi
recipient="$(env -i \
  PATH="$scratch_path" \
  HOME="$scratch/home" \
  XDG_RUNTIME_DIR="$scratch/runtime" \
  XDG_CONFIG_HOME="$scratch/config" \
  "$age_keygen_bin" -y "$age_key")" || fail 'age-keygen could not read the scratch recipient'
[[ "$recipient" == age1* ]] || fail 'scratch age recipient is invalid'

cat > "$scratch/.sops.yaml" <<EOF
creation_rules:
  - path_regex: secrets\\.human\\.d/[^/]+\\.env$
    age: $recipient
EOF
printf 'CAP_BROWSER=scratch-browser-capability\n' > "$scratch/plain.env"
if ! (
  cd "$scratch"
  # shellcheck disable=SC2094
  env -i \
    PATH="$scratch_path" \
    HOME="$scratch/home" \
    XDG_RUNTIME_DIR="$scratch/runtime" \
    XDG_CONFIG_HOME="$scratch/config" \
    SOPS_AGE_KEY_FILE="$age_key" \
    "$sops_bin" --filename-override "$scratch/source/secrets.human.d/CAP_BROWSER.env" \
      --input-type dotenv --output-type dotenv -e "$scratch/plain.env" \
      > "$scratch/source/secrets.human.d/CAP_BROWSER.env"
); then
  fail 'sops could not encrypt the scratch browser capability'
fi
rm -f -- "$scratch/plain.env"
[[ -s "$scratch/source/secrets.human.d/CAP_BROWSER.env" ]] || fail 'scratch browser capability ciphertext is absent'
pass 'created a scratch sops-encrypted browser capability'

secrets_config="$scratch/secretsd.toml"
printf '[source.scratch]\npath = "%s"\n' "$scratch/source" > "$secrets_config"
broker_socket="$scratch/runtime/secretsd.sock"
broker_log="$scratch/broker.log"
# The scratch broker runs as a transient user unit with every sandbox setting
# of the shipped unit, read from it on each run. env -i keeps the user
# manager's environment out and execs the broker, so MainPID is the broker.
unit_properties=()
for setting in "${sandbox_settings[@]}"; do
  unit_properties+=(-p "$setting")
done
started_units+=("$broker_unit")
if ! systemd-run --user --quiet --collect --unit "$broker_unit" \
  "${unit_properties[@]}" \
  -p "StandardOutput=append:$broker_log" \
  -p "StandardError=append:$broker_log" \
  -p RuntimeMaxSec=600 \
  "$env_bin" -i \
  PATH="$scratch_path" \
  HOME="$scratch/home" \
  XDG_RUNTIME_DIR="$scratch/runtime" \
  XDG_CONFIG_HOME="$scratch/config" \
  SECRETSD_SOCKET="$broker_socket" \
  SECRETSD_CONFIG="$secrets_config" \
  SOPS_AGE_KEY_FILE="$age_key" \
  SECRETSD_MEMLOCK=optional \
  "$secrets_bin" serve 2> "$scratch/systemd-run-broker.stderr"; then
  cat "$scratch/systemd-run-broker.stderr" >&2
  fail "could not start transient unit $broker_unit"
fi
broker_pid=0
for attempt in {1..200}; do
  broker_pid="$(systemctl --user show -p MainPID --value "$broker_unit")" || broker_pid=0
  [[ "$broker_pid" =~ ^[1-9][0-9]*$ ]] && break
  sleep 0.05
done
[[ "$broker_pid" =~ ^[1-9][0-9]*$ ]] || fail "transient unit $broker_unit reported no main pid"
track_process broker "$broker_pid"
unit_settings=()
for setting in "${sandbox_settings[@]}"; do
  key="${setting%%=*}"
  value="$(systemctl --user show -p "$key" --value "$broker_unit")" || fail "could not read $key of transient unit $broker_unit"
  [[ "$value" == "${setting#*=}" ]] || fail "transient unit $broker_unit has $key=$value, unlike $setting in systemd/secretsd.service"
  unit_settings+=("$key=$value")
done
pass "scratch broker runs as transient unit $broker_unit with the settings of systemd/secretsd.service: ${unit_settings[*]}"

wait_for_socket broker "$broker_socket" || fail 'scratch broker did not create its socket'
# Read once the broker serves, so the manager has set up its namespace.
broker_uid_map="$(uid_map_of "$broker_pid")" || fail 'could not read the uid_map of the scratch broker'
script_uid_map="$(uid_map_of "$$")" || fail "could not read this script's uid_map"
tracked_process_is_alive broker || fail 'scratch broker exited before its uid_map was compared'
[[ "$broker_uid_map" != "$script_uid_map" ]] || fail "scratch broker shares this script's user namespace"
pass 'scratch broker runs in its own user namespace'
broker_hello || fail 'scratch broker did not answer HELLO'
pass 'scratch broker answered HELLO on its scratch socket'

read -r grant_port relay_port bridge_port files_port <<< "$(allocate_ports)" || fail 'could not allocate scratch loopback ports'
for port in "$grant_port" "$relay_port" "$bridge_port" "$files_port"; do
  [[ "$port" =~ ^[1-9][0-9]*$ ]] || fail 'scratch port allocation was invalid'
done
forward_config="$scratch/forward.toml"
cat > "$forward_config" <<EOF
listen = "127.0.0.1"
peer = "127.0.0.1"
bridge_port = $bridge_port
relay_port = $relay_port
pcsc_port = 0
grant_port = $grant_port
pulse_port = 0
EOF
forward_log="$scratch/forward.log"
env -i \
  PATH="$scratch_path" \
  HOME="$scratch/home" \
  XDG_RUNTIME_DIR="$scratch/runtime" \
  XDG_CONFIG_HOME="$scratch/config" \
  SECRETSD_SOCK="$broker_socket" \
  "$forward_bin" serve --port "$files_port" --config "$forward_config" > "$forward_log" 2>&1 &
track_process forward "$!"
wait_for_socket forward "$scratch/runtime/forward/browser-grant.sock" || fail 'scratch forward serve did not create its grant socket'

stub_ready="$scratch/stub.ready"
stub_log="$scratch/stub.log"
env -i \
  PATH="$scratch_path" \
  HOME="$scratch/home" \
  XDG_RUNTIME_DIR="$scratch/runtime" \
  XDG_CONFIG_HOME="$scratch/config" \
  "$python_bin" - "$relay_port" "$grant_port" "$stub_ready" > "$stub_log" 2>&1 <<'PY' &
import socket
import sys
import threading
import time
from pathlib import Path

relay_port = int(sys.argv[1])
grant_port = int(sys.argv[2])
ready = Path(sys.argv[3])
tokens = set()
tokens_lock = threading.Lock()

listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind(("127.0.0.1", relay_port))
listener.listen()
ready.touch()


def attach_feed():
    deadline = time.monotonic() + 10
    while True:
        try:
            feed = socket.create_connection(("127.0.0.1", grant_port), timeout=1)
            break
        except OSError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.05)
    # The 1 s timeout bounds each connect attempt only. A grant can wait on the
    # broker for a touch far longer, and the feed must stay open through it.
    feed.settimeout(None)
    with feed:
        feed.sendall(b"FEED\n")
        reader = feed.makefile("rb")
        while True:
            line = reader.readline()
            if not line:
                return
            fields = line.rstrip(b"\n").split(b" ")
            if len(fields) != 3 or fields[0] != b"TOKEN":
                return
            with tokens_lock:
                tokens.add(fields[1])
            feed.sendall(b"OK\n")


threading.Thread(target=attach_feed, daemon=True).start()
while True:
    connection, _ = listener.accept()
    with connection:
        connection.settimeout(5)
        line = bytearray()
        while len(line) < 256:
            byte = connection.recv(1)
            if not byte:
                break
            line.extend(byte)
            if byte == b"\n":
                break
        if not line.startswith(b"RELAY "):
            continue
        token = bytes(line[6:].rstrip(b"\n"))
        with tokens_lock:
            accepted = token in tokens
        if not accepted:
            continue
        request = connection.recv(4096)
        if not request.startswith(b"GET /json/version "):
            continue
        body = b'{"Browser":"scratch","Protocol-Version":"1.3"}'
        response = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
        connection.sendall(response + str(len(body)).encode() + b"\r\n\r\n" + body)
PY
track_process stub "$!"
wait_for_socket stub "$scratch/runtime/forward/browser-grant.sock" || fail 'scratch forward grant socket disappeared'
for attempt in {1..200}; do
  [[ -f "$stub_ready" ]] && break
  tracked_process_is_alive stub || fail 'scratch laptop stub exited before listening'
  sleep 0.05
done
[[ -f "$stub_ready" ]] || fail 'scratch laptop stub did not listen on the relay port'
wait_for_log_line forward "$forward_log" 'forward: grant feed attached from 127.0.0.1' || fail 'scratch forward serve did not attach the grant feed'
pass 'scratch forward serve attached the grant feed'

omp_pid="$(nearest_omp_ancestor "$$")" || fail 'no omp process is an ancestor of this script'
[[ "$omp_pid" =~ ^[1-9][0-9]*$ ]] || fail 'nearest omp ancestor pid is invalid'
omp_start="$(proc_start "$omp_pid")" || fail 'nearest omp ancestor has no readable start time'
systemd_forward_stderr="$scratch/systemd-forward.stderr"
grant_stdout="$scratch/grant.stdout"
grant_stderr="$scratch/grant.stderr"
env -i \
  PATH="$scratch_path" \
  HOME="$scratch/home" \
  XDG_RUNTIME_DIR="$scratch/runtime" \
  XDG_CONFIG_HOME="$scratch/config" \
  SECRETSD_SOCK="$broker_socket" \
  "$forward_bin" browser grant --ttl 2m --config "$forward_config" \
  < /dev/null > "$grant_stdout" 2> "$grant_stderr" &
track_process grant "$!"
if ! wait "${process_pid[grant]}"; then
  cat "$grant_stderr" >&2
  fail 'pane browser grant command failed'
fi
mapfile -t grant_lines < "$grant_stdout"
(( ${#grant_lines[@]} == 1 )) || fail 'pane browser grant did not print one endpoint'
[[ "${grant_lines[0]}" =~ ^http://127\.0\.0\.1:([1-9][0-9]*)$ ]] || fail 'pane browser grant printed an invalid endpoint'
endpoint_port="${BASH_REMATCH[1]}"
pass 'pane browser grant printed a loopback endpoint'

relay_pids=()
for attempt in {1..200}; do
  mapfile -t relay_pids < <(find_relay_for_endpoint)
  (( ${#relay_pids[@]} == 1 )) && break
  (( ${#relay_pids[@]} < 2 )) || fail 'more than one relay serves the pane grant endpoint'
  sleep 0.05
done
(( ${#relay_pids[@]} == 1 )) || fail 'pane grant relay did not start'
track_process relay "${relay_pids[0]}"

if endpoint_body="$(http_json_version "$endpoint_port")"; then
  [[ "$endpoint_body" == *'"Browser":"scratch"'* ]] || fail 'pane child received an unexpected stub body'
else
  fail 'pane child could not read the stub version body'
fi
pass 'pane child received the scratch laptop version body'

started_units+=("$http_unit")
if systemd_body="$(run_as_manager "$http_unit" "$python_bin" - "$endpoint_port" 2> "$scratch/systemd-http.stderr" <<'PY'
import socket
import sys

sock = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=5)
sock.sendall(b"GET /json/version HTTP/1.1\r\nHost: localhost\r\n\r\n")
sys.stdout.buffer.write(sock.recv(1024))
PY
)"; then
  [[ "$systemd_body" == 'REFUSED SESSION' ]] || fail 'systemd-run child was not refused by the relay'
else
  fail 'systemd-run child could not reach the relay endpoint'
fi
pass 'systemd-run child was refused by the relay'

systemd_grant_stdout="$scratch/systemd-grant.stdout"
systemd_run_stderr="$scratch/systemd-run.stderr"
started_units+=("$grant_unit")
# shellcheck disable=SC2016
if run_as_manager "$grant_unit" sh -c 'exec </dev/null; exec "$FORWARD_BIN" browser grant --ttl 2m --config "$FORWARD_CONFIG" 2>"$FORWARD_STDERR"' \
  > "$systemd_grant_stdout" 2> "$systemd_run_stderr"; then
  systemd_grant_status=0
else
  systemd_grant_status=$?
fi
(( systemd_grant_status == 1 )) || fail 'systemd-run browser grant did not exit 1'
printf '%s\n' "$no_scope_refusal" > "$scratch/expected-no-scope.stderr"
cmp -s "$scratch/expected-no-scope.stderr" "$systemd_forward_stderr" || fail 'systemd-run browser grant did not print the no-scope refusal exactly'
pass 'systemd-run browser grant refused before broker access'

capability_audits=()
while IFS= read -r audit_line; do
  if [[ "$audit_line" == *'request handled'* && "$audit_line" == *'key=CAP_BROWSER'* ]]; then
    capability_audits+=("$audit_line")
  fi
done < "$broker_log"
(( ${#capability_audits[@]} == 1 )) || fail 'scratch broker did not record exactly one browser authorization'
[[ "${capability_audits[0]}" == *'scope_kind=Some(OmpProcess)'* ]] || fail 'browser authorization did not use omp scope'
[[ "${capability_audits[0]}" == *"scope_omp_pid=Some($omp_pid)"* ]] || fail 'browser authorization recorded the wrong omp pid'
pass 'scratch broker recorded one omp-scoped browser authorization'
pass 'systemd-run browser grant made no browser authorization'

capture_live_socket_inodes "$scratch/live-sockets.after"
cmp -s "$scratch/live-sockets.before" "$scratch/live-sockets.after" || fail 'live socket inodes changed during the scratch run'
live_sockets_verified=true
pass 'live socket inodes are unchanged'

stop_tracked_process stub || fail 'scratch laptop stub did not stop'
stop_tracked_process grant || fail 'pane browser grant process did not stop'
stop_tracked_process relay || fail 'pane grant relay did not stop'
if endpoint_stopped_answering "$endpoint_port"; then
  pass 'pane grant relay endpoint stopped answering'
else
  fail 'pane grant relay endpoint still answers after shutdown'
fi
stop_tracked_process forward || fail 'scratch forward serve did not stop'
systemctl --user stop "$broker_unit" || fail 'scratch broker did not stop'
if tracked_process_is_alive broker; then
  fail 'scratch broker did not stop'
fi
wait_for_units_unloaded "${started_units[@]}" || fail "a test unit stays loaded: ${still_loaded_units[*]}"
test_units_verified=true
pass "no test unit stays loaded: ${started_units[*]}"
if pgrep -f -- "$scratch" >/dev/null 2>&1; then
  fail 'a scratch process remained after shutdown'
fi
scratch_processes_verified=true
pass 'no scratch process remains running'

if ! rm -r -- "$scratch"; then
  fail 'could not remove the scratch directory'
fi
scratch=''
pass 'removed the scratch directory'
trap - ERR EXIT
exit 0
