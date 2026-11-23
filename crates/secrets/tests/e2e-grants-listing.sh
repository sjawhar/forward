#!/usr/bin/env bash
# Drives a built daemon through seven steps and checks what `secrets grants`
# answers at each one: secret grants, requests that wait for a touch, receipts
# not yet redeemed and capability grants (dispatch://HOME-291).
#
# Usage: e2e-grants-listing.sh DAEMON CLIENT [EXTRA_CLIENT...]
#
#   DAEMON        a `secrets` binary; `DAEMON serve` runs the scratch daemon
#   CLIENT        the `secrets` binary that runs `grants`, `lock` and the step-6
#                 `get KEY`
#   EXTRA_CLIENT  other `secrets` binaries (older releases); at step 6 each runs
#                 `get KEY --no-request` in the step's session and must exit 0
#                 with `"grant":true`
#
# The steps, and what the answer must hold:
#
#   1 before-any-request          exactly `no active grants`
#   2 while-authorize-waits       one `request` row for CAP_BROWSER, while the
#                                 AUTHORIZE decrypt waits on the fake sops
#   3 after-authorize             a CAP_BROWSER secret grant and one `receipt` row
#   4 after-unregister            only the `receipt` row
#   5 after-redeem                only one `capability` row
#   6 after-register-and-request  the step-6 key's secret grant and the
#                                 `capability` row
#   7 after-lock                  exactly `no active grants`
#
# Each step prints the stdout of `CLIENT grants` unchanged between
# `--- begin step N NAME` and `--- end step N NAME`, then `step N NAME: PASS`
# or `step N NAME: FAIL: WHY`. Every step runs whatever failed before it, every
# wait is bounded in seconds, and the script exits 0 only when all seven pass.
#
# The daemon and every client run under `env -i` with scratch settings only, so
# the machine's live secretsd and any session token in this environment are
# never used. One perl driver registers the sessions and stays alive: a request
# carrying a session token must come from a descendant of the registering
# process (tests/AGENTS.md, "Ancestry affects test shape"). GRANTS, LOCK and
# REDEEM carry no scope, so this script sends them itself.
#
# Needs: perl. Exits 77 when it is absent; the cargo wrapper treats that as
# "not exercised".
set -euo pipefail

readonly skip_status=77
readonly first_token='cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc'
readonly second_token='dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd'
readonly first_session='e2e-grants-listing-1'
readonly second_session='e2e-grants-listing-2'
readonly cap_key='CAP_BROWSER'
readonly human_key='E2E_LISTING_KEY'
# The daemon runs with these two; the expiry bounds below are read from them.
readonly max_grant_secs=7200
readonly request_ttl_secs=30
# RECEIPT_TTL, src/receipts.rs.
readonly receipt_ttl_secs=60
# How long the script waits for any one event, and the bound on each process
# it starts, so a stuck daemon gives a FAIL rather than a hang.
readonly wait_secs=10
readonly client_secs=10
readonly child_secs=20
readonly driver_secs=300
readonly hex_run='[0-9a-f]{64}'
readonly nothing_live=$'no active grants\n'
readonly secret_header=$'SECRET GRANT\tSCOPE\tEXPIRES\n'
readonly kind_header=$'KIND\tNAME\tSCOPE\tSTATE\tEXPIRES\n'
readonly t=$'\t' nl=$'\n'
# Rows of the KIND table; each captures its expiry in seconds.
readonly request_row="request${t}${cap_key}${t}session${t}(pending|decrypting), id [0-9]+${t}([0-9]+)s${nl}"
readonly receipt_row="receipt${t}browser${t}-${t}unredeemed${t}([0-9]+)s${nl}"
readonly capability_row="capability${t}browser${t}-${t}active${t}([0-9]+)s${nl}"
readonly names=(
  before-any-request
  while-authorize-waits
  after-authorize
  after-unregister
  after-redeem
  after-register-and-request
  after-lock
)

report() { printf 'e2e-grants-listing: %s\n' "$1"; }
fail() { printf 'e2e-grants-listing: FAIL: %s\n' "$1" >&2; exit 1; }
skip() { report "SKIP: $1"; exit "$skip_status"; }

if (($# < 2)); then
  printf 'usage: %s DAEMON CLIENT [EXTRA_CLIENT...]\n' "$0" >&2
  exit 64
fi

absolute() {
  if [[ "$1" == /* ]]; then
    printf '%s\n' "$1"
  else
    printf '%s/%s\n' "$PWD" "$1"
  fi
}

daemon_bin="$(absolute "$1")"
client_bin="$(absolute "$2")"
shift 2
extra_bins=()
for extra in "$@"; do
  extra_bins+=("$(absolute "$extra")")
done
readonly daemon_bin client_bin extra_bins
for bin in "$daemon_bin" "$client_bin" "${extra_bins[@]}"; do
  [[ -x "$bin" ]] || fail "not executable: $bin"
done

command -v perl >/dev/null 2>&1 || skip 'perl not available'

here="$(cd "$(dirname "$0")" && pwd)"
readonly here
umask 077
scratch="$(mktemp -d "${TMPDIR:-/tmp}/e2e-grants-listing.XXXXXX")"
readonly scratch
readonly out="$scratch/out"
readonly socket="$scratch/secretsd.sock"
readonly wait_marker="$scratch/release"
readonly decrypt_log="$scratch/decrypt.log"
readonly journal="$scratch/daemon.log"
readonly second_token_file="$scratch/$second_session.token"
daemon_pid=0
driver_pid=0

cleanup() {
  # Release any fake sops still waiting and stop the driver, then reap the
  # driver and the daemon, so no stray process outlives the run.
  : > "$wait_marker" 2>/dev/null || true
  : > "$out/stop" 2>/dev/null || true
  for stray in "$driver_pid" "$daemon_pid"; do
    if ((stray == 0)); then continue; fi
    kill "$stray" 2>/dev/null || true
    wait "$stray" 2>/dev/null || true
  done
  # A fake sops polls the marker every 10 ms; let it see the marker before the
  # marker is deleted with the rest of the scratch tree.
  sleep 0.2
  rm -rf "$scratch"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

mkdir -p "$scratch/root/secrets.human.d" "$scratch/bin" "$scratch/home" "$out"
: > "$scratch/root/secrets.env"
# The fake sops answers `KEY=value-for-KEY` for KEY.env; the files say the same.
for key in "$cap_key" "$human_key"; do
  printf '%s=value-for-%s\n' "$key" "$key" > "$scratch/root/secrets.human.d/$key.env"
done
cp "$here/fixtures/fake-sops-ok" "$scratch/bin/sops"
chmod u+x "$scratch/bin/sops"
cat > "$scratch/config.toml" <<EOF
[source.e2e]
path = "$scratch/root"
EOF
printf '%s' "$second_token" > "$second_token_file"
: > "$decrypt_log"

# SECRETSD_SOCKET moves only this daemon's listener; clients reach it through
# SECRETSD_SOCK below. Every sops call logs its file, then waits for the marker.
env -i \
  PATH="$PATH" \
  HOME="$scratch/home" \
  SECRETSD_SOCKET="$socket" \
  SECRETSD_CONFIG="$scratch/config.toml" \
  SECRETSD_SOPS_BIN="$scratch/bin/sops" \
  SECRETSD_MEMLOCK=optional \
  SECRETSD_TOUCH_POLICY=always \
  SECRETSD_COOLDOWN_SECS=1 \
  SECRETSD_MAX_GRANT_SECS="$max_grant_secs" \
  SECRETSD_REQUEST_TTL_SECS="$request_ttl_secs" \
  FAKE_SOPS_LOG="$decrypt_log" \
  FAKE_SOPS_WAIT_MARKER="$wait_marker" \
  "$daemon_bin" serve >"$journal" 2>&1 &
daemon_pid=$!

# await TEST PATH: wait up to wait_secs until `test TEST PATH` holds.
await() {
  local deadline=$((SECONDS + wait_secs))
  until test "$1" "$2"; do
    ((SECONDS < deadline)) || return 1
    sleep 0.05
  done
}

# oneline TEXT: TEXT on one line, for a FAIL reason.
oneline() {
  local text="${1//$'\n'/ }"
  printf '%s' "${text% }"
}

# text_of PATH: the file's text on one line, or nothing when it is absent.
text_of() {
  if [[ -e "$1" ]]; then oneline "$(<"$1")"; fi
}

# exit_text STATUS: how a process bounded by `bounded` ended.
exit_text() {
  if (($1 == 142)); then
    printf 'timed out after %ss' "$client_secs"
  else
    printf 'exited %s' "$1"
  fi
}

# bounded CMD...: run CMD; SIGALRM ends it after client_secs (status 142).
# shellcheck disable=SC2016  # perl source: its $variables are perl's, not the shell's
bounded() {
  perl -e 'alarm shift @ARGV; exec { $ARGV[0] } @ARGV or die "exec $ARGV[0]: $!\n"' \
    "$client_secs" "$@"
}

readonly client_env=(
  env -i
  PATH="$PATH"
  HOME="$scratch/home"
  SECRETSD_SOCK="$socket"
  SECRETSD_CONFIG="$scratch/config.toml"
  SECRETSD_SOPS_BIN="$scratch/bin/sops"
)

startup_deadline=$((SECONDS + wait_secs))
until [[ -S "$socket" ]]; do
  kill -0 "$daemon_pid" 2>/dev/null || fail "the daemon exited during startup: $(<"$journal")"
  ((SECONDS < startup_deadline)) || fail "the daemon never created $socket: $(<"$journal")"
  sleep 0.05
done

# The driver registers the first session, then serves one command file at a
# time: `cmd.NAME` in $out. Each answer lands whole (by rename) in $out/NAME.
# It never prints a token or a receipt: the AUTHORIZE reply goes to a 0600 file
# that only the REDEEM below reads.
# shellcheck disable=SC2016  # perl source: its $variables are perl's, not the shell's
env -i PATH="$PATH" perl -e '
  use strict;
  use warnings;
  use IO::Socket::UNIX;
  use POSIX qw(WNOHANG);

  my ($sock, $out, $client, $key, $path, $home, $config, $sops, $token_file,
      $token1, $session1, $token2, $session2, $lifetime, $child_secs, @extras) = @ARGV;
  my $parent = getppid();
  umask 077;
  alarm $lifetime;

  sub put {
    my ($name, $text) = @_;
    open(my $f, ">", "$out/$name.part") or die "open $name: $!";
    print $f $text or die "write $name: $!";
    close $f or die "close $name: $!";
    rename("$out/$name.part", "$out/$name") or die "rename $name: $!";
  }

  sub frame {
    my ($line) = @_;
    my $s = IO::Socket::UNIX->new(Type => SOCK_STREAM, Peer => $sock)
      or return "[connect: $!]\n";
    print $s "$line\n";
    my $reply = <$s>;
    return defined $reply ? $reply : "[no reply]\n";
  }

  # A child of this driver, so the daemon finds it inside the session tree.
  sub spawn {
    my ($code) = @_;
    my $pid = fork();
    defined $pid or die "fork: $!";
    return if $pid;
    alarm $child_secs;
    $code->();
    exit 0;
  }

  # Run one client in the second session; record its stdout, stderr and exit.
  sub run_client {
    my ($name, $bin, @args) = @_;
    alarm 0;
    my $pid = fork();
    defined $pid or die "fork: $!";
    if ($pid == 0) {
      %ENV = (PATH => $path, HOME => $home, SECRETSD_SOCK => $sock,
              SECRETSD_CONFIG => $config, SECRETSD_SOPS_BIN => $sops,
              SECRETSD_SESSION_TOKEN_FILE => $token_file);
      open(STDIN, "<", "/dev/null") or die "stdin: $!";
      open(STDOUT, ">", "$out/$name.out") or die "stdout: $!";
      open(STDERR, ">", "$out/$name.err") or die "stderr: $!";
      alarm $child_secs;
      exec {$bin} $bin, @args;
      die "exec $bin: $!";
    }
    waitpid($pid, 0) == $pid or die "waitpid: $!";
    put("$name.status", ($? & 127 ? "signal " . ($? & 127) : $? >> 8) . "\n");
  }

  put("register-1", frame("REGISTER\ttoken=$token1\tsession=$session1\tpid=$$"));
  until (-e "$out/stop" || getppid() != $parent) {
    for my $command (glob("$out/cmd.*")) {
      my ($name) = $command =~ m{/cmd\.([^/]+)\z};
      unlink $command or die "unlink $command: $!";
      if ($name eq "authorize") {
        spawn(sub { put("authorize", frame("AUTHORIZE\tcap=browser\ttoken=$token1")) });
      } elsif ($name eq "unregister") {
        put("unregister", frame("UNREGISTER\tsession=$session1"));
      } elsif ($name eq "register-2") {
        put("register-2", frame("REGISTER\ttoken=$token2\tsession=$session2\tpid=$$"));
      } elsif ($name eq "get") {
        spawn(sub { run_client("get", $client, "get", $key) });
      } elsif ($name eq "extras") {
        for my $i (0 .. $#extras) {
          spawn(sub { run_client("extra-$i", $extras[$i], "get", $key, "--no-request") });
        }
      } else {
        die "unknown command $name";
      }
    }
    1 while waitpid(-1, WNOHANG) > 0;
    select(undef, undef, undef, 0.05);
  }
' "$socket" "$out" "$client_bin" "$human_key" "$PATH" "$scratch/home" "$scratch/config.toml" \
  "$scratch/bin/sops" "$second_token_file" "$first_token" "$first_session" "$second_token" \
  "$second_session" "$driver_secs" "$child_secs" "${extra_bins[@]}" \
  >"$scratch/driver.log" 2>&1 &
driver_pid=$!

await -e "$out/register-1" ||
  fail "the driver did not register within ${wait_secs}s: $(<"$scratch/driver.log")"
registered="$(<"$out/register-1")"
[[ "$registered" == OK ]] || fail "the driver's REGISTER was answered [$registered]"

# ask NAME: have the driver run command NAME.
ask() { : > "$out/cmd.$1"; }

# redeem: send REDEEM with the receipt of the AUTHORIZE reply, which perl reads
# from its file, so the receipt is in no argument and no output.
# shellcheck disable=SC2016  # perl source: its $variables are perl's, not the shell's
redeem() {
  bounded perl -MIO::Socket::UNIX -e '
    my ($sock, $reply_file) = @ARGV;
    open(my $f, "<", $reply_file) or die "no AUTHORIZE reply: $!\n";
    my $authorized = <$f> // "";
    my ($receipt) = $authorized =~ /\breceipt=(\S+)/ or die "no receipt in the AUTHORIZE reply\n";
    my $s = IO::Socket::UNIX->new(Type => SOCK_STREAM, Peer => $sock) or die "connect: $!\n";
    print $s "REDEEM\treceipt=$receipt\tcap=browser\n";
    my $reply = <$s>;
    print defined $reply ? $reply : "[no reply]\n";
  ' "$socket" "$out/authorize"
}

passed=0
failed_steps=()
why=()
answer=''

# show_grants N: run `CLIENT grants`, print its stdout between the step's begin
# and end lines, keep it in $answer, and check that it holds no secret.
show_grants() {
  local n="$1" status=0 key
  local name="${names[n - 1]}"
  bounded "${client_env[@]}" "$client_bin" grants >"$out/step-$n.out" 2>"$out/step-$n.err" ||
    status=$?
  answer="$(cat "$out/step-$n.out"; printf x)"
  answer="${answer%x}"
  printf '%s\n' "--- begin step $n $name"
  printf '%s' "$answer"
  [[ -z "$answer" || "$answer" == *$'\n' ]] || printf '\n'
  printf '%s\n' "--- end step $n $name"
  ((status == 0)) || why+=("secrets grants $(exit_text "$status"): $(text_of "$out/step-$n.err")")
  [[ ! "$answer" =~ $hex_run ]] || why+=('the answer holds a run of 64 hex digits')
  for key in "$cap_key" "$human_key"; do
    [[ "$answer" != *"value-for-$key"* ]] || why+=("the answer holds the value of $key")
  done
}

# expect PATTERN WHAT: the answer must match PATTERN; captures in BASH_REMATCH.
expect() {
  [[ "$answer" =~ $1 ]] && return 0
  why+=("expected $2")
  return 1
}

# within SECS LOW HIGH WHAT: an expiry must lie in LOW..HIGH seconds.
within() {
  (($1 >= $2 && $1 <= $3)) || why+=("$4 expires in $1s, not within $2s..$3s")
}

verdict() {
  local n="$1" joined
  local name="${names[n - 1]}"
  if ((${#why[@]} == 0)); then
    printf 'step %d %s: PASS\n' "$n" "$name"
    passed=$((passed + 1))
  else
    printf -v joined '%s; ' "${why[@]}"
    printf 'step %d %s: FAIL: %s\n' "$n" "$name" "${joined%; }"
    failed_steps+=("$n")
  fi
  why=()
}

readonly grant_low=$((max_grant_secs - 60))

show_grants 1
[[ "$answer" == "$nothing_live" ]] || why+=("expected exactly 'no active grants'")
verdict 1

ask authorize
await -s "$decrypt_log" ||
  why+=("the fake sops did not start the AUTHORIZE decrypt within ${wait_secs}s")
show_grants 2
: > "$wait_marker"
if expect "^${kind_header}${request_row}\$" \
  "only a KIND table with one pending or decrypting request row for $cap_key in scope session"; then
  within "${BASH_REMATCH[2]}" 0 "$request_ttl_secs" 'the request'
fi
verdict 2

if await -e "$out/authorize"; then
  authorized="$(<"$out/authorize")"
  if [[ "$authorized" == *receipt=* && "$authorized" != $'OK\tstatus=authorized receipt='* ]]; then
    why+=('AUTHORIZE was answered with a receipt in an unexpected reply')
  elif [[ "$authorized" != $'OK\tstatus=authorized receipt='* ]]; then
    why+=("AUTHORIZE was answered [$(oneline "$authorized")]")
  fi
else
  why+=("AUTHORIZE did not return within ${wait_secs}s")
fi
show_grants 3
if expect "^${secret_header}${cap_key}${t}session${t}([0-9]+)s${nl}${nl}${kind_header}${receipt_row}\$" \
  "a $cap_key secret grant in scope session, then a KIND table with one receipt row for browser"; then
  within "${BASH_REMATCH[1]}" "$grant_low" "$max_grant_secs" "the $cap_key grant"
  within "${BASH_REMATCH[2]}" 0 "$receipt_ttl_secs" 'the receipt'
fi
verdict 3

ask unregister
if await -e "$out/unregister"; then
  unregistered="$(<"$out/unregister")"
  [[ "$unregistered" == OK ]] || why+=("UNREGISTER was answered [$(oneline "$unregistered")]")
else
  why+=("UNREGISTER was not answered within ${wait_secs}s")
fi
show_grants 4
if expect "^${kind_header}${receipt_row}\$" 'only a KIND table with one receipt row for browser'; then
  within "${BASH_REMATCH[1]}" 0 "$receipt_ttl_secs" 'the receipt'
fi
verdict 4

redeem_status=0
redeemed="$(redeem 2>"$out/redeem.err")" || redeem_status=$?
if ((redeem_status != 0)); then
  why+=("REDEEM $(exit_text "$redeem_status"): $(text_of "$out/redeem.err")")
elif [[ "$redeemed" != $'OK\tstatus=redeemed'* ]]; then
  why+=("REDEEM was answered [$(oneline "$redeemed")]")
fi
show_grants 5
if expect "^${kind_header}${capability_row}\$" 'only a KIND table with one capability row for browser'; then
  within "${BASH_REMATCH[1]}" "$grant_low" "$max_grant_secs" 'the capability grant'
fi
verdict 5

ask register-2
if await -e "$out/register-2"; then
  registered="$(<"$out/register-2")"
  [[ "$registered" == OK ]] || why+=("the second REGISTER was answered [$(oneline "$registered")]")
else
  why+=("the second REGISTER was not answered within ${wait_secs}s")
fi
ask get
if await -e "$out/get.status"; then
  got="$(<"$out/get.status")"
  [[ "$got" == 0 ]] || why+=("get $human_key exited $got: $(text_of "$out/get.err")")
else
  why+=("get $human_key did not finish within ${wait_secs}s")
fi
show_grants 6
if expect "^${secret_header}${human_key}${t}session${t}([0-9]+)s${nl}${nl}${kind_header}${capability_row}\$" \
  "a $human_key secret grant in scope session, then a KIND table with one capability row"; then
  within "${BASH_REMATCH[1]}" "$grant_low" "$max_grant_secs" "the $human_key grant"
  within "${BASH_REMATCH[2]}" "$grant_low" "$max_grant_secs" 'the capability grant'
fi
if ((${#extra_bins[@]} > 0)); then
  ask extras
  for i in "${!extra_bins[@]}"; do
    extra="${extra_bins[i]}"
    if ! await -e "$out/extra-$i.status"; then
      printf 'extra client %s: no exit within %ss\n' "$extra" "$wait_secs"
      why+=("extra client $extra did not finish within ${wait_secs}s")
      continue
    fi
    extra_status="$(<"$out/extra-$i.status")"
    extra_out="$(<"$out/extra-$i.out")"
    printf 'extra client %s: exit %s, stdout: %s\n' "$extra" "$extra_status" "$extra_out"
    [[ "$extra_status" == 0 && "$extra_out" == *'"grant":true'* ]] ||
      why+=("extra client $extra did not exit 0 with \"grant\":true: $(text_of "$out/extra-$i.err")")
  done
fi
verdict 6

lock_status=0
bounded "${client_env[@]}" "$client_bin" lock >"$out/lock.out" 2>"$out/lock.err" ||
  lock_status=$?
((lock_status == 0)) || why+=("secrets lock $(exit_text "$lock_status"): $(text_of "$out/lock.err")")
show_grants 7
[[ "$answer" == "$nothing_live" ]] || why+=("expected exactly 'no active grants'")
verdict 7

if ((passed != ${#names[@]})); then
  report "FAIL: step ${failed_steps[*]} failed"
  exit 1
fi
report "PASS: all ${#names[@]} steps"
