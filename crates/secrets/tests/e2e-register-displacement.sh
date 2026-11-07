#!/usr/bin/env bash
# Reproduces the 2026-11-07 incident (dispatch://INFRA-1644) against a scratch
# daemon and proves it is refused.
#
# On that day a session-copying script resumed a copy of a live agent session
# under the live session's own id. Its REGISTER displaced the live token and
# its exit UNREGISTERed the id, so 59 of 153 live sessions lost their
# credentials: each kept believing it was registered while every later request
# answered UNKNOWN_TOKEN, with no error of its own. A deliberate claim by any
# same-uid process looks identical.
#
# The shape here is that incident with nothing else in it:
#
#   - a victim process registers a session, is served its key, and stays alive;
#   - an outsider -- a sibling of the victim, not one of its descendants --
#     names the victim's session id in a REGISTER carrying its own token, then
#     tries UNREGISTER on it;
#   - both must be refused with FOREIGN_CALLER, the daemon must log the
#     refusal with the session and both pids, and the victim must still be
#     served afterwards.
#
# Against a daemon without the ancestry check on REGISTER, step 4 fails: the
# outsider is told OK and the victim's next request answers UNKNOWN_TOKEN.
#
# Needs: perl (to speak the line protocol from a process whose ancestry the
# harness controls). Exits 77 when it is absent; the cargo wrapper treats that
# as "not exercised".
set -euo pipefail

readonly skip_status=77
readonly victim_token='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
readonly outsider_token='bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
readonly session='e2e-register-displacement'
readonly human_key='E2E_DISPLACEMENT_KEY'
readonly human_value='value-for-the-victim'

report() { printf 'e2e-register-displacement: %s\n' "$1"; }
fail() { printf 'e2e-register-displacement: FAIL: %s\n' "$1" >&2; exit 1; }
skip() { report "SKIP: $1"; exit "$skip_status"; }

if (($# != 1)); then
  printf 'usage: %s PATH_TO_SECRETS_BINARY\n' "$0" >&2
  exit 2
fi
secrets_bin="$1"
[[ "$secrets_bin" == /* ]] || secrets_bin="$PWD/$secrets_bin"
readonly secrets_bin
[[ -x "$secrets_bin" ]] || fail "not executable: $secrets_bin"

command -v perl >/dev/null 2>&1 || skip 'perl not available'

scratch="$(mktemp -d "${TMPDIR:-/tmp}/e2e-register-displacement.XXXXXX")"
readonly scratch
here="$(cd "$(dirname "$0")" && pwd)"
readonly here
daemon_pid=0
victim_pid=0

cleanup() {
  # Reap, do not merely signal: the harness must not hand a stray daemon or
  # victim back to the suite that runs after it.
  : > "$scratch/release" 2>/dev/null || true
  for stray in "$victim_pid" "$daemon_pid"; do
    if ((stray == 0)); then continue; fi
    kill "$stray" 2>/dev/null || true
    wait "$stray" 2>/dev/null || true
  done
  rm -rf "$scratch"
}
trap cleanup EXIT

report '1/6 laying out a scratch source root with one human-tier key'
mkdir -p "$scratch/root/secrets.human.d" "$scratch/bin" "$scratch/home" "$scratch/out"
: > "$scratch/root/secrets.env"
printf '%s=%s\n' "$human_key" "$human_value" > "$scratch/root/secrets.human.d/$human_key.env"
cp "$here/fixtures/fake-sops-ok" "$scratch/bin/sops"
chmod +x "$scratch/bin/sops"
cat > "$scratch/config.toml" <<EOF
[source.e2e]
path = "$scratch/root"
EOF
readonly socket="$scratch/secretsd.sock"
readonly token_file="$scratch/$session.token"
printf '%s' "$victim_token" > "$token_file"
chmod 0600 "$token_file"
readonly journal="$scratch/daemon.log"
readonly decrypt_log="$scratch/decrypt.log"
: > "$decrypt_log"

report '2/6 starting a scratch daemon on its own socket'
# SECRETSD_SOCKET redirects only this daemon's listener, never a client on this
# machine, so the box's live secretsd and its registered sessions are untouched.
HOME="$scratch/home" \
  SECRETSD_SOCKET="$socket" \
  SECRETSD_CONFIG="$scratch/config.toml" \
  SECRETSD_SOPS_BIN="$scratch/bin/sops" \
  FAKE_SOPS_PASSTHROUGH=1 \
  FAKE_SOPS_LOG="$decrypt_log" \
  SECRETSD_MEMLOCK=optional \
  "$secrets_bin" serve >"$journal" 2>&1 &
daemon_pid=$!
for _ in {1..200}; do
  [[ -S "$socket" ]] && break
  kill -0 "$daemon_pid" 2>/dev/null || fail "daemon exited during startup: $(<"$journal")"
  sleep 0.05
done
[[ -S "$socket" ]] || fail "daemon never created $socket: $(<"$journal")"
report "   daemon pid $daemon_pid on $socket"

# probe NAME: ask the victim to fetch and check the key as one of its own
# children. Only a success marker crosses back to the harness, never the value.
probe() {
  local name="$1"
  rm -f "$scratch/out/$name" "$scratch/out/$name.err"
  : > "$scratch/out/ask-$name"
  for _ in {1..200}; do
    [[ -e "$scratch/out/$name" ]] && break
    sleep 0.05
  done
  [[ -e "$scratch/out/$name" ]] || fail "the victim never answered probe $name"
  cat "$scratch/out/$name"
}

assert_cached_grant() {
  local decryptions
  decryptions="$(wc -l < "$decrypt_log")"
  ((decryptions == 1)) ||
    fail "the victim's grant was decrypted $decryptions times, expected exactly once"
}

report '3/6 the victim registers its session and is served its key'
# The victim is the registrant and stays alive, so the ancestry check has a
# live root to walk to. Its probes run as its children, which is omp's shape:
# the harness registers once and its tool subprocesses are its children.
# shellcheck disable=SC2016  # perl source: its $variables are perl's, not the shell's
perl -MIO::Socket::UNIX -e '
  my ($sock, $token, $session, $key, $bin, $out, $config, $sops, $token_path, $release, $expected) = @ARGV;
  my $s = IO::Socket::UNIX->new(Type => SOCK_STREAM, Peer => $sock) or die "connect: $!";
  print $s "REGISTER\ttoken=$token\tsession=$session\tpid=$$\n";
  my $reply = <$s>;
  $reply = "[no reply]\n" unless defined $reply;
  open(my $r, ">", "$out/register.tmp") or die;
  print $r $reply or die;
  close $r or die;
  rename "$out/register.tmp", "$out/register" or die;
  exit 1 unless $reply eq "OK\n";
  $ENV{SECRETSD_SOCK} = $sock;
  $ENV{SECRETSD_CONFIG} = $config;
  $ENV{SECRETSD_SOPS_BIN} = $sops;
  $ENV{FAKE_SOPS_PASSTHROUGH} = 1;
  $ENV{SECRETSD_SESSION_TOKEN_FILE} = $token_path;
  until (-e $release) {
    for my $ask (glob("$out/ask-*")) {
      my ($name) = $ask =~ m{/ask-([^/]+)$};
      unlink $ask;
      my $child = fork();
      defined $child or die "fork: $!";
      if ($child == 0) {
        open(STDOUT, ">", "/dev/null") or die;
        open(STDERR, ">", "$out/$name.err") or die;
        exec {$bin} $bin, $key, "--", $^X, "-e",
          q{exit(($ENV{$ARGV[0]} // "") eq $ARGV[1] ? 0 : 1)}, $key, $expected;
        die "exec: $!";
      }
      waitpid($child, 0) == $child or die "waitpid: $!";
      my $result = $? == 0 ? "OK\n" : "FAILED\n";
      open(my $o, ">", "$out/$name.tmp") or die;
      print $o $result or die;
      close $o or die;
      rename "$out/$name.tmp", "$out/$name" or die;
    }
    select(undef, undef, undef, 0.05);
  }
' "$socket" "$victim_token" "$session" "$human_key" "$secrets_bin" "$scratch/out" \
  "$scratch/config.toml" "$scratch/bin/sops" "$token_file" "$scratch/release" "$human_value" &
victim_pid=$!
for _ in {1..200}; do
  [[ -e "$scratch/out/register" ]] && break
  sleep 0.05
done
[[ -e "$scratch/out/register" ]] || fail "the victim never registered: $(<"$journal")"
registered="$(<"$scratch/out/register")"
[[ "$registered" == "OK" ]] || fail "the victim's REGISTER was answered [$registered]"
before="$(probe before)"
[[ "$before" == "OK" ]] || fail "the victim was not served before the claim (stderr: $(<"$scratch/out/before.err"))"
assert_cached_grant
report "   victim pid $victim_pid registered $session and read $human_key"

report "4/6 an outsider claims $session with a token of its own"
# A sibling of the victim, started by this harness: it shares the uid and could
# read the token file, but it is not inside the victim's process tree. This is
# the forking script's position exactly.
# shellcheck disable=SC2016  # perl source: its $variables are perl's, not the shell's
outsider() {
  # Prints the sending process's own pid, then the daemon's reply, so the
  # refusal's `caller_pid` can be checked against the real caller rather than
  # against the (untrusted, deliberately wrong) pid on the wire.
  perl -MIO::Socket::UNIX -e '
    my ($sock, $line) = @ARGV;
    my $s = IO::Socket::UNIX->new(Type => SOCK_STREAM, Peer => $sock) or die "connect: $!";
    print "$$\n";
    print $s "$line\n";
    my $reply = <$s>;
    print defined $reply ? $reply : "[no reply]\n";
  ' "$socket" "$1"
}
mapfile -t claim_lines < <(outsider "REGISTER	token=$outsider_token	session=$session	pid=1")
claim_pid="${claim_lines[0]}"
claim="${claim_lines[1]-}"
report "   outsider pid $claim_pid REGISTER -> [$claim]"
if [[ "$claim" != $'ERR\tFOREIGN_CALLER\t'* ]]; then
  # Not a pass with extra output: this is the incident. Show what the victim
  # now gets, which is the only symptom it ever saw on 2026-11-07.
  displaced="$(probe displaced)"
  fail "the outsider's REGISTER was answered [$claim]; the victim now gets [$displaced] (stderr: $(<"$scratch/out/displaced.err"))"
fi
after_claim="$(probe after-claim)"
[[ "$after_claim" == "OK" ]] ||
  fail "the victim lost its session after the refused REGISTER (stderr: $(<"$scratch/out/after-claim.err"))"
assert_cached_grant
mapfile -t removal_lines < <(outsider "UNREGISTER	session=$session")
removal_pid="${removal_lines[0]}"
removal="${removal_lines[1]-}"
report "   outsider pid $removal_pid UNREGISTER -> [$removal]"
[[ "$removal" == $'ERR\tFOREIGN_CALLER\t'* ]] ||
  fail "the outsider's UNREGISTER was answered [$removal]; a live session is still removable"

report '5/6 the victim is still served after the claim'
after="$(probe after)"
[[ "$after" == "OK" ]] ||
  fail "the victim lost its session to the outsider (stderr: $(<"$scratch/out/after.err"))"
assert_cached_grant

report '6/6 each refusal named the operation, the session and both pids on one line'
# The incident took a day to find because nothing recorded it, so this is not
# satisfied by the three facts appearing somewhere in the log: each refusal
# must carry all of them on its own line, with the caller's real pid rather
# than the one it put on the wire (deliberately 1 above).
refusals="$(grep -c 'refused a claim on a session the caller was not shown to belong to' "$journal" || true)"
((refusals == 2)) || fail "the daemon logged $refusals refusals, expected exactly 2: $(<"$journal")"
for expected in "REGISTER $claim_pid" "UNREGISTER $removal_pid"; do
  operation="${expected% *}"
  caller="${expected#* }"
  line="$(grep "refused a claim on a session the caller was not shown to belong to" "$journal" |
    grep "operation=\"\?$operation\"\?" | grep "caller_pid=Some($caller)" || true)"
  [[ -n "$line" ]] ||
    fail "no refusal line names $operation from caller pid $caller: $(grep refused "$journal")"
  [[ "$line" == *"untrusted_registered_session=\"$session\""* ]] ||
    fail "the $operation refusal does not name the session: [$line]"
  [[ "$line" == *"holder_pid=Some($victim_pid)"* ]] ||
    fail "the $operation refusal does not name the holder pid $victim_pid: [$line]"
done
report 'PASS'
