---
name: using-secrets
description: "Use BEFORE running any command that needs an API key, token, password, or credential, when storing, adding, or rotating one, and whenever a secret looks missing, wrong, truncated, or like a placeholder. This machine has no secrets in the environment — a Legion credential broker session gets keys from `secret-run`, any other from the `secrets` CLI, and `secrets get KEY` does NOT print the value. Triggers on: secrets get, secrets list, API key, API token, access token, credential, OPENAI_API_KEY, ANTHROPIC_API_KEY, AIRTABLE_TOKEN, SLACK_MCP_XOXP_TOKEN, GROQ_API_KEY, DEEL_API_KEY, sk-, xoxp-, export KEY=, env var for a command, 'key is a placeholder', 'key looks wrong', 'invalid api key', 401, 403, authentication failed, sops, YubiKey touch, secretsd, secrets_request, SecretsRequest, grant expired, key blinking, TIMEOUT, TOO_MANY_PENDING, store a secret, add a key, add a secret, save a token, rotate a credential, rotate a key, secrets edit-human, secrets edit, secrets edit-local, secrets sources, sops set."
---

# Using `secrets` and the `secrets_request` tool

A credential a service or app uses is a resource declared in infrastructure code, minted from a seed credential a person created. Never mint a downstream credential by hand — not by curling a provider API with an admin token, and not by requesting a one-off broker secret to do it. Revert any credential minted out of band.

## In an agent session the Legion credential broker serves

When `agent-secrets identity` exits 0, this session gets its keys from the Legion credential
broker, not from secretsd. Run a command that needs a key through `secret-run`:

```bash
secret-run [--reason R] [--wait D] [--ttl D] KEY... -- cmd [args...]
```

`secret-run` asks the credential broker and runs `cmd` with each granted key in its
environment. A human-tier key then waits up to `--wait` (default 30m) for the human to approve
it in Dispatch, not for a YubiKey touch; the waiting message says who approves it and where.
`--ttl` ends the grant after that long, instead of when the session ends. `D` is a Go
duration, such as `30s` or `5m`. In such a session `secret-run` never falls back to secretsd.
In any other session or shell, it runs `secrets KEY... -- cmd` and drops `--reason`, `--wait`
and `--ttl`.

The credential broker's key names can differ from secretsd's: its `GITHUB_ADMIN_PAT` is
secretsd's `GITHUB_ADMIN_PAT_THEOREM`. `agent-secrets secret list` shows the keys the
credential broker holds.

The rest of this skill describes secretsd, and there "the broker" and "the daemon" mean
secretsd. secretsd is for the human's own shells and for sessions the Legion credential broker
does not serve. There, every credential comes from `secrets` (CLI) or `secrets_request` (the
MCP tool, shown as `SecretsRequest` in OpenCode). Nothing is pre-exported into the
environment, so a bare `echo $OPENAI_API_KEY` is empty and that is not a bug.

## The one mistake to never make

`secrets get KEY` does **not** print the secret. It prints a JSON status object and
pre-authorizes the key for this session:

```console
$ secrets get OPENAI_API_KEY
{"key":"OPENAI_API_KEY","tier":"agent","store":"sops file","source":"dotfiles","path":"/home/you/.dotfiles/secrets.env"}
```

That JSON **is not the value**. It is not a placeholder, it is not a truncated key, and its
character count means nothing. If you were about to report that a key "looks like a
placeholder" or is "only 14 characters", you are reading the status object — re-read this
section instead of telling the human their key is broken.

## Grant lifetime: not minutes

Once a human-tier key is granted, it stays granted **for the session's entire lifetime**. It
does not expire after a few minutes, after a tool call boundary, or because "a while" has
passed. If a key that was granted earlier in this session suddenly fails, the actual causes
are:

- **The daemon restarted.** It lost every registration and grant with it. Retry the command
  **once** — the plugin re-registers automatically — and expect one fresh touch.
- **The session ended, or was replaced** (`/new` or an equivalent session switch). Each
  session has its own grants; a new one starts with none.
- **`secrets lock` ran.** It wipes every grant on the daemon, for every session, on purpose.
- **The key's backing file was edited or rotated.** The daemon invalidates a grant the moment
  the ciphertext it decrypted changes; the next request needs a fresh touch.
- **The grant's own backstop expired.** 12h by default, or up to a day when the
  caller ran `secrets get KEY --ttl <duration>`. Vanishingly unlikely inside a
  normal agent session.

"Grants expire quickly" is a superstition, not a fact — forming it and blaming the broker for
an unrelated failure (a typo'd key name, a missing config entry, your own retry loop) is
exactly the mistake this section exists to prevent. Anything else means the grant is **not**
the problem — read the error table below.

## Request before unattended work

Do this **at the start of a task**, while the human is at the keyboard — never mid-flight
into long unattended work:

1. Run `secrets list` and work out every human-tier key the task will need.
2. For each one, **announce it in chat before requesting it**: "Requesting `DEEL_API_KEY` —
   your YubiKey will blink; please touch it."
3. Call `secrets_request(KEY)` (or run `secrets get KEY`, which triggers the same approval
   flow) and wait for the grant before moving to the next key.

A request that nobody is watching **times out after 90 seconds** and the daemon reports
`TIMEOUT` — that is not a broker error, it is an unwatched request expiring. Starting a long
unattended run and only then discovering a key needs a touch means the run dies waiting on a
human who was never told to look. Front-load every request while attention is on you.

## One at a time

Never fire multiple `secrets_request` (or `secrets get KEY`) calls in parallel. The daemon
services one YubiKey decrypt at a time, and each key needs its own physical touch a human
can attribute to a specific request. Parallel requests just stack blinks nobody can tell
apart: they queue one at a time, any the human does not touch dies as `TIMEOUT` after 90
seconds, and stacking more than three pending requests fails immediately with
`TOO_MANY_PENDING`. Request, wait for the grant (or denial), then request the next.

## Subagents inherit the parent's grants — don't re-request

Grants belong to the whole in-process session tree, not to one call. In omp, every subagent
you dispatch automatically shares the root session's token and its grants; nothing separate
needs to run for a subagent to use a key the root already has. Concretely:

- Get every human-tier grant the task needs **in the parent**, before dispatching subagents.
- A subagent must **never** be the one to call `secrets_request` for a human-tier key — it has
  no way to guarantee the human is watching for its blink, and the grant would land on the
  shared session anyway. If a subagent hits a key it does not have, that is a sign the parent
  skipped the request-before-dispatch step above, not something for the subagent to fix.

## What to run

**Running a command that needs the secret — do this by default:**

```bash
secrets OPENAI_API_KEY -- python script.py
secrets SLACK_MCP_XOXP_TOKEN -- slack-mcp-server
secrets AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY -- terraform apply
```

The value is placed in the child process's environment and never printed, so it cannot
land in the transcript. Prefer this over every other form.

**Checking that a read works** (diagnosing a broken shim, a fallback path, a
registration) is the same form with a command that reveals only the length:

```bash
secrets GH_PUBLIC_REPO_PAT -- sh -c 'echo len=${#GH_PUBLIC_REPO_PAT}'
```

A read that works prints `len=N`. A failure that involved the broker at all carries
`AGENT NOTICE: ask the human; do not retry-loop.` and the table below names the causes;
any other error is the client's own and prints plainly — the key is in no source root,
sops cannot decrypt a source, a dotenv file is malformed, the command would not run. The
notice is the signal to act on, not the tier: an agent-tier key never reaches the broker,
and a human-tier read can still fail plainly, because the client decrypts every agent-tier
source before it looks the key up and the value can arrive but the command still fail to
exec. This is the only acceptable probe — `--value` as a "does it work" check put a live
token in a transcript on 2026-09-17.

**Only when you genuinely need the bytes** (piping into a file, building a header):

```bash
secrets get OPENAI_API_KEY --value
```

This prints the secret, so it will appear in the transcript. Never run it to look at a
key, never run it to test whether the read works (use the length form above), and never
paste its output into a message. A value in a transcript means a rotation.

**Other forms:**

| Command | Does |
|---|---|
| `secrets get KEY` | JSON status naming the store that answers; pre-authorizes (prompts for a touch if the key needs one) |
| `secrets get KEY --ttl 8h` | same, but the freshly created grant lives up to 8h instead of the 12h default (operator use; capped server-side, ignored on a live grant) |
| `secrets get KEY --value` | prints the secret on stdout, and its store on stderr |
| `secrets get KEY --no-request` | status only; never prompts |
| `secrets KEY [KEY2 ...] -- cmd` | runs `cmd` with the keys in its environment, after one stderr line naming each key's store |
| `secrets list` | every key name with its tier and source; decrypts agent-tier files locally, never contacts the daemon or prompts; a key in both tiers is marked `ALSO agent tier` |
| `secrets grants` | which human-tier keys are currently unlocked |
| `secrets_request(KEY)` tool call | requests approval only; never returns the value |

## Which store answered

This machine may run more than one `secrets`-style CLI, each with its own store, and both
answer the same key names. Every answer from this one says so, and the store is part of what
you report:

- status prints `"store":"sops file"` with the file, or `"store":"secretsd daemon"` with the
  source root and the socket;
- a value or an injection writes one line to stderr first, such as
  `secrets: OPENAI_API_KEY from agent tier, source dotfiles (/home/you/.dotfiles/secrets.env)`;
- a refusal names every place this CLI looked.

Never tell the human a key is wrong, missing or stale without naming the store you read, and
never say a key came from a store this output did not name.

## Storing a secret

A value goes in through stdin, never argv: argv shows up in `ps`, in shell history and in transcripts. `secrets sources` prints each source root as `source <name>: <path>`. `--source` takes the `<name>`; the files live under the `<path>`.

| Tier | Create or rotate `KEY` |
|---|---|
| human | Piped into `secrets edit-human KEY --source <name>`, one line on stdin is encrypted straight into the root's `secrets.human.d/`; no plaintext file is written. `--local` writes the machine-local, uncommitted file instead. Creating a key needs no touch; reading it later does. |
| agent | `secrets edit --source <name>` opens the root's shared `secrets.env` in an editor, and `secrets edit-local --source <name>` the machine-local `secrets.local.env`. To create an absent file, use the matching `secrets edit` route first. Without an editor, once the file exists, pipe the value through `jq -R .` (sops takes a JSON string) into `sops set --value-stdin`. `sops set` cannot create a missing file and skips the CLI's check for a human-tier key of the same name, so run `secrets list` first: if it shows `KEY  (human tier: …)`, choose another name. |

```bash
# human tier
<producer> | secrets edit-human KEY --source <name>

# agent tier, without an editor
secrets list    # stop if it shows KEY  (human tier: …)
<producer> | jq -R . | sops set --value-stdin <path>/secrets.env '["KEY"]'

# a JSON credential: compact it to one line first
# human tier
<producer> | jq -c . | secrets edit-human KEY --source <name>
# agent tier
secrets list    # stop if it shows KEY  (human tier: …)
<producer> | jq -c . | jq -R . | sops set --value-stdin <path>/secrets.env '["KEY"]'

# a multi-line value that is not JSON: base64 it to one line, under a name ending _B64
# human tier
<producer> | base64 | tr -d '\n' | secrets edit-human KEY_B64 --source <name>
# agent tier
secrets list    # stop if it shows KEY_B64  (human tier: …)
<producer> | base64 | tr -d '\n' | jq -R . | sops set --value-stdin <path>/secrets.env '["KEY_B64"]'

# read it back decoded, never printed, into a consumer that reads the key on stdin
secrets KEY_B64 -- sh -c 'printf %s "$KEY_B64" | base64 -d | <consumer>'
# or into a private file that sh removes on exit
secrets KEY_B64 -- sh -c 'f=$(mktemp) && trap "rm -f \"\$f\"" EXIT && printf %s "$KEY_B64" | base64 -d > "$f" && <consumer> "$f"'
# or, for a file over about 96 KiB, piped in instead of injected
secrets get KEY_B64 --value | sh -c 'f=$(mktemp) && trap "rm -f \"\$f\"" EXIT && base64 -d > "$f" && test -s "$f" && <consumer> "$f"'
```

`<producer>` is the command that prints the value on stdout, such as a password manager's CLI or another tool's export command; when the value is already a file, `base64 < FILE` replaces `<producer> | base64`. Typing the value into the command line, as in `printf '<value>' | …`, puts it in the transcript and the shell history all the same.

The stored value must be one line; a trailing newline is dropped. Pretty-printed JSON spans several lines, so compact it with `jq -c .` as above; any other multi-line value, such as a PEM or OpenSSH private key, goes in base64-encoded under a name ending `_B64`. Piped in as is, a multi-line value fails loudly and writes nothing: `edit-human` reports `piped secret 'KEY' must be one single-line assignment value`, and `sops set` reports `Value for --set is not valid JSON`, because `jq -R .` turned each line into its own JSON string. `jq -Rs .` is no way around that: it stores the value, but sops's dotenv format writes each newline as the two characters `\n`, so the value reads back as one line.

A human-tier read returns at most 4096 bytes, so a human-tier `_B64` key holds a file of at most 3072 bytes (`wc -c < FILE`), too few for a 4096-bit RSA key; a larger file fits only the agent tier, because a larger human-tier key stores without error and then fails every read with `secretsd returned an invalid response`. The stdin form needs a consumer that reads the key from stdin, such as `ssh-keygen -y -f /dev/stdin`; otherwise use a file form, which skips `<consumer>` when `base64 -d` rejects a corrupt value. Keep the file and its `trap` inside that `sh -c`: an omp session on an older binary does not run a subshell's `EXIT` trap, and no omp bash tool call runs an `EXIT` trap set at its top level, so `( file=$(mktemp); trap … EXIT; … )` or a top-level `trap` can leave the decoded key on disk. Injection fails with `Argument list too long` once the encoded value passes the kernel's 128 KiB limit on one environment string, at about 96 KiB of file; the piped form has no such limit, and its `test -s` keeps a failed read from reaching `<consumer>`.

A key in a shared file, `secrets.human.d/KEY.env` or `secrets.env`, lives in the root's repository: commit and push that file, so the other machines get it. `--local` and `secrets edit-local` write machine-local files that are never committed. `edit-human` refuses a name the agent tier already holds, and the human tier refuses a name present in two roots. To rename a human-tier key, write it under the new name and delete the old file in the same change.

## Two tiers

`secrets list` marks each key. **Agent-tier** keys resolve locally and need no approval.
In secretsd, **human-tier** keys are unlocked by a physical YubiKey touch: one request per key per
session makes the human's key blink, and every later request for that same key in that same
session is free. In omp, "that same session" is the whole session tree — root or any of its
subagents share one grant. In OpenCode, registration is per session id; a sibling session
does not inherit another session's grants.

## When it refuses

Any failure that involved the broker starts with `AGENT NOTICE: ask the human; do not
retry-loop.` Take that literally: except for the two rows below that say otherwise,
re-running will not help, and a retried request that does reach the approval queue makes
the human's key blink again. Anything printed without that notice is the client's own
error — a missing key, a source sops cannot decrypt, a malformed dotenv, a command that
would not run — and re-running changes nothing there either until the cause is fixed.

**The message already says what happened.** The daemon ships one guidance string per error
code, next to the code that raises it, so that text is what to believe about the cause —
this table only says what to *do*. Don't infer a cause it didn't state: several of these
codes cover more than one fault.

| Message contains | Do |
|---|---|
| `not human-tier` | read it directly with `--value` or inject it; no approval is involved |
| `neither a terminal tty nor a session token` | ask the human to run it, or run inside the agent session |
| `outside that session's process tree` | run the request from this session. If it *is* this session, its registration is stale — restart the session rather than retrying |
| `secretsd failed while decrypting` | read `journalctl --user -u secretsd` for the daemon's *classification* of the failure (`sops_failure=…`). sops' own output is never logged — it can quote what it just decrypted — so do not go looking for it |
| `secret 'X' not found` | ask the human to add it; never invent a value |
| `the broker restarted` | run the command **once** more — the plugin re-registers between commands, so expect a touch. Twice means tell the human |
| `TIMEOUT` | tell the human *before* requesting again; the daemon's guidance is to wait for them rather than retry blind. If they say they touched it, read the journal before asking for another |
| `timed out waiting for approval` | this is the *client* giving up, not the daemon refusing — the daemon may still be working. Tell the human and read the journal before requesting again |
| `TOO_MANY_PENDING` | stop; wait for the pending request to resolve before requesting again |

## Never

- Never paste a secret's value into a message, a commit, a log, or a file.
- Never write a secret into a script, a `.env`, or a shell history line.
- Never conclude a key is wrong from `secrets get` output — that output is status, not the key.
- Never retry after an `AGENT NOTICE`, with two exceptions: `the broker restarted` clears itself once the plugin re-registers, so run that command **once** more; and the daemon's `TIMEOUT` — not the client's `timed out waiting for approval` — may be requested once more *after* telling the human. Never loop.
- Never conclude "grants expire quickly" from a failure — it is one of the causes in Grant lifetime above, or an unrelated bug, never the grant itself.
- Never request keys mid-flight into unattended work, and never fire `secrets_request` calls in parallel — see the two sections above.
- Never have a subagent request a human-tier key; request it in the parent before dispatching.
