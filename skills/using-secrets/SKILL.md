---
name: using-secrets
description: "Use BEFORE running any command that needs an API key, token, password, or credential, and whenever a secret looks missing, wrong, truncated, or like a placeholder. This machine has no secrets in the environment — every key comes from the `secrets` CLI, and `secrets get KEY` does NOT print the value. Triggers on: secrets get, secrets list, API key, API token, access token, credential, OPENAI_API_KEY, ANTHROPIC_API_KEY, AIRTABLE_TOKEN, SLACK_MCP_XOXP_TOKEN, GROQ_API_KEY, DEEL_API_KEY, sk-, xoxp-, export KEY=, env var for a command, 'key is a placeholder', 'key looks wrong', 'invalid api key', 401, 403, authentication failed, sops, YubiKey touch, secretsd, secrets_request, SecretsRequest, grant expired, key blinking, TIMEOUT, TOO_MANY_PENDING."
---

# Using `secrets` and the `secrets_request` tool

Every credential on this machine comes from `secrets` (CLI) or `secrets_request` (the MCP
tool, shown as `SecretsRequest` in OpenCode). Nothing is pre-exported into the environment,
so a bare `echo $OPENAI_API_KEY` is empty and that is not a bug.

## The one mistake to never make

`secrets get KEY` does **not** print the secret. It prints a JSON status object and
pre-authorizes the key for this session:

```console
$ secrets get OPENAI_API_KEY
{"key":"OPENAI_API_KEY","tier":"agent"}
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
| `secrets get KEY` | JSON status; pre-authorizes (prompts for a touch if the key needs one) |
| `secrets get KEY --ttl 8h` | same, but the freshly created grant lives up to 8h instead of the 12h default (operator use; capped server-side, ignored on a live grant) |
| `secrets get KEY --value` | prints the secret |
| `secrets get KEY --no-request` | status only; never prompts |
| `secrets KEY [KEY2 ...] -- cmd` | runs `cmd` with the keys in its environment |
| `secrets list` | every key name and its tier; never decrypts |
| `secrets grants` | which human-tier keys are currently unlocked |
| `secrets_request(KEY)` tool call | requests approval only; never returns the value |

## Two tiers

`secrets list` marks each key. **Agent-tier** keys resolve locally and need no approval.
**Human-tier** keys are unlocked by a physical YubiKey touch: one request per key per
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
