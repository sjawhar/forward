# src/client

The client half of the `secrets` binary. Reached from `src/bin/secrets.rs` for
any argv that is not `serve`.

## Tier split

`Context::value` forks on one fact: does the key appear in the configured
source roots' `secrets.human.d/` directories?

- **Agent tier** — decrypted here, in-process, by shelling out to sops. The
  daemon is never contacted, no grant exists, no touch happens.
- **Human tier** — brokered. `HumanClient` speaks the socket protocol and blocks
  until the daemon reaches a terminal response.

A key present in both tiers is a hard error for **that key** (`AmbiguousKey`),
never a silent preference for one: the tiers differ in who approves the read,
so letting either win would quietly change that. Other keys are unaffected — a
duplicate must not freeze the store (2026-09-20: one doubled key refused every
human-tier request for twenty minutes). The refusal points at `list`, which
renders a doubled key with an `ALSO agent tier` marker instead of failing.
`list` decrypts the agent-tier files (one sops call per file) and reads
human-tier names from filenames; it never contacts the daemon.

Every write door — `edit-human` (piped or interactive), `edit`/`edit-local` on
a new or existing agent file — takes the same write lock (an exclusive flock
on every configured source root's directory, in configuration order) and holds
it from its cross-tier check through the publish, so two writers cannot each
pass their check and both land; the read-time error is the fallback for stores
assembled out of band (two machines editing different tiers, then syncing) and
for writers that do not take the lock. Against those the existing-file edit
re-reads the original before its rename and refuses if it changed; a writer
landing between that re-read and the rename is not caught (no compare-and-rename
exists), the same window every write here and sops's own in-place edit has. `edit-human` refuses a name the agent
tier holds (`AgentKeyExists`) before reading stdin or touching a file. The
agent doors re-read the human tier under the lock right before publishing
(`ensure_no_human_clash`), so a key created while an editor was open is seen:
a new agent file checks the edited plaintext's names — read through the
zeroizing `PlaintextTemp` buffer — before encrypting; an existing agent file
never lets sops touch the original — sops edits a staged copy beside the
file's referent (a symlinked `secrets.env` is edited through the link, which
stays a link), the stage's names are read from its ciphertext (sops keeps
dotenv names in the clear), and the stage is renamed over the original only if
no name clashes (`HumanKeyExists`) and the original still holds the bytes that
were staged (`AgentFileChangedDuringEdit` otherwise). A sops failure leaves
the original untouched (`SopsEditFailed`).

| File | Owns |
|---|---|
| `cli.rs` | argv dispatch, the `get`/`list`/`edit`/inject surface |
| `../config.rs` | source-root loading and agent-file precedence shared with the daemon |
| `agent.rs` | local sops decryption of `secrets.env`; dotenv name/assignment parsing |
| `human.rs` | broker transport; builds the scoped frame for `GET`/`REQUEST` |
| `edit.rs` | write-door dispatch, the write lock, the publish-time human-tier re-check |
| `edit/new.rs` | creates new edited agent or human files; validates human assignments; `write_piped_human` reads a one-line value from stdin with core dumps disabled and encrypts it directly to the target without a plaintext temp file |
| `edit/existing.rs` | edits an existing agent file: sops on a staged copy, checked, renamed over the referent |
| `edit/plaintext.rs` | the editor's scratch file (`PlaintextTemp`): private, runtime-scoped, scrubbed on drop |
| `response.rs` | parsing broker replies, including exact-length payloads |
| `error.rs` | `CliError` and the agent-facing guidance strings |
| `status.rs` | `get` flag parsing and the JSON status line |

## The `get` contract

Three different operations behind one subcommand — do not collapse them:

| Form | Sends | Prints |
|---|---|---|
| `get KEY` | `REQUEST` | JSON status; pre-authorizes, so it may prompt for a touch |
| `get KEY --value` | `GET` | the secret bytes plus one newline |
| `get KEY --no-request` | `GRANTS` | JSON status only; never prompts |

Bare `get` deliberately does **not** print the value: an agent that runs it and
reads the JSON as the secret will report a working key as a placeholder. The
status path must never send `GET`, or a status check would make the human's key
blink.

## Conventions

Guidance strings for daemon errors start with
`AGENT NOTICE: ask the human; do not retry-loop.` and then say what to do. They
are the only place an agent learns why it was refused, so a new `ErrCode` needs
an arm in both `error.rs` and `response.rs` — the compiler enforces this via
exhaustive matches.

Never render a secret, a token, or any prefix of either into an error. Tests
assert the absence of the token bytes in stderr.
