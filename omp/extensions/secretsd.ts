/**
 * secretsd extension for oh-my-pi (omp).
 *
 * Mirrors the OpenCode plugin (../../opencode/plugins/secretsd.ts) using omp's
 * ExtensionAPI, and imports the protocol client from it so the broker protocol
 * stays single-sourced:
 *
 * - registers the session with the secretsd broker and writes its token file
 * - mirrors SECRETSD_SESSION_TOKEN_FILE into the omp process environment, which
 *   is how every child inherits the tree's broker identity: agent shells (omp
 *   rebuilds its cached shell spawn environment from it), MCP stdio servers and
 *   LSP servers alike, letting `secrets` CLI calls inside them act with this
 *   session's identity (human-tier keys included, after approval)
 * - keeps that identity usable through a side-effect-only `tool_call` /
 *   `user_bash` hook, which re-materializes a deleted token file and recovers
 *   from a daemon restart without replacing the bash tool or touching commands
 * - registers the secrets_request tool, which never sends a human-tier key to
 *   secretsd: it refuses with the Legion credential broker command instead
 *   (see `HumanTierGate`)
 * - exposes the bundled using-secrets skill
 * - unregisters and removes the token file on shutdown
 *
 * Session IDs: omp mints UUIDv7s, which satisfy the plugin's SESSION_ID_PATTERN.
 *
 * Process-shared identity: omp re-invokes `loadExtensions` for every
 * in-process subagent session, so each Extension binds to THAT session's own
 * `ExtensionAPI` (cwd, eventBus, runtime) -- `secretsdOmpExtension` therefore
 * runs once per session, root and every subagent alike, each getting a fresh
 * closure with no module state shared between them. Neither `SessionStartEvent`
 * nor `ExtensionContext` carries a root/subagent indicator (checked against
 * `@earendil-works/pi-coding-agent`'s published extension types: no such field
 * exists), so identity is anchored on `globalThis` instead of per-instance
 * state: the first instance to observe `session_start` in this OS process
 * mints the token and registers with the broker (the OWNER); every later
 * instance -- always a subagent, since subagents are created only after the
 * root session has already started -- adopts that anchor and never mints a
 * token or registers a scope of its own. Because subagents run in the SAME
 * process as the root (in-process `loadExtensions`, not a spawned child), the
 * daemon's `SO_PEERPIDFD` ancestry pin taken at REGISTER names that one shared
 * process regardless of which instance happened to call `register`. This is
 * what makes a subagent's shells and secrets_request act as the root
 * session -- extending docs/design.md's "the token-file path is inherited by
 * everything the session spawns" from a single session's process tree to the
 * whole in-process session tree.
 */
import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
	BrokerClient,
	failureOutcome,
	guidance,
	issueTokenFile,
	removeTokenFile,
	requestSecret,
	resolveRuntimeDir,
	resolveSocketPath,
	restoreTokenFile,
	type RequestOutcome,
	type SessionState,
} from "../../opencode/plugins/secretsd.ts";

const extensionDir = dirname(fileURLToPath(import.meta.url));
// One level up from omp/extensions/ is omp/; two is the package root, whose
// skills/ directory ships the using-secrets skill. v2.5.1 shipped an
// off-by-one ("../../../skills" = the package's PARENT), silently advertising
// a directory that does not exist; omp's own plugin sub-discovery masked it.
const SKILLS_DIRECTORY = resolve(extensionDir, "../../skills");

/// The process-wide identity every `secretsdOmpExtension` instance shares: one
/// token, one broker registration, one BrokerClient, regardless of how many
/// in-process sessions (root + subagents) load this extension.
export type SharedAnchor = {
	ownerSessionId: string;
	state: SessionState;
	runtimeDir: string;
	broker: BrokerClient;
	brokerInstance: string;
	registered: boolean;
	registration: Promise<void> | null;
	/// Aborts every in-flight `secrets_request` pinned to this anchor. Fired
	/// by the owner's `session_shutdown` and by the re-key path in
	/// `session_info_changed` -- both BEFORE the token file disappears or the
	/// broker registration is torn down -- so a request racing teardown fails
	/// loudly instead of resurrecting a dead anchor's registration.
	abort: AbortController;
};

/// `Symbol.for` (not a module-level `let`) because omp's per-session
/// `loadExtensions` call may or may not share this module's instance across
/// sessions; `globalThis` is correct either way.
export const SHARED_ANCHOR_KEY = Symbol.for("secretsd.omp.session");

/// The process-shared anchor accessor: the read/write seam every instance
/// (and every test) uses instead of touching `globalThis` directly.
export function getAnchor(): SharedAnchor | undefined {
	return (globalThis as Record<PropertyKey, unknown>)[SHARED_ANCHOR_KEY] as SharedAnchor | undefined;
}

export function setAnchor(anchor: SharedAnchor | undefined): void {
	(globalThis as Record<PropertyKey, unknown>)[SHARED_ANCHOR_KEY] = anchor;
	// Mirror the anchor's token file into the process environment. This is the
	// ONLY way the identity travels: omp rebuilds its cached shell spawn
	// environment from `process.env` once the session-identity handlers have
	// run, so every agent shell inherits it, and children spawned outside the
	// bash tool (MCP stdio servers, LSP servers) inherit that env verbatim.
	if (anchor) process.env.SECRETSD_SESSION_TOKEN_FILE = anchor.state.tokenFile;
	else delete process.env.SECRETSD_SESSION_TOKEN_FILE;
}

function createAnchor(sessionID: string): SharedAnchor {
	const runtimeDir = resolveRuntimeDir(undefined, process.env.XDG_RUNTIME_DIR, process.getuid?.());
	if (!runtimeDir) throw new Error("secretsd runtime directory unavailable");
	const state = issueTokenFile(runtimeDir, sessionID);
	const broker = new BrokerClient(resolveSocketPath(undefined, process.env.SECRETSD_SOCK, runtimeDir), (instance) => {
		// A new instance id means the daemon restarted and dropped every
		// registration; forget ours so the next use re-registers. Read the
		// anchor fresh: by the time a handshake resolves, session_info_changed
		// may have re-keyed it to a new SharedAnchor object.
		const anchor = getAnchor();
		if (!anchor) return;
		if (anchor.brokerInstance && instance !== anchor.brokerInstance) {
			anchor.registered = false;
		}
		anchor.brokerInstance = instance;
	});
	return {
		ownerSessionId: sessionID,
		state,
		runtimeDir,
		broker,
		brokerInstance: "",
		registered: false,
		registration: null,
		abort: new AbortController(),
	};
}

/// First `session_start` in the process wins ownership of the shared anchor;
/// every later instance (always a subagent) adopts it. The read-then-write is
/// synchronous end to end -- no `await` in between -- so two in-process
/// `session_start` handlers can never race this check.
function claimOrAdoptAnchor(sessionID: string): { anchor: SharedAnchor; owner: boolean } {
	const existing = getAnchor();
	if (existing) return { anchor: existing, owner: false };
	const anchor = createAnchor(sessionID);
	setAnchor(anchor);
	return { anchor, owner: true };
}

function ensureTokenFile(anchor: SharedAnchor): void {
	if (!existsSync(anchor.state.tokenFile)) {
		restoreTokenFile(anchor.runtimeDir, anchor.ownerSessionId, anchor.state);
	}
}

/// Throws if `anchor` is no longer the process-shared anchor, or its session
/// already tore down, by the time this fence runs. Every path that can
/// register or re-register on `anchor`'s behalf calls this first -- and, for
/// `ensureRegistered`, again right before actually sending REGISTER -- so a
/// call that started against a live anchor (a probe fired from
/// `refreshBrokerIdentity`, a queued `secrets_request`) can never resume after
/// `session_shutdown` or a `session_info_changed` re-key has retired it.
function assertAnchorLive(anchor: SharedAnchor): void {
	if (getAnchor() !== anchor || anchor.abort.signal.aborted) {
		throw new Error("secretsd session ended during the request");
	}
}

async function ensureRegistered(anchor: SharedAnchor): Promise<SessionState> {
	assertAnchorLive(anchor);
	if (anchor.registered) {
		try {
			await anchor.broker.probe();
		} catch {
			// Unreachable broker: keep the belief; the request itself reports.
		}
		if (anchor.registered) return anchor.state;
	}
	if (anchor.registration) {
		await anchor.registration;
		return anchor.state;
	}
	// Re-check right before committing to a REGISTER: the probe above awaited
	// a round trip, during which teardown or a re-key may have retired this
	// anchor.
	assertAnchorLive(anchor);
	const registration = anchor.broker
		.register(anchor.state, anchor.ownerSessionId, process.pid)
		.then(async () => {
			if (getAnchor() !== anchor || anchor.abort.signal.aborted) {
				// Retired while REGISTER was on the wire: the daemon now
				// believes this token is registered, but nobody here does.
				// Compensate so it doesn't keep a live scope for an anchor
				// this process has abandoned, and never flip `registered`.
				try {
					await anchor.broker.unregister(anchor.ownerSessionId);
				} catch {
					// Best-effort: daemon reaps dead pids on its own.
				}
				throw new Error("secretsd session ended during the request");
			}
			anchor.registered = true;
		})
		.finally(() => {
			anchor.registration = null;
		});
	anchor.registration = registration;
	await registration;
	return anchor.state;
}

/// The side effects the bash hook performs on the way past, for every agent
/// shell in the process tree -- owner and subagent alike. It returns nothing
/// and changes nothing the model or the user can see.
///
/// The token file itself does NOT travel from here: `setAnchor` mirrors it into
/// the omp process environment, and omp's own bash tool spawns with that. Until
/// v3.5.1 this extension instead REPLACED the bash tool to inject the variable,
/// which silently cost every parameter omp's own tool declares -- `async`,
/// named services, `cwd`, `pty` -- because the replacement carried the legacy
/// schema. Rewriting the command to carry an `export` is the other way to lose:
/// a `tool_call` revision is what omp schedules, renders and persists, so every
/// bash call in the transcript would open with the token path.
export function refreshBrokerIdentity(): void {
	const anchor = getAnchor();
	if (!anchor) return;
	// Fired, not awaited: this resolves after the command it precedes has
	// already spawned. What it buys is the NEXT call -- if the daemon
	// restarted, the probe's handshake carries a new instance id, which flips
	// `anchor.registered` false and re-registers the SAME token in the
	// background, so the skill's "run the command once more" finds a live
	// registration instead of repeating the same TIMEOUT.
	void ensureRegistered(anchor).catch(() => {});
	try {
		ensureTokenFile(anchor);
	} catch {
		// A token file that cannot be re-materialized is reported by the
		// `secrets` call that needs it, never by failing the bash call that
		// was about to run.
	}
}

/// What `secrets get --no-request KEY` says about a key's tier. It never asks
/// for a grant, so it never costs a touch. Its `grant` field is not read: the
/// CLI fills it from the daemon's whole grant table (GRANTS carries no token),
/// so it is true when ANY session holds the key.
export type KeyStatus = { tier: string } | { error: string };

/// The two facts `secrets_request` needs before it may ask secretsd for a key.
///
/// An agent's request for a human-tier key is refused here and never reaches
/// the daemon. The daemon's only prompt for such a key is a YubiKey blink, and
/// the key's firmware gives a touch about 15 seconds, so the request times out
/// unless the human is at the key. On 2026-10-25 Sami told agents to stop using
/// the YubiKey instead of the credential broker
/// (dispatch://INFRA-223/ask/d2bfc2df-9399-42a9-90b8-35b9f5a46d66), and on
/// 2026-11-01 he said again to get the admin token from the broker
/// (dispatch://INFRA-26/ask/1dc621e8-1e52-4b4c-ae1a-ac296d7f81f7); that day 13
/// human-tier requests still went to secretsd, and each one timed out
/// (`sops_failure="yubikey-stanza-undecryptable"`, then `decision="TIMEOUT"`).
/// The Legion credential broker sends an approval card to the human's Dispatch
/// inbox and grants for the session, so the refusal names its `secret-run`
/// command, or, for a session the broker does not serve, how to relaunch it.
/// Tests replace both members.
export type HumanTierGate = {
	status(key: string): Promise<KeyStatus>;
	brokerIdentity(): Promise<boolean>;
};

async function run(argv: string[]): Promise<{ code: number; stdout: string; stderr: string }> {
	const child = Bun.spawn(argv, { stdin: "ignore", stdout: "pipe", stderr: "pipe", env: process.env });
	const [stdout, stderr, code] = await Promise.all([
		new Response(child.stdout).text(),
		new Response(child.stderr).text(),
		child.exited,
	]);
	return { code, stdout, stderr };
}

export const defaultHumanTierGate: HumanTierGate = {
	async status(key) {
		try {
			const { code, stdout, stderr } = await run(["secrets", "get", "--no-request", key]);
			const reason = stderr.trim().split("\n")[0];
			if (code !== 0) return { error: reason || `secrets get --no-request exited ${code}` };
			const parsed: unknown = JSON.parse(stdout);
			if (typeof parsed !== "object" || parsed === null || !("tier" in parsed) || typeof parsed.tier !== "string") {
				return { error: "secrets get --no-request printed no tier" };
			}
			return { tier: parsed.tier };
		} catch (error) {
			return { error: String(error) };
		}
	},
	async brokerIdentity() {
		try {
			return (await run(["agent-secrets", "identity"])).code === 0;
		} catch {
			return false;
		}
	},
};

export const humanTierGate: HumanTierGate = { ...defaultHumanTierGate };

/// secretsd names the credential broker holds under another name: the same
/// token (Sami, in chat to the chief of staff, 2026-11-02).
const BROKER_NAMES: Readonly<Record<string, string>> = {
	GITHUB_ADMIN_PAT_THEOREM: "GITHUB_ADMIN_PAT",
};

/// Where an agent gets a human-tier key instead: the broker command, or, for a
/// session the broker does not serve, the relaunch line that makes it one.
export function brokerRoute(key: string, sessionID: string, registered: boolean): string {
	const brokerName = BROKER_NAMES[key];
	const name = brokerName ?? key;
	const lines: string[] = [];
	if (brokerName) {
		lines.push(
			`The broker holds this same token under the name ${brokerName}; ${key} is secretsd's name for it (Sami, in chat to the chief of staff, 2026-11-02).`,
		);
	}
	if (registered) {
		lines.push(
			`Ask the broker; an approval card reaches Sami in Dispatch and the grant lasts the session:\n    secret-run --reason "<what for>" ${name} -- <command>`,
		);
	} else {
		lines.push(
			`This session has no broker identity: it was not launched through ~/.dotfiles/shims/omp. Relaunch it from a shell whose PATH starts with ~/.dotfiles/shims:\n    omp --resume ${sessionID}\nthen ask the broker:\n    secret-run --reason "<what for>" ${name} -- <command>`,
		);
	}
	return lines.join("\n");
}

export function brokerOnlyGuidance(key: string, sessionID: string, registered: boolean): string {
	return [
		`refused: ${key} is human tier. secretsd's only prompt for it is a YubiKey blink that times out in about 15 seconds unless Sami is at the key, so nothing was requested. Agents get human-tier credentials from the Legion credential broker: Sami said so on 2026-10-25 (dispatch://INFRA-223/ask/d2bfc2df-9399-42a9-90b8-35b9f5a46d66) and again on 2026-11-01 (dispatch://INFRA-26/ask/1dc621e8-1e52-4b4c-ae1a-ac296d7f81f7), and 13 secretsd requests timed out on 2026-11-01.`,
		brokerRoute(key, sessionID, registered),
	].join("\n");
}

export default function secretsdOmpExtension(pi: ExtensionAPI) {
	const z = pi.zod;
	let isOwner = false;
	let claimed = false;
	// Captured at `session_start` so `secrets_request`'s lazy-reclaim path
	// (getAnchor() undefined -- a failed/torn-down claim) has this instance's
	// own session id to claim under, without re-deriving it from `ctx`.
	let ownSessionId: string | undefined;
	const requestAbort = new AbortController();

	function toolResult(key: string, outcome: RequestOutcome) {
		const text = guidance(outcome);
		const isError = !(
			outcome.kind === "granted" ||
			(outcome.kind === "daemon-error" && (outcome.code === "NOT_HUMAN_KEY" || outcome.code === "DENIED"))
		);
		return {
			content: [{ type: "text", text: `${key}: ${text}` }],
			isError,
			details: { key, outcome: outcome.kind },
		};
	}

	pi.on("resources_discover", async () => ({ skillPaths: [SKILLS_DIRECTORY] }));

	pi.on("session_start", async (_event, ctx: ExtensionContext) => {
		const sessionID = ctx.sessionManager.getSessionId();
		ownSessionId = sessionID;
		try {
			// Decide ownership at most once per instance -- a "reload"
			// session_start firing again on an already-adopting (non-owner)
			// instance must never re-run the first-wins race UNLESS the anchor
			// itself is gone: a torn-down or never-claimed anchor stranding the
			// whole tree is worse than a subagent claiming it, so ANY instance --
			// owner or subagent -- that observes a missing anchor here may claim
			// it (still the synchronous, race-free read-then-write below).
			if (!claimed || !getAnchor()) {
				const claim = claimOrAdoptAnchor(sessionID);
				isOwner = claim.owner;
				claimed = true;
			}
			const anchor = getAnchor();
			if (!anchor) throw new Error("secretsd anchor unavailable");
			await ensureRegistered(anchor);
		} catch (err) {
			// Broker down (or runtime dir unavailable) must not block the
			// session; tools report the details.
			ctx.ui.notify(`secretsd: registration deferred (${String(err)})`, "warning");
		}
	});

	// Side-effect only, by contract: omp owns the bash tool, its schema and its
	// spawn environment. Returning a revision here would put an `export` into
	// the persisted call; registering our own tool would drop half its
	// parameters. `user_bash` is omp's `!` shell, which never emits `tool_call`.
	pi.on("tool_call", async (event) => {
		if (event.toolName === "bash") refreshBrokerIdentity();
	});

	pi.on("user_bash", async () => {
		refreshBrokerIdentity();
	});

	/// Re-key the tree when the owner's session id changes. Registered below
	/// under every name a host may emit for that, because the hosts disagree.
	const reKeyOnSessionIdChange = async (_event: unknown, ctx: ExtensionContext) => {
		// A subagent's own session id never changes, and it must never mint the
		// whole tree a second identity -- only the owner re-keys the anchor.
		if (!isOwner) return;
		const id = ctx.sessionManager.getSessionId();
		const previous = getAnchor();
		if (!id || !previous || id === previous.ownerSessionId) return;

		// Session id can change on new/switch/fork; a new logical session is a
		// new presence-proof scope (docs/design.md "Grant lifecycle"), so mint a
		// fresh token and re-register rather than reusing the retiring one.
		let next: SharedAnchor;
		try {
			next = {
				...previous,
				ownerSessionId: id,
				state: issueTokenFile(previous.runtimeDir, id),
				registered: false,
				registration: null,
				// A fresh controller: `next` is a new presence-proof scope, so it
				// must not inherit `previous.abort`, which is about to fire.
				abort: new AbortController(),
			};
		} catch {
			return; // Could not mint a fresh token; keep the retiring anchor intact.
		}
		setAnchor(next);
		// Fence BEFORE unregistering/removing the token file: any
		// `secrets_request` still in flight against `previous` must fail loudly
		// rather than resurrect it via `reregister`.
		previous.abort.abort();
		removeTokenFile(previous.state);
		if (previous.registered) {
			try {
				await previous.broker.unregister(previous.ownerSessionId);
			} catch {
				// Best-effort: daemon reaps dead pids on its own.
			}
		}
		try {
			await ensureRegistered(next);
		} catch {
			// Broker down must not block the session switch; the next request
			// (secrets_request or a bash spawn) reports why.
		}
	};

	// Each host declares only its own name for a session id change, and they
	// are not the same name. The omp fork emits `session_switch` (and
	// `session_branch`) and contains no `session_info_changed` at all; the
	// pinned upstream `@earendil-works/pi-coding-agent` types declare
	// `session_info_changed` and neither of the others. Registering all three
	// is what makes a re-key reach this extension on either host: before this,
	// secretsd listened only for the upstream name, so on omp the handler was
	// dead and a re-keyed session kept serving the retired token.
	//
	// Registering is safe where an event never fires -- `pi.on` only records a
	// handler by name -- and safe where more than one fires, because the
	// handler returns early once the id already matches, so the second is a
	// no-op. All three are omp session-identity events, so omp rebuilds the
	// shell spawn environment after they run and the fresh token path reaches
	// the next shell. The cast covers the two names the pinned upstream types
	// do not declare; there is no overload for them to satisfy.
	const onSessionIdentityEvent = pi.on.bind(pi) as unknown as (
		event: string,
		handler: (event: unknown, ctx: ExtensionContext) => Promise<void>,
	) => void;
	for (const event of ["session_info_changed", "session_switch", "session_branch"]) {
		onSessionIdentityEvent(event, reKeyOnSessionIdChange);
	}

	pi.on("session_shutdown", async () => {
		requestAbort.abort();
		// A subagent's shutdown must never unregister the anchor: that would
		// revoke every grant for the whole tree out from under the root and any
		// sibling subagent still running. Only the owner tears it down.
		if (!isOwner) return;
		const anchor = getAnchor();
		if (!anchor) return;
		// Fence BEFORE unregistering/removing the token file: any
		// `secrets_request` still in flight must fail loudly rather than
		// resurrect the anchor via `reregister` after teardown starts.
		anchor.abort.abort();
		try {
			if (anchor.registered) await anchor.broker.unregister(anchor.ownerSessionId);
		} catch {
			// Best-effort: daemon reaps dead pids on its own.
		} finally {
			removeTokenFile(anchor.state);
			setAnchor(undefined);
		}
	});

	pi.registerTool({
		name: "secrets_request",
		label: "Secrets Request",
		description:
			"Ask secretsd about a key; never returns secret values. A human-tier key is refused without blinking the YubiKey, and the answer names the Legion credential broker command (`secret-run`) to use instead. An agent-tier key needs no approval: run commands with `secrets <KEY> -- <command>`.",
		parameters: z.object({
			key: z
				.string()
				.regex(/^[A-Z][A-Z0-9_]*$/, "key must be an UPPER_SNAKE_CASE secret name")
				.describe("Secret key name, e.g. DEEL_API_KEY"),
		}),
		execute: async (_id, params, signal) => {
			try {
				let anchor = getAnchor();
				if (!anchor) {
					// A missing anchor means a prior claim failed, was never made, or
					// was torn down (session_shutdown, `secrets lock`, a lost race);
					// claiming lazily here -- keyed off THIS instance's own session
					// id -- lets the very request that discovered the gap self-heal
					// it instead of erroring for the rest of the process's life.
					// Except when THIS instance's own session already shut down
					// (`requestAbort` fired): a stale call surviving past that point
					// must not mint and register a brand new anchor on its behalf.
					if (requestAbort.signal.aborted || !ownSessionId) {
						throw new Error("secretsd session not initialized");
					}
					const claim = claimOrAdoptAnchor(ownSessionId);
					anchor = claim.anchor;
					isOwner = claim.owner;
				}
				await ensureRegistered(anchor);
				const status = await humanTierGate.status(params.key);
				if ("error" in status) {
					const registered = await humanTierGate.brokerIdentity();
					return {
						content: [
							{
								type: "text",
								text: `${params.key}: error: could not read this key's tier without asking for a touch (secrets get --no-request: ${status.error}), so nothing was requested. If it is human tier, an agent gets it from the Legion credential broker, not secretsd.\n${brokerRoute(params.key, anchor.ownerSessionId, registered)}`,
							},
						],
						isError: true,
						details: { key: params.key, outcome: "status-unavailable" },
					};
				}
				if (status.tier === "human") {
					const registered = await humanTierGate.brokerIdentity();
					return {
						content: [
							{
								type: "text",
								text: `${params.key}: ${brokerOnlyGuidance(params.key, anchor.ownerSessionId, registered)}`,
							},
						],
						isError: true,
						details: { key: params.key, outcome: "broker-only" },
					};
				}
				const outcome = await requestSecret(anchor.broker, {
					state: anchor.state,
					sessionID: anchor.ownerSessionId,
					pid: process.pid,
					key: params.key,
					signal: AbortSignal.any(
						signal
							? [signal, requestAbort.signal, anchor.abort.signal]
							: [requestAbort.signal, anchor.abort.signal],
					),
					reregister: async () => {
						// The anchor this request started against may have been torn
						// down (teardown fence above) or re-keyed (session_info_changed)
						// while the request was in flight; re-registering it now would
						// resurrect a dead registration instead of failing loudly.
						assertAnchorLive(anchor);
						anchor.registered = false;
						await ensureRegistered(anchor);
					},
				});
				return toolResult(params.key, outcome);
			} catch (error) {
				return toolResult(params.key, failureOutcome(error));
			}
		},
	});
}
