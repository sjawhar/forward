//! The `browser` CLI subcommands: `grant`, and the relay it leaves behind.
//!
//! The no-scope refusal is first: it must not contact either service or cost a
//! human a touch. Once scope is available, the forward-serve probe still runs
//! before the broker ceremony, so a predictable serve refusal costs no touch.

use std::io::Write as _;
use std::net::TcpListener;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

use clap::Subcommand;
use forward::browser::grant::ProcessAnchor;
use forward::browser::peer::{omp_anchor_for, parent_anchor_for};
use forward::browser::relay;
use forward::browser::request::{
    ProbeOutcome, RequestFailure, describe_refusal, parse_ttl, probe, request, socket_path,
};

#[derive(Subcommand)]
pub(crate) enum BrowserCommand {
    /// Request browser access for this session (devbox side)
    Grant {
        /// Grant lifetime, for example 45s, 30m, or 2h
        #[arg(long, default_value = "30m")]
        ttl: String,
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Serve one grant's endpoint until the grant ends.
    ///
    /// Started by `browser grant`, never by hand: it takes the grant's
    /// listener and its control channel to `forward serve` as inherited
    /// descriptors, neither of which a shell can supply.
    #[command(hide = true)]
    Relay {
        #[arg(long)]
        anchor_pid: u32,
        #[arg(long)]
        anchor_start: u64,
    },
}

pub(crate) fn run(action: BrowserCommand) -> anyhow::Result<()> {
    match action {
        BrowserCommand::Grant { ttl, config } => grant(&ttl, config),
        BrowserCommand::Relay {
            anchor_pid,
            anchor_start,
        } => relay::run(ProcessAnchor::new(anchor_pid, anchor_start)).map_err(anyhow::Error::from),
    }
}

const NO_GRANT_SCOPE: &str = "forward: grant refused before any touch: no omp process runs above this command, and it has no session token and no terminal; run it from an omp session or an interactive terminal";

fn grant(ttl: &str, config: Option<PathBuf>) -> anyhow::Result<()> {
    let _ = crate::load_config(config)?;
    let Some(ttl_secs) = parse_ttl(ttl) else {
        eprintln!("forward: invalid --ttl {ttl:?}; use 45s, 30m, or 2h");
        std::process::exit(1);
    };

    // Read these once before any probe. The no-scope refusal must come before
    // either service is contacted, and the exact values selected here must form
    // the AUTHORIZE scope after a successful probe.
    let token =
        forward::secretsd::session_token().unwrap_or_else(|error| crate::exit_with_error(error));
    let tty = forward::secretsd::caller_tty();
    let pid = std::process::id();
    // The anchor is derived here, in the command itself, because here the
    // ancestry it walks is this process's own and is intact.
    let omp_anchor = omp_anchor_for(pid);
    if let Some(refusal) = grant_scope_refusal(token.is_some(), tty.is_some(), omp_anchor.is_some())
    {
        eprintln!("{refusal}");
        std::process::exit(1);
    }

    // The nearest process named `omp` above this command is both this relay's
    // anchor and the broker's tokenless capability scope. A token or tty
    // preserves the immediate-parent fallback for an interactive command with
    // no omp ancestor, and taking that parent directly keeps the ancestry walk
    // above to a single pass.
    let Some(anchor) = omp_anchor.or_else(|| parent_anchor_for(pid)) else {
        // Not `describe_refusal("ANCHOR")`: that sentence blames `forward serve`,
        // and here it is this command that could not find its session.
        eprintln!("forward: grant refused: could not anchor this command to a calling session");
        std::process::exit(1);
    };

    let socket = socket_path();
    // Scope is settled before this probe; after that gate, a deterministic
    // forward-serve refusal must still happen before the broker touch ceremony.
    match probe(&socket) {
        ProbeOutcome::Unreachable => exit_unreachable(&socket),
        ProbeOutcome::Refused(reason) => exit_refused(&reason),
        ProbeOutcome::Grantable => {}
    }
    // Bound before the ceremony for the same reason as the probe: a local bind
    // failure is predictable and must never cost a touch or receipt.
    let (listener, port) = bind_endpoint();
    // The broker owns the ceremony and retries failed hardware attempts inside
    // its request TTL. This waits for its final result using the token and tty
    // already read for the refusal decision above.
    let receipt = forward::secretsd::authorize_with(forward::secretsd::CAP_BROWSER, token, tty)
        .unwrap_or_else(|error| crate::exit_with_error(error));
    let granted = request(&socket, ttl_secs, &receipt, port);
    drop(receipt);
    let control = match granted {
        Ok(control) => control,
        Err(RequestFailure::Unreachable) => exit_unreachable(&socket),
        Err(RequestFailure::Refused(reason)) => exit_refused(&reason),
    };
    detach(&listener, &control, anchor);
    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "http://127.0.0.1:{port}")?;
    Ok(())
}

fn grant_scope_refusal(has_token: bool, has_tty: bool, has_omp: bool) -> Option<&'static str> {
    (!has_token && !has_tty && !has_omp).then_some(NO_GRANT_SCOPE)
}

/// Bind the grant's endpoint in this process's own network namespace, which is
/// the one its browser clients will dial.
fn bind_endpoint() -> (TcpListener, u16) {
    let bound = TcpListener::bind("127.0.0.1:0").and_then(|listener| {
        let port = listener.local_addr()?.port();
        Ok((listener, port))
    });
    match bound {
        Ok(endpoint) => endpoint,
        Err(error) => {
            eprintln!("forward: could not bind a loopback endpoint for the grant: {error}");
            std::process::exit(1);
        }
    }
}

/// Hand the endpoint to a detached child and return. The grant outlives this
/// command, so this process must not wait for it.
fn detach(listener: &TcpListener, control: &UnixStream, anchor: ProcessAnchor) {
    if let Err(error) = relay::spawn(listener, control, anchor) {
        eprintln!("forward: could not start the grant's relay: {error}");
        std::process::exit(1);
    }
}

fn exit_unreachable(socket: &Path) -> ! {
    eprintln!(
        "forward: no forward serve listening at {}",
        socket.display()
    );
    std::process::exit(1);
}

fn exit_refused(reason: &str) -> ! {
    eprintln!("forward: grant refused: {}", describe_refusal(reason));
    std::process::exit(1);
}

#[cfg(test)]
mod tests {
    use super::{NO_GRANT_SCOPE, grant_scope_refusal};

    #[test]
    fn grant_scope_refuses_only_without_token_tty_or_omp() {
        for (has_token, has_tty, has_omp, expected) in [
            (false, false, false, Some(NO_GRANT_SCOPE)),
            (true, false, false, None),
            (false, true, false, None),
            (false, false, true, None),
            (true, true, false, None),
            (true, false, true, None),
            (false, true, true, None),
            (true, true, true, None),
        ] {
            assert_eq!(grant_scope_refusal(has_token, has_tty, has_omp), expected);
        }
    }
}
