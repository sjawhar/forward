//! The `browser` CLI subcommands: `grant`, and the relay it leaves behind.
//!
//! Ordering is the point: every refusal forward serve can predict is answered
//! by the probe before the broker's YubiKey ceremony, so a refusal never costs
//! the human a touch or a single-use receipt.

use std::io::Write as _;
use std::net::TcpListener;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

use clap::Subcommand;
use forward::browser::grant::ProcessAnchor;
use forward::browser::peer::anchor_for;
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

fn grant(ttl: &str, config: Option<PathBuf>) -> anyhow::Result<()> {
    let _ = crate::load_config(config)?;
    let Some(ttl_secs) = parse_ttl(ttl) else {
        eprintln!("forward: invalid --ttl {ttl:?}; use 45s, 30m, or 2h");
        std::process::exit(1);
    };
    let socket = socket_path();
    match probe(&socket) {
        ProbeOutcome::Unreachable => exit_unreachable(&socket),
        ProbeOutcome::Refused(reason) => exit_refused(&reason),
        ProbeOutcome::Grantable => {}
    }
    // Derived here, before the ceremony, because here is the only place it can
    // be: this process's ancestry is intact and its `/proc/<pid>/exe` entries
    // are readable, neither of which holds for a `forward serve` on the other
    // side of an agent box's user namespace.
    let Some(anchor) = anchor_for(std::process::id()) else {
        // Not `describe_refusal("ANCHOR")`: that sentence blames `forward serve`,
        // and here it is this command that could not find its session.
        eprintln!("forward: grant refused: could not anchor this command to a calling session");
        std::process::exit(1);
    };
    // Bound before the ceremony for the same reason the probe runs before it:
    // a local bind failure is a refusal this command can predict, and a
    // predictable refusal must never cost a touch or a single-use receipt.
    let (listener, port) = bind_endpoint();
    // The broker runs the YubiKey ceremony; this blocks through the touch
    // window and prints nothing until it resolves.
    let receipt = forward::secretsd::authorize(forward::secretsd::CAP_BROWSER)
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
