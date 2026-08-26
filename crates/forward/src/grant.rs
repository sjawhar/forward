//! The `browser grant` CLI flow: probe, ceremony, request, report.
//!
//! Ordering is the point: every refusal forward serve can predict is answered
//! by the probe before the broker's YubiKey ceremony, so a refusal never costs
//! the human a touch or a single-use receipt.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use forward::browser::request::{
    ProbeOutcome, RequestFailure, describe_refusal, parse_ttl, probe, request, socket_path,
};

pub(crate) fn run(ttl: &str, config: Option<PathBuf>) -> anyhow::Result<()> {
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
    // The broker runs the YubiKey ceremony; this blocks through the touch
    // window and prints nothing until it resolves.
    let receipt = forward::secretsd::authorize(forward::secretsd::CAP_BROWSER)
        .unwrap_or_else(|error| crate::exit_with_error(error));
    let granted = request(&socket, ttl_secs, &receipt);
    drop(receipt);
    let port = match granted {
        Ok(port) => port,
        Err(RequestFailure::Unreachable) => exit_unreachable(&socket),
        Err(RequestFailure::Refused(reason)) => exit_refused(&reason),
    };
    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "http://127.0.0.1:{port}")?;
    Ok(())
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
