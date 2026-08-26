//! The grant socket's receipt-free answers: caller identity, `STATUS`, and
//! the deterministic pre-ceremony `PROBE`.

use std::io::Write as _;
use std::net::SocketAddr;
use std::os::unix::net::UnixStream;
use std::time::Instant;

use crate::browser::grant::{Grants, ProcessAnchor};

pub(super) fn answer_status(
    grants: &Grants,
    caller: Option<ProcessAnchor>,
    mut stream: UnixStream,
) {
    let reply = caller
        .and_then(|caller| grants.live_for_descendant(caller))
        .map(|(port, grant)| {
            format!(
                "LIVE {port} {}\n",
                grant
                    .deadline
                    .saturating_duration_since(Instant::now())
                    .as_secs()
            )
        })
        .unwrap_or_else(|| "NONE\n".to_owned());
    let _ = stream.write_all(reply.as_bytes());
}

/// The deterministic pre-ceremony checks, answered without a receipt so the
/// CLI can refuse before the broker runs the YubiKey ceremony. Advisory, never
/// a reservation: `GRANT` re-runs the same checks itself.
pub(super) fn answer_probe(
    pid: u32,
    anchor: Option<ProcessAnchor>,
    upstream: Option<SocketAddr>,
    mut stream: UnixStream,
) {
    let reply: &[u8] = if anchor.is_none() {
        eprintln!("forward: grant probe refused: could not anchor requesting pid {pid}");
        b"REFUSED ANCHOR\n"
    } else if upstream.is_none() {
        eprintln!("forward: grant probe refused: no peer configured to relay to");
        b"REFUSED UPSTREAM\n"
    } else {
        b"OK\n"
    };
    let _ = stream.write_all(reply);
}

pub(super) fn peer_pid(stream: &UnixStream) -> Option<u32> {
    let credentials =
        nix::sys::socket::getsockopt(stream, nix::sys::socket::sockopt::PeerCredentials).ok()?;
    u32::try_from(credentials.pid()).ok()
}
