use std::io::Read as _;
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use crate::browser::relay::SESSION_REFUSAL;
use crate::browser::request::{self, GrantStatus};

/// The probe's budget, spent twice at most: once on the connect, then once on
/// every read together. Long enough for a loopback accept and one refusal under
/// load, short enough that `doctor` stays a command a human waits through. The
/// reads share one deadline rather than a per-read timeout: a peer dribbling a
/// byte at a time must not be able to hold `doctor` for a multiple of it.
const ENDPOINT_PROBE_TIMEOUT: Duration = Duration::from_secs(3);

/// Report whether the invoking session holds a live grant. Informational,
/// like the pcsc row: holding no grant is not ill health.
pub(super) fn report() {
    super::print_line(line(
        request::status(&request::socket_path()),
        &endpoint_is_served,
    ));
}

/// A recorded grant is not a usable one. The endpoint lives in the caller's
/// network namespace and its relay is a separate process, so a grant can be
/// live in `forward serve`'s registry while nothing at all listens where the
/// session must dial. Reporting the record alone is how `doctor` came to read
/// green against an endpoint that refused every connection.
fn line(status: GrantStatus, served: &dyn Fn(u16) -> bool) -> String {
    match status {
        GrantStatus::Unreachable => {
            "browser grant: info — grant status unavailable; no valid STATUS reply from the local request socket"
                .to_owned()
        }
        GrantStatus::None => {
            "browser grant: none for this session — forward browser grant --ttl 30m".to_owned()
        }
        GrantStatus::Live {
            port,
            remaining_secs,
        } => {
            let row = format!(
                "browser grant: live for this session at http://127.0.0.1:{port} ({remaining_secs}s left)"
            );
            if served(port) {
                format!("{row} — endpoint served here; the laptop side is not probed from forward")
            } else {
                format!("{row} — no endpoint is served here; forward browser grant --ttl 30m")
            }
        }
    }
}

/// Whether a relay is serving this grant's endpoint in this namespace.
///
/// "Served" means exactly one thing: the relay answered `REFUSED SESSION`.
///
/// The probe sends nothing at all. It must not put bytes of its own on a port
/// a registry record merely asserts, and it could not earn a CDP answer even
/// if it wanted one: every `forward` process suppresses its core dumps, which
/// also makes its `/proc/<pid>/fd` unreadable to the relay, so the relay
/// cannot attribute this connection and refuses it. That refusal is the proof
/// being looked for, since nothing else on this loopback speaks it. Silence, a
/// closed port and every other answer are not proof of anything and read as
/// unserved — including, deliberately, an admitted connection: a probe that
/// sends nothing gets nothing back from Chrome, so there is no second thing to
/// accept here, only a second way to be wrong.
///
/// What this does *not* check is the far end: whether the laptop feed is
/// attached, whether Chrome is up, whether the token is still good. The
/// `browser relay` and `browser feed` rows are where those live.
#[doc(hidden)]
pub fn endpoint_is_served(port: u16) -> bool {
    let address = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let Ok(mut stream) = TcpStream::connect_timeout(&address, ENDPOINT_PROBE_TIMEOUT) else {
        return false;
    };
    let Some(deadline) = Instant::now().checked_add(ENDPOINT_PROBE_TIMEOUT) else {
        return false;
    };
    let mut answer = [0_u8; SESSION_REFUSAL.len()];
    let mut seen = 0;
    while let Some(rest) = answer.get_mut(seen..).filter(|rest| !rest.is_empty()) {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() || stream.set_read_timeout(Some(remaining)).is_err() {
            break;
        }
        match stream.read(rest) {
            Ok(0) => break,
            Ok(count) => seen = seen.saturating_add(count),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    let answer = answer.get(..seen).unwrap_or_default();
    answer.starts_with(SESSION_REFUSAL)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_grant_state_renders_its_own_row() {
        assert_eq!(
            line(GrantStatus::Unreachable, &|_| true),
            "browser grant: info — grant status unavailable; no valid STATUS reply from the local request socket"
        );
        assert_eq!(
            line(GrantStatus::None, &|_| true),
            "browser grant: none for this session — forward browser grant --ttl 30m"
        );
        let live = line(
            GrantStatus::Live {
                port: 12_811,
                remaining_secs: 900,
            },
            &|_| true,
        );
        assert!(live.contains("http://127.0.0.1:12811"));
        assert!(live.contains("900s left"));
        assert!(live.contains("endpoint served here"), "got {live}");
        assert!(!live.contains("no endpoint"), "got {live}");
    }

    #[test]
    fn a_recorded_grant_whose_endpoint_is_silent_does_not_read_as_ready() {
        // This is the #51 report: `doctor` named a live grant whose endpoint
        // had no listener at all, which read exactly like "ready to use".
        let live = line(
            GrantStatus::Live {
                port: 36_029,
                remaining_secs: 1_779,
            },
            &|_| false,
        );

        assert!(live.contains("http://127.0.0.1:36029"), "got {live}");
        assert!(live.contains("no endpoint is served here"), "got {live}");
        assert!(
            live.contains("forward browser grant --ttl 30m"),
            "got {live}"
        );
    }
}
