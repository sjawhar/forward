use std::io::{Read as _, Write as _};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::time::Duration;

use crate::browser::request::{self, GrantStatus};

/// The endpoint answers from the laptop's Chrome, two machines away, so this
/// is longer than a loopback round trip and still short enough that `doctor`
/// stays a command a human waits through.
const ENDPOINT_PROBE_TIMEOUT: Duration = Duration::from_secs(3);

/// Report whether the invoking session holds a live grant. Informational,
/// like the pcsc row: holding no grant is not ill health.
pub(super) fn report() {
    super::print_line(line(
        request::status(&request::socket_path()),
        &endpoint_answers,
    ));
}

/// A recorded grant is not a usable one. The endpoint lives in the caller's
/// network namespace and its relay is a separate process, so a grant can be
/// live in `forward serve`'s registry while nothing at all listens where the
/// session must dial. Reporting the record alone is how `doctor` came to read
/// green against an endpoint that refused every connection.
fn line(status: GrantStatus, answers: &dyn Fn(u16) -> bool) -> String {
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
            if answers(port) {
                row
            } else {
                format!(
                    "{row} — the endpoint does not answer; forward browser grant --ttl 30m"
                )
            }
        }
    }
}

/// Ask the endpoint the question the session's browser tool asks first.
fn endpoint_answers(port: u16) -> bool {
    let address = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let Ok(mut stream) = TcpStream::connect_timeout(&address, ENDPOINT_PROBE_TIMEOUT) else {
        return false;
    };
    if stream
        .set_read_timeout(Some(ENDPOINT_PROBE_TIMEOUT))
        .is_err()
        || stream
            .set_write_timeout(Some(ENDPOINT_PROBE_TIMEOUT))
            .is_err()
        || stream
            .write_all(
                b"GET /json/version HTTP/1.0\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
            )
            .is_err()
    {
        return false;
    }
    let mut status = [0_u8; 5];
    stream.read_exact(&mut status).is_ok() && &status == b"HTTP/"
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
        assert!(!live.contains("does not answer"));
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
        assert!(live.contains("the endpoint does not answer"), "got {live}");
        assert!(
            live.contains("forward browser grant --ttl 30m"),
            "got {live}"
        );
    }
}
