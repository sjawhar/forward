use std::io::Read as _;
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

/// The longest arming request accepted, in bytes.
///
/// `ARM 65535 4294967295\n` is 21 bytes and `HOLD 65535\n` is 11, so 64 is
/// generous. The cap stops a hostile or broken local process from making its
/// handler allocate without limit; the deadline releases that handler instead.
const MAX_ARM_LINE: usize = 64;
/// Maximum elapsed time to read an entire arming request.
const ARM_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// One arming request: a lease that expires on its own, or a hold that lasts
/// exactly as long as the requesting connection stays open.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Request {
    Arm { port: u16, ttl: u64 },
    Hold { port: u16 },
}

/// Read one newline-terminated `ARM <port> <ttl_secs>` or `HOLD <port>` request.
///
/// The line is read byte-by-byte under one cumulative deadline, so the cap and
/// newline are structural: a truncated line can never reach parsing. Nothing
/// past the newline is consumed, so a holder's connection carries on intact.
pub(super) fn read_request(stream: &mut UnixStream) -> Option<Request> {
    let deadline = Instant::now().checked_add(ARM_REQUEST_TIMEOUT)?;
    let mut line = Vec::with_capacity(MAX_ARM_LINE);
    let mut byte = [0_u8; 1];

    while line.len() < MAX_ARM_LINE {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() || stream.set_read_timeout(Some(remaining)).is_err() {
            return None;
        }
        match stream.read(&mut byte) {
            Ok(1) => {}
            Ok(_) => return None,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return None,
        }
        let [received] = byte;
        if received == b'\n' {
            return parse_request(&line);
        }
        line.push(received);
    }
    None
}

fn parse_request(line: &[u8]) -> Option<Request> {
    let mut fields = std::str::from_utf8(line).ok()?.split(' ');
    match (fields.next(), fields.next(), fields.next(), fields.next()) {
        (Some("ARM"), Some(port), Some(ttl), None) => Some(Request::Arm {
            port: number(port)?,
            ttl: number(ttl)?,
        }),
        (Some("HOLD"), Some(port), None, None) => Some(Request::Hold {
            port: number(port)?,
        }),
        _ => None,
    }
}

/// A field of decimal digits only: no sign, no space, never empty.
fn number<T: std::str::FromStr>(field: &str) -> Option<T> {
    if field.is_empty() || !field.bytes().all(|value| value.is_ascii_digit()) {
        return None;
    }
    field.parse().ok()
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use super::*;

    #[test]
    fn both_request_shapes_parse() {
        assert_eq!(
            parse_request(b"ARM 8400 300"),
            Some(Request::Arm {
                port: 8400,
                ttl: 300
            })
        );
        assert_eq!(
            parse_request(b"HOLD 5173"),
            Some(Request::Hold { port: 5173 })
        );
    }

    #[test]
    fn read_request_leaves_bytes_after_the_newline_for_the_holder() {
        let (mut bridge_end, mut holder_end) = UnixStream::pair().unwrap();
        holder_end.write_all(b"HOLD 5173\nDIAL\n").unwrap();

        assert_eq!(
            read_request(&mut bridge_end),
            Some(Request::Hold { port: 5173 })
        );

        let mut next = [0_u8; 5];
        std::io::Read::read_exact(&mut bridge_end, &mut next).unwrap();
        assert_eq!(&next, b"DIAL\n");
    }

    #[test]
    fn an_arm_takes_exactly_one_plain_port_and_ttl() {
        for line in [
            &b"ARM"[..],
            b"ARM ",
            b"ARM 8400",
            b"ARM 8400 300 extra",
            b"ARM +8400 300",
            b"ARM 8400 +300",
            b"ARM  8400 300",
            b"ARM 65536 300",
            b"ARM 8400 18446744073709551616",
            b"arm 8400 300",
        ] {
            assert_eq!(
                parse_request(line),
                None,
                "{:?}",
                String::from_utf8_lossy(line)
            );
        }
    }

    #[test]
    fn a_hold_takes_exactly_one_plain_port() {
        // A hold has no lease to name, and nothing but a decimal port may
        // reach the policy check: no sign, no padding, no second field.
        for line in [
            &b"HOLD"[..],
            b"HOLD ",
            b"HOLD 5173 300",
            b"HOLD +5173",
            b"HOLD  5173",
            b"HOLD 65536",
            b"hold 5173",
        ] {
            assert_eq!(
                parse_request(line),
                None,
                "{:?}",
                String::from_utf8_lossy(line)
            );
        }
    }
}
