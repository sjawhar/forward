use base64::{Engine as _, engine::general_purpose::STANDARD};
use std::io::Write;
use std::net::TcpStream;

#[derive(Debug, thiserror::Error)]
pub enum SendError {
    #[error("forward: opener tunnel down — run 'devbox' on your laptop")]
    TunnelDown,
    #[error("forward: send failed: {0}")]
    Io(#[from] std::io::Error),
}

pub fn send_url(url: &url::Url, channel_port: u16) -> Result<(), SendError> {
    let mut stream = TcpStream::connect(("127.0.0.1", channel_port)).map_err(|error| {
        if error.kind() == std::io::ErrorKind::ConnectionRefused {
            SendError::TunnelDown
        } else {
            SendError::Io(error)
        }
    })?;
    writeln!(stream, "{url}")?;
    stream.flush()?;
    Ok(())
}

fn osc52_sequence(text: &str, in_tmux: bool) -> String {
    let sequence = format!("\x1b]52;c;{}\x07", STANDARD.encode(text));
    if in_tmux {
        format!("\x1bPtmux;\x1b{sequence}\x1b\\")
    } else {
        sequence
    }
}

pub fn osc52_copy(text: &str) -> std::io::Result<()> {
    let in_tmux = std::env::var_os("TMUX").is_some_and(|value| !value.is_empty());
    let sequence = osc52_sequence(text, in_tmux);
    let mut tty = std::fs::OpenOptions::new().write(true).open("/dev/tty")?;
    tty.write_all(sequence.as_bytes())?;
    tty.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn sends_newline_terminated_url() {
        // Given: an opener-channel listener.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut received = String::new();
            stream.read_to_string(&mut received).unwrap();
            received
        });

        // When: a URL is sent to the listener.
        send_url(&url::Url::parse("https://example.com/a").unwrap(), port).unwrap();

        // Then: the listener receives one newline-terminated URL.
        assert_eq!(handle.join().unwrap(), "https://example.com/a\n");
    }

    #[test]
    fn osc52_sequence_is_bare_outside_tmux() {
        // Given: text copied outside tmux.
        let text = "hello";

        // When: OSC 52 is encoded.
        let sequence = osc52_sequence(text, false);

        // Then: it is a bare OSC 52 sequence.
        assert_eq!(sequence, "\x1b]52;c;aGVsbG8=\x07");
    }

    #[test]
    fn osc52_sequence_is_wrapped_inside_tmux() {
        // Given: text copied inside tmux.
        let text = "hello";

        // When: OSC 52 is encoded.
        let sequence = osc52_sequence(text, true);

        // Then: tmux passthrough wraps the OSC 52 sequence.
        assert_eq!(sequence, "\x1bPtmux;\x1b\x1b]52;c;aGVsbG8=\x07\x1b\\");
    }

    #[test]
    fn refused_connection_is_tunnel_down() {
        // Given: port 9 (discard) is outside the ephemeral range; nothing binds it in tests.

        // When: the sender attempts a connection.
        let result = send_url(&url::Url::parse("https://example.com").unwrap(), 9);

        // Then: the unavailable opener tunnel is reported distinctly.
        assert!(matches!(result, Err(SendError::TunnelDown)));
    }
}
