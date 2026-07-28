use crate::config::{Config, ConfigError};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};

#[derive(Debug, thiserror::Error)]
pub enum SendError {
    #[error("forward: invalid configuration: {source}")]
    Config {
        #[source]
        source: ConfigError,
    },
    #[error("forward: cannot reach the laptop daemon at {target}: {source}")]
    Unreachable {
        target: String,
        #[source]
        source: std::io::Error,
    },
    #[error("forward: send failed: {0}")]
    Io(#[from] std::io::Error),
}

/// Sends one newline-terminated URL to the counterpart's URL channel.
///
/// The literal `peer` address is dialled, never a name: a name would put DNS and
/// the Tailscale admin console inside the decision. A `peer` that will not parse
/// is an error rather than a quiet fall back to loopback, which would deliver the
/// laptop's URL to this machine instead.
///
/// An **unset** `peer` deliberately means loopback, and that is not a silent
/// fallback to be tidied away: it is what keeps an unconfigured install working
/// through the migration. On the devbox, loopback on the channel port is the SSH
/// forward that carries URLs to the laptop today, so the pre-migration path keeps
/// running until a `peer` is configured. If that forward is gone the connect is
/// refused and the caller prints and copies the URL rather than losing it, so this
/// is not a swallow. A review read it as one; changing it would break the
/// migration step that removes the SSH forwards only after the tailnet path is
/// verified working.
pub fn send_url(cfg: &Config, url: &url::Url, channel_port: u16) -> Result<(), SendError> {
    let ip = cfg
        .peer_ip()
        .map_err(|source| SendError::Config { source })?
        // An unset peer preserves the pre-migration SSH-forward loopback path.
        // Once peer is configured, this fallback no longer applies.
        .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));
    let target = SocketAddr::new(ip, channel_port);
    let mut stream = TcpStream::connect(target).map_err(|source| SendError::Unreachable {
        target: target.to_string(),
        source,
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
        // Given: an opener-channel listener, and a config with no peer, which
        // means loopback.
        let cfg = Config::default_values_for_test();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut received = String::new();
            stream.read_to_string(&mut received).unwrap();
            received
        });

        // When: a URL is sent to the listener.
        send_url(
            &cfg,
            &url::Url::parse("https://example.com/a").unwrap(),
            port,
        )
        .unwrap();

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
    fn unreachable_peer_is_reported_with_its_target() {
        // Given: a peer with nothing listening. Port 9 (discard) is outside the
        // ephemeral range, so nothing binds it in tests.
        let mut cfg = Config::default_values_for_test();
        cfg.peer = "127.0.0.1".to_owned();

        // When: a URL is sent.
        let result = send_url(&cfg, &url::Url::parse("https://example.com").unwrap(), 9);

        // Then: the error names what could not be reached, so the caller can
        // print and OSC 52 copy the URL instead of losing it.
        match result {
            Err(SendError::Unreachable { target, .. }) => assert_eq!(target, "127.0.0.1:9"),
            other => panic!("expected Unreachable, got {other:?}"),
        }
    }

    #[test]
    fn malformed_peer_is_reported_rather_than_falling_back_to_loopback() {
        // Given: a peer that is not an address, which Config::validate rejects.
        let mut cfg = Config::default_values_for_test();
        cfg.peer = "not-an-address".to_owned();

        // When: a URL is sent.
        let result = send_url(&cfg, &url::Url::parse("https://example.com").unwrap(), 9);

        // Then: it fails loudly rather than silently sending to this machine.
        assert!(matches!(result, Err(SendError::Config { .. })));
    }
}
