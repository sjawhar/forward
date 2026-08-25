use std::io::{BufRead as _, BufReader, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

use crate::config::{Config, ConfigError};

/// How long to wait for the daemon to report what it did with a URL. The
/// counterpart answers as soon as it has decided, before any browser has
/// finished loading, so this only has to cover the round trip.
const OUTCOME_TIMEOUT: Duration = Duration::from_secs(10);

/// What the counterpart did with a URL.
///
/// The caller cannot infer this: the allowlist lives in the daemon's config on
/// the machine with the browser, so only the daemon knows whether a URL opened.
/// Reporting it is what lets `forward open` fail when nothing opened, which in
/// turn is what lets callers that read an exit status — `xdg-open` consumers,
/// Python's `webbrowser`, agents reading tool output — fall back to handling the
/// URL themselves instead of waiting for a browser that never arrived.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The opener was spawned; a browser is coming up.
    Opened,
    /// The URL was handed to the user as a notification and a clipboard entry.
    /// Nothing opened, and nothing will without the user acting.
    Notified,
}

impl Outcome {
    #[must_use]
    pub fn as_wire(self) -> &'static str {
        match self {
            Self::Opened => "opened",
            Self::Notified => "notified",
        }
    }

    #[must_use]
    pub fn from_wire(line: &str) -> Option<Self> {
        match line.trim() {
            "opened" => Some(Self::Opened),
            "notified" => Some(Self::Notified),
            _ => None,
        }
    }
}

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
    #[error(
        "forward: the counterpart at {target} accepted {url} but never reported what it did with it; \
         upgrade the daemon so opens can be told apart from handovers"
    )]
    Unreported { target: String, url: String },
}

/// Sends one newline-terminated URL to the counterpart's URL channel and returns
/// what the counterpart did with it.
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
pub fn send_url(cfg: &Config, url: &url::Url, channel_port: u16) -> Result<Outcome, SendError> {
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
    stream.set_read_timeout(Some(OUTCOME_TIMEOUT))?;

    // A counterpart that answers nothing is a counterpart whose answer we must
    // not invent: guessing "opened" is exactly the silent success that leaves a
    // caller waiting on a browser that was never launched.
    let mut line = String::new();
    BufReader::new(&stream).read_line(&mut line)?;
    Outcome::from_wire(&line).ok_or_else(|| SendError::Unreported {
        target: target.to_string(),
        url: url.to_string(),
    })
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
mod tests;
