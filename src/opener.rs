use crate::FILES_PORT;
use forward::config::Config;
use forward::{bridge, send, target};
use std::io::Write as _;

pub(crate) const OPENER_REENTRY_ERROR: &str = "forward: refusing to open URL because the configured opener is routing back into forward open; set opener to an absolute path such as /usr/bin/xdg-open";

pub(crate) fn open_target(
    cfg: &Config,
    target: &str,
    channel_port: u16,
    opener_reentry: bool,
) -> anyhow::Result<()> {
    if opener_reentry {
        anyhow::bail!(OPENER_REENTRY_ERROR);
    }
    let url = target::to_url(target, &cfg.listen, FILES_PORT)?;
    bridge::arm_for_url(cfg, &url, &bridge::arm_socket_path());
    let outcome = match send::send_url(cfg, &url, channel_port) {
        Ok(outcome) => outcome,
        Err(error) => {
            // A URL that cannot be delivered is handed back rather than dropped.
            hand_back(&url);
            return Err(error.into());
        }
    };
    match outcome {
        send::Outcome::Opened => Ok(()),
        // Nothing opened, so saying nothing and exiting zero would tell every
        // caller a browser is coming. Hand the URL back and fail: a caller that
        // reads the status can then take the URL itself instead of waiting.
        send::Outcome::Notified => {
            hand_back(&url);
            anyhow::bail!(
                "forward: {} is not allowlisted, so it was sent as a notification and copied to the \
                 {} clipboard instead of opened; open the URL above to continue",
                url.host_str().unwrap_or("the target"),
                if cfg.peer.is_empty() {
                    "counterpart"
                } else {
                    "laptop"
                },
            )
        }
    }
}

/// Prints the URL and puts it on the local clipboard, so a URL that did not open
/// is still one paste away rather than lost.
fn hand_back(url: &url::Url) {
    let _ = writeln!(std::io::stdout(), "{url}");
    let _ = send::osc52_copy(url.as_str());
}

#[cfg(test)]
mod tests {
    use super::{Config, open_target};
    use std::io::{BufRead as _, Write as _};

    /// Accepts one connection on the opener channel, reads the URL line, and
    /// answers with `reply`.
    fn counterpart(reply: &'static str) -> (u16, std::thread::JoinHandle<String>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut received = String::new();
            std::io::BufReader::new(&stream)
                .read_line(&mut received)
                .unwrap();
            stream.write_all(reply.as_bytes()).unwrap();
            stream.flush().unwrap();
            received
        });
        (port, handle)
    }

    #[test]
    fn open_sends_url_when_opener_reentry_is_unset() {
        // Given: a default configuration and a counterpart that opens the URL.
        let cfg = Config::default_values_for_test();
        let (port, receiver) = counterpart("opened\n");

        // When: open runs without the re-entry marker.
        open_target(&cfg, "https://example.com/redirect", port, false).unwrap();

        // Then: it sends the URL through the opener channel.
        assert_eq!(receiver.join().unwrap(), "https://example.com/redirect\n");
    }

    #[test]
    fn open_fails_when_the_url_was_only_notified() {
        // Given: a counterpart that handed the URL over rather than opening it.
        let cfg = Config::default_values_for_test();
        let (port, receiver) = counterpart("notified\n");

        // When: open runs.
        let result = open_target(&cfg, "https://example.com/redirect", port, false);

        // Then: it fails, so a caller reading the exit status knows no browser is
        // coming, and the message names the host that was not allowlisted.
        let error = result.unwrap_err().to_string();
        assert!(error.contains("example.com"), "got {error}");
        assert!(error.contains("not allowlisted"), "got {error}");
        receiver.join().unwrap();
    }
}
