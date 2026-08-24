use crate::callback::{MAX_DYNAMIC_FORWARDS, is_dynamic_port};
use crate::config::Config;
use crate::localhost::forward_ports;
use std::path::Path;
use url::Url;

/// Devbox loopback ports an OAuth callback for this URL may arrive on.
///
/// Derived from the same `forward_ports` the laptop uses, so there is no port
/// negotiation. forward's own service ports are excluded: arming one would
/// let the bridge route callback bytes into a forward listener.
pub fn callback_ports(cfg: &Config, url: &Url) -> Vec<u16> {
    let mut ports: Vec<u16> = forward_ports(url)
        .into_iter()
        .filter(|port| is_dynamic_port(cfg, *port))
        .collect();
    if ports.len() > MAX_DYNAMIC_FORWARDS {
        eprintln!(
            "forward: dynamic forward limit reached; dropped {} port(s)",
            ports.len() - MAX_DYNAMIC_FORWARDS
        );
        ports.truncate(MAX_DYNAMIC_FORWARDS);
    }
    ports
}

/// Arms this URL's callback ports on the local `forward serve` bridge before
/// sending the URL, so the laptop's relay does not refuse browser callbacks.
///
/// A failure warns and returns zero rather than aborting: `forward serve` may
/// not be running, and losing the browser open would be worse than losing the
/// callback. This matches today's behaviour, where a failed forward still opens
/// the URL.
pub fn arm_for_url(cfg: &Config, url: &Url, socket: &Path) -> usize {
    let ports = callback_ports(cfg, url);
    if ports.is_empty() {
        return 0;
    }
    if !super::arm(socket, &ports, cfg.forward_ttl_secs) {
        eprintln!(
            "forward: could not arm callback port(s) {ports:?} on the local bridge; \
             is 'forward serve' running? sending the URL anyway"
        );
        return 0;
    }
    ports.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u(value: &str) -> Url {
        url::Url::parse(value).unwrap()
    }

    #[test]
    fn the_file_preview_port_is_never_armed() {
        // Given: the preview URL `forward open <path>` mints, on the static
        // file-server port.
        let url = u("http://localhost:12802/tmp/notes.md");

        // When: its callback ports are computed.
        // Then: none — arming a forward service port would be a bridge escape.
        assert!(callback_ports(&Config::default_values_for_test(), &url).is_empty());
    }

    #[test]
    fn an_oauth_callback_port_is_selected() {
        // Given: a provider URL whose redirect_uri is devbox loopback 8400.
        let url = u(
            "https://accounts.google.com/o/oauth2/auth?client_id=x&redirect_uri=http%3A%2F%2Flocalhost%3A8400%2F",
        );

        // When: its callback ports are computed.
        // Then: the callback port is armed and nothing else is.
        assert_eq!(
            callback_ports(&Config::default_values_for_test(), &url),
            vec![8400]
        );
    }

    #[test]
    fn more_ports_than_the_cap_are_truncated() {
        // Given: a URL naming five distinct loopback ports.
        let url = u(
            "http://localhost:8400/?redirect_uri=http%3A%2F%2F127.0.0.1%3A9001%2F&redirect_uri=http%3A%2F%2F127.0.0.1%3A9002%2F&redirect_uri=http%3A%2F%2F127.0.0.1%3A9003%2F&redirect_uri=http%3A%2F%2F127.0.0.1%3A9004%2F",
        );

        // When: its callback ports are computed.
        // Then: the cap holds and first-seen order is preserved, matching the
        // laptop's own cap so both sides agree on the set.
        assert_eq!(
            callback_ports(&Config::default_values_for_test(), &url),
            vec![8400, 9001, 9002, 9003]
        );
    }
}
