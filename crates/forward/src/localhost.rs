fn loopback_port(url: &url::Url) -> Option<u16> {
    let host = url.host_str()?;
    let is_loopback = matches!(host, "localhost" | "127.0.0.1" | "[::1]");

    if is_loopback {
        // port() yields None for a scheme's default port even when written explicitly.
        url.port()
    } else {
        None
    }
}

/// Ports the daemon must pre-forward, in first-seen order.
pub fn forward_ports(url: &url::Url) -> Vec<u16> {
    let mut ports = Vec::new();

    if let Some(port) = loopback_port(url) {
        ports.push(port);
    }

    for (key, value) in url.query_pairs() {
        if key == "redirect_uri"
            && let Ok(redirect_url) = url::Url::parse(&value)
            && let Some(port) = loopback_port(&redirect_url)
            && !ports.contains(&port)
        {
            ports.push(port);
        }
    }

    ports
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u(value: &str) -> url::Url {
        url::Url::parse(value).unwrap()
    }

    #[test]
    fn direct_localhost_port() {
        assert_eq!(
            forward_ports(&u("http://localhost:8400/cb?x=1")),
            vec![8400]
        );
    }

    #[test]
    fn loopback_ip() {
        assert_eq!(forward_ports(&u("http://127.0.0.1:9090/")), vec![9090]);
    }

    #[test]
    fn ipv6_loopback() {
        assert_eq!(forward_ports(&u("http://[::1]:8400/cb")), vec![8400]);
    }

    #[test]
    fn no_explicit_port_skipped() {
        assert!(forward_ports(&u("http://localhost/x")).is_empty());
    }

    #[test]
    fn non_localhost_skipped() {
        assert!(forward_ports(&u("https://github.com:8443/")).is_empty());
    }

    #[test]
    fn redirect_uri_port_extracted() {
        let url = u(
            "https://accounts.google.com/o/oauth2/auth?client_id=x&redirect_uri=http%3A%2F%2Flocalhost%3A8085%2F&scope=email",
        );

        assert_eq!(forward_ports(&url), vec![8085]);
    }

    #[test]
    fn uppercase_redirect_uri_is_skipped() {
        let url = u(
            "https://accounts.google.com/o/oauth2/auth?REDIRECT_URI=http%3A%2F%2Flocalhost%3A8085%2F",
        );

        assert!(forward_ports(&url).is_empty());
    }

    #[test]
    fn both_direct_and_redirect_deduped() {
        let url = u("http://localhost:8400/?redirect_uri=http%3A%2F%2F127.0.0.1%3A8400%2Fcb");

        assert_eq!(forward_ports(&url), vec![8400]);
    }

    #[test]
    fn multiple_ports_preserve_order() {
        let url = u(
            "http://localhost:8400/?redirect_uri=http%3A%2F%2F127.0.0.1%3A9000%2F&redirect_uri=http%3A%2F%2Flocalhost%3A8400%2F",
        );

        assert_eq!(forward_ports(&url), vec![8400, 9000]);
    }
}
