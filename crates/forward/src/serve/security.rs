use std::net::SocketAddr;

use tiny_http::Request;

use crate::config::Config;
use crate::peer::authorized;

/// Whether an inbound connection's source address may be served at all.
///
/// `tiny_http` parses the request before `respond` can run any check, so a
/// refused peer still reaches the HTTP parser. That residual exposure is
/// accepted: it is parser exposure, not file-read exposure, and a tailnet ACL
/// can narrow it as optional hardening. This check — user-owned, not any
/// org-owned ACL — is the authorization control for file reads.
///
/// **What passing this gate grants.** This server resolves any absolute path and
/// applies no root, so an allowed peer can read every file the serving user can —
/// private keys and credential caches included. For the counterpart that is
/// deliberate: `forward url` exists to preview arbitrary paths, and the laptop
/// already has SSH here, so it gains nothing new.
///
/// The consequence worth stating is local. `peer::authorized` always allows
/// loopback, and a local process can forge any `Host` header over raw TCP, so on a
/// multi-user machine **any** local user can read the serving user's files through
/// this port, mode 0600 included. The previous loopback-only bind had the same
/// property, so this is not a regression — but the SSH tunnel used to be a second
/// barrier and no longer is, and this check is now the entire access control.
/// Narrowing it means dropping the unconditional loopback allowance, which would
/// break `forward doctor` and the bridge's own loopback hop; do not do that without
/// replacing both.
pub(super) fn peer_allowed(cfg: &Config, request: &Request) -> bool {
    peer_addr_allowed(cfg, request.remote_addr())
}

/// Whether the `Host` header names the address this server was configured to
/// listen on.
///
/// The check exists to stop DNS rebinding, so a missing `Host` stays refused and
/// only the accepted value changes: the configured `listen` address, plus the
/// loopback names when `listen` is itself loopback — which is the default, and
/// therefore today's behaviour exactly.
pub(super) fn host_allowed(cfg: &Config, request: &Request) -> bool {
    let header = request
        .headers()
        .iter()
        .find(|header| header.field.equiv("Host"));
    host_value_allowed(cfg, header.map(|header| header.value.as_str()))
}

fn peer_addr_allowed(cfg: &Config, remote: Option<&SocketAddr>) -> bool {
    // `None` means tiny_http could not report a source address, which only
    // happens for a unix-socket listener forward never builds. Refusing is the
    // fail-closed reading of "we do not know who this is".
    remote.is_some_and(|remote| authorized(cfg, remote.ip()))
}

fn host_value_allowed(cfg: &Config, value: Option<&str>) -> bool {
    let Some(value) = value else {
        return false;
    };
    let value = value.to_ascii_lowercase();
    let Some(host) = host_part(&value) else {
        return false;
    };
    if host == cfg.listen.to_ascii_lowercase() {
        return true;
    }
    matches!(cfg.listen_ip(), Ok(listen) if listen.is_loopback())
        && matches!(host, "localhost" | "127.0.0.1" | "::1")
}

/// The host part of a `Host` header value, with IPv6 brackets removed so it can
/// be compared against a literal `listen` address, which carries none.
///
/// Returns `None` when the value carries something that is not a port, so a
/// malformed header is refused rather than silently truncated to a host.
fn host_part(value: &str) -> Option<&str> {
    if let Some(rest) = value.strip_prefix('[') {
        let (host, tail) = rest.split_once(']')?;
        if tail.is_empty()
            || tail
                .strip_prefix(':')
                .is_some_and(|port| port.parse::<u16>().is_ok())
        {
            return Some(host);
        }
        return None;
    }
    match value.split_once(':') {
        Some((host, port)) if port.parse::<u16>().is_ok() => Some(host),
        Some(_) => None,
        None => Some(value),
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use tiny_http::TestRequest;

    use crate::config::Config;

    fn cfg_listening_on(listen: &str, peer: &str) -> Config {
        let mut cfg = Config::default_values_for_test();
        cfg.listen = listen.to_owned();
        cfg.peer = peer.to_owned();
        cfg
    }

    #[test]
    fn loopback_defaults_accept_every_host_value_they_did_before() {
        // Given: the default loopback configuration, which an unconfigured
        // install still gets.
        let cfg = cfg_listening_on("127.0.0.1", "");

        // When: a browser sends each Host value that worked before this change.
        // Then: all of them still work, so defaults behave exactly as today.
        assert!(super::host_value_allowed(&cfg, Some("localhost")));
        assert!(super::host_value_allowed(&cfg, Some("LocalHost:12802")));
        assert!(super::host_value_allowed(&cfg, Some("127.0.0.1:12802")));
        assert!(super::host_value_allowed(&cfg, Some("[::1]:12802")));
    }

    #[test]
    fn the_configured_listen_address_is_accepted() {
        // Given: a file server configured to listen on a tailnet address.
        let cfg = cfg_listening_on("100.64.0.1", "100.64.0.2");

        // When: the browser sends that address as its Host, with and without a
        // port.
        // Then: both are accepted, because the check follows configuration
        // instead of a hardcoded loopback list.
        assert!(super::host_value_allowed(&cfg, Some("100.64.0.1")));
        assert!(super::host_value_allowed(&cfg, Some("100.64.0.1:12802")));
    }

    #[test]
    fn a_mismatched_host_is_refused() {
        // Given: a file server configured to listen on a tailnet address.
        let cfg = cfg_listening_on("100.64.0.1", "100.64.0.2");

        // When: the Host names anything else — including the loopback names a
        // loopback-bound server still accepts, and the counterpart's address.
        // Then: every one is refused. This is the DNS-rebinding protection the
        // check exists for; only the accepted value changed.
        assert!(!super::host_value_allowed(&cfg, Some("evil.example")));
        assert!(!super::host_value_allowed(&cfg, Some("localhost:12802")));
        assert!(!super::host_value_allowed(&cfg, Some("100.64.0.2:12802")));
    }

    #[test]
    fn a_missing_or_unparseable_host_is_refused() {
        // Given: any configuration.
        let cfg = cfg_listening_on("127.0.0.1", "");

        // When: the Host header is absent, empty, or carries a junk port.
        // Then: each is refused rather than defaulting open. Refusing a missing
        // Host is already correct on this branch and stays.
        assert!(!super::host_value_allowed(&cfg, None));
        assert!(!super::host_value_allowed(&cfg, Some("")));
        assert!(!super::host_value_allowed(
            &cfg,
            Some("localhost:not-a-port")
        ));
    }

    #[test]
    fn only_loopback_and_the_configured_peer_are_served() {
        // Given: a file server whose counterpart is one tailnet node.
        let cfg = cfg_listening_on("100.64.0.1", "100.64.0.2");
        let loopback: SocketAddr = "127.0.0.1:1024".parse().unwrap();
        let counterpart: SocketAddr = "100.64.0.2:1024".parse().unwrap();
        let stranger: SocketAddr = "100.64.0.9:1024".parse().unwrap();

        // When: connections arrive from loopback, the counterpart, and a third
        // tailnet node — a phone, say.
        // Then: only the first two are served. This port can read any file the
        // serving user can read, so a non-counterpart gets 403 and nothing else.
        assert!(super::peer_addr_allowed(&cfg, Some(&loopback)));
        assert!(super::peer_addr_allowed(&cfg, Some(&counterpart)));
        assert!(!super::peer_addr_allowed(&cfg, Some(&stranger)));
    }

    #[test]
    fn a_connection_with_no_source_address_is_refused() {
        // Given: any configuration.
        let cfg = cfg_listening_on("100.64.0.1", "100.64.0.2");

        // When: the server cannot report a source address, which tiny_http only
        // does for a unix-socket listener forward never builds.
        // Then: it fails closed instead of being treated as local.
        assert!(!super::peer_addr_allowed(&cfg, None));
    }

    #[test]
    fn a_non_counterpart_gets_a_forbidden_response() {
        // Given: a request whose reported source is a different tailnet node.
        let cfg = cfg_listening_on("100.64.0.1", "100.64.0.2");
        let request = TestRequest::new()
            .with_remote_addr("100.64.0.9:1024".parse().unwrap())
            .into();

        // When: the file server handles the request.
        let reply = super::super::respond(&cfg, &request);

        // Then: the observable HTTP response is 403, not merely a denied helper call.
        assert_eq!(reply.status, 403);
    }

    #[test]
    fn a_stranger_with_a_valid_host_header_is_still_refused() {
        // Given: a request from a non-counterpart tailnet node that presents
        // a Host value the server accepts. `host_allowed` passes, so the peer
        // check in `respond` is the only thing standing between this stranger
        // and a file read — deleting that check would serve the file.
        let cfg = cfg_listening_on("100.64.0.1", "100.64.0.2");
        let request = TestRequest::new()
            .with_remote_addr("100.64.0.9:1024".parse().unwrap())
            .with_path("/etc/hostname")
            .with_header(
                tiny_http::Header::from_bytes(b"Host", b"100.64.0.1:12802")
                    .unwrap_or_else(|()| unreachable!("static header is valid")),
            )
            .into();

        // When: the file server handles the request.
        let reply = super::super::respond(&cfg, &request);

        // Then: the peer gate refuses it, not merely a denied helper call.
        assert_eq!(reply.status, 403);
    }
}
