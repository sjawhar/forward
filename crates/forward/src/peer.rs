use std::net::IpAddr;

use crate::config::Config;

/// Whether a non-sensitive listener may serve an inbound connection.
///
/// Legacy non-sensitive channels retain their loopback exemption for SSH
/// tunnels and local tools. With `peers`, every source must be explicitly
/// listed, including loopback. Sensitive channels always require the configured
/// local address as well: loopback cannot impersonate a WireGuard peer.
pub fn authorized(cfg: &Config, remote: IpAddr) -> bool {
    (!cfg.is_multi_peer() && remote.to_canonical().is_loopback()) || authorized_remote(cfg, remote)
}

/// Whether the configured remote peer originated a connection.
pub(crate) fn authorized_remote(cfg: &Config, remote: IpAddr) -> bool {
    cfg.admits_peer(remote)
}

/// Whether a sensitive listener received a connection on its configured
/// address from its configured peer. Neither endpoint gets a loopback
/// exemption: a local process can otherwise impersonate the remote peer.
pub(crate) fn authorized_sensitive(cfg: &Config, remote: IpAddr, local: IpAddr) -> bool {
    authorized_remote(cfg, remote)
        && matches!(cfg.listen_ip(), Ok(listen) if listen.to_canonical() == local.to_canonical())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn cfg_with_peer(peer: &str) -> Config {
        let mut cfg = Config::default_values_for_test();
        cfg.peer = peer.to_owned();
        cfg
    }

    #[test]
    fn loopback_is_always_allowed() {
        // Given: any configuration, including one naming a remote peer.
        let cfg = cfg_with_peer("100.64.0.2");

        // When: a same-machine connection arrives.
        // Then: it is allowed, so local tooling and `forward doctor` keep
        // working, and the bridge's own loopback hop is never refused.
        assert!(authorized(&cfg, "127.0.0.1".parse().unwrap()));
        assert!(authorized(&cfg, "::1".parse().unwrap()));
    }

    #[test]
    fn configured_peer_is_allowed() {
        // Given: a configuration naming the counterpart.
        let cfg = cfg_with_peer("100.64.0.2");

        // When: the counterpart connects.
        // Then: it is allowed.
        assert!(authorized(&cfg, "100.64.0.2".parse().unwrap()));
    }

    #[test]
    fn sensitive_listener_requires_the_configured_local_and_remote_addresses() {
        let mut cfg = cfg_with_peer("100.64.0.2");
        cfg.listen = "100.64.0.1".to_owned();

        assert!(authorized_sensitive(
            &cfg,
            "100.64.0.2".parse().unwrap(),
            "100.64.0.1".parse().unwrap()
        ));
        assert!(!authorized_sensitive(
            &cfg,
            "127.0.0.1".parse().unwrap(),
            "100.64.0.1".parse().unwrap()
        ));
        assert!(!authorized_sensitive(
            &cfg,
            "100.64.0.2".parse().unwrap(),
            "127.0.0.1".parse().unwrap()
        ));
    }

    #[test]
    fn mapped_ipv6_peer_matches_ipv4_configured_peer() {
        // Given: a configuration naming an IPv4 counterpart.
        let cfg = cfg_with_peer("100.64.0.2");

        // When: that counterpart connects through an IPv4-mapped IPv6 address.
        // Then: it is allowed as the same address.
        assert!(authorized(&cfg, "::ffff:100.64.0.2".parse().unwrap()));
    }

    #[test]
    fn mapped_ipv6_loopback_is_always_allowed() {
        // Given: any configuration, including one naming a remote peer.
        let cfg = cfg_with_peer("100.64.0.2");

        // When: a same-machine connection arrives through an IPv4-mapped IPv6 address.
        // Then: it is allowed as loopback.
        assert!(authorized(&cfg, "::ffff:127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn other_addresses_are_refused() {
        // Given: a configuration naming one counterpart.
        let cfg = cfg_with_peer("100.64.0.2");

        // When: a different tailnet node, or an off-tailnet address, connects.
        // Then: it is refused — a phone or a tagged service node is not the
        // counterpart, and a personal tailnet routinely holds both.
        assert!(!authorized(&cfg, "100.64.0.9".parse().unwrap()));
        assert!(!authorized(&cfg, "10.0.0.5".parse().unwrap()));
    }

    #[test]
    fn no_peer_means_loopback_only() {
        // Given: no peer configured, which is the default.
        let cfg = cfg_with_peer("");

        // When: a non-loopback address connects.
        // Then: it is refused, and loopback still is not.
        assert!(!authorized(&cfg, "100.64.0.2".parse().unwrap()));
        assert!(authorized(&cfg, "127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn unparseable_peer_denies_everything_remote() {
        // Given: a malformed peer, which Config::validate would have rejected.
        let cfg = cfg_with_peer("not-an-address");

        // When: a remote address connects.
        // Then: it is refused rather than defaulting open.
        assert!(!authorized(&cfg, "100.64.0.2".parse().unwrap()));
        assert!(authorized(&cfg, "127.0.0.1".parse().unwrap()));
    }
}
