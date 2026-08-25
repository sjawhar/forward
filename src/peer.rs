use std::net::IpAddr;

use crate::config::Config;

/// Whether an inbound connection may be served.
///
/// Loopback is always allowed: it is the same machine, and refusing it would
/// break `forward doctor`, local tooling, and the bridge's own final hop to a
/// loopback-bound callback listener. Anything else must equal the configured
/// counterpart exactly. A missing or malformed `peer` denies every remote
/// address rather than defaulting open — `Config::validate` refuses that
/// combination at startup, and this is the second line of defence for a
/// process that reached a listener some other way.
///
/// Address equality is an identity check only because `Config::validate`
/// guarantees that the listener is bound to a specific tailnet address rather
/// than a wildcard address. On that listener, WireGuard authenticates inbound
/// packets against a peer's key and its `AllowedIPs`, and Tailscale addresses
/// are unique within the tailnet. This check alone is not safe on an arbitrary
/// listener, where an on-link host could own a CGNAT address.
pub fn authorized(cfg: &Config, remote: IpAddr) -> bool {
    let remote = remote.to_canonical();
    if remote.is_loopback() {
        return true;
    }
    matches!(cfg.peer_ip(), Ok(Some(peer)) if peer.to_canonical() == remote)
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
