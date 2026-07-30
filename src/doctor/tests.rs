use super::*;
use crate::bridge::denied_port;
use crate::callback::PCSC_PORT;
use crate::config::Config;

#[test]
fn the_bridge_probe_asks_for_a_permanently_denylisted_port() {
    // Given: the default configuration.
    let cfg = Config::default_values_for_test();

    // When: the port the bridge probe requests is put through the gate.
    // Then: it is denylisted, so the probe can never reach anything. If the
    // denylist ever stops covering it, this fails loudly instead of the
    // probe quietly becoming a real connection request for a hardware token.
    assert!(denied_port(cfg.bridge_port, PCSC_PORT));
}

#[test]
fn probe_targets_cover_both_roles_without_duplicates() {
    // Given: a devbox-shaped configuration.
    let mut cfg = Config::default_values_for_test();
    cfg.listen = "100.64.0.1".to_owned();
    cfg.peer = "100.64.0.2".to_owned();

    // When: the probe targets are computed.
    // Then: this machine's own address comes first, so the role that owns a
    // channel finds it locally, and the counterpart comes last, so the role
    // that must cross the tailnet finds it there.
    assert_eq!(
        probe_hosts(&cfg),
        vec![
            "100.64.0.1".to_owned(),
            "127.0.0.1".to_owned(),
            "100.64.0.2".to_owned(),
        ]
    );

    // And: the loopback default is not tried twice.
    let cfg = Config::default_values_for_test();
    assert_eq!(probe_hosts(&cfg), vec!["127.0.0.1".to_owned()]);
}

#[test]
fn routable_self_refusals_are_positive_evidence() {
    // Given: a devbox configuration whose self probe originates from its
    // routable listener address rather than the configured counterpart.
    let mut cfg = Config::default_values_for_test();
    cfg.listen = "100.64.0.1".to_owned();
    cfg.peer = "100.64.0.2".to_owned();

    // When: the file server or bridge refuses that self probe.
    // Then: the expected gate refusal is positive channel evidence.
    assert!(evidence_is_healthy(
        &cfg,
        &cfg.listen,
        ProbeEvidence::FileAccessRefused
    ));
    assert!(evidence_is_healthy(
        &cfg,
        &cfg.listen,
        ProbeEvidence::BridgePeerRefused
    ));

    // And: loopback, which the gate should serve, cannot use that exception.
    let cfg = Config::default_values_for_test();
    assert!(!evidence_is_healthy(
        &cfg,
        &cfg.listen,
        ProbeEvidence::FileAccessRefused
    ));
}
