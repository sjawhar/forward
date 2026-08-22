use super::browser::{RelayEvidence, classify};
use super::*;
use crate::bridge::denied_port;
use crate::callback::PCSC_PORT;
use crate::config::Config;
use std::net::TcpListener;
use std::thread;

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

#[test]
fn classifies_browser_relay_responses() {
    assert_eq!(classify(b"REFUSED PEER\n"), Ok(RelayEvidence::PeerRefused));
    assert_eq!(classify(b"REFUSED\n"), Ok(RelayEvidence::UpstreamDown));
    assert_eq!(classify(b"REFUSED BUSY\n"), Ok(RelayEvidence::Busy));
    assert_eq!(
        classify(b"HTTP/1.1 200 OK\r\n\r\n{}"),
        Ok(RelayEvidence::Healthy)
    );
    assert_eq!(
        classify(b"HTTP/1.1 503 Service Unavailable\r\n\r\n"),
        Ok(RelayEvidence::ExtensionDisconnected)
    );
    assert!(classify(b"unexpected").is_err());
}

fn spawn_relay(responses: &[&'static [u8]]) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let responses = responses.to_vec();
    thread::spawn(move || {
        for response in responses {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 512];
            let _ = stream.read(&mut request);
            stream.write_all(response).unwrap();
        }
    });
    port
}

fn dropped_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

#[test]
fn browser_relay_is_healthy_when_disabled_without_a_peer() {
    let mut cfg = Config::default_values_for_test();
    cfg.relay_port = 0;

    assert_eq!(
        super::browser::evaluate(&cfg, 0),
        (true, "browser relay: disabled (relay_port = 0)".to_owned())
    );
}

#[test]
fn browser_relay_probes_the_devbox_peer_end_to_end() {
    let mut cfg = Config::default_values_for_test();
    cfg.relay_port = 0;
    cfg.peer = "127.0.0.1".to_owned();
    let port = spawn_relay(&[
        b"HTTP/1.0 200 OK\r\n\r\n{}",
        b"HTTP/1.0 200 OK\r\n\r\n[{\"id\":\"relay-1\",\"title\":\"Example\",\"type\":\"page\",\"url\":\"https://example.test/\"}]",
    ]);

    let (healthy, line) = super::browser::evaluate(&cfg, port);

    assert!(healthy, "got {line}");
    assert!(line.contains("browser relay: healthy"), "got {line}");
    assert!(line.contains("(1 targets)"), "got {line}");
}

#[test]
fn browser_relay_reports_a_disconnected_extension_as_information() {
    let mut cfg = Config::default_values_for_test();
    cfg.relay_port = 0;
    cfg.peer = "127.0.0.1".to_owned();
    let port = spawn_relay(&[b"HTTP/1.0 503 Service Unavailable\r\n\r\n"]);

    let (healthy, line) = super::browser::evaluate(&cfg, port);

    assert!(healthy, "got {line}");
    assert!(
        line.contains("extension not connected — check the badge"),
        "got {line}"
    );
}

#[test]
fn browser_relay_reports_a_peer_refusal_from_the_devbox() {
    let mut cfg = Config::default_values_for_test();
    cfg.relay_port = 0;
    cfg.peer = "127.0.0.1".to_owned();
    let port = spawn_relay(&[b"REFUSED PEER\n"]);

    let (healthy, line) = super::browser::evaluate(&cfg, port);

    assert!(!healthy, "got {line}");
    assert!(
        line.contains("not the configured peer — check peer on the laptop"),
        "got {line}"
    );
}

#[test]
fn browser_relay_reports_a_missing_upstream_from_the_devbox() {
    let mut cfg = Config::default_values_for_test();
    cfg.relay_port = 0;
    cfg.peer = "127.0.0.1".to_owned();
    let port = spawn_relay(&[b"REFUSED\n"]);

    let (healthy, line) = super::browser::evaluate(&cfg, port);

    assert!(!healthy, "got {line}");
    assert!(
        line.contains("relay process down — start omp-browser-relay"),
        "got {line}"
    );
}

#[test]
fn browser_relay_reports_an_unbound_laptop_listener() {
    let cfg = Config {
        relay_port: dropped_port(),
        ..Config::default_values_for_test()
    };

    let (healthy, line) = super::browser::evaluate(&cfg, 0);

    assert!(!healthy, "got {line}");
    assert!(
        line.contains("relay channel down — is forward daemon running?"),
        "got {line}"
    );
}

#[test]
fn browser_relay_accepts_a_loopback_laptop_probe_end_to_end() {
    let port = spawn_relay(&[
        b"HTTP/1.0 200 OK\r\n\r\n{}",
        b"HTTP/1.0 200 OK\r\n\r\n[{\"id\":\"relay-1\",\"title\":\"Example\",\"type\":\"page\",\"url\":\"https://example.test/\"}]",
    ]);
    let cfg = Config {
        relay_port: port,
        ..Config::default_values_for_test()
    };

    let (healthy, line) = super::browser::evaluate(&cfg, 0);

    assert!(healthy, "got {line}");
    assert!(line.contains("browser relay: healthy"), "got {line}");
}
