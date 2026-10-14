//! The relay row when doctor runs on the devbox side, which reaches the
//! laptop's relay at `peer:relay_port` rather than at its own listen address.

use std::cell::RefCell;
use std::rc::Rc;

use super::browser::evaluate_with;
use crate::config::{Config, default_relay_port};

type Scripted = (
    &'static str,
    u16,
    &'static str,
    Result<&'static [u8], &'static str>,
);

/// Evaluate the relay row against an exact script of probes: a probe the script
/// does not name fails, and so does one it names that never runs.
fn evaluate_scripted(cfg: &Config, script: Vec<Scripted>) -> (bool, String) {
    let script = Rc::new(RefCell::new(script.into_iter()));
    let remaining = Rc::clone(&script);
    let mut request = move |host: &str, port: u16, path: &str| {
        let (expected_host, expected_port, expected_path, response) = remaining
            .borrow_mut()
            .next()
            .expect("unexpected relay probe");
        assert_eq!(
            (host, port, path),
            (expected_host, expected_port, expected_path)
        );
        response.map(<[u8]>::to_vec).map_err(str::to_owned)
    };
    let outcome = evaluate_with(cfg, default_relay_port(), 9_224, &mut request);
    assert!(
        script.borrow_mut().next().is_none(),
        "relay probe was incomplete"
    );
    outcome
}

#[test]
fn a_tunnel_devbox_checks_the_relay_at_its_peer() {
    // Given: the devbox side of an SSH-tunnel pair that has its own laptop
    // address at both ends, while tunnelled connections arrive from 127.0.0.1.
    let cfg = Config {
        listen: "127.0.0.2".to_owned(),
        peer: "127.0.0.1".to_owned(),
        relay_port: 12_803,
        ..Config::default_values_for_test()
    };

    // When: nothing answers at its own address, and the peer wants a token.
    let (healthy, line) = evaluate_scripted(
        &cfg,
        vec![
            (
                "127.0.0.2",
                12_803,
                "/json/version",
                Err("Connection refused"),
            ),
            (
                "127.0.0.1",
                12_803,
                "/json/version",
                Ok(b"REFUSED TOKEN\n".as_slice()),
            ),
        ],
    );

    // Then: the row reports the relay a granted connection dials.
    assert!(healthy, "got {line}");
    assert_eq!(line, "browser relay: locked at 127.0.0.1:12803 (no grant)");
}

#[test]
fn a_devbox_checks_the_peer_at_its_configured_relay_port() {
    // Given: a tailnet devbox whose pair moved the relay off the default port.
    let cfg = Config {
        listen: "100.113.243.90".to_owned(),
        peer: "100.100.92.97".to_owned(),
        relay_port: 12_913,
        ..Config::default_values_for_test()
    };

    // When/Then: the peer is probed on that port, where a granted connection goes.
    let (healthy, line) = evaluate_scripted(
        &cfg,
        vec![
            (
                "100.113.243.90",
                12_913,
                "/json/version",
                Err("Connection refused"),
            ),
            (
                "100.100.92.97",
                12_913,
                "/json/version",
                Ok(b"REFUSED TOKEN\n".as_slice()),
            ),
        ],
    );

    assert!(healthy, "got {line}");
    assert_eq!(
        line,
        "browser relay: locked at 100.100.92.97:12913 (no grant)"
    );
}

#[test]
fn a_loopback_pair_sharing_one_address_reports_its_listener_once() {
    // Given: a loopback pair whose ends share 127.0.0.1, so its own address is the peer.
    let cfg = Config {
        listen: "127.0.0.1".to_owned(),
        peer: "127.0.0.1".to_owned(),
        relay_port: 12_803,
        ..Config::default_values_for_test()
    };

    // When: nothing answers there.
    let (healthy, line) = evaluate_scripted(
        &cfg,
        vec![(
            "127.0.0.1",
            12_803,
            "/json/version",
            Err("Connection refused"),
        )],
    );

    // Then: it fails on that one probe instead of retrying the same address as the peer.
    assert!(!healthy, "got {line}");
    assert_eq!(
        line,
        "browser relay: FAIL — 127.0.0.1:12803 (Connection refused); relay channel down — is forward daemon running?"
    );
}
