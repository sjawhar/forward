use super::browser::evaluate_with;
use crate::config::Config;
use crate::config::{default_relay_port, load};
use std::cell::RefCell;
use std::net::TcpListener;
use std::rc::Rc;

fn ephemeral_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

#[test]
fn laptop_peer_refusal_proves_the_listener_then_checks_the_direct_relay() {
    const LISTEN: &str = "100.64.0.1";
    let relay_port = ephemeral_port();
    let upstream_port = ephemeral_port();
    let cfg = Config {
        listen: LISTEN.to_owned(),
        peer: "100.64.0.2".to_owned(),
        relay_port,
        ..Config::default_values_for_test()
    };
    let responses = Rc::new(RefCell::new(
        [
            (
                LISTEN,
                relay_port,
                "/json/version",
                b"REFUSED PEER\n".as_slice(),
            ),
            (
                "127.0.0.1",
                upstream_port,
                "/json/version",
                b"HTTP/1.0 200 OK\r\n\r\n{}".as_slice(),
            ),
            (
                "127.0.0.1",
                upstream_port,
                "/json/list",
                b"HTTP/1.0 200 OK\r\n\r\n[{\"webSocketDebuggerUrl\":\"ws://relay\"}]".as_slice(),
            ),
        ]
        .into_iter(),
    ));
    let expected = Rc::clone(&responses);
    let mut request = move |host: &str, port: u16, path: &str| {
        let (expected_host, expected_port, expected_path, response) = expected
            .borrow_mut()
            .next()
            .expect("unexpected relay probe");
        assert_eq!(
            (host, port, path),
            (expected_host, expected_port, expected_path)
        );
        Ok(response.to_vec())
    };

    let (healthy, line) = evaluate_with(&cfg, relay_port, upstream_port, &mut request);

    assert!(healthy, "got {line}");
    assert!(line.contains("browser relay: healthy"), "got {line}");
    assert!(line.contains("(1 targets)"), "got {line}");
    assert!(
        responses.borrow_mut().next().is_none(),
        "relay probe was incomplete"
    );
}

#[test]
fn devbox_config_without_relay_port_probes_the_laptop_peer() {
    const LISTEN: &str = "100.113.243.90";
    const PEER: &str = "100.100.92.97";
    let config = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(
        config.path(),
        format!("listen = \"{LISTEN}\"\npeer = \"{PEER}\"\n"),
    )
    .unwrap();
    let cfg = load(config.path()).unwrap();
    let relay_port = default_relay_port();
    assert_eq!(cfg.relay_port, relay_port);

    let responses = Rc::new(RefCell::new(
        [
            (
                LISTEN,
                relay_port,
                "/json/version",
                Err("Connection refused".to_owned()),
            ),
            (
                PEER,
                relay_port,
                "/json/version",
                Ok(b"HTTP/1.0 200 OK\r\n\r\n{}".as_slice()),
            ),
            (
                PEER,
                relay_port,
                "/json/list",
                Ok(
                    b"HTTP/1.0 200 OK\r\n\r\n[{\"webSocketDebuggerUrl\":\"ws://relay\"}]"
                        .as_slice(),
                ),
            ),
        ]
        .into_iter(),
    ));
    let expected = Rc::clone(&responses);
    let mut request = move |host: &str, port: u16, path: &str| {
        let (expected_host, expected_port, expected_path, response) = expected
            .borrow_mut()
            .next()
            .expect("unexpected relay probe");
        assert_eq!(
            (host, port, path),
            (expected_host, expected_port, expected_path)
        );
        response.map(|body| body.to_vec())
    };

    let (healthy, line) = evaluate_with(&cfg, relay_port, 9_224, &mut request);

    assert!(healthy, "got {line}");
    assert!(line.contains("browser relay: healthy"), "got {line}");
    assert!(
        responses.borrow_mut().next().is_none(),
        "relay probe was incomplete"
    );
}
