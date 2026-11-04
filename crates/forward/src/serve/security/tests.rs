use std::fs;
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt as _;

use tiny_http::{Header, TestRequest};

use crate::config::Config;

fn cfg_listening_on(listen: &str, peer: &str) -> Config {
    let mut cfg = Config::default_values_for_test();
    cfg.listen = listen.to_owned();
    cfg.peer = peer.to_owned();
    cfg
}

fn request(path: &str, remote: &str) -> tiny_http::Request {
    TestRequest::new()
        .with_remote_addr(remote.parse().unwrap())
        .with_path(path)
        .with_header(
            Header::from_bytes(b"Host", b"100.64.0.1:12802")
                .unwrap_or_else(|()| unreachable!("static header is valid")),
        )
        .into()
}

#[test]
fn loopback_defaults_accept_every_host_value_they_did_before() {
    let cfg = cfg_listening_on("127.0.0.1", "");

    assert!(super::host_value_allowed(&cfg, Some("localhost")));
    assert!(super::host_value_allowed(&cfg, Some("LocalHost:12802")));
    assert!(super::host_value_allowed(&cfg, Some("127.0.0.1:12802")));
    assert!(super::host_value_allowed(&cfg, Some("[::1]:12802")));
}

#[test]
fn the_configured_listen_address_is_accepted() {
    let cfg = cfg_listening_on("100.64.0.1", "100.64.0.2");

    assert!(super::host_value_allowed(&cfg, Some("100.64.0.1")));
    assert!(super::host_value_allowed(&cfg, Some("100.64.0.1:12802")));
}

#[test]
fn a_mismatched_host_is_refused() {
    let cfg = cfg_listening_on("100.64.0.1", "100.64.0.2");

    assert!(!super::host_value_allowed(&cfg, Some("evil.example")));
    assert!(!super::host_value_allowed(&cfg, Some("localhost:12802")));
    assert!(!super::host_value_allowed(&cfg, Some("100.64.0.2:12802")));
}

#[test]
fn a_missing_or_unparseable_host_is_refused() {
    let cfg = cfg_listening_on("127.0.0.1", "");

    assert!(!super::host_value_allowed(&cfg, None));
    assert!(!super::host_value_allowed(&cfg, Some("")));
    assert!(!super::host_value_allowed(
        &cfg,
        Some("localhost:not-a-port")
    ));
}

#[test]
fn only_the_configured_peer_is_served() {
    let cfg = cfg_listening_on("100.64.0.1", "100.64.0.2");
    let loopback: SocketAddr = "127.0.0.1:1024".parse().unwrap();
    let counterpart: SocketAddr = "100.64.0.2:1024".parse().unwrap();
    let stranger: SocketAddr = "100.64.0.9:1024".parse().unwrap();

    assert!(!super::peer_addr_allowed(&cfg, Some(&loopback)));
    assert!(super::peer_addr_allowed(&cfg, Some(&counterpart)));
    assert!(!super::peer_addr_allowed(&cfg, Some(&stranger)));
}

#[test]
fn a_connection_with_no_source_address_is_refused() {
    let cfg = cfg_listening_on("100.64.0.1", "100.64.0.2");

    assert!(!super::peer_addr_allowed(&cfg, None));
}

#[test]
fn a_non_counterpart_gets_a_forbidden_response() {
    let cfg = cfg_listening_on("100.64.0.1", "100.64.0.2");
    let request = TestRequest::new()
        .with_remote_addr("100.64.0.9:1024".parse().unwrap())
        .into();

    let reply = super::super::respond(&cfg, &request);

    assert_eq!(reply.status, 403);
}

#[test]
fn a_stranger_with_a_valid_host_header_is_still_refused() {
    let cfg = cfg_listening_on("100.64.0.1", "100.64.0.2");
    let request = request("/etc/hostname", "100.64.0.9:1024");

    let reply = super::super::respond(&cfg, &request);

    assert_eq!(reply.status, 403);
}

#[test]
fn loopback_can_only_read_the_synthetic_preview_health_probe() {
    // This fails if file preview accepts loopback for arbitrary paths: a local
    // uid can otherwise use this tailnet listener to bypass mode 0600.
    let directory = tempfile::tempdir().unwrap();
    let secret = directory.path().join("age-key.txt");
    fs::write(&secret, b"private age identity").unwrap();
    fs::set_permissions(&secret, fs::Permissions::from_mode(0o600)).unwrap();
    let secret_path = secret.to_str().unwrap();
    let cfg = cfg_listening_on("100.64.0.1", "100.64.0.2");

    let loopback_secret = request(secret_path, "127.0.0.1:1024");
    let loopback_probe = TestRequest::new()
        .with_remote_addr("127.0.0.1:1024".parse().unwrap())
        .with_path(super::super::HEALTH_PATH)
        .with_header(
            Header::from_bytes(b"Host", b"127.0.0.1:12802")
                .unwrap_or_else(|()| unreachable!("static header is valid")),
        )
        .into();
    let peer_secret = request(secret_path, "100.64.0.2:1024");

    assert_eq!(super::super::respond(&cfg, &loopback_secret).status, 403);
    for path in ["/etc/hostname", "/.well-known/forward/health?raw=1"] {
        let forbidden = request(path, "127.0.0.1:1024");
        assert_eq!(super::super::respond(&cfg, &forbidden).status, 403);
    }
    assert_eq!(super::super::respond(&cfg, &loopback_probe).status, 200);
    assert_eq!(super::super::respond(&cfg, &peer_secret).status, 200);
}

#[test]
fn preview_health_does_not_require_a_file_on_the_host() {
    let cfg = cfg_listening_on("100.64.0.1", "100.64.0.2");
    let health = request("/.well-known/forward/health", "100.64.0.2:1024");

    let reply = super::super::respond(&cfg, &health);

    assert_eq!(reply.status, 200);
    assert_eq!(reply.body, b"forward preview healthy\n");
}

#[test]
fn preview_health_does_not_authorize_unlisted_peers() {
    let cfg = cfg_listening_on("100.64.0.1", "100.64.0.2");
    let health = request("/.well-known/forward/health", "100.64.0.9:1024");

    assert_eq!(super::super::respond(&cfg, &health).status, 403);
}

#[test]
fn any_loopback_client_can_read_only_the_constant_health_body() {
    let cfg = cfg_listening_on("100.64.0.1", "100.64.0.2");
    let health = TestRequest::new()
        .with_remote_addr("127.0.0.2:1024".parse().unwrap())
        .with_path("/.well-known/forward/health")
        .with_header(Header::from_bytes(b"Host", b"another-host.invalid").unwrap())
        .into();
    let reply = super::super::respond(&cfg, &health);
    assert_eq!(reply.status, 200);
    assert_eq!(reply.body, b"forward preview healthy\n");
}

#[test]
fn peer_health_still_requires_the_correct_host() {
    let cfg = cfg_listening_on("100.64.0.1", "100.64.0.2");
    let health = TestRequest::new()
        .with_remote_addr("100.64.0.2:1024".parse().unwrap())
        .with_path("/.well-known/forward/health")
        .with_header(Header::from_bytes(b"Host", b"another-host.invalid").unwrap())
        .into();
    assert_eq!(super::super::respond(&cfg, &health).status, 403);
}

#[test]
fn loopback_health_path_must_match_exactly() {
    let cfg = cfg_listening_on("100.64.0.1", "100.64.0.2");
    for path in [
        "/.well-known/forward/health/",
        "/.well-known/forward/health?raw=1",
        "/.well-known/forward/health#x",
        "/.well-known/forward/../forward/health",
        "/.well-known/forward%2fhealth",
        "//.well-known/forward/health",
        "/.well-known/forward/%68ealth",
        "/.well-known/forward/HEALTH",
        "/.well-known/forward/./health",
        "/.well-known/forward/health%00",
        "http://100.64.0.1/.well-known/forward/health",
    ] {
        let variant = request(path, "127.0.0.1:1024");
        assert_eq!(super::super::respond(&cfg, &variant).status, 403, "{path}");
    }
}
