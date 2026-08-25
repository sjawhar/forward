use std::path::{Path, PathBuf};

use super::*;

fn rust_sources(directory: &Path, sources: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(directory).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_sources(&path, sources);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            sources.push(path);
        }
    }
}

#[test]
fn missing_file_gives_defaults() {
    let cfg = load(std::path::Path::new("/no/such/config.toml")).unwrap();
    assert_eq!(cfg.mode, Mode::Allowlist);
    assert_eq!(cfg.opener, vec!["xdg-open".to_string()]);
    assert!(cfg.allow.is_empty());
    assert_eq!(
        (cfg.listen.as_str(), cfg.peer.as_str(), cfg.bridge_port),
        ("127.0.0.1", "", 12_801)
    );
    assert_eq!(cfg.listen_ip().unwrap().to_string(), "127.0.0.1");
    assert_eq!(cfg.peer_ip().unwrap(), None);
}

#[test]
fn parses_full_config() {
    let f = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(
        &f,
        r#"
mode = "auto"
opener = ["firefox"]
allow = ["localhost", "*.awsapps.com"]
relay_port = 12803
"#,
    )
    .unwrap();
    let cfg = load(f.path()).unwrap();
    assert_eq!(cfg.mode, Mode::Auto);
    assert_eq!(cfg.opener, vec!["firefox".to_string()]);
    assert!(cfg.notifier.is_empty());
    assert_eq!(cfg.forward_ttl_secs, 300);
    assert_eq!(cfg.allow.len(), 2);
    assert_eq!((cfg.pcsc_port, cfg.grant_port), (12_804, 12_805));
}

#[test]
fn unknown_field_errors() {
    let f = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(&f, "moed = \"auto\"\n").unwrap();
    assert!(load(f.path()).is_err());
}

#[test]
fn malformed_toml_errors() {
    let f = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(&f, "mode = [\n").unwrap();
    assert!(load(f.path()).is_err());
}

#[test]
fn directory_errors_as_read() {
    let directory = tempfile::tempdir().unwrap();
    let err = load(directory.path()).unwrap_err();
    assert!(matches!(err, ConfigError::Read { .. }));
}

#[test]
fn parses_transport_fields() {
    let f = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(
        &f,
        "listen = \"100.64.0.1\"\npeer = \"100.64.0.2\"\nbridge_port = 12345\n",
    )
    .unwrap();

    let cfg = load(f.path()).unwrap();

    // Then: each address parses and the bridge port is honoured.
    assert_eq!(cfg.listen_ip().unwrap().to_string(), "100.64.0.1");
    assert_eq!(cfg.peer_ip().unwrap().unwrap().to_string(), "100.64.0.2");
    assert_eq!(cfg.bridge_port, 12_345);
    assert_eq!(cfg.relay_port, 12_803);
    assert!(cfg.validate().is_ok());

    for (contents, expected) in [("relay_port = 12811\n", 12_811), ("relay_port = 0\n", 0)] {
        std::fs::write(&f, contents).unwrap();
        assert_eq!(load(f.path()).unwrap().relay_port, expected);
    }
}

#[test]
fn non_literal_peer_is_rejected() {
    // Given: a peer given as a name rather than a literal address.
    let f = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(&f, "peer = \"box.example.ts.net\"\n").unwrap();

    // When: the peer address is resolved.
    let cfg = load(f.path()).unwrap();

    // Then: it is refused, because a name is mutable from the Tailscale admin
    // console and must never sit inside an identity check.
    assert!(matches!(
        cfg.peer_ip(),
        Err(ConfigError::Address { field: "peer", .. })
    ));
}

#[test]
fn non_loopback_listen_requires_a_peer() {
    // Given: a tailnet listen address with no counterpart configured.
    let f = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(&f, "listen = \"100.64.0.1\"\n").unwrap();

    // When: the configuration is validated.
    let cfg = load(f.path()).unwrap();

    // Then: it fails closed rather than exposing an unauthenticated port.
    assert!(matches!(cfg.validate(), Err(ConfigError::PeerRequired)));
}

#[test]
fn loopback_listen_needs_no_peer() {
    // Given: the default, loopback-only configuration.
    let cfg = load(std::path::Path::new("/no/such/config.toml")).unwrap();

    // When: it is validated.
    // Then: it is accepted — loopback confinement needs no counterpart.
    assert!(cfg.validate().is_ok());
}

#[test]
fn wildcard_listen_is_rejected_even_with_a_peer() {
    for listen in ["0.0.0.0", "::"] {
        let mut cfg = Config::default_values_for_test();
        cfg.listen = listen.to_owned();
        cfg.peer = "100.64.0.2".to_owned();
        assert!(matches!(
            cfg.validate(),
            Err(ConfigError::Address {
                field: "listen",
                ..
            })
        ));
    }
}

#[test]
fn unspecified_or_multicast_peer_is_rejected() {
    for peer in ["0.0.0.0", "::", "224.0.0.1", "ff02::1"] {
        let mut cfg = Config::default_values_for_test();
        cfg.listen = "100.64.0.1".to_owned();
        cfg.peer = peer.to_owned();
        assert!(matches!(
            cfg.validate(),
            Err(ConfigError::Address { field: "peer", .. })
        ));
    }
}

#[test]
fn broadcast_peer_is_rejected() {
    let mut cfg = Config::default_values_for_test();
    cfg.listen = "100.64.0.1".to_owned();
    cfg.peer = "255.255.255.255".to_owned();
    assert!(matches!(
        cfg.validate(),
        Err(ConfigError::Address { field: "peer", .. })
    ));
}

mod invariants;
