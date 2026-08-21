use super::*;
use std::path::{Path, PathBuf};

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
fn defaults_are_loopback() {
    // Given: no configuration file.
    let cfg = load(std::path::Path::new("/no/such/config.toml")).unwrap();

    // When: the transport addresses are resolved.
    // Then: they reproduce today's loopback-only behaviour, so an
    // unconfigured install never opens a tailnet port.
    assert_eq!(cfg.listen, "127.0.0.1");
    assert!(cfg.peer.is_empty());
    assert_eq!(cfg.bridge_port, 12_801);
    assert_eq!(cfg.listen_ip().unwrap().to_string(), "127.0.0.1");
    assert_eq!(cfg.peer_ip().unwrap(), None);
}

#[test]
fn parses_transport_fields() {
    // Given: both addresses written as literal tailnet addresses.
    let f = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(
        &f,
        "listen = \"100.64.0.1\"\npeer = \"100.64.0.2\"\nbridge_port = 12345\n",
    )
    .unwrap();

    // When: the file is loaded.
    let cfg = load(f.path()).unwrap();

    // Then: each address parses and the bridge port is honoured.
    assert_eq!(cfg.listen_ip().unwrap().to_string(), "100.64.0.1");
    assert_eq!(cfg.peer_ip().unwrap().unwrap().to_string(), "100.64.0.2");
    assert_eq!(cfg.bridge_port, 12_345);
    assert_eq!(cfg.relay_port, 12_803);
    assert!(cfg.validate().is_ok());

    for (contents, expected) in [
        ("relay_port = 12811\n", 12_811),
        ("relay_port = 0\n", 0),
    ] {
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

#[test]
fn test_constructor_matches_file_defaults() {
    // Given: nothing on disk.
    // When: the constructor later tasks' tests build a Config with is called.
    let cfg = Config::default_values_for_test();

    // Then: it agrees with the on-disk defaults, so a test starting from it
    // exercises the same fail-closed configuration a real install gets.
    assert_eq!(cfg.listen, "127.0.0.1");
    assert!(cfg.peer.is_empty());
    assert_eq!((cfg.bridge_port, cfg.relay_port), (12_801, 12_803));
    assert_eq!(cfg.forward_ttl_secs, 300);
    assert!(cfg.validate().is_ok());
}

#[test]
fn config_with_retired_ssh_fields_is_refused() {
    // Given: a deployed configuration from before the tailnet transport.
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(
        &file,
        "ssh = [\"ssh\"]\ntunnel_host = \"devbox-tunnel-ctl\"\nmode = \"allowlist\"\n",
    )
    .unwrap();

    // When: it is loaded by a binary that no longer has those fields.
    let error = load(file.path()).unwrap_err();

    // Then: deny_unknown_fields refuses it loudly, pointing at the config,
    // rather than silently ignoring settings the operator believes are live.
    assert!(matches!(error, ConfigError::Parse { .. }));
}
#[test]
fn production_source_contains_no_legacy_ssh_transport() {
    // Given: every production Rust source file in the crate.
    let source_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut source_paths = Vec::new();
    rust_sources(&source_root, &mut source_paths);

    // When: comments are excluded.
    let legacy_references: Vec<_> = source_paths
        .iter()
        .filter(|path| !path.ends_with("tests.rs"))
        .filter_map(|path| {
            let executable_source = std::fs::read_to_string(path)
                .unwrap()
                .lines()
                .filter(|line| !line.trim_start().starts_with("//"))
                .collect::<String>();
            (executable_source.to_ascii_lowercase().contains("ssh")
                || executable_source.contains("tunnel_host"))
            .then(|| path.display().to_string())
        })
        .collect();

    // Then: no production file references the retired SSH transport at all.
    assert!(
        legacy_references.is_empty(),
        "legacy SSH transport reference(s) in production source: {legacy_references:?}"
    );
}
