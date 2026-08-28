use std::path::Path;

use super::super::*;
use super::rust_sources;

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
            // Test modules name the retired transport deliberately; the scan is
            // about production code. Excludes both `tests.rs` and any file
            // inside a `tests/` module directory.
            .filter(|path| {
                !path.ends_with("tests.rs")
                    && !path
                        .components()
                        .any(|component| component.as_os_str() == "tests")
            })
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

#[test]
fn channel_ports_default_and_parse() {
    // This fails if the channel ports are missing, misdefaulted, or not
    // overridable from config.toml.
    let cfg = Config::default_values_for_test();
    assert_eq!(cfg.pcsc_port, 12_804);
    assert_eq!(cfg.grant_port, 12_805);
    assert_eq!(cfg.pulse_port, 12_806);

    let parsed: Config =
        toml::from_str("pcsc_port = 0\ngrant_port = 12905\npulse_port = 0\n").unwrap();
    assert_eq!(parsed.pcsc_port, 0);
    assert_eq!(parsed.grant_port, 12_905);
    assert_eq!(parsed.pulse_port, 0);
}
