use super::*;
use std::path::PathBuf;

#[test]
fn relay_token_path_prefers_the_configured_override() {
    let mut cfg = Config::default_values_for_test();
    cfg.relay_token_file = Some(PathBuf::from("/etc/forward/relay.token"));
    assert_eq!(
        cfg.relay_token_path(),
        Some(PathBuf::from("/etc/forward/relay.token"))
    );
}

#[test]
fn relay_token_path_falls_back_from_xdg_to_home() {
    assert_eq!(
        relay_token_path_from(
            None,
            Some(PathBuf::from("/xdg")),
            Some(PathBuf::from("/home/u"))
        ),
        Some(PathBuf::from("/xdg/forward/relay.token"))
    );
    assert_eq!(
        relay_token_path_from(None, None, Some(PathBuf::from("/home/u"))),
        Some(PathBuf::from("/home/u/.config/forward/relay.token"))
    );
    // A relative or empty variable does not name a usable directory.
    assert_eq!(
        relay_token_path_from(
            None,
            Some(PathBuf::from("relative")),
            Some(PathBuf::from("/home/u"))
        ),
        Some(PathBuf::from("/home/u/.config/forward/relay.token"))
    );
    assert_eq!(relay_token_path_from(None, None, None), None);
}

#[test]
fn relay_token_file_parses_and_defaults_to_none() {
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(&file, "relay_token_file = \"/tmp/relay.token\"\n").unwrap();
    assert_eq!(
        load(file.path()).unwrap().relay_token_file,
        Some(PathBuf::from("/tmp/relay.token"))
    );
    assert_eq!(Config::default_values_for_test().relay_token_file, None);
}
