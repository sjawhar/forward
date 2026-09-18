use std::io::ErrorKind;
use std::path::Path;
use std::time::Duration;

use super::*;
use crate::{Config, TouchPolicy};

#[test]
#[cfg_attr(miri, ignore)]
fn from_env_reads_the_probe_timeout_from_its_environment() {
    // Given a valid source root and a probe timeout override in the daemon's environment.
    let directory = tempfile::tempdir().unwrap();
    let config_file = directory.path().join("config.toml");
    std::fs::write(
        &config_file,
        format!("[source.test]\npath = \"{}\"\n", directory.path().display()),
    )
    .unwrap();

    // When the daemon configuration is constructed.
    let config = {
        let _environment = ConfigEnvironment::clear();
        ConfigEnvironment::set("HOME", Path::new("/home/u"));
        ConfigEnvironment::set("SECRETSD_CONFIG", &config_file);
        ConfigEnvironment::set("SECRETSD_YUBIKEY_PROBE_TIMEOUT_SECS", "7");
        Config::from_env().unwrap()
    };

    // Then the probe timeout is the configured number of seconds.
    assert_eq!(config.yubikey_probe_timeout, Duration::from_secs(7));
}

#[test]
#[cfg_attr(miri, ignore)]
fn from_env_defaults_the_probe_timeout_to_two_seconds() {
    // Given a valid source root and no probe timeout in the daemon's environment.
    let directory = tempfile::tempdir().unwrap();
    let config_file = directory.path().join("config.toml");
    std::fs::write(
        &config_file,
        format!("[source.test]\npath = \"{}\"\n", directory.path().display()),
    )
    .unwrap();

    // When the daemon configuration is constructed.
    let config = {
        let _environment = ConfigEnvironment::clear();
        ConfigEnvironment::set("HOME", Path::new("/home/u"));
        ConfigEnvironment::set("SECRETSD_CONFIG", &config_file);
        Config::from_env().unwrap()
    };

    // Then the probe timeout keeps the direct-pcscd default.
    assert_eq!(config.yubikey_probe_timeout, Duration::from_secs(2));
}

#[test]
#[cfg_attr(miri, ignore)]
fn from_env_reads_an_always_touch_policy() {
    // Given a valid source root and an Always touch-policy declaration.
    let directory = tempfile::tempdir().unwrap();
    let config_file = directory.path().join("config.toml");
    std::fs::write(
        &config_file,
        format!("[source.test]\npath = \"{}\"\n", directory.path().display()),
    )
    .unwrap();

    // When the daemon configuration is constructed.
    let config = {
        let _environment = ConfigEnvironment::clear();
        ConfigEnvironment::set("HOME", Path::new("/home/u"));
        ConfigEnvironment::set("SECRETSD_CONFIG", &config_file);
        ConfigEnvironment::set("SECRETSD_TOUCH_POLICY", "always");
        Config::from_env().unwrap()
    };

    // Then the declared hardware policy is carried into the configuration.
    assert_eq!(config.touch_policy, TouchPolicy::Always);
}

#[test]
#[cfg_attr(miri, ignore)]
fn from_env_defaults_the_touch_policy_to_cached() {
    // Given a valid source root and no touch-policy declaration.
    let directory = tempfile::tempdir().unwrap();
    let config_file = directory.path().join("config.toml");
    std::fs::write(
        &config_file,
        format!("[source.test]\npath = \"{}\"\n", directory.path().display()),
    )
    .unwrap();

    // When the daemon configuration is constructed.
    let config = {
        let _environment = ConfigEnvironment::clear();
        ConfigEnvironment::set("HOME", Path::new("/home/u"));
        ConfigEnvironment::set("SECRETSD_CONFIG", &config_file);
        Config::from_env().unwrap()
    };

    // Then the stricter Cached assumption holds, keeping the cooldown floor.
    assert_eq!(config.touch_policy, TouchPolicy::Cached);
}

#[test]
#[cfg_attr(miri, ignore)]
fn from_env_rejects_an_unknown_touch_policy() {
    // Given a valid source root and an unsupported touch-policy value.
    let directory = tempfile::tempdir().unwrap();
    let config_file = directory.path().join("config.toml");
    std::fs::write(
        &config_file,
        format!("[source.test]\npath = \"{}\"\n", directory.path().display()),
    )
    .unwrap();

    // When the daemon configuration is constructed.
    let error = {
        let _environment = ConfigEnvironment::clear();
        ConfigEnvironment::set("HOME", Path::new("/home/u"));
        ConfigEnvironment::set("SECRETSD_CONFIG", &config_file);
        ConfigEnvironment::set("SECRETSD_TOUCH_POLICY", "never");
        Config::from_env().unwrap_err()
    };

    // Then startup refuses rather than guessing at the hardware's gate.
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    assert!(
        error
            .to_string()
            .contains("SECRETSD_TOUCH_POLICY must be cached (default) or always"),
        "{error}"
    );
}

#[path = "from_env/max_requested_grant.rs"]
mod max_requested_grant;
