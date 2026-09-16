use std::io::ErrorKind;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::time::Duration;

use super::super::ConfigEnvironment;
use crate::Config;

#[test]
#[cfg_attr(miri, ignore)]
fn from_env_reads_the_max_requested_grant_from_its_environment() {
    // Given a valid source root and a requested-grant ceiling override.
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
        ConfigEnvironment::set("SECRETSD_MAX_REQUESTED_GRANT_SECS", "3600");
        Config::from_env().unwrap()
    };

    // Then the ceiling is the configured number of seconds.
    assert_eq!(config.max_requested_grant, Duration::from_secs(3_600));
}

#[test]
#[cfg_attr(miri, ignore)]
fn from_env_defaults_the_max_requested_grant_ceiling_to_one_day() {
    // Given a valid source root and no ceiling override in the daemon's environment.
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

    // Then a caller-requested `--ttl` can reach a full day, twice the 12h
    // default a grant gets when the flag is omitted.
    assert_eq!(config.max_requested_grant, Duration::from_hours(24));
}

#[test]
#[cfg_attr(miri, ignore)]
fn from_env_rejects_an_unparseable_max_requested_grant() {
    // Given a valid source root and a malformed requested-grant ceiling.
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
        ConfigEnvironment::set("SECRETSD_MAX_REQUESTED_GRANT_SECS", "not-a-number");
        Config::from_env().unwrap_err()
    };

    // Then startup refuses rather than silently widening the ceiling to its
    // permissive 24h default.
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    assert!(
        error
            .to_string()
            .contains("SECRETSD_MAX_REQUESTED_GRANT_SECS must be a number of seconds"),
        "{error}"
    );
}

#[test]
#[cfg_attr(miri, ignore)]
fn from_env_rejects_an_empty_max_requested_grant() {
    // Given a valid source root and a requested-grant ceiling that is present
    // but empty, e.g. `Environment=SECRETSD_MAX_REQUESTED_GRANT_SECS=` in a
    // unit file.
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
        ConfigEnvironment::set("SECRETSD_MAX_REQUESTED_GRANT_SECS", "");
        Config::from_env().unwrap_err()
    };

    // Then startup refuses rather than treating the empty value as absent and
    // silently restoring the permissive 24h default.
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    assert!(
        error
            .to_string()
            .contains("SECRETSD_MAX_REQUESTED_GRANT_SECS must be a number of seconds"),
        "{error}"
    );
}

#[test]
#[cfg_attr(miri, ignore)]
fn from_env_rejects_a_non_unicode_max_requested_grant() {
    // Given a valid source root and a requested-grant ceiling that is not
    // valid UTF-8.
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
        ConfigEnvironment::set(
            "SECRETSD_MAX_REQUESTED_GRANT_SECS",
            std::ffi::OsStr::from_bytes(b"\xff\xfe"),
        );
        Config::from_env().unwrap_err()
    };

    // Then startup refuses rather than treating non-UTF-8 as absent.
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    assert!(
        error
            .to_string()
            .contains("SECRETSD_MAX_REQUESTED_GRANT_SECS must be a number of seconds"),
        "{error}"
    );
}
