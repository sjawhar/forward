use std::io::ErrorKind;
use std::path::Path;

use super::*;
use crate::Config;

#[test]
#[cfg_attr(miri, ignore)]
fn load_reports_missing_configuration_with_creation_guidance() {
    // Given the configuration environment points at a missing file.
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("missing.toml");
    // When the configuration is loaded.
    let result = {
        let _environment = ConfigEnvironment::clear();
        ConfigEnvironment::set("HOME", Path::new("/home/u"));
        ConfigEnvironment::set("SECRETSD_CONFIG", &path);
        Sources::load()
    };

    // Then the missing-file error tells the operator how to create a source root.
    let error = result.unwrap_err();
    assert!(matches!(&error, ConfigError::Missing(missing) if *missing == path));
    assert_eq!(
        error.to_string(),
        format!(
            "no secretsd config at {}; create it with a [source.<name>] table per secrets root, e.g.\n[source.dotfiles]\npath = \"~/dotfiles\"",
            path.display()
        )
    );
}

#[test]
#[cfg_attr(miri, ignore)]
fn from_env_maps_a_missing_source_configuration_to_invalid_input() {
    // Given the daemon configuration environment points at a missing source-root file.
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("missing.toml");

    // When the daemon configuration is constructed.
    let error = {
        let _environment = ConfigEnvironment::clear();
        ConfigEnvironment::set("HOME", Path::new("/home/u"));
        ConfigEnvironment::set("SECRETSD_CONFIG", &path);
        Config::from_env().unwrap_err()
    };

    // Then callers receive an invalid-input error with source configuration guidance.
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    assert!(
        error
            .to_string()
            .contains("create it with a [source.<name>] table per secrets root"),
        "{error}"
    );
}

#[test]
#[cfg_attr(miri, ignore)]
fn load_rejects_an_unset_home_directory() {
    // Given no source configuration override or home directory.
    let result = {
        let _environment = ConfigEnvironment::clear();

        // When sources are loaded.
        Sources::load()
    };

    // Then loading refuses to fabricate a root-relative configuration path.
    assert!(matches!(result, Err(ConfigError::NoHome)));
}

#[test]
#[cfg_attr(miri, ignore)]
fn load_rejects_a_root_that_is_not_a_directory() {
    // Given configuration that names a regular file as a root.
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("not-a-directory");
    std::fs::write(&root, "not a directory").unwrap();
    let config = directory.path().join("config.toml");
    std::fs::write(
        &config,
        format!("[source.dotfiles]\npath = \"{}\"\n", root.display()),
    )
    .unwrap();
    // When the configuration is loaded.
    let result = {
        let _environment = ConfigEnvironment::clear();
        ConfigEnvironment::set("HOME", Path::new("/home/u"));
        ConfigEnvironment::set("SECRETSD_CONFIG", &config);
        Sources::load()
    };

    // Then the named root is rejected because it is not a directory, and the
    // error names the config file that declared it.
    assert!(matches!(
        result,
        Err(ConfigError::RootNotDirectory { name, path, config: declared })
            if name == "dotfiles" && path == root && declared == config
    ));
}
