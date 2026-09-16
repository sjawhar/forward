use std::path::Path;

use super::*;

#[test]
#[cfg_attr(miri, ignore)]
fn config_path_prefers_the_explicit_override() {
    // Given every config-path environment variable is set.
    // When the configuration path is resolved.
    let path = {
        let _environment = ConfigEnvironment::clear();
        ConfigEnvironment::set("HOME", Path::new("/home/u"));
        ConfigEnvironment::set("XDG_CONFIG_HOME", Path::new("/xdg"));
        ConfigEnvironment::set("SECRETSD_CONFIG", Path::new("/custom/config.toml"));
        Sources::config_path().unwrap()
    };

    // Then the explicit override wins.
    assert_eq!(path, Path::new("/custom/config.toml"));
}

#[test]
#[cfg_attr(miri, ignore)]
fn config_path_falls_back_to_xdg_config_home() {
    // Given no explicit path and an XDG configuration directory.
    // When the configuration path is resolved.
    let path = {
        let _environment = ConfigEnvironment::clear();
        ConfigEnvironment::set("HOME", Path::new("/home/u"));
        ConfigEnvironment::set("XDG_CONFIG_HOME", Path::new("/xdg"));
        Sources::config_path().unwrap()
    };

    // Then it is placed under the XDG configuration directory.
    assert_eq!(path, Path::new("/xdg/secretsd/config.toml"));
}

#[test]
#[cfg_attr(miri, ignore)]
fn config_path_falls_back_to_home_config_directory_and_rejects_relative_home() {
    // Given neither an explicit path nor an XDG configuration directory, and absolute or relative HOME values.
    // When the configuration path is resolved for each home-directory value.
    let [absolute, relative] = [Path::new("/home/u"), Path::new("relhome")].map(|home| {
        let _environment = ConfigEnvironment::clear();
        ConfigEnvironment::set("HOME", home);
        Sources::config_path()
    });

    // Then it uses the conventional absolute home configuration directory and refuses a relative fallback.
    assert_eq!(
        absolute.unwrap(),
        Path::new("/home/u/.config/secretsd/config.toml")
    );
    assert!(matches!(relative, Err(ConfigError::NoHome)));
}
