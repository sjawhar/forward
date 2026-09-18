use std::ffi::{OsStr, OsString};
use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use super::{ConfigError, Sources};

static CONFIG_ENVIRONMENT_LOCK: Mutex<()> = Mutex::new(());

struct ConfigEnvironment {
    config: Option<OsString>,
    home: Option<OsString>,
    xdg_config_home: Option<OsString>,
    yubikey_probe_timeout: Option<OsString>,
    touch_policy: Option<OsString>,
    max_requested_grant: Option<OsString>,
    _lock: MutexGuard<'static, ()>,
}

impl ConfigEnvironment {
    fn clear() -> Self {
        let lock = CONFIG_ENVIRONMENT_LOCK.lock().unwrap();
        let config = std::env::var_os("SECRETSD_CONFIG");
        let home = std::env::var_os("HOME");
        let xdg_config_home = std::env::var_os("XDG_CONFIG_HOME");
        let yubikey_probe_timeout = std::env::var_os("SECRETSD_YUBIKEY_PROBE_TIMEOUT_SECS");
        let touch_policy = std::env::var_os("SECRETSD_TOUCH_POLICY");
        let max_requested_grant = std::env::var_os("SECRETSD_MAX_REQUESTED_GRANT_SECS");

        // SAFETY: this test holds the process-wide environment lock and no daemon thread runs.
        unsafe { std::env::remove_var("SECRETSD_CONFIG") };
        // SAFETY: this test holds the process-wide environment lock and no daemon thread runs.
        unsafe { std::env::remove_var("HOME") };
        // SAFETY: this test holds the process-wide environment lock and no daemon thread runs.
        unsafe { std::env::remove_var("XDG_CONFIG_HOME") };
        // SAFETY: this test holds the process-wide environment lock and no daemon thread runs.
        unsafe { std::env::remove_var("SECRETSD_YUBIKEY_PROBE_TIMEOUT_SECS") };
        // SAFETY: this test holds the process-wide environment lock and no daemon thread runs.
        unsafe { std::env::remove_var("SECRETSD_TOUCH_POLICY") };
        // SAFETY: this test holds the process-wide environment lock and no daemon thread runs.
        unsafe { std::env::remove_var("SECRETSD_MAX_REQUESTED_GRANT_SECS") };

        Self {
            config,
            home,
            xdg_config_home,
            yubikey_probe_timeout,
            touch_policy,
            max_requested_grant,
            _lock: lock,
        }
    }

    fn set(name: &str, value: impl AsRef<OsStr>) {
        // SAFETY: this test retains the process-wide environment lock until restoration.
        unsafe { std::env::set_var(name, value) };
    }
}

impl Drop for ConfigEnvironment {
    fn drop(&mut self) {
        for (name, value) in [
            ("SECRETSD_CONFIG", self.config.take()),
            ("HOME", self.home.take()),
            ("XDG_CONFIG_HOME", self.xdg_config_home.take()),
            (
                "SECRETSD_YUBIKEY_PROBE_TIMEOUT_SECS",
                self.yubikey_probe_timeout.take(),
            ),
            ("SECRETSD_TOUCH_POLICY", self.touch_policy.take()),
            (
                "SECRETSD_MAX_REQUESTED_GRANT_SECS",
                self.max_requested_grant.take(),
            ),
        ] {
            match value {
                Some(value) => {
                    // SAFETY: this guard retains the process-wide environment lock until restoration.
                    unsafe { std::env::set_var(name, value) };
                }
                None => {
                    // SAFETY: this guard retains the process-wide environment lock until restoration.
                    unsafe { std::env::remove_var(name) };
                }
            }
        }
    }
}

fn parse(text: &str) -> Result<Sources, ConfigError> {
    Sources::parse(text, Path::new("/home/u"))
}

#[path = "tests/config_path.rs"]
mod config_path;
#[path = "tests/from_env.rs"]
mod from_env;
#[path = "tests/load.rs"]
mod load;
#[path = "tests/roots.rs"]
mod roots;
