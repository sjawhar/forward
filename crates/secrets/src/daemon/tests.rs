use super::*;

#[test]
fn rejects_a_cooldown_at_or_below_the_piv_touch_cache() {
    let config = Config {
        socket_path: PathBuf::from("/tmp/secretsd-test.sock"),
        human_sources: Vec::new(),
        sops_bin: PathBuf::from("sops"),
        pcsc_socket: None,
        yubikey_probe_argv: Vec::new(),
        yubikey_probe_timeout: Duration::from_secs(2),
        touch_policy: TouchPolicy::Cached,
        max_grant: Duration::from_secs(1),
        max_requested_grant: Duration::from_secs(1),
        cooldown: Duration::from_secs(15),
        request_ttl: Duration::from_secs(1),
        max_pending_per_scope: 1,
    };
    assert!(config.validate().is_err());
}

#[test]
fn startup_configuration_accepts_an_empty_human_source_set() {
    // Given a daemon configuration whose configured roots currently have no human directories.
    let config = Config {
        socket_path: PathBuf::from("/tmp/secretsd-test.sock"),
        human_sources: Vec::new(),
        sops_bin: PathBuf::from("sops"),
        pcsc_socket: None,
        yubikey_probe_argv: Vec::new(),
        yubikey_probe_timeout: Duration::from_secs(2),
        touch_policy: TouchPolicy::Cached,
        max_grant: Duration::from_secs(1),
        max_requested_grant: Duration::from_secs(1),
        cooldown: Duration::from_secs(16),
        request_ttl: Duration::from_secs(1),
        max_pending_per_scope: 1,
    };

    // When startup validates the configuration.
    let result = config.validate();

    // Then absence of human-tier files is not a configuration failure.
    assert!(result.is_ok());
}

#[test]
fn accepts_a_short_cooldown_when_the_touch_policy_is_always() {
    // Given hardware declared as touch-policy Always, where no touch cache exists.
    let config = Config {
        socket_path: PathBuf::from("/tmp/secretsd-test.sock"),
        human_sources: Vec::new(),
        sops_bin: PathBuf::from("sops"),
        pcsc_socket: None,
        yubikey_probe_argv: Vec::new(),
        yubikey_probe_timeout: Duration::from_secs(2),
        touch_policy: TouchPolicy::Always,
        max_grant: Duration::from_secs(1),
        max_requested_grant: Duration::from_secs(1),
        cooldown: Duration::from_secs(2),
        request_ttl: Duration::from_secs(1),
        max_pending_per_scope: 1,
    };

    // When startup validates the configuration.
    let result = config.validate();

    // Then the touch-cache cooldown floor does not apply.
    assert!(result.is_ok());
}

#[test]
fn rejects_a_short_cooldown_when_the_touch_policy_is_cached() {
    // Given hardware left at the default Cached declaration and a sub-cache cooldown.
    let config = Config {
        socket_path: PathBuf::from("/tmp/secretsd-test.sock"),
        human_sources: Vec::new(),
        sops_bin: PathBuf::from("sops"),
        pcsc_socket: None,
        yubikey_probe_argv: Vec::new(),
        yubikey_probe_timeout: Duration::from_secs(2),
        touch_policy: TouchPolicy::Cached,
        max_grant: Duration::from_secs(1),
        max_requested_grant: Duration::from_secs(1),
        cooldown: Duration::from_secs(2),
        request_ttl: Duration::from_secs(1),
        max_pending_per_scope: 1,
    };

    // When startup validates the configuration.
    let result = config.validate();

    // Then a cooldown inside the touch cache is refused.
    assert!(result.is_err());
}
