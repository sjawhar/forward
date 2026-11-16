/// The daemon timing, touch policy and fixture switches one `Harness` starts with.
struct HarnessSettings {
    cooldown: Duration,
    request_ttl: Duration,
    touch_policy: TouchPolicy,
    pcsc_socket: Option<PathBuf>,
    yubikey_probe_argv: Vec<String>,
    always_stanza_keys: Vec<&'static str>,
    fail_stderr: Option<&'static str>,
    probe_always_fails: bool,
    wait_for_marker: bool,
}

impl HarnessSettings {
    const fn standard(wait_for_marker: bool) -> Self {
        Self {
            cooldown: Duration::from_secs(16),
            request_ttl: Duration::from_secs(20),
            touch_policy: TouchPolicy::Cached,
            pcsc_socket: None,
            yubikey_probe_argv: Vec::new(),
            always_stanza_keys: Vec::new(),
            fail_stderr: None,
            probe_always_fails: false,
            wait_for_marker,
        }
    }

    fn fast() -> Self {
        Self {
            cooldown: Duration::from_secs(1),
            request_ttl: Duration::from_secs(8),
            touch_policy: TouchPolicy::Always,
            ..Self::standard(false)
        }
    }
}
