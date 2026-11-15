fn probe_settings(always_fails: bool) -> (tempfile::TempDir, HarnessSettings) {
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("pcsc.socket");
    std::fs::write(&socket, b"probe").unwrap();
    let fixture = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/fake-yubikey-probe-fail-once");
    let mut settings = HarnessSettings::fast();
    settings.pcsc_socket = Some(socket);
    settings.yubikey_probe_argv = vec![fixture.to_string_lossy().into_owned()];
    settings.probe_always_fails = always_fails;
    (directory, settings)
}

#[test]
#[cfg_attr(miri, ignore)]
fn retry_authorize_retries_a_missed_yubikey_stanza() {
    retry_authorize_after_sops_failure(STANZA_FAILURE, "yubikey-stanza-undecryptable");
}

#[test]
#[cfg_attr(miri, ignore)]
fn retry_authorize_retries_a_yubikey_plugin_failure() {
    retry_authorize_after_sops_failure(PLUGIN_FAILURE, "yubikey-plugin-error");
}

#[test]
#[cfg_attr(miri, ignore)]
fn retry_authorize_retries_a_pcsc_failure() {
    retry_authorize_after_sops_failure(PCSC_FAILURE, "pcsc-communication-error");
}

#[test]
#[cfg_attr(miri, ignore)]
fn retry_authorize_retries_a_failed_yubikey_probe() {
    prepare_retry_log();
    let (_directory, settings) = probe_settings(false);
    let harness = Harness::start_with_settings(&["CAP_BROWSER"], "fake-sops-ok", settings);
    register(&harness, TOKEN_A, "probe");

    let (reply, _) = harness.send(&format!("AUTHORIZE\tcap=browser\ttoken={}", token(TOKEN_A)));

    assert!(reply.starts_with("OK\tstatus=authorized receipt="), "{reply}");
    assert_two_attempts("yubikey-unreachable-probe");
    assert_eq!(harness.sops_invocations(), 1);
}

#[test]
#[cfg_attr(miri, ignore)]
fn retry_get_retries_a_human_tier_key() {
    prepare_retry_log();
    let harness = Harness::start_with_settings(
        &["DEEL_API_KEY"],
        "fake-sops-fail-once",
        retry_settings(STANZA_FAILURE),
    );
    register(&harness, TOKEN_A, "get");

    let (reply, value) = harness.send(&format!("GET\tkey=DEEL_API_KEY\ttoken={}", token(TOKEN_A)));

    assert!(reply.starts_with("OK\tlen="), "{reply}");
    assert_eq!(value, b"value-for-DEEL_API_KEY");
    assert_two_attempts("yubikey-stanza-undecryptable");
}

#[test]
#[cfg_attr(miri, ignore)]
fn retry_always_failing_stanza_times_out_at_the_request_ttl() {
    let mut settings = HarnessSettings::fast();
    settings.always_stanza_keys = vec!["CAP_BROWSER"];
    let ttl = settings.request_ttl;
    let harness = Harness::start_with_settings(&["CAP_BROWSER"], "fake-sops-fail-once", settings);
    register(&harness, TOKEN_A, "timeout");
    let started = Instant::now();

    let (reply, _) = harness.send(&format!("AUTHORIZE\tcap=browser\ttoken={}", token(TOKEN_A)));

    assert!(started.elapsed() >= ttl, "{reply}");
    assert!(reply.contains("TIMEOUT"), "{reply}");
    assert!(harness.sops_invocations() >= 2, "{reply}");
}

#[test]
#[cfg_attr(miri, ignore)]
fn retry_always_failing_probe_reports_unreachable_at_the_request_ttl() {
    let (_directory, settings) = probe_settings(true);
    let ttl = settings.request_ttl;
    let harness = Harness::start_with_settings(&["CAP_BROWSER"], "fake-sops-ok", settings);
    register(&harness, TOKEN_A, "unreachable");
    let started = Instant::now();

    let (reply, _) = harness.send(&format!("AUTHORIZE\tcap=browser\ttoken={}", token(TOKEN_A)));

    assert!(started.elapsed() >= ttl, "{reply}");
    assert!(reply.contains("YUBIKEY_UNREACHABLE"), "{reply}");
    assert_eq!(harness.sops_invocations(), 0, "{reply}");
}
