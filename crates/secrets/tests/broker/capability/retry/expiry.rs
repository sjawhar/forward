#[test]
#[cfg_attr(miri, ignore)]
fn retry_deny_during_a_failing_attempt_stays_denied() {
    let mut settings = retry_settings(STANZA_FAILURE);
    settings.wait_for_marker = true;
    let harness = Harness::start_with_settings(&["CAP_BROWSER"], "fake-sops-fail-once", settings);
    register(&harness, TOKEN_A, "deny-in-flight");
    let authorization = send_later(
        &harness,
        format!("AUTHORIZE\tcap=browser\ttoken={}", token(TOKEN_A)),
    );
    wait_for_path(harness.sops_attempt_marker());

    let (denied, _) = harness.send("DENY\tid=1");
    std::fs::write(harness.wait_marker(), b"release").unwrap();
    let (reply, _) = authorization.join().unwrap();

    assert!(denied.starts_with("OK"), "{denied}");
    assert!(reply.contains("DENIED"), "{reply}");
    assert_eq!(harness.sops_invocations(), 1);
}

#[test]
#[cfg_attr(miri, ignore)]
fn retry_expiry_during_a_failing_attempt_stays_timed_out() {
    let mut settings = retry_settings(STANZA_FAILURE);
    settings.wait_for_marker = true;
    settings.request_ttl = Duration::from_secs(2);
    let ttl = settings.request_ttl;
    let harness = Harness::start_with_settings(&["CAP_BROWSER"], "fake-sops-fail-once", settings);
    register(&harness, TOKEN_A, "expiry");
    let started = Instant::now();
    let authorization = send_later(
        &harness,
        format!("AUTHORIZE\tcap=browser\ttoken={}", token(TOKEN_A)),
    );
    wait_for_path(harness.sops_attempt_marker());

    let (reply, _) = authorization.join().unwrap();

    assert!(started.elapsed() >= ttl, "{reply}");
    assert!(reply.contains("TIMEOUT"), "{reply}");
    assert_eq!(harness.sops_invocations(), 1);
}
