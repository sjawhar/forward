#[test]
#[cfg_attr(miri, ignore)]
fn retry_two_scopes_do_not_block_a_later_successful_request() {
    prepare_retry_log();
    let mut settings = HarnessSettings::fast();
    settings.always_stanza_keys = vec!["ALWAYS_KEY"];
    let ttl = settings.request_ttl;
    let harness = Harness::start_with_settings(
        &["ALWAYS_KEY", "OK_KEY"],
        "fake-sops-fail-once",
        settings,
    );
    register(&harness, TOKEN_A, "first");
    register(&harness, TOKEN_B, "second");
    let first = send_later(
        &harness,
        format!("GET\tkey=ALWAYS_KEY\ttoken={}", token(TOKEN_A)),
    );
    wait_for_path(harness.sops_attempt_marker());
    wait_for_attempts(1);
    let started = Instant::now();

    let (reply, value) = harness.send(&format!("GET\tkey=OK_KEY\ttoken={}", token(TOKEN_B)));

    assert!(started.elapsed() < ttl, "{reply}");
    assert!(reply.starts_with("OK\tlen="), "{reply}");
    assert_eq!(value, b"value-for-OK_KEY");
    let (denied, _) = harness.send("DENY\tid=1");
    assert!(denied.starts_with("OK"), "{denied}");
    let (first_reply, _) = first.join().unwrap();
    assert!(first_reply.contains("DENIED"), "{first_reply}");
}

#[test]
#[cfg_attr(miri, ignore)]
fn retry_deny_between_attempts_stops_further_sops_calls() {
    prepare_retry_log();
    let harness = Harness::start_with_settings(
        &["CAP_BROWSER"],
        "fake-sops-fail-once",
        retry_settings(STANZA_FAILURE),
    );
    register(&harness, TOKEN_A, "deny");
    let authorization = send_later(
        &harness,
        format!("AUTHORIZE\tcap=browser\ttoken={}", token(TOKEN_A)),
    );
    wait_for_path(harness.sops_attempt_marker());
    wait_for_attempts(1);

    let (denied, _) = harness.send("DENY\tid=1");
    let (reply, _) = authorization.join().unwrap();

    assert!(denied.starts_with("OK"), "{denied}");
    assert!(reply.contains("DENIED"), "{reply}");
    assert!(!reply.contains("receipt="), "{reply}");
    assert_eq!(harness.sops_invocations(), 1);
}

#[test]
#[cfg_attr(miri, ignore)]
fn retry_lock_during_an_attempt_denies_without_a_receipt() {
    let mut settings = retry_settings(STANZA_FAILURE);
    settings.wait_for_marker = true;
    let harness = Harness::start_with_settings(&["CAP_BROWSER"], "fake-sops-fail-once", settings);
    register(&harness, TOKEN_A, "lock-in-flight");
    let authorization = send_later(
        &harness,
        format!("AUTHORIZE\tcap=browser\ttoken={}", token(TOKEN_A)),
    );
    wait_for_path(harness.sops_attempt_marker());

    let (locked, _) = harness.send("LOCK");
    std::fs::write(harness.wait_marker(), b"release").unwrap();
    let (reply, _) = authorization.join().unwrap();

    assert!(locked.starts_with("OK"), "{locked}");
    assert!(reply.contains("DENIED"), "{reply}");
    assert!(!reply.contains("receipt="), "{reply}");
    assert_eq!(harness.sops_invocations(), 1);
}

#[test]
#[cfg_attr(miri, ignore)]
fn retry_lock_between_attempts_stops_further_sops_calls() {
    prepare_retry_log();
    let harness = Harness::start_with_settings(
        &["CAP_BROWSER"],
        "fake-sops-fail-once",
        retry_settings(STANZA_FAILURE),
    );
    register(&harness, TOKEN_A, "lock-between");
    let authorization = send_later(
        &harness,
        format!("AUTHORIZE\tcap=browser\ttoken={}", token(TOKEN_A)),
    );
    wait_for_path(harness.sops_attempt_marker());
    wait_for_attempts(1);

    let (locked, _) = harness.send("LOCK");
    let (reply, _) = authorization.join().unwrap();

    assert!(locked.starts_with("OK"), "{locked}");
    assert!(reply.contains("DENIED"), "{reply}");
    assert_eq!(harness.sops_invocations(), 1);
}

#[test]
#[cfg_attr(miri, ignore)]
fn retry_lock_keeps_a_never_attempted_token_request() {
    let mut settings = retry_settings(STANZA_FAILURE);
    settings.wait_for_marker = true;
    let harness = Harness::start_with_settings(
        &["FIRST_KEY", "SECOND_KEY"],
        "fake-sops-fail-once",
        settings,
    );
    register(&harness, TOKEN_A, "first");
    register(&harness, TOKEN_B, "second");
    let first = send_later(
        &harness,
        format!("GET\tkey=FIRST_KEY\ttoken={}", token(TOKEN_A)),
    );
    wait_for_path(harness.sops_attempt_marker());
    let second = send_later(
        &harness,
        format!("GET\tkey=SECOND_KEY\ttoken={}", token(TOKEN_B)),
    );
    for _ in 0..10 {
        thread::yield_now();
    }

    let (locked, _) = harness.send("LOCK");
    std::fs::write(harness.wait_marker(), b"release").unwrap();
    let (first_reply, _) = first.join().unwrap();
    let (second_reply, second_value) = second.join().unwrap();

    assert!(locked.starts_with("OK"), "{locked}");
    assert!(first_reply.contains("DENIED"), "{first_reply}");
    assert!(second_reply.starts_with("OK\tlen="), "{second_reply}");
    assert_eq!(second_value, b"value-for-SECOND_KEY");
    assert_eq!(harness.sops_invocations(), 2);
}
