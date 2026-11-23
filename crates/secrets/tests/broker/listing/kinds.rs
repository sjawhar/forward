#[test]
fn a_request_waiting_on_sops_gives_one_request_row_with_its_id() {
    let harness = Harness::start_with_waiting_sops(&["DEEL_API_KEY"]);
    register(&harness);
    let reply = request_later(&harness, "DEEL_API_KEY");
    wait_for_sops_calls(&harness, 1);

    let (answer, seconds) = grants(&harness);
    release(&harness);
    let (granted, _) = reply.join().unwrap();

    let expected = format!("{KIND}request\tDEEL_API_KEY\tsession\tdecrypting, id 1\tNs\n");
    assert_eq!(answer, expected);
    // The standard harness gives a request 20 s; the row shows the time left.
    assert!(
        matches!(seconds.as_slice(), [secs] if *secs <= 20),
        "{seconds:?}"
    );
    assert!(granted.starts_with("OK\tstatus=granted"), "{granted}");
    drop(harness);
}

#[test]
fn a_receipt_after_its_session_ends_gives_one_receipt_row() {
    let harness = Harness::start(&["CAP_BROWSER"]);
    register(&harness);
    let receipt = authorize(&harness);
    unregister(&harness);

    let (answer, seconds) = grants(&harness);

    assert_eq!(
        answer,
        format!("{KIND}receipt\tbrowser\t-\tunredeemed\tNs\n")
    );
    assert!(!answer.contains(&receipt), "the listing named the receipt");
    assert!(
        matches!(seconds.as_slice(), [secs] if *secs <= 60),
        "{seconds:?}"
    );
    drop(harness);
}

#[test]
fn a_capability_grant_after_its_session_ends_gives_one_capability_row() {
    let harness = Harness::start(&["CAP_BROWSER"]);
    register(&harness);
    let receipt = authorize(&harness);
    redeem(&harness, &receipt);
    unregister(&harness);

    let (answer, seconds) = grants(&harness);

    assert_eq!(
        answer,
        format!("{KIND}capability\tbrowser\t-\tactive\tNs\n")
    );
    // The harness's 12 h maximum grant: the row counts down from it.
    assert!(
        matches!(seconds.as_slice(), [secs] if *secs > 43_000),
        "{seconds:?}"
    );
    drop(harness);
}

#[test]
fn a_get_gives_one_row_under_secret_grant() {
    let harness = Harness::start(&["DEEL_API_KEY"]);
    register(&harness);
    get(&harness, "DEEL_API_KEY");

    let (answer, seconds) = grants(&harness);

    assert_eq!(answer, format!("{SECRET_GRANT}DEEL_API_KEY\tsession\tNs\n"));
    assert!(
        matches!(seconds.as_slice(), [secs] if *secs > 43_000),
        "{seconds:?}"
    );
    drop(harness);
}
