#[test]
fn authorization_and_redemption_never_log_credentials() {
    install_request_log_capture();
    match request_log().lock() {
        Ok(mut log) => log.clear(),
        Err(error) => error.into_inner().clear(),
    }
    let session_token = token(TOKEN_A);
    let harness = Harness::start(&["CAP_BROWSER"]);
    harness.send(&format!(
        "REGISTER\ttoken={session_token}\tsession=ses_a\tpid=1"
    ));
    let (header, _) = harness.send(&format!("AUTHORIZE\tcap=browser\ttoken={session_token}"));
    let receipt = receipt_from(&header);
    let (redeemed, _) = harness.send(&format!("REDEEM\treceipt={receipt}\tcap=browser"));
    assert_redeemed(&redeemed, 0);
    let (replayed, _) = harness.send(&format!("REDEEM\treceipt={receipt}\tcap=browser"));
    assert!(replayed.contains("DENIED"));
    let captured = match request_log().lock() {
        Ok(log) => log.clone(),
        Err(error) => error.into_inner().clone(),
    };
    let log = String::from_utf8(captured).unwrap();
    assert!(log.contains("key=CAP_BROWSER"));
    assert!(log.contains("cap=browser"));
    assert!(log.contains("redeemed=true"));
    assert!(log.contains("redeemed=false"));
    assert!(!log.contains(&session_token));
    assert!(!log.contains(&receipt));
}

#[test]
fn capability_values_are_unreachable_through_get_and_request() {
    let harness = Harness::start(&["CAP_BROWSER"]);
    harness.send(&format!(
        "REGISTER\ttoken={}\tsession=ses_a\tpid=1",
        token(TOKEN_A)
    ));

    let (get, payload) = harness.send(&format!("GET\tkey=CAP_BROWSER\ttoken={}", token(TOKEN_A)));
    assert!(get.contains("NOT_HUMAN_KEY"), "{get}");
    assert!(payload.is_empty());
    let (request, _) = harness.send(&format!(
        "REQUEST\tkey=CAP_BROWSER\ttoken={}",
        token(TOKEN_A)
    ));
    assert!(request.contains("NOT_HUMAN_KEY"), "{request}");
    assert_eq!(
        harness.sops_invocations(),
        0,
        "the guard must refuse before any decrypt"
    );
}
