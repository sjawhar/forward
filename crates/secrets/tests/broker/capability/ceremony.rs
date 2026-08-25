#[test]
fn a_repeat_authorization_runs_a_fresh_ceremony_and_mints() {
    install_request_log_capture();
    match request_log().lock() {
        Ok(mut log) => log.clear(),
        Err(error) => error.into_inner().clear(),
    }
    let harness = Harness::start(&["CAP_BROWSER"]);
    harness.send(&format!(
        "REGISTER\ttoken={}\tsession=ses_a\tpid=1",
        token(TOKEN_A)
    ));
    let (first, _) = harness.send(&format!("AUTHORIZE\tcap=browser\ttoken={}", token(TOKEN_A)));
    let (second, _) = harness.send(&format!("AUTHORIZE\tcap=browser\ttoken={}", token(TOKEN_A)));

    assert!(first.starts_with("OK\tstatus=authorized receipt="));
    assert!(second.starts_with("OK\tstatus=authorized receipt="));
    assert_ne!(receipt_from(&first), receipt_from(&second));
    assert_eq!(harness.sops_invocations(), 2);
    let captured = match request_log().lock() {
        Ok(log) => log.clone(),
        Err(error) => error.into_inner().clone(),
    };
    let log = String::from_utf8(captured).unwrap();
    assert!(!log.contains("grant invalidated after backing file changed"));
}

#[test]
fn two_fresh_capability_authorizations_yield_distinct_receipts() {
    let harness = Harness::start(&["CAP_BROWSER"]);
    harness.send(&format!(
        "REGISTER\ttoken={}\tsession=ses_a\tpid=1",
        token(TOKEN_A)
    ));
    let (first, _) = harness.send(&format!("AUTHORIZE\tcap=browser\ttoken={}", token(TOKEN_A)));
    harness.send("LOCK");
    let (second, _) = harness.send(&format!("AUTHORIZE\tcap=browser\ttoken={}", token(TOKEN_A)));

    assert_ne!(receipt_from(&first), receipt_from(&second));
    assert_eq!(harness.sops_invocations(), 2);
}

#[test]
fn authorize_for_an_unprovisioned_capability_names_the_missing_key() {
    let harness = Harness::start(&[]);
    harness.send(&format!(
        "REGISTER\ttoken={}\tsession=ses_a\tpid=1",
        token(TOKEN_A)
    ));
    let (header, _) = harness.send(&format!("AUTHORIZE\tcap=browser\ttoken={}", token(TOKEN_A)));
    assert!(header.contains("NOT_HUMAN_KEY"), "{header}");
}

#[test]
fn a_denied_authorize_mints_no_receipt() {
    let harness = Harness::start_with_sops(&["CAP_BROWSER"], "fake-sops-hang");
    let marker = harness.hang_marker().clone();
    harness.send(&format!(
        "REGISTER\ttoken={}\tsession=ses_a\tpid=1",
        token(TOKEN_A)
    ));
    let socket = harness.socket().clone();
    let authorize = std::thread::spawn(move || {
        let mut stream = std::os::unix::net::UnixStream::connect(&socket).unwrap();
        std::io::Write::write_all(
            &mut stream,
            format!("AUTHORIZE\tcap=browser\ttoken={}\n", token(TOKEN_A)).as_bytes(),
        )
        .unwrap();
        let mut reply = String::new();
        std::io::Read::read_to_string(&mut stream, &mut reply).unwrap();
        reply
    });
    // The hang marker appears when fake-sops-hang starts: the ceremony is now
    // genuinely mid-decrypt. Bounded wait, so a broken daemon fails loudly
    // instead of hanging the test.
    for _ in 0..100 {
        if marker.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    // Request ids are sequential per daemon; the AUTHORIZE above is this
    // harness's first approval request, so it is id 1.
    harness.send("DENY\tid=1");

    let reply = authorize.join().unwrap();
    assert!(reply.contains("DENIED"), "{reply}");
    assert!(
        !reply.contains("receipt="),
        "a denied ceremony must not attest"
    );
}

#[test]
fn lock_kills_receipts_minted_before_it() {
    // Lock must mean locked. Without receipts dying in the lock path, this
    // receipt would stay redeemable for up to 60 seconds after an explicit
    // `secrets lock`, letting forward serve grant browser access post-lock.
    // This is the discriminating regression for the fix: it fails if lock()
    // does not clear the receipt table.
    let harness = Harness::start(&["CAP_BROWSER"]);
    harness.send(&format!(
        "REGISTER\ttoken={}\tsession=ses_a\tpid=1",
        token(TOKEN_A)
    ));
    let (header, _) = harness.send(&format!("AUTHORIZE\tcap=browser\ttoken={}", token(TOKEN_A)));
    let receipt = receipt_from(&header);

    harness.send("LOCK");

    let (after, _) = harness.send(&format!("REDEEM\treceipt={receipt}\tcap=browser"));
    assert!(
        after.contains("DENIED"),
        "a receipt minted before a lock must die with it: {after}"
    );
}
