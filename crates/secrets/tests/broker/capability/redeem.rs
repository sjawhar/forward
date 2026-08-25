#[test]
fn authorize_grants_and_the_receipt_redeems_exactly_once() {
    let harness = Harness::start(&["CAP_BROWSER"]);
    harness.send(&format!(
        "REGISTER\ttoken={}\tsession=ses_a\tpid=1",
        token(TOKEN_A)
    ));

    let (header, _) = harness.send(&format!("AUTHORIZE\tcap=browser\ttoken={}", token(TOKEN_A)));
    assert!(
        header.starts_with("OK\tstatus=authorized receipt="),
        "{header}"
    );
    let receipt = receipt_from(&header);

    let (redeemed, _) = harness.send(&format!("REDEEM\treceipt={receipt}\tcap=browser"));
    assert_redeemed(&redeemed, 0);

    let (again, _) = harness.send(&format!("REDEEM\treceipt={receipt}\tcap=browser"));
    assert!(again.contains("DENIED"), "second redeem must fail: {again}");
}

#[test]
fn hello_and_redeem_report_the_lock_epoch() {
    let harness = Harness::start(&["CAP_BROWSER"]);
    harness.send(&format!(
        "REGISTER\ttoken={}\tsession=ses_a\tpid=1",
        token(TOKEN_A)
    ));
    let (hello_before, _) = harness.send(&format!(
        "HELLO\tversion={}",
        secrets::proto::PROTOCOL_VERSION
    ));
    let (header, _) = harness.send(&format!("AUTHORIZE\tcap=browser\ttoken={}", token(TOKEN_A)));
    let receipt = receipt_from(&header);
    let (redeemed, _) = harness.send(&format!("REDEEM\treceipt={receipt}\tcap=browser"));

    harness.send("LOCK");

    let (hello_after, _) = harness.send(&format!(
        "HELLO\tversion={}",
        secrets::proto::PROTOCOL_VERSION
    ));

    assert_eq!(epoch_from(&hello_before), Some(0));
    assert_eq!(epoch_from(&redeemed), Some(0));
    assert_eq!(epoch_from(&hello_after), Some(1));
}

#[test]
fn redeem_refuses_a_mismatched_capability_without_consuming_the_receipt() {
    let harness = Harness::start(&["CAP_BROWSER"]);
    harness.send(&format!(
        "REGISTER\ttoken={}\tsession=ses_a\tpid=1",
        token(TOKEN_A)
    ));
    let (header, _) = harness.send(&format!("AUTHORIZE\tcap=browser\ttoken={}", token(TOKEN_A)));
    let receipt = receipt_from(&header);

    let (mismatched, _) = harness.send(&format!("REDEEM\treceipt={receipt}\tcap=admin"));
    assert!(mismatched.contains("DENIED"));

    let (redeemed, _) = harness.send(&format!("REDEEM\treceipt={receipt}\tcap=browser"));
    assert_redeemed(&redeemed, 0);
}

#[test]
fn a_lock_racing_an_in_flight_authorize_leaves_no_redeemable_receipt() {
    // The companion case: the lock lands while the ceremony is still
    // decrypting. The lock epoch — captured before dispatch_access, rechecked
    // under the same state lock as the mint — makes the whole AUTHORIZE
    // atomic with respect to LOCK, so no interleaving mints a receipt that
    // survives the lock.
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
    // The hang marker appears when fake-sops-hang starts: the decrypt is now
    // actually in flight, so the LOCK below genuinely races the ceremony.
    // Bounded wait — a broken daemon fails the assertions instead of hanging.
    for _ in 0..100 {
        if marker.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    harness.send("LOCK");

    let reply = authorize.join().unwrap();
    assert!(
        !reply.contains("receipt="),
        "an authorize crossing a lock must not attest: {reply}"
    );
}
