/// A daemon whose fake sops waits for the marker, with the fast harness timing:
/// a 1 s cooldown and an 8 s request TTL.
fn start_waiting_fast() -> Harness {
    let settings = HarnessSettings {
        wait_for_marker: true,
        ..HarnessSettings::fast()
    };
    Harness::start_with_settings(
        &["CAP_BROWSER", "DEEL_API_KEY", "SECOND_KEY"],
        "fake-sops-ok",
        settings,
    )
}

/// Make an item of each kind live: the secret grants of a GET and of two
/// AUTHORIZEs, the capability grant the first receipt is redeemed into, the
/// second receipt, and a REQUEST of `SECOND_KEY` that waits in its sops call.
/// Returns that request's reply and when it was sent.
fn four_kinds(harness: &Harness) -> (JoinHandle<(String, Vec<u8>)>, Instant) {
    release(harness);
    register(harness);
    get(harness, "DEEL_API_KEY");
    let receipt = authorize(harness);
    redeem(harness, &receipt);
    authorize(harness);
    std::fs::remove_file(harness.wait_marker()).unwrap();
    let sent = Instant::now();
    let reply = request_later(harness, "SECOND_KEY");
    wait_for_sops_calls(harness, 4);
    (reply, sent)
}

#[test]
fn all_four_kinds_give_both_tables() {
    let harness = start_waiting_fast();
    let (reply, sent) = four_kinds(&harness);

    let (answer, _) = grants(&harness);
    let answered_in_time = sent.elapsed() < HarnessSettings::fast().request_ttl;
    release(&harness);
    let (granted, _) = reply.join().unwrap();

    assert!(answered_in_time, "GRANTS answered after the request's TTL");
    let expected = format!(
        "{SECRET_GRANT}DEEL_API_KEY\tsession\tNs\n\
         CAP_BROWSER\tsession\tNs\n\n\
         {KIND}request\tSECOND_KEY\tsession\tdecrypting, id 4\tNs\n\
         receipt\tbrowser\t-\tunredeemed\tNs\n\
         capability\tbrowser\t-\tactive\tNs\n"
    );
    assert_eq!(answer, expected);
    assert!(granted.starts_with("OK\tstatus=granted"), "{granted}");
    drop(harness);
}

#[test]
fn nothing_live_after_lock_gives_exactly_no_active_grants() {
    let harness = start_waiting_fast();
    let (reply, _) = four_kinds(&harness);

    let (locked, _) = harness.send("LOCK");
    let (_, payload) = harness.send("GRANTS");
    release(&harness);
    let (denied, _) = reply.join().unwrap();

    assert!(locked.starts_with("OK"), "{locked}");
    assert_eq!(String::from_utf8_lossy(&payload), "no active grants\n");
    assert!(denied.contains("DENIED"), "{denied}");
    drop(harness);
}
