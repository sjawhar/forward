//! The `GRANTS` answer of a live daemon: one row per live item of each kind.

use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use super::{Harness, HarnessSettings, TOKEN_A, TOKEN_B, send_to, token};

const SECRET_GRANT: &str = "SECRET GRANT\tSCOPE\tEXPIRES\n";
const KIND: &str = "KIND\tNAME\tSCOPE\tSTATE\tEXPIRES\n";

/// The `GRANTS` answer with each row's whole seconds written `Ns`, and those
/// seconds in row order, so a test asserts whole rows without racing the clock.
fn grants(harness: &Harness) -> (String, Vec<u64>) {
    let (_, payload) = harness.send("GRANTS");
    let text = String::from_utf8(payload).unwrap();
    let (mut masked, mut seconds) = (String::new(), Vec::new());
    for line in text.split_inclusive('\n') {
        let (body, end) = line
            .strip_suffix('\n')
            .map_or((line, ""), |body| (body, "\n"));
        let row = body.rsplit_once('\t').and_then(|(fields, last)| {
            let secs = last.strip_suffix('s')?.parse::<u64>().ok()?;
            Some((fields, secs))
        });
        if let Some((fields, secs)) = row {
            masked.push_str(fields);
            masked.push_str("\tNs");
            seconds.push(secs);
        } else {
            masked.push_str(body);
        }
        masked.push_str(end);
    }
    (masked, seconds)
}

fn register(harness: &Harness) {
    let (reply, _) = harness.send(&format!(
        "REGISTER\ttoken={}\tsession=ses_a\tpid=1",
        token(TOKEN_A)
    ));
    assert!(reply.starts_with("OK"), "{reply}");
}

fn unregister(harness: &Harness) {
    let (reply, _) = harness.send("UNREGISTER\tsession=ses_a");
    assert!(reply.starts_with("OK"), "{reply}");
}

fn get(harness: &Harness, key: &str) {
    let (reply, _) = harness.send(&format!("GET\tkey={key}\ttoken={}", token(TOKEN_A)));
    assert!(reply.starts_with("OK\tlen="), "{reply}");
}

/// AUTHORIZE `browser` for the registered session; returns the receipt.
fn authorize(harness: &Harness) -> String {
    let (reply, _) = harness.send(&format!("AUTHORIZE\tcap=browser\ttoken={}", token(TOKEN_A)));
    let receipt = reply
        .trim_end()
        .strip_prefix("OK\tstatus=authorized receipt=")
        .and_then(|fields| fields.split(' ').next());
    assert!(receipt.is_some(), "{reply}");
    receipt.unwrap().to_owned()
}

fn redeem(harness: &Harness, receipt: &str) {
    let (reply, _) = harness.send(&format!("REDEEM\treceipt={receipt}\tcap=browser"));
    assert!(reply.starts_with("OK\tstatus=redeemed"), "{reply}");
}

/// Send a REQUEST of `key` for the registered session from a thread, since it
/// blocks until its decrypt ends.
fn request_later(harness: &Harness, key: &str) -> JoinHandle<(String, Vec<u8>)> {
    let socket = harness.socket().clone();
    let frame = format!("REQUEST\tkey={key}\ttoken={}", token(TOKEN_A));
    thread::spawn(move || send_to(&socket, &frame))
}

/// Wait until the fake sops has been called `count` times. On a timeout the
/// wait marker is created first, so no fake sops is left waiting for it.
fn wait_for_sops_calls(harness: &Harness, count: usize) {
    for _ in 0..1000 {
        if harness.sops_invocations() >= count {
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
    release(harness);
    assert!(
        harness.sops_invocations() >= count,
        "sops was not called {count} times"
    );
}

/// Let every fake sops that waits for the marker finish.
fn release(harness: &Harness) {
    std::fs::write(harness.wait_marker(), b"release").unwrap();
}

#[test]
fn replacing_a_session_registration_revokes_displaced_grants() {
    let harness = Harness::start(&["DEEL_API_KEY"]);
    harness.send(&format!(
        "REGISTER\ttoken={}\tsession=ses_a\tpid=1",
        token(TOKEN_A)
    ));
    harness.send(&format!("GET\tkey=DEEL_API_KEY\ttoken={}", token(TOKEN_A)));
    harness.send(&format!(
        "REGISTER\ttoken={}\tsession=ses_a\tpid=1",
        token(TOKEN_B)
    ));

    let (header, payload) = harness.send("GRANTS");
    assert!(header.starts_with("OK"), "{header}");
    assert!(
        String::from_utf8_lossy(&payload).contains("no active grants"),
        "replaced token retained an unreachable plaintext grant"
    );
    drop(harness);
}

#[test]
fn lock_wipes_all_grants() {
    let harness = Harness::start(&["DEEL_API_KEY"]);
    harness.send(&format!(
        "REGISTER\ttoken={}\tsession=ses_a\tpid=1",
        token(TOKEN_A)
    ));
    harness.send(&format!("GET\tkey=DEEL_API_KEY\ttoken={}", token(TOKEN_A)));
    harness.send("LOCK");

    let (header, payload) = harness.send("GRANTS");
    assert!(header.starts_with("OK"), "{header}");
    let text = String::from_utf8_lossy(&payload);
    assert!(text.contains("no active grants"), "{text}");
    drop(harness);
}

#[test]
fn grants_listing_never_contains_values() {
    let harness = Harness::start(&["DEEL_API_KEY"]);
    harness.send(&format!(
        "REGISTER\ttoken={}\tsession=ses_a\tpid=1",
        token(TOKEN_A)
    ));
    harness.send(&format!("GET\tkey=DEEL_API_KEY\ttoken={}", token(TOKEN_A)));
    let (_, payload) = harness.send("GRANTS");
    let text = String::from_utf8_lossy(&payload);
    assert!(
        !text.contains("value-for-"),
        "grant listing leaked a secret: {text}"
    );
    drop(harness);
}

#[test]
fn a_tokenless_request_from_a_tty_with_control_bytes_lists_it_escaped() {
    let harness = Harness::start_with_waiting_sops(&["DEEL_API_KEY"]);
    let socket = harness.socket().clone();
    let frame = "REQUEST\tkey=DEEL_API_KEY\ttty=/x\0\x1b[2Ky";
    let reply = thread::spawn(move || send_to(&socket, frame));
    wait_for_sops_calls(&harness, 1);

    let (header, payload) = harness.send("GRANTS");
    let (answer, _) = grants(&harness);
    release(&harness);
    reply.join().unwrap();

    assert!(header.starts_with("OK\tlen="), "{header}");
    let control = |byte: &u8| (*byte < 0x20 && !matches!(byte, b'\t' | b'\n')) || *byte == 0x7f;
    assert!(!payload.iter().any(control), "{payload:?}");
    let tty = r"/x\0\u{001B}[2Ky";
    let expected = format!("{KIND}request\tDEEL_API_KEY\ttty {tty}\tdecrypting, id 1\tNs\n");
    assert_eq!(answer, expected);
    drop(harness);
}

include!("listing/kinds.rs");
include!("listing/together.rs");
