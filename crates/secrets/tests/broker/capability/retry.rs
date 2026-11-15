use std::thread;
use std::time::{Duration, Instant};


const STANZA_FAILURE: &str =
    "age: yubikey plugin: Failed to decrypt YubiKey stanza. Did you touch it?";
const PLUGIN_FAILURE: &str = "age: yubikey plugin: Error while communicating with YubiKey";
const PCSC_FAILURE: &str = "Error: Error while communicating with YubiKey: PC/SC error";

fn prepare_retry_log() {
    install_request_log_capture();
    request_log().lock().unwrap().clear();
}

fn retry_settings(stderr: &'static str) -> HarnessSettings {
    let mut settings = HarnessSettings::fast();
    settings.fail_stderr = Some(stderr);
    settings
}

fn register(harness: &Harness, prefix: &str, session: &str) {
    let (reply, _) = harness.send(&format!(
        "REGISTER\ttoken={}\tsession={session}\tpid=1",
        token(prefix)
    ));
    assert!(reply.starts_with("OK"), "{reply}");
}

fn send_later(harness: &Harness, frame: String) -> thread::JoinHandle<(String, Vec<u8>)> {
    let socket = harness.socket().clone();
    thread::spawn(move || send_to(&socket, &frame))
}

fn wait_for_path(path: &std::path::Path) {
    let Some(deadline) = Instant::now().checked_add(Duration::from_secs(10)) else {
        panic!("marker deadline is out of range");
    };
    while !path.exists() {
        assert!(
            Instant::now() < deadline,
            "marker did not appear: {}",
            path.display()
        );
        thread::sleep(Duration::from_millis(10));
    }
}

fn attempt_lines() -> Vec<String> {
    String::from_utf8(request_log().lock().unwrap().clone())
        .unwrap()
        .lines()
        .filter(|line| line.contains("decrypt attempt"))
        .map(ToOwned::to_owned)
        .collect()
}

fn wait_for_attempts(count: usize) {
    let Some(deadline) = Instant::now().checked_add(Duration::from_secs(10)) else {
        panic!("attempt deadline is out of range");
    };
    while attempt_lines().len() < count {
        assert!(Instant::now() < deadline, "decrypt attempt log did not arrive");
        thread::sleep(Duration::from_millis(10));
    }
}

fn assert_two_attempts(label: &str) {
    wait_for_attempts(2);
    let attempts = attempt_lines();
    assert_eq!(attempts.len(), 2, "{attempts:#?}");
    let [first, second] = attempts.as_slice() else {
        panic!("expected two attempt lines: {attempts:#?}");
    };
    let request_id = first
        .split_whitespace()
        .find(|field| field.starts_with("request_id="))
        .unwrap();
    assert!(
        attempts.iter().all(|line| line.contains(request_id)),
        "{attempts:#?}"
    );
    assert!(first.contains("attempt=1"), "{attempts:#?}");
    assert!(second.contains("attempt=2"), "{attempts:#?}");
    assert!(first.contains(&format!("result={label}")), "{attempts:#?}");
    assert!(second.contains("result=ok"), "{attempts:#?}");
    assert!(attempts.iter().all(|line| line.contains("duration_ms=")), "{attempts:#?}");
}

fn retry_authorize_after_sops_failure(stderr: &'static str, label: &str) {
    prepare_retry_log();
    let harness = Harness::start_with_settings(
        &["CAP_BROWSER"],
        "fake-sops-fail-once",
        retry_settings(stderr),
    );
    register(&harness, TOKEN_A, "retry");

    let (reply, _) = harness.send(&format!("AUTHORIZE\tcap=browser\ttoken={}", token(TOKEN_A)));

    assert!(
        reply.starts_with("OK\tstatus=authorized receipt="),
        "{reply}\n{:#?}",
        attempt_lines()
    );
    assert_two_attempts(label);
    assert_eq!(harness.sops_invocations(), 2);
}

include!("retry/attempts.rs");
include!("retry/control.rs");
include!("retry/expiry.rs");
