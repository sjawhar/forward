#![allow(
    clippy::expect_used,
    clippy::panic,
    missing_docs,
    reason = "the integration test delegates its observable end-to-end checks to the standalone harness"
)]

use std::path::Path;
use std::process::Command;

#[test]
#[cfg_attr(miri, ignore)]
fn e2e_an_outsider_cannot_displace_or_remove_a_live_sessions_registration() {
    // Given the built binary plus the standalone displacement harness.
    let script = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/e2e-register-displacement.sh"
    );
    assert!(
        Path::new(script).is_file(),
        "the standalone register-displacement harness must exist"
    );

    // When the harness runs a scratch daemon, registers a session from a live
    // process, and has a sibling of that process claim the same session id.
    let output = Command::new(script)
        .arg(env!("CARGO_BIN_EXE_secrets"))
        .output()
        .expect("start standalone register-displacement harness");

    // Then it succeeds. Exit 77 means the harness could not run (no perl); the
    // test passes without exercising the shape, the same contract as
    // `e2e_client.rs`.
    match output.status.code() {
        Some(0 | 77) => {}
        Some(code) => panic!(
            "register-displacement harness exited {code}: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
        None => panic!("register-displacement harness terminated by signal"),
    }
}
