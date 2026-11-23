#![allow(
    clippy::expect_used,
    clippy::panic,
    missing_docs,
    reason = "the integration test delegates its observable end-to-end checks to the standalone script"
)]

use std::path::Path;
use std::process::Command;

#[test]
#[cfg_attr(miri, ignore)]
fn e2e_grants_lists_each_kind_at_each_step_of_a_scratch_daemon() {
    // Given the built binary plus the standalone grants-listing script.
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/e2e-grants-listing.sh");
    assert!(
        Path::new(script).is_file(),
        "the standalone grants-listing script must exist"
    );

    // When the script drives a scratch daemon through its seven steps, with
    // the built binary as both the daemon and the client.
    let secrets = env!("CARGO_BIN_EXE_secrets");
    let output = Command::new(script)
        .args([secrets, secrets])
        .output()
        .expect("start standalone grants-listing script");

    // Then every step passes. Exit 77 means the script could not run (no
    // perl); the test passes without exercising the steps, the same contract
    // as `e2e_register_displacement.rs`.
    match output.status.code() {
        Some(0 | 77) => {}
        Some(code) => panic!(
            "grants-listing script exited {code}: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
        None => panic!("grants-listing script terminated by signal"),
    }
}
