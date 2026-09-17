#![allow(
    clippy::expect_used,
    clippy::panic,
    missing_docs,
    reason = "the integration test delegates its observable end-to-end checks to the standalone harness"
)]

use std::path::Path;
use std::process::Command;

#[test]
fn e2e_a_same_uid_client_in_a_sysbox_container_is_served_by_a_mount_protected_daemon() {
    // Given the built binary plus the standalone sysbox harness.
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/e2e-sysbox-peer.sh");
    assert!(
        Path::new(script).is_file(),
        "the standalone sysbox-peer harness must exist"
    );

    // When the harness runs the daemon socket-activated as a mount-protected user
    // unit and a client registers and requests from inside a sysbox container.
    let output = Command::new(script)
        .arg(env!("CARGO_BIN_EXE_secrets"))
        .output()
        .expect("start standalone sysbox-peer harness");

    // Then it succeeds. Exit 77 means the harness could not run (no systemd user
    // manager or no sysbox runtime); the test passes without exercising the shape,
    // the same contract as `e2e_client.rs`, so a plain machine's suite stays green.
    match output.status.code() {
        Some(0 | 77) => {}
        Some(code) => panic!(
            "sysbox-peer harness exited {code}: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
        None => panic!("sysbox-peer harness terminated by signal"),
    }
}
