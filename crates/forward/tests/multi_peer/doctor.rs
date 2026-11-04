use std::process::Command;

use super::*;

#[test]
fn doctor_reports_a_dead_peer_even_when_another_peer_answers() {
    // First-success probing must not hide a dead second VM.
    let listener = TcpListener::bind("127.0.0.2:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            drop(stream);
        }
    });
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(
        &path,
        format!(
            "peers = ['127.0.0.2', '127.0.0.3']\nbridge_port = 9\nrelay_port = 0\npcsc_port = 0\npulse_port = 0\ngrant_port = {port}\n",
        ),
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_forward"))
        .args([
            "doctor",
            "--channel-port",
            "9",
            "--files-port",
            "9",
            "--config",
        ])
        .arg(path)
        .env("HOME", dir.path())
        .env("XDG_RUNTIME_DIR", dir.path())
        .output()
        .unwrap();
    let report = String::from_utf8_lossy(&output.stdout);
    assert!(
        report.contains(&format!(
            "peer 127.0.0.2 browser feed: accepted TCP at 127.0.0.2:{port}"
        )),
        "{report}"
    );
    assert!(
        report.contains("peer 127.0.0.3 browser feed: FAIL"),
        "{report}"
    );
    assert!(
        report.contains("peer 127.0.0.2 callback bridge:"),
        "{report}"
    );
    assert!(report.contains("peer 127.0.0.3 file preview:"), "{report}");
    assert!(!output.status.success());
}
