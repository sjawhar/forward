use std::process::Command;

#[test]
fn vm_services_refuse_daemon_peer_lists_before_starting_any_listener() {
    // The peer list belongs to the laptop daemon, never the VM HTTP parser.
    for peers in ["['127.0.0.2']", "['127.0.0.2', '127.0.0.3']"] {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.toml");
        std::fs::write(&config, format!("peers = {peers}\n")).unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_forward"))
            .args(["serve", "--port", "0", "--config"])
            .arg(config)
            .env("XDG_RUNTIME_DIR", dir.path())
            .output()
            .unwrap();
        assert!(!output.status.success());
        let log = String::from_utf8_lossy(&output.stderr);
        assert!(log.contains("peers is a laptop daemon setting"), "{log}");
        assert!(!log.contains("listening"), "{log}");
        assert!(!dir.path().join("forward/arm.sock").exists());
    }
}
