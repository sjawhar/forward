use std::io::{BufRead as _, Write as _};
use std::process::Command;

#[test]
fn browser_grant_loads_its_explicit_config() {
    let directory = tempfile::tempdir().unwrap();
    let config = directory.path().join("config.toml");
    std::fs::write(&config, "unexpected_key = true\n").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_forward"))
        .args(["browser", "grant", "--config"])
        .arg(&config)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("failed to parse config"));
}

#[test]
fn a_deterministic_refusal_never_contacts_the_broker() {
    // The probe runs before AUTHORIZE, so a refusal forward serve can predict
    // must never cost the human a YubiKey touch. This fails if the ceremony
    // moves back ahead of the probe: the broker listener would see a connection.
    let directory = tempfile::tempdir().unwrap();
    let runtime = directory.path();
    let grant_socket = runtime.join("forward-browser-grant.sock");
    let listener = std::os::unix::net::UnixListener::bind(&grant_socket).unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut line = String::new();
        std::io::BufReader::new(stream.try_clone().unwrap())
            .read_line(&mut line)
            .unwrap();
        assert_eq!(line, "PROBE\n");
        stream.write_all(b"REFUSED UPSTREAM\n").unwrap();
    });
    let broker_socket = runtime.join("broker.sock");
    let broker = std::os::unix::net::UnixListener::bind(&broker_socket).unwrap();
    broker.set_nonblocking(true).unwrap();
    let config = runtime.join("config.toml");
    std::fs::write(&config, "").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_forward"))
        .args(["browser", "grant", "--ttl", "45s", "--config"])
        .arg(&config)
        .env("XDG_RUNTIME_DIR", runtime)
        .env("SECRETSD_SOCK", &broker_socket)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("no peer configured to relay to"),
        "stderr: {stderr}"
    );
    server.join().unwrap();
    assert!(
        matches!(broker.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock),
        "the broker was contacted for a request that was refused deterministically"
    );
}
