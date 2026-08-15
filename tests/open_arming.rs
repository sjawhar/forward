use std::io::{BufRead as _, Write as _};
use std::path::Path;
use std::process::Command;
use std::time::Duration;

fn wait_for_socket(path: &Path) {
    for _ in 0..100 {
        if path.exists() {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("arming socket never appeared at {}", path.display());
}

#[test]
fn open_arms_a_dynamic_callback_port_on_the_local_arming_socket() {
    // Given: a real local arming socket in an isolated runtime directory and an
    // opener channel listener on a kernel-selected port.
    let runtime_dir = tempfile::tempdir().unwrap();
    let socket = runtime_dir.path().join("forward-arm.sock");
    let armed = forward::bridge::Armed::new();
    forward::bridge::serve_arming(armed.clone(), socket.clone());
    wait_for_socket(&socket);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let channel_port = listener.local_addr().unwrap().port();
    // `forward open` waits to be told what happened to the URL, so the stand-in
    // counterpart has to answer as the daemon would.
    let counterpart = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut url = String::new();
        std::io::BufReader::new(&stream)
            .read_line(&mut url)
            .unwrap();
        stream.write_all(b"opened\n").unwrap();
        stream.flush().unwrap();
    });
    let config = runtime_dir.path().join("config.toml");
    std::fs::write(&config, "").unwrap();

    // When: `forward open` sends a URL that names a dynamic loopback callback.
    let output = Command::new(env!("CARGO_BIN_EXE_forward"))
        .args([
            "open",
            "https://accounts.example.test/login?redirect_uri=http%3A%2F%2F127.0.0.1%3A8400%2Fcallback",
            "--port",
        ])
        .arg(channel_port.to_string())
        .arg("--config")
        .arg(&config)
        .env("XDG_RUNTIME_DIR", runtime_dir.path())
        .output()
        .unwrap();

    // Then: the callback port arrives at the socket before the URL is delivered.
    assert!(output.status.success(), "stderr: {:?}", output.stderr);
    assert!(armed.is_armed(8400));
    counterpart.join().unwrap();
}

#[test]
fn open_rejects_an_unspecified_peer_before_sending() {
    // Given: an unspecified peer and a local opener channel that would receive
    // the URL if `0.0.0.0` were silently treated as loopback.
    let runtime_dir = tempfile::tempdir().unwrap();
    let config = runtime_dir.path().join("config.toml");
    std::fs::write(&config, "peer = \"0.0.0.0\"\n").unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let channel_port = listener.local_addr().unwrap().port();

    // When: `forward open` loads the configuration.
    let output = Command::new(env!("CARGO_BIN_EXE_forward"))
        .args(["open", "https://example.com/login", "--port"])
        .arg(channel_port.to_string())
        .arg("--config")
        .arg(&config)
        .env("XDG_RUNTIME_DIR", runtime_dir.path())
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    listener.set_nonblocking(true).unwrap();

    // Then: the invalid peer is reported before a URL can reach loopback.
    assert!(!output.status.success(), "stderr: {stderr:?}");
    assert!(stderr.contains("forward: peer"), "stderr: {stderr:?}");
    assert!(!stderr.contains("cannot reach the laptop daemon"));
    assert!(matches!(
        listener.accept(),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
    ));
}
