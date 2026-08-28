use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::UnixStream;
use std::process::Stdio;
use std::thread;
use std::time::{Duration, Instant};

struct Guard {
    child: std::process::Child,
    stderr_reader: Option<thread::JoinHandle<()>>,
}

impl Drop for Guard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(reader) = self.stderr_reader.take() {
            let _ = reader.join();
        }
    }
}

#[test]
fn serve_creates_the_pulse_socket() {
    // This fails if the Serve arm never spawns the pulse devbox end, or the
    // socket arrives with the wrong modes.
    let home = tempfile::tempdir().unwrap();
    let runtime = tempfile::tempdir().unwrap();
    let config = home.path().join("config.toml");
    std::fs::write(
        &config,
        "listen = \"127.0.0.1\"\npeer = \"127.0.0.1\"\ngrant_port = 0\n",
    )
    .unwrap();
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_forward"))
        .args(["serve", "--port", "0", "--config"])
        .arg(&config)
        .env("HOME", home.path())
        .env("XDG_RUNTIME_DIR", runtime.path())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stderr = child.stderr.take().unwrap();
    let stderr_log = home.path().join("serve.stderr");
    let reader_log = stderr_log.clone();
    let stderr_reader = thread::spawn(move || {
        let mut log = std::fs::File::create(reader_log).unwrap();
        std::io::copy(&mut std::io::BufReader::new(stderr), &mut log).unwrap();
    });
    let guard = Guard {
        child,
        stderr_reader: Some(stderr_reader),
    };
    let expected = format!(
        "forward: pulse socket at {} relaying to 127.0.0.1:12806",
        runtime.path().join("forward/pulse.sock").display()
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let log = std::fs::read_to_string(&stderr_log).unwrap_or_default();
        if log.lines().any(|line| line == expected) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "no pulse startup line before deadline; stderr: {log}"
        );
        thread::sleep(Duration::from_millis(10));
    }

    let socket = runtime.path().join("forward/pulse.sock");
    UnixStream::connect(&socket).expect("pulse socket must accept");
    let socket_mode = std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777;
    assert_eq!(socket_mode, 0o600);
    let dir_mode = std::fs::metadata(socket.parent().unwrap())
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(dir_mode, 0o700);
    drop(guard);
}
