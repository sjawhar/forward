use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::thread;
use std::time::Duration;

static DAEMON_TEST_LOCK: Mutex<()> = Mutex::new(());
const TEST_PORT_BASE: u16 = 20_000;
static NEXT_TEST_PORT: AtomicU16 = AtomicU16::new(TEST_PORT_BASE);

pub fn stub(dir: &Path, name: &str, body: &str) -> String {
    let path = dir.join(name);
    std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path.to_str().unwrap().to_owned()
}

pub struct Daemon {
    child: Child,
    stderr_log: std::path::PathBuf,
    stderr_reader: Option<thread::JoinHandle<()>>,
    _lock: MutexGuard<'static, ()>,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(reader) = self.stderr_reader.take() {
            let _ = reader.join();
        }
    }
}

impl Daemon {
    pub fn log(&self) -> String {
        std::fs::read_to_string(&self.stderr_log).unwrap_or_default()
    }

    pub fn wait_for_log(&self, expected: &str) {
        for _ in 0..50 {
            if std::fs::read_to_string(&self.stderr_log)
                .is_ok_and(|contents| contents.contains(expected))
            {
                return;
            }
            thread::sleep(Duration::from_millis(100));
        }
        panic!("no daemon stderr line containing {expected:?}");
    }
}

pub fn start(dir: &Path, config_body: &str) -> (Daemon, u16) {
    let lock = DAEMON_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let config = dir.join("config.toml");
    std::fs::write(&config, config_body).unwrap();
    let port = test_port();
    let existing_path = std::env::var_os("PATH").unwrap_or_default();
    let path = std::env::join_paths(
        std::iter::once(dir.to_path_buf()).chain(std::env::split_paths(&existing_path)),
    )
    .unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_forward"))
        .args([
            "daemon",
            "--port",
            &port.to_string(),
            "--config",
            config.to_str().unwrap(),
        ])
        .env("PATH", path)
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stderr_log = dir.join("daemon.stderr");
    let mut stderr = child.stderr.take().unwrap();
    let stderr_path = stderr_log.clone();
    let stderr_reader = thread::spawn(move || {
        let mut log = std::fs::File::create(stderr_path).unwrap();
        let _ = std::io::copy(&mut stderr, &mut log);
    });
    for _ in 0..50 {
        if TcpStream::connect_timeout(&loopback(port), Duration::from_millis(100)).is_ok() {
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }
    (
        Daemon {
            child,
            stderr_log,
            stderr_reader: Some(stderr_reader),
            _lock: lock,
        },
        port,
    )
}

/// Runs the daemon expecting it to refuse to start, and returns all of its
/// stderr. Unlike `start`, this waits for the process to exit rather than
/// returning a live child, so there is no `Daemon` and no `Drop` to kill.
pub fn start_expecting_failure(dir: &Path, config_body: &str) -> String {
    let _lock = DAEMON_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let config = dir.join("config.toml");
    std::fs::write(&config, config_body).unwrap();
    let port = test_port();
    let output = Command::new(env!("CARGO_BIN_EXE_forward"))
        .args([
            "daemon",
            "--port",
            &port.to_string(),
            "--config",
            config.to_str().unwrap(),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "daemon started when it should have refused"
    );
    String::from_utf8_lossy(&output.stderr).into_owned()
}

pub fn send(port: u16, url: &str) {
    let mut stream = connect(port);
    writeln!(stream, "{url}").unwrap();
}

pub fn send_bytes(port: u16, bytes: &[u8]) {
    let mut stream = connect(port);
    stream.write_all(bytes).unwrap();
}

pub fn wait_for(path: &Path) -> String {
    for _ in 0..50 {
        if let Ok(contents) = std::fs::read_to_string(path)
            && !contents.is_empty()
        {
            return contents;
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("no invocation recorded at {path:?}");
}

/// Stands in for the devbox callback bridge: records the `CONNECT <port>` line
/// of each connection, read a byte at a time so no payload is swallowed.
pub fn spawn_bridge(record: &Path) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let record = record.to_path_buf();
    thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            let mut line = Vec::new();
            let mut byte = [0u8; 1];
            while stream.read(&mut byte).unwrap_or(0) == 1 && byte[0] != b'\n' {
                line.push(byte[0]);
            }
            let mut log = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&record)
                .unwrap();
            writeln!(log, "{}", String::from_utf8_lossy(&line).trim()).unwrap();
        }
    });
    port
}

pub fn test_port() -> u16 {
    NEXT_TEST_PORT.fetch_add(1, Ordering::Relaxed)
}

pub fn connect(port: u16) -> TcpStream {
    let stream = TcpStream::connect_timeout(&loopback(port), Duration::from_secs(5)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream
}

pub fn connection_is_refused(port: u16) -> bool {
    TcpStream::connect_timeout(&loopback(port), Duration::from_millis(100)).is_err()
}

fn loopback(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

#[test]
fn test_port_is_outside_the_ephemeral_range() {
    let port = test_port();

    assert!(!(32_768..=60_999).contains(&port));
}
