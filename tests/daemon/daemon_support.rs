use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, MutexGuard};
use std::thread;
use std::time::Duration;

static DAEMON_TEST_LOCK: Mutex<()> = Mutex::new(());

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
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
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
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
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

pub fn send(port: u16, url: &str) {
    let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    writeln!(stream, "{url}").unwrap();
}

pub fn send_bytes(port: u16, bytes: &[u8]) {
    let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
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
