use std::io::{Read as _, Write as _};
use std::os::unix::net::UnixListener;
use std::sync::Mutex;
use std::thread;

use forward::config::Config;

pub static PROCESS_STATE_LOCK: Mutex<()> = Mutex::new(());

pub fn cfg() -> Config {
    let mut config = Config::default_values_for_test();
    config.peer = "127.0.0.1".to_owned();
    config
}

pub fn is_bare_close(error: &std::io::Error) -> bool {
    // A refused connection's bare close can surface client-side as a broken
    // pipe or reset on read/write, or as ENOTCONN when the server's reset
    // lands before the client's own shutdown(Write) call.
    matches!(
        error.kind(),
        std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::NotConnected
    )
}

pub fn tempdir() -> tempfile::TempDir {
    // devbox::spawn temporarily changes the process-wide umask. A tempfile
    // directory created during that window can lose its execute bit.
    let _lock = PROCESS_STATE_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    tempfile::tempdir().unwrap()
}

/// A unix echo server at `dir/native`, standing in for pipewire-pulse.
pub fn unix_echo(dir: &std::path::Path) -> std::path::PathBuf {
    let path = dir.join("native");
    let listener = UnixListener::bind(&path).unwrap();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            thread::spawn(move || {
                let mut request = Vec::new();
                stream.read_to_end(&mut request).unwrap();
                stream.write_all(&request).unwrap();
            });
        }
    });
    path
}

struct RuntimeDirRestore(Option<std::ffi::OsString>);

impl Drop for RuntimeDirRestore {
    fn drop(&mut self) {
        // SAFETY: XDG_RUNTIME_DIR is protected by PROCESS_STATE_LOCK for
        // every test that mutates it.
        unsafe {
            match self.0.as_ref() {
                Some(dir) => std::env::set_var("XDG_RUNTIME_DIR", dir),
                None => std::env::remove_var("XDG_RUNTIME_DIR"),
            }
        }
    }
}

/// Run `test` with XDG_RUNTIME_DIR set to `dir`, or unset for `None`.
pub fn with_runtime_dir<T>(dir: Option<&std::path::Path>, test: impl FnOnce() -> T) -> T {
    let lock = PROCESS_STATE_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let restore = RuntimeDirRestore(std::env::var_os("XDG_RUNTIME_DIR"));
    // SAFETY: XDG_RUNTIME_DIR is protected by PROCESS_STATE_LOCK for every
    // test that mutates it.
    unsafe {
        match dir {
            Some(dir) => std::env::set_var("XDG_RUNTIME_DIR", dir),
            None => std::env::remove_var("XDG_RUNTIME_DIR"),
        }
    }
    let result = test();
    drop(restore);
    drop(lock);
    result
}
