use std::io::{Read as _, Write as _};
use std::os::unix::net::UnixListener;
use std::sync::Mutex;
use std::thread;

use forward::config::Config;

pub static PROCESS_STATE_LOCK: Mutex<()> = Mutex::new(());

pub fn cfg() -> Config {
    Config::default_values_for_test()
}

pub fn tempdir() -> tempfile::TempDir {
    // devbox::spawn temporarily changes the process-wide umask. A tempfile
    // directory created during that window can lose its execute bit.
    let _lock = PROCESS_STATE_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    tempfile::tempdir().unwrap()
}

pub fn unix_echo(dir: &std::path::Path) -> std::path::PathBuf {
    let path = dir.join("pcscd.comm");
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

struct HomeRestore(Option<std::ffi::OsString>);

impl Drop for HomeRestore {
    fn drop(&mut self) {
        // SAFETY: HOME is protected by PROCESS_STATE_LOCK for every test that mutates it.
        unsafe {
            match self.0.as_ref() {
                Some(home) => std::env::set_var("HOME", home),
                None => std::env::remove_var("HOME"),
            }
        }
    }
}

pub fn with_home<T>(home: &std::path::Path, test: impl FnOnce() -> T) -> T {
    let lock = PROCESS_STATE_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let restore = HomeRestore(std::env::var_os("HOME"));
    // SAFETY: HOME is protected by PROCESS_STATE_LOCK for every test that mutates it.
    unsafe { std::env::set_var("HOME", home) };
    let result = test();
    drop(restore);
    drop(lock);
    result
}
