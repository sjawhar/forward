use forward::config::Config;
use std::io::{Read as _, Write as _};
use std::net::{IpAddr, Shutdown, TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Mutex;
use std::thread;
use std::time::Duration;

fn cfg() -> Config {
    Config::default_values_for_test()
}

fn unix_echo(dir: &std::path::Path) -> std::path::PathBuf {
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

#[test]
fn laptop_channel_pipes_raw_bytes_to_the_pcscd_socket() {
    // This fails if the channel parses, frames, or injects anything: pcscd
    // bytes must arrive verbatim and flow back.
    let dir = tempfile::tempdir().unwrap();
    let upstream = unix_echo(dir.path());
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    forward::pcsc::laptop::spawn_with_listener(cfg(), listener, upstream).unwrap();

    let mut client = TcpStream::connect(address).unwrap();
    client.write_all(&[0x12, 0x00, 0x00, 0x00, 0x11]).unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    let mut reply = Vec::new();
    client.read_to_end(&mut reply).unwrap();

    assert_eq!(reply, [0x12, 0x00, 0x00, 0x00, 0x11]);
}

#[test]
fn laptop_channel_refuses_an_unauthorized_peer_with_a_bare_close() {
    // This fails if a non-peer address is served, or if the refusal writes
    // bytes into a protocol that has no place for them.
    let dir = tempfile::tempdir().unwrap();
    let upstream = unix_echo(dir.path());
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let accepted = thread::spawn(move || listener.accept().unwrap().0);
    let mut client = TcpStream::connect(address).unwrap();
    let server_side = accepted.join().unwrap();

    let mut config = cfg();
    config.peer = "100.64.0.9".to_owned();
    forward::pcsc::laptop::handle_from(
        &config,
        &upstream,
        "100.64.0.7".parse::<IpAddr>().unwrap(),
        server_side,
    );

    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut reply = Vec::new();
    client.read_to_end(&mut reply).unwrap();
    assert!(
        reply.is_empty(),
        "refusal must not write protocol-corrupting bytes"
    );
}

#[test]
fn laptop_channel_closes_immediately_when_pcscd_is_absent() {
    // This fails if a missing pcscd socket hangs the client instead of the
    // loud connection-refused semantics the socat bridge had.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    forward::pcsc::laptop::spawn_with_listener(
        cfg(),
        listener,
        std::path::PathBuf::from("/nonexistent/pcscd.comm"),
    )
    .unwrap();

    let mut client = TcpStream::connect(address).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut reply = Vec::new();
    client.read_to_end(&mut reply).unwrap();
    assert!(reply.is_empty());
}

#[test]
fn disabled_laptop_channel_does_not_resolve_or_bind_its_listener() {
    // The disabled setting is a complete opt-out: no listener or upstream
    // socket is touched, even with a deliberately invalid listen address.
    let mut config = cfg();
    config.pcsc_port = 0;
    config.listen = "not-an-address".to_owned();

    assert!(forward::pcsc::laptop::spawn(&config).is_ok());
}

static HOME_LOCK: Mutex<()> = Mutex::new(());

struct HomeRestore(Option<std::ffi::OsString>);

impl Drop for HomeRestore {
    fn drop(&mut self) {
        // SAFETY: HOME is protected by HOME_LOCK for every test that mutates it.
        unsafe {
            match self.0.as_ref() {
                Some(home) => std::env::set_var("HOME", home),
                None => std::env::remove_var("HOME"),
            }
        }
    }
}

fn with_home<T>(home: &std::path::Path, test: impl FnOnce() -> T) -> T {
    let lock = HOME_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let restore = HomeRestore(std::env::var_os("HOME"));
    // SAFETY: HOME is protected by HOME_LOCK for every test that mutates it.
    unsafe { std::env::set_var("HOME", home) };
    let result = test();
    drop(restore);
    drop(lock);
    result
}

#[test]
fn devbox_socket_pipes_raw_bytes_to_the_laptop_leg() {
    // This fails if the devbox leg frames, drops, or reorders pcscd bytes.
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("pcscd.comm");
    let laptop = TcpListener::bind("127.0.0.1:0").unwrap();
    let laptop_address = laptop.local_addr().unwrap();
    thread::spawn(move || {
        let (mut stream, _) = laptop.accept().unwrap();
        let mut request = Vec::new();
        stream.read_to_end(&mut request).unwrap();
        stream.write_all(&request).unwrap();
    });
    let listener = UnixListener::bind(&socket).unwrap();
    forward::pcsc::devbox::spawn_with_unix_listener(listener, laptop_address).unwrap();

    let mut client = UnixStream::connect(&socket).unwrap();
    client.write_all(b"\x01raw pcscd frame").unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    let mut reply = Vec::new();
    client.read_to_end(&mut reply).unwrap();

    assert_eq!(reply, b"\x01raw pcscd frame");
}

#[test]
fn devbox_socket_closes_fast_when_the_laptop_is_unreachable() {
    // This fails if an unreachable laptop hangs pcsc clients instead of the
    // immediate loud failure secretsd's classifier expects.
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("pcscd.comm");
    // A bound-then-dropped port refuses connections immediately.
    let dead = TcpListener::bind("127.0.0.1:0").unwrap();
    let dead_address = dead.local_addr().unwrap();
    drop(dead);
    let listener = UnixListener::bind(&socket).unwrap();
    forward::pcsc::devbox::spawn_with_unix_listener(listener, dead_address).unwrap();

    let mut client = UnixStream::connect(&socket).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let started = std::time::Instant::now();
    let mut reply = Vec::new();
    client.read_to_end(&mut reply).unwrap();

    assert!(reply.is_empty());
    assert!(
        started.elapsed() < Duration::from_secs(8),
        "close took {:?}; must be far under the connect timeout ceiling",
        started.elapsed()
    );
}

#[test]
fn devbox_spawn_replaces_a_stale_socket_with_mode_0600() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join(".pcscd/pcscd.comm");
    std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
    drop(UnixListener::bind(&socket).unwrap());

    with_home(dir.path(), || {
        let mut config = cfg();
        config.peer = "127.0.0.1".to_owned();
        config.pcsc_port = 1;
        forward::pcsc::devbox::spawn(&config).unwrap();

        let mode = std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    });
}

#[test]
fn devbox_spawn_does_not_replace_a_live_socket() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join(".pcscd/pcscd.comm");
    std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
    let _live = UnixListener::bind(&socket).unwrap();

    with_home(dir.path(), || {
        let mut config = cfg();
        config.peer = "127.0.0.1".to_owned();
        config.pcsc_port = 1;
        let error = forward::pcsc::devbox::spawn(&config).expect_err("live socket must win");

        assert!(
            matches!(
                error,
                forward::pcsc::PcscError::Socket { source, .. }
                    if source.kind() == std::io::ErrorKind::AddrInUse
            ),
            "live socket must report an address-in-use error"
        );
        UnixStream::connect(&socket).expect("live socket must remain connectable");
    });
}
