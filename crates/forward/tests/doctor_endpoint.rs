//! What `forward doctor` can actually learn about a grant's endpoint.
//!
//! Its own binary on purpose: the probing side must suppress its core dumps,
//! exactly as every `forward` process does, and that is a process-wide setting
//! that would follow unrelated tests sharing the process.

use std::io::Read as _;
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::process::Command;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use forward::browser::grant::ProcessAnchor;
use forward::browser::peer::{pid_for_connection, process_start};
use forward::browser::relay;
use forward::doctor::endpoint_is_served;

const PROBE_PORT_ENV: &str = "FORWARD_TEST_PROBE_PORT";
const PROBE_RESULT_ENV: &str = "FORWARD_TEST_PROBE_RESULT";

#[test]
fn a_relays_refusal_is_what_proves_the_endpoint_is_served_here() {
    if let (Some(port), Some(result)) = (
        std::env::var_os(PROBE_PORT_ENV),
        std::env::var_os(PROBE_RESULT_ENV),
    ) {
        probe_as_doctor_does(&port, &result);
        return;
    }

    // A real relay: the real `/proc`-reading resolver, anchored to this
    // process tree, with nothing injected.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (server, caller) = UnixStream::pair().unwrap();
    let pid = std::process::id();
    let anchor = ProcessAnchor::new(pid, process_start(pid).unwrap());
    thread::spawn(move || relay::serve(listener, caller, anchor, Arc::new(pid_for_connection)));

    let directory = tempfile::tempdir().unwrap();
    let result = directory.path().join("served");
    let mut probe = Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("a_relays_refusal_is_what_proves_the_endpoint_is_served_here")
        .env(PROBE_PORT_ENV, port.to_string())
        .env(PROBE_RESULT_ENV, &result)
        .spawn()
        .unwrap();

    assert!(probe.wait().unwrap().success());
    assert_eq!(
        std::fs::read_to_string(&result).unwrap(),
        "true",
        "a served endpoint did not read as served; the row would tell a healthy \
         session to spend a YubiKey touch re-granting"
    );
    // And the probe was refused, not relayed: nothing reached forward serve,
    // so no laptop connection was opened on a `doctor` run.
    server
        .set_read_timeout(Some(Duration::from_millis(250)))
        .unwrap();
    assert!(
        (&mut &server).read(&mut [0_u8; 1]).is_err(),
        "doctor's probe was handed to forward serve"
    );
}

/// The probing half, as `forward doctor` really is: a `forward` process that
/// has suppressed its core dumps, which is what makes its `/proc/<pid>/fd`
/// unreadable to the relay and so makes it unattributable.
fn probe_as_doctor_does(port: &std::ffi::OsStr, result: &std::ffi::OsStr) {
    hygiene::hardening::apply_no_core_dumps().unwrap();
    let port: u16 = port.to_str().unwrap().parse().unwrap();
    std::fs::write(result, endpoint_is_served(port).to_string()).unwrap();
}

#[test]
fn a_port_nothing_listens_on_is_not_served() {
    // The #51 report's state: a recorded grant whose endpoint has no listener.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    assert!(!endpoint_is_served(port));
}

#[test]
fn a_listener_that_says_nothing_is_not_taken_for_an_endpoint() {
    // Something else holding the port is not this grant's relay. This fails if
    // the probe treats a completed TCP handshake as proof, which is the weaker
    // check it would be tempting to write.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        thread::sleep(Duration::from_secs(10));
        drop(stream);
    });

    assert!(!endpoint_is_served(port));
}

/// A connection the relay refuses is the only answer a probe can earn, so it
/// is worth pinning that the two really are the same bytes.
#[test]
fn the_probe_recognises_the_relays_own_refusal() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (_server, caller) = UnixStream::pair().unwrap();
    let anchor = ProcessAnchor::new(1, 1);
    thread::spawn(move || relay::serve(listener, caller, anchor, Arc::new(|_, _| None)));

    assert!(endpoint_is_served(port));
    // The same connection carries no laptop bytes: it was refused outright.
    let mut client = TcpStream::connect(("127.0.0.1", port)).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut answer = Vec::new();
    client.read_to_end(&mut answer).unwrap();
    assert_eq!(answer, b"REFUSED SESSION\n");
}
