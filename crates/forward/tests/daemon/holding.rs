use std::io::{BufRead as _, BufReader, Write as _};
use std::net::TcpListener;
use std::os::unix::net::UnixListener;
use std::process::{Command, ExitStatus, Stdio};
use std::thread;
use std::time::Duration;

use forward::send::{HoldReply, SendError, send_hold};

use super::daemon_support::{connect, spawn_bridge, start, stub, test_port, wait_for};

fn devbox(channel: u16) -> (forward::config::Config, u16) {
    let mut cfg = forward::config::Config::default_values_for_test();
    cfg.peer = "127.0.0.1".to_owned();
    (cfg, channel)
}

#[test]
fn a_hold_serves_the_laptop_port_and_opens_nothing_in_allowlist_mode() {
    // Given: a daemon whose opener would leave a mark, and a fake devbox bridge.
    let dir = tempfile::tempdir().unwrap();
    let bridged = dir.path().join("bridged");
    let bridge_port = spawn_bridge(&bridged);
    let port = test_port();
    let opened = dir.path().join("opened");
    let opener = stub(dir.path(), "opener", &format!("touch {}", opened.display()));
    let (_daemon, channel) = start(
        dir.path(),
        &format!(
            r#"
mode = "allowlist"
allow = ["localhost:{port}"]
opener = ["{opener}"]
peer = "127.0.0.1"
bridge_port = {bridge_port}
"#
        ),
    );

    // When: the devbox holds a port and a browser then connects to it.
    let (cfg, channel) = devbox(channel);
    assert_eq!(send_hold(&cfg, port, 30, channel).unwrap(), HoldReply::Held);
    let mut browser = connect(port);
    browser.write_all(b"GET / HTTP/1.1\r\n\r\n").unwrap();

    // Then: the connection goes to the bridge for that port, and nothing opened.
    assert_eq!(wait_for(&bridged).trim(), format!("CONNECT {port}"));
    assert!(!opened.exists(), "a hold must never open a browser");
}

#[test]
fn an_oversized_hold_request_is_capped_instead_of_crashing_the_daemon() {
    // Given: a daemon and a fake devbox bridge.
    let dir = tempfile::tempdir().unwrap();
    let bridged = dir.path().join("bridged");
    let bridge_port = spawn_bridge(&bridged);
    let port = test_port();
    let (_daemon, channel) = start(
        dir.path(),
        &format!("mode = \"auto\"\npeer = \"127.0.0.1\"\nbridge_port = {bridge_port}\n"),
    );

    // When: a broken or hostile client asks for a lease far beyond the daemon cap.
    let (cfg, channel) = devbox(channel);
    assert_eq!(
        send_hold(&cfg, port, u64::MAX, channel).unwrap(),
        HoldReply::Held
    );
    let mut browser = connect(port);
    browser.write_all(b"GET / HTTP/1.1\r\n\r\n").unwrap();

    // Then: the daemon still serves a bounded hold instead of panicking or hanging up.
    assert_eq!(wait_for(&bridged).trim(), format!("CONNECT {port}"));
}

#[test]
fn a_hold_the_laptop_cannot_serve_is_refused_with_its_reason() {
    // Given: a daemon, and laptop processes already using one port on IPv4
    // loopback and another on IPv6 loopback only. A browser resolving
    // `localhost` to either family would reach the squatter, not the devbox.
    let dir = tempfile::tempdir().unwrap();
    let bridge_port = spawn_bridge(&dir.path().join("bridged"));
    let (v4_port, v6_port) = (test_port(), test_port());
    let _v4_squatter = TcpListener::bind(("127.0.0.1", v4_port)).unwrap();
    let _v6_squatter = TcpListener::bind(("::1", v6_port)).unwrap();
    let (_daemon, channel) = start(
        dir.path(),
        &format!("mode = \"auto\"\npeer = \"127.0.0.1\"\nbridge_port = {bridge_port}\n"),
    );

    for port in [v4_port, v6_port] {
        // When: the devbox asks to hold it.
        let (cfg, channel) = devbox(channel);
        let reply = send_hold(&cfg, port, 30, channel).unwrap();

        // Then: the devbox learns it was refused and why, rather than a false "held".
        let HoldReply::Refused(reason) = reply else {
            panic!("port {port}, in use on the laptop, must be refused, got {reply:?}");
        };
        assert!(reason.contains(&port.to_string()), "{reason}");
    }
}

#[test]
fn a_daemon_that_predates_holds_is_reported_as_needing_an_upgrade() {
    // Given: a counterpart that, like a daemon from before holds, reads the
    // line as a malformed URL and hangs up without answering.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let channel = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut line = String::new();
        BufReader::new(&stream).read_line(&mut line).unwrap();
    });

    // When/Then: the hold fails with the upgrade instruction, never as held.
    let (cfg, channel) = devbox(channel);
    assert!(matches!(
        send_hold(&cfg, 5_173, 30, channel),
        Err(SendError::HoldUnanswered { .. })
    ));
}

#[test]
fn forward_port_exits_nonzero_when_the_bridge_ends_a_hold() {
    // Given: a bridge that accepts one hold and then closes it, and a laptop daemon that holds.
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("forward")).unwrap();
    let arming = UnixListener::bind(dir.path().join("forward/arm.sock")).unwrap();
    let laptop = TcpListener::bind("127.0.0.1:0").unwrap();
    let channel = laptop.local_addr().unwrap().port();
    let reservation = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = reservation.local_addr().unwrap().port();
    let arm_thread = thread::spawn(move || {
        let (mut stream, _) = arming.accept().unwrap();
        let mut line = String::new();
        BufReader::new(&stream).read_line(&mut line).unwrap();
        assert_eq!(line, format!("HOLD {port}\n"));
        stream.write_all(b"ok\n").unwrap();
    });
    let laptop_thread = thread::spawn(move || {
        let (mut stream, _) = laptop.accept().unwrap();
        let mut line = String::new();
        BufReader::new(&stream).read_line(&mut line).unwrap();
        assert_eq!(line, format!("HOLD {port} 180\n"));
        stream.write_all(b"held\n").unwrap();
    });
    let config = dir.path().join("config.toml");
    std::fs::write(&config, "peer = \"127.0.0.1\"\n").unwrap();

    // When: the CLI loses the devbox-side hold after startup.
    let mut child = Command::new(env!("CARGO_BIN_EXE_forward"))
        .arg("port")
        .arg(port.to_string())
        .arg("--channel-port")
        .arg(channel.to_string())
        .arg("--config")
        .arg(&config)
        .env("XDG_RUNTIME_DIR", dir.path())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let status = wait_for_exit(&mut child);
    arm_thread.join().unwrap();
    laptop_thread.join().unwrap();

    // Then: supervisors see the forward die instead of a silently dead port forward.
    assert!(
        !status.success(),
        "forward port exited successfully after its hold ended"
    );
}

fn wait_for_exit(child: &mut std::process::Child) -> ExitStatus {
    for _ in 0..50 {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        thread::sleep(Duration::from_millis(100));
    }
    let _ = child.kill();
    let _ = child.wait();
    panic!("forward port did not exit after its bridge hold ended");
}
