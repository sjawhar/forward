use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::Stdio;
use std::time::{Duration, Instant};

struct Kill(std::process::Child);

impl Drop for Kill {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn wait_for_socket(path: &Path) {
    for _ in 0..100 {
        if path.exists() {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("arming socket never appeared at {}", path.display());
}

fn wait_for_bridge(port: u16) {
    for _ in 0..100 {
        // A probe connection sends no CONNECT line, so the bridge refuses it.
        // All this proves is that the listener is bound.
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("callback bridge never bound port {port}");
}

#[test]
fn arming_over_the_local_socket_makes_a_port_reachable() {
    // Given: a bridge with an arming socket in a temporary directory.
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("arm.sock");
    let armed = forward::bridge::Armed::new();
    forward::bridge::serve_arming(armed.clone(), socket.clone());
    wait_for_socket(&socket);

    // When: a local process arms two ports, as `forward open` does.
    assert!(forward::bridge::arm(&socket, &[8400, 9000], 300));

    // Then: both are reachable and nothing else is.
    assert!(armed.is_armed(8400));
    assert!(armed.is_armed(9000));
    assert!(!armed.is_armed(8401));
}

#[test]
fn arming_a_missing_socket_reports_failure_without_panicking() {
    // Given: no bridge running, which is the case on the laptop.
    let missing = Path::new("/nonexistent/forward-arm.sock");

    // When: arming is attempted.
    // Then: it reports failure rather than aborting the caller, because
    // `forward open` must still send and open the URL.
    assert!(!forward::bridge::arm(missing, &[8400], 300));
}

#[test]
fn arming_socket_refuses_unsafe_callback_ports() {
    // Given: a live local arming socket and an inspector port supplied by a URL.
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("arm.sock");
    let armed = forward::bridge::Armed::new();
    forward::bridge::serve_arming(armed.clone(), socket.clone());
    wait_for_socket(&socket);

    // When: a local forward client asks to arm the Node inspector.
    let armed_reply = forward::bridge::arm(&socket, &[9229], 300);

    // Then: the client receives no success acknowledgement and no lease exists.
    assert!(!armed_reply);
    assert!(!armed.is_armed(9229));
}

#[test]
fn an_overlong_unterminated_arm_line_is_refused_without_arming() {
    // Given: a bridge with an arming socket.
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("arm.sock");
    let armed = forward::bridge::Armed::new();
    forward::bridge::serve_arming(armed.clone(), socket.clone());
    wait_for_socket(&socket);

    // When: a local process sends a long ARM line and never terminates it.
    let mut hostile = UnixStream::connect(&socket).unwrap();
    let padding = " ".repeat(4096);
    hostile
        .write_all(format!("ARM 8400 300{padding}").as_bytes())
        .unwrap();
    hostile.flush().unwrap();

    // Then: it is refused with no reply and nothing is armed. The read is
    // tolerated rather than unwrapped: a refusal closes the connection, and
    // whether that arrives as a clean EOF or a reset is kernel timing.
    let mut reply = String::new();
    let _ = hostile.read_to_string(&mut reply);
    assert!(reply.is_empty(), "got {reply:?}");
    assert!(!armed.is_armed(8400));

    // And: the socket still serves, so the bounded read released the handler
    // instead of pinning it on a line that never ends.
    assert!(forward::bridge::arm(&socket, &[9100], 300));
    assert!(armed.is_armed(9100));
}

#[test]
fn a_slow_arming_client_does_not_block_other_clients() {
    // Given: a real server with an isolated runtime directory and bridge port.
    let bridge_probe = TcpListener::bind("127.0.0.1:0").unwrap();
    let bridge_port = bridge_probe.local_addr().unwrap().port();
    drop(bridge_probe);
    let runtime_dir = tempfile::tempdir().unwrap();
    let config = runtime_dir.path().join("config.toml");
    std::fs::write(&config, format!("bridge_port = {bridge_port}\n")).unwrap();
    let child = std::process::Command::new(env!("CARGO_BIN_EXE_forward"))
        .args(["serve", "--port", "0"])
        .arg("--config")
        .arg(&config)
        .env("XDG_RUNTIME_DIR", runtime_dir.path())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let _guard = Kill(child);
    let socket = runtime_dir.path().join("forward-arm.sock");
    wait_for_socket(&socket);
    let mut slow_client = UnixStream::connect(&socket).unwrap();
    slow_client.write_all(b"A").unwrap();

    // When: another local client sends a complete request before the drip times out.
    let started = Instant::now();
    let armed = forward::bridge::arm(&socket, &[8400], 300);

    // Then: its acknowledgement is not queued behind the slow client.
    assert!(armed);
    assert!(started.elapsed() < Duration::from_secs(1));
}

#[test]
fn serve_shares_one_armed_set_between_the_socket_and_the_bridge() {
    // Given: an upstream bound ONLY to loopback, the shape an OAuth CLI binds.
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_port = upstream.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let (mut stream, _) = upstream.accept().unwrap();
        let mut buf = [0_u8; 4];
        stream.read_exact(&mut buf).unwrap();
        stream.write_all(b"pong").unwrap();
    });

    // And: a real `forward serve`, given its own runtime directory and a bridge
    // port the kernel chose, so parallel tests and a real devbox daemon cannot
    // collide with it. The probe listener is released before the child binds.
    let probe = TcpListener::bind("127.0.0.1:0").unwrap();
    let bridge_port = probe.local_addr().unwrap().port();
    drop(probe);
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.toml");
    std::fs::write(&config, format!("bridge_port = {bridge_port}\n")).unwrap();
    let child = std::process::Command::new(env!("CARGO_BIN_EXE_forward"))
        .args(["serve", "--port", "0"])
        .arg("--config")
        .arg(&config)
        .env("XDG_RUNTIME_DIR", dir.path())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let _guard = Kill(child);
    let socket = dir.path().join("forward-arm.sock");
    wait_for_socket(&socket);
    wait_for_bridge(bridge_port);

    // When: a local process arms the callback port over the socket, as
    // `forward open` does, and a peer then asks the bridge for that port.
    assert!(forward::bridge::arm(&socket, &[upstream_port], 300));
    let mut client = TcpStream::connect(("127.0.0.1", bridge_port)).unwrap();
    writeln!(client, "CONNECT {upstream_port}").unwrap();
    client.write_all(b"ping").unwrap();

    // Then: the hop happens, which it can only do if `serve` handed the socket
    // and the bridge the same armed set.
    let mut reply = String::new();
    client.read_to_string(&mut reply).unwrap();
    assert_eq!(reply, "pong");
}

#[test]
fn open_arms_only_the_dynamic_callback_ports_of_a_url() {
    // Given: a bridge arming socket, as `forward serve` provides.
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("arm.sock");
    let armed = forward::bridge::Armed::new();
    forward::bridge::serve_arming(armed.clone(), socket.clone());
    wait_for_socket(&socket);
    let cfg = forward::config::Config::default_values_for_test();

    // When: `forward open` arms the ports of a URL carrying both a callback on
    // devbox loopback 8400 and the static file-preview port.
    let url =
        url::Url::parse("http://localhost:12802/?redirect_uri=http%3A%2F%2F127.0.0.1%3A8400%2Fcb")
            .unwrap();
    let count = forward::bridge::arm_for_url(&cfg, &url, &socket);

    // Then: the callback port is reachable through the bridge and the static
    // port is not.
    assert_eq!(count, 1);
    assert!(armed.is_armed(8400));
    assert!(!armed.is_armed(12_802));
}
