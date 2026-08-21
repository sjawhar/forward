use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

fn cfg(bridge_port: u16) -> forward::config::Config {
    let mut cfg = forward::config::Config::default_values_for_test();
    cfg.bridge_port = bridge_port;
    cfg
}

fn assert_refused(client: &mut TcpStream, expected: &str) {
    client
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let mut reply = String::new();
    client
        .read_to_string(&mut reply)
        .expect("the bridge must write its refusal before closing");
    assert_eq!(reply, expected);
}

fn wait_for_exit(child: &mut Child) -> Option<std::process::ExitStatus> {
    for _ in 0..10 {
        if let Some(status) = child.try_wait().unwrap() {
            return Some(status);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    None
}

#[test]
fn wildcard_listen_is_refused_before_serve_opens_tcp_ports() {
    // Given: free ports for both TCP listeners and a wildcard bridge configuration.
    let bridge_probe = TcpListener::bind("127.0.0.1:0").unwrap();
    let bridge_port = bridge_probe.local_addr().unwrap().port();
    let file_probe = TcpListener::bind("127.0.0.1:0").unwrap();
    let file_port = file_probe.local_addr().unwrap().port();
    drop((bridge_probe, file_probe));
    let directory = tempfile::tempdir().unwrap();
    let config = directory.path().join("config.toml");
    std::fs::write(
        &config,
        format!("listen = \"0.0.0.0\"\nbridge_port = {bridge_port}\n"),
    )
    .unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_forward"))
        .args(["serve", "--port", &file_port.to_string()])
        .arg("--config")
        .arg(&config)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    // When: the command starts.
    let status = wait_for_exit(&mut child);

    // Then: configuration failure ends it before either listener can remain bound.
    let Some(status) = status else {
        child.kill().unwrap();
        child.wait().unwrap();
        panic!("forward serve accepted a wildcard listen configuration");
    };
    assert!(!status.success());
    assert!(TcpListener::bind(("127.0.0.1", bridge_port)).is_ok());
    assert!(TcpListener::bind(("127.0.0.1", file_port)).is_ok());
}

#[test]
fn bridge_serve_refuses_wildcard_listen_before_binding_a_port() {
    // Given: a probed free bridge port and a wildcard listener configuration.
    let port_probe = TcpListener::bind("127.0.0.1:0").unwrap();
    let bridge_port = port_probe.local_addr().unwrap().port();
    drop(port_probe);
    let mut bridge_cfg = cfg(bridge_port);
    bridge_cfg.listen = "0.0.0.0".to_owned();
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let _ = sender.send(forward::bridge::serve(
            bridge_cfg,
            forward::bridge::Armed::new(),
        ));
    });

    // When: the bridge entrypoint is invoked directly.
    let result = receiver
        .recv_timeout(Duration::from_secs(1))
        .expect("bridge serve did not return for invalid configuration");

    // Then: validation returns an error before the bridge can bind its port.
    assert!(matches!(
        result,
        Err(forward::bridge::BridgeError::Bind { .. })
    ));
    assert!(TcpListener::bind(("127.0.0.1", bridge_port)).is_ok());
}

#[test]
fn dangerous_ports_are_never_armed_or_relayed() {
    // Given: a bridge listener and every forbidden port armed by a local caller.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let bridge_port = listener.local_addr().unwrap().port();
    let armed = forward::bridge::Armed::new();
    let forbidden = [
        0, 80, 1_023, 2_345, 2_375, 2_376, 3_306, 5_432, 5_678, 6_379, 8_001, 9_229,
    ];
    for port in forbidden {
        armed.arm(port, Duration::from_secs(30));
    }
    forward::bridge::spawn_with_listener(cfg(bridge_port), armed.clone(), listener);

    // When: the local caller checks its leases and a peer requests each one.
    // Then: no lease exists and the bridge independently refuses every request.
    for port in forbidden {
        assert!(!armed.is_armed(port), "port {port} was armed");
        assert!(forward::bridge::denied_port(bridge_port, port));
        let mut client = TcpStream::connect(("127.0.0.1", bridge_port)).unwrap();
        writeln!(client, "CONNECT {port}").unwrap();
        assert_refused(&mut client, "REFUSED DENIED\n");
    }
}

#[test]
fn actual_listener_port_is_refused_even_when_config_port_differs() {
    // Given: a bridge whose injected listener differs from its Config port.
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_port = upstream.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let (mut stream, _) = upstream.accept().unwrap();
        let mut request = [0_u8; 4];
        stream.read_exact(&mut request).unwrap();
        stream.write_all(b"pong").unwrap();
    });
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let listener_port = listener.local_addr().unwrap().port();
    let configured_port = listener_port.checked_add(1).unwrap();
    let armed = forward::bridge::Armed::new();
    armed.arm(listener_port, Duration::from_secs(30));
    armed.arm(upstream_port, Duration::from_secs(30));
    forward::bridge::spawn_with_listener(cfg(configured_port), armed, listener);

    // When: a peer tries to tunnel another CONNECT request through the listener itself.
    let mut client = TcpStream::connect(("127.0.0.1", listener_port)).unwrap();
    client
        .write_all(format!("CONNECT {listener_port}\nCONNECT {upstream_port}\nping").as_bytes())
        .unwrap();

    // Then: the actual listener port, not the stale Config value, stops the loop.
    assert_refused(&mut client, "REFUSED DENIED\n");
}

#[test]
fn a_flooding_client_still_gets_its_refusal_and_frees_its_slot() {
    // Given: an unarmed bridge and a client continually writing after its request.
    let bridge_port = super::spawn_bridge(forward::bridge::Armed::new());
    let client = TcpStream::connect(("127.0.0.1", bridge_port)).unwrap();
    let mut reader = client.try_clone().unwrap();
    reader
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let writer_stop = Arc::clone(&stop);
    let writer = std::thread::spawn(move || {
        let _ = (&client).write_all(b"CONNECT 12799\n");
        while !writer_stop.load(Ordering::Relaxed) {
            let _ = (&client).write_all(&[0_u8; 4096]);
        }
    });

    // When: the bounded drain handles the continuous write stream.
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut reply = Vec::new();
    let result = loop {
        let mut chunk = [0_u8; 32];
        match reader.read(&mut chunk) {
            Ok(0) => break Err("bridge closed before sending its refusal"),
            Ok(count) => {
                reply.extend_from_slice(&chunk[..count]);
                if reply.ends_with(b"REFUSED DENIED\n") {
                    break Ok(reply);
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) && Instant::now() < deadline =>
            {
                continue;
            }
            Err(_) => break Err("bridge did not send its refusal within five seconds"),
        }
    };
    stop.store(true, Ordering::Relaxed);
    writer.join().unwrap();

    // Then: delivery proves the drain returned. `refuse` is the DENIED arm's tail
    // call, so this handler returned too and RAII released its ConnectionPermit.
    assert_eq!(result.unwrap(), b"REFUSED DENIED\n");
}
