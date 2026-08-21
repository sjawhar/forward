use std::io::{Read as _, Write as _};
use std::net::TcpListener;

fn spawn_accept_and_close() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        if let Ok((stream, _)) = listener.accept() {
            drop(stream);
        }
    });
    port
}

fn spawn_bridge_refusal(reply: &'static [u8]) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut line = [0_u8; 64];
            let _ = stream.read(&mut line);
            let _ = stream.write_all(reply);
        }
    });
    port
}

fn spawn_file_preview(status: u16) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut request = [0_u8; 512];
            let _ = stream.read(&mut request);
            let response = match status {
                200 => b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n".as_slice(),
                403 => b"HTTP/1.0 403 Forbidden\r\nContent-Length: 0\r\n\r\n".as_slice(),
                _ => unreachable!("test helper only serves doctor probe statuses"),
            };
            let _ = stream.write_all(response);
        }
    });
    port
}

#[derive(Clone, Copy)]
struct DoctorPorts {
    channel: u16,
    files: u16,
    bridge: u16,
}

fn run_doctor(ports: DoctorPorts) -> std::process::Output {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.toml");
    std::fs::write(
        &config,
        format!("bridge_port = {}\nrelay_port = 0\n", ports.bridge),
    )
    .unwrap();
    std::process::Command::new(env!("CARGO_BIN_EXE_forward"))
        .args([
            "doctor",
            "--channel-port",
            &ports.channel.to_string(),
            "--files-port",
            &ports.files.to_string(),
            "--config",
        ])
        .arg(config)
        .output()
        .unwrap()
}

fn output_text(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stdout).to_string() + &String::from_utf8_lossy(&output.stderr)
}

fn assert_channel_failed(output: &std::process::Output, channel: &str, port: u16) {
    let text = output_text(output);
    assert!(!output.status.success(), "got {text}");
    assert!(text.contains(&format!("{channel}: FAIL")), "got {text}");
    assert!(text.contains(&format!("127.0.0.1:{port}")), "got {text}");
}

#[test]
fn doctor_names_every_channel_and_exits_non_zero_when_one_is_down() {
    // Given: a config pointing every channel at a dead port. Port 9 (discard)
    // sits outside the ephemeral range and is never bound in tests, and
    // 127.0.0.2 is a second loopback address so both probe candidates are tried.
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.toml");
    std::fs::write(&config, "peer = \"127.0.0.2\"\nbridge_port = 9\n").unwrap();

    // When: doctor runs.
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_forward"))
        .args([
            "doctor",
            "--channel-port",
            "9",
            "--files-port",
            "9",
            "--config",
        ])
        .arg(&config)
        .output()
        .unwrap();

    // Then: it names each channel, marks the dead ones, keeps the PC/SC line
    // informational, and exits non-zero so a wrapper can act on it.
    let text = output_text(&output);
    assert!(text.contains("url channel: FAIL"), "got {text}");
    assert!(text.contains("file preview: FAIL"), "got {text}");
    assert!(text.contains("callback bridge: FAIL"), "got {text}");
    assert!(text.contains("pcsc: info"), "got {text}");
    assert!(text.contains("belongs to the secrets broker"), "got {text}");
    assert!(!output.status.success());
}

#[test]
fn the_pcsc_line_never_decides_overall_health() {
    // Given: all three channels forward owns answering the way doctor expects,
    // and no assumption whatsoever about the PC/SC forward, which stays on SSH
    // and may or may not have a listener on this machine.
    let channel_port = spawn_accept_and_close();
    let bridge_port = spawn_bridge_refusal(b"REFUSED DENIED\n");
    let files_port = spawn_file_preview(200);
    let mut cfg = forward::config::Config::default_values_for_test();
    cfg.bridge_port = bridge_port;

    // When: doctor reports.
    let healthy = forward::doctor::run(&cfg, channel_port, files_port);

    // Then: the verdict is healthy. The PC/SC line is informational, so whether
    // 12799 answers here cannot change it.
    assert!(healthy);
}

#[test]
fn doctor_labels_url_tcp_acceptance_as_delivery_unverified() {
    // Given: listeners that exhibit the limited evidence doctor can obtain
    // without delivering a URL or opening a browser.
    let ports = DoctorPorts {
        channel: spawn_accept_and_close(),
        files: spawn_file_preview(200),
        bridge: spawn_bridge_refusal(b"REFUSED DENIED\n"),
    };

    // When: doctor checks the channels.
    let output = run_doctor(ports);

    // Then: it reports the accepted TCP connection without claiming delivery.
    let text = output_text(&output);
    assert!(output.status.success(), "got {text}");
    assert!(
        text.contains(&format!(
            "url channel: accepted TCP at 127.0.0.1:{}; delivery unverified",
            ports.channel
        )),
        "got {text}"
    );
}

#[test]
fn doctor_rejects_a_busy_bridge_refusal() {
    // Given: a URL listener and file server, but a bridge-shaped listener that
    // emits the refusal a saturated bridge returns.
    let ports = DoctorPorts {
        channel: spawn_accept_and_close(),
        files: spawn_file_preview(200),
        bridge: spawn_bridge_refusal(b"REFUSED BUSY\n"),
    };

    // When: doctor checks the channels.
    let output = run_doctor(ports);

    // Then: a saturation refusal is not mistaken for the denylist gate response.
    assert_channel_failed(&output, "callback bridge", ports.bridge);
}

#[test]
fn doctor_fails_when_only_the_url_channel_is_down() {
    // Given: working file and bridge listeners but no URL-channel listener.
    let ports = DoctorPorts {
        channel: 9,
        files: spawn_file_preview(200),
        bridge: spawn_bridge_refusal(b"REFUSED DENIED\n"),
    };

    // When: doctor checks the channels.
    let output = run_doctor(ports);

    // Then: the missing URL channel alone makes the command fail.
    assert_channel_failed(&output, "url channel", ports.channel);
}

#[test]
fn doctor_fails_when_only_file_preview_is_down() {
    // Given: working URL and bridge listeners but no file-preview listener.
    let ports = DoctorPorts {
        channel: spawn_accept_and_close(),
        files: 9,
        bridge: spawn_bridge_refusal(b"REFUSED DENIED\n"),
    };

    // When: doctor checks the channels.
    let output = run_doctor(ports);

    // Then: the missing file-preview listener alone makes the command fail.
    assert_channel_failed(&output, "file preview", ports.files);
}

#[test]
fn doctor_fails_when_only_the_callback_bridge_is_down() {
    // Given: working URL and file listeners but no callback bridge.
    let ports = DoctorPorts {
        channel: spawn_accept_and_close(),
        files: spawn_file_preview(200),
        bridge: 9,
    };

    // When: doctor checks the channels.
    let output = run_doctor(ports);

    // Then: the missing bridge alone makes the command fail.
    assert_channel_failed(&output, "callback bridge", ports.bridge);
}
