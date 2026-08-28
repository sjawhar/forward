use std::io::{Read as _, Write as _};
use std::net::TcpListener;

fn run_doctor_with(ports: super::DoctorPorts, relay_lines: &str) -> std::process::Output {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.toml");
    std::fs::write(
        &config,
        format!(
            "bridge_port = {}\npcsc_port = 0\ngrant_port = 0\npulse_port = 0\n{relay_lines}",
            ports.bridge
        ),
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

fn healthy_ports() -> super::DoctorPorts {
    super::DoctorPorts {
        channel: super::spawn_accept_and_close(),
        files: super::spawn_file_preview(200),
        bridge: super::spawn_bridge_refusal(b"REFUSED DENIED\n"),
    }
}

fn dropped_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

fn spawn_relay() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for response in [
            b"HTTP/1.0 200 OK\r\n\r\n{}".as_slice(),
            b"HTTP/1.0 200 OK\r\n\r\n[{\"id\":\"relay-1\",\"title\":\"Example\",\"type\":\"page\",\"url\":\"https://example.test/\"}]".as_slice(),
        ] {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 512];
            let _ = stream.read(&mut request);
            stream.write_all(response).unwrap();
        }
    });
    port
}

fn spawn_token_refusal_relay() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = [0_u8; 512];
        let _ = stream.read(&mut request);
        stream.write_all(b"REFUSED TOKEN\n").unwrap();
    });
    port
}

#[test]
fn the_disabled_row_reports_and_never_fails() {
    let output = super::run_doctor(healthy_ports());
    let text = super::output_text(&output);

    assert!(output.status.success(), "got {text}");
    assert!(
        text.contains("browser relay: disabled (relay_port = 0)"),
        "got {text}"
    );
}

#[test]
fn laptop_role_reports_relay_channel_down_when_nothing_is_bound() {
    let output = run_doctor_with(
        healthy_ports(),
        &format!("relay_port = {}\n", dropped_port()),
    );
    let text = super::output_text(&output);

    assert!(!output.status.success(), "got {text}");
    assert!(text.contains("browser relay: FAIL"), "got {text}");
    assert!(
        text.contains("relay channel down — is forward daemon running?"),
        "got {text}"
    );
}

#[test]
fn loopback_listen_answers_end_to_end_on_the_listen_leg() {
    let output = run_doctor_with(
        healthy_ports(),
        &format!("relay_port = {}\n", spawn_relay()),
    );
    let text = super::output_text(&output);

    assert!(output.status.success(), "got {text}");
    assert!(text.contains("browser relay: healthy"), "got {text}");
    assert!(text.contains("(1 targets)"), "got {text}");
}

#[test]
fn a_token_refusal_reports_locked_but_healthy() {
    let output = run_doctor_with(
        healthy_ports(),
        &format!("relay_port = {}\n", spawn_token_refusal_relay()),
    );
    let text = super::output_text(&output);

    assert!(output.status.success(), "got {text}");
    assert!(text.contains("browser relay: locked"), "got {text}");
    assert!(text.contains("(no grant)"), "got {text}");
    assert!(text.contains("browser grant:"), "got {text}");
}
