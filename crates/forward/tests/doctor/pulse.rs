use std::net::TcpListener;

fn healthy_ports() -> super::DoctorPorts {
    super::DoctorPorts {
        channel: super::spawn_accept_and_close(),
        files: super::spawn_file_preview(200),
        bridge: super::spawn_bridge_refusal(b"REFUSED DENIED\n"),
    }
}

fn run_doctor_with_pulse(ports: super::DoctorPorts, pulse_port: u16) -> std::process::Output {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.toml");
    std::fs::write(
        &config,
        format!(
            "bridge_port = {}\nrelay_port = 0\npcsc_port = 0\ngrant_port = 0\npulse_port = {pulse_port}\n",
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
        .env_remove("XDG_RUNTIME_DIR")
        .output()
        .unwrap()
}

#[test]
fn pulse_channel_tcp_acceptance_is_delivery_unverified() {
    let pulse_port = super::spawn_accept_and_close();
    let output = run_doctor_with_pulse(healthy_ports(), pulse_port);
    let text = super::output_text(&output);

    assert!(output.status.success(), "got {text}");
    assert!(
        text.contains(&format!(
            "pulse channel: accepted TCP at 127.0.0.1:{pulse_port}; delivery unverified"
        )),
        "got {text}"
    );
}

#[test]
fn pulse_channel_down_makes_doctor_fail() {
    let held = TcpListener::bind("127.0.0.1:0").unwrap();
    let pulse_port = held.local_addr().unwrap().port();
    drop(held);
    let output = run_doctor_with_pulse(healthy_ports(), pulse_port);
    let text = super::output_text(&output);

    assert!(!output.status.success(), "got {text}");
    assert!(text.contains("pulse channel: FAIL"), "got {text}");
}
