use std::process::Command;

#[test]
fn browser_grant_loads_its_explicit_config() {
    let directory = tempfile::tempdir().unwrap();
    let config = directory.path().join("config.toml");
    std::fs::write(&config, "unexpected_key = true\n").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_forward"))
        .args(["browser", "grant", "--config"])
        .arg(&config)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("failed to parse config"));
}
