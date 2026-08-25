use super::{Guard, spawn_serve};

#[test]
fn invalid_config_is_refused_before_binding_the_file_server() {
    // Given: a wildcard listener configuration that must fail closed.
    let mut cfg = forward::config::Config::default_values_for_test();
    cfg.listen = "0.0.0.0".to_owned();
    cfg.peer = "100.64.0.2".to_owned();

    // When: the public file-server entrypoint is invoked directly.
    let result = forward::serve::run(&cfg, 0);

    // Then: it returns the configuration error before opening a TCP port.
    assert!(matches!(
        result,
        Err(forward::serve::ServeError::Config(
            forward::config::ConfigError::Address {
                field: "listen",
                ..
            }
        ))
    ));
}

#[test]
fn rejects_oversized_sparse_files() {
    let config_root = tempfile::tempdir().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let oversized = dir.path().join("oversized.bin");
    std::fs::File::create(&oversized)
        .unwrap()
        .set_len(64 * 1024 * 1024 + 1)
        .unwrap();
    let (child, port) = spawn_serve(config_root.path());
    let _guard = Guard(child);
    let error = ureq::get(&format!(
        "http://127.0.0.1:{port}{}/oversized.bin",
        dir.path().display()
    ))
    .call()
    .unwrap_err();

    assert!(matches!(error, ureq::Error::Status(413, _)));
}

#[test]
fn serves_files_within_size_limit() {
    let config_root = tempfile::tempdir().unwrap();
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("small.txt"), "small").unwrap();
    let (child, port) = spawn_serve(config_root.path());
    let _guard = Guard(child);
    let response = ureq::get(&format!(
        "http://127.0.0.1:{port}{}/small.txt",
        dir.path().display()
    ))
    .call()
    .unwrap();

    assert_eq!(response.into_string().unwrap(), "small");
}
