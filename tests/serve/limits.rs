use super::{Guard, spawn_serve};

#[test]
fn rejects_oversized_sparse_files() {
    let dir = tempfile::tempdir().unwrap();
    let oversized = dir.path().join("oversized.bin");
    std::fs::File::create(&oversized)
        .unwrap()
        .set_len(64 * 1024 * 1024 + 1)
        .unwrap();
    let (child, port) = spawn_serve(dir.path());
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
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("small.txt"), "small").unwrap();
    let (child, port) = spawn_serve(dir.path());
    let _guard = Guard(child);
    let response = ureq::get(&format!(
        "http://127.0.0.1:{port}{}/small.txt",
        dir.path().display()
    ))
    .call()
    .unwrap();

    assert_eq!(response.into_string().unwrap(), "small");
}
