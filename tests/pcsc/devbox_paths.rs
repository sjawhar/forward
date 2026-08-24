use super::{cfg, with_home};

#[test]
fn devbox_spawn_preserves_non_socket_paths() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join(".pcscd/pcscd.comm");
    std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
    std::fs::write(&socket, b"do not delete").unwrap();

    with_home(dir.path(), || {
        let mut config = cfg();
        config.peer = "127.0.0.1".to_owned();
        config.pcsc_port = 1;
        let error = forward::pcsc::devbox::spawn(&config).expect_err("regular file must win");

        assert!(matches!(
            error,
            forward::pcsc::PcscError::Socket { source, .. }
                if source.kind() == std::io::ErrorKind::ConnectionRefused
        ));
        assert_eq!(std::fs::read(&socket).unwrap(), b"do not delete");

        std::fs::remove_file(&socket).unwrap();
        std::os::unix::fs::symlink("missing-pcscd.comm", &socket).unwrap();
        let error = forward::pcsc::devbox::spawn(&config).expect_err("dangling symlink must win");

        assert!(matches!(
            error,
            forward::pcsc::PcscError::Socket { source, .. }
                if source.kind() == std::io::ErrorKind::NotFound
        ));
        assert!(
            std::fs::symlink_metadata(&socket)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    });
}
