use crate::pulse_support::{cfg, tempdir, with_runtime_dir};

#[test]
fn devbox_spawn_preserves_non_socket_paths() {
    let dir = tempdir();
    let socket = dir.path().join("forward/pulse.sock");
    std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
    std::fs::write(&socket, b"do not delete").unwrap();

    with_runtime_dir(Some(dir.path()), || {
        let mut config = cfg();
        config.peer = "127.0.0.1".to_owned();
        config.pulse_port = 1;
        let error = forward::pulse::devbox::spawn(&config).expect_err("regular file must win");

        assert!(matches!(
            error,
            forward::pulse::PulseError::Socket { source, .. }
                if source.kind() == std::io::ErrorKind::ConnectionRefused
        ));
        assert_eq!(std::fs::read(&socket).unwrap(), b"do not delete");

        std::fs::remove_file(&socket).unwrap();
        std::os::unix::fs::symlink("missing-pulse.sock", &socket).unwrap();
        let error = forward::pulse::devbox::spawn(&config).expect_err("dangling symlink must win");

        assert!(matches!(
            error,
            forward::pulse::PulseError::Socket { source, .. }
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
