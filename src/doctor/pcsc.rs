use std::os::unix::net::UnixStream;

use crate::config::Config;

/// The devbox Unix leg lives at `~/.pcscd/pcscd.comm`. A successful probe
/// reports only that the path accepted a connection; it cannot attribute the
/// listener or verify its configured relay target.
pub(super) fn report(cfg: &Config) -> bool {
    let (healthy, line) = evaluate(
        cfg,
        crate::pcsc::devbox::socket_path()
            .filter(|path| path.parent().is_some_and(|dir| dir.is_dir())),
    );
    super::print_line(line);
    healthy
}

fn evaluate(cfg: &Config, socket: Option<std::path::PathBuf>) -> (bool, String) {
    let Some(path) = socket else {
        return (
            true,
            "pcsc socket: not served on this machine (no ~/.pcscd)".to_owned(),
        );
    };
    if cfg.peer.is_empty() {
        return (
            true,
            "pcsc socket: not served (no peer configured)".to_owned(),
        );
    }
    if cfg.pcsc_port == 0 {
        return (
            true,
            "pcsc socket: not served (pcsc channel disabled, pcsc_port = 0)".to_owned(),
        );
    }
    match UnixStream::connect(&path) {
        Ok(_) => (true, format!("pcsc socket: {} accepts", path.display())),
        Err(error) => (
            false,
            format!(
                "pcsc socket: FAIL — {} ({error}); is forward serve running?",
                path.display()
            ),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    #[test]
    fn each_socket_state_renders_its_own_row() {
        let mut cfg = Config::default_values_for_test();
        cfg.peer = "100.100.92.97".to_owned();
        let (healthy, line) = evaluate(&cfg, None);
        assert!(healthy);
        assert!(line.contains("not served on this machine"));

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pcscd.comm");

        cfg.pcsc_port = 0;
        let (healthy, line) = evaluate(&cfg, Some(path.clone()));
        assert!(healthy, "a disabled channel must not fail doctor: {line}");
        assert!(line.contains("disabled"));
        cfg.pcsc_port = crate::config::default_pcsc_port();

        let (healthy, line) = evaluate(&cfg, Some(path.clone()));
        assert!(!healthy, "a dead socket must fail the devbox row: {line}");
        assert!(line.contains("is forward serve running?"));

        let _listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let expected = format!("pcsc socket: {} accepts", path.display());
        let (healthy, line) = evaluate(&cfg, Some(path));
        assert!(healthy, "{line}");
        assert_eq!(line, expected);
    }
}
