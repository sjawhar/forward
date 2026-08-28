use std::os::unix::net::UnixStream;

use crate::config::Config;

/// The devbox Unix leg lives at `$XDG_RUNTIME_DIR/forward/pulse.sock`. A
/// successful probe reports only that the path accepted a connection; it
/// cannot attribute the listener or verify its configured relay target. The
/// parent-directory vantage check mirrors the pcsc row, with one caveat: that
/// directory is tmpfs-backed: a devbox that rebooted and never started
/// `forward serve` reads as "not served" rather than FAIL.
pub(super) fn report(cfg: &Config) -> bool {
    let (healthy, line) = evaluate(
        cfg,
        crate::pulse::devbox::socket_path()
            .filter(|path| path.parent().is_some_and(|dir| dir.is_dir())),
    );
    super::print_line(line);
    healthy
}

fn evaluate(cfg: &Config, socket: Option<std::path::PathBuf>) -> (bool, String) {
    let Some(path) = socket else {
        return (
            true,
            "pulse socket: not served on this machine (no $XDG_RUNTIME_DIR/forward)".to_owned(),
        );
    };
    if cfg.peer.is_empty() {
        return (
            true,
            "pulse socket: not served (no peer configured)".to_owned(),
        );
    }
    if cfg.pulse_port == 0 {
        return (
            true,
            "pulse socket: not served (pulse channel disabled, pulse_port = 0)".to_owned(),
        );
    }
    match UnixStream::connect(&path) {
        Ok(_) => (true, format!("pulse socket: {} accepts", path.display())),
        Err(error) => (
            false,
            format!(
                "pulse socket: FAIL — {} ({error}); is forward serve running?",
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
        let path = dir.path().join("pulse.sock");

        cfg.pulse_port = 0;
        let (healthy, line) = evaluate(&cfg, Some(path.clone()));
        assert!(healthy, "a disabled channel must not fail doctor: {line}");
        assert!(line.contains("disabled"));
        cfg.pulse_port = crate::config::default_pulse_port();

        let (healthy, line) = evaluate(&cfg, Some(path.clone()));
        assert!(!healthy, "a dead socket must fail the devbox row: {line}");
        assert!(line.contains("is forward serve running?"));

        let _listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let expected = format!("pulse socket: {} accepts", path.display());
        let (healthy, line) = evaluate(&cfg, Some(path));
        assert!(healthy, "{line}");
        assert_eq!(line, expected);
    }
}
