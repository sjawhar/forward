use std::os::unix::net::UnixListener;
use std::path::Path;
use std::process::{Command, Stdio};

const NO_GRANT_SCOPE: &str = "forward: grant refused before any touch: no omp process runs above this command, and it has no session token and no terminal; run it from an omp session or an interactive terminal";
const NESTED_SHELL: &str = "depth=$1; shift; if [ \"$depth\" -gt 1 ]; then sh -c \"$0\" \"$0\" \"$((depth - 1))\" \"$@\"; else \"$@\"; fi; status=$?; :; exit \"$status\"";
// One shell past the hop cap, so the omp walk stops short of any omp running this test.
const SHELLS: usize = containment::MAX_ANCESTRY_HOPS + 1;

fn grant_beneath_more_shells_than_the_hop_cap(config: &Path) -> Command {
    let mut command = Command::new("sh");
    command
        .args(["-c", NESTED_SHELL, NESTED_SHELL])
        .arg(SHELLS.to_string())
        .arg(env!("CARGO_BIN_EXE_forward"))
        .args(["browser", "grant", "--config"])
        .arg(config)
        .stdin(Stdio::null());
    command
}

#[cfg_attr(miri, ignore)]
#[test]
fn browser_grant_scope_refuses_before_any_connection() {
    let directory = tempfile::tempdir().unwrap();
    let runtime = directory.path().join("runtime");
    std::fs::create_dir(&runtime).unwrap();
    let broker_socket = runtime.join("secretsd.sock");
    let listener = UnixListener::bind(&broker_socket).unwrap();
    listener.set_nonblocking(true).unwrap();
    let config = directory.path().join("forward.toml");
    std::fs::write(&config, "").unwrap();

    let output = grant_beneath_more_shells_than_the_hop_cap(&config)
        .env("SECRETSD_SOCK", &broker_socket)
        .env("XDG_RUNTIME_DIR", &runtime)
        .env_remove("SECRETSD_SESSION_TOKEN_FILE")
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        format!("{NO_GRANT_SCOPE}\n")
    );
    assert!(matches!(
        listener.accept(),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
    ));
}
