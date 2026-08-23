use forward::browser::grant::{Grant, ProcessAnchor};
use forward::browser::request::{
    GrantStatus, parse, parse_status, parse_ttl, request, serve_with_resolver, status,
};
use parking_lot::Mutex;
use std::os::unix::net::UnixStream;
use std::process::Command;
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, Instant};

fn await_socket(path: &std::path::Path) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while UnixStream::connect(path).is_err() {
        assert!(Instant::now() < deadline, "request socket never came up");
        thread::sleep(Duration::from_millis(10));
    }
}

fn spawn_server(
    grants: forward::browser::grant::Grants,
    path: std::path::PathBuf,
    resolver: forward::browser::request::SessionResolver,
) {
    let mut cfg = forward::config::Config::default_values_for_test();
    cfg.peer = "127.0.0.1".to_owned();
    thread::spawn(move || serve_with_resolver(grants, cfg, path, resolver));
}

#[test]
fn a_well_formed_request_parses() {
    assert_eq!(
        parse(b"GRANT 1800 correct-horse"),
        Some((1800, b"correct-horse".to_vec()))
    );
}

#[test]
fn a_request_without_the_verb_is_rejected() {
    assert_eq!(parse(b"1800 correct-horse"), None);
    assert_eq!(parse(b"STATUS"), None);
}

#[test]
fn a_non_numeric_ttl_is_rejected() {
    assert_eq!(parse(b"GRANT soon correct-horse"), None);
}

#[test]
fn a_missing_token_is_rejected() {
    assert_eq!(parse(b"GRANT 1800"), None);
    assert_eq!(parse(b"GRANT 1800 "), None);
}

#[test]
fn a_token_containing_a_space_is_rejected() {
    assert_eq!(parse(b"GRANT 1800 correct horse"), None);
}

#[test]
fn a_zero_or_overlong_ttl_is_rejected() {
    assert_eq!(parse(b"GRANT 0 correct-horse"), None);
    assert_eq!(parse(b"GRANT 43201 correct-horse"), None);
}

#[test]
fn ttl_shorthand_parses() {
    assert_eq!(parse_ttl("45s"), Some(45));
    assert_eq!(parse_ttl("30m"), Some(1_800));
    assert_eq!(parse_ttl("2h"), Some(7_200));
    assert_eq!(parse_ttl("0m"), None);
    assert_eq!(parse_ttl("5x"), None);
    assert_eq!(parse_ttl("m"), None);
    assert_eq!(parse_ttl(""), None);
}

#[test]
fn a_status_reply_parses() {
    assert_eq!(parse_status("NONE"), GrantStatus::None);
    assert_eq!(
        parse_status("LIVE 12811 1799"),
        GrantStatus::Live {
            port: 12_811,
            remaining_secs: 1_799,
        }
    );
    assert_eq!(parse_status("LIVE nonsense"), GrantStatus::Unreachable);
}

const CHILD_SOCKET_ENV: &str = "FORWARD_TEST_GRANT_SOCKET";
const CHILD_PORT_PATH_ENV: &str = "FORWARD_TEST_GRANT_PORT_PATH";

#[test]
fn the_request_socket_attributes_the_caller_through_peer_credentials() {
    if let (Some(socket), Some(port_path)) = (
        std::env::var_os(CHILD_SOCKET_ENV),
        std::env::var_os(CHILD_PORT_PATH_ENV),
    ) {
        let port = request(&std::path::PathBuf::from(socket), 60, b"correct-horse")
            .expect("the child grant request must succeed");
        std::fs::write(port_path, port.to_string()).unwrap();
        return;
    }

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("grant.sock");
    let child_port_path = directory.path().join("child-port");
    let grants = forward::browser::grant::Grants::new();
    let (sender, receiver) = mpsc::channel();
    let sender = Mutex::new(sender);
    let resolver: forward::browser::request::SessionResolver = Arc::new(move |pid| {
        let start_time = forward::browser::peer::process_start(pid).unwrap();
        sender.lock().send((pid, start_time)).unwrap();
        Some("session-a".to_owned())
    });
    spawn_server(grants.clone(), path.clone(), resolver);
    await_socket(&path);

    let mut child = Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("the_request_socket_attributes_the_caller_through_peer_credentials")
        .env(CHILD_SOCKET_ENV, &path)
        .env(CHILD_PORT_PATH_ENV, &child_port_path)
        .spawn()
        .unwrap();
    let child_pid = child.id();
    assert!(child.wait().unwrap().success());
    let port = std::fs::read_to_string(child_port_path)
        .unwrap()
        .parse()
        .unwrap();

    let grant = grants.live(port).expect("the grant must be recorded");
    let pids: Vec<(u32, u64)> = receiver.try_iter().collect();
    let (_, child_start_time) = pids
        .iter()
        .copied()
        .find(|(pid, _)| *pid == child_pid)
        .expect("SO_PEERCRED must report the child process");
    assert_eq!(grant.session, "session-a");
    assert_eq!(grant.anchor.pid, child_pid);
    assert_eq!(grant.anchor.start_time, child_start_time);
}

#[test]
fn status_reports_the_calling_sessions_grant_over_the_socket() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("grant.sock");
    assert_eq!(status(&path), GrantStatus::Unreachable);

    let grants = forward::browser::grant::Grants::new();
    let resolver: forward::browser::request::SessionResolver =
        Arc::new(|_pid| Some("session-a".to_owned()));
    spawn_server(grants, path.clone(), resolver);
    await_socket(&path);

    assert_eq!(status(&path), GrantStatus::None);
    let port = request(&path, 60, b"correct-horse").expect("the grant request must succeed");
    match status(&path) {
        GrantStatus::Live {
            port: live_port,
            remaining_secs,
        } => {
            assert_eq!(live_port, port);
            assert!(remaining_secs <= 60);
        }
        other => panic!("expected a live grant, got {other:?}"),
    }
}

#[test]
fn status_does_not_disclose_a_grant_for_a_forged_session_string() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("grant.sock");
    let grants = forward::browser::grant::Grants::new();
    grants.insert(
        12811,
        Grant {
            session: "target-session".to_owned(),
            anchor: ProcessAnchor {
                pid: u32::MAX,
                start_time: 0,
            },
            token: b"test-only".to_vec(),
            deadline: Instant::now() + Duration::from_secs(60),
        },
    );
    let resolver: forward::browser::request::SessionResolver =
        Arc::new(|_pid| Some("target-session".to_owned()));
    spawn_server(grants, path.clone(), resolver);
    await_socket(&path);

    assert_eq!(status(&path), GrantStatus::None);
}
