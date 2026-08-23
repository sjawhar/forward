use forward::browser::grant::{Grant, ProcessAnchor};
use forward::browser::request::{
    GrantStatus, parse, parse_status, parse_ttl, request, serve_with_resolver, status,
};
use parking_lot::Mutex;
use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
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
const CHILD_ROLE_ENV: &str = "FORWARD_TEST_GRANT_ROLE";

#[test]
fn sibling_children_of_a_session_can_use_its_grant() {
    if let (Some(socket), Some(port_path), Some(role)) = (
        std::env::var_os(CHILD_SOCKET_ENV),
        std::env::var_os(CHILD_PORT_PATH_ENV),
        std::env::var_os(CHILD_ROLE_ENV),
    ) {
        let path = std::path::PathBuf::from(socket);
        if role == "grant" {
            let port =
                request(&path, 60, b"correct-horse").expect("the child grant request must succeed");
            std::fs::write(port_path, port.to_string()).unwrap();
            return;
        }

        let port = std::fs::read_to_string(port_path).unwrap().parse().unwrap();
        assert!(matches!(
            status(&path),
            GrantStatus::Live {
                port: live_port,
                ..
            } if live_port == port
        ));
        let mut browser = TcpStream::connect(("127.0.0.1", port)).unwrap();
        browser.write_all(b"browser-payload").unwrap();
        let mut reply = [0_u8; 4];
        browser.read_exact(&mut reply).unwrap();
        assert_eq!(&reply, b"pong");
        return;
    }

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("grant.sock");
    let child_port_path = directory.path().join("child-port");
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_port = upstream.local_addr().unwrap().port();
    let upstream_task = thread::spawn(move || {
        let (mut stream, _) = upstream.accept().unwrap();
        let mut line = Vec::new();
        let mut byte = [0_u8; 1];
        while stream.read(&mut byte).unwrap() == 1 && byte[0] != b'\n' {
            line.push(byte[0]);
        }
        assert_eq!(line, b"RELAY correct-horse");
        let mut payload = [0_u8; 15];
        stream.read_exact(&mut payload).unwrap();
        assert_eq!(&payload, b"browser-payload");
        stream.write_all(b"pong").unwrap();
    });

    let grants = forward::browser::grant::Grants::new();
    let (sender, receiver) = mpsc::channel();
    let sender = Mutex::new(sender);
    let resolver: forward::browser::request::SessionResolver = Arc::new(move |pid| {
        let start_time = forward::browser::peer::process_start(pid).unwrap();
        sender.lock().send((pid, start_time)).unwrap();
        Some("session-a".to_owned())
    });
    let mut cfg = forward::config::Config::default_values_for_test();
    cfg.peer = "127.0.0.1".to_owned();
    cfg.relay_port = upstream_port;
    let server_path = path.clone();
    thread::spawn(move || serve_with_resolver(grants, cfg, server_path, resolver));
    await_socket(&path);

    let current_exe = std::env::current_exe().unwrap();
    let mut grant_child = Command::new(&current_exe)
        .arg("--exact")
        .arg("sibling_children_of_a_session_can_use_its_grant")
        .env(CHILD_SOCKET_ENV, &path)
        .env(CHILD_PORT_PATH_ENV, &child_port_path)
        .env(CHILD_ROLE_ENV, "grant")
        .spawn()
        .unwrap();
    let grant_pid = grant_child.id();
    assert!(grant_child.wait().unwrap().success());
    let seen_pids: Vec<(u32, u64)> = receiver.try_iter().collect();
    assert!(seen_pids.iter().any(|(pid, _)| *pid == grant_pid));

    let mut user_child = Command::new(current_exe)
        .arg("--exact")
        .arg("sibling_children_of_a_session_can_use_its_grant")
        .env(CHILD_SOCKET_ENV, &path)
        .env(CHILD_PORT_PATH_ENV, &child_port_path)
        .env(CHILD_ROLE_ENV, "use")
        .spawn()
        .unwrap();
    assert!(user_child.wait().unwrap().success());
    upstream_task.join().unwrap();
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
