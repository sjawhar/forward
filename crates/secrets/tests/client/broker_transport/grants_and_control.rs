use secrets::client::{CliError, ClientError, read_token_file};
use secrets::proto::ErrCode;

use super::super::{FakeBroker, Fixture, Reply};
use super::hello;

#[test]
fn get_with_no_request_reports_an_active_session_grant() {
    let token = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let broker = FakeBroker::script([
        Reply::Hello,
        Reply::Bytes(b"KEY\tSCOPE\tAGE\nHUMAN\tsession\t0s\n".to_vec()),
    ]);
    let fixture = Fixture::human("HUMAN");
    let token_file = fixture.write_token(token);

    let output = fixture.run_broker(
        ["get", "HUMAN", "--no-request"],
        broker.socket(),
        Some(&token_file),
        None,
    );

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        output.stdout,
        b"{\"key\":\"HUMAN\",\"tier\":\"human\",\"grant\":true,\"ttl\":null}\n"
    );
    assert_eq!(broker.frames(), [hello(), "GRANTS".to_owned()]);
}

#[test]
fn token_file_rejects_empty_non_utf8_and_whitespace_padded_contents() {
    let directory = tempfile::tempdir().unwrap();
    for (name, bytes) in [
        ("empty", b"".as_slice()),
        ("non-utf8", b"\xff".as_slice()),
        ("leading-space", b" token".as_slice()),
        ("trailing-newline", b"token\n".as_slice()),
    ] {
        let path = directory.path().join(name);
        std::fs::write(&path, bytes).unwrap();

        assert_eq!(read_token_file(path), Err(ClientError::TokenFile));
    }
}

#[test]
fn unknown_token_does_not_render_token_file_contents() {
    let token = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let broker = FakeBroker::script_with_token(
        [
            Reply::Hello,
            Reply::Raw(b"ERR\tUNKNOWN_TOKEN\tregistered session missing\n".to_vec()),
        ],
        token.to_owned(),
    );
    let fixture = Fixture::human("HUMAN");
    let token_file = fixture.write_token(token);

    let output = fixture.run_broker(["get", "HUMAN"], broker.socket(), Some(&token_file), None);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_ne!(output.status.code(), Some(0));
    assert!(stderr.contains("broker restarted"));
    assert!(!stderr.contains(token));
}

#[test]
fn every_daemon_error_has_distinct_retry_safe_guidance() {
    for (code, guidance) in [
        (ErrCode::BadRequest, "malformed request"),
        (ErrCode::UnknownOp, "unsupported operation"),
        (ErrCode::VersionMismatch, "different protocol versions"),
        (ErrCode::UnknownToken, "broker restarted"),
        (ErrCode::NoScope, "echo $SECRETSD_SESSION_TOKEN_FILE"),
        (ErrCode::AgentTty, "known agent terminal"),
        (ErrCode::NotHumanKey, "restart secretsd"),
        (ErrCode::AmbiguousKey, "remove or rename"),
        (ErrCode::Denied, "declined"),
        (ErrCode::Timeout, "expired"),
        (ErrCode::YubikeyUnreachable, "hardware path"),
        (ErrCode::TooManyPending, "too many pending"),
        (ErrCode::Internal, "journalctl --user -u secretsd"),
    ] {
        let text = CliError::from_broker(code).to_string();
        assert!(text.starts_with("AGENT NOTICE: ask the human; do not retry-loop."));
        assert!(text.contains(guidance), "{code:?}: {text}");
    }
}

#[test]
fn control_operations_use_the_broker_without_a_token_or_tty() {
    let broker = FakeBroker::script([
        Reply::Hello,
        Reply::Bytes(b"pending=0\n".to_vec()),
        Reply::Hello,
        Reply::Ok,
        Reply::Hello,
        Reply::Ok,
    ]);
    let fixture = Fixture::agent("");

    let grants = fixture.run_broker(["grants"], broker.socket(), None, None);
    let deny = fixture.run_broker(["deny", "7"], broker.socket(), None, None);
    let lock = fixture.run_broker(["lock"], broker.socket(), None, None);

    assert_eq!(grants.stdout, b"pending=0\n");
    assert_eq!(deny.status.code(), Some(0));
    assert_eq!(lock.status.code(), Some(0));
    assert_eq!(
        broker.frames(),
        [
            hello(),
            "GRANTS".to_owned(),
            hello(),
            "DENY\tid=7".to_owned(),
            hello(),
            "LOCK".to_owned(),
        ]
    );
}

#[test]
fn bare_human_get_requests_a_grant_without_receiving_the_value() {
    // A bare `get` pre-authorizes the session: it sends REQUEST, which blocks for
    // the human's approval and triggers the touch, and it never asks for bytes.
    let token = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let broker = FakeBroker::script_with_token(
        [Reply::Hello, Reply::Raw(b"OK\tstatus=granted\n".to_vec())],
        token.to_owned(),
    );
    let fixture = Fixture::human("HUMAN");
    let token_file = fixture.write_token(token);

    let output = fixture.run_broker(["get", "HUMAN"], broker.socket(), Some(&token_file), None);

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        output.stdout,
        b"{\"key\":\"HUMAN\",\"tier\":\"human\",\"grant\":true,\"ttl\":null}\n"
    );
    assert_eq!(
        broker.frames(),
        [hello(), "REQUEST\tkey=HUMAN\ttoken=<redacted>".to_owned()]
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("human-value"));
}

#[test]
fn a_ttl_flag_is_sent_on_the_wire_and_the_effective_value_is_reported_back() {
    // The broker may clamp what was asked for; the CLI reports what it
    // actually got, not a blind echo of the flag.
    let token = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let broker = FakeBroker::script_with_token(
        [
            Reply::Hello,
            Reply::Raw(b"OK\tstatus=granted ttl=28800\n".to_vec()),
        ],
        token.to_owned(),
    );
    let fixture = Fixture::human("HUMAN");
    let token_file = fixture.write_token(token);

    let output = fixture.run_broker(
        ["get", "HUMAN", "--ttl", "8h"],
        broker.socket(),
        Some(&token_file),
        None,
    );

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        output.stdout,
        b"{\"key\":\"HUMAN\",\"tier\":\"human\",\"grant\":true,\"ttl\":28800}\n"
    );
    assert_eq!(
        broker.frames(),
        [
            hello(),
            "REQUEST\tkey=HUMAN\ttoken=<redacted>\tttl=28800".to_owned()
        ]
    );
}
