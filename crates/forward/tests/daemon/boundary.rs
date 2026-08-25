use std::io::Write as _;
use std::thread;
use std::time::Duration;

use super::daemon_support::{send_bytes, start, stub, wait_for};

#[test]
fn url_line_at_the_byte_limit_is_processed() {
    let dir = tempfile::tempdir().unwrap();
    let opened = dir.path().join("opened");
    let opener = stub(
        dir.path(),
        "opener",
        &format!("echo \"$@\" >> {}", opened.display()),
    );
    let (daemon, port) = start(
        dir.path(),
        &format!(
            r#"
mode = "auto"
opener = ["{opener}"]
"#
        ),
    );
    let prefix = "https://example.com/";
    let url = format!("{prefix}{}", "x".repeat(8_191 - prefix.len()));
    send_bytes(port, format!("{url}\n").as_bytes());
    assert!(wait_for(&opened).contains(&url));
    drop(daemon);
}

#[test]
fn overlong_url_line_is_dropped_before_parsing() {
    let dir = tempfile::tempdir().unwrap();
    let opened = dir.path().join("opened");
    let opener = stub(
        dir.path(),
        "opener",
        &format!("echo \"$@\" >> {}", opened.display()),
    );
    let (daemon, port) = start(
        dir.path(),
        &format!(
            r#"
mode = "auto"
opener = ["{opener}"]
"#
        ),
    );
    send_bytes(port, &vec![b'x'; 8_192]);
    daemon.wait_for_log("URL line exceeded 8192 bytes");
    assert!(
        !opened.exists(),
        "overlong URL lines must not reach the opener"
    );
}

#[test]
fn url_line_ended_by_eof_is_dropped_before_parsing() {
    let dir = tempfile::tempdir().unwrap();
    let opener = stub(dir.path(), "opener", "exit 0");
    let (daemon, port) = start(
        dir.path(),
        &format!(
            r#"
mode = "auto"
opener = ["{opener}"]
"#
        ),
    );
    send_bytes(port, b"https://e.co/abcdefg");
    daemon.wait_for_log("no newline before end of stream");
}

#[test]
fn url_dribbled_past_the_overall_deadline_is_dropped() {
    let dir = tempfile::tempdir().unwrap();
    let opener = stub(dir.path(), "opener", "exit 0");
    let (daemon, port) = start(
        dir.path(),
        &format!(
            r#"
mode = "auto"
opener = ["{opener}"]
"#
        ),
    );
    let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream.write_all(b"h").unwrap();
    thread::sleep(Duration::from_secs(4));
    stream.write_all(b"t").unwrap();

    daemon.wait_for_log("no newline before deadline");
}
