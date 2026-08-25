use std::io::{BufRead as _, BufReader, Write as _};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use forward::secretsd::{self, BrokerError, CAP_BROWSER};

const RECEIPT: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const HELLO_OK: &[u8] = b"OK\tversion=3 instance=abc123\n";

struct FakeBroker {
    _dir: tempfile::TempDir,
    path: PathBuf,
    worker: JoinHandle<()>,
}

enum Reply {
    Bytes(Vec<u8>),
    Trickle { bytes: Vec<u8>, interval: Duration },
}

impl FakeBroker {
    fn start(reply: Reply) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secretsd.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let worker = thread::spawn(move || {
            for (expected, reply) in [
                (
                    "HELLO\tversion=3\n".to_owned(),
                    Reply::Bytes(HELLO_OK.to_vec()),
                ),
                (format!("REDEEM\treceipt={RECEIPT}\tcap=browser\n"), reply),
            ] {
                let (stream, _) = listener.accept().unwrap();
                let mut frame = String::new();
                BufReader::new(stream.try_clone().unwrap())
                    .read_line(&mut frame)
                    .unwrap();
                assert!(frame == expected, "unexpected broker frame");
                write_reply(stream, reply);
            }
        });
        Self {
            _dir: dir,
            path,
            worker,
        }
    }

    fn finish(self) {
        self.worker.join().unwrap();
    }
}

fn write_reply(mut stream: std::os::unix::net::UnixStream, reply: Reply) {
    match reply {
        Reply::Bytes(bytes) => {
            let _ = stream.write_all(&bytes);
        }
        Reply::Trickle { bytes, interval } => {
            for byte in bytes {
                if stream.write_all(&[byte]).is_err() {
                    return;
                }
                thread::sleep(interval);
            }
        }
    }
}

#[test]
fn a_trickled_reply_cannot_extend_the_control_deadline() {
    let broker = FakeBroker::start(Reply::Trickle {
        bytes: b"OK\tstatus=redeemed cap=browser\n".to_vec(),
        interval: Duration::from_millis(200),
    });

    let started = Instant::now();
    let result = secretsd::redeem(&broker.path, RECEIPT.as_bytes(), CAP_BROWSER);
    let elapsed = started.elapsed();
    broker.finish();
    assert!(elapsed < Duration::from_secs(6));
    assert!(matches!(
        result,
        Err(BrokerError::Connect { source, .. })
            if matches!(source.kind(), std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock)
    ));
}

#[test]
fn an_invalid_utf8_reply_is_a_sanitized_protocol_error() {
    const MARKER: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    let mut bytes = format!("OK\tstatus=redeemed cap=browser receipt={MARKER}").into_bytes();
    bytes.push(0xff);
    bytes.push(b'\n');
    let broker = FakeBroker::start(Reply::Bytes(bytes));

    let error = secretsd::redeem(&broker.path, RECEIPT.as_bytes(), CAP_BROWSER).unwrap_err();
    broker.finish();
    assert!(matches!(error, BrokerError::Protocol(_)));
    assert!(!error.to_string().contains(MARKER));
    assert!(!format!("{error:?}").contains(MARKER));
}
