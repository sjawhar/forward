use std::io::{BufRead as _, BufReader, Write as _};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::thread::{self, JoinHandle};

use forward::secretsd::{self, BrokerError, CAP_BROWSER};

const RECEIPT: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const HELLO_OK: &str = "OK\tversion=3 instance=abc123 epoch=0\n";

struct Step {
    expected: String,
    reply: Reply,
}

enum Reply {
    Text(String),
    Close,
}

struct FakeBroker {
    _dir: tempfile::TempDir,
    path: PathBuf,
    worker: JoinHandle<()>,
}

impl FakeBroker {
    fn start(steps: Vec<Step>) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secretsd.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let worker = thread::spawn(move || {
            for step in steps {
                let (stream, _) = listener.accept().unwrap();
                let mut frame = String::new();
                BufReader::new(stream.try_clone().unwrap())
                    .read_line(&mut frame)
                    .unwrap();
                assert!(frame == step.expected, "unexpected broker frame");
                if let Reply::Text(reply) = step.reply {
                    let mut stream = stream;
                    stream.write_all(reply.as_bytes()).unwrap();
                }
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

fn hello() -> Step {
    Step {
        expected: "HELLO\tversion=3\n".to_owned(),
        reply: Reply::Text(HELLO_OK.to_owned()),
    }
}

fn redeem() -> String {
    format!("REDEEM\treceipt={RECEIPT}\tcap=browser\n")
}

#[test]
fn redeem_accepts_matching_capability() {
    let broker = FakeBroker::start(vec![
        hello(),
        Step {
            expected: redeem(),
            reply: Reply::Text("OK\tstatus=redeemed cap=browser epoch=7\n".to_owned()),
        },
    ]);

    let result = secretsd::redeem(&broker.path, RECEIPT.as_bytes(), CAP_BROWSER);
    broker.finish();
    assert_eq!(result.ok(), Some(7));
}

#[test]
fn redeem_refuses_a_success_reply_without_an_epoch() {
    let broker = FakeBroker::start(vec![
        hello(),
        Step {
            expected: redeem(),
            reply: Reply::Text("OK\tstatus=redeemed cap=browser\n".to_owned()),
        },
    ]);

    let result = secretsd::redeem(&broker.path, RECEIPT.as_bytes(), CAP_BROWSER);
    broker.finish();

    assert!(matches!(result, Err(BrokerError::Protocol(_))));
}

#[test]
fn lock_epoch_reads_the_fresh_hello_extension() {
    let broker = FakeBroker::start(vec![hello()]);

    let epoch = secretsd::lock_epoch(&broker.path);
    broker.finish();

    assert_eq!(epoch.ok(), Some(0));
}

#[test]
fn redeem_maps_denied_to_receipt_rejected() {
    let broker = FakeBroker::start(vec![
        hello(),
        Step {
            expected: redeem(),
            reply: Reply::Text("ERR\tDENIED\treceipt is not redeemable\n".to_owned()),
        },
    ]);

    let error = secretsd::redeem(&broker.path, RECEIPT.as_bytes(), CAP_BROWSER).unwrap_err();
    broker.finish();
    assert!(matches!(error, BrokerError::ReceiptRejected));
}

#[test]
fn an_old_daemon_maps_unknown_op_to_upgrade_guidance() {
    let broker = FakeBroker::start(vec![
        hello(),
        Step {
            expected: redeem(),
            reply: Reply::Text("ERR\tUNKNOWN_OP\tunknown operation\n".to_owned()),
        },
    ]);

    let error = secretsd::redeem(&broker.path, RECEIPT.as_bytes(), CAP_BROWSER).unwrap_err();
    broker.finish();
    assert!(matches!(error, BrokerError::UnknownOp));
    assert!(error.to_string().contains("2.6.0"));
}

#[test]
fn a_version_mismatch_is_a_protocol_error() {
    let broker = FakeBroker::start(vec![Step {
        expected: "HELLO\tversion=3\n".to_owned(),
        reply: Reply::Text("OK\tversion=2 instance=abc\n".to_owned()),
    }]);

    let error = secretsd::redeem(&broker.path, RECEIPT.as_bytes(), CAP_BROWSER).unwrap_err();
    broker.finish();
    assert!(matches!(error, BrokerError::Protocol(_)));
}

#[test]
fn a_malformed_reply_is_a_sanitized_protocol_error() {
    const SENSITIVE: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    let broker = FakeBroker::start(vec![
        hello(),
        Step {
            expected: redeem(),
            reply: Reply::Text(format!("MALFORMED {SENSITIVE}\n")),
        },
    ]);

    let error = secretsd::redeem(&broker.path, RECEIPT.as_bytes(), CAP_BROWSER).unwrap_err();
    broker.finish();
    assert!(matches!(error, BrokerError::Protocol(_)));
    assert!(!error.to_string().contains(SENSITIVE));
    assert!(!format!("{error:?}").contains(SENSITIVE));
}

#[test]
fn a_closed_socket_is_a_protocol_error() {
    let broker = FakeBroker::start(vec![
        hello(),
        Step {
            expected: redeem(),
            reply: Reply::Close,
        },
    ]);

    let error = secretsd::redeem(&broker.path, RECEIPT.as_bytes(), CAP_BROWSER).unwrap_err();
    broker.finish();
    assert!(matches!(error, BrokerError::Protocol(_)));
}

#[test]
fn a_reply_without_a_newline_is_a_protocol_error() {
    let broker = FakeBroker::start(vec![
        hello(),
        Step {
            expected: redeem(),
            reply: Reply::Text("OK\tstatus=redeemed cap=browser".to_owned()),
        },
    ]);

    let error = secretsd::redeem(&broker.path, RECEIPT.as_bytes(), CAP_BROWSER).unwrap_err();
    broker.finish();
    assert!(matches!(error, BrokerError::Protocol(_)));
}

#[test]
fn redeem_rejects_an_authorize_shaped_success() {
    let broker = FakeBroker::start(vec![
        hello(),
        Step {
            expected: redeem(),
            reply: Reply::Text("OK\tstatus=authorized cap=browser\n".to_owned()),
        },
    ]);

    let result = secretsd::redeem(&broker.path, RECEIPT.as_bytes(), CAP_BROWSER);
    broker.finish();
    assert!(matches!(result, Err(BrokerError::Protocol(_))));
}

#[test]
fn redeem_rejects_duplicate_or_unexpected_success_fields() {
    for response in [
        "OK\tstatus=redeemed cap=browser epoch=7 cap=other\n",
        "OK\tstatus=redeemed cap=browser epoch=7 extra=value\n",
    ] {
        let broker = FakeBroker::start(vec![
            hello(),
            Step {
                expected: redeem(),
                reply: Reply::Text(response.to_owned()),
            },
        ]);

        let result = secretsd::redeem(&broker.path, RECEIPT.as_bytes(), CAP_BROWSER);
        broker.finish();
        assert!(matches!(result, Err(BrokerError::Protocol(_))));
    }
}
