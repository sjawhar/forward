use std::ffi::OsString;
use std::io::{BufRead as _, BufReader, Write as _};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::thread::{self, JoinHandle};

use forward::secretsd::{self, BrokerError, CAP_BROWSER};
use parking_lot::Mutex;
use zeroize::Zeroizing;

const TOKEN: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const RECEIPT: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const HELLO_OK: &str = "OK\tversion=3 instance=abc123\n";
static AUTHORIZE_ENV: Mutex<()> = Mutex::new(());

struct AuthorizeEnvironment {
    socket: Option<OsString>,
    token_file: Option<OsString>,
}

impl AuthorizeEnvironment {
    fn set(socket: &Path, token_file: &Path) -> Self {
        let environment = Self {
            socket: std::env::var_os("SECRETSD_SOCK"),
            token_file: std::env::var_os("SECRETSD_SESSION_TOKEN_FILE"),
        };
        // Serialized by AUTHORIZE_ENV because process environment is global.
        unsafe {
            std::env::set_var("SECRETSD_SOCK", socket);
            std::env::set_var("SECRETSD_SESSION_TOKEN_FILE", token_file);
        }
        environment
    }
}

impl Drop for AuthorizeEnvironment {
    fn drop(&mut self) {
        unsafe {
            match self.socket.take() {
                Some(value) => std::env::set_var("SECRETSD_SOCK", value),
                None => std::env::remove_var("SECRETSD_SOCK"),
            }
            match self.token_file.take() {
                Some(value) => std::env::set_var("SECRETSD_SESSION_TOKEN_FILE", value),
                None => std::env::remove_var("SECRETSD_SESSION_TOKEN_FILE"),
            }
        }
    }
}

struct FakeBroker {
    dir: tempfile::TempDir,
    path: PathBuf,
    worker: JoinHandle<()>,
}

impl FakeBroker {
    fn start(reply: &'static str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secretsd.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let worker = thread::spawn(move || {
            let steps = [
                ("HELLO\tversion=3\n", HELLO_OK),
                (
                    "AUTHORIZE\tcap=browser\ttoken=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n",
                    reply,
                ),
            ];
            for (expected, reply) in steps {
                let (stream, _) = listener.accept().unwrap();
                let mut frame = String::new();
                BufReader::new(stream.try_clone().unwrap())
                    .read_line(&mut frame)
                    .unwrap();
                assert!(frame == expected, "unexpected broker frame");
                let mut stream = stream;
                stream.write_all(reply.as_bytes()).unwrap();
            }
        });
        Self { dir, path, worker }
    }

    fn finish(self) {
        self.worker.join().unwrap();
    }
}

fn authorize(broker: &FakeBroker) -> Result<Zeroizing<Vec<u8>>, BrokerError> {
    let token_file = broker.dir.path().join("token");
    std::fs::write(&token_file, TOKEN).unwrap();
    let _environment = AuthorizeEnvironment::set(&broker.path, &token_file);
    secretsd::authorize_for_test(CAP_BROWSER)
}

#[test]
fn authorize_returns_a_receipt_after_a_broker_approval() {
    let _lock = AUTHORIZE_ENV.lock();
    let broker = FakeBroker::start(
        "OK\tstatus=authorized receipt=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
    );

    let result = authorize(&broker);
    broker.finish();
    assert!(result.as_ref().is_ok_and(
        |receipt| receipt.len() == RECEIPT.len() && receipt.iter().all(|byte| *byte == b'a')
    ));
}

#[test]
fn authorize_maps_denied_to_authorization_denied() {
    let _lock = AUTHORIZE_ENV.lock();
    let broker = FakeBroker::start("ERR\tDENIED\tapproval declined\n");

    let result = authorize(&broker);
    broker.finish();
    assert!(matches!(result, Err(BrokerError::Denied)));
}

#[test]
fn authorize_rejects_wrong_duplicate_or_unexpected_success_fields() {
    for response in [
        "OK\tstatus=redeemed receipt=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
        "OK\tstatus=authorized receipt=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa receipt=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
        "OK\tstatus=authorized receipt=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa extra=value\n",
    ] {
        let _lock = AUTHORIZE_ENV.lock();
        let broker = FakeBroker::start(response);

        let result = authorize(&broker);
        broker.finish();
        assert!(matches!(result, Err(BrokerError::Protocol(_))));
    }
}

#[test]
fn an_oversized_authorize_frame_never_reaches_the_broker() {
    let _lock = AUTHORIZE_ENV.lock();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("secretsd.sock");
    let listener = UnixListener::bind(&path).unwrap();
    listener.set_nonblocking(true).unwrap();
    let token_file = dir.path().join("token");
    std::fs::write(&token_file, TOKEN).unwrap();
    let _environment = AuthorizeEnvironment::set(&path, &token_file);

    let cap = "a".repeat(4_096);
    let result = secretsd::authorize(&cap);
    assert!(matches!(result, Err(BrokerError::Protocol(_))));
    assert!(matches!(
        listener.accept(),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
    ));
}

#[test]
fn a_control_containing_token_file_never_reaches_the_broker() {
    let _lock = AUTHORIZE_ENV.lock();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("secretsd.sock");
    let listener = UnixListener::bind(&path).unwrap();
    listener.set_nonblocking(true).unwrap();
    let token_file = dir.path().join("token");
    std::fs::write(&token_file, format!("{TOKEN}\n")).unwrap();
    let _environment = AuthorizeEnvironment::set(&path, &token_file);

    let result = secretsd::authorize(CAP_BROWSER);
    assert!(matches!(result, Err(BrokerError::Protocol(_))));
    assert!(matches!(
        listener.accept(),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
    ));
}
