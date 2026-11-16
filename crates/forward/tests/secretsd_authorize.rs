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
const HELLO_OK: &str = "OK\tversion=4 instance=abc123\n";
const AUTHORIZE_TOKEN: &str = "AUTHORIZE\tcap=browser\ttoken=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n";
const AUTHORIZE_TTY: &str = "AUTHORIZE\tcap=browser\ttty=/dev/pts/1\n";
const AUTHORIZE_WITHOUT_SCOPE: &str = "AUTHORIZE\tcap=browser\n";
const AUTHORIZED: &str = "OK\tstatus=authorized receipt=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n";
static AUTHORIZE_ENV: Mutex<()> = Mutex::new(());

struct AuthorizeEnvironment {
    socket: Option<OsString>,
    token_file: Option<OsString>,
}

impl AuthorizeEnvironment {
    fn set(socket: &Path, token_file: Option<&Path>) -> Self {
        let environment = Self {
            socket: std::env::var_os("SECRETSD_SOCK"),
            token_file: std::env::var_os("SECRETSD_SESSION_TOKEN_FILE"),
        };
        // Serialized by AUTHORIZE_ENV because process environment is global.
        unsafe {
            std::env::set_var("SECRETSD_SOCK", socket);
            match token_file {
                Some(token_file) => std::env::set_var("SECRETSD_SESSION_TOKEN_FILE", token_file),
                None => std::env::remove_var("SECRETSD_SESSION_TOKEN_FILE"),
            }
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
    fn start(expected_authorize: &'static str, reply: &'static str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secretsd.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let worker = thread::spawn(move || {
            let steps = [
                ("HELLO\tversion=4\n", HELLO_OK),
                (expected_authorize, reply),
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
    let _environment = AuthorizeEnvironment::set(&broker.path, Some(&token_file));
    secretsd::authorize(CAP_BROWSER)
}

fn authorize_with(
    broker: &FakeBroker,
    token: Option<String>,
    tty: Option<String>,
) -> Result<Zeroizing<Vec<u8>>, BrokerError> {
    let _environment = AuthorizeEnvironment::set(&broker.path, None);
    secretsd::authorize_with(CAP_BROWSER, token, tty)
}

#[test]
fn authorize_returns_a_receipt_after_a_broker_approval() {
    let _lock = AUTHORIZE_ENV.lock();
    let broker = FakeBroker::start(AUTHORIZE_TOKEN, AUTHORIZED);

    let result = authorize(&broker);
    broker.finish();
    assert!(result.as_ref().is_ok_and(
        |receipt| receipt.len() == RECEIPT.len() && receipt.iter().all(|byte| *byte == b'a')
    ));
}

#[test]
fn authorize_maps_denied_to_authorization_denied() {
    let _lock = AUTHORIZE_ENV.lock();
    let broker = FakeBroker::start(AUTHORIZE_TOKEN, "ERR\tDENIED\tapproval declined\n");

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
        let broker = FakeBroker::start(AUTHORIZE_TOKEN, response);

        let result = authorize(&broker);
        broker.finish();
        assert!(matches!(result, Err(BrokerError::Protocol(_))));
    }
}

#[cfg_attr(miri, ignore)]
#[test]
fn authorize_sends_a_scope_less_frame() {
    let _lock = AUTHORIZE_ENV.lock();
    let broker = FakeBroker::start(AUTHORIZE_WITHOUT_SCOPE, AUTHORIZED);

    let result = authorize_with(&broker, None, None);
    broker.finish();
    assert!(result.is_ok());
}

#[cfg_attr(miri, ignore)]
#[test]
fn authorize_prefers_a_token_to_a_tty() {
    let _lock = AUTHORIZE_ENV.lock();
    let broker = FakeBroker::start(AUTHORIZE_TOKEN, AUTHORIZED);

    let result = authorize_with(
        &broker,
        Some(TOKEN.to_owned()),
        Some("/dev/pts/1".to_owned()),
    );
    broker.finish();
    assert!(result.is_ok());
}

#[cfg_attr(miri, ignore)]
#[test]
fn authorize_uses_a_tty_without_a_token() {
    let _lock = AUTHORIZE_ENV.lock();
    let broker = FakeBroker::start(AUTHORIZE_TTY, AUTHORIZED);

    let result = authorize_with(&broker, None, Some("/dev/pts/1".to_owned()));
    broker.finish();
    assert!(result.is_ok());
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
    let _environment = AuthorizeEnvironment::set(&path, Some(&token_file));

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
    let _environment = AuthorizeEnvironment::set(&path, Some(&token_file));

    let result = secretsd::authorize(CAP_BROWSER);
    assert!(matches!(result, Err(BrokerError::Protocol(_))));
    assert!(matches!(
        listener.accept(),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
    ));
}
