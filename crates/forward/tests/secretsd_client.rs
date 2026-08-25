use std::io::{BufRead as _, BufReader, Write as _};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::thread::{self, JoinHandle};

#[path = "secretsd_client/framing.rs"]
mod framing;
#[path = "secretsd_client/identity.rs"]
mod identity;

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

/// The real `(device, inode)` of a socket path, which is what forward records.
fn socket_identity_of(path: &std::path::Path) -> forward::secretsd::SocketIdentity {
    use std::os::linux::fs::MetadataExt as _;
    let metadata = std::fs::metadata(path).expect("socket exists");
    forward::secretsd::SocketIdentity {
        device: metadata.st_dev(),
        inode: metadata.st_ino(),
    }
}
