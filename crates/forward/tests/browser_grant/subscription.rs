use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use forward::browser::grant::Grants;
use forward::browser::subscription::{SubscriptionTiming, spawn_with_socket};

use super::{assert_refused, current_anchor, grant, proxy, spawn_held_upstream};

enum Command {
    Lock,
    Drop,
}

enum Script {
    Lock,
    Gap,
}

struct FakeBroker {
    _directory: tempfile::TempDir,
    path: PathBuf,
    command: mpsc::Sender<Command>,
    attached: mpsc::Receiver<()>,
    dropped: mpsc::Receiver<()>,
    reattached: mpsc::Receiver<()>,
}

impl FakeBroker {
    fn start(script: Script) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("secretsd.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let (command, commands) = mpsc::channel();
        let (attached_sender, attached) = mpsc::channel();
        let (dropped_sender, dropped) = mpsc::channel();
        let (reattached_sender, reattached) = mpsc::channel();
        thread::spawn(move || match script {
            Script::Lock => {
                let mut subscription = subscribe(&listener, 0);
                attached_sender.send(()).unwrap();
                assert!(matches!(commands.recv().unwrap(), Command::Lock));
                subscription.write_all(b"EPOCH 1\n").unwrap();
            }
            Script::Gap => {
                let subscription = subscribe(&listener, 0);
                attached_sender.send(()).unwrap();
                assert!(matches!(commands.recv().unwrap(), Command::Drop));
                drop(subscription);
                dropped_sender.send(()).unwrap();
                assert!(matches!(commands.recv().unwrap(), Command::Lock));
                let _subscription = subscribe(&listener, 1);
                reattached_sender.send(()).unwrap();
            }
        });
        Self {
            _directory: directory,
            path,
            command,
            attached,
            dropped,
            reattached,
        }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn wait_for_attach(&self) {
        self.attached
            .recv_timeout(Duration::from_secs(5))
            .expect("forward never subscribed");
    }

    fn lock(&self) {
        self.command.send(Command::Lock).unwrap();
    }

    fn drop_subscription(&self) {
        self.command.send(Command::Drop).unwrap();
        self.dropped
            .recv_timeout(Duration::from_secs(5))
            .expect("fake broker did not drop the subscription");
    }

    fn wait_for_reattach(&self) {
        self.reattached
            .recv_timeout(Duration::from_secs(5))
            .expect("forward did not reconnect its subscription");
    }
}

fn subscribe(listener: &UnixListener, epoch: u64) -> UnixStream {
    hello(listener, epoch);
    let (mut stream, _) = listener.accept().unwrap();
    let mut frame = String::new();
    BufReader::new(stream.try_clone().unwrap())
        .read_line(&mut frame)
        .unwrap();
    assert_eq!(frame, "SUBSCRIBE\n");
    stream
        .write_all(format!("EPOCH {epoch}\n").as_bytes())
        .unwrap();
    stream
}

fn hello(listener: &UnixListener, epoch: u64) {
    let (mut stream, _) = listener.accept().unwrap();
    let mut frame = String::new();
    BufReader::new(stream.try_clone().unwrap())
        .read_line(&mut frame)
        .unwrap();
    assert_eq!(frame, "HELLO\tversion=3\n");
    stream
        .write_all(format!("OK\tversion=3 instance=broker-a epoch={epoch}\n").as_bytes())
        .unwrap();
}

fn spawn_subscription(
    grants: Grants,
    path: &Path,
) -> forward::browser::subscription::SubscriptionHandle {
    spawn_with_socket(
        grants,
        path.to_path_buf(),
        SubscriptionTiming {
            reconnect_backoff: Duration::from_millis(5),
            outage_reconnect_backoff: Duration::from_secs(60),
            max_unhealthy: Duration::from_secs(5),
        },
    )
    .unwrap()
}

#[test]
fn lock_epoch_ends_an_established_browser_pipe_and_refuses_its_port() {
    // This fails if EPOCH advances do not call the existing grant expiry path:
    // the pipe stays live and the proxy still admits a second connection.
    let broker = FakeBroker::start(Script::Lock);
    let grants = Grants::new();
    let subscription = spawn_subscription(grants.clone(), broker.path());
    broker.wait_for_attach();

    let (upstream, established, task) = spawn_held_upstream();
    let proxy = proxy::bind(grants.clone(), upstream).unwrap();
    let port = proxy.port();
    grants.insert(
        port,
        grant(
            current_anchor(),
            std::time::Instant::now() + Duration::from_secs(600),
        ),
    );
    proxy.serve();
    let mut client = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    client.write_all(b"hold").unwrap();
    established
        .recv_timeout(Duration::from_secs(5))
        .expect("pipe did not establish");

    broker.lock();

    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut buffer = [0_u8; 16];
    assert!(matches!(client.read(&mut buffer), Ok(0)));
    task.join().unwrap();
    let mut late = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    assert_refused(&mut late, b"REFUSED UNGRANTED\n");
    subscription.shutdown();
}

#[test]
fn a_same_instance_reconnect_after_a_subscription_gap_expires_grants_by_epoch() {
    // This fails if reconnect trusts instance= alone: the fake broker retains
    // broker-a while its epoch advances between the dropped socket and HELLO.
    let broker = FakeBroker::start(Script::Gap);
    let grants = Grants::new();
    let subscription = spawn_subscription(grants.clone(), broker.path());
    broker.wait_for_attach();

    let (upstream, established, task) = spawn_held_upstream();
    let proxy = proxy::bind(grants.clone(), upstream).unwrap();
    let port = proxy.port();
    grants.insert(
        port,
        grant(
            current_anchor(),
            std::time::Instant::now() + Duration::from_secs(600),
        ),
    );
    proxy.serve();
    let mut client = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    client.write_all(b"hold").unwrap();
    established
        .recv_timeout(Duration::from_secs(5))
        .expect("pipe did not establish");

    broker.drop_subscription();
    broker.lock();
    broker.wait_for_reattach();

    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut buffer = [0_u8; 16];
    assert!(matches!(client.read(&mut buffer), Ok(0)));
    task.join().unwrap();
    let mut late = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    assert_refused(&mut late, b"REFUSED UNGRANTED\n");
    subscription.shutdown();
}
