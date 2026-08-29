use std::io::{BufRead as _, BufReader, Write as _};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

enum Command {
    Trigger,
    Drop,
    Mute,
}

pub(super) enum Script {
    Lock,
    Close,
    Mute,
    Capacity,
    Gap,
    Restart,
    MalformedEvent,
    MalformedHello,
}

pub(super) struct FakeBroker {
    _directory: tempfile::TempDir,
    path: PathBuf,
    command: mpsc::Sender<Command>,
    attached: mpsc::Receiver<()>,
    dropped: mpsc::Receiver<()>,
    reattached: mpsc::Receiver<()>,
}

impl FakeBroker {
    pub(super) fn start(script: Script) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("secretsd.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let (command, commands) = mpsc::channel();
        let (attached_sender, attached) = mpsc::channel();
        let (dropped_sender, dropped) = mpsc::channel();
        let (reattached_sender, reattached) = mpsc::channel();
        thread::spawn(move || match script {
            Script::Lock => {
                let mut subscription = subscribe(&listener, "broker-a", 0);
                attached_sender.send(()).unwrap();
                assert!(matches!(commands.recv().unwrap(), Command::Trigger));
                write_event(&mut subscription, "broker-a", 1).unwrap();
                // Hold the stream open: revocation must come from the epoch
                // advance, never from a trailing EOF.
                let _ = commands.recv();
            }
            Script::Close => {
                let subscription = subscribe(&listener, "broker-a", 0);
                attached_sender.send(()).unwrap();
                assert!(matches!(commands.recv().unwrap(), Command::Drop));
                drop(subscription);
                dropped_sender.send(()).unwrap();
            }
            Script::Mute => {
                let mut subscription = subscribe(&listener, "broker-a", 0);
                attached_sender.send(()).unwrap();
                // Keepalives hold the feed healthy until the test commands
                // silence, so the read deadline measures from that moment
                // instead of racing the pipe establishment.
                while matches!(commands.try_recv(), Err(mpsc::TryRecvError::Empty)) {
                    if write_event(&mut subscription, "broker-a", 0).is_err() {
                        break;
                    }
                    thread::sleep(Duration::from_millis(10));
                }
                let _ = commands.recv();
            }
            Script::Capacity => {
                let mut subscription = subscribe(&listener, "broker-a", 0);
                attached_sender.send(()).unwrap();
                assert!(matches!(commands.recv().unwrap(), Command::Drop));
                subscription
                    .write_all(proto::SUBSCRIBER_CAPACITY_RESPONSE.as_bytes())
                    .unwrap();
                dropped_sender.send(()).unwrap();
            }
            Script::Gap => {
                let subscription = subscribe(&listener, "broker-a", 0);
                attached_sender.send(()).unwrap();
                assert!(matches!(commands.recv().unwrap(), Command::Drop));
                drop(subscription);
                dropped_sender.send(()).unwrap();
                assert!(matches!(commands.recv().unwrap(), Command::Trigger));
                let _subscription = subscribe(&listener, "broker-a", 1);
                reattached_sender.send(()).unwrap();
            }
            Script::Restart => {
                let subscription = subscribe(&listener, "broker-a", 0);
                attached_sender.send(()).unwrap();
                assert!(matches!(commands.recv().unwrap(), Command::Drop));
                drop(subscription);
                dropped_sender.send(()).unwrap();
                hello(&listener, "broker-a", 0);
                let (mut subscription, _) = listener.accept().unwrap();
                let mut frame = String::new();
                BufReader::new(subscription.try_clone().unwrap())
                    .read_line(&mut frame)
                    .unwrap();
                assert_eq!(frame, "SUBSCRIBE\n");
                write_event(&mut subscription, "broker-b", 0).unwrap();
                reattached_sender.send(()).unwrap();
            }
            Script::MalformedEvent => {
                let mut subscription = subscribe(&listener, "broker-a", 0);
                attached_sender.send(()).unwrap();
                assert!(matches!(commands.recv().unwrap(), Command::Trigger));
                subscription.write_all(b"EPOCH broken\n").unwrap();
                // Hold the stream open: revocation must come from the
                // malformed frame, never from a trailing EOF.
                let _ = commands.recv();
            }
            Script::MalformedHello => {
                let subscription = subscribe(&listener, "broker-a", 0);
                attached_sender.send(()).unwrap();
                assert!(matches!(commands.recv().unwrap(), Command::Drop));
                drop(subscription);
                dropped_sender.send(()).unwrap();
                malformed_hello(&listener);
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

    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    pub(super) fn wait_for_attach(&self) {
        self.attached
            .recv_timeout(Duration::from_secs(5))
            .expect("forward never subscribed");
    }

    pub(super) fn lock(&self) {
        self.command.send(Command::Trigger).unwrap();
    }

    pub(super) fn corrupt(&self) {
        self.command.send(Command::Trigger).unwrap();
    }

    pub(super) fn mute(&self) {
        self.command.send(Command::Mute).unwrap();
    }

    pub(super) fn drop_subscription(&self) {
        self.command.send(Command::Drop).unwrap();
        self.dropped
            .recv_timeout(Duration::from_secs(5))
            .expect("fake broker did not drop the subscription");
    }

    pub(super) fn wait_for_reattach(&self) {
        self.reattached
            .recv_timeout(Duration::from_secs(5))
            .expect("forward did not reconnect its subscription");
    }
}

fn subscribe(listener: &UnixListener, instance: &str, epoch: u64) -> UnixStream {
    hello(listener, instance, epoch);
    let (mut stream, _) = listener.accept().unwrap();
    let mut frame = String::new();
    BufReader::new(stream.try_clone().unwrap())
        .read_line(&mut frame)
        .unwrap();
    assert_eq!(frame, "SUBSCRIBE\n");
    write_event(&mut stream, instance, epoch).unwrap();
    stream
}

fn hello(listener: &UnixListener, instance: &str, epoch: u64) {
    let (mut stream, _) = listener.accept().unwrap();
    let mut frame = String::new();
    BufReader::new(stream.try_clone().unwrap())
        .read_line(&mut frame)
        .unwrap();
    assert_eq!(frame, "HELLO\tversion=3\n");
    stream
        .write_all(format!("OK\tversion=3 instance={instance} epoch={epoch}\n").as_bytes())
        .unwrap();
}

fn write_event(stream: &mut UnixStream, instance: &str, epoch: u64) -> std::io::Result<()> {
    stream.write_all(format!("EPOCH {epoch} instance={instance}\n").as_bytes())
}

fn malformed_hello(listener: &UnixListener) {
    let (mut stream, _) = listener.accept().unwrap();
    let mut frame = String::new();
    BufReader::new(stream.try_clone().unwrap())
        .read_line(&mut frame)
        .unwrap();
    assert_eq!(frame, "HELLO\tversion=3\n");
    stream.write_all(b"OK\tversion=3 epoch=0\n").unwrap();
}
