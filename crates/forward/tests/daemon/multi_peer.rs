use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::Duration;

use socket2::{Domain, Protocol, Socket, Type};

use super::daemon_support::{start, stub, test_port};

const WAIT: Duration = Duration::from_secs(5);

fn source_connect(source: &str, port: u16) -> TcpStream {
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).unwrap();
    socket
        .bind(&format!("{source}:0").parse::<SocketAddr>().unwrap().into())
        .unwrap();
    socket
        .connect_timeout(&SocketAddr::from(([127, 0, 0, 1], port)).into(), WAIT)
        .unwrap();
    let stream: TcpStream = socket.into();
    stream.set_read_timeout(Some(WAIT)).unwrap();
    stream.set_write_timeout(Some(WAIT)).unwrap();
    stream
}

fn request(source: &str, port: u16, line: &str) -> String {
    let mut stream = source_connect(source, port);
    writeln!(stream, "{line}").unwrap();
    let mut reply = String::new();
    BufReader::new(stream).read_line(&mut reply).unwrap();
    reply
}

fn bridge(listener: TcpListener, identity: &'static str) {
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            std::thread::spawn(move || {
                let mut reader = BufReader::new(stream);
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                assert!(line.starts_with("CONNECT "));
                writeln!(reader.get_mut(), "{identity}").unwrap();
            });
        }
    });
}

fn callback_identity(port: u16) -> String {
    let stream = source_connect("127.0.0.1", port);
    let mut reply = String::new();
    BufReader::new(stream).read_line(&mut reply).unwrap();
    reply
}

#[test]
fn callbacks_and_port_holds_keep_the_origin_and_reject_cross_peer_renewals() {
    // Choosing the first peer, or refreshing by port alone, sends the callback
    // to the wrong VM and lets a different VM keep another session's port alive.
    let dir = tempfile::tempdir().unwrap();
    let a = TcpListener::bind("127.0.0.2:0").unwrap();
    let bridge_port = a.local_addr().unwrap().port();
    let b = TcpListener::bind(("127.0.0.3", bridge_port)).unwrap();
    bridge(a, "vm-a");
    bridge(b, "vm-b");
    let (daemon, channel) = start(
        dir.path(),
        &format!(
            "peers = ['127.0.0.2', '127.0.0.3']\nbridge_port = {bridge_port}\nmode = 'auto'\nopener = ['true']\nforward_ttl_secs = 3\n",
        ),
    );
    let callback_a = test_port();
    let callback_b = test_port();
    std::thread::scope(|scope| {
        let a = scope.spawn(|| {
            request(
                "127.0.0.2",
                channel,
                &format!("https://auth.example/?redirect_uri=http://localhost:{callback_a}/a"),
            )
        });
        let b = scope.spawn(|| request("127.0.0.3", channel, &format!("HOLD {callback_b} 3")));
        assert_eq!(a.join().unwrap(), "opened\n");
        assert_eq!(b.join().unwrap(), "held\n");
    });
    assert_eq!(callback_identity(callback_a), "vm-a\n");
    assert_eq!(callback_identity(callback_b), "vm-b\n");
    assert!(
        request("127.0.0.3", channel, &format!("HOLD {callback_a} 600")).starts_with("refused ")
    );
    assert!(
        request("127.0.0.2", channel, &format!("HOLD {callback_b} 600")).starts_with("refused ")
    );
    let colliding_url =
        format!("https://second-vm.example/?redirect_uri=http://localhost:{callback_a}/b");
    assert!(request("127.0.0.3", channel, &colliding_url).starts_with("refused "));
    daemon.wait_for_log("refused URL");
    assert!(
        !daemon
            .log()
            .contains(&format!("URL {colliding_url} decision=open"))
    );
    assert_eq!(callback_identity(callback_a), "vm-a\n");
    assert_eq!(callback_identity(callback_b), "vm-b\n");
    daemon.wait_for_log(&format!("callback port {callback_a} released"));
    daemon.wait_for_log(&format!("callback port {callback_b} released"));
    assert_eq!(
        request("127.0.0.3", channel, &format!("HOLD {callback_a} 10")),
        "held\n"
    );
    assert_eq!(callback_identity(callback_a), "vm-b\n");
}

#[test]
fn peer_preview_is_auto_allowed_only_for_the_originating_vm() {
    // Auto-allowing every configured preview host lets one VM open another's files.
    let dir = tempfile::tempdir().unwrap();
    let notifier = stub(dir.path(), "notifier", "exit 1");
    let (_daemon, channel) = start(
        dir.path(),
        &format!(
            "peers = ['127.0.0.2', '127.0.0.3']\nopener = ['true']\nnotifier = ['{notifier}']\n",
        ),
    );
    for (source, own, other) in [
        ("127.0.0.2", "127.0.0.2", "127.0.0.3"),
        ("127.0.0.3", "127.0.0.3", "127.0.0.2"),
    ] {
        assert_eq!(
            request(source, channel, &format!("http://{own}:12802/tmp/preview")),
            "opened\n"
        );
        assert_eq!(
            request(
                source,
                channel,
                &format!("http://{other}:12802/tmp/private")
            ),
            "notified\n"
        );
        assert_eq!(
            request(source, channel, &format!("http://{own}:9999/")),
            "notified\n"
        );
    }
    for source in ["127.0.0.1", "127.0.0.4"] {
        let mut stranger = source_connect(source, channel);
        let mut byte = [0];
        assert_eq!(
            stranger.read(&mut byte).unwrap(),
            0,
            "read URL bytes before ACL"
        );
    }
}

#[test]
fn multi_peer_urls_never_open_with_unserved_callback_ports() {
    let dir = tempfile::tempdir().unwrap();
    let (daemon, channel) = start(
        dir.path(),
        "peers = ['127.0.0.2', '127.0.0.3']\nmode = 'auto'\nopener = ['true']\n",
    );
    let occupied = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = occupied.local_addr().unwrap().port();
    assert!(
        request(
            "127.0.0.2",
            channel,
            &format!("http://localhost:{port}/occupied")
        )
        .starts_with("refused ")
    );
    let mut excessive = "https://auth.example/?".to_owned();
    for _ in 0..5 {
        excessive.push_str(&format!("redirect_uri=http://localhost:{}/&", test_port()));
    }
    assert!(request("127.0.0.2", channel, &excessive).starts_with("refused "));
    daemon.wait_for_log("refused URL");
    assert!(!daemon.log().contains("decision=open"));
}
