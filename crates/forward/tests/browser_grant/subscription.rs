use std::io::{Read as _, Write as _};
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;
use std::thread;
use std::time::Duration;

use forward::browser::grant::Grants;
use forward::browser::subscription::{SubscriptionTiming, spawn_with_socket};

use super::{assert_refused, current_anchor, grant, insert_grant_as, proxy, spawn_held_upstream};

#[path = "subscription/broker.rs"]
mod broker;
#[path = "subscription/health.rs"]
mod health;
#[path = "subscription/lock_and_close.rs"]
mod lock_and_close;
#[path = "subscription/reconnect.rs"]
mod reconnect;

use broker::{FakeBroker, Script};

/// Long enough that feed silence can never sever pipes in tests whose
/// revocation trigger is data or EOF, even on a starved parallel runner.
const INERT_READ_TIMEOUT: Duration = Duration::from_secs(30);

fn spawn_subscription(
    grants: Grants,
    path: &Path,
    read_timeout: Duration,
) -> forward::browser::subscription::SubscriptionHandle {
    spawn_with_socket(
        grants,
        path.to_path_buf(),
        SubscriptionTiming {
            reconnect_backoff: Duration::from_millis(5),
            outage_reconnect_backoff: Duration::from_secs(60),
            max_unhealthy: Duration::from_secs(5),
            read_timeout,
        },
    )
    .unwrap()
}

/// The authority the subscription will observe from this fake broker: its
/// events carry instance broker-a epoch 0, attributed to the socket's real
/// device and inode. Planting the same identity means feed events revoke a
/// grant only through a genuine epoch or instance change.
fn broker_authority(path: &Path) -> forward::secretsd::BrokerIdentity {
    let metadata = std::fs::metadata(path).unwrap();
    forward::secretsd::BrokerIdentity {
        instance: "broker-a".to_owned(),
        epoch: 0,
        socket: forward::secretsd::SocketIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        },
    }
}

fn established_pipe(
    grants: Grants,
    broker_path: &Path,
) -> (u16, std::net::TcpStream, thread::JoinHandle<()>) {
    let (upstream, established, task) = spawn_held_upstream();
    let proxy = proxy::bind(grants.clone(), upstream).unwrap();
    let port = proxy.port();
    insert_grant_as(
        &grants,
        port,
        broker_authority(broker_path),
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
    (port, client, task)
}

fn assert_revoked(
    mut client: std::net::TcpStream,
    task: thread::JoinHandle<()>,
    port: u16,
    within: Duration,
) {
    client.set_read_timeout(Some(within)).unwrap();
    let mut buffer = [0_u8; 16];
    assert!(matches!(client.read(&mut buffer), Ok(0)));
    task.join().unwrap();
    let mut late = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    assert_refused(&mut late, b"REFUSED UNGRANTED\n");
}
