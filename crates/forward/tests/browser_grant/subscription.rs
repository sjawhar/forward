use std::io::{Read as _, Write as _};
use std::path::Path;
use std::thread;
use std::time::Duration;

use forward::browser::grant::Grants;
use forward::browser::subscription::{SubscriptionTiming, spawn_with_socket};

use super::{assert_refused, current_anchor, grant, insert_grant, proxy, spawn_held_upstream};

#[path = "subscription/broker.rs"]
mod broker;
#[path = "subscription/health.rs"]
mod health;
#[path = "subscription/lock_and_close.rs"]
mod lock_and_close;
#[path = "subscription/reconnect.rs"]
mod reconnect;

use broker::{FakeBroker, Script};

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
            read_timeout: Duration::from_millis(250),
        },
    )
    .unwrap()
}

fn established_pipe(grants: Grants) -> (u16, std::net::TcpStream, thread::JoinHandle<()>) {
    let (upstream, established, task) = spawn_held_upstream();
    let proxy = proxy::bind(grants.clone(), upstream).unwrap();
    let port = proxy.port();
    insert_grant(
        &grants,
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
