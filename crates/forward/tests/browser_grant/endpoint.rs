//! A grant wired the way a real one is: an endpoint relay in this process's
//! network namespace, a `forward serve` control loop on the far end of the
//! grant's control channel, and the registry entry that ties them together.

use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::thread;
use std::time::{Duration, Instant};

use forward::browser::grant::Grants;
use forward::browser::relay::{self, Resolver};
use forward::browser::request::serve_control;
use forward::secretsd::BrokerIdentity;

use super::{current_anchor, grant, insert_grant_as};

pub(super) struct Endpoint {
    pub(super) id: u64,
    pub(super) port: u16,
}

impl Endpoint {
    pub(super) fn connect(&self) -> TcpStream {
        TcpStream::connect(("127.0.0.1", self.port)).unwrap()
    }

    /// Wait for the endpoint to stop accepting, which is the only way a grant
    /// ending reaches a caller that never connected.
    pub(super) fn assert_retired(&self, within: Duration) {
        let deadline = Instant::now() + within;
        while TcpStream::connect(("127.0.0.1", self.port)).is_ok() {
            assert!(
                Instant::now() < deadline,
                "the endpoint outlived its grant on port {}",
                self.port
            );
            thread::sleep(Duration::from_millis(10));
        }
    }
}

pub(super) fn start(
    grants: &Grants,
    upstream: SocketAddr,
    deadline: Instant,
    resolver: Resolver,
) -> Endpoint {
    start_as(grants, super::authority(), upstream, deadline, resolver)
}

pub(super) fn start_as(
    grants: &Grants,
    authority: BrokerIdentity,
    upstream: SocketAddr,
    deadline: Instant,
    resolver: Resolver,
) -> Endpoint {
    // Bound before either half is spawned, so a client may connect the instant
    // this returns: the backlog exists from `bind`, not from `accept`.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (server, caller) = UnixStream::pair().unwrap();
    let id = insert_grant_as(
        grants,
        authority,
        grant(current_anchor(), deadline, port),
        &server,
    );
    let control_grants = grants.clone();
    thread::spawn(move || serve_control(control_grants, id, upstream, server));
    let anchor = current_anchor();
    thread::spawn(move || relay::serve(listener, caller, anchor, resolver));
    Endpoint { id, port }
}

/// A control loop with no endpoint in front of it, for the cases a relay
/// cannot produce on demand: a grant that ended between the hand-over and the
/// registry lookup, and a relay that sends the wrong kind of descriptor.
pub(super) struct Channel {
    pub(super) caller: UnixStream,
}

pub(super) fn control_only(grants: &Grants, id: u64, upstream: SocketAddr) -> Channel {
    let (server, caller) = UnixStream::pair().unwrap();
    let grants = grants.clone();
    thread::spawn(move || serve_control(grants, id, upstream, server));
    Channel { caller }
}

impl Channel {
    /// Hand over a connection exactly as the relay's accept loop does.
    pub(super) fn hand_over(&self, socket: &impl std::os::fd::AsRawFd) {
        relay::hand_over(&self.caller, socket).unwrap();
    }
}

/// A loopback client whose accepted server side is what gets handed over.
pub(super) fn accepted_pair() -> (TcpStream, TcpStream, TcpListener) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (accepted, _) = listener.accept().unwrap();
    (client, accepted, listener)
}
