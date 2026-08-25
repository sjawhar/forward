//! What remains here is the loopback-TCP pid resolution, which is forward's
//! own: it reads this process's socket table. The ancestry walk, anchor
//! derivation, and session labelling now live in `crates/containment` and are
//! tested there against an injected process table, which also lets them run
//! under miri.

use std::net::{TcpListener, TcpStream};

use super::*;

#[test]
fn a_live_loopback_connection_resolves_to_this_process() {
    // Given: a loopback connection this test process owns both ends of.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let local = match listener.local_addr().unwrap() {
        std::net::SocketAddr::V4(address) => address,
        other => panic!("expected IPv4, got {other}"),
    };
    let client = TcpStream::connect(local).unwrap();
    let (_server, _) = listener.accept().unwrap();
    let peer = match client.local_addr().unwrap() {
        std::net::SocketAddr::V4(address) => address,
        other => panic!("expected IPv4, got {other}"),
    };

    // When/Then: the client socket resolves to this process.
    assert_eq!(pid_for_connection(peer, local), Some(std::process::id()));
}
