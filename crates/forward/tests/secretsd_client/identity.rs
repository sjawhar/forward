use forward::secretsd::{self, BrokerIdentity, SocketIdentity};

use super::{FakeBroker, hello};

#[test]
fn broker_identity_reads_the_fresh_hello_extension() {
    let broker = FakeBroker::start(vec![hello()]);
    let expected_socket = super::socket_identity_of(&broker.path);

    let identity = secretsd::broker_identity(&broker.path);
    broker.finish();

    // The socket identity comes from the bound path, not from the reply.
    assert_eq!(
        identity.ok(),
        Some(BrokerIdentity {
            instance: "abc123".to_owned(),
            epoch: 0,
            socket: expected_socket,
        })
    );
}

#[test]
fn an_impostor_replaying_a_valid_hello_yields_a_different_authority() {
    // A same-uid impostor cannot be refused at connect: it owns the socket it
    // bound, its uid is ours, and the broker sets PR_SET_DUMPABLE=0 so its
    // executable is unreadable to a sibling process anyway. What it cannot
    // reuse is the socket the real broker is bound to -- rebinding a path
    // necessarily creates a new inode. So an impostor that replays the real
    // instance and epoch verbatim still yields a different identity, which
    // `Grants::observe_authority` treats as an authority change and revokes on.
    //
    // This fails if `socket` leaves BrokerIdentity: the two identities below
    // would compare equal and a rebind would be invisible.
    let impostor = FakeBroker::start(vec![hello()]);

    let observed = secretsd::broker_identity(&impostor.path).expect("a valid HELLO");
    impostor.finish();

    let same_fields_rebound_socket = BrokerIdentity {
        instance: observed.instance.clone(),
        epoch: observed.epoch,
        socket: SocketIdentity {
            device: observed.socket.device,
            inode: observed.socket.inode.saturating_add(1),
        },
    };
    assert_ne!(observed, same_fields_rebound_socket);
}
