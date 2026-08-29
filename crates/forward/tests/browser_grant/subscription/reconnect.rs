use std::time::Duration;

use forward::browser::grant::Grants;

use super::{
    FakeBroker, INERT_READ_TIMEOUT, Script, assert_revoked, established_pipe, spawn_subscription,
};

#[test]
fn a_same_instance_reconnect_after_a_subscription_gap_expires_grants_by_epoch() {
    // End-to-end reconnect shape: the drop itself revokes (no grace after
    // attach), and the epoch-1 reattach must leave the port refused rather
    // than resurrect authority for the old epoch's grants.
    let broker = FakeBroker::start(Script::Gap);
    let grants = Grants::new();
    let subscription = spawn_subscription(grants.clone(), broker.path(), INERT_READ_TIMEOUT);
    broker.wait_for_attach();

    let (port, client, task) = established_pipe(grants, broker.path());
    broker.drop_subscription();
    broker.lock();
    broker.wait_for_reattach();
    assert_revoked(client, task, port, Duration::from_secs(5));
    subscription.shutdown();
}

#[test]
fn a_broker_restart_at_epoch_zero_revokes_the_prior_instance_grants() {
    // End-to-end restart shape: the drop itself revokes (no grace after
    // attach), and the broker-b epoch-0 reattach must leave the port refused
    // rather than treat the fresh instance as the old authority.
    let broker = FakeBroker::start(Script::Restart);
    let grants = Grants::new();
    let subscription = spawn_subscription(grants.clone(), broker.path(), INERT_READ_TIMEOUT);
    broker.wait_for_attach();

    let (port, client, task) = established_pipe(grants, broker.path());
    broker.drop_subscription();
    broker.wait_for_reattach();
    assert_revoked(client, task, port, Duration::from_secs(2));
    subscription.shutdown();
}

#[test]
fn a_malformed_subscription_event_revokes_without_outage_grace() {
    // This fails if a malformed EPOCH frame on the live feed is treated as a
    // transport outage: the broker holds its stream open after the frame, so
    // only the malformed frame itself can sever the pipe.
    let broker = FakeBroker::start(Script::MalformedEvent);
    let grants = Grants::new();
    let subscription = spawn_subscription(grants.clone(), broker.path(), INERT_READ_TIMEOUT);
    broker.wait_for_attach();

    let (port, client, task) = established_pipe(grants, broker.path());
    broker.corrupt();
    assert_revoked(client, task, port, Duration::from_secs(2));
    drop(broker);
    subscription.shutdown();
}

#[test]
fn a_malformed_hello_revokes_without_outage_grace() {
    // End-to-end reconnect shape: the drop itself revokes (no grace after
    // attach), and the malformed HELLO at reattach must leave the port
    // refused rather than restore authority.
    let broker = FakeBroker::start(Script::MalformedHello);
    let grants = Grants::new();
    let subscription = spawn_subscription(grants.clone(), broker.path(), INERT_READ_TIMEOUT);
    broker.wait_for_attach();

    let (port, client, task) = established_pipe(grants, broker.path());
    broker.drop_subscription();
    broker.wait_for_reattach();
    assert_revoked(client, task, port, Duration::from_secs(2));
    subscription.shutdown();
}
