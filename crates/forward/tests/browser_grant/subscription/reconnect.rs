use std::time::Duration;

use forward::browser::grant::Grants;

use super::{FakeBroker, Script, assert_revoked, established_pipe, spawn_subscription};

#[test]
fn a_same_instance_reconnect_after_a_subscription_gap_expires_grants_by_epoch() {
    // This fails if reconnect trusts instance= alone: the fake broker retains
    // broker-a while its epoch advances between the dropped socket and HELLO.
    let broker = FakeBroker::start(Script::Gap);
    let grants = Grants::new();
    let subscription = spawn_subscription(grants.clone(), broker.path());
    broker.wait_for_attach();

    let (port, client, task) = established_pipe(grants);
    broker.drop_subscription();
    broker.lock();
    broker.wait_for_reattach();
    assert_revoked(client, task, port, Duration::from_secs(5));
    subscription.shutdown();
}

#[test]
fn a_broker_restart_at_epoch_zero_revokes_the_prior_instance_grants() {
    // This fails if the attach event carries only epoch: a restart from
    // broker-a epoch 0 to broker-b epoch 0 would leave the pipe authorized.
    let broker = FakeBroker::start(Script::Restart);
    let grants = Grants::new();
    let subscription = spawn_subscription(grants.clone(), broker.path());
    broker.wait_for_attach();

    let (port, client, task) = established_pipe(grants);
    broker.drop_subscription();
    broker.wait_for_reattach();
    assert_revoked(client, task, port, Duration::from_secs(2));
    subscription.shutdown();
}

#[test]
fn a_malformed_subscription_event_revokes_without_outage_grace() {
    // This fails if a malformed EPOCH is treated as a transport outage: the
    // five-second test grace leaves this established pipe alive.
    let broker = FakeBroker::start(Script::MalformedEvent);
    let grants = Grants::new();
    let subscription = spawn_subscription(grants.clone(), broker.path());
    broker.wait_for_attach();

    let (port, client, task) = established_pipe(grants);
    broker.drop_subscription();
    broker.wait_for_reattach();
    assert_revoked(client, task, port, Duration::from_secs(2));
    subscription.shutdown();
}

#[test]
fn a_malformed_hello_revokes_without_outage_grace() {
    // This fails if a malformed HELLO is treated as a transport outage: the
    // five-second test grace leaves this established pipe alive.
    let broker = FakeBroker::start(Script::MalformedHello);
    let grants = Grants::new();
    let subscription = spawn_subscription(grants.clone(), broker.path());
    broker.wait_for_attach();

    let (port, client, task) = established_pipe(grants);
    broker.drop_subscription();
    broker.wait_for_reattach();
    assert_revoked(client, task, port, Duration::from_secs(2));
    subscription.shutdown();
}
