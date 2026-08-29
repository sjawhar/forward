use std::time::Duration;

use forward::browser::grant::Grants;

use super::{
    FakeBroker, INERT_READ_TIMEOUT, Script, assert_revoked, established_pipe, spawn_subscription,
};

#[test]
fn lock_epoch_ends_an_established_browser_pipe_and_refuses_its_port() {
    // This fails if EPOCH advances do not call the existing grant expiry path:
    // the broker holds its stream open after the event, so only the epoch
    // advance itself can sever the pipe or refuse the second connection.
    let broker = FakeBroker::start(Script::Lock);
    let grants = Grants::new();
    let subscription = spawn_subscription(grants.clone(), broker.path(), INERT_READ_TIMEOUT);
    broker.wait_for_attach();

    let (port, client, task) = established_pipe(grants, broker.path());
    broker.lock();
    assert_revoked(client, task, port, Duration::from_secs(5));
    drop(broker);
    subscription.shutdown();
}
#[test]
fn a_closed_attached_subscription_severs_live_pipes_without_outage_grace() {
    // This fails if EOF takes the initial-connect outage path: that five-second
    // grace leaves a pipe usable after a broker dropped this subscriber.
    let broker = FakeBroker::start(Script::Close);
    let grants = Grants::new();
    let subscription = spawn_subscription(grants.clone(), broker.path(), INERT_READ_TIMEOUT);
    broker.wait_for_attach();

    let (port, client, task) = established_pipe(grants, broker.path());
    broker.drop_subscription();
    assert_revoked(client, task, port, Duration::from_secs(2));
    subscription.shutdown();
}
