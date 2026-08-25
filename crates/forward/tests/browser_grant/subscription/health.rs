use std::time::Duration;

use forward::browser::grant::Grants;

use super::{FakeBroker, Script, assert_revoked, established_pipe, spawn_subscription};

#[test]
fn a_silent_attached_subscription_severs_live_pipes_at_the_read_deadline() {
    // This fails if the subscription stream has no read timeout: the broker
    // sends one authority event, then stops forever while the pipe stays open.
    let broker = FakeBroker::start(Script::Mute);
    let grants = Grants::new();
    let subscription = spawn_subscription(grants.clone(), broker.path());
    broker.wait_for_attach();

    let (port, client, task) = established_pipe(grants);
    assert_revoked(client, task, port, Duration::from_secs(2));
    subscription.shutdown();
}
#[test]
fn a_capacity_refusal_after_attach_revokes_without_outage_grace() {
    // This fails if a complete capacity frame is treated as an initial connect
    // failure: the live pipe survives the five-second outage grace.
    let broker = FakeBroker::start(Script::Capacity);
    let grants = Grants::new();
    let subscription = spawn_subscription(grants.clone(), broker.path());
    broker.wait_for_attach();

    let (port, client, task) = established_pipe(grants);
    broker.drop_subscription();
    assert_revoked(client, task, port, Duration::from_secs(2));
    subscription.shutdown();
}
