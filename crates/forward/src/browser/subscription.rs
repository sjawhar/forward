//! Broker authority-event subscription for the devbox grant registry.

use std::io::{BufRead as _, BufReader, Read as _};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, TryRecvError};
use std::thread;
use std::time::{Duration, Instant};

use super::grant::Grants;

const MAX_EPOCH_LINE: u64 = 64;

/// Capped retry and fail-closed timing for the authority subscription.
#[doc(hidden)]
#[derive(Clone, Copy)]
pub struct SubscriptionTiming {
    pub reconnect_backoff: Duration,
    pub outage_reconnect_backoff: Duration,
    pub max_unhealthy: Duration,
    pub read_timeout: Duration,
}

impl SubscriptionTiming {
    const STANDARD: Self = Self {
        reconnect_backoff: Duration::from_secs(5),
        outage_reconnect_backoff: Duration::from_secs(60),
        max_unhealthy: Duration::from_secs(30),
        read_timeout: Duration::from_secs(30),
    };
}

/// A test subscription that can be stopped after its fake broker closes.
#[doc(hidden)]
pub struct SubscriptionHandle {
    stop: mpsc::Sender<()>,
    worker: thread::JoinHandle<()>,
}

impl SubscriptionHandle {
    pub fn shutdown(self) {
        let _ = self.stop.send(());
        let _ = self.worker.join();
    }
}

#[derive(Default)]
struct ReconnectBudget {
    unhealthy_since: Option<Instant>,
}

impl ReconnectBudget {
    fn exhausted(&mut self, now: Instant, maximum: Duration) -> bool {
        now.duration_since(*self.unhealthy_since.get_or_insert(now)) >= maximum
    }
}

/// Spawn the broker subscription for the lifetime of `forward serve`.
pub fn spawn(grants: Grants) -> std::io::Result<()> {
    spawn_worker(
        grants,
        crate::secretsd::socket_path(),
        SubscriptionTiming::STANDARD,
        None,
        false,
    )
    .map(drop)
}

/// Test seam for a fake broker socket and short reconnect cadence.
#[doc(hidden)]
pub fn spawn_with_socket(
    grants: Grants,
    socket: PathBuf,
    timing: SubscriptionTiming,
) -> std::io::Result<SubscriptionHandle> {
    let (stop, stopped) = mpsc::channel();
    let worker = spawn_worker(grants, socket, timing, Some(stopped), true)?;
    Ok(SubscriptionHandle { stop, worker })
}

fn spawn_worker(
    grants: Grants,
    socket: PathBuf,
    timing: SubscriptionTiming,
    stop: Option<mpsc::Receiver<()>>,
    test_broker: bool,
) -> std::io::Result<thread::JoinHandle<()>> {
    thread::Builder::new()
        .name("broker-subscription".to_owned())
        .spawn(move || worker(grants, socket, timing, stop, test_broker))
}

fn worker(
    grants: Grants,
    socket: PathBuf,
    timing: SubscriptionTiming,
    stop: Option<mpsc::Receiver<()>>,
    test_broker: bool,
) {
    let mut budget = ReconnectBudget::default();
    let mut in_outage = false;
    loop {
        if stopped(&stop) {
            return;
        }
        let failure = match run_once(&grants, &socket, timing.read_timeout, test_broker) {
            Ok(()) => return,
            Err(failure) => failure,
        };
        if stopped(&stop) {
            return;
        }
        match failure {
            SubscriptionFailure::Attached(error) => {
                if matches!(error, crate::secretsd::BrokerError::SubscriberCapacity) {
                    eprintln!(
                        "forward: broker authority subscription refused: subscriber capacity reached"
                    );
                } else {
                    eprintln!("forward: broker authority subscription lost after attach: {error}");
                }
                // A closed, unreadable, or rejected subscription cannot prove
                // that its prior epoch remains current. Spec §6.3(b) therefore
                // permits no outage grace after attachment.
                grants.invalidate_authority();
                budget = ReconnectBudget::default();
                in_outage = false;
                thread::sleep(timing.reconnect_backoff);
            }
            SubscriptionFailure::Initial(error)
                if !matches!(error, crate::secretsd::BrokerError::Connect { .. }) =>
            {
                eprintln!("forward: broker authority subscription failed: {error}");
                grants.invalidate_authority();
                budget = ReconnectBudget::default();
                in_outage = false;
                thread::sleep(timing.reconnect_backoff);
            }
            SubscriptionFailure::Initial(error) => {
                eprintln!("forward: broker authority subscription failed: {error}");
                let now = Instant::now();
                if budget.exhausted(now, timing.max_unhealthy) {
                    grants.invalidate_authority();
                    if !in_outage {
                        eprintln!(
                            "forward: broker authority subscription grace expired; grants revoked and retrying every {}s",
                            timing.outage_reconnect_backoff.as_secs()
                        );
                    }
                    in_outage = true;
                    thread::sleep(timing.outage_reconnect_backoff);
                } else {
                    in_outage = false;
                    thread::sleep(timing.reconnect_backoff);
                }
            }
        }
    }
}

fn stopped(stop: &Option<mpsc::Receiver<()>>) -> bool {
    stop.as_ref()
        .is_some_and(|receiver| !matches!(receiver.try_recv(), Err(TryRecvError::Empty)))
}

enum SubscriptionFailure {
    Initial(crate::secretsd::BrokerError),
    Attached(crate::secretsd::BrokerError),
}

fn run_once(
    grants: &Grants,
    socket: &Path,
    read_timeout: Duration,
    test_broker: bool,
) -> Result<(), SubscriptionFailure> {
    let identity = if test_broker {
        crate::secretsd::broker_identity_for_test(socket)
    } else {
        crate::secretsd::broker_identity(socket)
    }
    .map_err(SubscriptionFailure::Initial)?;
    grants.observe_authority(identity);
    let stream = if test_broker {
        crate::secretsd::subscribe_for_test(socket, read_timeout)
    } else {
        crate::secretsd::subscribe(socket, read_timeout)
    }
    .map_err(SubscriptionFailure::Initial)?;
    let mut reader = BufReader::new(stream);
    loop {
        let mut line = String::new();
        let bytes = reader
            .by_ref()
            .take(MAX_EPOCH_LINE)
            .read_line(&mut line)
            .map_err(|source| {
                SubscriptionFailure::Attached(crate::secretsd::BrokerError::Connect {
                    path: socket.to_path_buf(),
                    source,
                })
            })?;
        if bytes == 0 {
            return Err(SubscriptionFailure::Attached(
                crate::secretsd::BrokerError::SubscriptionClosed,
            ));
        }
        if line == proto::SUBSCRIBER_CAPACITY_RESPONSE {
            return Err(SubscriptionFailure::Attached(
                crate::secretsd::BrokerError::SubscriberCapacity,
            ));
        }
        let (instance, epoch) = proto::parse_authority_event(&line).ok_or_else(|| {
            SubscriptionFailure::Attached(crate::secretsd::BrokerError::Protocol(
                "malformed broker subscription event".to_owned(),
            ))
        })?;
        grants.observe_authority(crate::secretsd::BrokerIdentity {
            instance: instance.to_owned(),
            epoch,
        });
    }
}
