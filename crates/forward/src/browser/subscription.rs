//! Broker authority-event subscription for the devbox grant registry.

use std::io::{BufRead as _, BufReader, Read as _};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, TryRecvError};
use std::thread;
use std::time::{Duration, Instant};

use super::grant::Grants;

const MAX_EPOCH_LINE: u64 = 64;
const MIN_USEFUL_SUBSCRIPTION_LIFETIME: Duration = Duration::from_secs(30);

/// Capped retry and fail-closed timing for the authority subscription.
#[doc(hidden)]
#[derive(Clone, Copy)]
pub struct SubscriptionTiming {
    pub reconnect_backoff: Duration,
    pub outage_reconnect_backoff: Duration,
    pub max_unhealthy: Duration,
}

impl SubscriptionTiming {
    const STANDARD: Self = Self {
        reconnect_backoff: Duration::from_secs(5),
        outage_reconnect_backoff: Duration::from_secs(60),
        max_unhealthy: Duration::from_secs(30),
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

    fn restored_if_long_lived(&mut self, connected_at: Instant) {
        if connected_at.elapsed() >= MIN_USEFUL_SUBSCRIPTION_LIFETIME {
            self.unhealthy_since = None;
        }
    }
}

/// Spawn the broker subscription for the lifetime of `forward serve`.
pub fn spawn(grants: Grants) -> std::io::Result<()> {
    spawn_worker(
        grants,
        crate::secretsd::socket_path(),
        SubscriptionTiming::STANDARD,
        None,
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
    let worker = spawn_worker(grants, socket, timing, Some(stopped))?;
    Ok(SubscriptionHandle { stop, worker })
}

fn spawn_worker(
    grants: Grants,
    socket: PathBuf,
    timing: SubscriptionTiming,
    stop: Option<mpsc::Receiver<()>>,
) -> std::io::Result<thread::JoinHandle<()>> {
    thread::Builder::new()
        .name("broker-subscription".to_owned())
        .spawn(move || worker(grants, socket, timing, stop))
}

fn worker(
    grants: Grants,
    socket: PathBuf,
    timing: SubscriptionTiming,
    stop: Option<mpsc::Receiver<()>>,
) {
    let mut budget = ReconnectBudget::default();
    let mut in_outage = false;
    loop {
        if stopped(&stop) {
            return;
        }
        let connected_at = Instant::now();
        let result = run_once(&grants, &socket);
        budget.restored_if_long_lived(connected_at);
        if stopped(&stop) {
            return;
        }
        match &result {
            Ok(()) => eprintln!("forward: broker authority subscription closed"),
            Err(error) => eprintln!("forward: broker authority subscription failed: {error}"),
        }
        if matches!(&result, Err(error) if !matches!(error, crate::secretsd::BrokerError::Connect { .. }))
        {
            // A syntactically bad reply has no bounded continuity argument:
            // revoke before the next reconnect attempt rather than using the
            // transport-outage grace.
            grants.invalidate_authority();
            budget = ReconnectBudget::default();
            in_outage = false;
            thread::sleep(timing.reconnect_backoff);
            continue;
        }
        let now = Instant::now();
        let exhausted = budget.exhausted(now, timing.max_unhealthy);
        if exhausted {
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

fn stopped(stop: &Option<mpsc::Receiver<()>>) -> bool {
    stop.as_ref()
        .is_some_and(|receiver| !matches!(receiver.try_recv(), Err(TryRecvError::Empty)))
}

fn run_once(grants: &Grants, socket: &Path) -> Result<(), crate::secretsd::BrokerError> {
    let identity = crate::secretsd::broker_identity(socket)?;
    grants.observe_authority(identity);
    let stream = crate::secretsd::subscribe(socket)?;
    let mut reader = BufReader::new(stream);
    loop {
        let mut line = String::new();
        let bytes = reader
            .by_ref()
            .take(MAX_EPOCH_LINE)
            .read_line(&mut line)
            .map_err(|source| crate::secretsd::BrokerError::Connect {
                path: socket.to_path_buf(),
                source,
            })?;
        if bytes == 0 {
            return Ok(());
        }
        let identity = parse_identity(&line).ok_or_else(|| {
            crate::secretsd::BrokerError::Protocol("malformed broker subscription event".to_owned())
        })?;
        grants.observe_authority(identity);
    }
}

fn parse_identity(line: &str) -> Option<crate::secretsd::BrokerIdentity> {
    let (epoch, instance) = line
        .strip_suffix('\n')?
        .strip_prefix("EPOCH ")?
        .split_once(" instance=")?;
    let epoch = epoch.parse().ok()?;
    (!instance.is_empty()
        && instance.is_ascii()
        && !instance
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace()))
    .then(|| crate::secretsd::BrokerIdentity {
        instance: instance.to_owned(),
        epoch,
    })
}
