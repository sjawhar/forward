use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::net::{SocketAddr, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use super::super::BrowserError;
use super::{RelayTokens, clamp_wire_ttl};
use crate::config::Config;
use crate::pipe::keepalive;

const RECONNECT_BACKOFF: Duration = Duration::from_secs(5);
/// Past the outage budget the peer is down, not blipping; keep dialing, but at
/// a cadence that will not spam the journal for the length of a real outage.
const OUTAGE_RECONNECT_BACKOFF: Duration = Duration::from_secs(60);
pub(super) const MAX_UNHEALTHY_FEED: Duration = Duration::from_secs(30);
const MAX_FEED_LINE: u64 = 128;
/// A feed that stays attached for a full outage window is useful even without
/// a grant. Shorter greeting-and-close loops must not erase the outage budget.
const MIN_USEFUL_FEED_LIFETIME: Duration = MAX_UNHEALTHY_FEED;

#[derive(Default)]
pub(super) struct ReconnectBudget {
    unhealthy_since: Option<Instant>,
}

impl ReconnectBudget {
    pub(super) fn failed_at(&mut self, now: Instant) -> bool {
        now.duration_since(*self.unhealthy_since.get_or_insert(now)) >= MAX_UNHEALTHY_FEED
    }

    pub(super) fn restored(&mut self) {
        self.unhealthy_since = None;
    }

    fn restored_if_long_lived(&mut self, connected_at: Instant) {
        if connected_at.elapsed() >= MIN_USEFUL_FEED_LIFETIME {
            self.restored();
        }
    }
}

/// Dial the devbox feed listener for the life of the process.
pub fn spawn_client(cfg: &Config, tokens: RelayTokens) -> Result<(), BrowserError> {
    let Ok(Some(peer)) = cfg.peer_ip() else {
        eprintln!("forward: grant feed disabled: no peer configured");
        return Ok(());
    };
    if cfg.grant_port == 0 {
        eprintln!("forward: grant feed disabled (grant_port = 0)");
        return Ok(());
    }
    let address = SocketAddr::new(peer, cfg.grant_port);
    client_spawn_result(
        thread::Builder::new()
            .name("grant-feed".to_owned())
            .spawn(move || worker(address, tokens)),
    )
}

pub(super) fn client_spawn_result(
    result: std::io::Result<thread::JoinHandle<()>>,
) -> Result<(), BrowserError> {
    result
        .map(drop)
        .map_err(|source| BrowserError::Spawn { source })
}

fn worker(address: SocketAddr, tokens: RelayTokens) {
    client_loop(address, &tokens)
}

fn client_loop(address: SocketAddr, tokens: &RelayTokens) -> ! {
    let mut failures = ReconnectBudget::default();
    let mut in_outage = false;
    loop {
        match run_once(address, tokens, &mut failures) {
            Ok(()) => eprintln!("forward: grant feed to {address} closed"),
            Err(error) => eprintln!("forward: grant feed to {address} failed: {error}"),
        }
        tokens.set_connected(false);
        thread::sleep(next_backoff(&mut failures, &mut in_outage, Instant::now()));
    }
}

/// An exhausted outage budget slows the dial cadence instead of exiting: the
/// feed is one channel of the laptop daemon, and an unreachable devbox must
/// not take the URL opener and browser relay down with it.
fn next_backoff(failures: &mut ReconnectBudget, in_outage: &mut bool, now: Instant) -> Duration {
    if failures.failed_at(now) {
        if !*in_outage {
            eprintln!(
                "forward: grant feed outage budget exhausted; dialing every {}s until the peer returns",
                OUTAGE_RECONNECT_BACKOFF.as_secs()
            );
        }
        *in_outage = true;
        OUTAGE_RECONNECT_BACKOFF
    } else {
        *in_outage = false;
        RECONNECT_BACKOFF
    }
}

fn run_once(
    address: SocketAddr,
    tokens: &RelayTokens,
    failures: &mut ReconnectBudget,
) -> std::io::Result<()> {
    let mut stream = TcpStream::connect_timeout(&address, crate::pcsc::CONNECT_TIMEOUT)?;
    keepalive(&stream)?;
    stream.write_all(b"FEED\n")?;
    let connected_at = Instant::now();
    tokens.set_connected(true);
    let mut reader = BufReader::new(stream.try_clone()?);
    loop {
        let mut line = Zeroizing::new(String::new());
        let bytes = match reader.by_ref().take(MAX_FEED_LINE).read_line(&mut line) {
            Ok(bytes) => bytes,
            Err(error) => {
                failures.restored_if_long_lived(connected_at);
                return Err(error);
            }
        };
        if bytes == 0 {
            failures.restored_if_long_lived(connected_at);
            return Ok(());
        }
        let Some((token, ttl)) = parse_token_line(line.trim_end_matches(['\r', '\n'])) else {
            failures.restored_if_long_lived(connected_at);
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "malformed feed line",
            ));
        };
        tokens.insert(token, Duration::from_secs(ttl));
        failures.restored();
        stream.write_all(b"OK\n")?;
    }
}

fn parse_token_line(line: &str) -> Option<(Zeroizing<Vec<u8>>, u64)> {
    let rest = line.strip_prefix("TOKEN ")?;
    let (token, ttl) = rest.split_once(' ')?;
    if token.is_empty() || token.contains(' ') {
        return None;
    }
    let ttl: u64 = ttl.parse().ok()?;
    (ttl != 0).then(|| {
        (
            Zeroizing::new(token.as_bytes().to_vec()),
            clamp_wire_ttl(Duration::from_secs(ttl)).as_secs(),
        )
    })
}

#[cfg(test)]
mod tests;
