use super::super::BrowserError;
use super::RelayTokens;
use crate::config::Config;
use crate::pipe::keepalive;
use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::net::{SocketAddr, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

const RECONNECT_BACKOFF: Duration = Duration::from_secs(5);
pub(super) const MAX_UNHEALTHY_FEED: Duration = Duration::from_secs(30);
const MAX_FEED_LINE: u64 = 128;

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
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client_loop(address, &tokens)
    }));
    match outcome {
        Err(_) => eprintln!("forward: grant feed worker panicked; exiting"),
        Ok(()) => eprintln!("forward: grant feed reconnect budget exhausted; exiting"),
    }
    std::process::exit(1);
}

fn client_loop(address: SocketAddr, tokens: &RelayTokens) {
    let mut failures = ReconnectBudget::default();
    loop {
        match run_once(address, tokens, &mut failures) {
            Ok(()) => eprintln!("forward: grant feed to {address} closed"),
            Err(error) => eprintln!("forward: grant feed to {address} failed: {error}"),
        }
        tokens.set_connected(false);
        if failures.failed_at(Instant::now()) {
            return;
        }
        thread::sleep(RECONNECT_BACKOFF);
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
    failures.restored();
    tokens.set_connected(true);
    let mut reader = BufReader::new(stream.try_clone()?);
    loop {
        let mut line = String::new();
        let bytes = reader.by_ref().take(MAX_FEED_LINE).read_line(&mut line)?;
        if bytes == 0 {
            return Ok(());
        }
        let Some((token, ttl)) = parse_token_line(line.trim_end_matches(['\r', '\n'])) else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "malformed feed line",
            ));
        };
        tokens.insert(token, Duration::from_secs(ttl));
        stream.write_all(b"OK\n")?;
    }
}

fn parse_token_line(line: &str) -> Option<(Vec<u8>, u64)> {
    let rest = line.strip_prefix("TOKEN ")?;
    let (token, ttl) = rest.split_once(' ')?;
    if token.is_empty() || token.contains(' ') {
        return None;
    }
    let ttl: u64 = ttl.parse().ok()?;
    (ttl != 0).then(|| (token.as_bytes().to_vec(), ttl))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn a_successful_feed_handshake_resets_a_prior_outage() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut greeting = String::new();
            BufReader::new(stream).read_line(&mut greeting).unwrap();
            assert_eq!(greeting, "FEED\n");
        });
        let tokens = RelayTokens::new();
        let now = Instant::now();
        let mut failures = ReconnectBudget {
            unhealthy_since: Some(now - MAX_UNHEALTHY_FEED),
        };

        run_once(address, &tokens, &mut failures).unwrap();
        server.join().unwrap();

        assert!(!failures.failed_at(Instant::now()));
    }
}
