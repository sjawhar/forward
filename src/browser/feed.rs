//! The laptop side of the browser grant feed.
//!
//! The laptop dials the devbox and holds one persistent connection. Each
//! `TOKEN <token> <ttl>` line registers a relay token until its deadline.

use crate::config::Config;
use crate::pipe::keepalive;
use parking_lot::Mutex;
use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use zeroize::Zeroize as _;

/// More live grants than this is not a workflow; evict the oldest.
const MAX_LIVE_TOKENS: usize = 64;
const RECONNECT_BACKOFF: Duration = Duration::from_secs(5);
/// `TOKEN ` + a 43-character token + ` ` + TTL digits is well under this.
const MAX_FEED_LINE: u64 = 128;

struct TokenEntry {
    token: Vec<u8>,
    deadline: Instant,
}

impl Drop for TokenEntry {
    fn drop(&mut self) {
        self.token.zeroize();
    }
}

#[derive(Default)]
struct Inner {
    entries: Vec<TokenEntry>,
    connected: bool,
}

/// Live relay tokens shared by the feed client and relay connection handlers.
#[derive(Clone, Default)]
pub struct RelayTokens {
    inner: Arc<Mutex<Inner>>,
}

impl RelayTokens {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&self, token: Vec<u8>, ttl: Duration) {
        let mut inner = self.inner.lock();
        let now = Instant::now();
        inner.entries.retain(|entry| entry.deadline > now);
        if inner.entries.len() == MAX_LIVE_TOKENS {
            inner.entries.remove(0);
        }
        inner.entries.push(TokenEntry {
            token,
            deadline: now + ttl,
        });
    }

    /// Compare against every live token without early exit. Expiry is checked
    /// before comparison, while a token's byte position remains indistinguishable.
    pub fn accepts(&self, presented: &[u8]) -> bool {
        let mut inner = self.inner.lock();
        let now = Instant::now();
        inner.entries.retain(|entry| entry.deadline > now);
        inner.entries.iter().fold(false, |accepted, entry| {
            accepted | constant_time_eq(&entry.token, presented)
        })
    }

    pub fn set_connected(&self, connected: bool) {
        self.inner.lock().connected = connected;
    }

    pub fn is_connected(&self) -> bool {
        self.inner.lock().connected
    }
}

/// Compare without an early exit. Length is not secret: a token of the wrong
/// size is already wrong.
pub(crate) fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0_u8;
    for (left_byte, right_byte) in left.iter().zip(right) {
        difference |= left_byte ^ right_byte;
    }
    difference == 0
}

/// Dial the devbox feed listener for the life of the process.
pub fn spawn_client(cfg: &Config, tokens: RelayTokens) {
    let Ok(Some(peer)) = cfg.peer_ip() else {
        eprintln!("forward: grant feed disabled: no peer configured");
        return;
    };
    if cfg.grant_port == 0 {
        eprintln!("forward: grant feed disabled (grant_port = 0)");
        return;
    }
    let address = SocketAddr::new(peer, cfg.grant_port);
    drop(
        thread::Builder::new()
            .name("grant-feed".to_owned())
            .spawn(move || {
                loop {
                    match run_once(address, &tokens) {
                        Ok(()) => eprintln!("forward: grant feed to {address} closed"),
                        Err(error) => eprintln!("forward: grant feed to {address} failed: {error}"),
                    }
                    tokens.set_connected(false);
                    thread::sleep(RECONNECT_BACKOFF);
                }
            }),
    );
}

fn run_once(address: SocketAddr, tokens: &RelayTokens) -> std::io::Result<()> {
    let mut stream = TcpStream::connect_timeout(&address, crate::pcsc::CONNECT_TIMEOUT)?;
    keepalive(&stream)?;
    stream.write_all(b"FEED\n")?;
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
