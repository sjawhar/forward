//! The devbox side of the browser grant feed: one attached laptop connection,
//! `TOKEN` pushes acknowledged by `OK`, and server-side token minting. The
//! laptop dials us; whoever binds `grant_port` answers, which is this daemon.

use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use base64::Engine as _;
use parking_lot::Mutex;
use zeroize::Zeroizing;

use crate::bridge::limit::ConnectionLimit;
use crate::browser::BrowserError;
use crate::browser::grant::Grants;
use crate::config::Config;
use crate::peer::authorized_sensitive;
use crate::pipe::keepalive;

const ACK_TIMEOUT: Duration = Duration::from_secs(5);
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(50);
const MAX_UNHEALTHY_LISTENER: Duration = Duration::from_secs(30);
const TOKEN_BYTES: usize = 32;
const RENEW: Duration = Duration::from_secs(60);
const MAX_FEED_GREETING: u64 = 128;

/// The one attached feed connection, if any. Grants fail while empty: a token
/// the laptop never acknowledged would be a dead grant sold as live.
#[derive(Clone, Default)]
pub struct FeedSlot {
    inner: Arc<Mutex<Option<TcpStream>>>,
}

impl FeedSlot {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn attach(&self, stream: TcpStream) {
        let mut slot = self.inner.lock();
        if let Some(previous) = slot.take() {
            let _ = previous.shutdown(Shutdown::Both);
        }
        *slot = Some(stream);
    }

    fn is_attached(&self) -> bool {
        self.inner.lock().is_some()
    }

    /// Push one token and wait for the laptop's `OK`. Serialized by the slot
    /// lock: grants are rare, human-gated events.
    pub fn push(&self, token: &[u8], ttl_secs: u64) -> bool {
        let mut slot = self.inner.lock();
        let Some(stream) = slot.as_mut() else {
            return false;
        };
        let delivered = stream
            .set_read_timeout(Some(ACK_TIMEOUT))
            .and_then(|()| stream.set_write_timeout(Some(ACK_TIMEOUT)))
            .and_then(|()| stream.write_all(b"TOKEN "))
            .and_then(|()| stream.write_all(token))
            .and_then(|()| writeln!(stream, " {ttl_secs}"))
            .and_then(|()| {
                let mut ack = [0_u8; 3];
                stream.read_exact(&mut ack)?;
                (ack == *b"OK\n").then_some(()).ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, "feed ack was not OK")
                })
            });
        match delivered {
            Ok(()) => true,
            Err(error) => {
                eprintln!("forward: grant feed push failed: {error}");
                if let Some(dead) = slot.take() {
                    let _ = dead.shutdown(Shutdown::Both);
                }
                false
            }
        }
    }
}

/// Mint a relay token: 32 bytes of `/dev/urandom`, base64 no-pad (43 ASCII
/// bytes). Returned, never logged; its only destinations are the grant table
/// and the feed.
pub(crate) fn mint_token() -> std::io::Result<Vec<u8>> {
    let mut raw = Zeroizing::new([0_u8; TOKEN_BYTES]);
    std::fs::File::open("/dev/urandom")?.read_exact(&mut *raw)?;
    Ok(base64::engine::general_purpose::STANDARD_NO_PAD
        .encode(*raw)
        .into_bytes())
}

/// Serve feed attachments on the configured address.
pub fn spawn_listener(cfg: &Config, slot: FeedSlot, grants: Grants) -> Result<(), BrowserError> {
    if cfg.grant_port == 0 {
        eprintln!("forward: grant feed listener disabled (grant_port = 0)");
        return Ok(());
    }
    let ip = cfg.listen_ip().map_err(|source| BrowserError::Bind {
        address: cfg.listen.clone(),
        source: std::io::Error::other(source),
    })?;
    let listener =
        TcpListener::bind((ip, cfg.grant_port)).map_err(|source| BrowserError::Bind {
            address: format!("{ip}:{}", cfg.grant_port),
            source,
        })?;
    eprintln!("forward: grant feed listener on {ip}:{}", cfg.grant_port);
    spawn_renewer(slot.clone(), grants.clone())?;

    let cfg = cfg.clone();
    thread::Builder::new()
        .name("grant-feed-listener".to_owned())
        .spawn(move || worker(cfg, listener, slot, grants))
        .map(drop)
        .map_err(|source| BrowserError::Spawn { source })
}

fn spawn_renewer(slot: FeedSlot, grants: Grants) -> Result<(), BrowserError> {
    thread::Builder::new()
        .name("grant-feed-renewer".to_owned())
        .spawn(move || renewal_loop(slot, grants))
        .map(drop)
        .map_err(|source| BrowserError::Spawn { source })
}

fn worker(cfg: Config, listener: TcpListener, slot: FeedSlot, grants: Grants) {
    // The workspace builds with panic = "abort", so a panic here raises
    // SIGABRT before any unwinding: the default hook still prints the
    // thread, message, location and backtrace, and exit 134 is non-zero, so
    // a dead channel still cannot masquerade as healthy. A catch_unwind
    // wrapper around this could never observe a panic.
    accept_loop(cfg, listener, slot, grants);
    eprintln!("forward: grant feed listener unavailable for too long; exiting");
    std::process::exit(1);
}

#[derive(Default)]
struct AcceptBudget {
    unhealthy_since: Option<Instant>,
}

impl AcceptBudget {
    fn failed_at(&mut self, now: Instant) -> bool {
        now.duration_since(*self.unhealthy_since.get_or_insert(now)) >= MAX_UNHEALTHY_LISTENER
    }

    fn restored(&mut self) {
        self.unhealthy_since = None;
    }
}

fn accept_loop(cfg: Config, listener: TcpListener, slot: FeedSlot, grants: Grants) {
    let mut failures = AcceptBudget::default();
    let limit = ConnectionLimit::standard();
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                failures.restored();
                let Some(permit) = limit.acquire() else {
                    eprintln!("forward: grant feed refused connection: concurrency limit reached");
                    let _ = stream.shutdown(Shutdown::Both);
                    continue;
                };
                let cfg = cfg.clone();
                let slot = slot.clone();
                let grants = grants.clone();
                drop(thread::spawn(move || {
                    let _permit = permit;
                    attach_if_feed(&cfg, &slot, &grants, stream);
                }));
            }
            Err(error) => {
                eprintln!("forward: grant feed accept failed: {error}");
                if failures.failed_at(Instant::now()) {
                    return;
                }
                thread::sleep(ACCEPT_ERROR_BACKOFF);
            }
        }
    }
}

fn renewal_loop(slot: FeedSlot, grants: Grants) -> ! {
    loop {
        thread::sleep(RENEW);
        if slot.is_attached() {
            push_live(&slot, &grants);
        }
    }
}

/// A connection becomes the feed only after identifying itself with `FEED`:
/// an empty health probe cannot displace a live feed or receive a token.
fn attach_if_feed(cfg: &Config, slot: &FeedSlot, grants: &Grants, stream: TcpStream) {
    let (remote, local) = match (stream.peer_addr(), stream.local_addr()) {
        (Ok(remote), Ok(local)) => (remote, local),
        _ => return,
    };
    if !authorized_sensitive(cfg, remote.ip(), local.ip()) {
        eprintln!("forward: grant feed refused peer {}", remote.ip());
        return;
    }
    if stream.set_read_timeout(Some(ACK_TIMEOUT)).is_err() || keepalive(&stream).is_err() {
        return;
    }
    let Ok(clone) = stream.try_clone() else {
        return;
    };
    let mut reader = BufReader::new(clone);
    let mut line = String::new();
    let Ok(bytes) = reader.by_ref().take(MAX_FEED_GREETING).read_line(&mut line) else {
        return;
    };
    if bytes == 0 || line.trim_end() != "FEED" {
        return;
    }
    eprintln!("forward: grant feed attached from {}", remote.ip());
    slot.attach(stream);
    push_live(slot, grants);
}
fn push_live(slot: &FeedSlot, grants: &Grants) {
    for (token, remaining_secs) in grants.snapshot_live() {
        if !slot.push(token.as_slice(), remaining_secs) {
            return;
        }
    }
}
