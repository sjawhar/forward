pub mod grant;
pub mod init;
pub mod peer;
pub mod proxy;
pub mod request;

mod token;

use crate::bridge::limit::ConnectionLimit;
use crate::callback::RELAY_TARGET_PORT;
use crate::config::Config;
use crate::peer::authorized;
use crate::pipe::bidirectional;
use crate::refusal::refuse;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

/// The maximum idle read or blocked-write interval for a proxied CDP session.
/// The relay sends websocket keepalives every 30s, so this only reaps dead peers.
const PIPE_IDLE_TIMEOUT: Duration = Duration::from_secs(15 * 60);
/// Waiting after a failed accept avoids a tight EMFILE error loop.
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(50);
const GENERIC_REFUSAL: &[u8] = b"REFUSED\n";
const PEER_REFUSAL: &[u8] = b"REFUSED PEER\n";
const BUSY_REFUSAL: &[u8] = b"REFUSED BUSY\n";
const TOKEN_FILE_REFUSAL: &[u8] = b"REFUSED TOKEN FILE\n";
const TOKEN_UPSTREAM_HEALTHY_REFUSAL: &[u8] = b"REFUSED TOKEN UPSTREAM 200\n";
const TOKEN_UPSTREAM_DOWN_REFUSAL: &[u8] = b"REFUSED TOKEN UPSTREAM 503\n";
/// How long a connection may take to send its request line.
const REQUEST_LINE_READ_TIMEOUT: Duration = Duration::from_secs(10);
/// `RELAY ` plus a base64 32-byte token is 50 bytes; 128 is generous.
const MAX_REQUEST_LINE: usize = 128;

#[derive(Debug, thiserror::Error)]
pub enum BrowserError {
    #[error("forward: failed to bind browser relay channel on {address}: {source}")]
    Bind {
        address: String,
        #[source]
        source: std::io::Error,
    },
    #[error("forward: failed to start browser relay accept loop: {source}")]
    Spawn {
        #[source]
        source: std::io::Error,
    },
}

/// Start the browser relay channel on the configured address.
pub fn spawn(cfg: &Config) -> Result<(), BrowserError> {
    if cfg.relay_port == 0 {
        eprintln!("forward: browser relay channel disabled (relay_port = 0)");
        return Ok(());
    }

    let address = format!("{}:{}", cfg.listen, cfg.relay_port);
    cfg.validate().map_err(|source| BrowserError::Bind {
        address: address.clone(),
        source: io::Error::other(source),
    })?;
    let ip = cfg.listen_ip().map_err(|source| BrowserError::Bind {
        address,
        source: io::Error::other(source),
    })?;
    let listener =
        TcpListener::bind((ip, cfg.relay_port)).map_err(|source| BrowserError::Bind {
            address: format!("{ip}:{}", cfg.relay_port),
            source,
        })?;
    eprintln!("forward: browser relay channel on {ip}:{}", cfg.relay_port);
    spawn_with_listener(
        cfg.clone(),
        listener,
        SocketAddr::from(([127, 0, 0, 1], RELAY_TARGET_PORT)),
    )
}

/// Test seam: run the browser relay on a listener the caller already bound.
#[doc(hidden)]
pub fn spawn_with_listener(
    cfg: Config,
    listener: TcpListener,
    upstream: SocketAddr,
) -> Result<(), BrowserError> {
    thread::Builder::new()
        .name("browser-relay".to_owned())
        .spawn(move || {
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                accept_loop(cfg, listener, upstream)
            }));
            match outcome {
                Err(_) => eprintln!("forward: browser relay accept loop panicked; exiting"),
                Ok(()) => eprintln!("forward: browser relay accept loop ended; exiting"),
            }
            std::process::exit(1);
        })
        .map(drop)
        .map_err(|source| BrowserError::Spawn { source })
}

fn accept_loop(cfg: Config, listener: TcpListener, upstream: SocketAddr) {
    let limit = ConnectionLimit::standard();
    for connection in listener.incoming() {
        match connection {
            Ok(mut stream) => {
                let Some(permit) = limit.acquire() else {
                    eprintln!(
                        "forward: browser relay refused connection: concurrency limit reached"
                    );
                    refuse(&mut stream, BUSY_REFUSAL);
                    continue;
                };
                let cfg = cfg.clone();
                drop(thread::spawn(move || {
                    let _permit = permit;
                    handle(&cfg, upstream, stream);
                }));
            }
            Err(error) => {
                eprintln!("forward: browser relay accept failed: {error}");
                thread::sleep(ACCEPT_ERROR_BACKOFF);
            }
        }
    }
}

fn handle(cfg: &Config, upstream: SocketAddr, mut stream: TcpStream) {
    let remote = match stream.peer_addr() {
        Ok(remote) => remote,
        Err(_) => {
            refuse(&mut stream, GENERIC_REFUSAL);
            return;
        }
    };
    handle_from(cfg, upstream, remote.ip(), stream);
}

/// Test seam: handle a connection whose peer address is supplied by the caller.
#[doc(hidden)]
pub fn handle_from(cfg: &Config, upstream: SocketAddr, remote: IpAddr, mut stream: TcpStream) {
    if !authorized(cfg, remote) {
        eprintln!("forward: browser relay refused peer {remote}");
        refuse(&mut stream, PEER_REFUSAL);
        return;
    }

    let Some(expected) = cfg.relay_token_path().and_then(|path| token::load(&path)) else {
        eprintln!("forward: browser relay local token is unavailable");
        refuse(&mut stream, TOKEN_FILE_REFUSAL);
        return;
    };
    let presented = read_relay_token(&mut stream, REQUEST_LINE_READ_TIMEOUT);
    let accepted = presented
        .as_deref()
        .is_some_and(|presented| token::constant_time_eq(&expected, presented));
    if !accepted {
        eprintln!("forward: browser relay refused an untokened connection from {remote}");
        refuse(&mut stream, token_refusal(upstream));
        return;
    }

    let upstream_stream = match TcpStream::connect(upstream) {
        Ok(stream) => stream,
        Err(error) => {
            eprintln!("forward: browser relay could not reach {upstream}: {error}");
            refuse(&mut stream, GENERIC_REFUSAL);
            return;
        }
    };
    if let Err(error) = configure_pipe_timeouts(&stream, &upstream_stream, PIPE_IDLE_TIMEOUT) {
        eprintln!("forward: browser relay could not set pipe timeout for {remote}: {error}");
        return;
    }
    if let Err(error) = bidirectional(stream, upstream_stream) {
        eprintln!("forward: browser relay session for {remote} ended: {error}");
    }
}

/// Report only whether the extension's status endpoint is healthy to an
/// already-authorized peer whose token did not match.
fn token_refusal(upstream: SocketAddr) -> &'static [u8] {
    let Ok(mut stream) = TcpStream::connect_timeout(&upstream, REQUEST_LINE_READ_TIMEOUT) else {
        return TOKEN_UPSTREAM_DOWN_REFUSAL;
    };
    if stream
        .set_read_timeout(Some(REQUEST_LINE_READ_TIMEOUT))
        .and_then(|()| stream.set_write_timeout(Some(REQUEST_LINE_READ_TIMEOUT)))
        .and_then(|()| stream.write_all(b"GET /json/version HTTP/1.0\r\nHost: localhost\r\n\r\n"))
        .is_err()
    {
        return TOKEN_UPSTREAM_DOWN_REFUSAL;
    }

    let mut status = Vec::new();
    if BufReader::new(stream)
        .read_until(b'\n', &mut status)
        .is_ok_and(|_| status.windows(4).any(|window| window == b" 200"))
    {
        TOKEN_UPSTREAM_HEALTHY_REFUSAL
    } else {
        TOKEN_UPSTREAM_DOWN_REFUSAL
    }
}
/// Read `RELAY <token>\n` one byte at a time from the piped stream.
fn read_relay_token(stream: &mut TcpStream, timeout: Duration) -> Option<Vec<u8>> {
    let deadline = Instant::now().checked_add(timeout)?;
    let mut line = Vec::with_capacity(MAX_REQUEST_LINE);
    let mut byte = [0_u8; 1];

    while line.len() < MAX_REQUEST_LINE {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() || stream.set_read_timeout(Some(remaining)).is_err() {
            return None;
        }
        match stream.read(&mut byte) {
            Ok(1) => {}
            Ok(_) => return None,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return None,
        }
        let [received] = byte;
        if received == b'\n' {
            return line.strip_prefix(b"RELAY ".as_slice()).map(<[u8]>::to_vec);
        }
        line.push(received);
    }
    None
}

fn configure_pipe_timeouts(
    left: &TcpStream,
    right: &TcpStream,
    timeout: Duration,
) -> io::Result<()> {
    left.set_read_timeout(Some(timeout))?;
    left.set_write_timeout(Some(timeout))?;
    right.set_read_timeout(Some(timeout))?;
    right.set_write_timeout(Some(timeout))
}
