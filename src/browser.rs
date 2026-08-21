use crate::bridge::limit::ConnectionLimit;
use crate::callback::RELAY_TARGET_PORT;
use crate::config::Config;
use crate::peer::authorized;
use crate::pipe::bidirectional;
use crate::refusal::refuse;
use std::io;
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

/// The maximum idle read or blocked-write interval for a proxied CDP session.
/// The relay sends websocket keepalives every 30s, so this only reaps dead peers.
const PIPE_IDLE_TIMEOUT: Duration = Duration::from_secs(15 * 60);
/// Waiting after a failed accept avoids a tight EMFILE error loop.
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(50);
const GENERIC_REFUSAL: &[u8] = b"REFUSED\n";
const PEER_REFUSAL: &[u8] = b"REFUSED PEER\n";
const BUSY_REFUSAL: &[u8] = b"REFUSED BUSY\n";

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
