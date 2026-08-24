use super::Armed;
use super::limit::ConnectionLimit;
use super::port_policy::denied_port;
use crate::config::Config;
use crate::peer::authorized;
use crate::pipe::bidirectional;
use crate::refusal::refuse;
use std::io::Read;
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

/// How long a connection may take to send its request line.
const REQUEST_LINE_READ_TIMEOUT: Duration = Duration::from_secs(10);
/// The maximum idle read or blocked-write interval for an authenticated callback.
const PIPE_IDLE_TIMEOUT: Duration = Duration::from_secs(15 * 60);
/// Longest request line accepted, newline excluded. `CONNECT 65535` is 13 bytes.
const MAX_REQUEST_LINE: usize = 64;
/// Waiting after a failed accept avoids a tight EMFILE error loop.
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(50);
const GENERIC_REFUSAL: &[u8] = b"REFUSED\n";
const PEER_REFUSAL: &[u8] = b"REFUSED PEER\n";
const BUSY_REFUSAL: &[u8] = b"REFUSED BUSY\n";
const DENIED_PORT_REFUSAL: &[u8] = b"REFUSED DENIED\n";
const UNARMED_PORT_REFUSAL: &[u8] = b"REFUSED UNARMED\n";

#[derive(Debug, thiserror::Error)]
pub enum BridgeError {
    #[error("forward: could not bind callback bridge on {address}: {source}")]
    Bind {
        address: String,
        #[source]
        source: std::io::Error,
    },
}

/// Serve the callback bridge on the configured address. Blocks.
pub fn serve(cfg: Config, armed: Armed) -> Result<(), BridgeError> {
    cfg.validate().map_err(|source| BridgeError::Bind {
        address: cfg.listen.clone(),
        source: std::io::Error::other(source),
    })?;
    let ip = cfg.listen_ip().map_err(|source| BridgeError::Bind {
        address: cfg.listen.clone(),
        source: std::io::Error::other(source),
    })?;
    let listener =
        TcpListener::bind((ip, cfg.bridge_port)).map_err(|source| BridgeError::Bind {
            address: format!("{ip}:{}", cfg.bridge_port),
            source,
        })?;
    eprintln!("forward: callback bridge on {ip}:{}", cfg.bridge_port);
    accept_loop(cfg, armed, listener);
    Ok(())
}

/// Test seam: run the accept loop on a listener the caller already bound.
#[doc(hidden)]
pub fn spawn_with_listener(cfg: Config, armed: Armed, listener: TcpListener) {
    drop(thread::spawn(move || accept_loop(cfg, armed, listener)));
}

fn accept_loop(cfg: Config, armed: Armed, listener: TcpListener) {
    let Ok(listener_port) = listener.local_addr().map(|address| address.port()) else {
        eprintln!("forward: bridge could not determine its listener port");
        return;
    };
    let limit = ConnectionLimit::standard();
    for connection in listener.incoming() {
        match connection {
            Ok(mut stream) => {
                let Some(permit) = limit.acquire() else {
                    eprintln!("forward: bridge refused connection: concurrency limit reached");
                    refuse(&mut stream, BUSY_REFUSAL);
                    continue;
                };
                let cfg = cfg.clone();
                let armed = armed.clone();
                drop(thread::spawn(move || {
                    let _permit = permit;
                    handle(&cfg, &armed, listener_port, stream);
                }));
            }
            Err(error) => {
                eprintln!("forward: bridge accept failed: {error}");
                thread::sleep(ACCEPT_ERROR_BACKOFF);
            }
        }
    }
}

fn handle(cfg: &Config, armed: &Armed, listener_port: u16, mut stream: TcpStream) {
    let remote = match stream.peer_addr() {
        Ok(remote) => remote,
        Err(_) => {
            refuse(&mut stream, GENERIC_REFUSAL);
            return;
        }
    };
    if !authorized(cfg, remote.ip()) {
        eprintln!("forward: bridge refused peer {}", remote.ip());
        refuse(&mut stream, PEER_REFUSAL);
        return;
    }
    let Some(port) = read_port(&mut stream) else {
        eprintln!("forward: bridge refused a malformed request line");
        refuse(&mut stream, GENERIC_REFUSAL);
        return;
    };
    if denied_port(cfg, listener_port, port) {
        eprintln!("forward: bridge refused denylisted port {port}");
        refuse(&mut stream, DENIED_PORT_REFUSAL);
        return;
    }
    if !armed.is_armed(port) {
        eprintln!("forward: bridge refused unarmed port {port}");
        refuse(&mut stream, UNARMED_PORT_REFUSAL);
        return;
    }

    match TcpStream::connect(("127.0.0.1", port)) {
        Ok(upstream) => {
            if let Err(error) = stream.set_read_timeout(Some(PIPE_IDLE_TIMEOUT)) {
                eprintln!("forward: bridge could not set client read timeout: {error}");
                refuse(&mut stream, GENERIC_REFUSAL);
                return;
            }
            if let Err(error) = stream.set_write_timeout(Some(PIPE_IDLE_TIMEOUT)) {
                eprintln!("forward: bridge could not set client write timeout: {error}");
                refuse(&mut stream, GENERIC_REFUSAL);
                return;
            }
            if let Err(error) = upstream.set_read_timeout(Some(PIPE_IDLE_TIMEOUT)) {
                eprintln!("forward: bridge could not set upstream read timeout: {error}");
                refuse(&mut stream, GENERIC_REFUSAL);
                return;
            }
            if let Err(error) = upstream.set_write_timeout(Some(PIPE_IDLE_TIMEOUT)) {
                eprintln!("forward: bridge could not set upstream write timeout: {error}");
                refuse(&mut stream, GENERIC_REFUSAL);
                return;
            }
            if let Err(error) = bidirectional(stream, upstream) {
                eprintln!("forward: bridge relay for port {port} ended: {error}");
            }
        }
        Err(error) => {
            eprintln!("forward: bridge could not reach 127.0.0.1:{port}: {error}");
            refuse(&mut stream, GENERIC_REFUSAL);
        }
    }
}

/// Read `CONNECT <port>\n` one byte at a time from the piped stream.
///
/// Bounded, byte-at-a-time reading is structural: a buffered reader can consume
/// callback bytes past the newline and discard them on drop, hanging or corrupting
/// the callback. Read this exact stream, never a clone of the stream being piped.
fn read_port(stream: &mut TcpStream) -> Option<u16> {
    read_port_with_timeout(stream, REQUEST_LINE_READ_TIMEOUT)
}

fn read_port_with_timeout(stream: &mut TcpStream, timeout: Duration) -> Option<u16> {
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
            let request = std::str::from_utf8(&line).ok()?.strip_prefix("CONNECT ")?;
            if request.is_empty() || !request.bytes().all(|value| value.is_ascii_digit()) {
                return None;
            }
            return request.parse().ok();
        }
        line.push(received);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn request_line_deadline_is_cumulative() {
        // Given: one byte is ready now and the rest arrives after the whole deadline.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(address).unwrap();
        let (mut server, _) = listener.accept().unwrap();
        client.write_all(b"C").unwrap();
        let writer = thread::spawn(move || {
            thread::sleep(Duration::from_millis(12));
            let _ = client.write_all(b"O");
            thread::sleep(Duration::from_millis(12));
            let _ = client.write_all(b"NNECT 8400\n");
        });

        // When: the request read has one deadline rather than one deadline per byte.
        let port = read_port_with_timeout(&mut server, Duration::from_millis(20));

        // Then: the drip is refused as a whole.
        assert_eq!(port, None);
        writer.join().unwrap();
    }

    #[test]
    fn request_line_parses_zero_for_the_policy_to_refuse() {
        // Given: the doctor's configuration-independent probe request.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(address).unwrap();
        let (mut server, _) = listener.accept().unwrap();
        client.write_all(b"CONNECT 0\n").unwrap();

        // When/Then: parsing retains zero; the policy layer rejects it before
        // any dial rather than treating it as a malformed protocol line.
        assert_eq!(read_port(&mut server), Some(0));
    }
}
