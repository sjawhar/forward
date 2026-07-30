use super::relay::relay;
use super::{AtomicBool, Leases, Ordering};
use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

/// How long an idle accept loop waits before re-checking its stop flag.
const ACCEPT_POLL: Duration = Duration::from_millis(20);

pub(super) fn bind_polling(ip: IpAddr, port: u16) -> std::io::Result<TcpListener> {
    let listener = TcpListener::bind((ip, port))?;
    listener.set_nonblocking(true)?;
    Ok(listener)
}

pub(super) fn spawn_accept_loop(
    listener: TcpListener,
    bridge: SocketAddr,
    port: u16,
    leases: Leases,
    stop: Arc<AtomicBool>,
) -> bool {
    // The listener drops when the loop returns, and that drop is the entire
    // release mechanism: nothing has to connect to the port to free it.
    let release_leases = leases.clone();
    let release_stop = Arc::clone(&stop);
    let result = thread::Builder::new()
        .name(format!("callback-{port}"))
        .spawn(move || {
            let accept_loop = AcceptLoop {
                bridge,
                port,
                leases,
                stop,
            };
            accept_loop.run(|| listener.accept());
            drop(listener);
            accept_loop.release();
        });
    if let Err(error) = result {
        eprintln!("forward: failed to start callback listener on {port}: {error}");
        if release_leases.release(port, &release_stop) {
            eprintln!("forward: callback port {port} released");
        }
        return false;
    }
    true
}

struct AcceptLoop {
    bridge: SocketAddr,
    port: u16,
    leases: Leases,
    stop: Arc<AtomicBool>,
}

impl AcceptLoop {
    fn run<A>(&self, mut accept: A)
    where
        A: FnMut() -> std::io::Result<(TcpStream, SocketAddr)>,
    {
        while !self.stop.load(Ordering::Relaxed) {
            match accept() {
                // Once accept returns a stream, its TCP connection is established. Serve it
                // even if expiry won this race so the browser never sees a silent empty reply.
                Ok((browser, _)) => {
                    let bridge = self.bridge;
                    let port = self.port;
                    drop(thread::spawn(move || relay(bridge, browser, port)));
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => thread::sleep(ACCEPT_POLL),
                Err(error) => {
                    eprintln!("forward: callback accept failed on {}: {error}", self.port);
                    self.stop.store(true, Ordering::Relaxed);
                    return;
                }
            }
        }
    }

    fn release(&self) {
        if self.leases.release(self.port, &self.stop) {
            eprintln!("forward: callback port {} released", self.port);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use std::io::{Read, Write};
    use std::time::Instant;

    const TEST_TIMEOUT: Duration = Duration::from_secs(1);

    fn cfg(bridge: SocketAddr) -> Config {
        let mut cfg = Config::default_values_for_test();
        cfg.bridge_port = bridge.port();
        cfg.peer = bridge.ip().to_string();
        cfg
    }

    fn spawn_echo_bridge() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        drop(thread::spawn(move || {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let _ = stream.set_read_timeout(Some(TEST_TIMEOUT));
            let _ = stream.set_write_timeout(Some(TEST_TIMEOUT));
            let mut byte = [0_u8; 1];
            while stream.read(&mut byte).ok() == Some(1) && byte[0] != b'\n' {}
            let mut payload = [0_u8; 4];
            if stream.read_exact(&mut payload).is_ok() {
                let _ = stream.write_all(&payload);
            }
        }));
        address
    }

    fn connect(port: u16) -> TcpStream {
        let address = SocketAddr::from(([127, 0, 0, 1], port));
        let stream = TcpStream::connect_timeout(&address, TEST_TIMEOUT).unwrap();
        stream.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
        stream.set_write_timeout(Some(TEST_TIMEOUT)).unwrap();
        stream
    }

    fn waits_for_listener_to_close(port: u16) -> bool {
        let deadline = Instant::now() + TEST_TIMEOUT;
        while Instant::now() < deadline {
            if TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], port))).is_ok() {
                return true;
            }
            thread::sleep(Duration::from_millis(10));
        }
        false
    }

    #[test]
    fn rebinds_after_an_accept_error_retires_its_lease() {
        // Given: a real callback port whose accept loop fatally exits.
        let listener = bind_polling("127.0.0.1".parse().unwrap(), 0).unwrap();
        let port = listener.local_addr().unwrap().port();
        let leases = Leases::new();
        let stop = Arc::new(AtomicBool::new(false));
        leases.insert(port, Duration::from_secs(30), Arc::clone(&stop), 1);
        let bridge = spawn_echo_bridge();
        let loop_ = AcceptLoop {
            bridge,
            port,
            leases: leases.clone(),
            stop,
        };

        // When: the owned listener reports a non-retryable accept error and drops.
        loop_.run(|| Err(std::io::Error::other("injected accept failure")));
        drop(listener);
        loop_.release();
        let rebound = super::super::request_on(&cfg(bridge), &leases, port).unwrap();
        let mut browser = connect(rebound);
        browser.write_all(b"ping").unwrap();

        // Then: the request rebinds a real listener instead of refreshing a corpse.
        let mut echoed = [0_u8; 4];
        browser.read_exact(&mut echoed).unwrap();
        assert_eq!(echoed, *b"ping");
    }

    #[test]
    fn overwriting_a_lease_stops_the_listener_it_replaces() {
        // Given: a real listener backed by the first lease flag.
        let listener = bind_polling("127.0.0.1".parse().unwrap(), 0).unwrap();
        let port = listener.local_addr().unwrap().port();
        let leases = Leases::new();
        let old_stop = Arc::new(AtomicBool::new(false));
        leases.insert(port, Duration::from_secs(30), Arc::clone(&old_stop), 1);
        assert!(spawn_accept_loop(
            listener,
            SocketAddr::from(([127, 0, 0, 1], 0)),
            port,
            leases.clone(),
            old_stop,
        ));

        // When: another listener replaces the port's logical lease.
        leases.insert(
            port,
            Duration::from_secs(30),
            Arc::new(AtomicBool::new(false)),
            1,
        );

        // Then: the replaced listener observes its stop flag and releases its socket.
        assert!(
            waits_for_listener_to_close(port),
            "replaced listener kept port {port} bound"
        );
    }

    #[test]
    fn accepted_connection_is_relayed_when_expiry_wins_the_race() {
        // Given: a browser TCP connection already queued for acceptance.
        let listener = bind_polling("127.0.0.1".parse().unwrap(), 0).unwrap();
        let port = listener.local_addr().unwrap().port();
        let bridge = spawn_echo_bridge();
        let leases = Leases::new();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_after_accept = Arc::clone(&stop);
        let loop_ = AcceptLoop {
            bridge,
            port,
            leases,
            stop,
        };
        let mut browser = connect(port);

        // When: expiry is recorded immediately after accept returns its stream.
        loop_.run(|| {
            let accepted = listener.accept();
            stop_after_accept.store(true, Ordering::Relaxed);
            accepted
        });
        browser.write_all(b"ping").unwrap();

        // Then: the established connection is relayed, never silently dropped.
        let mut echoed = [0_u8; 4];
        browser.read_exact(&mut echoed).unwrap();
        assert_eq!(echoed, *b"ping");
    }
}
