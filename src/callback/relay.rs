use std::io::{self, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use super::PIPE_IDLE_TIMEOUT;
use crate::pipe::bidirectional;

pub(super) fn relay(bridge: SocketAddr, browser: TcpStream, port: u16) {
    let mut upstream = match TcpStream::connect(bridge) {
        Ok(upstream) => upstream,
        Err(error) => {
            eprintln!("forward: cannot reach callback bridge at {bridge}: {error}");
            return;
        }
    };
    if let Err(error) = writeln!(upstream, "CONNECT {port}") {
        eprintln!("forward: cannot ask the bridge for callback port {port}: {error}");
        return;
    }
    if let Err(error) = configure_pipe_timeouts(&browser, &upstream, PIPE_IDLE_TIMEOUT) {
        eprintln!("forward: cannot set callback pipe timeout for port {port}: {error}");
        return;
    }
    if let Err(error) = bidirectional(browser, upstream) {
        eprintln!("forward: callback relay for port {port} ended: {error}");
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

#[cfg(test)]
mod tests {
    use std::net::{Shutdown, TcpListener};
    use std::sync::mpsc;
    use std::thread;

    use socket2::Socket;

    use super::*;

    fn tcp_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let client = TcpStream::connect(address).unwrap();
        let (server, _) = listener.accept().unwrap();
        (server, client)
    }

    fn restrict_send_buffer(stream: TcpStream) -> TcpStream {
        let socket = Socket::from(stream);
        socket.set_send_buffer_size(1_024).unwrap();
        socket.into()
    }

    #[test]
    fn write_timeouts_release_a_relay_when_both_peers_stop_reading() {
        // Given: peers that each keep sending but never read their relay output.
        let (left, left_peer) = tcp_pair();
        let (right, right_peer) = tcp_pair();
        let left = restrict_send_buffer(left);
        let right = restrict_send_buffer(right);
        configure_pipe_timeouts(&left, &right, Duration::from_millis(20)).unwrap();
        let (done, outcome) = mpsc::channel();
        drop(thread::spawn(move || {
            let _ = done.send(bidirectional(left, right));
        }));
        let writers = [
            left_peer.try_clone().unwrap(),
            right_peer.try_clone().unwrap(),
        ]
        .map(|mut peer| {
            thread::spawn(move || {
                let _ = peer.set_write_timeout(Some(Duration::from_millis(300)));
                let _ = peer.write_all(&vec![0_u8; 1 << 20]);
            })
        });

        // When: both directions are blocked in writes rather than reads.
        let finished_before_cleanup = outcome.recv_timeout(Duration::from_millis(200));
        let _ = left_peer.shutdown(Shutdown::Both);
        let _ = right_peer.shutdown(Shutdown::Both);

        // Then: the relay ended on its own; cleanup merely guarantees the test cannot hang.
        if finished_before_cleanup.is_err() {
            let _ = outcome.recv_timeout(Duration::from_secs(1));
        }
        for writer in writers {
            writer.join().unwrap();
        }
        assert!(
            finished_before_cleanup.is_ok(),
            "relay only ended after test cleanup, so its writes were unbounded"
        );
    }
}
