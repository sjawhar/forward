use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};

use super::browser::{RelayEvidence, classify};
use super::response::read_response;

const REQUEST: &[u8] =
    b"GET /json/version HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n";

fn queued_connection(response: &[u8]) -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    client.set_read_timeout(Some(super::PROBE_TIMEOUT)).unwrap();
    // Queue the request before accept; the refusing side never reads it.
    client.write_all(REQUEST).unwrap();
    let (mut server, _) = listener.accept().unwrap();
    server.write_all(response).unwrap();
    (client, server)
}

fn closed_response(response: &[u8]) -> io::Result<Vec<u8>> {
    let (mut client, server) = queued_connection(response);
    drop(server);
    read_response(&mut client)
}

#[test]
fn complete_refusals_survive_close_with_unread_request_bytes() {
    for frame in [
        b"REFUSED\n".as_slice(),
        b"REFUSED PEER\n",
        b"REFUSED DENIED\n",
        b"REFUSED BUSY\n",
        b"REFUSED UNARMED\n",
        b"REFUSED FEED\n",
        b"REFUSED TOKEN\n",
        b"REFUSED TOKEN UPSTREAM 200\n",
        b"REFUSED TOKEN UPSTREAM 503\n",
    ] {
        let response = closed_response(frame).unwrap();
        assert_eq!(response, frame);
    }
}

#[test]
fn complete_peer_refusal_is_evidence_before_the_socket_closes() {
    let (mut client, server) = queued_connection(b"REFUSED PEER\n");
    let response = read_response(&mut client).unwrap();
    assert_eq!(classify(&response), Ok(RelayEvidence::PeerRefused));
    drop(server);
}

#[test]
fn truncated_and_malformed_refusals_fail_after_unread_request_close() {
    for frame in [
        b"REFUSED".as_slice(),
        b"REFUSED PEER",
        b"REFUSED PEER extra\n",
        b"REFUSED PEER\r\n",
        b"REFUSED PEER \n",
        b"REFUSEDPEER\n",
        b"REFUSED TOKEN UPSTREAM 503extra\n",
        b"REFUSED UNKNOWN\n",
    ] {
        assert!(closed_response(frame).is_err(), "accepted {frame:?}");
    }
}

#[test]
fn missing_refusal_newline_fails_on_clean_eof_too() {
    let (mut client, server) = queued_connection(b"REFUSED PEER");
    server.shutdown(Shutdown::Write).unwrap();
    assert_eq!(
        read_response(&mut client).unwrap_err().kind(),
        io::ErrorKind::UnexpectedEof
    );
}

#[test]
fn malformed_and_oversized_refusals_fail_without_waiting_for_eof() {
    for frame in [
        b"REFUSED PEER extra\n".as_slice(),
        b"REFUSED TOKEN UPSTREAM 503extra\n",
        b"REFUSED AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    ] {
        let (mut client, server) = queued_connection(frame);
        assert_eq!(
            read_response(&mut client).unwrap_err().kind(),
            io::ErrorKind::InvalidData,
            "frame {frame:?}"
        );
        drop(server);
    }
}

#[test]
fn ordinary_http_including_refusal_text_is_read_through_eof() {
    let response =
        b"HTTP/1.0 200 OK\r\nConnection: close\r\n\r\nREFUSED PEER\nbody after the refusal text";
    let (mut client, server) = queued_connection(response);
    server.shutdown(Shutdown::Write).unwrap();
    let body = read_response(&mut client).unwrap();
    assert_eq!(body, response);
    assert_eq!(classify(&body), Ok(RelayEvidence::Healthy));
}

#[cfg(target_os = "linux")]
#[test]
fn an_http_reset_after_response_bytes_remains_an_error() {
    let error = closed_response(b"HTTP/1.0 200 OK\r\n\r\n{}").unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
}

#[test]
fn fragmented_refusal_reads_keep_the_entire_frame() {
    // A short reader pins segmentation independently of TCP packet coalescing.
    struct OneByte<'a>(&'a [u8]);
    impl Read for OneByte<'_> {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            self.0.read(&mut output[..1])
        }
    }
    let mut reader = OneByte(b"REFUSED TOKEN UPSTREAM 503\n");
    let body = read_response(&mut reader).unwrap();
    assert_eq!(classify(&body), Ok(RelayEvidence::ExtensionDisconnected));
}
