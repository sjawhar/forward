use std::io::{Read as _, Write as _};
use std::net::TcpListener;
use std::thread;

use super::*;

#[test]
fn preview_probe_uses_service_health_not_host_files() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let responder = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = [0_u8; 512];
        let length = stream.read(&mut request).unwrap();
        if request[..length].starts_with(b"GET /.well-known/forward/health HTTP/1.0\r\n") {
            stream
                .write_all(
                    b"HTTP/1.0 200 OK\r\nContent-Length: 24\r\n\r\nforward preview healthy\n",
                )
                .unwrap();
        } else {
            stream
                .write_all(b"HTTP/1.0 404 Not Found\r\nContent-Length: 0\r\n\r\n")
                .unwrap();
        }
    });

    let result = preview::probe("127.0.0.1", port);
    responder.join().unwrap();

    assert!(matches!(result, Ok(ProbeEvidence::PreviewHealthy)));
}

#[test]
fn a_success_status_without_the_health_marker_is_not_healthy() {
    for response in [
        b"HTTP/1.0 200 OK\r\n\r\nordinary page".as_slice(),
        b"HTTP/1.0 200 OK\r\n\r\nforward preview healthy\nextra".as_slice(),
        b"HTTP/1.0 200 OK\r\n\r\nforward preview health".as_slice(),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let responder = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 512];
            let _ = stream.read(&mut request).unwrap();
            stream.write_all(response).unwrap();
        });

        let result = preview::probe("127.0.0.1", port);
        responder.join().unwrap();

        assert!(result.is_err(), "accepted an unrelated HTTP 200 response");
    }
}

#[test]
fn preview_health_rejects_invalid_http_framing() {
    for response in [
        b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\nforward preview healthy\n".as_slice(),
        b"HTTP/1.0 200 OK\r\nContent-Length: 100\r\n\r\nforward preview healthy\n".as_slice(),
        b"HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nforward preview healthy\n".as_slice(),
        b"HTTP/1.0 200 OK\r\nContent-Length: 24\r\nTransfer-Encoding: chunked\r\n\r\nforward preview healthy\n".as_slice(),
        b"HTTP/1.0 200 OK\r\nContent-Length: 24\r\nContent-Length: 0\r\n\r\nforward preview healthy\n".as_slice(),
        b"HTTP/1.0 200 OK\r\nContent-Length: invalid\r\n\r\nforward preview healthy\n".as_slice(),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let responder = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 512];
            let _ = stream.read(&mut request).unwrap();
            stream.write_all(response).unwrap();
        });
        let result = preview::probe("127.0.0.1", port);
        responder.join().unwrap();
        assert!(result.is_err(), "accepted invalid framing");
    }
}

#[test]
fn preview_response_deadline_is_not_extended_by_partial_progress() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let responder = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = [0_u8; 512];
        let _ = stream.read(&mut request).unwrap();
        stream
            .write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 24\r\n\r\n")
            .unwrap();
        for bytes in b"forward preview healthy\n".chunks(8) {
            thread::sleep(Duration::from_millis(1100));
            if stream.write_all(bytes).is_err() {
                break;
            }
        }
    });
    let start = std::time::Instant::now();
    let result = preview::probe("127.0.0.1", port);
    let elapsed = start.elapsed();
    responder.join().unwrap();
    assert!(
        result.is_err(),
        "partial reads extended the response deadline"
    );
    assert!(elapsed < Duration::from_secs(4), "took {elapsed:?}");
}

#[test]
fn preview_health_rejects_malformed_header_fields() {
    for headers in [
        " Content-Length: 24",
        "\tContent-Length: 24",
        "Content-Length : 24",
        "Content-Length: 24\r\nBad@Name: value",
        "Content-Length: 24\r\nX: value\nTransfer-Encoding: chunked",
        "Content-Length: 24\r\nX: value\rTransfer-Encoding: chunked",
        "Content-Length: \u{2003}24",
        "Content-Length: 24\r\nX: value\u{000b}",
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let response = format!("HTTP/1.0 200 OK\r\n{headers}\r\n\r\nforward preview healthy\n");
        let responder = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 512];
            let _ = stream.read(&mut request).unwrap();
            stream.write_all(response.as_bytes()).unwrap();
        });
        let result = preview::probe("127.0.0.1", port);
        responder.join().unwrap();
        assert!(result.is_err(), "accepted malformed header {headers:?}");
    }
}

#[test]
fn preview_health_rejects_malformed_status_lines() {
    for status in [
        "HTTP/1.0 200 OK\u{0000}",
        "HTTP/1.0\u{000b}200 OK",
        "HTTP/1.0\t200 OK",
        "HTTP/1.0 200 OK\u{007f}",
        "HTTP/1.0  200 OK",
        "HTTP/1.0 200  OK",
        " HTTP/1.0 200 OK",
        "HTTP/1.0 200",
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let response = format!("{status}\r\nContent-Length: 24\r\n\r\nforward preview healthy\n");
        let responder = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 512];
            let _ = stream.read(&mut request).unwrap();
            stream.write_all(response.as_bytes()).unwrap();
        });
        let result = preview::probe("127.0.0.1", port);
        responder.join().unwrap();
        assert!(result.is_err(), "accepted malformed status {status:?}");
    }
}
