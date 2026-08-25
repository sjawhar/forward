//! Framing and HELLO validation over a caller-supplied broker stream.
use std::io::{BufRead as _, BufReader, Write as _};
use std::os::unix::net::UnixStream;
use std::thread;
use std::time::Duration;

use proto::{BrokerClient, BrokerResponse};

#[test]
fn request_on_uses_the_supplied_stream_with_standard_framing() {
    let (client_stream, mut broker_stream) = UnixStream::pair().unwrap();
    let broker = thread::spawn(move || {
        let mut request = String::new();
        BufReader::new(broker_stream.try_clone().unwrap())
            .read_line(&mut request)
            .unwrap();
        broker_stream.write_all(b"OK\n").unwrap();
        request
    });
    let client =
        BrokerClient::with_timeouts("unused", Duration::from_secs(1), Duration::from_secs(1));

    assert_eq!(
        client.request_on(client_stream, "LOCK"),
        Ok(BrokerResponse::Ok)
    );
    assert_eq!(broker.join().unwrap(), "LOCK\n");
}

#[test]
fn hello_on_validates_the_supplied_stream_response() {
    let (client_stream, mut broker_stream) = UnixStream::pair().unwrap();
    let broker = thread::spawn(move || {
        let mut request = String::new();
        BufReader::new(broker_stream.try_clone().unwrap())
            .read_line(&mut request)
            .unwrap();
        broker_stream
            .write_all(b"OK\tversion=3 instance=broker epoch=0\n")
            .unwrap();
        request
    });
    let client =
        BrokerClient::with_timeouts("unused", Duration::from_secs(1), Duration::from_secs(1));

    assert_eq!(
        client.hello_on(client_stream).unwrap().required("instance"),
        Ok("broker")
    );
    assert_eq!(broker.join().unwrap(), "HELLO\tversion=3\n");
}
