use std::io::{BufRead as _, BufReader, Write as _};
use std::net::TcpListener;

#[test]
fn a_refused_callback_url_is_reported_as_refused_not_as_opened_or_an_old_daemon() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let daemon = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = String::new();
        BufReader::new(&stream).read_line(&mut request).unwrap();
        stream
            .write_all(b"refused callback port 8400 is already owned by another peer\n")
            .unwrap();
    });
    let cfg = forward::config::Config::default_values_for_test();
    let url = url::Url::parse("https://auth.example/?redirect_uri=http://localhost:8400/").unwrap();
    let error = forward::send::send_url(&cfg, &url, port).unwrap_err();
    assert!(
        matches!(error, forward::send::SendError::Refused { ref reason, .. }
        if reason == "callback port 8400 is already owned by another peer")
    );
    daemon.join().unwrap();
}
