use std::net::TcpListener;

use super::*;

#[test]
fn a_parsed_feed_token_resets_a_prior_outage() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut greeting = String::new();
        BufReader::new(stream.try_clone().unwrap())
            .read_line(&mut greeting)
            .unwrap();
        assert_eq!(greeting, "FEED\n");
        stream.write_all(b"TOKEN relay-token 30\n").unwrap();
        let mut ack = [0_u8; 3];
        stream.read_exact(&mut ack).unwrap();
        assert_eq!(ack, *b"OK\n");
    });
    let tokens = RelayTokens::new();
    let now = Instant::now();
    let mut failures = ReconnectBudget {
        unhealthy_since: Some(now - MAX_UNHEALTHY_FEED),
    };

    run_once(address, &tokens, &mut failures).unwrap();
    server.join().unwrap();

    assert!(!failures.failed_at(Instant::now()));
}

#[test]
fn greet_then_close_preserves_an_exhausted_outage_budget() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut greeting = String::new();
        BufReader::new(stream).read_line(&mut greeting).unwrap();
        assert_eq!(greeting, "FEED\n");
    });
    let tokens = RelayTokens::new();
    let now = Instant::now();
    let mut failures = ReconnectBudget {
        unhealthy_since: Some(now - MAX_UNHEALTHY_FEED),
    };

    run_once(address, &tokens, &mut failures).unwrap();
    server.join().unwrap();

    assert!(
        failures.failed_at(Instant::now()),
        "a greeting followed by close must not reset the outage budget"
    );
}

#[test]
fn a_long_lived_idle_feed_resets_a_prior_outage() {
    let now = Instant::now();
    let mut failures = ReconnectBudget {
        unhealthy_since: Some(now - MAX_UNHEALTHY_FEED),
    };

    failures.restored_if_long_lived(now - MIN_USEFUL_FEED_LIFETIME);

    assert!(!failures.failed_at(Instant::now()));
}

#[test]
fn an_exhausted_budget_slows_the_dial_cadence_instead_of_exiting() {
    let now = Instant::now();
    let mut failures = ReconnectBudget {
        unhealthy_since: Some(now - MAX_UNHEALTHY_FEED),
    };
    let mut in_outage = false;

    assert_eq!(
        next_backoff(&mut failures, &mut in_outage, now),
        OUTAGE_RECONNECT_BACKOFF
    );
    assert_eq!(
        next_backoff(&mut failures, &mut in_outage, now),
        OUTAGE_RECONNECT_BACKOFF
    );
    assert!(in_outage);
}

#[test]
fn a_restored_feed_returns_the_outage_cadence_to_normal() {
    let now = Instant::now();
    let mut failures = ReconnectBudget {
        unhealthy_since: Some(now - MAX_UNHEALTHY_FEED),
    };
    let mut in_outage = false;
    let _ = next_backoff(&mut failures, &mut in_outage, now);

    failures.restored();

    assert_eq!(
        next_backoff(&mut failures, &mut in_outage, now),
        RECONNECT_BACKOFF
    );
    assert!(!in_outage);
}

#[test]
fn a_budget_within_its_window_keeps_the_normal_cadence() {
    let now = Instant::now();
    let mut failures = ReconnectBudget {
        unhealthy_since: Some(now - (MAX_UNHEALTHY_FEED - Duration::from_millis(1))),
    };
    let mut in_outage = false;

    assert_eq!(
        next_backoff(&mut failures, &mut in_outage, now),
        RECONNECT_BACKOFF
    );
    assert!(!in_outage);
}
