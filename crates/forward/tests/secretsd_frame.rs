use forward::secretsd::{BrokerError, authorize_request};

#[test]
fn authorize_request_rejects_control_characters_in_fields() {
    for (cap, token, tty) in [
        ("browser\tcap=other", Some("token"), None),
        ("browser", Some("token\nREDEEM"), None),
        ("browser", Some("token\r"), None),
        ("browser", Some("token\0"), None),
        ("browser", Some("téken"), None),
        ("browser", None, Some("/dev/pts/1\tother")),
    ] {
        assert!(matches!(
            authorize_request(cap, token.map(str::to_owned), tty.map(str::to_owned),),
            Err(BrokerError::Protocol(_))
        ));
    }
}

#[test]
fn authorize_request_rejects_a_frame_larger_than_the_broker_limit() {
    let cap = "a".repeat(4_096);
    assert!(matches!(
        authorize_request(&cap, Some("token".to_owned()), None),
        Err(BrokerError::Protocol(_))
    ));
}

#[test]
fn authorize_request_allows_the_exact_broker_limit() {
    let cap_len = 4_096 - "AUTHORIZE\tcap=".len() - "\ttoken=".len() - "t".len() - "\n".len();
    let cap = "a".repeat(cap_len);

    // The request is built without the trailing newline the transport appends,
    // so the largest accepted request is one byte under the broker's bound.
    let request = authorize_request(&cap, Some("t".to_owned()), None);
    assert!(request.as_ref().is_ok_and(|request| request.len() == 4_095));
}
