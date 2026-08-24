use forward::secretsd::{BrokerError, authorize_frame};

#[test]
fn authorize_frame_rejects_control_characters_in_fields() {
    for (cap, token, tty) in [
        ("browser\tcap=other", Some("token"), None),
        ("browser", Some("token\nREDEEM"), None),
        ("browser", Some("token\r"), None),
        ("browser", Some("token\0"), None),
        ("browser", Some("téken"), None),
        ("browser", None, Some("/dev/pts/1\tother")),
    ] {
        assert!(matches!(
            authorize_frame(cap, token.map(str::to_owned), tty.map(str::to_owned),),
            Err(BrokerError::Protocol(_))
        ));
    }
}

#[test]
fn authorize_frame_rejects_a_frame_larger_than_the_broker_limit() {
    let cap = "a".repeat(4_096);
    assert!(matches!(
        authorize_frame(&cap, Some("token".to_owned()), None),
        Err(BrokerError::Protocol(_))
    ));
}

#[test]
fn authorize_frame_allows_the_exact_broker_limit_before_its_newline() {
    let cap_len = 4_096 - "AUTHORIZE\tcap=".len() - "\ttoken=".len() - 1;
    let cap = "a".repeat(cap_len);

    let frame = authorize_frame(&cap, Some("t".to_owned()), None);
    assert!(frame.as_ref().is_ok_and(|frame| frame.len() == 4_097));
}
