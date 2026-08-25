use super::*;

#[test]
fn authorize_request_prefers_a_token_over_a_tty() {
    let request = authorize_request(
        "browser",
        Some("token".to_owned()),
        Some("/dev/pts/1".to_owned()),
    )
    .unwrap();

    assert_eq!(request, "AUTHORIZE\tcap=browser\ttoken=token");
}

#[test]
fn authorize_request_uses_a_tty_or_rejects_an_unknown_scope() {
    let request = authorize_request("browser", None, Some("/dev/pts/1".to_owned())).unwrap();
    assert_eq!(request, "AUTHORIZE\tcap=browser\ttty=/dev/pts/1");

    // No token and no terminal is not an anonymous request; it is a refusal.
    assert!(matches!(
        authorize_request("browser", None, None),
        Err(BrokerError::NoScope)
    ));
}

#[test]
fn the_authorize_bound_counts_the_newline_the_transport_appends() {
    let prefix = "AUTHORIZE\tcap=browser\ttoken=";
    let at_limit = "a".repeat(proto::MAX_FRAME_BYTES - prefix.len() - 1);
    let request = authorize_request("browser", Some(at_limit), None).unwrap();
    // One byte short of the broker's bound, because the transport adds '\n'.
    assert_eq!(request.len(), proto::MAX_FRAME_BYTES - 1);

    let over_limit = "a".repeat(proto::MAX_FRAME_BYTES - prefix.len());
    assert!(matches!(
        authorize_request("browser", Some(over_limit), None),
        Err(BrokerError::Protocol(_))
    ));
}

#[test]
fn a_control_character_in_a_field_is_refused_before_the_socket() {
    // A newline in a scope value would split one frame into two requests.
    assert!(matches!(
        authorize_request("browser", Some("tok\nen".to_owned()), None),
        Err(BrokerError::Protocol(_))
    ));
    assert!(matches!(
        authorize_request("brow ser\t", Some("token".to_owned()), None),
        Err(BrokerError::Protocol(_))
    ));
}

#[test]
fn broker_errors_map_per_verb() {
    // The same code means different things depending on what was asked, which
    // is why this mapping cannot live in the shared transport.
    let authorize = Verb::Authorize { cap: "browser" };

    assert!(matches!(map_code("DENIED", authorize), BrokerError::Denied));
    assert!(matches!(
        map_code("DENIED", Verb::Redeem),
        BrokerError::ReceiptRejected
    ));
    assert!(matches!(
        map_code("TIMEOUT", authorize),
        BrokerError::Timeout
    ));
    assert!(matches!(
        map_code("YUBIKEY_UNREACHABLE", authorize),
        BrokerError::YubikeyUnreachable
    ));
    assert!(matches!(
        map_code("TOO_MANY_PENDING", authorize),
        BrokerError::TooManyPending
    ));
    assert!(matches!(
        map_code("UNKNOWN_OP", Verb::Redeem),
        BrokerError::UnknownOp
    ));
    // A provisioning failure names the key the human has to create.
    let BrokerError::NotProvisioned(cap, key) = map_code("NOT_HUMAN_KEY", authorize) else {
        panic!("expected NotProvisioned");
    };
    assert_eq!((cap.as_str(), key.as_str()), ("browser", "BROWSER"));
    // Every scope-shaped refusal collapses to one actionable message.
    for code in ["NO_SCOPE", "UNKNOWN_TOKEN", "FOREIGN_CALLER", "AGENT_TTY"] {
        assert!(
            matches!(map_code(code, authorize), BrokerError::NoScope),
            "{code}"
        );
    }
    // An unrecognized code must not be silently treated as success.
    assert!(matches!(
        map_code("SOMETHING_NEW", authorize),
        BrokerError::Protocol(_)
    ));
}

#[test]
fn a_reply_must_carry_exactly_the_expected_fields() {
    assert!(authorized_receipt("status=authorized").is_err());
    assert!(authorized_receipt(&format!("status=authorized receipt={}", "a".repeat(64))).is_ok());
    // A duplicate field is malformed, not last-wins.
    assert!(
        authorized_receipt(&format!(
            "status=authorized receipt={r} receipt={r}",
            r = "a".repeat(64)
        ))
        .is_err()
    );
    // A receipt that is not 64 lowercase hex bytes is refused.
    assert!(authorized_receipt("status=authorized receipt=NOTHEX").is_err());

    assert!(matches!(
        redeemed_cap("status=redeemed cap=browser epoch=7", "browser"),
        Ok(7)
    ));
    assert!(redeemed_cap("status=redeemed cap=browser", "browser").is_err());
    // A reply naming a different capability must not authorize this one.
    assert!(redeemed_cap("status=redeemed cap=other epoch=7", "browser").is_err());
}
