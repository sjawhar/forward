use super::*;

#[test]
fn parses_hello_when_version_present() {
    let req = parse_request(b"HELLO\tversion=1").unwrap();
    assert_eq!(req, Request::Hello { version: 1 });
}

#[test]
fn parses_get_with_token_and_tty() {
    let line = b"GET\tkey=DEEL_API_KEY\ttoken=ab12\ttty=/dev/pts/3";
    let req = parse_request(line).unwrap();
    assert_eq!(
        req,
        Request::Get {
            key: "DEEL_API_KEY".to_owned(),
            token_hex: Some(Zeroizing::new("ab12".to_owned())),
            tty: Some("/dev/pts/3".to_owned()),
        }
    );
}

#[test]
fn request_debug_redacts_bearer_credentials() {
    let register = parse_request(b"REGISTER\ttoken=deadbeef\tsession=session\tpid=1").unwrap();
    let redeem = parse_request(b"REDEEM\treceipt=feedface\tcap=browser").unwrap();

    assert!(!format!("{register:?}").contains("deadbeef"));
    assert!(!format!("{redeem:?}").contains("feedface"));
}

#[test]
fn parses_get_without_token() {
    let req = parse_request(b"GET\tkey=K\ttty=/dev/pts/3").unwrap();
    assert_eq!(
        req,
        Request::Get {
            key: "K".to_owned(),
            token_hex: None,
            tty: Some("/dev/pts/3".to_owned()),
        }
    );
}

#[test]
fn subscription_is_input_free() {
    assert_eq!(
        parse_request(SUBSCRIBE_VERB.as_bytes()),
        Ok(Request::Subscribe)
    );
    assert_eq!(
        parse_request(format!("{SUBSCRIBE_VERB}\tpid=1").as_bytes()),
        Err(ErrCode::BadRequest)
    );
}
#[test]
fn rejects_unknown_op() {
    assert_eq!(parse_request(b"FROBNICATE\tx=1"), Err(ErrCode::UnknownOp));
}

#[test]
fn ambiguous_key_error_round_trips_its_wire_token() {
    assert_eq!(
        ErrCode::parse_wire("AMBIGUOUS_KEY"),
        Some(ErrCode::AmbiguousKey)
    );
    assert_eq!(ErrCode::AmbiguousKey.wire(), "AMBIGUOUS_KEY");
}

#[test]
fn rejects_removed_announcement_frames_and_errors() {
    assert_eq!(parse_request(b"ACK\tid=9"), Err(ErrCode::UnknownOp));
    assert_eq!(ErrCode::parse_wire("NOT_ANNOUNCED"), None);
}

#[test]
fn rejects_missing_required_field() {
    assert_eq!(
        parse_request(b"GET\ttty=/dev/pts/3"),
        Err(ErrCode::BadRequest)
    );
}

#[test]
fn rejects_empty_line() {
    assert_eq!(parse_request(b""), Err(ErrCode::BadRequest));
}

#[test]
fn rejects_oversized_frame() {
    let line = vec![b'A'; MAX_FRAME_BYTES + 1];
    assert_eq!(parse_request(&line), Err(ErrCode::BadRequest));
}

#[test]
fn rejects_non_utf8() {
    assert_eq!(
        parse_request(&[b'G', b'E', b'T', b'\t', 0xff]),
        Err(ErrCode::BadRequest)
    );
}

#[test]
fn rejects_duplicate_field() {
    assert_eq!(
        parse_request(b"GET\tkey=A\tkey=B"),
        Err(ErrCode::BadRequest)
    );
}

#[test]
fn parses_authorize_with_token_and_redeem() {
    let req = parse_request(b"AUTHORIZE\tcap=browser\ttoken=ab12").unwrap();
    assert_eq!(
        req,
        Request::Authorize {
            cap: "browser".to_owned(),
            token_hex: Some(Zeroizing::new("ab12".to_owned())),
            tty: None,
        }
    );
    let req = parse_request(b"REDEEM\treceipt=deadbeef\tcap=browser").unwrap();
    assert_eq!(
        req,
        Request::Redeem {
            receipt_hex: Zeroizing::new("deadbeef".to_owned()),
            cap: "browser".to_owned(),
        }
    );
}

#[test]
fn authorize_requires_a_cap_and_redeem_a_receipt() {
    assert_eq!(
        parse_request(b"AUTHORIZE\ttoken=ab"),
        Err(ErrCode::BadRequest)
    );
    assert_eq!(
        parse_request(b"REDEEM\tcap=browser"),
        Err(ErrCode::BadRequest)
    );
    assert_eq!(
        parse_request(b"REDEEM\treceipt=deadbeef"),
        Err(ErrCode::BadRequest)
    );
}

#[test]
fn rejects_duplicate_authorize_capability_fields() {
    assert_eq!(
        parse_request(b"AUTHORIZE\tcap=browser\tcap=admin\ttoken=ab12"),
        Err(ErrCode::BadRequest)
    );
}

#[test]
fn formats_ok_bytes_header() {
    assert_eq!(format_response(&Response::OkBytes(42)), "OK\tlen=42\n");
}

#[test]
fn every_ok_fields_payload_is_space_separated_key_values() {
    // A space separates fields on the wire, and `sanitize` does not protect
    // it, so a value containing one would reach a client as an extra field.
    // Pin the shape of every payload this daemon emits.
    let instance = "ab".repeat(16);
    let handshake = format!("version={PROTOCOL_VERSION} instance={instance}");
    for fields in [handshake.as_str(), "status=granted"] {
        let line = format_response(&Response::OkFields(fields));
        let body = line
            .strip_prefix("OK\t")
            .and_then(|rest| rest.strip_suffix('\n'))
            .unwrap();
        assert!(
            body.split(' ')
                .all(|field| !field.is_empty() && field.contains('=')),
            "payload is not space-separated k=v: {body}"
        );
    }
}

#[test]
#[should_panic(expected = "not space-separated")]
fn a_field_value_containing_a_space_is_caught() {
    // The tripwire above must actually fire, or it documents nothing.
    let _ = format_response(&Response::OkFields("note=hello world"));
}

#[test]
fn formats_error_with_code_and_message() {
    assert_eq!(
        format_response(&Response::Failed(ErrCode::UnknownToken, "no such session")),
        "ERR\tUNKNOWN_TOKEN\tno such session\n"
    );
}

#[test]
fn error_message_newlines_are_sanitized() {
    let out = format_response(&Response::Failed(ErrCode::Internal, "bad\nthing"));
    assert_eq!(out.matches('\n').count(), 1);
}
