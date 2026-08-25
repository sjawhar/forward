//! Reply-size limits: a declared payload above the frame bound is
//! rejected during header parsing, before any allocation.
use proto::{ClientError, MAX_FRAME_BYTES, parse_response};

#[test]
fn rejects_a_payload_larger_than_the_protocol_reply_limit() {
    let length = MAX_FRAME_BYTES + 1;
    let mut response = format!("OK\tlen={length}\n").into_bytes();
    response.resize(response.len() + length, b'x');

    assert_eq!(parse_response(&response), Err(ClientError::InvalidResponse));
    assert!(matches!(
        parse_response(&response),
        Err(ClientError::InvalidResponse)
    ));
}
