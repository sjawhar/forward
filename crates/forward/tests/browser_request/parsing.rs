use forward::browser::request::{GrantStatus, parse, parse_status, parse_ttl};

use super::RECEIPT;

const HEX: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

#[test]
fn a_well_formed_request_parses() {
    assert!(matches!(
        parse(format!("GRANT 1800 {HEX} 38987").as_bytes()),
        Some((1800, receipt, 38_987)) if receipt.len() == RECEIPT.len()
    ));
}

#[test]
fn a_request_without_the_verb_is_rejected() {
    assert!(parse(format!("1800 {HEX} 38987").as_bytes()).is_none());
    assert!(parse(b"STATUS").is_none());
}

#[test]
fn a_non_numeric_ttl_is_rejected() {
    assert!(parse(format!("GRANT soon {HEX} 38987").as_bytes()).is_none());
}

#[test]
fn a_missing_receipt_is_rejected() {
    assert!(parse(b"GRANT 1800").is_none());
    assert!(parse(b"GRANT 1800 ").is_none());
}

#[test]
fn a_malformed_receipt_is_rejected() {
    assert!(parse(b"GRANT 1800 correct-horse 38987").is_none());
    assert!(parse(format!("GRANT 1800 {} 38987", HEX.to_uppercase()).as_bytes()).is_none());
    assert!(parse(format!("GRANT 1800 {} 38987", &HEX[1..]).as_bytes()).is_none());
}

#[test]
fn a_request_without_a_usable_endpoint_port_is_rejected() {
    // A grant with no endpoint behind it is unusable, and a trailing field is
    // a caller speaking a protocol this one does not know.
    assert!(parse(format!("GRANT 1800 {HEX}").as_bytes()).is_none());
    assert!(parse(format!("GRANT 1800 {HEX} ").as_bytes()).is_none());
    assert!(parse(format!("GRANT 1800 {HEX} 0").as_bytes()).is_none());
    assert!(parse(format!("GRANT 1800 {HEX} 65536").as_bytes()).is_none());
    assert!(parse(format!("GRANT 1800 {HEX} soon").as_bytes()).is_none());
    assert!(parse(format!("GRANT 1800 {HEX} 38987 extra").as_bytes()).is_none());
}

#[test]
fn a_zero_or_overlong_ttl_is_rejected() {
    assert!(parse(format!("GRANT 0 {HEX} 38987").as_bytes()).is_none());
    assert!(parse(format!("GRANT 43201 {HEX} 38987").as_bytes()).is_none());
}

#[test]
fn ttl_shorthand_parses() {
    assert_eq!(parse_ttl("45s"), Some(45));
    assert_eq!(parse_ttl("30m"), Some(1_800));
    assert_eq!(parse_ttl("2h"), Some(7_200));
    assert_eq!(parse_ttl("0m"), None);
    assert_eq!(parse_ttl("5x"), None);
    assert_eq!(parse_ttl("m"), None);
    assert_eq!(parse_ttl(""), None);
}

#[test]
fn a_status_reply_parses() {
    assert_eq!(parse_status("NONE"), GrantStatus::None);
    assert_eq!(
        parse_status("LIVE 12811 1799"),
        GrantStatus::Live {
            port: 12_811,
            remaining_secs: 1_799,
        }
    );
    assert_eq!(parse_status("LIVE nonsense"), GrantStatus::Unreachable);
}
