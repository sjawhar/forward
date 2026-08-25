use forward::browser::request::{GrantStatus, parse, parse_status, parse_ttl};

use super::RECEIPT;

#[test]
fn a_well_formed_request_parses() {
    assert!(matches!(
        parse(b"GRANT 1800 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        Some((1800, receipt)) if receipt.len() == RECEIPT.len()
    ));
}

#[test]
fn a_request_without_the_verb_is_rejected() {
    assert!(
        parse(b"1800 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").is_none()
    );
    assert!(parse(b"STATUS").is_none());
}

#[test]
fn a_non_numeric_ttl_is_rejected() {
    assert!(
        parse(b"GRANT soon aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            .is_none()
    );
}

#[test]
fn a_missing_receipt_is_rejected() {
    assert!(parse(b"GRANT 1800").is_none());
    assert!(parse(b"GRANT 1800 ").is_none());
}

#[test]
fn a_malformed_receipt_is_rejected() {
    assert!(parse(b"GRANT 1800 correct-horse").is_none());
    assert!(
        parse(b"GRANT 1800 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
            .is_none()
    );
    assert!(
        parse(b"GRANT 1800 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ")
            .is_none()
    );
}

#[test]
fn a_zero_or_overlong_ttl_is_rejected() {
    assert!(
        parse(b"GRANT 0 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            .is_none()
    );
    assert!(
        parse(b"GRANT 43201 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            .is_none()
    );
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
