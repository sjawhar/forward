use std::time::Duration;

use super::clock::BootTime;
use super::{constant_time_eq, hex};

#[test]
fn constant_time_eq_matches_equality_including_length() {
    assert!(constant_time_eq(b"", b""));
    assert!(constant_time_eq(b"relay-token", b"relay-token"));
    assert!(!constant_time_eq(b"relay-token", b"relay-tokeN"));
    // Length mismatch is a mismatch, not a prefix match: a truncated token
    // must never authorize.
    assert!(!constant_time_eq(b"relay-token", b"relay-toke"));
    assert!(!constant_time_eq(b"relay-toke", b"relay-token"));
    assert!(!constant_time_eq(b"", b"x"));
}

#[test]
fn hex_round_trips_at_the_declared_length() {
    let bytes = [0x00_u8, 0x0f, 0x10, 0xa5, 0xff];
    let encoded = hex::encode(&bytes);

    assert_eq!(encoded.as_str(), "000f10a5ff");

    let decoded = hex::decode_exact(&encoded, bytes.len()).expect("round trip");
    assert_eq!(decoded.as_ref(), bytes.as_slice());
}

#[test]
fn hex_decode_refuses_anything_but_the_exact_length() {
    // A short read must refuse rather than yield a shorter credential.
    assert!(hex::decode_exact("00ff", 3).is_none());
    assert!(hex::decode_exact("00ff", 1).is_none());
    assert!(hex::decode_exact("00ff", 2).is_some());
}

#[test]
fn hex_decode_refuses_non_hex_bytes() {
    assert!(hex::decode_exact("00zz", 2).is_none());
    assert!(hex::decode_exact("00 f", 2).is_none());
    // Uppercase is accepted: the wire format is lowercase, but a peer that
    // sends uppercase is unambiguous, not hostile.
    assert!(hex::decode_exact("00FF", 2).is_some());
}

#[test]
fn boot_time_arithmetic_saturates_instead_of_wrapping() {
    let base = BootTime::from_duration_since_boot(Duration::from_secs(100));
    let later = BootTime::from_duration_since_boot(Duration::from_secs(160));

    assert_eq!(
        later.saturating_duration_since(base),
        Duration::from_secs(60)
    );
    // Reversed operands saturate at zero rather than underflowing, so a clock
    // that appears to move backwards expires a lease instead of granting a
    // near-infinite one.
    assert_eq!(base.saturating_duration_since(later), Duration::ZERO);
}

#[test]
fn boot_time_advances_and_is_readable() {
    let first = BootTime::now().expect("CLOCK_BOOTTIME is readable");
    let second = BootTime::now().expect("CLOCK_BOOTTIME is readable");

    // Monotone: the mirror's expiry check depends on this never going
    // backwards between two reads.
    assert!(second >= first);
    assert!(first.checked_add(Duration::from_secs(1)).is_some());
}
