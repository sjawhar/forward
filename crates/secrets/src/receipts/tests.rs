use std::time::Instant;

use zeroize::Zeroize as _;

use super::*;

#[test]
#[cfg_attr(miri, ignore)]
fn a_receipt_redeems_exactly_once_and_expires() {
    let mut table = ReceiptTable::default();
    let now = Instant::now();
    let cap = Capability::parse("browser").unwrap();
    let receipt = table.mint(&cap, now).unwrap();
    assert_eq!(receipt.len(), RECEIPT_LEN * 2);

    assert_eq!(
        table.redeem(&receipt, &cap, now).unwrap().as_str(),
        "browser"
    );
    assert!(
        table.redeem(&receipt, &cap, now).is_none(),
        "second redeem must fail"
    );

    let stale = table.mint(&cap, now).unwrap();
    assert!(
        table.redeem(&stale, &cap, now + RECEIPT_TTL).is_none(),
        "expired redeem must fail"
    );
}

#[test]
fn redeem_rejects_malformed_hex_without_panicking() {
    let mut table = ReceiptTable::default();
    let cap = Capability::parse("browser").unwrap();
    assert!(table.redeem("zz", &cap, Instant::now()).is_none());
    assert!(
        table
            .redeem(&"a".repeat(63), &cap, Instant::now())
            .is_none()
    );
}

#[test]
fn redeeming_seeded_receipt_scans_and_consumes_it() {
    let now = Instant::now();
    let browser = Capability::parse("browser").unwrap();
    let admin = Capability::parse("admin").unwrap();
    let browser_expected = browser.clone();
    let admin_expected = admin.clone();
    let mut table = ReceiptTable {
        entries: vec![
            Entry {
                id: Zeroizing::new(vec![0x42; RECEIPT_LEN].into_boxed_slice()),
                cap: browser,
                minted: now,
            },
            Entry {
                id: Zeroizing::new(vec![0x24; RECEIPT_LEN].into_boxed_slice()),
                cap: admin,
                minted: now,
            },
        ],
    };
    let browser_receipt = Zeroizing::new("42".repeat(RECEIPT_LEN));
    let admin_receipt = Zeroizing::new("24".repeat(RECEIPT_LEN));

    let redeemed = table.redeem(&browser_receipt, &browser_expected, now);

    assert_eq!(redeemed.as_ref().map(Capability::as_str), Some("browser"));
    assert_eq!(
        table
            .redeem(&admin_receipt, &admin_expected, now)
            .as_ref()
            .map(Capability::as_str),
        Some("admin")
    );
    assert!(table.entries.is_empty());
}

#[test]
fn mismatched_capability_does_not_consume_a_receipt() {
    let browser = Capability::parse("browser").unwrap();
    let admin = Capability::parse("admin").unwrap();
    let now = Instant::now();
    let receipt = Zeroizing::new("42".repeat(RECEIPT_LEN));
    let mut table = ReceiptTable {
        entries: vec![Entry {
            id: Zeroizing::new(vec![0x42; RECEIPT_LEN].into_boxed_slice()),
            cap: browser.clone(),
            minted: now,
        }],
    };

    assert!(table.redeem(&receipt, &admin, now).is_none());
    assert_eq!(
        table.redeem(&receipt, &browser, now).unwrap().as_str(),
        "browser"
    );
}

#[test]
fn rendered_receipt_is_a_zeroizing_string() {
    let mut receipt: Zeroizing<String> = hex::encode(&[0xab; RECEIPT_LEN]);

    assert_eq!(receipt.len(), RECEIPT_LEN * 2);
    receipt.zeroize();
    assert!(receipt.is_empty());
}

#[test]
#[cfg_attr(miri, ignore)]
fn clear_forgets_every_outstanding_receipt() {
    let mut table = ReceiptTable::default();
    let cap = Capability::parse("browser").unwrap();
    let now = Instant::now();
    let receipt = table.mint(&cap, now).unwrap();

    table.clear();

    assert!(
        table.redeem(&receipt, &cap, now).is_none(),
        "a cleared receipt must be dead"
    );
}

#[test]
#[cfg_attr(miri, ignore)]
fn sweep_removes_expired_receipts_without_redemption() {
    let mut table = ReceiptTable::default();
    let cap = Capability::parse("browser").unwrap();
    let now = Instant::now();
    let receipt = table.mint(&cap, now).unwrap();

    table.sweep(now + RECEIPT_TTL);

    assert!(table.entries.is_empty());
    assert!(table.redeem(&receipt, &cap, now + RECEIPT_TTL).is_none());
}

#[test]
#[cfg_attr(miri, ignore)]
fn mint_at_capacity_refuses_without_revoking_receipts() {
    let mut table = ReceiptTable::default();
    let cap = Capability::parse("browser").unwrap();
    let now = Instant::now();
    let mut receipts = Vec::with_capacity(MAX_RECEIPTS);
    for _ in 0..MAX_RECEIPTS {
        receipts.push(table.mint(&cap, now).unwrap());
    }

    let error = table.mint(&cap, now).unwrap_err();

    assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
    for receipt in receipts {
        let redeemed = table.redeem(&receipt, &cap, now);
        assert_eq!(redeemed.as_ref().map(Capability::as_str), Some("browser"));
    }
}

#[test]
#[cfg_attr(miri, ignore)]
fn full_table_keeps_the_oldest_receipt() {
    let mut table = ReceiptTable::default();
    let cap = Capability::parse("browser").unwrap();
    let now = Instant::now();
    let oldest = table.mint(&cap, now).unwrap();
    for _ in 1..MAX_RECEIPTS {
        table.mint(&cap, now).unwrap();
    }

    assert!(table.mint(&cap, now).is_err());

    let redeemed = table.redeem(&oldest, &cap, now);
    assert_eq!(redeemed.as_ref().map(Capability::as_str), Some("browser"));
}

#[test]
fn mint_refuses_an_over_capacity_table_without_reducing_it() {
    let mut table = ReceiptTable::default();
    let cap = Capability::parse("browser").unwrap();
    let now = Instant::now();
    for _ in 0..=MAX_RECEIPTS {
        table.entries.push(Entry {
            id: Zeroizing::new(vec![0_u8; RECEIPT_LEN].into_boxed_slice()),
            cap: cap.clone(),
            minted: now,
        });
    }

    let error = table.mint(&cap, now).unwrap_err();

    assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
    assert_eq!(table.entries.len(), MAX_RECEIPTS + 1);
}

#[test]
#[cfg_attr(miri, ignore)]
fn mint_returns_a_zeroizing_string() {
    let mut table = ReceiptTable::default();
    let cap = Capability::parse("browser").unwrap();
    let now = Instant::now();
    let mut receipt: Zeroizing<String> = table.mint(&cap, now).unwrap();

    assert_eq!(receipt.len(), RECEIPT_LEN * 2);
    receipt.zeroize();
    assert!(receipt.is_empty());
}
