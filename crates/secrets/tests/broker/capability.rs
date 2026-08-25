#![allow(
    clippy::panic,
    clippy::significant_drop_tightening,
    reason = "the task specification provides this integration harness verbatim"
)]

use super::{Harness, TOKEN_A, install_request_log_capture, request_log, token};

fn receipt_from(header: &str) -> String {
    header
        .trim_end()
        .split(' ')
        .find_map(|field| field.strip_prefix("receipt="))
        .unwrap_or_else(|| panic!("no receipt in {header:?}"))
        .to_owned()
}

fn assert_redeemed(header: &str, epoch: u64) {
    assert!(
        header.starts_with("OK\tstatus=redeemed cap=browser instance="),
        "{header}"
    );
    assert_eq!(epoch_from(header), Some(epoch));
}

fn epoch_from(header: &str) -> Option<u64> {
    header
        .trim_end()
        .split(' ')
        .find_map(|field| field.strip_prefix("epoch="))
        .and_then(|epoch| epoch.parse().ok())
}

include!("capability/audit.rs");
include!("capability/ceremony.rs");
include!("capability/redeem.rs");
