use forward::secretsd::{self, BrokerError, BrokerIdentity, CAP_BROWSER, RedeemedGrant};

use super::{FakeBroker, RECEIPT, Reply, Step, hello, redeem};

#[test]
fn redeem_accepts_matching_capability() {
    let broker = FakeBroker::start(vec![
        hello(),
        Step {
            expected: redeem(),
            reply: Reply::Text(
                "OK\tstatus=redeemed cap=browser instance=abc123 epoch=7 ttl=60\n".to_owned(),
            ),
        },
    ]);

    let result = secretsd::redeem_for_test(&broker.path, RECEIPT.as_bytes(), CAP_BROWSER);
    broker.finish();
    assert_eq!(
        result.ok(),
        Some(RedeemedGrant {
            authority: BrokerIdentity {
                instance: "abc123".to_owned(),
                epoch: 7,
            },
            ttl_secs: 60,
        })
    );
}

#[test]
fn redeem_refuses_a_success_reply_without_an_epoch() {
    let broker = FakeBroker::start(vec![
        hello(),
        Step {
            expected: redeem(),
            reply: Reply::Text("OK\tstatus=redeemed cap=browser instance=abc123\n".to_owned()),
        },
    ]);

    let result = secretsd::redeem_for_test(&broker.path, RECEIPT.as_bytes(), CAP_BROWSER);
    broker.finish();

    assert!(matches!(result, Err(BrokerError::Protocol(_))));
}

#[test]
fn redeem_refuses_a_success_reply_without_an_instance() {
    // This fails if a receipt can be accepted using epoch alone.
    let broker = FakeBroker::start(vec![
        hello(),
        Step {
            expected: redeem(),
            reply: Reply::Text("OK\tstatus=redeemed cap=browser epoch=7\n".to_owned()),
        },
    ]);

    let result = secretsd::redeem_for_test(&broker.path, RECEIPT.as_bytes(), CAP_BROWSER);
    broker.finish();

    assert!(matches!(result, Err(BrokerError::Protocol(_))));
}

#[test]
fn redeem_maps_denied_to_receipt_rejected() {
    let broker = FakeBroker::start(vec![
        hello(),
        Step {
            expected: redeem(),
            reply: Reply::Text("ERR\tDENIED\treceipt is not redeemable\n".to_owned()),
        },
    ]);

    let error =
        secretsd::redeem_for_test(&broker.path, RECEIPT.as_bytes(), CAP_BROWSER).unwrap_err();
    broker.finish();
    assert!(matches!(error, BrokerError::ReceiptRejected));
}

#[test]
fn an_old_daemon_maps_unknown_op_to_upgrade_guidance() {
    let broker = FakeBroker::start(vec![
        hello(),
        Step {
            expected: redeem(),
            reply: Reply::Text("ERR\tUNKNOWN_OP\tunknown operation\n".to_owned()),
        },
    ]);

    let error =
        secretsd::redeem_for_test(&broker.path, RECEIPT.as_bytes(), CAP_BROWSER).unwrap_err();
    broker.finish();
    assert!(matches!(error, BrokerError::UnknownOp));
    assert!(error.to_string().contains("2.6.0"));
}

#[test]
fn a_version_mismatch_is_a_protocol_error() {
    let broker = FakeBroker::start(vec![Step {
        expected: "HELLO\tversion=3\n".to_owned(),
        reply: Reply::Text("OK\tversion=2 instance=abc\n".to_owned()),
    }]);

    let error =
        secretsd::redeem_for_test(&broker.path, RECEIPT.as_bytes(), CAP_BROWSER).unwrap_err();
    broker.finish();
    assert!(matches!(error, BrokerError::Protocol(_)));
}

#[test]
fn a_malformed_reply_is_a_sanitized_protocol_error() {
    const SENSITIVE: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    let broker = FakeBroker::start(vec![
        hello(),
        Step {
            expected: redeem(),
            reply: Reply::Text(format!("MALFORMED {SENSITIVE}\n")),
        },
    ]);

    let error =
        secretsd::redeem_for_test(&broker.path, RECEIPT.as_bytes(), CAP_BROWSER).unwrap_err();
    broker.finish();
    assert!(matches!(error, BrokerError::Protocol(_)));
    assert!(!error.to_string().contains(SENSITIVE));
    assert!(!format!("{error:?}").contains(SENSITIVE));
}

#[test]
fn a_closed_socket_is_a_protocol_error() {
    let broker = FakeBroker::start(vec![
        hello(),
        Step {
            expected: redeem(),
            reply: Reply::Close,
        },
    ]);

    let error =
        secretsd::redeem_for_test(&broker.path, RECEIPT.as_bytes(), CAP_BROWSER).unwrap_err();
    broker.finish();
    assert!(matches!(error, BrokerError::Protocol(_)));
}

#[test]
fn a_reply_without_a_newline_is_a_protocol_error() {
    let broker = FakeBroker::start(vec![
        hello(),
        Step {
            expected: redeem(),
            reply: Reply::Text("OK\tstatus=redeemed cap=browser".to_owned()),
        },
    ]);

    let error =
        secretsd::redeem_for_test(&broker.path, RECEIPT.as_bytes(), CAP_BROWSER).unwrap_err();
    broker.finish();
    assert!(matches!(error, BrokerError::Protocol(_)));
}

#[test]
fn redeem_rejects_an_authorize_shaped_success() {
    let broker = FakeBroker::start(vec![
        hello(),
        Step {
            expected: redeem(),
            reply: Reply::Text("OK\tstatus=authorized cap=browser\n".to_owned()),
        },
    ]);

    let result = secretsd::redeem_for_test(&broker.path, RECEIPT.as_bytes(), CAP_BROWSER);
    broker.finish();
    assert!(matches!(result, Err(BrokerError::Protocol(_))));
}

#[test]
fn redeem_rejects_duplicate_or_unexpected_success_fields() {
    for response in [
        "OK\tstatus=redeemed cap=browser instance=abc123 epoch=7 cap=other\n",
        "OK\tstatus=redeemed cap=browser instance=abc123 epoch=7 extra=value\n",
    ] {
        let broker = FakeBroker::start(vec![
            hello(),
            Step {
                expected: redeem(),
                reply: Reply::Text(response.to_owned()),
            },
        ]);

        let result = secretsd::redeem_for_test(&broker.path, RECEIPT.as_bytes(), CAP_BROWSER);
        broker.finish();
        assert!(matches!(result, Err(BrokerError::Protocol(_))));
    }
}
