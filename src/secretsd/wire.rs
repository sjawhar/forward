//! Capability broker wire helpers, split by frame and reply responsibility.

mod frame;
mod reply;

pub use frame::authorize_frame;
pub(super) use frame::{caller_tty, process_uid, session_token};
pub(super) use reply::{Verb, authorized_receipt, call, hello, redeemed_cap, valid_receipt_bytes};

#[cfg(test)]
mod tests {
    use super::reply::ok_fields;
    use super::*;
    use crate::secretsd::BrokerError;

    #[test]
    fn authorize_frame_prefers_a_token_over_a_tty() {
        let frame = authorize_frame(
            "browser",
            Some("token".to_owned()),
            Some("/dev/pts/1".to_owned()),
        )
        .unwrap();
        assert!(
            frame == "AUTHORIZE\tcap=browser\ttoken=token\n",
            "wrong authorize frame"
        );
    }

    #[test]
    fn authorize_frame_uses_a_tty_or_rejects_an_unknown_scope() {
        let frame = authorize_frame("browser", None, Some("/dev/pts/1".to_owned())).unwrap();
        assert!(
            frame == "AUTHORIZE\tcap=browser\ttty=/dev/pts/1\n",
            "wrong authorize frame"
        );
        assert!(matches!(
            authorize_frame("browser", None, None),
            Err(BrokerError::NoScope)
        ));
    }

    #[test]
    fn authorize_frame_limit_includes_the_trailing_newline() {
        let prefix = "AUTHORIZE\tcap=browser\ttoken=";
        let at_limit = "a".repeat(4_096 - prefix.len() - 1);
        let frame = authorize_frame("browser", Some(at_limit), None).unwrap();
        assert_eq!(frame.len(), 4_096);

        let over_limit = "a".repeat(4_096 - prefix.len());
        assert!(matches!(
            authorize_frame("browser", Some(over_limit), None),
            Err(BrokerError::Protocol(_))
        ));
    }

    #[test]
    fn broker_errors_map_per_verb() {
        let denied = "ERR\tDENIED\tdeclined";
        assert!(matches!(
            ok_fields(denied, Verb::Authorize { cap: "browser" }),
            Err(BrokerError::Denied)
        ));
        assert!(matches!(
            ok_fields(denied, Verb::Redeem),
            Err(BrokerError::ReceiptRejected)
        ));
        assert!(matches!(
            ok_fields(denied, Verb::Hello),
            Err(BrokerError::Protocol(_))
        ));
        assert!(matches!(
            ok_fields("ERR\tTIMEOUT\texpired", Verb::Authorize { cap: "browser" }),
            Err(BrokerError::Timeout)
        ));
        assert!(matches!(
            ok_fields("ERR\tTIMEOUT\texpired", Verb::Redeem),
            Err(BrokerError::Protocol(_))
        ));
        assert!(matches!(
            ok_fields("ERR\tTIMEOUT\texpired", Verb::Hello),
            Err(BrokerError::Protocol(_))
        ));
        assert!(matches!(
            ok_fields(
                "ERR\tYUBIKEY_UNREACHABLE\treader missing",
                Verb::Authorize { cap: "browser" }
            ),
            Err(BrokerError::YubikeyUnreachable)
        ));
        assert!(matches!(
            ok_fields("ERR\tYUBIKEY_UNREACHABLE\treader missing", Verb::Redeem),
            Err(BrokerError::Protocol(_))
        ));
        assert!(matches!(
            ok_fields("ERR\tYUBIKEY_UNREACHABLE\treader missing", Verb::Hello),
            Err(BrokerError::Protocol(_))
        ));
        for code in ["NO_SCOPE", "UNKNOWN_TOKEN", "FOREIGN_CALLER", "AGENT_TTY"] {
            let reply = format!("ERR\t{code}\tscope rejected");
            assert!(matches!(
                ok_fields(&reply, Verb::Authorize { cap: "browser" }),
                Err(BrokerError::NoScope)
            ));
            assert!(matches!(
                ok_fields(&reply, Verb::Redeem),
                Err(BrokerError::Protocol(_))
            ));
            assert!(matches!(
                ok_fields(&reply, Verb::Hello),
                Err(BrokerError::Protocol(_))
            ));
        }
        assert!(matches!(
            ok_fields("ERR\tNOT_HUMAN_KEY\tmissing", Verb::Authorize { cap: "browser" }),
            Err(BrokerError::NotProvisioned(cap, key)) if cap == "browser" && key == "BROWSER"
        ));
        assert!(matches!(
            ok_fields("ERR\tUNKNOWN_OP\tunknown", Verb::Redeem),
            Err(BrokerError::UnknownOp)
        ));
        assert!(matches!(
            ok_fields("ERR\tDENIED", Verb::Redeem),
            Err(BrokerError::Protocol(_))
        ));
    }
}
