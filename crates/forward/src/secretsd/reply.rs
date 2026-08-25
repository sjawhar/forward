use zeroize::Zeroizing;

use super::{BrokerError, BrokerIdentity, RedeemedGrant};

pub(super) fn authorized_receipt(fields: &str) -> Result<Zeroizing<String>, BrokerError> {
    let parsed = expected_fields(fields, &["status", "receipt"])?;
    match (value(&parsed, "status"), value(&parsed, "receipt")) {
        (Some("authorized"), Some(receipt)) if valid_hex_bytes(receipt.as_bytes(), 64) => {
            Ok(Zeroizing::new(receipt.to_owned()))
        }
        _ => Err(BrokerError::Protocol(
            "broker did not return an authorized receipt".to_owned(),
        )),
    }
}

/// `socket` comes from the connection that carried this reply, so the authority
/// it establishes names the socket that actually answered.
pub(super) fn redeemed_cap(
    fields: &str,
    cap: &str,
    socket: super::SocketIdentity,
) -> Result<RedeemedGrant, BrokerError> {
    let parsed = expected_fields(fields, &["status", "cap", "instance", "epoch", "ttl"])?;
    match (
        value(&parsed, "status"),
        value(&parsed, "cap"),
        value(&parsed, "instance"),
        value(&parsed, "epoch"),
        value(&parsed, "ttl"),
    ) {
        (Some("redeemed"), Some(returned), Some(instance), Some(epoch), Some(ttl))
            if returned == cap =>
        {
            if !valid_field(instance) {
                return Err(BrokerError::Protocol(
                    "broker redeem reply has no usable instance".to_owned(),
                ));
            }
            let epoch = epoch.parse().map_err(|_| {
                BrokerError::Protocol("broker redeem reply has no usable epoch".to_owned())
            })?;
            let ttl_secs = ttl
                .parse()
                .ok()
                .filter(|ttl: &u64| *ttl > 0)
                .ok_or_else(|| {
                    BrokerError::Protocol("broker redeem reply has no usable ttl".to_owned())
                })?;
            Ok(RedeemedGrant {
                authority: BrokerIdentity {
                    socket,
                    instance: instance.to_owned(),
                    epoch,
                },
                ttl_secs,
            })
        }
        (Some(status), _, _, _, _) if status != "redeemed" => Err(BrokerError::Protocol(
            "broker success reply has an unexpected status".to_owned(),
        )),
        _ => Err(BrokerError::ReceiptRejected),
    }
}

pub(super) fn valid_field(value: &str) -> bool {
    !value.is_empty() && value.is_ascii() && !value.bytes().any(|byte| byte.is_ascii_control())
}

pub(super) fn valid_hex_bytes(value: &[u8], length: usize) -> bool {
    value.len() == length
        && value
            .iter()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn expected_fields<'a>(
    fields: &'a str,
    expected: &[&str],
) -> Result<Vec<(&'a str, &'a str)>, BrokerError> {
    let mut parsed = Vec::with_capacity(expected.len());
    for field in fields.split(' ') {
        let Some((name, field_value)) = field.split_once('=') else {
            return Err(BrokerError::Protocol(
                "malformed broker success reply".to_owned(),
            ));
        };
        if name.is_empty()
            || field_value.is_empty()
            || !expected.contains(&name)
            || parsed.iter().any(|(seen, _)| *seen == name)
        {
            return Err(BrokerError::Protocol(
                "unexpected or duplicate broker success field".to_owned(),
            ));
        }
        parsed.push((name, field_value));
    }
    (parsed.len() == expected.len())
        .then_some(parsed)
        .ok_or_else(|| BrokerError::Protocol("broker success reply is missing a field".to_owned()))
}

fn value<'a>(fields: &[(&'a str, &'a str)], name: &str) -> Option<&'a str> {
    fields
        .iter()
        .find_map(|(field, field_value)| (*field == name).then_some(*field_value))
}
