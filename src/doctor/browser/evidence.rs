#[derive(Debug, PartialEq, Eq)]
pub(in crate::doctor) enum RelayEvidence {
    PeerRefused,
    TokenFileMissing,
    TokenRequired,
    UpstreamDown,
    Busy,
    ExtensionDisconnected,
    Healthy,
}

pub(in crate::doctor) fn classify(body: &[u8]) -> Result<RelayEvidence, String> {
    if body.starts_with(b"REFUSED PEER") {
        return Ok(RelayEvidence::PeerRefused);
    }
    if body.starts_with(b"REFUSED TOKEN FILE") {
        return Ok(RelayEvidence::TokenFileMissing);
    }
    if body.starts_with(b"REFUSED TOKEN UPSTREAM 503") {
        return Ok(RelayEvidence::ExtensionDisconnected);
    }
    if body.starts_with(b"REFUSED TOKEN") {
        return Ok(RelayEvidence::TokenRequired);
    }
    if body == b"REFUSED\n" {
        return Ok(RelayEvidence::UpstreamDown);
    }
    if body.starts_with(b"REFUSED BUSY") {
        return Ok(RelayEvidence::Busy);
    }

    let status = body.split(|byte| *byte == b'\n').next().unwrap_or_default();
    if status.windows(4).any(|window| window == b" 200") {
        return Ok(RelayEvidence::Healthy);
    }
    if status.windows(4).any(|window| window == b" 503") {
        return Ok(RelayEvidence::ExtensionDisconnected);
    }
    Err(format!("unexpected {}-byte response {body:?}", body.len()))
}
