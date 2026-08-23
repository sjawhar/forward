use crate::callback::RELAY_TARGET_PORT;
use crate::config::Config;
use crate::target::url_host;
use std::io::{Read, Write};

type Request = dyn for<'host, 'path> FnMut(&'host str, u16, &'path str) -> Result<Vec<u8>, String>;

pub(super) fn report(cfg: &Config) -> bool {
    let (healthy, line) = evaluate(cfg, crate::config::default_relay_port());
    super::print_line(line);
    healthy
}

pub(super) fn evaluate(cfg: &Config, well_known_port: u16) -> (bool, String) {
    let mut send_request = |host: &str, port: u16, path: &str| request(host, port, path);
    evaluate_with(cfg, well_known_port, RELAY_TARGET_PORT, &mut send_request)
}

/// Test seam: evaluate the role split with injected relay request results.
pub(super) fn evaluate_with(
    cfg: &Config,
    well_known_port: u16,
    relay_target_port: u16,
    request: &mut Request,
) -> (bool, String) {
    if cfg.relay_port == 0 && cfg.peer.is_empty() {
        return (true, "browser relay: disabled (relay_port = 0)".to_owned());
    }

    if cfg.relay_port == 0 {
        return report_probe(
            probe(request, &cfg.peer, well_known_port, "/json/version"),
            &cfg.peer,
            well_known_port,
            &cfg.peer,
            well_known_port,
            request,
        );
    }

    let result = probe(request, &cfg.listen, cfg.relay_port, "/json/version");
    match result {
        Ok(RelayEvidence::PeerRefused) if has_routable_listen(cfg) => report_laptop_upstream(
            probe(request, "127.0.0.1", relay_target_port, "/json/version"),
            &cfg.listen,
            cfg.relay_port,
            relay_target_port,
            request,
        ),
        Err(local_error) if has_routable_listen(cfg) && !cfg.peer.is_empty() => {
            report_devbox_peer(cfg, local_error, well_known_port, request)
        }
        result => report_probe(
            result,
            &cfg.listen,
            cfg.relay_port,
            &cfg.listen,
            cfg.relay_port,
            request,
        ),
    }
}

fn has_routable_listen(cfg: &Config) -> bool {
    matches!(cfg.listen_ip(), Ok(address) if !address.is_loopback())
}

fn report_devbox_peer(
    cfg: &Config,
    local_error: String,
    well_known_port: u16,
    request: &mut Request,
) -> (bool, String) {
    match probe(request, &cfg.peer, well_known_port, "/json/version") {
        Err(peer_error) => (
            false,
            format!(
                "browser relay: FAIL — neither local listener {}:{} ({local_error}) nor laptop peer {}:{well_known_port} ({peer_error}) answered",
                cfg.listen, cfg.relay_port, cfg.peer
            ),
        ),
        result => report_probe(
            result,
            &cfg.peer,
            well_known_port,
            &cfg.peer,
            well_known_port,
            request,
        ),
    }
}

fn report_laptop_upstream(
    result: Result<RelayEvidence, String>,
    host: &str,
    port: u16,
    relay_target_port: u16,
    request: &mut Request,
) -> (bool, String) {
    match result {
        Err(_) | Ok(RelayEvidence::UpstreamDown) => (
            false,
            format!(
                "browser relay: FAIL — relay process down — start omp-browser-relay (via {host}:{port})"
            ),
        ),
        result => report_probe(result, host, port, "127.0.0.1", relay_target_port, request),
    }
}

fn report_probe(
    result: Result<RelayEvidence, String>,
    host: &str,
    port: u16,
    probe_host: &str,
    probe_port: u16,
    request: &mut Request,
) -> (bool, String) {
    match result {
        Err(error) => (
            false,
            format!(
                "browser relay: FAIL — {host}:{port} ({error}); relay channel down — is forward daemon running?"
            ),
        ),
        Ok(RelayEvidence::PeerRefused) => (
            false,
            format!(
                "browser relay: FAIL — {host}:{port}: not the configured peer — check peer on the laptop"
            ),
        ),
        Ok(RelayEvidence::TokenFileMissing) => (
            false,
            format!(
                "browser relay: FAIL — laptop token file missing — run forward browser init-token (at {host}:{port})"
            ),
        ),
        Ok(RelayEvidence::TokenRequired) => (
            true,
            format!("browser relay: locked at {host}:{port} (no grant)"),
        ),
        Ok(RelayEvidence::UpstreamDown) => (
            false,
            format!(
                "browser relay: FAIL — relay process down — start omp-browser-relay (via {host}:{port})"
            ),
        ),
        Ok(RelayEvidence::Busy) => (
            false,
            format!("browser relay: FAIL — {host}:{port} at its connection limit"),
        ),
        Ok(RelayEvidence::ExtensionDisconnected) => (
            true,
            format!(
                "browser relay: relay up, extension not connected — check the badge (at {host}:{port})"
            ),
        ),
        Ok(RelayEvidence::Healthy) => match request(probe_host, probe_port, "/json/list") {
            Ok(body) => (
                true,
                format!(
                    "browser relay: healthy at {host}:{port} ({} targets)",
                    count_targets(&body)
                ),
            ),
            Err(error) => (
                false,
                format!("browser relay: FAIL — {host}:{port} (/json/list: {error})"),
            ),
        },
    }
}

fn probe(
    request: &mut Request,
    host: &str,
    port: u16,
    path: &str,
) -> Result<RelayEvidence, String> {
    request(host, port, path).and_then(|body| classify(&body))
}

fn request(host: &str, port: u16, path: &str) -> Result<Vec<u8>, String> {
    let mut stream = super::connect(host, port)?;
    let request = format!(
        "GET {path} HTTP/1.0\r\nHost: {}:{port}\r\nConnection: close\r\n\r\n",
        url_host(host)
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|error| error.to_string())?;
    let mut body = Vec::new();
    stream
        .read_to_end(&mut body)
        .map_err(|error| error.to_string())?;
    Ok(body)
}

fn count_targets(body: &[u8]) -> usize {
    body.windows(b"\"id\":".len())
        .filter(|window| *window == b"\"id\":")
        .count()
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum RelayEvidence {
    PeerRefused,
    TokenFileMissing,
    TokenRequired,
    UpstreamDown,
    Busy,
    ExtensionDisconnected,
    Healthy,
}

pub(super) fn classify(body: &[u8]) -> Result<RelayEvidence, String> {
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

#[cfg(test)]
mod tests {
    use super::count_targets;

    #[test]
    fn count_targets_handles_relay_entries_without_websocket_urls() {
        let relay_list = br#"[{"id":"3DDE3F56ABCD1234","title":"Example","type":"page","url":"https://example.com/"},{"id":"5BAE4F23DCBA4321","title":"Search","type":"page","url":"https://search.example/"},{"id":"6C3E8D12A4B5F678","title":"Inbox","type":"page","url":"https://mail.example/"}]"#;

        assert_eq!(count_targets(relay_list), 3);
    }
}
