use crate::callback::RELAY_TARGET_PORT;
use crate::config::Config;
use crate::target::url_host;
use std::io::{Read, Write};

pub(super) fn report(cfg: &Config) -> bool {
    let (healthy, line) = evaluate(cfg, crate::config::default_relay_port());
    super::print_line(line);
    healthy
}

pub(super) fn evaluate(cfg: &Config, well_known_port: u16) -> (bool, String) {
    if cfg.relay_port == 0 && cfg.peer.is_empty() {
        return (true, "browser relay: disabled (relay_port = 0)".to_owned());
    }

    if cfg.relay_port == 0 {
        return report_probe(
            probe(&cfg.peer, well_known_port, "/json/version"),
            &cfg.peer,
            well_known_port,
            &cfg.peer,
            well_known_port,
        );
    }

    let result = probe(&cfg.listen, cfg.relay_port, "/json/version");
    if matches!(result, Ok(RelayEvidence::PeerRefused))
        && matches!(cfg.listen_ip(), Ok(address) if !address.is_loopback())
    {
        return report_laptop_upstream(
            probe("127.0.0.1", RELAY_TARGET_PORT, "/json/version"),
            &cfg.listen,
            cfg.relay_port,
        );
    }
    report_probe(
        result,
        &cfg.listen,
        cfg.relay_port,
        &cfg.listen,
        cfg.relay_port,
    )
}

pub(super) fn report_laptop_upstream(
    result: Result<RelayEvidence, String>,
    host: &str,
    port: u16,
) -> (bool, String) {
    match result {
        Err(_) | Ok(RelayEvidence::UpstreamDown) => (
            false,
            format!(
                "browser relay: FAIL — relay process down — start omp-browser-relay (via {host}:{port})"
            ),
        ),
        result => report_probe(result, host, port, "127.0.0.1", RELAY_TARGET_PORT),
    }
}

fn report_probe(
    result: Result<RelayEvidence, String>,
    host: &str,
    port: u16,
    probe_host: &str,
    probe_port: u16,
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

fn probe(host: &str, port: u16, path: &str) -> Result<RelayEvidence, String> {
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
    body.windows(b"webSocketDebuggerUrl".len())
        .filter(|window| *window == b"webSocketDebuggerUrl")
        .count()
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum RelayEvidence {
    PeerRefused,
    UpstreamDown,
    Busy,
    ExtensionDisconnected,
    Healthy,
}

pub(super) fn classify(body: &[u8]) -> Result<RelayEvidence, String> {
    if body.starts_with(b"REFUSED PEER") {
        return Ok(RelayEvidence::PeerRefused);
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
