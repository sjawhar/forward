#[cfg(test)]
use std::net::SocketAddr;

use tiny_http::Request;

use crate::config::Config;
use crate::peer::authorized_remote;

const LOOPBACK_HEALTH_PATH: &str = "/etc/hostname";

/// Whether an inbound connection's source address may read a preview.
///
/// `tiny_http` parses the request before `respond` can run this check, so a
/// refused peer still reaches the HTTP parser. That residual exposure is
/// accepted: it is parser exposure, not file-read exposure. This check is the
/// authorization control for file reads.
///
/// The configured laptop peer may preview any path the serving user can read:
/// `forward url` deliberately supports arbitrary paths and the laptop already
/// has SSH access to the same account. Loopback is not equivalent to the
/// configured peer on a tailnet-bound listener — any local uid can originate a
/// loopback connection to it — so loopback is refused for all previews except
/// the fixed, world-readable doctor probe at `/etc/hostname`.
pub(super) fn peer_allowed(cfg: &Config, request: &Request) -> bool {
    loopback_health_probe(request)
        || request
            .remote_addr()
            .is_some_and(|remote| authorized_remote(cfg, remote.ip()))
}

/// Whether the `Host` header names the address this server was configured to
/// listen on.
///
/// The check stops DNS rebinding. The one exception is the loopback doctor
/// probe, which `peer_allowed` has already constrained to the fixed,
/// world-readable health path; its loopback `Host` value is not the configured
/// tailnet address.
pub(super) fn host_allowed(cfg: &Config, request: &Request) -> bool {
    if loopback_health_probe(request) {
        return true;
    }
    let header = request
        .headers()
        .iter()
        .find(|header| header.field.equiv("Host"));
    host_value_allowed(cfg, header.map(|header| header.value.as_str()))
}

fn loopback_health_probe(request: &Request) -> bool {
    request.url() == LOOPBACK_HEALTH_PATH
        && request
            .remote_addr()
            .is_some_and(|remote| remote.ip().to_canonical().is_loopback())
}

#[cfg(test)]
fn peer_addr_allowed(cfg: &Config, remote: Option<&SocketAddr>) -> bool {
    // `None` means tiny_http could not report a source address, which only
    // happens for a unix-socket listener forward never builds. Refusing is the
    // fail-closed reading of "we do not know who this is".
    remote.is_some_and(|remote| authorized_remote(cfg, remote.ip()))
}

fn host_value_allowed(cfg: &Config, value: Option<&str>) -> bool {
    let Some(value) = value else {
        return false;
    };
    let value = value.to_ascii_lowercase();
    let Some(host) = host_part(&value) else {
        return false;
    };
    if host == cfg.listen.to_ascii_lowercase() {
        return true;
    }
    matches!(cfg.listen_ip(), Ok(listen) if listen.is_loopback())
        && matches!(host, "localhost" | "127.0.0.1" | "::1")
}

/// The host part of a `Host` header value, with IPv6 brackets removed so it can
/// be compared against a literal `listen` address, which carries none.
///
/// Returns `None` when the value carries something that is not a port, so a
/// malformed header is refused rather than silently truncated to a host.
fn host_part(value: &str) -> Option<&str> {
    if let Some(rest) = value.strip_prefix('[') {
        let (host, tail) = rest.split_once(']')?;
        if tail.is_empty()
            || tail
                .strip_prefix(':')
                .is_some_and(|port| port.parse::<u16>().is_ok())
        {
            return Some(host);
        }
        return None;
    }
    match value.split_once(':') {
        Some((host, port)) if port.parse::<u16>().is_ok() => Some(host),
        Some(_) => None,
        None => Some(value),
    }
}

#[cfg(test)]
mod tests;
