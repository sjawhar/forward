use std::net::IpAddr;
use std::time::Duration;

use forward::callback::{
    FILES_PORT, Leases, MAX_DYNAMIC_FORWARDS, ServeError, is_dynamic_port, serve_on,
};
use forward::config::Config;
use forward::localhost::forward_ports;
use forward::target::url_host;

/// Only the accepted socket's identity chooses callbacks and automatic preview
/// permission. Legacy tunnel pairs keep their configured loopback/custom ports.
pub(super) fn config(mut cfg: Config, origin: IpAddr) -> Config {
    if cfg.is_multi_peer() {
        cfg.peer = origin.to_canonical().to_string();
        cfg.peers = None;
        cfg.allow
            .push(format!("{}:{FILES_PORT}", url_host(&cfg.peer)));
    }
    cfg
}

pub(super) fn forward_url(
    cfg: &Config,
    url: &url::Url,
    leases: &Leases,
    strict: bool,
) -> Result<(), ServeError> {
    let ports = forward_ports(url);
    if strict && ports.len() > MAX_DYNAMIC_FORWARDS {
        return Err(ServeError::TooMany);
    }
    let mut forwarded = 0;
    let mut dropped = 0;
    for port in ports {
        if !is_dynamic_port(cfg, port) {
            if strict {
                return Err(ServeError::Reserved { port });
            }
            continue;
        }
        if forwarded == MAX_DYNAMIC_FORWARDS {
            dropped += 1;
            continue;
        }
        match serve_on(cfg, leases, port, Duration::from_secs(cfg.forward_ttl_secs)) {
            // Opening a URL after this refusal would send its OAuth callback
            // into the other VM's live listener. Refuse the URL as well.
            Err(error @ ServeError::Owned { .. }) => return Err(error),
            Err(error) if strict => return Err(error),
            Err(error) => eprintln!("forward: {error}"),
            Ok(_) => {}
        }
        forwarded += 1;
    }
    if dropped > 0 {
        eprintln!("forward: dynamic forward limit reached; dropped {dropped} port(s)");
    }
    Ok(())
}
