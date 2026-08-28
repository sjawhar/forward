use std::fmt::Display;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use crate::config::Config;
use crate::target::url_host;

const PROBE_TIMEOUT: Duration = Duration::from_secs(3);
const PREVIEW_PROBE_PATH: &str = "/etc/hostname";

type Probe = fn(&str, u16) -> Result<ProbeEvidence, String>;

#[derive(Clone, Copy)]
enum ProbeEvidence {
    TcpAccepted,
    FileServed,
    FileAccessRefused,
    BridgeDenied,
    BridgePeerRefused,
}

impl ProbeEvidence {
    fn observation(self, host: &str, port: u16) -> String {
        match self {
            Self::TcpAccepted => format!("accepted TCP at {host}:{port}; delivery unverified"),
            Self::FileServed => format!("served probe file at {host}:{port}"),
            Self::FileAccessRefused => {
                format!("reachable and correctly refused self-probe at {host}:{port} (HTTP 403)")
            }
            Self::BridgeDenied => format!(
                "confirmed denied-port refusal at {host}:{port}; active relay delivery unverified"
            ),
            Self::BridgePeerRefused => format!(
                "reachable and correctly refused self-probe at {host}:{port}; active relay delivery unverified"
            ),
        }
    }

    const fn failure_reason(self) -> &'static str {
        match self {
            Self::TcpAccepted | Self::FileServed | Self::BridgeDenied => {
                "internal doctor evidence classification error"
            }
            Self::FileAccessRefused => "HTTP 403 from a vantage that should be served",
            Self::BridgePeerRefused => "peer refusal from a vantage that should be served",
        }
    }
}

fn probe_hosts(cfg: &Config) -> Vec<String> {
    let mut hosts = Vec::new();
    for host in [cfg.listen.as_str(), "127.0.0.1", cfg.peer.as_str()] {
        if !host.is_empty() && !hosts.iter().any(|existing| existing == host) {
            hosts.push(host.to_owned());
        }
    }
    hosts
}

/// Report evidence for each channel and return whether none contradicts its protocol.
pub fn run(cfg: &Config, channel_port: u16, files_port: u16) -> bool {
    let hosts = probe_hosts(cfg);
    let url = channel(cfg, &hosts, "url channel", channel_port, probe_url_channel);
    let preview = channel(cfg, &hosts, "file preview", files_port, probe_file_preview);
    let bridge = channel(
        cfg,
        &hosts,
        "callback bridge",
        cfg.bridge_port,
        probe_bridge,
    );
    let relay = browser::report(cfg);
    grant::report();
    let feed = optional_channel(cfg, &hosts, "browser feed", "grant_port", cfg.grant_port);
    let pcsc_channel = optional_channel(cfg, &hosts, "pcsc channel", "pcsc_port", cfg.pcsc_port);
    let pcsc_socket = pcsc::report(cfg);
    let pulse_channel =
        optional_channel(cfg, &hosts, "pulse channel", "pulse_port", cfg.pulse_port);
    let pulse_socket = pulse::report(cfg);
    url && preview
        && bridge
        && relay
        && feed
        && pcsc_channel
        && pcsc_socket
        && pulse_channel
        && pulse_socket
}

/// Report one TCP channel across the probe hosts.
fn channel(cfg: &Config, hosts: &[String], name: &'static str, port: u16, probe: Probe) -> bool {
    let mut failures = Vec::new();
    for host in hosts {
        match probe(host, port) {
            Ok(evidence) if evidence_is_healthy(cfg, host, evidence) => {
                print_line(format_args!("{name}: {}", evidence.observation(host, port)));
                return true;
            }
            Ok(evidence) => failures.push(format!("{host}:{port} ({})", evidence.failure_reason())),
            Err(reason) => failures.push(format!("{host}:{port} ({reason})")),
        }
    }
    print_line(format_args!("{name}: FAIL — tried {}", failures.join(", ")));
    false
}

/// Report a plain TCP channel that a zero port deliberately disables.
fn optional_channel(
    cfg: &Config,
    hosts: &[String],
    name: &'static str,
    field: &'static str,
    port: u16,
) -> bool {
    if port == 0 {
        print_line(format_args!("{name}: disabled ({field} = 0)"));
        return true;
    }
    channel(cfg, hosts, name, port, probe_url_channel)
}

fn evidence_is_healthy(cfg: &Config, host: &str, evidence: ProbeEvidence) -> bool {
    match evidence {
        ProbeEvidence::FileAccessRefused | ProbeEvidence::BridgePeerRefused => {
            host == cfg.listen && matches!(cfg.listen_ip(), Ok(address) if !address.is_loopback())
        }
        ProbeEvidence::TcpAccepted | ProbeEvidence::FileServed | ProbeEvidence::BridgeDenied => {
            true
        }
    }
}

fn connect(host: &str, port: u16) -> Result<TcpStream, String> {
    let address = (host, port)
        .to_socket_addrs()
        .map_err(|error| error.to_string())?
        .next()
        .ok_or_else(|| "no address".to_owned())?;
    let stream =
        TcpStream::connect_timeout(&address, PROBE_TIMEOUT).map_err(|error| error.to_string())?;
    stream
        .set_read_timeout(Some(PROBE_TIMEOUT))
        .map_err(|error| error.to_string())?;
    Ok(stream)
}

/// Connect and close without sending a URL, which the daemon discards as empty input.
fn probe_url_channel(host: &str, port: u16) -> Result<ProbeEvidence, String> {
    connect(host, port).map(|_| ProbeEvidence::TcpAccepted)
}

fn probe_file_preview(host: &str, port: u16) -> Result<ProbeEvidence, String> {
    let mut stream = connect(host, port)?;
    let request = format!(
        "GET {PREVIEW_PROBE_PATH} HTTP/1.0\r\nHost: {}\r\nConnection: close\r\n\r\n",
        url_host(host)
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|error| error.to_string())?;
    let mut status = [0_u8; 12];
    stream
        .read_exact(&mut status)
        .map_err(|error| error.to_string())?;
    let line = String::from_utf8_lossy(&status).into_owned();
    if line.ends_with(" 200") {
        Ok(ProbeEvidence::FileServed)
    } else if line.ends_with(" 403") {
        Ok(ProbeEvidence::FileAccessRefused)
    } else {
        Err(format!("{PREVIEW_PROBE_PATH} answered {line:?}"))
    }
}

fn probe_bridge(host: &str, port: u16) -> Result<ProbeEvidence, String> {
    let mut stream = connect(host, port)?;
    stream
        .write_all(b"CONNECT 0\n")
        .map_err(|error| error.to_string())?;
    let mut body = Vec::new();
    match stream.read_to_end(&mut body) {
        Ok(_) if body == b"REFUSED DENIED\n" => Ok(ProbeEvidence::BridgeDenied),
        Ok(_) if body == b"REFUSED PEER\n" => Ok(ProbeEvidence::BridgePeerRefused),
        Ok(0) => Err("closed without a protocol refusal".to_owned()),
        Ok(count) => Err(format!("unexpected {count}-byte response {body:?}")),
        Err(error) => Err(error.to_string()),
    }
}

fn print_line(message: impl Display) {
    let _ = writeln!(std::io::stdout(), "{message}");
}

mod browser;
mod grant;
mod pcsc;
mod pulse;

#[cfg(test)]
mod browser_tests;

#[cfg(test)]
mod tests;
