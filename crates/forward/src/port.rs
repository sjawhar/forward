use std::collections::BTreeSet;
use std::io::Write as _;
use std::thread;
use std::time::Duration;

use forward::bridge::{self, HoldError};
use forward::config::Config;
use forward::send::{self, HoldReply, SendError};

/// How often the laptop's listeners are renewed.
const RENEW_EVERY: Duration = Duration::from_secs(60);
/// How long one renewal keeps a laptop listener: three renewals' worth, so a
/// single slow or lost round trip never drops a page that is in use.
const LAPTOP_LEASE_SECS: u64 = 3 * RENEW_EVERY.as_secs();

#[derive(Debug, thiserror::Error)]
pub(crate) enum PortError {
    #[error(transparent)]
    Hold(#[from] HoldError),
    #[error(transparent)]
    Send(#[from] SendError),
    #[error("forward: the laptop refused port {port}: {reason}")]
    LaptopRefused { port: u16, reason: String },
}

/// Point laptop `localhost:<port>` at this machine's loopback `<port>`, for
/// every port given, until the process is stopped.
///
/// "This machine" is wherever the process runs: inside an agent box it is the
/// box's loopback, because the box's own holder does the dialling.
pub(crate) fn run(cfg: &Config, ports: &[u16], channel_port: u16) -> Result<(), PortError> {
    let mut unique = Vec::with_capacity(ports.len());
    for port in ports {
        if !unique.contains(port) {
            unique.push(*port);
        }
    }
    let path = bridge::arm_socket_path();
    let holds = unique
        .iter()
        .map(|port| bridge::hold(&path, *port))
        .collect::<Result<Vec<_>, _>>()?;
    for port in &unique {
        renew(cfg, *port, channel_port)?;
    }
    let mut stdout = std::io::stdout();
    for held in holds {
        let port = held.port();
        drop(thread::spawn(move || {
            // Without its hold the forward is dead on the devbox side, so exit
            // and let whatever supervises this process see it.
            eprintln!("{}", held.serve());
            std::process::exit(1);
        }));
        let _ = writeln!(
            stdout,
            "forward: laptop localhost:{port} -> 127.0.0.1:{port} here"
        );
    }
    let _ = writeln!(stdout, "forward: holding until stopped");
    let mut failing = BTreeSet::new();
    loop {
        thread::sleep(RENEW_EVERY);
        for port in &unique {
            match renew(cfg, *port, channel_port) {
                Ok(()) if failing.remove(port) => {
                    eprintln!("forward: laptop port {port} renewed again");
                }
                Ok(()) => {}
                Err(error) if failing.insert(*port) => {
                    eprintln!("{error}; the devbox side stays held, retrying every minute");
                }
                Err(_) => {}
            }
        }
    }
}

fn renew(cfg: &Config, port: u16, channel_port: u16) -> Result<(), PortError> {
    match send::send_hold(cfg, port, LAPTOP_LEASE_SECS, channel_port)? {
        HoldReply::Held => Ok(()),
        HoldReply::Refused(reason) => Err(PortError::LaptopRefused { port, reason }),
    }
}
