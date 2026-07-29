use crate::config::Config;
use crate::process::{WaitResult, run_command, stderr};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::process::Command;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

const SSH_TIMEOUT: Duration = Duration::from_secs(5);
const REAPER_INTERVAL: Duration = Duration::from_millis(100);
pub const PCSC_PORT: u16 = 12_799;
pub const CHANNEL_PORT: u16 = 12_800;
pub const FILES_PORT: u16 = 12_802;
const STATIC_TUNNEL_PORTS: [u16; 3] = [PCSC_PORT, CHANNEL_PORT, FILES_PORT];

#[derive(Clone)]
pub struct ForwardTracker {
    leases: Arc<Mutex<HashMap<u16, Lease>>>,
}

struct Lease {
    deadline: Instant,
    active: bool,
}

impl ForwardTracker {
    pub fn new() -> Self {
        Self {
            leases: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn reserve(&self, port: u16, ttl: Duration) -> bool {
        let deadline = Instant::now() + ttl;
        let mut leases = self.leases.lock();
        match leases.get_mut(&port) {
            Some(lease) => {
                lease.deadline = deadline;
                false
            }
            None => {
                leases.insert(
                    port,
                    Lease {
                        deadline,
                        active: false,
                    },
                );
                true
            }
        }
    }

    fn finish_creation(&self, port: u16, succeeded: bool) {
        let mut leases = self.leases.lock();
        if succeeded {
            if let Some(lease) = leases.get_mut(&port) {
                lease.active = true;
            }
        } else {
            leases.remove(&port);
        }
    }

    fn expired(&self) -> Vec<u16> {
        let now = Instant::now();
        let mut expired = Vec::new();
        self.leases.lock().retain(|port, lease| {
            let release = lease.active && lease.deadline <= now;
            if release {
                expired.push(*port);
            }
            !release
        });
        expired
    }
}

pub fn is_dynamic_port(port: u16) -> bool {
    !STATIC_TUNNEL_PORTS.contains(&port)
}

pub fn request_forward(cfg: &Config, tracker: &ForwardTracker, port: u16) {
    if !is_dynamic_port(port) {
        return;
    }
    if !tracker.reserve(port, Duration::from_secs(cfg.forward_ttl_secs)) {
        eprintln!("forward: refreshed SSH forward lease for port {port}");
        return;
    }
    let succeeded = run_ssh(cfg, "forward", port, "forwarding");
    tracker.finish_creation(port, succeeded);
    if succeeded {
        eprintln!("forward: SSH forward created for port {port}");
    }
}

pub fn spawn_reaper(cfg: Config, tracker: ForwardTracker) {
    if let Err(error) = thread::Builder::new()
        .name("forward-reaper".to_owned())
        .spawn(move || {
            loop {
                thread::sleep(REAPER_INTERVAL);
                for port in tracker.expired() {
                    if run_ssh(&cfg, "cancel", port, "forward release") {
                        eprintln!("forward: SSH forward released for port {port}");
                    }
                }
            }
        })
    {
        eprintln!("forward: failed to start SSH forward reaper: {error}");
    }
}

fn run_ssh(cfg: &Config, operation: &str, port: u16, action: &str) -> bool {
    let Some(command) = ssh_command(cfg, operation, port) else {
        eprintln!("forward: SSH command is empty; cannot {action} port {port}");
        return false;
    };
    match run_command(command, SSH_TIMEOUT) {
        Ok(WaitResult::Exited(output)) if output.status.success() => true,
        Ok(WaitResult::Exited(output)) => {
            eprintln!(
                "forward: SSH {action} failed for port {port}: {:?}",
                stderr(&output)
            );
            false
        }
        Ok(WaitResult::TimedOut(output)) => {
            eprintln!(
                "forward: SSH {action} timed out for port {port}: {:?}",
                stderr(&output)
            );
            false
        }
        Err(error) => {
            eprintln!("forward: failed during SSH {action} for port {port}: {error}");
            false
        }
    }
}

fn ssh_command(cfg: &Config, operation: &str, port: u16) -> Option<Command> {
    let (program, arguments) = cfg.ssh.split_first()?;
    let spec = format!("127.0.0.1:{port}:127.0.0.1:{port}");
    let mut command = Command::new(program);
    command.args(arguments).args([
        "-O",
        operation,
        "-L",
        spec.as_str(),
        cfg.tunnel_host.as_str(),
    ]);
    Some(command)
}
