//! Running sops to decrypt one key.

use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use nix::fcntl::{FcntlArg, fcntl};
use nix::sys::signal::{Signal, killpg};
use nix::unistd::Pid;
use zeroize::Zeroize;

use crate::proto::ErrCode;
use crate::secret::{SecretBytes, SecretName, parse_single_assignment};
use crate::store::{FileIdentity, HumanStore, OpenedHumanFile};

mod classify;

use classify::{classify_sops_stderr, failure_code};

/// Polling period while a sops child is active.
const POLL_INTERVAL: Duration = Duration::from_millis(50);
const MAX_SOPS_STDERR_BYTES: u64 = 300;

fn duplicate_ciphertext_fd(validated: &std::fs::File) -> Result<std::fs::File, ErrCode> {
    // `F_DUPFD`, not `_CLOEXEC`: the sops child reads the ciphertext through it.
    let inherited_raw_fd = fcntl(validated, FcntlArg::F_DUPFD(3)).map_err(|_| ErrCode::Internal)?;
    // SAFETY: `F_DUPFD` returned a fresh non-CLOEXEC descriptor with a unique close-on-drop
    // obligation, which this `File` assumes and discharges.
    Ok(unsafe { std::fs::File::from_raw_fd(inherited_raw_fd) })
}

/// A bounded command that verifies a PC/SC bridge reaches the `YubiKey`.
#[derive(Debug, Clone)]
pub struct YubikeyProbe {
    command: PathBuf,
    args: Vec<String>,
    timeout: Duration,
}

impl YubikeyProbe {
    /// Build a probe command with an explicit timeout.
    pub const fn new(command: PathBuf, args: Vec<String>, timeout: Duration) -> Self {
        Self {
            command,
            args,
            timeout,
        }
    }

    /// Build the configured probe, or no probe when its command is empty.
    pub fn from_argv(command_argv: &[String], timeout: Duration) -> Option<Self> {
        let (command, args) = command_argv.split_first()?;
        Some(Self::new(PathBuf::from(command), args.to_vec(), timeout))
    }

    fn responds(&self) -> bool {
        let Some(deadline) = Instant::now().checked_add(self.timeout) else {
            return false;
        };
        let Ok(mut child) = Command::new(&self.command)
            .args(&self.args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn()
        else {
            return false;
        };
        let Ok(process_id) = i32::try_from(child.id()) else {
            let _ = child.kill();
            let _ = child.wait();
            return false;
        };

        loop {
            match child.try_wait() {
                Ok(Some(status)) => return status.success(),
                Ok(None) if Instant::now() >= deadline => {
                    terminate_process_group(&mut child, process_id);
                    return false;
                }
                Ok(None) => std::thread::sleep(POLL_INTERVAL),
                Err(_) => {
                    terminate_process_group(&mut child, process_id);
                    return false;
                }
            }
        }
    }
}

fn terminate_process_group(child: &mut std::process::Child, process_id: i32) {
    let _ = killpg(Pid::from_raw(process_id), Signal::SIGKILL);
    let _ = child.wait();
}

/// PC/SC socket and optional far-end liveness probe used before a decrypt.
#[derive(Debug, Clone)]
pub struct PcscReachability {
    socket: Option<PathBuf>,
    probe: Option<YubikeyProbe>,
}

impl PcscReachability {
    /// Build a reachability check for direct or bridged PC/SC access.
    pub const fn new(socket: Option<PathBuf>, probe: Option<YubikeyProbe>) -> Self {
        Self { socket, probe }
    }

    fn is_reachable(&self) -> bool {
        self.socket.as_ref().is_none_or(|path| {
            path.exists() && self.probe.as_ref().is_none_or(YubikeyProbe::responds)
        })
    }
}

/// Runs sops against one ciphertext file.
#[derive(Debug, Clone)]
pub struct Decryptor {
    sops_bin: PathBuf,
    timeout: Duration,
    reachability: PcscReachability,
}

pub(crate) struct DecryptedHumanFile {
    pub(crate) source: String,
    pub(crate) identity: FileIdentity,
    pub(crate) value: SecretBytes,
}

impl Decryptor {
    /// Build a decryptor.
    pub const fn new(sops_bin: PathBuf, timeout: Duration, reachability: PcscReachability) -> Self {
        Self {
            sops_bin,
            timeout,
            reachability,
        }
    }

    /// Whether hardware is reachable without triggering a touch.
    pub fn reachable(&self) -> bool {
        self.reachability.is_reachable()
    }

    /// Decrypt one validated human-tier file.
    pub fn decrypt(&self, store: &HumanStore, key: &SecretName) -> Result<SecretBytes, ErrCode> {
        self.decrypt_with_start(store, key, |_| {})
    }

    /// Decrypt one validated human-tier file and report its process group at spawn.
    pub fn decrypt_with_start<F>(
        &self,
        store: &HumanStore,
        key: &SecretName,
        on_started: F,
    ) -> Result<SecretBytes, ErrCode>
    where
        F: FnOnce(i32),
    {
        self.decrypt_opened_with_start(store, key, on_started)
            .map(|decrypted| decrypted.value)
    }

    pub(crate) fn decrypt_opened_with_start<F>(
        &self,
        store: &HumanStore,
        key: &SecretName,
        on_started: F,
    ) -> Result<DecryptedHumanFile, ErrCode>
    where
        F: FnOnce(i32),
    {
        if !self.reachable() {
            return Err(ErrCode::YubikeyUnreachable);
        }
        let OpenedHumanFile {
            label: source,
            identity,
            file: validated,
        } = store.open(key)?;
        let inherited = duplicate_ciphertext_fd(&validated)?;
        let fd_path = format!("/proc/self/fd/{}", inherited.as_raw_fd());
        let mut child = Command::new(&self.sops_bin)
            .arg("-d")
            .arg("--input-type")
            .arg("dotenv")
            .arg("--output-type")
            .arg("dotenv")
            .arg(fd_path)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0)
            .spawn()
            .map_err(|error| {
                // The INTERNAL guidance sends the human to journald for the cause,
                // and a spawn that never happened has no stderr to classify: this
                // is the only record. The io error names the binary and the reason
                // (missing, not executable) and cannot carry secret material.
                tracing::warn!(
                    sops_bin = %self.sops_bin.display(),
                    %error,
                    "could not spawn sops"
                );
                ErrCode::Internal
            })?;
        let process_id = i32::try_from(child.id()).map_err(|_| ErrCode::Internal)?;
        on_started(process_id);
        let deadline = Instant::now()
            .checked_add(self.timeout)
            .ok_or(ErrCode::Internal)?;

        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    let mut stderr = Vec::new();
                    let read_result = child
                        .stderr
                        .take()
                        .ok_or(ErrCode::Internal)?
                        .by_ref()
                        .take(MAX_SOPS_STDERR_BYTES)
                        .read_to_end(&mut stderr);
                    let stderr_bytes = stderr.len();
                    let failure = match read_result {
                        Ok(_) => classify_sops_stderr(&stderr),
                        Err(_) => "stderr-unreadable",
                    };
                    stderr.zeroize();
                    if !status.success() {
                        tracing::warn!(
                            %status,
                            sops_failure = failure,
                            sops_stderr_bytes = stderr_bytes,
                            "sops decrypt failed"
                        );
                        return Err(failure_code(failure));
                    }
                    let mut stdout = Vec::new();
                    let mut stdout_pipe = child.stdout.take().ok_or(ErrCode::Internal)?;
                    if stdout_pipe.read_to_end(&mut stdout).is_err() {
                        stdout.zeroize();
                        return Err(ErrCode::Internal);
                    }
                    let result = parse_single_assignment(&stdout, key);
                    stdout.zeroize();
                    return result.map(|value| DecryptedHumanFile {
                        source,
                        identity,
                        value,
                    });
                }
                Ok(None) if Instant::now() >= deadline => {
                    let _ = killpg(Pid::from_raw(process_id), Signal::SIGKILL);
                    let _ = child.wait();
                    return Err(ErrCode::Timeout);
                }
                Ok(None) => std::thread::sleep(POLL_INTERVAL),
                Err(_) => return Err(ErrCode::Internal),
            }
        }
    }
}

#[cfg(test)]
mod tests;
