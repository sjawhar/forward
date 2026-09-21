//! Secure creation flow for a new encrypted secrets file.

use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::Path;
use std::process::{ChildStdout, Command, Stdio};

use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use tempfile::Builder;
use zeroize::Zeroize;

use super::super::CliError;
use super::super::agent::AgentStore;
use super::plaintext::PlaintextTemp;
use crate::config::SourceRoot;
use crate::secret::{SecretBytes, SecretName, parse_single_assignment};

const MAX_SOPS_CIPHERTEXT_BYTES: u64 = 1024 * 1024;

pub(super) fn agent(path: &Path, local: bool, roots: &[SourceRoot]) -> Result<(), CliError> {
    let role = if local {
        "# local agent-tier secrets\n"
    } else {
        "# shared agent-tier secrets\n"
    };
    create(path, role, Tier::Agent(roots))
}

pub(super) fn human(path: &Path, name: &SecretName) -> Result<(), CliError> {
    create(path, &format!("{}=\n", name.as_str()), Tier::Human(name))
}

/// Which tier a created file belongs to, with what its edited plaintext is
/// checked against before encryption.
#[derive(Clone, Copy)]
enum Tier<'a> {
    /// Agent file: no name may also be a human-tier key (re-read at publish).
    Agent(&'a [SourceRoot]),
    /// Human file: exactly one non-empty assignment of this name.
    Human(&'a SecretName),
}

/// Store a human-tier key from a non-terminal standard input stream. Runs
/// under the write lock the caller holds; each completed write is atomic.
/// Rotation replaces the ciphertext inode, so `HumanStore` detects the changed
/// `FileIdentity` and revokes stale grants.
pub(super) fn write_piped_human(path: &Path, name: &SecretName) -> Result<(), CliError> {
    crate::hardening::apply_no_core_dumps().map_err(CliError::Hardening)?;
    let assignment = read_piped_assignment(name)?;
    let rotated = path.exists();
    encrypt_bytes(&assignment, path)?;
    let action = if rotated { "rotated" } else { "created" };
    writeln!(std::io::stdout().lock(), "{action} {}", path.display()).map_err(CliError::Stdout)
}

fn create(path: &Path, prefill: &str, tier: Tier<'_>) -> Result<(), CliError> {
    let mut plaintext = PlaintextTemp::create()?;
    plaintext.write(prefill.as_bytes())?;
    run_editor(plaintext.path())?;
    plaintext.reopen_after_editor()?;
    match tier {
        Tier::Human(name) => validate_human(&mut plaintext, name)?,
        Tier::Agent(roots) => {
            // Names only; the value bytes stay in the zeroizing buffer.
            let edited = plaintext.read()?;
            super::ensure_no_human_clash(&AgentStore::names_of(edited.as_slice())?, roots)?;
        }
    }
    encrypt(&mut plaintext, path)
}

fn run_editor(path: &Path) -> Result<(), CliError> {
    let editor = std::env::var_os("VISUAL")
        .filter(|value| !value.is_empty())
        .or_else(|| std::env::var_os("EDITOR").filter(|value| !value.is_empty()))
        .unwrap_or_else(|| OsString::from("vi"));
    let status = Command::new(editor)
        .arg(path)
        .status()
        .map_err(CliError::EditorStart)?;
    if status.success() {
        Ok(())
    } else {
        Err(CliError::EditorExited)
    }
}

fn validate_human(plaintext: &mut PlaintextTemp, name: &SecretName) -> Result<(), CliError> {
    let plaintext = plaintext.read()?;
    let value = parse_single_assignment(plaintext.as_slice(), name)
        .map_err(|_| CliError::InvalidEditedHumanSecret(name.clone()))?;
    if value.is_empty() {
        Err(CliError::EmptyEditedHumanSecret(name.clone()))
    } else {
        Ok(())
    }
}
fn read_piped_assignment(name: &SecretName) -> Result<SecretBytes, CliError> {
    let stdin = std::io::stdin();

    let mut value = Vec::new();
    let read_result = stdin.lock().read_to_end(&mut value);
    if let Err(error) = read_result {
        value.zeroize();
        return Err(CliError::PipedHumanRead(error));
    }
    if value.last() == Some(&b'\n') {
        let _ = value.pop();
        if value.last() == Some(&b'\r') {
            let _ = value.pop();
        }
    }
    if value.is_empty() {
        value.zeroize();
        return Err(CliError::EmptyPipedHumanSecret(name.clone()));
    }
    if value.contains(&b'\n') || value.contains(&b'\r') {
        value.zeroize();
        return Err(CliError::InvalidPipedHumanSecret(name.clone()));
    }

    let mut assignment = Vec::new();
    assignment.extend_from_slice(name.as_str().as_bytes());
    assignment.push(b'=');
    assignment.extend_from_slice(&value);
    assignment.push(b'\n');
    value.zeroize();
    let assignment = SecretBytes::from_vec(assignment);
    if parse_single_assignment(assignment.as_slice(), name).is_err() {
        return Err(CliError::InvalidPipedHumanSecret(name.clone()));
    }
    Ok(assignment)
}

fn encrypt(plaintext: &mut PlaintextTemp, target: &Path) -> Result<(), CliError> {
    let directory = target.parent().ok_or(CliError::InstallEditedSecret)?;
    let ciphertext = Builder::new()
        .prefix(".secretsd-ciphertext-")
        .tempfile_in(directory)
        .map_err(|_| CliError::InstallEditedSecret)?;
    let input = plaintext.duplicate_at_start()?;
    let output = ciphertext
        .as_file()
        .try_clone()
        .map_err(|_| CliError::InstallEditedSecret)?;
    let mut child = sops_encrypt_command(directory, target)
        .stdin(Stdio::from(input))
        .stdout(Stdio::from(output))
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| CliError::EncryptEditedSecret(target.to_path_buf()))?;
    let stderr_result = child
        .stderr
        .take()
        .ok_or_else(|| CliError::EncryptEditedSecret(target.to_path_buf()))
        .and_then(|mut stderr| {
            std::io::copy(&mut stderr, &mut std::io::sink())
                .map(|_| ())
                .map_err(|_| CliError::EncryptEditedSecret(target.to_path_buf()))
        });
    let status = child
        .wait()
        .map_err(|_| CliError::EncryptEditedSecret(target.to_path_buf()))?;
    if stderr_result.is_err() || !status.success() {
        return Err(CliError::EncryptEditedSecret(target.to_path_buf()));
    }
    ciphertext
        .persist_noclobber(target)
        .map(|_| ())
        .map_err(|_| CliError::InstallEditedSecret)
}

fn sops_encrypt_command(directory: &Path, target: &Path) -> Command {
    let mut command = Command::new("sops");
    command
        .current_dir(directory)
        .arg("encrypt")
        .arg("--filename-override")
        .arg(target)
        .args(["--input-type", "dotenv", "--output-type", "dotenv"]);
    command
}

/// Why draining the sops child's stdout failed, so the caller can say which.
enum DrainFailure {
    /// Reading the pipe failed outright.
    Read,
    /// The child produced more than `MAX_SOPS_CIPHERTEXT_BYTES`.
    TooLarge,
}

fn drain_sops_stdout(mut stdout: ChildStdout, process_id: Pid) -> Result<Vec<u8>, DrainFailure> {
    let mut output = Vec::new();
    let read_result = stdout
        .by_ref()
        .take(MAX_SOPS_CIPHERTEXT_BYTES + 1)
        .read_to_end(&mut output);
    let output_too_large =
        u64::try_from(output.len()).map_or(true, |length| length > MAX_SOPS_CIPHERTEXT_BYTES);
    if read_result.is_err() || output_too_large {
        output.zeroize();
        let _ = kill(process_id, Signal::SIGKILL);
        return Err(if read_result.is_err() {
            DrainFailure::Read
        } else {
            DrainFailure::TooLarge
        });
    }
    Ok(output)
}

fn encrypt_bytes(plaintext: &SecretBytes, target: &Path) -> Result<(), CliError> {
    let directory = target.parent().ok_or(CliError::InstallEditedSecret)?;
    let mut child = sops_encrypt_command(directory, target)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| CliError::EncryptEditedSecret(target.to_path_buf()))?;
    let process_id = i32::try_from(child.id())
        .map(Pid::from_raw)
        .map_err(|_| CliError::EncryptEditedSecret(target.to_path_buf()))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| CliError::EncryptEditedSecret(target.to_path_buf()))?;
    let stdout_reader = std::thread::spawn(move || drain_sops_stdout(stdout, process_id));
    let mut stderr = child
        .stderr
        .take()
        .ok_or_else(|| CliError::EncryptEditedSecret(target.to_path_buf()))?;
    let stderr_reader =
        std::thread::spawn(move || std::io::copy(&mut stderr, &mut std::io::sink()));
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| CliError::EncryptEditedSecret(target.to_path_buf()))?;
    let write_result = stdin.write_all(plaintext.as_slice());
    drop(stdin);
    let status = child.wait();
    let stdout_result = stdout_reader.join();
    let stderr_result = stderr_reader.join();
    let mut output = match stdout_result {
        Ok(Ok(output)) => output,
        Ok(Err(DrainFailure::TooLarge)) => {
            return Err(CliError::SopsCiphertextTooLarge {
                limit: MAX_SOPS_CIPHERTEXT_BYTES,
            });
        }
        Ok(Err(DrainFailure::Read)) | Err(_) => {
            return Err(CliError::EncryptEditedSecret(target.to_path_buf()));
        }
    };
    if write_result.is_err()
        || !matches!(status, Ok(status) if status.success())
        || !matches!(stderr_result, Ok(Ok(_)))
    {
        output.zeroize();
        return Err(CliError::EncryptEditedSecret(target.to_path_buf()));
    }

    let mut ciphertext = Builder::new()
        .prefix(".secretsd-ciphertext-")
        .tempfile_in(directory)
        .map_err(|_| CliError::InstallEditedSecret)?;
    let write_result = ciphertext.as_file_mut().write_all(&output);
    output.zeroize();
    write_result.map_err(|_| CliError::InstallEditedSecret)?;
    ciphertext
        .persist(target)
        .map(|_| ())
        .map_err(|_| CliError::InstallEditedSecret)
}
