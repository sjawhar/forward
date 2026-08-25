use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

pub(crate) struct CommandOutput {
    pub(crate) status: ExitStatus,
    pub(crate) stdout: Vec<u8>,
    stderr: Vec<u8>,
}
pub(crate) enum WaitResult {
    Exited(CommandOutput),
    TimedOut,
}

pub(crate) fn run_command(mut command: Command, timeout: Duration) -> std::io::Result<WaitResult> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn()?;
    let Some(stdout) = child.stdout.take() else {
        return reap_setup_error(child, "stdout was not piped");
    };
    let Some(stderr) = child.stderr.take() else {
        return reap_setup_error(child, "stderr was not piped");
    };
    let stdout_reader = drain(stdout);
    let stderr_reader = drain(stderr);
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                return collect_output(status, stdout_reader, stderr_reader)
                    .map(WaitResult::Exited);
            }
            Ok(None) if Instant::now() >= deadline => {
                let kill_error = child.kill().err();
                let status = child.wait();
                collect_output(status?, stdout_reader, stderr_reader)?;
                return match kill_error {
                    Some(error) => Err(error),
                    None => Ok(WaitResult::TimedOut),
                };
            }
            Ok(None) => thread::sleep(Duration::from_millis(10)),
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout_reader.join();
                let _ = stderr_reader.join();
                return Err(error);
            }
        }
    }
}
pub(crate) fn stderr(output: &CommandOutput) -> String {
    String::from_utf8_lossy(&output.stderr).trim().to_owned()
}
fn reap_setup_error(mut child: Child, message: &str) -> std::io::Result<WaitResult> {
    let _ = child.kill();
    let _ = child.wait();
    Err(std::io::Error::other(message))
}
fn drain<R: std::io::Read + Send + 'static>(
    mut reader: R,
) -> thread::JoinHandle<std::io::Result<Vec<u8>>> {
    thread::spawn(move || {
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes)?;
        Ok(bytes)
    })
}
fn collect_output(
    status: ExitStatus,
    stdout: thread::JoinHandle<std::io::Result<Vec<u8>>>,
    stderr: thread::JoinHandle<std::io::Result<Vec<u8>>>,
) -> std::io::Result<CommandOutput> {
    Ok(CommandOutput {
        status,
        stdout: join_reader(stdout)?,
        stderr: join_reader(stderr)?,
    })
}
fn join_reader(reader: thread::JoinHandle<std::io::Result<Vec<u8>>>) -> std::io::Result<Vec<u8>> {
    reader
        .join()
        .map_err(|_| std::io::Error::other("subprocess output reader panicked"))?
}

#[cfg(test)]
mod tests {
    use std::process::Command;
    use std::time::Duration;

    use super::{WaitResult, run_command};

    #[test]
    fn captures_stdout_when_command_exits() {
        let mut command = Command::new("sh");
        command.args(["-c", "printf expected"]);

        let result = run_command(command, Duration::from_secs(1)).unwrap();

        let WaitResult::Exited(output) = result else {
            panic!("command should exit before its timeout");
        };
        assert!(output.status.success());
        assert_eq!(output.stdout, b"expected");
    }

    #[test]
    fn timeout_kills_and_reaps_child() {
        let directory = tempfile::tempdir().unwrap();
        let pid_file = directory.path().join("pid");
        let mut command = Command::new("sh");
        command.args([
            "-c",
            &format!("echo $$ > {}; exec sleep 10", pid_file.display()),
        ]);

        let result = run_command(command, Duration::from_millis(200)).unwrap();

        assert!(matches!(result, WaitResult::TimedOut));
        let pid = std::fs::read_to_string(pid_file).unwrap();
        assert!(!std::path::Path::new(&format!("/proc/{}", pid.trim())).exists());
    }

    #[test]
    fn drains_large_stderr_without_blocking() {
        let mut command = Command::new("sh");
        command.args(["-c", "head -c 100000 /dev/zero | tr '\\0' x >&2"]);

        let result = run_command(command, Duration::from_secs(1)).unwrap();

        let WaitResult::Exited(output) = result else {
            panic!("command should complete while stderr is drained");
        };
        assert!(output.status.success());
        assert_eq!(output.stderr.len(), 100_000);
    }
}
