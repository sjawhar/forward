//! Starting one grant's relay as a detached child of the grant CLI.
//!
//! Re-executing this binary rather than forking in place: by the time a grant
//! is issued the CLI has run the broker ceremony and may hold threads, and a
//! `fork` from a threaded process gives the child a single thread and every
//! other thread's locks held forever. `exec` starts clean.
//!
//! The listener and the control channel travel as inherited descriptors on
//! fixed numbers rather than as addresses: the listener's port means nothing
//! outside this namespace, and the control channel is authenticated by being
//! the one connection on which the receipt was redeemed.

use std::os::fd::{AsRawFd as _, RawFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt as _;
use std::process::{Command, Stdio};

use nix::libc;

use crate::browser::grant::ProcessAnchor;

/// The grant's loopback listener, as the relay child receives it.
pub const LISTENER_FD: RawFd = 3;
/// The grant's control channel to `forward serve`, as the relay child
/// receives it.
pub const CONTROL_FD: RawFd = 4;
/// Where a descriptor is parked while the two above are put in place.
const STAGING_FD: RawFd = CONTROL_FD + 1;

/// Start the relay for a grant and return without waiting for it.
///
/// The child is its own session leader, so the terminal that ran the grant
/// closing does not end the grant; it ends when `forward serve` closes the
/// control channel, or when this machine reboots.
pub fn spawn(
    listener: &std::net::TcpListener,
    control: &UnixStream,
    anchor: ProcessAnchor,
) -> std::io::Result<()> {
    let program = std::env::current_exe()?;
    let listener_fd = listener.as_raw_fd();
    let control_fd = control.as_raw_fd();
    let mut command = Command::new(program);
    command
        .args(["browser", "relay", "--anchor-pid"])
        .arg(anchor.pid.to_string())
        .arg("--anchor-start")
        .arg(anchor.start.to_string())
        // The CLI's terminal is gone long before the relay is: writing to it
        // later would interleave with whatever the human is doing there.
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // SAFETY: the closure runs in the forked child between fork and exec,
    // where only async-signal-safe calls are allowed. `fcntl`, `dup2` and
    // `setsid` are all on that list, it allocates nothing, and it touches
    // nothing but this child's own descriptor table.
    unsafe {
        command.pre_exec(move || place(listener_fd, control_fd));
    }
    command.spawn().map(drop)
}

fn place(listener_fd: RawFd, control_fd: RawFd) -> std::io::Result<()> {
    // Stage both above the fixed numbers first: either descriptor may already
    // sit on the other's target, and a bare `dup2` would then close it. The
    // staged copies keep their close-on-exec flag and so vanish at `exec`,
    // while `dup2` clears it on the two the relay is meant to inherit.
    let staged_listener = stage(listener_fd)?;
    let staged_control = stage(control_fd)?;
    dup2(staged_listener, LISTENER_FD)?;
    dup2(staged_control, CONTROL_FD)?;
    // SAFETY: async-signal-safe, and it affects only this child process.
    if unsafe { libc::setsid() } == -1 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn stage(fd: RawFd) -> std::io::Result<RawFd> {
    // SAFETY: async-signal-safe; duplicates one descriptor this child owns.
    let staged = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, STAGING_FD) };
    if staged == -1 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(staged)
}

fn dup2(from: RawFd, to: RawFd) -> std::io::Result<()> {
    // SAFETY: async-signal-safe; both numbers belong to this child alone.
    if unsafe { libc::dup2(from, to) } == -1 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}
