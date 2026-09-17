//! The listening socket: created here or adopted from systemd, and proven to be
//! the owner-only node the peer uid gate rests on.
//!
//! The daemon runs as a systemd user unit whose mount protections
//! (`ProtectKernelTunables`, `PrivateTmp`, …) put it in a private user namespace
//! mapping only its own uid. `SO_PEERCRED` therefore reports every other uid —
//! a container's subordinate uid, another user, root — as the kernel overflow
//! uid, and the gate cannot tell those apart. It does not try: who may connect
//! is decided by the socket node's `0600` mode in the peer's own namespace, and
//! this module refuses to serve a node that is not in that shape.

use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd};
use std::os::unix::net::UnixListener;
use std::path::Path;

use nix::sys::socket::sockopt::{AcceptConn, SockType as SocketType};
use nix::sys::socket::{SockType, UnixAddr, getsockname, getsockopt};
use nix::sys::stat::{Mode, SFlag, fstat, stat, umask};
use nix::unistd::geteuid;

use crate::Config;

/// The uid the kernel reports for a peer whose real uid has no mapping in this
/// process's user namespace. 65534 is the kernel default for
/// `kernel.overflowuid`; a host that changes it fails closed, refusing such
/// peers as foreign.
const OVERFLOW_UID: u32 = 65534;

/// Whether a peer's kernel-reported uid may proceed to identification.
///
/// `listener` serves only an owner-only socket node, so the kernel has already
/// refused every peer that is not this uid in its own user namespace; from a
/// namespace this process cannot map, that same-uid peer arrives as the overflow
/// uid. Any other value means the node's mode was bypassed and is refused. The
/// peer's session is still bound by token and pidfd ancestry in `handle`; this
/// gate grants nothing.
pub(super) const fn uid_is_authorized(peer_uid: u32, daemon_uid: u32) -> bool {
    peer_uid == daemon_uid || peer_uid == OVERFLOW_UID
}

fn socket_activated() -> bool {
    std::env::var("LISTEN_FDS").is_ok_and(|value| value == "1")
        && std::env::var("LISTEN_PID")
            .ok()
            .and_then(|value| value.parse::<u32>().ok())
            .is_some_and(|pid| pid == std::process::id())
}

fn activation_environment_present() -> bool {
    std::env::var_os("LISTEN_FDS").is_some() || std::env::var_os("LISTEN_PID").is_some()
}

/// Refuse a socket node that is not this uid's alone.
///
/// The uid gate accepts the overflow uid on the strength of this mode, so a node
/// that is group- or world-reachable, or owned by someone else, is a daemon that
/// must not start rather than one that serves anyway.
fn assert_owner_only(path: &Path) -> std::io::Result<()> {
    let node = stat(path).map_err(std::io::Error::other)?;
    if !SFlag::from_bits_truncate(node.st_mode).contains(SFlag::S_IFSOCK) {
        return Err(std::io::Error::other(
            "listening socket path is not a socket",
        ));
    }
    if node.st_uid != geteuid().as_raw() {
        return Err(std::io::Error::other(
            "listening socket is not owned by this uid",
        ));
    }
    let mode = node.st_mode & 0o777;
    if mode != 0o600 {
        return Err(std::io::Error::other(format!(
            "listening socket mode is {mode:o}, not 0600"
        )));
    }
    Ok(())
}

fn validate_activated_listener(fd: BorrowedFd<'_>) -> std::io::Result<()> {
    let socket = fstat(fd).map_err(std::io::Error::other)?;
    if !SFlag::from_bits_truncate(socket.st_mode).contains(SFlag::S_IFSOCK) {
        return Err(std::io::Error::other("activation fd is not a socket"));
    }
    if getsockopt(&fd, SocketType).map_err(std::io::Error::other)? != SockType::Stream {
        return Err(std::io::Error::other(
            "activation fd is not a stream socket",
        ));
    }
    if !getsockopt(&fd, AcceptConn).map_err(std::io::Error::other)? {
        return Err(std::io::Error::other("activation socket is not listening"));
    }
    let address: UnixAddr = getsockname(fd.as_raw_fd()).map_err(std::io::Error::other)?;
    let path = address
        .path()
        .ok_or_else(|| std::io::Error::other("activation socket has no filesystem path"))?;
    assert_owner_only(path)
}

pub(super) fn listener(config: &Config) -> std::io::Result<UnixListener> {
    if socket_activated() {
        // SAFETY: fd 3 is valid for the duration of this call because activation
        // descriptors are inherited from this process; `validate_activated_listener`
        // verifies its socket type, listening state, and owner-only node before adoption.
        let fd = unsafe { BorrowedFd::borrow_raw(3) };
        validate_activated_listener(fd)?;
        // SAFETY: the borrowed fd was validated above and ownership transfers once
        // into the resulting listener, which closes it exactly once on drop.
        return Ok(unsafe { UnixListener::from_raw_fd(3) });
    }
    if activation_environment_present() {
        return Err(std::io::Error::other(
            "invalid socket activation environment",
        ));
    }
    if let Err(error) = std::fs::remove_file(&config.socket_path)
        && error.kind() != std::io::ErrorKind::NotFound
    {
        return Err(error);
    }
    bind_owner_only(&config.socket_path)
}

/// Bind a listening socket whose node is owner-only from the moment it exists.
///
/// A peer that connects before a later `chmod` sits in the backlog and then
/// passes the uid gate on the strength of a mode the node never had, so the
/// mode cannot be applied after the fact. `bind` creates the node with
/// `0666 & !umask`, which makes the umask the only way to get there; nothing
/// here may replace it with a `set_permissions` call. The umask is
/// process-wide, and this runs at startup before any worker thread exists.
fn bind_owner_only(path: &Path) -> std::io::Result<UnixListener> {
    let inherited = umask(Mode::from_bits_truncate(0o177));
    let bound = UnixListener::bind(path);
    umask(inherited);
    let listener = bound?;
    assert_owner_only(path)?;
    Ok(listener)
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsFd;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    use super::*;

    #[test]
    fn binds_an_owner_only_node_without_a_second_step() {
        // The node's mode comes from `bind` itself: under a fully permissive
        // umask it must still be 0600, with nothing applied afterwards to get
        // it there. nextest runs each test in its own process, so the umask
        // change is confined here.
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("secretsd.sock");
        let _ = umask(Mode::empty());

        let _listener = bind_owner_only(&path).unwrap();

        let mode = std::fs::metadata(&path).unwrap().mode() & 0o777;
        assert_eq!(mode, 0o600, "node created with mode {mode:o}");
    }

    #[test]
    fn refuses_a_mapped_uid_other_than_the_daemons() {
        // These values reach the gate only when the daemon shares the peer's
        // user namespace; the socket mode, not this check, is what keeps them
        // from connecting at all.
        assert!(!uid_is_authorized(1000, 1001));
        assert!(!uid_is_authorized(0, 1000));
        assert!(!uid_is_authorized(231_072 + 1000, 1000));
    }

    #[test]
    fn accepts_the_daemon_uid_and_the_overflow_uid() {
        // A sysbox container maps its uid 1000 onto a host subordinate uid;
        // the daemon, in the private user namespace its mount protections
        // imply, sees that peer as the overflow uid. The owner-only node
        // already proved the peer is this uid in *some* namespace.
        assert!(uid_is_authorized(1000, 1000));
        assert!(uid_is_authorized(OVERFLOW_UID, 1000));
    }

    #[test]
    fn rejects_a_non_socket_activation_fd() {
        let file = tempfile::tempfile().unwrap();

        assert!(validate_activated_listener(file.as_fd()).is_err());
    }

    #[test]
    fn adopts_only_an_owner_only_activation_socket() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("secretsd.sock");
        let listening = UnixListener::bind(&path).unwrap();

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660)).unwrap();
        let group_reachable = validate_activated_listener(listening.as_fd());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let owner_only = validate_activated_listener(listening.as_fd());

        assert!(
            group_reachable
                .as_ref()
                .is_err_and(|error| error.to_string().contains("not 0600")),
            "a group-reachable node was adopted: {group_reachable:?}"
        );
        assert!(
            owner_only.is_ok(),
            "the owner-only node was refused: {owner_only:?}"
        );
    }

    #[test]
    fn refuses_a_listening_socket_whose_node_was_replaced() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("secretsd.sock");
        let listening = UnixListener::bind(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, b"").unwrap();

        let replaced = validate_activated_listener(listening.as_fd());

        assert!(
            replaced
                .as_ref()
                .is_err_and(|error| error.to_string().contains("not a socket")),
            "a plain file at the socket path was accepted: {replaced:?}"
        );
    }
}
