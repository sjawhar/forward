use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use super::armed::Armed;
use super::limit::ConnectionLimit;

/// The longest arming request accepted, in bytes.
///
/// `ARM 65535 4294967295\n` is 21 bytes, so 64 is generous. The cap stops a
/// hostile or broken local process from making its handler allocate without
/// limit; the deadline releases that handler instead.
const MAX_ARM_LINE: usize = 64;
/// Maximum elapsed time to read an entire arming request.
const ARM_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const ARM_REPLY_TIMEOUT: Duration = Duration::from_secs(5);

/// Where `forward open` reaches the local bridge.
///
/// A unix socket in the runtime directory, never a TCP port: only local
/// processes can reach it, and filesystem permissions scope it. Arming grants a
/// local process nothing it could not already do by connecting to loopback
/// directly; the gate exists to constrain the *remote* peer.
///
/// When `XDG_RUNTIME_DIR` is unset the path falls back to systemd's
/// `/run/user/<uid>` — pam_systemd sets the variable for login sessions, but a
/// shell inside a tmux server that was itself started without it inherits the
/// gap, while the socket is still there, because `forward serve` runs under
/// the user manager, which always has it. The fallback is trusted only when
/// the directory proves the same property `$XDG_RUNTIME_DIR` has — owned by
/// this uid, writable by nobody else, so no other user can pre-create the
/// socket. Anything less deliberately yields a non-connectable path: arming
/// is unavailable rather than trusting a predictable shared directory.
pub fn arm_socket_path() -> PathBuf {
    let configured = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .filter(|path| !path.as_os_str().is_empty());
    arm_socket_path_in(configured.or_else(default_runtime_dir))
}

fn arm_socket_path_in(runtime_dir: Option<PathBuf>) -> PathBuf {
    let dir = runtime_dir
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| PathBuf::from("/dev/null"));
    dir.join("forward-arm.sock")
}

/// systemd's runtime directory for this process's own uid, if trustworthy.
fn default_runtime_dir() -> Option<PathBuf> {
    // /proc/self is owned by this process's effective uid; std exposes no
    // getuid, and the no-new-dependencies rule forbids libc.
    let uid = std::fs::metadata("/proc/self").ok()?.uid();
    trusted_runtime_dir(PathBuf::from(format!("/run/user/{uid}")), uid)
}

/// `dir`, only if `uid` owns it and nobody else can write into it.
fn trusted_runtime_dir(dir: PathBuf, uid: u32) -> Option<PathBuf> {
    let metadata = std::fs::metadata(&dir).ok()?;
    (metadata.uid() == uid && metadata.mode() & 0o022 == 0).then_some(dir)
}

/// Serve arming requests on `path` for the life of the process.
pub fn serve_arming(armed: Armed, path: PathBuf) {
    let _ = std::fs::remove_file(&path);
    let Ok(listener) = UnixListener::bind(&path) else {
        eprintln!("forward: could not bind arming socket {}", path.display());
        return;
    };
    // Restrict the socket rather than inheriting the process umask.
    let owner_only = std::fs::Permissions::from_mode(0o600);
    if let Err(error) = std::fs::set_permissions(&path, owner_only) {
        eprintln!(
            "forward: could not restrict arming socket {}: {error}",
            path.display()
        );
        let _ = std::fs::remove_file(&path);
        return;
    }
    drop(std::thread::spawn(move || {
        let limit = ConnectionLimit::standard();
        for connection in listener.incoming() {
            let Ok(stream) = connection else {
                continue;
            };
            let Some(permit) = limit.acquire() else {
                eprintln!("forward: arming refused connection: concurrency limit reached");
                continue;
            };
            let armed = armed.clone();
            drop(thread::spawn(move || {
                let _permit = permit;
                handle_arming(&armed, stream);
            }));
        }
    }));
}

fn handle_arming(armed: &Armed, mut stream: UnixStream) {
    let Some((port, ttl)) = read_request(&mut stream) else {
        return;
    };
    if !armed.arm(port, Duration::from_secs(ttl)) {
        eprintln!("forward: refused unsafe callback port {port}");
        return;
    }
    eprintln!("forward: armed callback port {port} for {ttl}s");
    let _ = writeln!(stream, "ok");
}

/// Read one newline-terminated `ARM <port> <ttl_secs>` request.
///
/// The line is read byte-by-byte under one cumulative deadline, so the cap and
/// newline are structural: a truncated line can never reach parsing.
fn read_request(stream: &mut UnixStream) -> Option<(u16, u64)> {
    let deadline = Instant::now().checked_add(ARM_REQUEST_TIMEOUT)?;
    let mut line = Vec::with_capacity(MAX_ARM_LINE);
    let mut byte = [0_u8; 1];

    while line.len() < MAX_ARM_LINE {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() || stream.set_read_timeout(Some(remaining)).is_err() {
            return None;
        }
        match stream.read(&mut byte) {
            Ok(1) => {}
            Ok(_) => return None,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return None,
        }
        let [received] = byte;
        if received == b'\n' {
            return parse_request(&line);
        }
        line.push(received);
    }
    None
}

fn parse_request(line: &[u8]) -> Option<(u16, u64)> {
    let request = std::str::from_utf8(line).ok()?;
    if !request.is_ascii() {
        return None;
    }
    let mut fields = request.split(' ');
    let (Some("ARM"), Some(port), Some(ttl), None) =
        (fields.next(), fields.next(), fields.next(), fields.next())
    else {
        return None;
    };
    if port.is_empty()
        || ttl.is_empty()
        || !port.bytes().all(|value| value.is_ascii_digit())
        || !ttl.bytes().all(|value| value.is_ascii_digit())
    {
        return None;
    }
    Some((port.parse().ok()?, ttl.parse().ok()?))
}

/// Arm `ports` on the local bridge, true only if every one was armed.
///
/// An empty slice is not a success: a caller with nothing to arm must skip this
/// call rather than read the result as a failure.
pub fn arm(path: &Path, ports: &[u16], ttl_secs: u64) -> bool {
    let mut armed_all = !ports.is_empty();
    for port in ports {
        armed_all &= arm_one(path, *port, ttl_secs);
    }
    armed_all
}

fn arm_one(path: &Path, port: u16, ttl_secs: u64) -> bool {
    let Ok(mut stream) = UnixStream::connect(path) else {
        eprintln!(
            "forward: no local bridge at {} — callback port {port} will not be reachable",
            path.display()
        );
        return false;
    };
    // `forward open` must never hang on a wedged bridge.
    if stream.set_read_timeout(Some(ARM_REPLY_TIMEOUT)).is_err() {
        return false;
    }
    if writeln!(stream, "ARM {port} {ttl_secs}").is_err() {
        return false;
    }
    let mut reply = [0_u8; 3];
    stream.read_exact(&mut reply).is_ok() && reply == *b"ok\n"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arm_socket_path_is_nonconnectable_without_a_runtime_dir() {
        // Given: a client with no configured and no trusted default directory.
        let path = arm_socket_path_in(None);

        // When/Then: it must not use the predictable global temporary directory.
        assert_eq!(path, PathBuf::from("/dev/null/forward-arm.sock"));
        assert!(UnixStream::connect(path).is_err());
    }

    #[test]
    fn a_runtime_dir_is_trusted_only_when_owned_and_private() {
        // Given: a directory owned by this uid with default private permissions,
        // and this process's real uid.
        let dir = tempfile::tempdir().unwrap();
        let uid = std::fs::metadata("/proc/self").unwrap().uid();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();

        // When/Then: it qualifies for this uid — and stops qualifying the
        // moment the owner differs or anyone else can write into it, because
        // either lets another user pre-create the socket and answer "ok".
        assert!(trusted_runtime_dir(dir.path().to_path_buf(), uid).is_some());
        assert!(trusted_runtime_dir(dir.path().to_path_buf(), uid + 1).is_none());
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o722)).unwrap();
        assert!(trusted_runtime_dir(dir.path().to_path_buf(), uid).is_none());
        assert!(trusted_runtime_dir(PathBuf::from("/no/such/runtime/dir"), uid).is_none());
    }
}
