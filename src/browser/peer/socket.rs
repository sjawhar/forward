use std::net::SocketAddrV4;
use std::path::Path;

/// The pid owning the loopback socket `peer` -> `local`, if one can be found.
///
/// Racy by construction: the pid is read after the fact and could in principle
/// be reused. Resolution happens at accept while the socket is live, which
/// bounds the window; a failure to resolve is refused, never allowed.
pub fn pid_for_connection(peer: SocketAddrV4, local: SocketAddrV4) -> Option<u32> {
    let inode = inode_for(peer, local)?;
    pid_for_inode(&inode)
}

fn endpoint(address: SocketAddrV4) -> String {
    format!(
        "{:08X}:{:04X}",
        u32::from_le_bytes(address.ip().octets()),
        address.port()
    )
}

/// The socket inode whose local/remote pair is the client's side of `peer` ->
/// `local`.
fn inode_for(peer: SocketAddrV4, local: SocketAddrV4) -> Option<String> {
    let (want_local, want_remote) = (endpoint(peer), endpoint(local));
    let table = std::fs::read_to_string("/proc/net/tcp").ok()?;
    table.lines().skip(1).find_map(|line| {
        let mut fields = line.split_whitespace().skip(1);
        let found_local = fields.next()?;
        let found_remote = fields.next()?;
        if found_local != want_local || found_remote != want_remote {
            return None;
        }
        fields.nth(6).map(str::to_owned)
    })
}

fn pid_for_inode(inode: &str) -> Option<u32> {
    let target = format!("socket:[{inode}]");
    for entry in std::fs::read_dir("/proc").ok()?.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse().ok())
        else {
            continue;
        };
        let Ok(descriptors) = std::fs::read_dir(entry.path().join("fd")) else {
            continue;
        };
        for descriptor in descriptors.flatten() {
            if std::fs::read_link(descriptor.path()).is_ok_and(|link| link == Path::new(&target)) {
                return Some(pid);
            }
        }
    }
    None
}
