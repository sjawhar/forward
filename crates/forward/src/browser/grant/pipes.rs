use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::Mutex;

use super::{GrantEntry, Grants};

/// Duplicated descriptors for every pipe a port's grant is serving.
pub(super) type PipeTable = HashMap<u16, Vec<(u64, (std::net::TcpStream, std::net::TcpStream))>>;
pub(super) type PipeHandles = Vec<(u64, (std::net::TcpStream, std::net::TcpStream))>;

/// Removes its pipe's handles when the pipe ends of its own accord.
pub struct PipeGuard {
    pipes: Arc<Mutex<PipeTable>>,
    port: u16,
    id: u64,
}

impl Grants {
    /// Register a live pipe's socket pair under `port`, so ending the grant
    /// ends the pipe.
    ///
    /// CDP multiplexes a whole session over one long-lived websocket, so a
    /// grant that only refuses *new* connections leaves an established session
    /// driving the browser for as long as it likes. The handles are duplicated
    /// descriptors: shutting them down wakes the blocked copies inside the
    /// pipe threads, and the returned guard removes the entry when the pipe
    /// ends on its own, so a finished pipe does not leak two descriptors.
    pub(crate) fn register_pipe(
        &self,
        port: u16,
        grant_id: u64,
        client: &std::net::TcpStream,
        laptop: &std::net::TcpStream,
    ) -> std::io::Result<PipeGuard> {
        // Lock pipes before ports, as `expire` does below: this keeps its
        // removal from falling between the live-grant check and registration.
        let mut pipes = self.pipes.lock();
        let ports = self.ports.lock();
        if ports
            .get(&port)
            .is_none_or(|entry: &GrantEntry| entry.id != grant_id)
        {
            return Err(std::io::Error::from(std::io::ErrorKind::NotFound));
        }
        let handles = (client.try_clone()?, laptop.try_clone()?);
        let id = self
            .next_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        pipes.entry(port).or_default().push((id, handles));
        drop(ports);
        Ok(PipeGuard {
            pipes: Arc::clone(&self.pipes),
            port,
            id,
        })
    }
}

impl Drop for PipeGuard {
    fn drop(&mut self) {
        if let Some(entries) = self.pipes.lock().get_mut(&self.port) {
            entries.retain(|(id, _)| *id != self.id);
        }
    }
}

pub(super) fn shutdown(severed: PipeHandles) {
    for (_, (client, laptop)) in severed {
        // Both directions of both sockets: the pipe threads block on reads of
        // either end, and a one-sided shutdown leaves the other blocked.
        let _ = client.shutdown(std::net::Shutdown::Both);
        let _ = laptop.shutdown(std::net::Shutdown::Both);
    }
}
