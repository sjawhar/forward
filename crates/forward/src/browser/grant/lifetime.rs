//! How a grant ends: on its deadline, on revocation, or on a caller's exit.
//!
//! Every ending goes through one of these, and each shuts the grant's control
//! channel down. That single act reaches both halves of a grant at once — the
//! `forward serve` control loop blocked in `recvmsg`, and the caller's relay
//! watching the same channel for its cue to close the endpoint — so no ending
//! leaves a listener accepting for a grant the registry no longer holds.

use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::thread;
use std::time::Instant;

use zeroize::Zeroize as _;

use super::{Grants, PipeHandles, pipes, scrub};

impl Grants {
    /// Drop `id`'s grant now, zeroing the registry's token copy in place,
    /// severing every live pipe it was serving, and closing its control
    /// channel. Removing a grant that is already gone is a no-op.
    pub fn expire(&self, id: u64) {
        let (removed, severed) = {
            // Lock pipes before grants, as `register_pipe` does, so a
            // registration cannot escape the pipe table after this removal.
            let mut pipes = self.pipes.lock();
            let mut grants = self.grants.lock();
            (
                scrub(&mut grants, id),
                pipes.remove(&id).unwrap_or_default(),
            )
        };
        pipes::shutdown(severed);
        if let Some(entry) = removed {
            end_control(&entry.control);
        }
    }

    /// Expire `id` at `deadline`.
    ///
    /// Nothing has to be woken by hand: closing the grant's control channel is
    /// what tells the caller's relay to stop accepting, so an endpoint no
    /// client ever connected to still goes away on time.
    pub fn reap_at(&self, id: u64, deadline: Instant) {
        let grants = self.clone();
        drop(thread::spawn(move || {
            thread::sleep(deadline.saturating_duration_since(Instant::now()));
            grants.expire(id);
        }));
    }

    pub(super) fn revoke_all(&self) {
        let (controls, severed) = self.drain_all();
        pipes::shutdown(severed);
        for control in &controls {
            end_control(control);
        }
    }

    fn drain_all(&self) -> (Vec<UnixStream>, PipeHandles) {
        let mut pipes = self.pipes.lock();
        let mut grants = self.grants.lock();
        let controls = grants
            .drain()
            .map(|(_, mut entry)| {
                entry.grant.token.zeroize();
                entry.control
            })
            .collect();
        let severed = std::mem::take(&mut *pipes)
            .into_values()
            .flatten()
            .collect();
        (controls, severed)
    }
}

/// Best-effort, like `pipes::shutdown`: the caller may already be gone, and a
/// severed channel is exactly the state this is trying to reach.
fn end_control(control: &UnixStream) {
    let _ = control.shutdown(Shutdown::Both);
}
