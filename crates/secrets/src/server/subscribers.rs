use std::io::Write;
use std::os::unix::net::UnixStream;
use std::sync::Mutex;

use super::{Shared, lock_state};
use crate::proto::SUBSCRIBER_CAPACITY_RESPONSE;

pub(super) const SUBSCRIBER_CAPACITY: usize = 8;

#[derive(Debug)]
pub(super) struct Subscriber {
    peer: crate::peer::PeerIdentity,
    stream: UnixStream,
}

#[derive(Debug, Default)]
pub(super) struct SubscriberHub {
    subscribers: Mutex<Vec<Subscriber>>,
}

impl SubscriberHub {
    pub(super) fn attach(
        &self,
        shared: &Shared,
        mut stream: UnixStream,
        peer: crate::peer::PeerIdentity,
    ) -> std::io::Result<()> {
        // Writes never wait under the attachment/publication mutex. A peer
        // whose socket cannot accept its attach event is not a subscriber.
        stream.set_nonblocking(true)?;
        // This lock serializes attach with publication, and is deliberately
        // held across the epoch read, the attach write, and the push. Release
        // it earlier and a LOCK landing in between publishes to a table this
        // peer is not yet in: it would then believe the pre-lock epoch and
        // never receive the event that corrected it — the missed-lock hole
        // §6.3(b) exists to close. Only its tail is released early, below.
        let mut subscribers = self
            .subscribers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // A PinnedPeer keeps its pidfd open, so two live entries with this pid
        // identify the same process and one reconnect replaces the other.
        let peer_pid = peer.pid();
        subscribers
            .retain(|subscriber| subscriber.peer.is_alive() && subscriber.peer.pid() != peer_pid);
        if subscribers.len() >= SUBSCRIBER_CAPACITY {
            // Release before writing: the refusal needs no table, and holding
            // the mutex across a socket write would serialize every other
            // attach and publication behind this peer.
            drop(subscribers);
            return stream.write_all(SUBSCRIBER_CAPACITY_RESPONSE.as_bytes());
        }
        let line = {
            let (mutex, _) = &**shared;
            let state = lock_state(mutex);
            let line = ::proto::authority_event(&state.instance, state.lock_epoch);
            drop(state);
            line
        };
        if stream.write(line.as_bytes())? != line.len() {
            return Err(std::io::Error::from(std::io::ErrorKind::WriteZero));
        }
        subscribers.push(Subscriber { peer, stream });
        drop(subscribers);
        Ok(())
    }

    pub(super) fn publish_current(&self, shared: &Shared) {
        let mut subscribers = self
            .subscribers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let line = {
            let (mutex, _) = &**shared;
            let state = lock_state(mutex);
            ::proto::authority_event(&state.instance, state.lock_epoch)
        };
        subscribers.retain_mut(|subscriber| {
            subscriber.peer.is_alive()
                && matches!(
                    subscriber.stream.write(line.as_bytes()),
                    Ok(written) if written == line.len()
                )
        });
    }
}

pub(super) fn publish_current_authority(shared: &Shared) {
    let subscribers = {
        let (mutex, _) = &**shared;
        std::sync::Arc::clone(&lock_state(mutex).subscribers)
    };
    subscribers.publish_current(shared);
}

#[cfg(test)]
mod tests;
