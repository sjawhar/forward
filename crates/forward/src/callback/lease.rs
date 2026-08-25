use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use parking_lot::{Condvar, Mutex};

struct Lease {
    deadline: Instant,
    listeners: usize,
    stop: Arc<AtomicBool>,
}

/// One logical lease per callback port, however many listeners serve it.
#[derive(Clone)]
pub struct Leases {
    inner: Arc<Mutex<HashMap<u16, Lease>>>,
    released: Arc<Condvar>,
}

pub(super) enum Refresh {
    Live,
    Releasing,
    Absent,
}

impl Default for Leases {
    fn default() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            released: Arc::new(Condvar::new()),
        }
    }
}

impl Leases {
    pub fn new() -> Self {
        Self::default()
    }

    pub(super) fn refresh(&self, port: u16, ttl: Duration) -> Refresh {
        let mut leases = self.inner.lock();
        match leases.get_mut(&port) {
            Some(lease) if !lease.stop.load(Ordering::Relaxed) => {
                lease.deadline = Instant::now() + ttl;
                Refresh::Live
            }
            Some(_) => Refresh::Releasing,
            None => Refresh::Absent,
        }
    }

    pub(super) fn insert(&self, port: u16, ttl: Duration, stop: Arc<AtomicBool>, listeners: usize) {
        let mut leases = self.inner.lock();
        if let Some(replaced) = leases.get(&port) {
            replaced.stop.store(true, Ordering::Relaxed);
        }
        leases.insert(
            port,
            Lease {
                deadline: Instant::now() + ttl,
                listeners,
                stop,
            },
        );
    }

    pub(super) fn release(&self, port: u16, stop: &Arc<AtomicBool>) -> bool {
        match self.inner.lock().entry(port) {
            Entry::Occupied(mut lease) if Arc::ptr_eq(&lease.get().stop, stop) => {
                let last_listener = {
                    let lease = lease.get_mut();
                    lease.listeners -= 1;
                    lease.listeners == 0
                };
                if last_listener {
                    lease.remove().stop.store(true, Ordering::Relaxed);
                    self.released.notify_all();
                    return true;
                }
            }
            Entry::Occupied(_) | Entry::Vacant(_) => {}
        }
        false
    }

    pub(super) fn expire(&self) {
        let now = Instant::now();
        for lease in self.inner.lock().values() {
            if lease.deadline <= now {
                lease.stop.store(true, Ordering::Relaxed);
            }
        }
    }

    pub(super) fn wait_until_released(&self, port: u16) {
        let mut leases = self.inner.lock();
        while leases.contains_key(&port) {
            self.released.wait(&mut leases);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;
    use std::thread;

    use super::*;

    #[test]
    fn a_removed_lease_is_immediately_rebindable() {
        // Given: a listener whose lease has expired but has not dropped yet.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let leases = Leases::new();
        let stop = Arc::new(AtomicBool::new(false));
        leases.insert(port, Duration::ZERO, Arc::clone(&stop), 1);

        // When: the reaper expires the lease.
        leases.expire();

        // Then: the map must retain it until the listener is actually gone.
        assert!(leases.inner.lock().contains_key(&port));
        assert!(matches!(
            leases.refresh(port, Duration::from_secs(30)),
            Refresh::Releasing
        ));
        let waiting_leases = leases.clone();
        let rebind = thread::spawn(move || {
            waiting_leases.wait_until_released(port);
            TcpListener::bind(("127.0.0.1", port)).is_ok()
        });
        drop(listener);
        assert!(leases.release(port, &stop));
        assert!(!leases.inner.lock().contains_key(&port));
        assert!(rebind.join().unwrap());
    }
}
