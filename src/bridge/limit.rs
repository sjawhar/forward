use std::sync::Arc;

use parking_lot::Mutex;

const MAX_CONCURRENT_CONNECTIONS: usize = 32;

#[derive(Clone)]
pub(crate) struct ConnectionLimit {
    active: Arc<Mutex<usize>>,
    capacity: usize,
}

pub(crate) struct ConnectionPermit(Arc<Mutex<usize>>);

impl ConnectionLimit {
    pub(crate) fn standard() -> Self {
        Self::new(MAX_CONCURRENT_CONNECTIONS)
    }

    fn new(capacity: usize) -> Self {
        Self {
            active: Arc::new(Mutex::new(0)),
            capacity,
        }
    }

    pub(crate) fn acquire(&self) -> Option<ConnectionPermit> {
        let mut active = self.active.lock();
        if *active == self.capacity {
            return None;
        }
        *active += 1;
        Some(ConnectionPermit(Arc::clone(&self.active)))
    }
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        *self.0.lock() -= 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_limit_refuses_work_above_its_cap() {
        // Given: a bridge with two active connection slots.
        let limit = ConnectionLimit::new(2);
        let first = limit.acquire();
        let second = limit.acquire();

        // When: a third connection arrives before either handler finishes.
        let third = limit.acquire();

        // Then: it is refused rather than spawning an unbounded thread.
        assert!(first.is_some());
        assert!(second.is_some());
        assert!(third.is_none());
    }
}
