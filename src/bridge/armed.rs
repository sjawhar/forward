use super::port_policy::can_arm;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Callback ports the devbox will hop to, and until when.
///
/// The bridge is a service that connects to loopback ports on request, which is
/// the shape of a confinement bypass. This set is what stops a reachable peer
/// from choosing a port: only ports a local `forward open` armed — from a URL
/// that actually named them — are reachable, and only until the lease expires.
///
/// Clones share one set, so the arming socket and the bridge listener can hold a
/// handle each.
#[derive(Clone, Default)]
pub struct Armed {
    ports: Arc<Mutex<HashMap<u16, Instant>>>,
}

impl Armed {
    pub fn new() -> Self {
        Self::default()
    }

    /// Arm `port` for `ttl`. A longer lease replaces a shorter one; a shorter one
    /// never shortens a lease already granted. Returns false for an unsafe port or
    /// an unrepresentable deadline.
    pub fn arm(&self, port: u16, ttl: Duration) -> bool {
        if !can_arm(port) {
            return false;
        }
        let mut ports = self.ports.lock();
        let Some(deadline) = Instant::now().checked_add(ttl) else {
            return false;
        };
        let entry = ports.entry(port).or_insert(deadline);
        if *entry < deadline {
            *entry = deadline;
        }
        true
    }

    /// Whether `port` is armed right now. Expired entries are dropped here, so no
    /// reaper thread is needed for this set.
    pub fn is_armed(&self, port: u16) -> bool {
        let mut ports = self.ports.lock();
        let now = Instant::now();
        ports.retain(|_, deadline| *deadline > now);
        ports.contains_key(&port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn an_armed_port_is_reachable_until_it_expires() {
        // Given: a port armed for a very short window.
        let armed = Armed::new();
        armed.arm(8400, Duration::from_millis(80));

        // When: it is checked inside and then outside that window.
        assert!(armed.is_armed(8400));
        std::thread::sleep(Duration::from_millis(140));

        // Then: it stops being reachable on its own.
        assert!(!armed.is_armed(8400));
    }

    #[test]
    fn an_unarmed_port_is_never_reachable() {
        // Given: one armed port.
        let armed = Armed::new();
        armed.arm(8400, Duration::from_secs(60));

        // When/Then: a port nobody armed is not reachable through it.
        assert!(!armed.is_armed(9999));
    }

    #[test]
    fn arming_again_extends_the_window() {
        // Given: a port armed for a window about to close.
        let armed = Armed::new();
        armed.arm(8400, Duration::from_millis(60));
        std::thread::sleep(Duration::from_millis(40));

        // When: a second `forward open` arms the same port for longer.
        armed.arm(8400, Duration::from_secs(30));
        std::thread::sleep(Duration::from_millis(40));

        // Then: the longer lease wins instead of the first one expiring.
        assert!(armed.is_armed(8400));
    }

    #[test]
    fn arming_again_never_shortens_the_window() {
        // Given: a port armed for a long window.
        let armed = Armed::new();
        armed.arm(8400, Duration::from_secs(30));

        // When: it is immediately armed again for a much shorter window.
        armed.arm(8400, Duration::from_millis(1));
        std::thread::sleep(Duration::from_millis(20));

        // Then: the first lease still keeps it reachable.
        assert!(armed.is_armed(8400));
    }

    #[test]
    fn clones_share_one_set() {
        // Given: a handle cloned for another thread.
        let armed = Armed::new();
        let other = armed.clone();

        // When: one clone arms a port.
        other.arm(8400, Duration::from_secs(30));

        // Then: the original sees it.
        assert!(armed.is_armed(8400));
    }

    #[test]
    fn dangerous_and_privileged_ports_are_never_armed() {
        // Given: ports that an OAuth loopback callback cannot legitimately own.
        let armed = Armed::new();
        let forbidden = [
            0, 443, 1_023, 2_345, 2_375, 2_376, 3_306, 5_432, 5_678, 6_379, 8_001, 9_229,
        ];

        // When: a URL-controlled arming request names each one.
        for port in forbidden {
            assert!(!armed.arm(port, Duration::from_secs(30)));
        }

        // Then: none becomes reachable through the callback bridge.
        for port in forbidden {
            assert!(!armed.is_armed(port), "port {port} was armed");
        }
    }
}
