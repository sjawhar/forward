use crate::callback::{CHANNEL_PORT, FILES_PORT, PCSC_PORT};

const LOWEST_CALLBACK_PORT: u16 = 1_024;
const LETHAL_DEVELOPMENT_PORTS: [u16; 9] = [
    2_345, 2_375, 2_376, 3_306, 5_432, 5_678, 6_379, 8_001, 9_229,
];

pub(super) fn can_arm(port: u16) -> bool {
    !globally_denied(port)
}

/// Whether `port` is never safe for the callback bridge to dial.
///
/// 12799 comes first: it is the devbox endpoint of the SSH tunnel carrying the
/// laptop hardware token. 12800 is forward's URL receiver and 12802 its file
/// server, so both avoid self-routing into another forward service. Port zero
/// has no destination, ports below 1024 are privileged and cannot be legitimate
/// RFC 8252 loopback callbacks, and the configured listener port would recurse.
/// Docker's unauthenticated APIs (2375, 2376), common debugger endpoints (2345,
/// 5678, 8001, 9229), Redis (6379), PostgreSQL (5432), and MySQL (3306) grant
/// code execution or direct access to devbox secrets and data.
pub fn denied_port(listener_port: u16, port: u16) -> bool {
    globally_denied(port) || port == listener_port
}

fn globally_denied(port: u16) -> bool {
    port == 0
        || port < LOWEST_CALLBACK_PORT
        || [PCSC_PORT, CHANNEL_PORT, FILES_PORT].contains(&port)
        || LETHAL_DEVELOPMENT_PORTS.contains(&port)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forward_internal_ports_are_never_armable() {
        // Given: services that the callback bridge must never reach.
        let forward_ports = [PCSC_PORT, CHANNEL_PORT, FILES_PORT];

        // When/Then: their local arming request is refused before acknowledgement.
        for port in forward_ports {
            assert!(!can_arm(port), "port {port} was armable");
        }
    }
}
