use crate::callback::service_ports;
use crate::config::Config;

const LOWEST_CALLBACK_PORT: u16 = 1_024;
const LETHAL_DEVELOPMENT_PORTS: [u16; 9] = [
    2_345, 2_375, 2_376, 3_306, 5_432, 5_678, 6_379, 8_001, 9_229,
];

pub(super) fn can_arm(cfg: &Config, port: u16) -> bool {
    !globally_denied(cfg, port)
}

/// Whether `port` is never safe for the callback bridge to dial.
///
/// The denied forward services derive from the effective config: the URL
/// channel, file preview, bridge, browser relay, pcsc channel, grant feed, and
/// pulse channel.
/// The shipped list held constants and missed the configurable relay port,
/// letting the bridge dial the browser relay; deriving from `Config` closes the
/// class of self-routing holes. Port zero has no destination, ports below 1024
/// are privileged and cannot be legitimate RFC 8252 loopback callbacks, and
/// the configured listener port would recurse. Docker's unauthenticated APIs
/// (2375, 2376), common debugger endpoints (2345, 5678, 8001, 9229), Redis
/// (6379), PostgreSQL (5432), and MySQL (3306) grant code execution or direct
/// access to devbox secrets and data.
pub fn denied_port(cfg: &Config, listener_port: u16, port: u16) -> bool {
    globally_denied(cfg, port) || port == listener_port
}

fn globally_denied(cfg: &Config, port: u16) -> bool {
    port == 0
        || port < LOWEST_CALLBACK_PORT
        || service_ports(cfg).contains(&port)
        || LETHAL_DEVELOPMENT_PORTS.contains(&port)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::callback::{CHANNEL_PORT, FILES_PORT};
    use crate::config::Config;

    #[test]
    fn the_default_relay_port_is_denied() {
        // Regression for the shipped defect: relay_port joined the config in
        // v0.4.0 but never joined this denylist, so the bridge could dial the
        // browser relay listener. The effective config is the source of truth.
        let cfg = Config::default_values_for_test();
        assert!(!can_arm(&cfg, cfg.relay_port));
        assert!(denied_port(&cfg, cfg.bridge_port, cfg.relay_port));
    }

    #[test]
    fn every_effective_service_port_is_denied_even_when_overridden() {
        // Given: a config that moves every configurable service port off its
        // default, the way a machine resolving a port conflict would.
        let mut cfg = Config::default_values_for_test();
        cfg.bridge_port = 12_901;
        cfg.relay_port = 12_903;
        cfg.pcsc_port = 12_914;
        cfg.grant_port = 12_915;
        cfg.pulse_port = 12_916;

        // When/Then: the constants and every effective port refuse arming.
        for port in [
            CHANNEL_PORT,
            FILES_PORT,
            12_901,
            12_903,
            12_914,
            12_915,
            12_916,
        ] {
            assert!(!can_arm(&cfg, port), "port {port} was armable");
        }
        // And the abandoned defaults are ordinary callback ports again, as is
        // the retired tunnel port — proof the set tracks config, not constants.
        for abandoned in [
            crate::config::default_relay_port(),
            crate::config::default_pcsc_port(),
            crate::config::default_grant_port(),
            crate::config::default_pulse_port(),
            12_799,
        ] {
            assert!(can_arm(&cfg, abandoned), "port {abandoned} still reserved");
        }
    }
}
