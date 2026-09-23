use std::time::Duration;

use super::*;
use crate::config::Config;

#[test]
fn an_armed_port_is_reachable_until_it_expires() {
    // Given: a port armed for a very short window.
    let armed = Armed::new(Config::default_values_for_test());
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
    let armed = Armed::new(Config::default_values_for_test());
    armed.arm(8400, Duration::from_secs(60));

    // When/Then: a port nobody armed is not reachable through it.
    assert!(!armed.is_armed(9999));
}

#[test]
fn arming_again_extends_the_window() {
    // Given: a port armed for a window about to close.
    let armed = Armed::new(Config::default_values_for_test());
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
    let armed = Armed::new(Config::default_values_for_test());
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
    let armed = Armed::new(Config::default_values_for_test());
    let other = armed.clone();

    // When: one clone arms a port.
    other.arm(8400, Duration::from_secs(30));

    // Then: the original sees it.
    assert!(armed.is_armed(8400));
}

#[test]
fn dangerous_and_privileged_ports_are_never_armed() {
    // Given: ports that an OAuth loopback callback cannot legitimately own.
    let armed = Armed::new(Config::default_values_for_test());
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
