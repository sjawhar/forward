#[test]
fn test_constructor_is_visible_to_integration_tests() {
    // Given: an integration-test crate, which links the library normally and
    // therefore cannot see any `#[cfg(test)]` item inside it.

    // When: it builds a Config through the doc-hidden constructor.
    let cfg = forward::config::Config::default_values_for_test();

    // Then: it compiles and yields the fail-closed defaults. If someone marks
    // the constructor `#[cfg(test)]`, this file stops compiling, which is the
    // point: Tasks 2 and 5 onward call it from exactly here.
    assert_eq!(cfg.listen, "127.0.0.1");
    assert!(cfg.peer.is_empty());
    assert!(cfg.validate().is_ok());
}
