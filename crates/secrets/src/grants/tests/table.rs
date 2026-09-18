use std::time::Instant;

use super::*;

#[test]
fn grants_are_isolated_between_sessions() {
    let mut table = GrantTable::default();
    let now = Instant::now();
    let scope_a = Scope::Session(token(0xaa));
    let scope_b = Scope::Session(token(0xbb));
    table.insert(
        scope_a.clone(),
        name("K"),
        secret("v"),
        now,
        origin("test"),
        Duration::from_hours(12),
    );

    assert_eq!(
        table
            .lookup(&scope_a, &name("K"), now)
            .map(|(value, _, _)| value.as_slice()),
        Some(&b"v"[..])
    );
    assert!(
        table.lookup(&scope_b, &name("K"), now).is_none(),
        "sibling session inherited a grant"
    );
}

#[test]
fn tty_grants_are_not_shared_across_boot_ids() {
    let mut table = GrantTable::default();
    let now = Instant::now();
    let first = Scope::Tty {
        tty: "/dev/pts/3".to_owned(),
        boot_id: "first-boot".to_owned(),
    };
    let second = Scope::Tty {
        tty: "/dev/pts/3".to_owned(),
        boot_id: "second-boot".to_owned(),
    };
    table.insert(
        first.clone(),
        name("K"),
        secret("v"),
        now,
        origin("test"),
        Duration::from_hours(12),
    );

    assert_ne!(first, second);
    assert!(table.lookup(&second, &name("K"), now).is_none());
}

#[test]
fn revoking_tokens_drops_their_grants() {
    let mut table = GrantTable::default();
    let now = Instant::now();
    table.insert(
        Scope::Session(token(0xaa)),
        name("K"),
        secret("v"),
        now,
        origin("test"),
        Duration::from_hours(12),
    );
    table.revoke_tokens(&[token(0xaa)]);
    assert!(table.is_empty());
}

#[test]
fn backstop_expires_old_grants_only() {
    let mut table = GrantTable::default();
    let now = Instant::now();
    let old = now.checked_sub(Duration::from_hours(13)).unwrap();
    table.insert(
        Scope::Session(token(0xaa)),
        name("OLD"),
        secret("v"),
        old,
        origin("test"),
        Duration::from_hours(12),
    );
    table.insert(
        Scope::Session(token(0xbb)),
        name("NEW"),
        secret("v"),
        now,
        origin("test"),
        Duration::from_hours(12),
    );

    let removed = table.revoke_expired(now);
    assert_eq!(removed, 1);
    assert!(
        table
            .lookup(&Scope::Session(token(0xbb)), &name("NEW"), now)
            .is_some()
    );
    assert!(
        table
            .lookup(&Scope::Session(token(0xaa)), &name("OLD"), now)
            .is_none()
    );
}

#[test]
fn lock_revokes_everything() {
    let mut table = GrantTable::default();
    let now = Instant::now();
    table.insert(
        Scope::Session(token(0xaa)),
        name("K"),
        secret("v"),
        now,
        origin("test"),
        Duration::from_hours(12),
    );
    table.revoke_all();
    assert!(table.is_empty());
}

#[test]
fn render_never_includes_secret_values() {
    let mut table = GrantTable::default();
    let now = Instant::now();
    table.insert(
        Scope::Session(token(0xaa)),
        name("K"),
        secret("super-secret"),
        now,
        origin("test"),
        Duration::from_hours(12),
    );
    let rendered = table.render(now);
    assert!(rendered.contains('K'));
    assert!(
        !rendered.contains("super-secret"),
        "grant listing leaked a value"
    );
}
#[test]
fn a_shorter_ttl_expires_before_a_longer_one_inserted_at_the_same_time() {
    // Given: two grants inserted together with different requested lifetimes.
    let mut table = GrantTable::default();
    let now = Instant::now();
    table.insert(
        Scope::Session(token(0xaa)),
        name("SHORT"),
        secret("v"),
        now,
        origin("test"),
        Duration::from_secs(30),
    );
    table.insert(
        Scope::Session(token(0xbb)),
        name("LONG"),
        secret("v"),
        now,
        origin("test"),
        Duration::from_hours(12),
    );

    // When: time passes just beyond the shorter grant's own ttl.
    let later = now + Duration::from_secs(31);
    let removed = table.revoke_expired(later);

    // Then: only the grant that outlived its own recorded ttl is gone.
    assert_eq!(removed, 1);
    assert!(
        table
            .lookup(&Scope::Session(token(0xaa)), &name("SHORT"), later)
            .is_none()
    );
    assert!(
        table
            .lookup(&Scope::Session(token(0xbb)), &name("LONG"), later)
            .is_some()
    );
}

#[test]
fn remaining_secs_reports_the_live_grants_own_backstop() {
    let mut table = GrantTable::default();
    let now = Instant::now();
    let scope = Scope::Session(token(0xaa));
    table.insert(
        scope.clone(),
        name("K"),
        secret("v"),
        now,
        origin("test"),
        Duration::from_secs(100),
    );

    assert_eq!(
        table.remaining_secs(&scope, &name("K"), now + Duration::from_secs(40)),
        Some(60)
    );
}

#[test]
fn remaining_secs_is_none_for_a_missing_or_expired_grant() {
    let mut table = GrantTable::default();
    let now = Instant::now();
    let scope = Scope::Session(token(0xaa));
    assert_eq!(table.remaining_secs(&scope, &name("K"), now), None);

    table.insert(
        scope.clone(),
        name("K"),
        secret("v"),
        now,
        origin("test"),
        Duration::from_secs(10),
    );
    assert_eq!(
        table.remaining_secs(&scope, &name("K"), now + Duration::from_secs(11)),
        None
    );
}
