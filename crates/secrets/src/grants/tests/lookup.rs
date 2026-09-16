use super::*;
use crate::store::{FileIdentity, FileTimestamp};

#[test]
fn lookup_returns_the_grant_source_label() {
    // Given: a grant associated with the source file that supplied its plaintext.
    let mut table = GrantTable::default();
    let scope = Scope::Session(token(0xaa));
    let key = name("K");
    table.insert(
        scope.clone(),
        key.clone(),
        secret("v"),
        Instant::now(),
        origin("test.local"),
        Duration::from_hours(12),
    );

    // When: the grant is looked up for a repeat request.
    let (_, source, _) = table.lookup(&scope, &key, Instant::now()).unwrap();

    // Then: the label identifies the file that supplied the cached plaintext.
    assert_eq!(source, "test.local");
}

#[test]
fn lookup_retains_the_backing_file_identity() {
    // Given: a grant produced from one specific opened ciphertext file.
    let mut table = GrantTable::default();
    let scope = Scope::Session(token(0xaa));
    let key = name("K");
    let identity = FileIdentity::new(1, 2, 3, FileTimestamp::new(4, 5), FileTimestamp::new(6, 7));
    table.insert(
        scope.clone(),
        key.clone(),
        secret("v"),
        Instant::now(),
        GrantOrigin {
            source: "test".to_owned(),
            identity: identity.clone(),
        },
        Duration::from_hours(12),
    );

    // When: a later access compares the stored identity with a resolved file.
    let (_, _, stored) = table.lookup(&scope, &key, Instant::now()).unwrap();

    // Then: only the same device, inode, size, mtime, and ctime match.
    assert_eq!(stored, &identity);
    assert_ne!(
        stored,
        &FileIdentity::new(1, 2, 4, FileTimestamp::new(4, 5), FileTimestamp::new(6, 7),)
    );
    assert_ne!(
        stored,
        &FileIdentity::new(1, 2, 3, FileTimestamp::new(4, 5), FileTimestamp::new(6, 8),)
    );
}

#[test]
fn replacing_a_grant_replaces_its_source_label() {
    // Given: a cached grant sourced from one human file.
    let mut table = GrantTable::default();
    let scope = Scope::Session(token(0xaa));
    let key = name("K");
    table.insert(
        scope.clone(),
        key.clone(),
        secret("first"),
        Instant::now(),
        origin("test"),
        Duration::from_hours(12),
    );

    // When: a fresh grant replaces it after decrypting a differently labeled source.
    table.insert(
        scope.clone(),
        key.clone(),
        secret("second"),
        Instant::now(),
        origin("test.local"),
        Duration::from_hours(12),
    );

    // Then: repeat access observes the replacement's source label.
    let (_, source, _) = table.lookup(&scope, &key, Instant::now()).unwrap();
    assert_eq!(source, "test.local");
}

#[test]
fn lookup_refuses_a_grant_that_has_outlived_its_own_recorded_ttl() {
    // Given: a grant inserted with a short ttl, before the worker's periodic
    // sweep has had a chance to revoke it.
    let mut table = GrantTable::default();
    let scope = Scope::Session(token(0xaa));
    let key = name("K");
    let now = Instant::now();
    table.insert(
        scope.clone(),
        key.clone(),
        secret("v"),
        now,
        origin("test"),
        Duration::from_secs(30),
    );

    // When: looked up after its recorded ttl has elapsed.
    let after_expiry = now + Duration::from_secs(31);

    // Then: the cached plaintext is never served, even though the sweep has
    // not yet removed the stale entry.
    assert!(table.lookup(&scope, &key, after_expiry).is_none());
}
