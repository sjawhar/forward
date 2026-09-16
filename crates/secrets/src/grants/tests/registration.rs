use std::time::Instant;

use super::*;

#[test]
#[cfg_attr(miri, ignore)]
fn replacing_a_session_revokes_its_displaced_token_grants_from_the_table() {
    // Given: a session and a grant associated with its original token.
    let mut registry = Registry::default();
    let mut table = GrantTable::default();
    let original = token(0xaa);
    registry
        .register(Registration {
            token: original,
            session: "ses_a".to_owned(),
            root: crate::peer::current_for_test(),
        })
        .unwrap();
    table.insert(
        Scope::Session(original),
        name("K"),
        secret("v"),
        Instant::now(),
        origin("test"),
        Duration::from_hours(12),
    );

    // When: the same session identifier is registered with a new token.
    let displaced = registry
        .register(Registration {
            token: token(0xbb),
            session: "ses_a".to_owned(),
            root: crate::peer::current_for_test(),
        })
        .unwrap();
    table.revoke_tokens(&displaced);

    // Then: the old token's plaintext grant was removed, not merely hidden.
    assert!(
        table.grants.is_empty(),
        "replacing a session left its displaced token grant in the table"
    );
}

#[test]
#[cfg_attr(miri, ignore)]
fn re_registering_same_token_keeps_its_grants() {
    // Re-affirming a session with its own current token -- what the plugin
    // does to recover a registration the broker lost on restart -- must not
    // revoke the grants that token already holds. Only a genuine token change
    // displaces (see the test above); the same token is idempotent.
    let mut registry = Registry::default();
    let mut table = GrantTable::default();
    let token = token(0xaa);
    registry
        .register(Registration {
            token,
            session: "ses_a".to_owned(),
            root: crate::peer::current_for_test(),
        })
        .unwrap();
    table.insert(
        Scope::Session(token),
        name("K"),
        secret("v"),
        Instant::now(),
        origin("test"),
        Duration::from_hours(12),
    );

    // When: the same session re-registers with the identical token.
    let displaced = registry
        .register(Registration {
            token,
            session: "ses_a".to_owned(),
            root: crate::peer::current_for_test(),
        })
        .unwrap();
    table.revoke_tokens(&displaced);

    // Then: nothing was displaced and the live grant survived.
    assert!(
        displaced.is_empty(),
        "re-registering a session's own token displaced it"
    );
    assert!(
        table
            .lookup(&Scope::Session(token), &name("K"), Instant::now())
            .is_some(),
        "re-registering a session's own token dropped its grant"
    );
}

#[test]
#[cfg_attr(miri, ignore)]
fn re_registering_a_live_token_keeps_the_root_it_was_pinned_to() {
    // A same-uid caller can read a session's token file -- that is an
    // accepted residual -- so REGISTER must never let it become the root of a
    // session that already holds grants. Were the root replaced here, the
    // ancestry check would then pass for that caller and hand it the grant
    // with no touch, defeating the containment FOREIGN_CALLER provides.
    let mut registry = Registry::default();
    let token = token(0xaa);
    registry
        .register(Registration {
            token,
            session: "ses_a".to_owned(),
            root: crate::peer::current_for_test(),
        })
        .unwrap();

    // When: the same session and token are presented again.
    registry
        .register(Registration {
            token,
            session: "ses_a".to_owned(),
            root: crate::peer::current_for_test(),
        })
        .unwrap();

    // Then: exactly one registration survives, so no second binding can
    // shadow it, and its root is the one the first REGISTER pinned.
    assert_eq!(registry.sessions.len(), 1);
    assert_eq!(
        registry
            .registration(&token)
            .map(|entry| entry.session.clone()),
        Some("ses_a".to_owned())
    );
}

#[test]
#[cfg_attr(miri, ignore)]
fn refuses_a_token_already_bound_to_another_session() {
    // One token names exactly one session. Allowing a second binding would
    // make `resolve`'s lookup order-dependent, so a caller that read the
    // token file could register it under a name of its own and race to be
    // the entry that `find` returns.
    let mut registry = Registry::default();
    let token = token(0xaa);
    registry
        .register(Registration {
            token,
            session: "ses_a".to_owned(),
            root: crate::peer::current_for_test(),
        })
        .unwrap();

    let refused = registry.register(Registration {
        token,
        session: "ses_impostor".to_owned(),
        root: crate::peer::current_for_test(),
    });

    assert_eq!(refused.err(), Some(ErrCode::BadRequest));
    assert_eq!(registry.sessions.len(), 1);
    assert_eq!(
        registry
            .registration(&token)
            .map(|entry| entry.session.clone()),
        Some("ses_a".to_owned())
    );
}
