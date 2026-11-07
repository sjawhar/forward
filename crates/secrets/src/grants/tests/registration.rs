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

    assert_eq!(refused.err(), Some(Refusal::TokenBoundElsewhere));
    assert_eq!(registry.sessions.len(), 1);
    assert_eq!(
        registry
            .registration(&token)
            .map(|entry| entry.session.clone()),
        Some("ses_a".to_owned())
    );
}

/// Register `session` as a process this test does not descend from.
///
/// The returned child is the holder: it stays alive until it is dropped or
/// told to exit, so the registry sees a live root outside the caller's tree.
fn held_by_a_stranger(registry: &mut Registry, session: &str, held: SessionToken) -> ChildPeer {
    let holder = ChildPeer::spawn();
    registry
        .register(Registration {
            token: held,
            session: session.to_owned(),
            root: holder.identity().clone(),
        })
        .unwrap();
    holder
}

#[test]
#[cfg_attr(miri, ignore)]
fn a_first_register_for_a_session_nobody_holds_succeeds() {
    // Every session starts this way, so the displacement rule must not stand
    // in front of an identifier no live process holds.
    let mut registry = Registry::default();

    let displaced = registry
        .register(Registration {
            token: token(0xaa),
            session: "ses_a".to_owned(),
            root: crate::peer::current_for_test(),
        })
        .unwrap();

    assert!(displaced.is_empty());
    assert_eq!(registry.sessions.len(), 1);
}

#[test]
#[cfg_attr(miri, ignore)]
fn the_holder_may_re_register_its_own_session_with_a_new_token() {
    // omp's recovery path: the daemon restarted, so the harness mints a fresh
    // token and registers the same session identifier again from the same
    // process. Refusing that would strand every session on a daemon restart.
    let mut registry = Registry::default();
    registry
        .register(Registration {
            token: token(0xaa),
            session: "ses_a".to_owned(),
            root: crate::peer::current_for_test(),
        })
        .unwrap();

    let displaced = registry
        .register(Registration {
            token: token(0xbb),
            session: "ses_a".to_owned(),
            root: crate::peer::current_for_test(),
        })
        .unwrap();

    assert_eq!(displaced, vec![token(0xaa)]);
    assert_eq!(
        registry
            .registration(&token(0xbb))
            .map(|entry| entry.session.clone()),
        Some("ses_a".to_owned())
    );
}

#[test]
#[cfg_attr(miri, ignore)]
fn a_descendant_of_the_holder_may_re_register_the_session() {
    // The holder is this process and the caller is its child, which is the
    // shape of every harness that re-registers from a helper it spawned.
    let mut registry = Registry::default();
    registry
        .register(Registration {
            token: token(0xaa),
            session: "ses_a".to_owned(),
            root: crate::peer::current_for_test(),
        })
        .unwrap();
    let caller = ChildPeer::spawn();

    let displaced = registry
        .register(Registration {
            token: token(0xbb),
            session: "ses_a".to_owned(),
            root: caller.identity().clone(),
        })
        .unwrap();

    assert_eq!(displaced, vec![token(0xaa)]);
    assert!(registry.registration(&token(0xaa)).is_none());
    assert_eq!(
        registry.resolve(Some(&token(0xbb)), None, Some(caller.identity())),
        Ok(Scope::Session(token(0xbb)))
    );
    assert_eq!(
        registry.resolve(
            Some(&token(0xbb)),
            None,
            Some(&crate::peer::current_for_test())
        ),
        Err(ErrCode::ForeignCaller)
    );
}

#[test]
#[cfg_attr(miri, ignore)]
fn refuses_a_register_that_would_displace_a_live_holder() {
    // The 2026-11-07 incident (dispatch://INFRA-1644): a second process named
    // a live session's identifier, and the registry handed it the session.
    let mut registry = Registry::default();
    let holder = held_by_a_stranger(&mut registry, "ses_a", token(0xaa));
    let holder_pid = holder.identity().pid();

    let refused = registry.register(Registration {
        token: token(0xbb),
        session: "ses_a".to_owned(),
        root: crate::peer::current_for_test(),
    });

    assert_eq!(refused.err(), Some(Refusal::ForeignClaim { holder_pid }));
    // The victim keeps its registration, so its own requests still resolve.
    assert_eq!(registry.sessions.len(), 1);
    assert_eq!(
        registry
            .resolve(Some(&token(0xaa)), None, Some(holder.identity()))
            .ok(),
        Some(Scope::Session(token(0xaa)))
    );
    assert!(registry.registration(&token(0xbb)).is_none());
}

#[test]
#[cfg_attr(miri, ignore)]
fn refuses_an_unregister_from_outside_the_holders_process_tree() {
    // UNREGISTER names a session and carries no token, so without the check
    // any process could end any session's scope by naming it.
    let mut registry = Registry::default();
    let holder = held_by_a_stranger(&mut registry, "ses_a", token(0xaa));
    let holder_pid = holder.identity().pid();

    let refused = registry.unregister("ses_a", &crate::peer::current_for_test());

    assert_eq!(refused.err(), Some(Refusal::ForeignClaim { holder_pid }));
    assert_eq!(
        registry
            .resolve(Some(&token(0xaa)), None, Some(holder.identity()))
            .ok(),
        Some(Scope::Session(token(0xaa)))
    );
}

#[test]
#[cfg_attr(miri, ignore)]
fn the_holder_may_unregister_its_own_session() {
    let mut registry = Registry::default();
    registry
        .register(Registration {
            token: token(0xaa),
            session: "ses_a".to_owned(),
            root: crate::peer::current_for_test(),
        })
        .unwrap();

    let revoked = registry
        .unregister("ses_a", &crate::peer::current_for_test())
        .unwrap();

    assert_eq!(revoked, vec![token(0xaa)]);
    assert!(registry.sessions.is_empty());
}

#[test]
#[cfg_attr(miri, ignore)]
fn unregistering_a_session_nobody_holds_stays_a_success() {
    // A harness shutting down after the daemon restarted has nothing to
    // remove, and must not be handed an error for work already done.
    let mut registry = Registry::default();

    let revoked = registry
        .unregister("ses_gone", &crate::peer::current_for_test())
        .unwrap();

    assert!(revoked.is_empty());
}

#[test]
#[cfg_attr(miri, ignore)]
fn a_session_whose_holder_exited_can_be_claimed_again() {
    // A session killed outright never sends UNREGISTER. Its pinned root
    // reports no pid, nothing can descend from it, and `resolve` already
    // refuses every caller, so the identifier is free for the next process.
    let mut registry = Registry::default();
    let mut holder = held_by_a_stranger(&mut registry, "ses_a", token(0xaa));
    holder.exit();
    assert_eq!(holder.identity().pid(), None);

    let displaced = registry
        .register(Registration {
            token: token(0xbb),
            session: "ses_a".to_owned(),
            root: crate::peer::current_for_test(),
        })
        .unwrap();

    assert_eq!(displaced, vec![token(0xaa)]);
    assert_eq!(
        registry
            .resolve(
                Some(&token(0xbb)),
                None,
                Some(&crate::peer::current_for_test())
            )
            .ok(),
        Some(Scope::Session(token(0xbb)))
    );
}

#[test]
#[cfg_attr(miri, ignore)]
fn a_holder_that_has_exited_but_is_unreaped_still_holds_its_session() {
    // "Gone" means the kernel says so. A zombie still has a pid, and the
    // daemon cannot tell a pid it can still read from one whose owner is
    // mid-teardown, so the session stays held until the holder is reaped.
    // Releasing on anything softer would mean releasing on a read that merely
    // failed -- the fail-open this whole check exists to remove.
    let mut registry = Registry::default();
    let mut holder = held_by_a_stranger(&mut registry, "ses_a", token(0xaa));
    holder.zombify();
    assert!(holder.identity().pid().is_some());
    assert_ne!(holder.identity().liveness(), crate::peer::Liveness::Exited);

    let refused = registry.register(Registration {
        token: token(0xbb),
        session: "ses_a".to_owned(),
        root: crate::peer::current_for_test(),
    });

    assert!(matches!(refused.err(), Some(Refusal::ForeignClaim { .. })));

    assert!(matches!(
        registry
            .unregister("ses_a", &crate::peer::current_for_test())
            .err(),
        Some(Refusal::ForeignClaim { .. })
    ));
    assert!(registry.registration(&token(0xaa)).is_some());
}

#[test]
#[cfg_attr(miri, ignore)]
fn reclaiming_a_dead_session_needs_a_new_token_not_the_old_one() {
    // Re-presenting a session's current token stays a no-op even once its
    // holder is gone, so the dead root is kept rather than transferred. That
    // is deliberate: adopting the root would hand the dead session's existing
    // grants to whoever read its token file, with no touch. Reclaiming the
    // identifier means presenting a new token, which revokes those grants.
    let mut registry = Registry::default();
    let mut holder = held_by_a_stranger(&mut registry, "ses_a", token(0xaa));
    holder.exit();

    let displaced = registry
        .register(Registration {
            token: token(0xaa),
            session: "ses_a".to_owned(),
            root: crate::peer::current_for_test(),
        })
        .unwrap();

    assert!(displaced.is_empty());
    assert_eq!(
        registry
            .resolve(
                Some(&token(0xaa)),
                None,
                Some(&crate::peer::current_for_test())
            )
            .err(),
        Some(ErrCode::ForeignCaller),
        "the dead root must not be transferred to the caller that re-presented its token"
    );
}

#[test]
#[cfg_attr(miri, ignore)]
fn known_tokens_cannot_move_or_shadow_either_sessions_registration() {
    let mut registry = Registry::default();
    let holder = held_by_a_stranger(&mut registry, "ses_a", token(0xaa));
    let caller = crate::peer::current_for_test();
    registry
        .register(Registration {
            token: token(0xbb),
            session: "ses_b".to_owned(),
            root: caller.clone(),
        })
        .unwrap();

    for (presented, session) in [(token(0xaa), "ses_b"), (token(0xbb), "ses_a")] {
        assert_eq!(
            registry
                .register(Registration {
                    token: presented,
                    session: session.to_owned(),
                    root: caller.clone(),
                })
                .err(),
            Some(Refusal::TokenBoundElsewhere)
        );
    }
    assert!(
        registry
            .register(Registration {
                token: token(0xaa),
                session: "ses_a".to_owned(),
                root: caller.clone(),
            })
            .unwrap()
            .is_empty()
    );

    assert_eq!(registry.sessions.len(), 2);
    assert_eq!(
        registry.resolve(Some(&token(0xaa)), None, Some(&caller)),
        Err(ErrCode::ForeignCaller)
    );
    assert_eq!(
        registry.resolve(Some(&token(0xaa)), None, Some(holder.identity())),
        Ok(Scope::Session(token(0xaa)))
    );
    assert_eq!(
        registry.resolve(Some(&token(0xbb)), None, Some(&caller)),
        Ok(Scope::Session(token(0xbb)))
    );
}

#[test]
#[cfg_attr(miri, ignore)]
fn an_unreadable_holder_does_not_release_its_registration() {
    // No Pid field is an unknown identity, not positive evidence of death.
    let root =
        crate::peer::PeerIdentity::from_owned_fd(std::fs::File::open("/dev/null").unwrap().into());
    let mut registry = Registry::default();
    registry
        .register(Registration {
            token: token(0xaa),
            session: "ses_a".to_owned(),
            root,
        })
        .unwrap();
    let refusal = Some(Refusal::ForeignClaim { holder_pid: None });
    let caller = crate::peer::current_for_test();

    assert_eq!(
        registry
            .register(Registration {
                token: token(0xbb),
                session: "ses_a".to_owned(),
                root: caller.clone(),
            })
            .err(),
        refusal
    );
    assert_eq!(registry.unregister("ses_a", &caller).err(), refusal);
    assert_eq!(registry.sessions.len(), 1);
    assert!(registry.registration(&token(0xaa)).is_some());
    assert!(registry.registration(&token(0xbb)).is_none());
}

#[test]
#[cfg_attr(miri, ignore)]
fn a_live_descendant_may_unregister_but_a_reaped_caller_cannot() {
    let mut registry = registered();
    let mut caller = ChildPeer::spawn();
    caller.exit();

    assert!(matches!(
        registry.unregister("ses_a", caller.identity()).err(),
        Some(Refusal::ForeignClaim { .. })
    ));
    assert!(registry.registration(&token(0xaa)).is_some());

    let live_caller = ChildPeer::spawn();
    assert_eq!(
        registry
            .unregister("ses_a", live_caller.identity())
            .unwrap(),
        vec![token(0xaa)]
    );
    assert!(registry.sessions.is_empty());
}

#[test]
#[cfg_attr(miri, ignore)]
fn a_reaped_holder_can_be_unregistered_by_an_unrelated_caller() {
    let mut registry = Registry::default();
    let mut holder = held_by_a_stranger(&mut registry, "ses_a", token(0xaa));
    holder.exit();

    assert_eq!(
        registry
            .unregister("ses_a", &crate::peer::current_for_test())
            .unwrap(),
        vec![token(0xaa)]
    );
    assert!(registry.sessions.is_empty());
}
