use super::*;

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
