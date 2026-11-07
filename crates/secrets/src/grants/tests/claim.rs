use super::*;

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
