use super::*;

#[test]
#[cfg_attr(miri, ignore)]
fn resolves_registered_token_to_session_scope() {
    let mut registry = registered();
    let scope = registry
        .resolve(
            Some(&token(0xaa)),
            Some("/dev/pts/3"),
            Some(&crate::peer::current_for_test()),
        )
        .unwrap();
    assert_eq!(scope.kind(), ScopeKind::VerifiedSession);
}

#[test]
#[cfg_attr(miri, ignore)]
fn rejects_unregistered_token() {
    let mut registry = registered();
    assert_eq!(
        registry
            .resolve(
                Some(&token(0xbb)),
                Some("/dev/pts/3"),
                Some(&crate::peer::current_for_test())
            )
            .err(),
        Some(ErrCode::UnknownToken)
    );
}

#[test]
#[cfg_attr(miri, ignore)]
fn unknown_token_never_falls_back_to_tokenless() {
    // A stale token (broker restarted, session did not re-register) must be
    // a hard identity error -- silently degrading to a tty scope would let
    // an env-stripped agent launder itself into the interactive path.
    let mut registry = registered();
    let err = registry
        .resolve(
            Some(&token(0xcc)),
            Some("/dev/pts/9"),
            Some(&crate::peer::current_for_test()),
        )
        .err();
    assert_eq!(err, Some(ErrCode::UnknownToken));
    assert!(!registry.is_agent_tty("/dev/pts/9"));
}

#[test]
#[cfg_attr(miri, ignore)]
fn tokenless_request_from_fresh_tty_is_interactive() {
    let mut registry = registered();
    let scope = registry
        .resolve(
            None,
            Some("/dev/pts/7"),
            Some(&crate::peer::current_for_test()),
        )
        .unwrap();
    assert_eq!(scope.kind(), ScopeKind::TokenlessTty);
}

#[test]
#[cfg_attr(miri, ignore)]
fn tokenless_request_from_learned_agent_tty_is_rejected() {
    let mut registry = registered();
    registry
        .resolve(
            Some(&token(0xaa)),
            Some("/dev/pts/3"),
            Some(&crate::peer::current_for_test()),
        )
        .unwrap();
    assert!(registry.is_agent_tty("/dev/pts/3"));
    assert_eq!(
        registry
            .resolve(
                None,
                Some("/dev/pts/3"),
                Some(&crate::peer::current_for_test())
            )
            .err(),
        Some(ErrCode::AgentTty)
    );
}

#[test]
#[cfg_attr(miri, ignore)]
fn request_without_token_or_tty_has_no_scope() {
    let mut registry = registered();
    assert_eq!(
        registry
            .resolve(None, None, Some(&crate::peer::current_for_test()))
            .err(),
        Some(ErrCode::NoScope)
    );
}

#[test]
#[cfg_attr(miri, ignore)]
fn unregister_returns_tokens_to_revoke() {
    let mut registry = registered();
    let revoked = registry.unregister("ses_a");
    assert_eq!(revoked, vec![token(0xaa)]);
    assert_eq!(
        registry
            .resolve(
                Some(&token(0xaa)),
                None,
                Some(&crate::peer::current_for_test())
            )
            .err(),
        Some(ErrCode::UnknownToken)
    );
}
