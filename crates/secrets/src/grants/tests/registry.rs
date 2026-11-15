use containment::omp::OmpProcess;

use super::*;

#[allow(
    clippy::unnecessary_wraps,
    reason = "the injectable registry locator is a function pointer returning Option"
)]
fn found_omp(_: &crate::peer::PeerIdentity) -> Option<OmpProcess> {
    Some(OmpProcess::new(42, 84))
}

fn no_omp(_: &crate::peer::PeerIdentity) -> Option<OmpProcess> {
    None
}

#[test]
#[cfg_attr(miri, ignore)]
fn omp_scope_token_stays_the_scope_when_an_omp_is_available() {
    let mut registry = Registry::new_with_omp_locator("test-boot".to_owned(), found_omp);
    registry
        .register(Registration {
            token: token(0xaa),
            session: "ses_a".to_owned(),
            root: crate::peer::current_for_test(),
        })
        .unwrap();

    let scope = registry
        .resolve(
            Some(&token(0xaa)),
            None,
            Some(&crate::peer::current_for_test()),
            ScopeUse::Capability,
        )
        .unwrap();

    assert_eq!(scope, Scope::Session(token(0xaa)));
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
                Some(&crate::peer::current_for_test()),
                ScopeUse::Secret
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
            ScopeUse::Capability,
        )
        .err();
    assert_eq!(err, Some(ErrCode::UnknownToken));
    assert!(!registry.is_agent_tty("/dev/pts/9"));
}

#[test]
#[cfg_attr(miri, ignore)]
fn omp_scope_tty_stays_the_scope_when_an_omp_is_available() {
    let mut registry = Registry::new_with_omp_locator("test-boot".to_owned(), found_omp);
    let scope = registry
        .resolve(
            None,
            Some("/dev/pts/7"),
            Some(&crate::peer::current_for_test()),
            ScopeUse::Capability,
        )
        .unwrap();

    assert_eq!(scope.kind(), ScopeKind::TokenlessTty);
}

#[test]
#[cfg_attr(miri, ignore)]
fn omp_scope_agent_tty_stays_refused_when_an_omp_is_available() {
    let mut registry = Registry::new_with_omp_locator("test-boot".to_owned(), found_omp);
    registry
        .register(Registration {
            token: token(0xaa),
            session: "ses_a".to_owned(),
            root: crate::peer::current_for_test(),
        })
        .unwrap();
    registry
        .resolve(
            Some(&token(0xaa)),
            Some("/dev/pts/3"),
            Some(&crate::peer::current_for_test()),
            ScopeUse::Secret,
        )
        .unwrap();

    assert_eq!(
        registry
            .resolve(
                None,
                Some("/dev/pts/3"),
                Some(&crate::peer::current_for_test()),
                ScopeUse::Capability
            )
            .err(),
        Some(ErrCode::AgentTty)
    );
}

#[test]
#[cfg_attr(miri, ignore)]
fn omp_scope_capability_uses_the_injected_omp() {
    let mut registry = Registry::new_with_omp_locator("test-boot".to_owned(), found_omp);

    let scope = registry
        .resolve(
            None,
            None,
            Some(&crate::peer::current_for_test()),
            ScopeUse::Capability,
        )
        .unwrap();

    assert_eq!(scope, Scope::Omp { pid: 42, start: 84 });
    assert_eq!(scope.kind(), ScopeKind::OmpProcess);
}

#[test]
#[cfg_attr(miri, ignore)]
fn omp_scope_capability_without_an_omp_has_no_scope() {
    let mut registry = Registry::new_with_omp_locator("test-boot".to_owned(), no_omp);

    assert_eq!(
        registry
            .resolve(
                None,
                None,
                Some(&crate::peer::current_for_test()),
                ScopeUse::Capability
            )
            .err(),
        Some(ErrCode::NoScope)
    );
}

#[test]
#[cfg_attr(miri, ignore)]
fn omp_scope_secret_use_never_falls_back_to_an_omp() {
    let mut registry = Registry::new_with_omp_locator("test-boot".to_owned(), found_omp);

    assert_eq!(
        registry
            .resolve(
                None,
                None,
                Some(&crate::peer::current_for_test()),
                ScopeUse::Secret
            )
            .err(),
        Some(ErrCode::NoScope)
    );
}

#[test]
#[cfg_attr(miri, ignore)]
fn unregister_returns_tokens_to_revoke() {
    let mut registry = registered();
    let revoked = registry
        .unregister("ses_a", &crate::peer::current_for_test())
        .unwrap();
    assert_eq!(revoked, vec![token(0xaa)]);
    assert_eq!(
        registry
            .resolve(
                Some(&token(0xaa)),
                None,
                Some(&crate::peer::current_for_test()),
                ScopeUse::Secret
            )
            .err(),
        Some(ErrCode::UnknownToken)
    );
}
