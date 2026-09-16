use std::sync::{Mutex, mpsc};
use std::time::Instant;

use super::*;
use crate::server::approval::Access;

#[test]
fn receipt_capacity_is_not_reported_as_an_entropy_failure() {
    let error = std::io::Error::from(std::io::ErrorKind::WouldBlock);

    assert!(matches!(
        receipt_mint_failure(&error),
        Outcome::Failed(ErrCode::TooManyPending, _)
    ));
}

#[test]
fn receipt_entropy_failure_is_internal() {
    let error = std::io::Error::from(std::io::ErrorKind::NotFound);

    assert!(matches!(
        receipt_mint_failure(&error),
        Outcome::Failed(ErrCode::Internal, _)
    ));
}

#[test]
fn receipt_outcome_debug_is_redacted() {
    let receipt = Zeroizing::new("a".repeat(crate::receipts::RECEIPT_LEN * 2));

    assert_eq!(
        format!("{:?}", Outcome::Receipt(receipt)),
        "Receipt(<redacted>)"
    );
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "this lock-race regression needs one complete broker state fixture"
)]
fn lock_between_authorization_and_mint_clears_capability_grants_and_refuses_the_receipt() {
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::sync::{Arc, Condvar};
    use std::time::Duration;

    use crate::grants::{Registration, SessionToken};
    use crate::store::HumanSource;

    let directory = tempfile::tempdir();
    assert!(directory.is_ok());
    let Some(directory) = directory.ok() else {
        return;
    };
    let human_dir = directory.path().join("human");
    assert!(std::fs::create_dir(&human_dir).is_ok());
    assert!(std::fs::write(human_dir.join("CAP_BROWSER.env"), b"ciphertext").is_ok());
    let sops = directory.path().join("fake-sops");
    assert!(std::fs::write(&sops, "#!/bin/sh\nprintf 'CAP_BROWSER=value\\n'\n").is_ok());
    assert!(std::fs::set_permissions(&sops, std::fs::Permissions::from_mode(0o700)).is_ok());
    let config = crate::Config {
        socket_path: PathBuf::from("/tmp/secretsd-dispatch-test.sock"),
        human_sources: vec![HumanSource {
            label: "test".to_owned(),
            dir: human_dir,
        }],
        sops_bin: sops,
        pcsc_socket: None,
        yubikey_probe_argv: Vec::new(),
        yubikey_probe_timeout: Duration::from_secs(2),
        touch_policy: crate::TouchPolicy::Cached,
        max_grant: Duration::from_secs(1),
        max_requested_grant: Duration::from_secs(1),
        cooldown: Duration::ZERO,
        request_ttl: Duration::from_secs(1),
        max_pending_per_scope: 1,
    };
    let state = super::super::State::new(config);
    assert!(state.is_ok());
    let Some(state) = state.ok() else {
        return;
    };
    let shared = Arc::new((Mutex::new(state), Condvar::new()));
    let caller = crate::peer::current_for_test();
    let token_hex = "aa".repeat(32);
    let token = SessionToken::parse_hex(&token_hex);
    assert!(token.is_ok());
    let Some(token) = token.ok() else {
        return;
    };
    let registered = super::super::lock_state(&shared.0)
        .registry
        .register(Registration {
            token,
            session: "session".to_owned(),
            root: caller.clone(),
        });
    assert!(registered.is_ok());
    let cap = crate::capability::Capability::parse("browser");
    assert!(cap.is_ok());
    let Some(cap) = cap.ok() else {
        return;
    };
    let access = Access {
        key: cap.key_name(),
        token_hex: Some(Zeroizing::new(token_hex)),
        tty: None,
        requested_ttl: None,
    };
    super::super::lock_state(&shared.0)
        .capability_grants
        .insert(Instant::now() + Duration::from_secs(1));
    let epoch_before = super::super::lock_state(&shared.0).lock_epoch;
    let worker_shared = Arc::clone(&shared);
    let _worker = std::thread::spawn(move || super::super::worker(&worker_shared));
    let decision = dispatch_access(&shared, &access, false, true, &caller);
    assert!(decision.request_id.is_some());
    assert!(matches!(&decision.outcome, Outcome::Fields(_)));
    let (entered_tx, entered_rx) = mpsc::sync_channel(0);
    let (resume_tx, resume_rx) = mpsc::sync_channel(0);
    let mut pause = mint_pause()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    assert!(pause.is_none());
    *pause = Some(MintPause {
        entered: entered_tx,
        resume: resume_rx,
    });
    drop(pause);
    let shared_for_authorize = Arc::clone(&shared);
    let authorizer = std::thread::spawn(move || {
        finish_authorization(&shared_for_authorize, &cap, epoch_before, decision)
    });
    assert!(entered_rx.recv_timeout(Duration::from_secs(1)).is_ok());
    lock(&shared);
    assert_eq!(
        super::super::lock_state(&shared.0).capability_grants.len(),
        0
    );
    let _ = resume_tx.send(());
    let result = authorizer.join();
    assert!(result.is_ok());
    let Ok(decision) = result else {
        return;
    };
    assert!(matches!(
        decision.outcome,
        Outcome::Failed(ErrCode::Denied, "locked during authorization")
    ));
}
