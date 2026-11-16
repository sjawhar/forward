use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use super::super::Outcome;
use super::super::capability::authorize;
use crate::grants::Registry;
use crate::proto::ErrCode;
use crate::store::HumanSource;

#[test]
#[cfg_attr(miri, ignore)]
fn retry_omp_scope_wrong_start_denies_before_a_second_decrypt() {
    let directory = tempfile::tempdir().unwrap();
    let human_dir = directory.path().join("human");
    std::fs::create_dir(&human_dir).unwrap();
    std::fs::write(human_dir.join("CAP_BROWSER.env"), b"ciphertext").unwrap();
    let sops = directory.path().join("fake-sops");
    std::fs::write(
        &sops,
        "#!/bin/sh\nprintf 'run\\n' >> \"${0}.calls\"\nprintf '%s\\n' 'failed to decrypt yubikey stanza' >&2\nexit 1\n",
    )
    .unwrap();
    std::fs::set_permissions(&sops, std::fs::Permissions::from_mode(0o700)).unwrap();
    let config = crate::Config {
        socket_path: PathBuf::from("/tmp/secretsd-omp-retry-test.sock"),
        human_sources: vec![HumanSource {
            label: "test".to_owned(),
            dir: human_dir,
        }],
        sops_bin: sops.clone(),
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
    let mut state = crate::server::State::new(config).unwrap();
    state.registry =
        Registry::new_with_omp_locator("test-boot".to_owned(), super::omp_with_wrong_start);
    let shared = Arc::new((Mutex::new(state), Condvar::new()));
    let caller = crate::peer::ChildPeer::spawn();
    let worker_shared = Arc::clone(&shared);
    let _worker = std::thread::spawn(move || crate::server::worker(&worker_shared));

    let decision = authorize(&shared, "browser", None, None, caller.identity());

    assert!(matches!(
        &decision.outcome,
        Outcome::Failed(ErrCode::Denied, _)
    ));
    assert!(!matches!(&decision.outcome, Outcome::Receipt(_)));
    assert_eq!(
        std::fs::read_to_string(format!("{}.calls", sops.display()))
            .unwrap_or_default()
            .lines()
            .count(),
        1
    );
}
