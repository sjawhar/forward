#[cfg(test)]
use std::sync::{LazyLock, Mutex, mpsc};
use std::time::Instant;

use zeroize::Zeroizing;

use super::{Decision, Outcome};
use crate::proto::ErrCode;
use crate::server::approval::{Access, dispatch_access};
use crate::server::{Shared, lock_state};

pub(super) fn receipt_mint_failure(error: &std::io::Error) -> Outcome {
    match error.kind() {
        std::io::ErrorKind::WouldBlock => {
            Outcome::Failed(ErrCode::TooManyPending, "too many outstanding receipts")
        }
        _ => Outcome::Failed(ErrCode::Internal, "receipt entropy unavailable"),
    }
}

#[cfg(test)]
pub(super) struct MintPause {
    pub(super) entered: mpsc::SyncSender<()>,
    pub(super) resume: mpsc::Receiver<()>,
}

#[cfg(test)]
pub(super) fn mint_pause() -> &'static Mutex<Option<MintPause>> {
    static PAUSE: LazyLock<Mutex<Option<MintPause>>> = LazyLock::new(|| Mutex::new(None));
    &PAUSE
}

#[cfg(test)]
pub(super) fn pause_before_receipt_mint() {
    let pause = mint_pause()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take();
    if let Some(pause) = pause {
        let _ = pause.entered.send(());
        let _ = pause.resume.recv();
    }
}

pub(super) fn finish_authorization(
    shared: &Shared,
    cap: &crate::capability::Capability,
    epoch_before: u64,
    Decision {
        outcome,
        scope_kind,
        source,
        request_id,
    }: Decision,
) -> Decision {
    #[cfg(test)]
    pause_before_receipt_mint();
    let (mutex, _) = &**shared;
    let outcome = match (outcome, request_id) {
        (Outcome::Fields(_), Some(_)) => {
            let mut state = lock_state(mutex);
            if state.lock_epoch == epoch_before {
                state
                    .receipts
                    .mint(cap, Instant::now())
                    .map_or_else(|error| receipt_mint_failure(&error), Outcome::Receipt)
            } else {
                Outcome::Failed(ErrCode::Denied, "locked during authorization")
            }
        }
        (other, _) => other,
    };
    Decision {
        outcome,
        scope_kind,
        source,
        request_id,
    }
}

pub(super) fn authorize(
    shared: &Shared,
    cap: &str,
    token_hex: Option<Zeroizing<String>>,
    tty: Option<String>,
    caller: &crate::peer::PeerIdentity,
) -> Decision {
    let cap = match crate::capability::Capability::parse(cap) {
        Ok(cap) => cap,
        Err(error) => return Decision::new(Outcome::Failed(error, "invalid capability name")),
    };
    let access = Access {
        key: cap.key_name(),
        token_hex,
        tty,
        requested_ttl: None,
    };
    let (mutex, _) = &**shared;
    let epoch_before = lock_state(mutex).lock_epoch;
    let decision = dispatch_access(shared, &access, false, true, caller);
    finish_authorization(shared, &cap, epoch_before, decision)
}

pub(super) fn redeem(shared: &Shared, receipt_hex: &str, expected_cap: &str) -> Decision {
    let expected_cap = match crate::capability::Capability::parse(expected_cap) {
        Ok(cap) => cap,
        Err(error) => return Decision::new(Outcome::Failed(error, "invalid capability name")),
    };
    let (mutex, _) = &**shared;
    let mut state = lock_state(mutex);
    let now = Instant::now();
    let Some(deadline) = now.checked_add(state.config.max_grant) else {
        return Decision::new(Outcome::Failed(
            ErrCode::Internal,
            "capability grant deadline is out of range",
        ));
    };
    let redeemed = state.receipts.redeem(receipt_hex, &expected_cap, now);
    tracing::info!(
        cap = %expected_cap.as_str(),
        redeemed = redeemed.is_some(),
        "capability receipt redemption"
    );
    let outcome = redeemed.map_or(
        Outcome::Failed(ErrCode::Denied, "receipt is not redeemable"),
        |cap| {
            let grant = state.capability_grants.insert(deadline);
            let Some(ttl) = state.capability_grants.remaining_secs(grant, now) else {
                return Outcome::Failed(ErrCode::Internal, "capability grant record missing");
            };
            Outcome::Fields(format!(
                "status=redeemed cap={} instance={} epoch={} ttl={ttl}",
                cap.as_str(),
                state.instance,
                state.lock_epoch
            ))
        },
    );
    drop(state);
    Decision::new(outcome)
}
