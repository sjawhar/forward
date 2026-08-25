use std::sync::Arc;
use std::thread;

use forward::browser::grant::Grants;
use forward::browser::push::FeedSlot;
use forward::browser::request::{Binder, Deps, Redeemer, SessionResolver, serve_with_binder};

use super::{accepting_identity_reader, grant_config};

#[path = "failures/races.rs"]
mod races;
#[path = "failures/timeouts.rs"]
mod timeouts;

fn spawn_with_binder(
    grants: Grants,
    path: std::path::PathBuf,
    slot: FeedSlot,
    redeemer: Redeemer,
    binder: Binder,
) {
    thread::spawn(move || {
        serve_with_binder(
            Deps {
                grants,
                slot,
                resolver: Arc::new(|_pid| Some("session-a".to_owned())) as SessionResolver,
                redeemer,
                identity_reader: accepting_identity_reader(),
                binder,
            },
            grant_config(),
            path,
        )
    });
}
