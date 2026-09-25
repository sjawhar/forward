use std::sync::Arc;
use std::thread;

use forward::browser::grant::Grants;
use forward::browser::push::FeedSlot;
use forward::browser::request::{Deps, Redeemer, SessionResolver, serve_with_deps};

use super::{accepting_identity_reader, grant_config};

#[path = "failures/races.rs"]
mod races;
#[path = "failures/timeouts.rs"]
mod timeouts;

fn spawn_failing_server(
    grants: Grants,
    path: std::path::PathBuf,
    slot: FeedSlot,
    redeemer: Redeemer,
) {
    thread::spawn(move || {
        serve_with_deps(
            Deps {
                grants,
                slot,
                resolver: Arc::new(|_pid| Some("session-a".to_owned())) as SessionResolver,
                redeemer,
                identity_reader: accepting_identity_reader(),
            },
            grant_config(),
            path,
        )
    });
}
