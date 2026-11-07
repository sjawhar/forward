use std::time::{Duration, Instant};

use super::*;
use crate::peer::ChildPeer;
use crate::proto::ErrCode;
use crate::secret::{SecretBytes, SecretName};
use crate::store::{FileIdentity, FileTimestamp};

fn token(byte: u8) -> SessionToken {
    SessionToken::parse_hex(&format!("{byte:02x}").repeat(32)).unwrap()
}

fn name(raw: &str) -> SecretName {
    SecretName::parse(raw).unwrap()
}

fn secret(raw: &str) -> SecretBytes {
    SecretBytes::from_vec(raw.as_bytes().to_vec())
}

fn identity() -> FileIdentity {
    FileIdentity::new(1, 2, 3, FileTimestamp::new(4, 5), FileTimestamp::new(6, 7))
}

fn origin(source: &str) -> GrantOrigin {
    GrantOrigin {
        source: source.to_owned(),
        identity: identity(),
    }
}

fn registered() -> Registry {
    let mut registry = Registry::default();
    registry
        .register(Registration {
            token: token(0xaa),
            session: "ses_a".to_owned(),
            root: crate::peer::current_for_test(),
        })
        .unwrap();
    registry
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

#[path = "tests/claim.rs"]
mod claim;
#[path = "tests/holder_lifecycle.rs"]
mod holder_lifecycle;
#[path = "tests/lookup.rs"]
mod lookup;
#[path = "tests/registration.rs"]
mod registration;
#[path = "tests/registry.rs"]
mod registry_tests;
#[path = "tests/table.rs"]
mod table;
#[path = "tests/token.rs"]
mod token_tests;
