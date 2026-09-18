use std::time::{Duration, Instant};

use super::*;
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
