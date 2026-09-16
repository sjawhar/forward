//! Who is asking, and what they are allowed to see.
//!
//! Authorization inputs are the presented token (verified) and the caller's
//! tty. A claimed session identifier is never an authorization input.

use crate::store::FileIdentity;

mod registry;
mod scope;
mod table;
mod token;

pub use registry::{Registration, Registry};
pub use scope::{Scope, ScopeKind};
pub use table::GrantTable;
pub use token::SessionToken;

#[derive(Debug)]
pub(crate) struct GrantOrigin {
    pub(crate) source: String,
    pub(crate) identity: FileIdentity,
}

#[cfg(test)]
mod tests;
