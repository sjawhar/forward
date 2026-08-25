//! Primitives that both binaries must get right identically.
//!
//! Every item here existed twice, or existed in one binary and was missing from
//! the other that needed it just as much. The bug class this crate exists to
//! close is a definition drifting between the two: a constant-time compare that
//! is constant-time on one side only, a hex encoder that leaks digits through
//! `core::fmt`'s buffer in one binary and not the other, a process that
//! suppresses core dumps while its sibling holding the same bearer tokens does
//! not, or two deadlines compared across different clock domains.
//!
//! Nothing here is secret-bearing state. These are the mechanisms; the policy
//! that uses them stays in the binary that owns it.

pub mod clock;
pub mod hardening;
pub mod hex;

/// Compare two byte strings without an early exit.
///
/// Length is deliberately not secret: a token of the wrong size is already
/// wrong, and the length of a credential is not the credential. This delegates
/// to `subtle` rather than hand-rolling the fold, so the "does the optimiser
/// keep this constant-time" question has one audited answer for both binaries.
#[must_use]
pub fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    use subtle::ConstantTimeEq as _;

    left.ct_eq(right).into()
}

#[cfg(test)]
mod tests;
