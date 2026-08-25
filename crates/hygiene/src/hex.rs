//! Hex encoding that never lets a secret through `core::fmt`.
//!
//! `format!("{:02x}")` builds each byte's digits in a local buffer inside
//! `core::fmt`'s machinery, which no `Zeroizing` wrapper on the result can
//! reach. This module writes digits straight into a buffer that scrubs on drop.

use zeroize::Zeroizing;

const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

/// Render `bytes` as lowercase hex in a buffer that wipes itself on drop.
#[allow(
    clippy::indexing_slicing,
    reason = "each masked nibble is in 0..16 before the static lookup"
)]
#[must_use]
pub fn encode(bytes: &[u8]) -> Zeroizing<String> {
    // saturating: the capacity is a hint, and a slice long enough to overflow
    // this cannot exist.
    let mut rendered = Zeroizing::new(String::with_capacity(bytes.len().saturating_mul(2)));
    for &byte in bytes {
        rendered.push(char::from(HEX_DIGITS[usize::from(byte >> 4)]));
        rendered.push(char::from(HEX_DIGITS[usize::from(byte & 0x0f)]));
    }
    rendered
}

/// Decode exactly `expected_len` bytes of lowercase-or-uppercase hex.
///
/// Returns `None` on any length mismatch or non-hex byte. The caller states the
/// length it wants rather than accepting whatever arrives, because every use
/// here decodes a fixed-width credential: a short read must be a refusal, not a
/// shorter token.
///
/// The result is a boxed slice, not a `Vec`: a `Vec` that is ever grown,
/// truncated, or reallocated leaves copies of its old contents outside the
/// region `Zeroizing` will wipe.
#[must_use]
pub fn decode_exact(raw: &str, expected_len: usize) -> Option<Zeroizing<Box<[u8]>>> {
    if raw.len() != expected_len.saturating_mul(2)
        || !raw.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return None;
    }
    let mut parsed = Zeroizing::new(vec![0_u8; expected_len].into_boxed_slice());
    for (slot, chunk) in parsed.iter_mut().zip(raw.as_bytes().chunks_exact(2)) {
        let text = std::str::from_utf8(chunk).ok()?;
        *slot = u8::from_str_radix(text, 16).ok()?;
    }
    Some(parsed)
}
