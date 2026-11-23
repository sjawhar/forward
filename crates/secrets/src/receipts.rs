//! Single-use attestation receipts for capability authorizations.
//!
//! A receipt lets a process outside the session tree (forward serve) verify
//! with this daemon that a touch ceremony completed, without becoming able to
//! read anything. Receipts are not secrets-shaped: never persisted, never
//! logged, dead after one redeem or sixty seconds.

use std::io::Read as _;
use std::time::{Duration, Instant};

use hygiene::hex;
use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

use crate::capability::Capability;

/// Receipt entropy in bytes; hex-encoded on the wire (double this length).
pub const RECEIPT_LEN: usize = 32;
/// A receipt is redeemed by the very next hop; a minute is generous.
pub const RECEIPT_TTL: Duration = Duration::from_mins(1);
/// Receipts are minted one per successful touch ceremony; this bound exists
/// only so a pathological caller cannot grow the table. Minting fails rather
/// than invalidating a live receipt when the bound is reached.
const MAX_RECEIPTS: usize = 32;

struct Entry {
    // The Vec moves this pointer, not credential bytes, during reallocation,
    // removal, and retention.
    id: Zeroizing<Box<[u8]>>,
    cap: Capability,
    minted: Instant,
}

impl Entry {
    /// Whether this receipt is younger than `RECEIPT_TTL` at `now`.
    fn is_live(&self, now: Instant) -> bool {
        now.duration_since(self.minted) < RECEIPT_TTL
    }
}

/// Outstanding receipts. No values live here.
#[derive(Default)]
pub struct ReceiptTable {
    entries: Vec<Entry>,
}

impl std::fmt::Debug for ReceiptTable {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ReceiptTable")
            .field("outstanding", &self.entries.len())
            .finish()
    }
}

impl ReceiptTable {
    /// Mint a zeroizing receipt for a completed authorization.
    pub fn mint(&mut self, cap: &Capability, now: Instant) -> std::io::Result<Zeroizing<String>> {
        self.sweep(now);
        if self.entries.len() >= MAX_RECEIPTS {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "too many outstanding receipts",
            ));
        }
        let mut random = std::fs::File::open("/dev/urandom")?;
        loop {
            let mut id = Zeroizing::new(vec![0_u8; RECEIPT_LEN].into_boxed_slice());
            random.read_exact(id.as_mut())?;
            let candidate: &[u8] = id.as_ref();
            let duplicate = self
                .entries
                .iter()
                .fold(subtle::Choice::from(0), |found, entry| {
                    let stored: &[u8] = entry.id.as_ref();
                    found | stored.ct_eq(candidate)
                });
            if !bool::from(duplicate) {
                let receipt = hex::encode(id.as_ref());
                self.entries.push(Entry {
                    id,
                    cap: cap.clone(),
                    minted: now,
                });
                return Ok(receipt);
            }
        }
    }

    /// Consume a receipt for the expected capability at most once, within TTL.
    pub fn redeem(
        &mut self,
        receipt_hex: &str,
        expected_cap: &Capability,
        now: Instant,
    ) -> Option<Capability> {
        self.sweep(now);
        let presented = hex::decode_exact(receipt_hex, RECEIPT_LEN)?;
        let presented: &[u8] = presented.as_ref();
        let mut position = 0;
        let mut found = subtle::Choice::from(0);
        for (index, entry) in self.entries.iter().enumerate() {
            let stored: &[u8] = entry.id.as_ref();
            let matches = stored.ct_eq(presented);
            let mask = 0_usize.wrapping_sub(usize::from((matches & !found).unwrap_u8()));
            position = (position & !mask) | (index & mask);
            found |= matches;
        }
        if bool::from(found)
            && self
                .entries
                .get(position)
                .is_some_and(|entry| entry.cap == *expected_cap)
        {
            Some(self.entries.swap_remove(position).cap)
        } else {
            None
        }
    }

    /// Drop expired receipts.
    pub fn sweep(&mut self, now: Instant) {
        self.entries.retain(|entry| entry.is_live(now));
    }

    /// Each receipt not yet redeemed and younger than `RECEIPT_TTL`, in table
    /// order: its capability and its whole seconds left. Never the receipt.
    pub(crate) fn live(&self, now: Instant) -> impl Iterator<Item = (&Capability, u64)> {
        self.entries
            .iter()
            .filter(move |entry| entry.is_live(now))
            .map(move |entry| {
                let left = RECEIPT_TTL.saturating_sub(now.duration_since(entry.minted));
                (&entry.cap, left.as_secs())
            })
    }

    /// Forget every outstanding receipt. `LOCK` calls this in the same
    /// critical section that revokes grants: a receipt is standing authority
    /// exactly like a grant, and an attestation minted before a lock must not
    /// outlive it.
    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

#[cfg(test)]
mod tests;
