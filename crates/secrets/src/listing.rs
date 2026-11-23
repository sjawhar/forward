//! The answer to `GRANTS`: each live item that a restart of secretsd ends.
//!
//! Up to two tables. The first lists the secret grants, each row in the three
//! fields (key, scope, expiry) that every client's `get KEY --no-request`
//! reads. The second lists requests, receipts and capability grants, five
//! fields per row behind a `KIND` header, so no client reads one of them as a
//! secret grant. One empty line stands between the two tables, and the answer
//! is `no active grants` only when no item of any kind is live.

use std::fmt::Write as _;
use std::time::Instant;

use crate::capability_grants::CapabilityGrantTable;
use crate::grants::GrantTable;
use crate::proto::MAX_FRAME_BYTES;
use crate::receipts::ReceiptTable;
use crate::requests::{Queue, RequestState};

const NOTHING_LIVE: &str = "no active grants\n";
const SECRET_GRANT_HEADER: &str = "SECRET GRANT\tSCOPE\tEXPIRES\n";
const KIND_HEADER: &str = "KIND\tNAME\tSCOPE\tSTATE\tEXPIRES\n";
const MORE_PREFIX: &str = "more\t-\t-\t";
const MORE_SUFFIX: &str = " not shown\t-\n";

/// Render the `GRANTS` answer of these four tables at `now`.
///
/// Each expiry is the whole seconds left. The first table is written whole.
/// The second is held to `MAX_FRAME_BYTES`: when its rows do not all fit, the
/// first row that does not fit and every row after it are dropped and counted
/// in a last `more` row, and when not even its header and that row fit, it is
/// left out. So the answer is at most one frame whenever the first table is.
#[allow(
    clippy::redundant_pub_crate,
    reason = "the GRANTS handler in `server::dispatch` reaches this crate-private module"
)]
pub(crate) fn render(
    grants: &GrantTable,
    queue: &Queue,
    receipts: &ReceiptTable,
    capability_grants: &CapabilityGrantTable,
    now: Instant,
) -> String {
    let mut answer = String::new();
    for (key, scope, secs) in grants.live(now) {
        if answer.is_empty() {
            answer.push_str(SECRET_GRANT_HEADER);
        }
        let _ = writeln!(answer, "{}\t{}\t{secs}s", key.as_str(), scope.label());
    }

    let table_start = answer.len();
    if table_start > 0 {
        answer.push('\n');
    }
    answer.push_str(KIND_HEADER);
    let header_end = answer.len();
    let mut row_ends = Vec::new();
    for (id, key, scope, state, secs) in queue.live(now) {
        let state = if state == RequestState::Decrypting {
            "decrypting"
        } else {
            "pending"
        };
        let _ = writeln!(
            answer,
            "request\t{}\t{}\t{state}, id {}\t{secs}s",
            key.as_str(),
            scope.label(),
            id.0
        );
        row_ends.push(answer.len());
    }
    for (cap, secs) in receipts.live(now) {
        let _ = writeln!(answer, "receipt\t{}\t-\tunredeemed\t{secs}s", cap.as_str());
        row_ends.push(answer.len());
    }
    for (cap, secs) in capability_grants.live(now) {
        let _ = writeln!(answer, "capability\t{}\t-\tactive\t{secs}s", cap.as_str());
        row_ends.push(answer.len());
    }

    if row_ends.is_empty() {
        answer.truncate(table_start);
        if answer.is_empty() {
            answer.push_str(NOTHING_LIVE);
        }
    } else if answer.len() > MAX_FRAME_BYTES {
        hold_to_frame(&mut answer, table_start, header_end, &row_ends);
    }
    answer
}

/// Drop the second table's rows from the end until the rows kept and a `more`
/// row counting the rest fit in one frame, or drop the whole second table
/// (from `table_start`) when not even its header and that row fit. Called only
/// when the whole answer is past the frame, so the last row is always dropped.
fn hold_to_frame(answer: &mut String, table_start: usize, header_end: usize, row_ends: &[usize]) {
    let mut kept_end = header_end;
    let mut dropped = row_ends.len();
    for (&row_end, after) in row_ends.iter().zip((0..row_ends.len()).rev()) {
        if row_end.saturating_add(more_row_len(after)) > MAX_FRAME_BYTES {
            break;
        }
        kept_end = row_end;
        dropped = after;
    }
    if kept_end.saturating_add(more_row_len(dropped)) > MAX_FRAME_BYTES {
        answer.truncate(table_start);
    } else {
        answer.truncate(kept_end);
        let _ = write!(answer, "{MORE_PREFIX}{dropped}{MORE_SUFFIX}");
    }
}

/// The bytes of the `more` row that counts `dropped` rows, its digits included.
fn more_row_len(dropped: usize) -> usize {
    let digits = dropped
        .checked_ilog10()
        .map_or(1, |log| log.saturating_add(1));
    MORE_PREFIX
        .len()
        .saturating_add(digits as usize)
        .saturating_add(MORE_SUFFIX.len())
}

#[cfg(test)]
mod tests;
