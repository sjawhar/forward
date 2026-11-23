use std::time::{Duration, Instant};

use super::render;
use crate::capability::Capability;
use crate::capability_grants::CapabilityGrantTable;
use crate::grants::{GrantOrigin, GrantTable, Scope, SessionToken};
use crate::receipts::{RECEIPT_TTL, ReceiptTable};
use crate::requests::{Queue, QueueLimits, RequestId, RequestState};
use crate::secret::{SecretBytes, SecretName};
use crate::store::{FileIdentity, FileTimestamp};

#[path = "tests/frame.rs"]
mod frame;

const KIND: &str = "KIND\tNAME\tSCOPE\tSTATE\tEXPIRES\n";
const SECRET_GRANT: &str = "SECRET GRANT\tSCOPE\tEXPIRES\n";
const NONE: &str = "no active grants\n";
const VALUE: &str = "super-secret";
const TOKEN_HEX: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

/// The four tables that `GRANTS` reads; requests live 90 s.
struct Tables {
    grants: GrantTable,
    queue: Queue,
    receipts: ReceiptTable,
    capability_grants: CapabilityGrantTable,
}

impl Tables {
    fn new() -> Self {
        Self {
            grants: GrantTable::default(),
            queue: Queue::new(QueueLimits {
                cooldown: Duration::ZERO,
                ttl: secs(90),
                max_pending_per_scope: 64,
            }),
            receipts: ReceiptTable::default(),
            capability_grants: CapabilityGrantTable::default(),
        }
    }

    fn render(&self, now: Instant) -> String {
        let Self {
            grants,
            queue,
            receipts,
            capability_grants,
        } = self;
        render(grants, queue, receipts, capability_grants, now)
    }

    fn grant(&mut self, scope: Scope, key: &str, created: Instant, ttl: Duration) {
        let (changed, modified) = (FileTimestamp::new(4, 5), FileTimestamp::new(6, 7));
        let identity = FileIdentity::new(1, 2, 3, changed, modified);
        let source = "test".to_owned();
        let value = SecretBytes::from_vec(VALUE.as_bytes().to_vec());
        let origin = GrantOrigin { source, identity };
        self.grants
            .insert(scope, name(key), value, created, origin, ttl);
    }

    fn request(&mut self, scope: Scope, key: &str, created: Instant) -> RequestId {
        self.queue.enqueue(scope, name(key), created, None).unwrap()
    }

    fn capability(&mut self, deadline: Instant) {
        self.capability_grants.insert(browser(), deadline);
    }
}

const fn secs(secs: u64) -> Duration {
    Duration::from_secs(secs)
}

fn name(raw: &str) -> SecretName {
    SecretName::parse(raw).unwrap()
}

fn session() -> Scope {
    Scope::Session(SessionToken::parse_hex(TOKEN_HEX).unwrap())
}

fn browser() -> Capability {
    Capability::parse("browser").unwrap()
}

#[test]
fn a_grant_alone_lists_its_seconds_left_under_the_secret_grant_header() {
    let (mut tables, t) = (Tables::new(), Instant::now());
    tables.grant(session(), "K", t, secs(100));

    let expected = format!("{SECRET_GRANT}K\tsession\t70s\n");
    assert_eq!(tables.render(t + secs(30)), expected);
}

#[test]
#[cfg_attr(miri, ignore)]
fn a_receipt_alone_lists_its_capability_never_the_receipt() {
    let (mut tables, t) = (Tables::new(), Instant::now());
    let receipt = tables.receipts.mint(&browser(), t).unwrap();

    let answer = tables.render(t + secs(10));
    assert_eq!(
        answer,
        format!("{KIND}receipt\tbrowser\t-\tunredeemed\t50s\n")
    );
    assert!(!answer.contains(receipt.as_str()));
    assert_eq!(tables.render(t + RECEIPT_TTL), NONE, "a receipt at its TTL");
}

#[test]
fn a_capability_grant_alone_lists_its_seconds_to_the_deadline() {
    let (mut tables, t) = (Tables::new(), Instant::now());
    tables.capability(t + secs(100));

    let expected = format!("{KIND}capability\tbrowser\t-\tactive\t70s\n");
    assert_eq!(tables.render(t + secs(30)), expected);
}

#[test]
fn a_request_alone_lists_its_state_id_and_seconds_to_the_deadline() {
    let (mut tables, t) = (Tables::new(), Instant::now());
    let id = tables.request(session(), "K", t);
    let expected = format!("{KIND}request\tK\tsession\tpending, id 1\t60s\n");
    assert_eq!(tables.render(t + secs(30)), expected);

    assert!(tables.queue.mark_decrypting(id, t).is_some());
    let expected = format!("{KIND}request\tK\tsession\tdecrypting, id 1\t60s\n");
    assert_eq!(tables.render(t + secs(30)), expected);
}

#[test]
fn tty_and_omp_scopes_are_written_as_tty_path_and_omp_pid() {
    let (mut tables, t) = (Tables::new(), Instant::now());
    let tty = "/dev/pts/3".to_owned();
    let boot_id = "boot".to_owned();
    tables.grant(Scope::Tty { tty, boot_id }, "T", t, secs(100));
    let omp = Scope::Omp {
        pid: 4242,
        start: 7,
    };
    tables.request(omp, "CAP_BROWSER", t);

    let expected = format!(
        "{SECRET_GRANT}T\ttty /dev/pts/3\t100s\n\n\
         {KIND}request\tCAP_BROWSER\tomp 4242\tpending, id 1\t90s\n"
    );
    assert_eq!(tables.render(t), expected);
}

#[test]
fn requests_are_listed_in_id_order_after_a_retry_moves_one_to_the_end() {
    let (mut tables, t) = (Tables::new(), Instant::now());
    let first = tables.request(session(), "A", t);
    tables.request(session(), "B", t);
    assert!(tables.queue.mark_decrypting(first, t).is_some());
    assert!(tables.queue.retry(first, t));
    let later = t + secs(30);
    assert_eq!(tables.queue.next_ready(later), Some(RequestId(2)));

    let expected = format!(
        "{KIND}request\tA\tsession\tpending, id 1\t60s\n\
         request\tB\tsession\tpending, id 2\t60s\n"
    );
    assert_eq!(tables.render(later), expected);
}

#[test]
fn an_item_at_its_limit_is_not_listed() {
    let (mut tables, t) = (Tables::new(), Instant::now());
    tables.grant(session(), "K", t, secs(100));
    tables.capability(t + secs(100));
    assert_eq!(tables.render(t + secs(100)), NONE);

    let mut tables = Tables::new();
    let id = tables.request(session(), "K", t);
    let expected = format!("{KIND}request\tK\tsession\tpending, id 1\t0s\n");
    assert_eq!(tables.render(t + secs(90)), expected, "at its deadline");
    assert_eq!(tables.render(t + secs(91)), NONE);
    assert_eq!(tables.queue.state_of(id), Some(RequestState::Pending));
}

#[test]
fn a_request_in_a_final_state_is_not_listed() {
    let (mut tables, t) = (Tables::new(), Instant::now());
    let granted = tables.request(session(), "G", t);
    let generation = tables.queue.mark_decrypting(granted, t).unwrap();
    assert!(tables.queue.complete(granted, generation, t));
    let denied = tables.request(session(), "D", t);
    assert!(tables.queue.deny(denied));
    let timed_out = tables.request(session(), "O", t);
    assert!(tables.queue.timeout(timed_out, t));
    let failed = tables.request(session(), "F", t);
    assert!(tables.queue.mark_decrypting(failed, t).is_some());
    tables.queue.fail(failed, t);

    for (id, state) in [
        (granted, RequestState::Granted),
        (denied, RequestState::Denied),
        (timed_out, RequestState::TimedOut),
        (failed, RequestState::Failed),
    ] {
        assert_eq!(tables.queue.state_of(id), Some(state));
    }
    assert_eq!(tables.render(t), NONE);
}

#[test]
fn nothing_live_is_exactly_no_active_grants() {
    assert_eq!(Tables::new().render(Instant::now()), NONE);
}

#[test]
#[cfg_attr(miri, ignore)]
fn all_four_kinds_give_both_tables_with_one_empty_line_between() {
    let (mut tables, t) = (Tables::new(), Instant::now());
    tables.grant(session(), "K", t, secs(100));
    tables.request(session(), "K", t);
    let receipt = tables.receipts.mint(&browser(), t + secs(20)).unwrap();
    tables.capability(t + secs(100));

    let answer = tables.render(t + secs(30));
    let expected = format!(
        "{SECRET_GRANT}K\tsession\t70s\n\n\
         {KIND}request\tK\tsession\tpending, id 1\t60s\n\
         receipt\tbrowser\t-\tunredeemed\t50s\n\
         capability\tbrowser\t-\tactive\t70s\n"
    );
    assert_eq!(answer, expected);
    for private in [VALUE, receipt.as_str(), TOKEN_HEX] {
        assert!(!answer.contains(private), "a value, receipt or token");
    }
}
