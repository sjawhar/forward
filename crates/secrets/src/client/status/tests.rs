use std::time::{Duration, Instant};

use super::{CallerScope, lists_grant};
use crate::capability::Capability;
use crate::capability_grants::CapabilityGrantTable;
use crate::grants::{GrantOrigin, GrantTable, Scope, SessionToken};
use crate::listing::render;
use crate::receipts::ReceiptTable;
use crate::requests::{Queue, QueueLimits};
use crate::secret::{SecretBytes, SecretName};
use crate::store::{FileIdentity, FileTimestamp};

const TTY: &str = "/dev/pts/3";
/// The `GRANTS` answer of a daemon whose answer starts with `KEY\tSCOPE\tAGE`
/// (v3.8.4 and earlier).
const V3_8_4: &str = "KEY\tSCOPE\tAGE\nK\tsession\t5s\nT\ttty /dev/pts/3\t9s\n";

/// The four tables that `GRANTS` reads, empty; requests live 90 s.
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
                ttl: Duration::from_secs(90),
                max_pending_per_scope: 64,
            }),
            receipts: ReceiptTable::default(),
            capability_grants: CapabilityGrantTable::default(),
        }
    }

    /// A secret grant of `K` to `scope` beside a request of `K`, a receipt and
    /// a capability grant.
    fn every_kind(scope: Scope, now: Instant) -> Self {
        let mut tables = Self::new();
        let (changed, modified) = (FileTimestamp::new(4, 5), FileTimestamp::new(6, 7));
        let identity = FileIdentity::new(1, 2, 3, changed, modified);
        let origin = GrantOrigin {
            source: "test".to_owned(),
            identity,
        };
        let value = SecretBytes::from_vec(b"value".to_vec());
        let ttl = Duration::from_secs(100);
        tables
            .grants
            .insert(scope.clone(), name("K"), value, now, origin, ttl);
        tables.queue.enqueue(scope, name("K"), now, None).unwrap();
        tables.receipts.mint(&browser(), now).unwrap();
        let deadline = now.checked_add(ttl).unwrap();
        tables.capability_grants.insert(browser(), deadline);
        tables
    }

    fn render(&self, now: Instant) -> String {
        render(
            &self.grants,
            &self.queue,
            &self.receipts,
            &self.capability_grants,
            now,
        )
    }
}

fn name(raw: &str) -> SecretName {
    SecretName::parse(raw).unwrap()
}

fn browser() -> Capability {
    Capability::parse("browser").unwrap()
}

fn session() -> Scope {
    let token = "a".repeat(64);
    Scope::Session(SessionToken::parse_hex(&token).unwrap())
}

fn tty() -> Scope {
    Scope::Tty {
        tty: TTY.to_owned(),
        boot_id: "boot".to_owned(),
    }
}

fn caller_tty() -> CallerScope {
    CallerScope::Tty(TTY.to_owned())
}

#[test]
#[cfg_attr(miri, ignore)]
fn a_session_grant_is_found_beside_every_other_kind() {
    let now = Instant::now();
    let answer = Tables::every_kind(session(), now).render(now);
    assert!(answer.contains("\n\nKIND\t"), "both tables: {answer}");

    assert!(lists_grant(&answer, &name("K"), &CallerScope::Session));
    assert!(!lists_grant(&answer, &name("K"), &caller_tty()));
    assert!(!lists_grant(&answer, &name("K"), &CallerScope::None));
}

#[test]
#[cfg_attr(miri, ignore)]
fn a_tty_grant_is_found_beside_every_other_kind() {
    let now = Instant::now();
    let answer = Tables::every_kind(tty(), now).render(now);
    assert!(answer.contains("\n\nKIND\t"), "both tables: {answer}");

    assert!(lists_grant(&answer, &name("K"), &caller_tty()));
    assert!(!lists_grant(&answer, &name("K"), &CallerScope::Session));
    let other_tty = CallerScope::Tty("/dev/pts/4".to_owned());
    assert!(!lists_grant(&answer, &name("K"), &other_tty));
}

#[test]
fn a_key_scope_age_answer_is_still_read() {
    assert!(lists_grant(V3_8_4, &name("K"), &CallerScope::Session));
    assert!(lists_grant(V3_8_4, &name("T"), &caller_tty()));
    assert!(!lists_grant(V3_8_4, &name("K"), &caller_tty()));
    assert!(!lists_grant(V3_8_4, &name("T"), &CallerScope::Session));
}

#[test]
fn a_request_row_is_not_a_grant() {
    let now = Instant::now();
    let mut tables = Tables::new();
    tables
        .queue
        .enqueue(session(), name("K"), now, None)
        .unwrap();
    tables.queue.enqueue(tty(), name("K"), now, None).unwrap();
    let answer = tables.render(now);
    let expected = "KIND\tNAME\tSCOPE\tSTATE\tEXPIRES\n\
                    request\tK\tsession\tpending, id 1\t90s\n\
                    request\tK\ttty /dev/pts/3\tpending, id 2\t90s\n";
    assert_eq!(answer, expected);

    assert!(!lists_grant(&answer, &name("K"), &CallerScope::Session));
    assert!(!lists_grant(&answer, &name("K"), &caller_tty()));
}

#[test]
#[cfg_attr(miri, ignore)]
fn a_receipt_or_capability_row_is_not_a_grant() {
    let now = Instant::now();
    let mut tables = Tables::new();
    tables.receipts.mint(&browser(), now).unwrap();
    tables
        .capability_grants
        .insert(browser(), now + Duration::from_secs(100));
    let answer = tables.render(now);
    let expected = "KIND\tNAME\tSCOPE\tSTATE\tEXPIRES\n\
                    receipt\tbrowser\t-\tunredeemed\t60s\n\
                    capability\tbrowser\t-\tactive\t100s\n";
    assert_eq!(answer, expected);

    for scope in [CallerScope::Session, caller_tty(), CallerScope::None] {
        assert!(!lists_grant(&answer, &name("browser"), &scope));
    }
}

#[test]
fn a_header_line_alone_is_not_a_grant() {
    let headers = [
        "SECRET GRANT\tSCOPE\tEXPIRES\n",
        "KIND\tNAME\tSCOPE\tSTATE\tEXPIRES\n",
        "KEY\tSCOPE\tAGE\n",
        "no active grants\n",
    ];
    for answer in headers {
        for key in ["KEY", "KIND", "SCOPE", "K"] {
            for scope in [CallerScope::Session, caller_tty(), CallerScope::None] {
                assert!(!lists_grant(answer, &name(key), &scope), "{answer}");
            }
        }
    }
}
