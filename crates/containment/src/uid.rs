//! Is the peer of a unix socket this same user?
//!
//! `SO_PEERCRED` reports the peer's uid in the *reader's* user namespace. When
//! the peer's uid has no mapping there, the kernel reports the overflow uid
//! instead of failing. That is the normal case across an agentbox boundary:
//! Sysbox maps the box's uid 1000 onto a host subordinate uid, so the daemon
//! sees a box client as the overflow uid, and a box client sees the host daemon
//! (host uid 1000, unmappable inside the box) the same way.
//!
//! Both halves rest the same-user question on a filesystem fact the kernel has
//! already enforced, not on this number: the daemon serves only an owner-only
//! socket node, and the node lives in the user's own `0700` runtime directory.
//! A peer that got through that is this uid in *some* namespace; the uid gate
//! only refuses a mapped uid that is visibly someone else.

/// The uid the kernel reports for a peer it cannot map into this namespace.
///
/// 65534 is the kernel default for `kernel.overflowuid`; a host that changes it
/// fails closed, refusing such peers as foreign.
pub const OVERFLOW_UID: u32 = 65534;

/// Whether a peer's kernel-reported uid is this user.
///
/// Seen from `own_uid`'s namespace. Grants nothing on its own: the daemon still
/// binds a session by token and pidfd ancestry, and the client still binds the
/// broker by the socket's `(device, inode)`.
pub const fn same_user(peer_uid: u32, own_uid: u32) -> bool {
    peer_uid == own_uid || peer_uid == OVERFLOW_UID
}

#[cfg(test)]
mod tests {
    use super::{OVERFLOW_UID, same_user};

    #[test]
    fn refuses_a_mapped_uid_that_is_someone_else() {
        // A mapped uid is a real identity in this namespace; a different one is
        // another user, whatever the socket mode says.
        assert!(!same_user(1000, 1001));
        assert!(!same_user(0, 1000));
        assert!(!same_user(231_072 + 1000, 1000));
    }

    #[test]
    fn accepts_this_uid_and_the_overflow_uid() {
        // The overflow uid is what an agentbox boundary looks like from either
        // side: box client to host daemon, and host daemon to box client.
        assert!(same_user(1000, 1000));
        assert!(same_user(OVERFLOW_UID, 1000));
    }
}
