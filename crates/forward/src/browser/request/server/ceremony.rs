//! The `GRANT` path: redeem the receipt, mint and publish a relay token, and
//! record the grant, in that order.
//!
//! Nothing here binds a listener any more. The caller bound its own endpoint
//! before it asked, in the namespace where its clients live, and the
//! connection this ran on becomes that grant's control channel.

use std::io::Write as _;
use std::net::SocketAddr;
use std::os::unix::net::UnixStream;
use std::thread;
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use super::{Deps, control};
use crate::browser::grant::{Grant, ProcessAnchor};

pub(super) fn answer(
    deps: &Deps,
    upstream: Option<SocketAddr>,
    caller: (u32, Option<ProcessAnchor>),
    request: (u64, Vec<u8>, u16),
    mut stream: UnixStream,
) {
    let (pid, anchor) = caller;
    let (ttl, receipt, endpoint_port) = request;
    let receipt = Zeroizing::new(receipt);
    let Some(anchor) = anchor else {
        eprintln!("forward: grant refused: could not anchor requesting pid {pid}");
        let _ = stream.write_all(b"REFUSED ANCHOR\n");
        return;
    };
    let Some(upstream) = upstream else {
        eprintln!("forward: grant refused: no peer configured to relay to");
        let _ = stream.write_all(b"REFUSED UPSTREAM\n");
        return;
    };
    // Descriptive only: this anchor names the grant in log lines and answers
    // `STATUS`. Admission per CDP connection is enforced by the caller's own
    // relay, which can read the `/proc` entries a host cannot.
    let session = (deps.resolver)(pid).unwrap_or_else(|| format!("pid {pid}"));
    let redeemed = match (deps.redeemer)(receipt.as_slice()) {
        Ok(redeemed) => redeemed,
        Err(error) => {
            eprintln!("forward: grant refused: receipt not redeemed: {error}");
            let _ = stream.write_all(b"REFUSED RECEIPT\n");
            return;
        }
    };
    let ttl = ttl.min(redeemed.ttl_secs);
    let Ok(token) = crate::browser::push::mint_token() else {
        let _ = stream.write_all(b"REFUSED\n");
        return;
    };
    let mut token = Zeroizing::new(token);
    if !authority_is_current(deps, &redeemed.authority) {
        let _ = stream.write_all(b"REFUSED\n");
        return;
    }
    if !deps.slot.push(token.as_slice(), ttl) {
        eprintln!("forward: grant refused: laptop feed unavailable");
        let _ = stream.write_all(b"REFUSED LAPTOP\n");
        return;
    }
    // The feed acknowledgement can wait five seconds. Recheck again immediately
    // before insertion so a lock or broker restart during that wait cannot
    // cross this boundary. A refusal leaves the already-pushed laptop token
    // bounded by the five-minute lease and never renewed.
    if !authority_is_current(deps, &redeemed.authority) {
        let _ = stream.write_all(b"REFUSED\n");
        return;
    }

    let deadline = Instant::now() + Duration::from_secs(ttl);
    let Some(id) = deps.grants.insert_if_authority(
        &redeemed.authority,
        Grant {
            session: session.clone(),
            anchor,
            token: std::mem::take(&mut *token),
            deadline,
            endpoint_port,
        },
        &stream,
    ) else {
        let _ = stream.write_all(b"REFUSED\n");
        return;
    };
    deps.grants.reap_at(id, deadline);
    eprintln!(
        "forward: granted browser access to session {session} on 127.0.0.1:{endpoint_port} for {ttl}s"
    );
    if stream.write_all(b"OK\n").is_err() {
        deps.grants.expire(id);
        return;
    }
    let grants = deps.grants.clone();
    drop(thread::spawn(move || {
        control::serve(grants, id, upstream, stream);
    }));
}

fn authority_is_current(deps: &Deps, redeemed_authority: &crate::secretsd::BrokerIdentity) -> bool {
    match (deps.identity_reader)() {
        Ok(current) if current == *redeemed_authority => true,
        Ok(_) => {
            eprintln!("forward: grant refused: broker authority changed after redemption");
            false
        }
        Err(error) => {
            eprintln!("forward: grant refused: could not recheck broker authority: {error}");
            false
        }
    }
}
