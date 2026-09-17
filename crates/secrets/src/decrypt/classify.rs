//! Reducing a sops stderr buffer to a stable label, and that label to an error
//! code.
//!
//! Split from `decrypt.rs` because these are pure functions over bytes: they
//! spawn nothing, hold no secret, and are the part of the decrypt path a test
//! can exercise directly.

use zeroize::Zeroize;

use crate::proto::ErrCode;

/// Known sops/age failure signatures, matched against lowercased stderr.
///
/// Ordered most specific first; the last entry is a generic wrapper sops emits
/// around any key failure, so it only matches once the others have missed.
const SOPS_STDERR_SIGNATURES: &[(&str, &str)] = &[
    (
        "failed to decrypt yubikey stanza",
        "yubikey-stanza-undecryptable",
    ),
    ("yubikey plugin", "yubikey-plugin-error"),
    // The plugin's own transport failure, which reaches us unwrapped when sops
    // surfaces the plugin's stderr verbatim. A stale pcscd tunnel produces this.
    ("pc/sc error", "pcsc-communication-error"),
    ("no identity matched", "no-matching-identity"),
    ("sops metadata not found", "missing-sops-metadata"),
    ("no such file or directory", "input-unreadable"),
    ("permission denied", "input-permission-denied"),
    ("failed to get the data key", "data-key-unavailable"),
];

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.len() >= needle.len() && haystack.windows(needle.len()).any(|w| w == needle)
}

/// Reduce a sops stderr buffer to a stable label.
///
/// The child's bytes never reach a log. A decrypt failure can quote the material
/// it just decrypted, so logging that output would put plaintext in the journal;
/// only this label and a byte count are recorded.
pub(super) fn classify_sops_stderr(stderr: &[u8]) -> &'static str {
    let mut lowered = stderr.to_ascii_lowercase();
    let label = SOPS_STDERR_SIGNATURES
        .iter()
        .find(|(needle, _)| contains_subslice(&lowered, needle.as_bytes()))
        .map_or("unclassified", |(_, label)| *label);
    lowered.zeroize();
    label
}

/// Labels that mean the hardware could not be reached, rather than a fault in
/// the request or the ciphertext.
///
/// The reachability probe only sees whether the PC/SC socket exists, so a live
/// socket whose far end is dead -- a stale pcscd tunnel is the common case --
/// gets all the way to sops before failing. Reporting `Internal` there tells the
/// caller to go read the daemon's log about spawning sops, when the actionable
/// fact is that the key is unreachable.
const UNREACHABLE_FAILURE_LABELS: &[&str] = &["yubikey-plugin-error", "pcsc-communication-error"];

/// Labels that mean the key was reachable but nobody touched it.
///
/// The plugin gives a touch a window of its own, shorter than this daemon's
/// request TTL, so a human who is slow to reach the key loses the race inside
/// sops rather than at our deadline. Both mean the same thing to the caller --
/// no approval happened -- so both must say so instead of blaming sops.
const UNTOUCHED_FAILURE_LABELS: &[&str] = &["yubikey-stanza-undecryptable"];

pub(super) fn failure_code(label: &str) -> ErrCode {
    if UNREACHABLE_FAILURE_LABELS.contains(&label) {
        ErrCode::YubikeyUnreachable
    } else if UNTOUCHED_FAILURE_LABELS.contains(&label) {
        ErrCode::Timeout
    } else {
        ErrCode::Internal
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_known_sops_signatures_and_falls_back_to_unclassified() {
        // The first case is the real message seen when a YubiKey touch never lands;
        // it contains both yubikey signatures, so ordering must pick the specific one.
        assert_eq!(
            classify_sops_stderr(
                b"age: yubikey plugin: Failed to decrypt YubiKey stanza. Did you touch it?"
            ),
            "yubikey-stanza-undecryptable"
        );
        assert_eq!(
            classify_sops_stderr(b"Failed to get the data key required to decrypt the SOPS file."),
            "data-key-unavailable"
        );
        assert_eq!(
            classify_sops_stderr(b"open /nope: no such file or directory"),
            "input-unreadable"
        );
        assert_eq!(
            classify_sops_stderr(b"sops metadata not found"),
            "missing-sops-metadata"
        );
        assert_eq!(classify_sops_stderr(b"a novel failure"), "unclassified");
        assert_eq!(classify_sops_stderr(b""), "unclassified");
    }

    #[test]
    fn unreachable_hardware_reports_itself_rather_than_an_internal_fault() {
        // Both wrappings of a stale pcscd tunnel, taken from real output: the socket
        // exists, so the reachability probe passes and sops is what discovers the key
        // is gone. sops usually prefixes the plugin's name, but surfaces the plugin's
        // own stderr verbatim when it does not.
        let wrapped = b"age: yubikey plugin: Error while communicating with YubiKey: \
    PC/SC error: An internal communications error has been detected";
        let raw = b"Error: Error while communicating with YubiKey: PC/SC error: \
    An internal communications error has been detected";
        assert_eq!(classify_sops_stderr(wrapped), "yubikey-plugin-error");
        assert_eq!(classify_sops_stderr(raw), "pcsc-communication-error");
        for stderr in [wrapped.as_slice(), raw.as_slice()] {
            assert_eq!(
                failure_code(classify_sops_stderr(stderr)),
                ErrCode::YubikeyUnreachable,
                "a caller told to inspect journalctl for a sops spawn failure cannot act; \
                 an unreachable key is actionable"
            );
        }

        // A touch that never landed is an approval that did not happen, not an
        // internal fault: sops gives the touch a shorter window than our request
        // TTL, so a slow human loses the race inside sops.
        assert_eq!(
            classify_sops_stderr(
                b"age: yubikey plugin: Failed to decrypt YubiKey stanza. Did you touch it?"
            ),
            "yubikey-stanza-undecryptable"
        );
        assert_eq!(
            failure_code("yubikey-stanza-undecryptable"),
            ErrCode::Timeout,
            "a missed touch must tell the caller to wait for the human, not to read \
             the daemon's log about spawning sops"
        );

        // Everything genuinely unexplained stays Internal.
        for label in [
            "data-key-unavailable",
            "input-unreadable",
            "input-permission-denied",
            "no-matching-identity",
            "missing-sops-metadata",
            "unclassified",
            "stderr-unreadable",
        ] {
            assert_eq!(failure_code(label), ErrCode::Internal, "{label}");
        }
    }
}
