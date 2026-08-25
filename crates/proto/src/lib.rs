//! Wire protocol v3, shared by both binaries.
//!
//! Line-oriented, tab-separated, ASCII, and hand-rolled deliberately: secret
//! plaintext is written straight from a zeroizing buffer to the socket and
//! never passes through a serializer whose internal buffers we cannot wipe.
//!
//! This crate holds the protocol vocabulary and the transport client. The
//! server-side `Request` grammar stays in the broker, which is the only thing
//! that parses one.

/// Protocol version. A mismatch is a hard error, never a downgrade.
pub const PROTOCOL_VERSION: u32 = 3;

/// Maximum accepted request frame and response payload. Requests never carry
/// secret values, but replies must be bounded before allocating their payload.
pub const MAX_FRAME_BYTES: usize = 4096;

/// The sole input-free request verb that holds a broker connection open.
pub const SUBSCRIBE_VERB: &str = "SUBSCRIBE";
/// A subscription was refused before it could prove broker authority.
pub const SUBSCRIBER_CAPACITY_RESPONSE: &str = "ERR SUBSCRIBER_CAPACITY\n";

/// Render one complete broker authority event.
#[must_use]
pub fn authority_event(instance: &str, epoch: u64) -> String {
    format!("EPOCH {epoch} instance={instance}\n")
}

/// Parse exactly one complete broker authority event.
#[must_use]
pub fn parse_authority_event(line: &str) -> Option<(&str, u64)> {
    let body = line.strip_prefix("EPOCH ")?;
    let (epoch, instance) = body.split_once(" instance=")?;
    let instance = instance.strip_suffix('\n')?;
    if epoch.is_empty()
        || !epoch.bytes().all(|byte| byte.is_ascii_digit())
        || instance.is_empty()
        || !instance.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return None;
    }
    Some((instance, epoch.parse().ok()?))
}

/// Machine-readable failure reasons. The wire form is stable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// Exhaustive on purpose: these are the protocol's error codes, and a new one
// is a protocol change every caller must handle deliberately.
#[allow(clippy::exhaustive_enums, reason = "the wire protocol is the contract")]
pub enum ErrCode {
    /// Frame was malformed, oversized, or missing a required field.
    BadRequest,
    /// Operation name is not part of this protocol version.
    UnknownOp,
    /// Client speaks a different protocol version.
    VersionMismatch,
    /// Token was not issued by a registered session.
    UnknownToken,
    /// Neither a token nor a usable tty accompanied the request.
    NoScope,
    /// Tokenless request arrived from a tty known to belong to an agent session.
    AgentTty,
    /// Token was presented by a process outside its session's process tree.
    ForeignCaller,
    /// Key is not present in the human-tier store.
    NotHumanKey,
    /// Key resolves to more than one human-tier file, so access is refused.
    AmbiguousKey,
    /// A human denied the request.
    Denied,
    /// The request expired before approval.
    Timeout,
    /// The `YubiKey` is not reachable from this machine right now.
    YubikeyUnreachable,
    /// This scope already has too many requests awaiting approval.
    TooManyPending,
    /// Decryption failed for a reason that is not the client's fault.
    Internal,
}

impl ErrCode {
    /// Stable wire token for this code.
    pub const fn wire(self) -> &'static str {
        match self {
            Self::BadRequest => "BAD_REQUEST",
            Self::UnknownOp => "UNKNOWN_OP",
            Self::VersionMismatch => "VERSION_MISMATCH",
            Self::UnknownToken => "UNKNOWN_TOKEN",
            Self::NoScope => "NO_SCOPE",
            Self::AgentTty => "AGENT_TTY",
            Self::ForeignCaller => "FOREIGN_CALLER",
            Self::NotHumanKey => "NOT_HUMAN_KEY",
            Self::AmbiguousKey => "AMBIGUOUS_KEY",
            Self::Denied => "DENIED",
            Self::Timeout => "TIMEOUT",
            Self::YubikeyUnreachable => "YUBIKEY_UNREACHABLE",
            Self::TooManyPending => "TOO_MANY_PENDING",
            Self::Internal => "INTERNAL",
        }
    }

    /// Parse a stable wire token into its protocol error code.
    pub fn parse_wire(token: &str) -> Option<Self> {
        match token {
            "BAD_REQUEST" => Some(Self::BadRequest),
            "UNKNOWN_OP" => Some(Self::UnknownOp),
            "VERSION_MISMATCH" => Some(Self::VersionMismatch),
            "UNKNOWN_TOKEN" => Some(Self::UnknownToken),
            "NO_SCOPE" => Some(Self::NoScope),
            "AGENT_TTY" => Some(Self::AgentTty),
            "FOREIGN_CALLER" => Some(Self::ForeignCaller),
            "NOT_HUMAN_KEY" => Some(Self::NotHumanKey),
            "AMBIGUOUS_KEY" => Some(Self::AmbiguousKey),
            "DENIED" => Some(Self::Denied),
            "TIMEOUT" => Some(Self::Timeout),
            "YUBIKEY_UNREACHABLE" => Some(Self::YubikeyUnreachable),
            "TOO_MANY_PENDING" => Some(Self::TooManyPending),
            "INTERNAL" => Some(Self::Internal),
            _ => None,
        }
    }
}

/// Transport client.
///
/// Socket resolution, framing, and the version handshake.
pub mod client;
/// Typed broker responses.
///
/// Includes the errors a client can see.
pub mod response;

pub use client::{BrokerClient, SocketPath, caller_tty, read_token_file};
pub use response::{BrokerResponse, ClientError, parse_response};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authority_events_round_trip_through_the_shared_grammar() {
        let line = authority_event("6e57b1e32c564c4ca0c53d9fc5983a14", 42);

        assert_eq!(line, "EPOCH 42 instance=6e57b1e32c564c4ca0c53d9fc5983a14\n");
        assert_eq!(
            parse_authority_event(&line),
            Some(("6e57b1e32c564c4ca0c53d9fc5983a14", 42))
        );
        assert_eq!(SUBSCRIBE_VERB, "SUBSCRIBE");
        assert_eq!(SUBSCRIBER_CAPACITY_RESPONSE, "ERR SUBSCRIBER_CAPACITY\n");
    }
}
