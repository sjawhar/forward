use std::os::linux::fs::MetadataExt as _;
use std::os::unix::net::UnixStream;
use std::path::Path;

use proto::{BrokerClient, BrokerResponse, ClientError};
use zeroize::Zeroizing;

use super::{BrokerError, Verb};

pub(super) fn call(
    path: &Path,
    request: &str,
    verb: Verb<'_>,
) -> Result<Zeroizing<String>, BrokerError> {
    call_with_socket(path, request, verb).map(|(fields, _)| fields)
}

/// As [`call`], also reporting the identity of the socket that answered.
///
/// REDEEM needs it: the socket identity is part of the authority the reply
/// establishes, and it has to come from the connection that carried the reply
/// rather than from a later, separately-connected lookup.
pub(super) fn call_with_socket(
    path: &Path,
    request: &str,
    verb: Verb<'_>,
) -> Result<(Zeroizing<String>, super::SocketIdentity), BrokerError> {
    let client = BrokerClient::new(path);
    client
        .hello_on(connect_verified(path)?.0)
        .map(drop)
        .map_err(|error| map_error(error, path, Verb::Hello))?;
    let (stream, socket) = connect_verified(path)?;
    match client.request_on(stream, request) {
        Ok(BrokerResponse::Ok) => Ok((Zeroizing::new(String::new()), socket)),
        Ok(BrokerResponse::Fields(fields)) => Ok((Zeroizing::new(fields), socket)),
        Ok(BrokerResponse::Bytes(_)) => Err(BrokerError::Protocol(
            "broker returned a payload to a capability verb".to_owned(),
        )),
        Err(error) => Err(map_error(error, path, verb)),
    }
}

pub(super) fn broker_identity(path: &Path) -> Result<super::BrokerIdentity, BrokerError> {
    let client = BrokerClient::new(path);
    let (stream, socket) = connect_verified(path)?;
    let fields = client
        .hello_on(stream)
        .map_err(|error| map_error(error, path, Verb::Hello))?;
    let instance = fields.required("instance").map_err(|_| {
        BrokerError::Protocol("broker HELLO reply has no usable instance".to_owned())
    })?;
    if !super::reply::valid_field(instance) {
        return Err(BrokerError::Protocol(
            "broker HELLO reply has no usable instance".to_owned(),
        ));
    }
    let epoch = fields
        .required("epoch")
        .map_err(|_| BrokerError::Protocol("broker HELLO reply has no usable epoch".to_owned()))?
        .parse()
        .map_err(|_| BrokerError::Protocol("broker HELLO reply has no usable epoch".to_owned()))?;
    Ok(super::BrokerIdentity {
        instance: instance.to_owned(),
        epoch,
        socket,
    })
}

/// Connect and verify the peer, returning the stream and the socket's identity.
///
/// The uid check is the cheap half. The load-bearing half is the socket's
/// `(device, inode)`: callers fold it into [`super::BrokerIdentity`], so a
/// rebind of the path is caught as an authority change even when the impostor
/// replays the real instance string.
///
/// It deliberately does *not* read `/proc/<pid>/exe`. The broker sets
/// `PR_SET_DUMPABLE=0`, which makes that link unreadable to any process that
/// is not its ancestor — and in production forward and the broker are sibling
/// systemd units. An exe check therefore refuses the *legitimate* broker,
/// which is how it was caught: `forward serve` against a real hardened broker
/// logged `did not pass uid and executable verification` on every attempt.
///
/// Nor is it the peer pid: under socket activation `SO_PEERPIDFD` names
/// systemd, which holds the listening socket, so the pid does not change when
/// the broker does.
pub(super) fn connect_verified(
    path: &Path,
) -> Result<(UnixStream, super::SocketIdentity), BrokerError> {
    let stream = UnixStream::connect(path).map_err(|source| BrokerError::Connect {
        path: path.to_path_buf(),
        source,
    })?;
    let untrusted = || BrokerError::UntrustedPeer {
        path: path.to_path_buf(),
    };
    let credentials =
        nix::sys::socket::getsockopt(&stream, nix::sys::socket::sockopt::PeerCredentials)
            .map_err(|_| untrusted())?;
    if credentials.uid() != nix::unistd::geteuid().as_raw() {
        return Err(untrusted());
    }
    // Read the identity *after* connecting, so a path swapped between the two
    // is caught by the next connection's comparison rather than silently
    // accepted by this one.
    let metadata = std::fs::metadata(path).map_err(|_| untrusted())?;
    let socket = super::SocketIdentity {
        device: metadata.st_dev(),
        inode: metadata.st_ino(),
    };
    Ok((stream, socket))
}

fn map_error(error: ClientError, path: &Path, verb: Verb<'_>) -> BrokerError {
    match error {
        ClientError::Io(source) => BrokerError::Connect {
            path: path.to_path_buf(),
            source,
        },
        ClientError::ApprovalTimeout => match verb {
            Verb::Authorize { .. } => BrokerError::Timeout,
            Verb::Redeem => BrokerError::Protocol("redeem timed out".to_owned()),
            Verb::Hello => BrokerError::Protocol("HELLO timed out".to_owned()),
        },
        ClientError::VersionHandshake => {
            BrokerError::Protocol("broker did not confirm protocol version 3".to_owned())
        }
        ClientError::Broker(code) => map_code(code.wire(), verb),
        ClientError::InvalidRequest | ClientError::InvalidResponse => {
            BrokerError::Protocol("malformed broker exchange".to_owned())
        }
        ClientError::TokenFile => {
            BrokerError::Protocol("session token file is not valid UTF-8".to_owned())
        }
    }
}

pub(super) fn map_code(code: &str, verb: Verb<'_>) -> BrokerError {
    match (code, verb) {
        ("UNKNOWN_OP", _) => BrokerError::UnknownOp,
        ("DENIED", Verb::Authorize { .. }) => BrokerError::Denied,
        ("DENIED", Verb::Redeem) => BrokerError::ReceiptRejected,
        ("TIMEOUT", Verb::Authorize { .. }) => BrokerError::Timeout,
        ("YUBIKEY_UNREACHABLE", Verb::Authorize { .. }) => BrokerError::YubikeyUnreachable,
        ("TOO_MANY_PENDING", Verb::Authorize { .. }) => BrokerError::TooManyPending,
        ("NOT_HUMAN_KEY" | "AMBIGUOUS_KEY", Verb::Authorize { cap }) => {
            BrokerError::NotProvisioned(cap.to_owned(), cap.to_ascii_uppercase())
        }
        ("NO_SCOPE" | "UNKNOWN_TOKEN" | "FOREIGN_CALLER" | "AGENT_TTY", Verb::Authorize { .. }) => {
            BrokerError::NoScope
        }
        _ => BrokerError::Protocol("unrecognized broker error".to_owned()),
    }
}
