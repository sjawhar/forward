use std::ffi::{OsStr, OsString};
use std::os::unix::net::UnixStream;
use std::path::Path;

use proto::{BrokerClient, BrokerResponse, ClientError};
use zeroize::Zeroizing;

use super::{BrokerError, Verb};

pub(super) fn call_as(
    path: &Path,
    request: &str,
    verb: Verb<'_>,
    expected_executable: &OsStr,
) -> Result<Zeroizing<String>, BrokerError> {
    let client = BrokerClient::new(path);
    client
        .hello_on(connect_as(path, expected_executable)?)
        .map(drop)
        .map_err(|error| map_error(error, path, Verb::Hello))?;
    match client.request_on(connect_as(path, expected_executable)?, request) {
        Ok(BrokerResponse::Ok) => Ok(Zeroizing::new(String::new())),
        Ok(BrokerResponse::Fields(fields)) => Ok(Zeroizing::new(fields)),
        Ok(BrokerResponse::Bytes(_)) => Err(BrokerError::Protocol(
            "broker returned a payload to a capability verb".to_owned(),
        )),
        Err(error) => Err(map_error(error, path, verb)),
    }
}
pub(super) fn broker_identity_as(
    path: &Path,
    expected_executable: &OsStr,
) -> Result<super::BrokerIdentity, BrokerError> {
    let client = BrokerClient::new(path);
    let fields = client
        .hello_on(connect_as(path, expected_executable)?)
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
    })
}

pub(super) fn connect_as(
    path: &Path,
    expected_executable: &OsStr,
) -> Result<UnixStream, BrokerError> {
    let stream = UnixStream::connect(path).map_err(|source| BrokerError::Connect {
        path: path.to_path_buf(),
        source,
    })?;
    let credentials =
        nix::sys::socket::getsockopt(&stream, nix::sys::socket::sockopt::PeerCredentials).map_err(
            |_| BrokerError::UntrustedPeer {
                path: path.to_path_buf(),
            },
        )?;
    let peer = containment::pinned::PinnedPeer::from_stream(&stream).map_err(|_| {
        BrokerError::UntrustedPeer {
            path: path.to_path_buf(),
        }
    })?;
    let executable_is_expected = peer
        .pid()
        .and_then(|pid| std::fs::read_link(format!("/proc/{pid}/exe")).ok())
        .and_then(|executable| executable.file_name().map(OsStr::to_os_string))
        .is_some_and(|executable| executable == expected_executable);
    if credentials.uid() != nix::unistd::geteuid().as_raw() || !executable_is_expected {
        return Err(BrokerError::UntrustedPeer {
            path: path.to_path_buf(),
        });
    }
    Ok(stream)
}

pub(super) fn test_peer_executable(path: &Path) -> Result<OsString, BrokerError> {
    std::env::current_exe()
        .ok()
        .and_then(|executable| executable.file_name().map(OsStr::to_os_string))
        .ok_or_else(|| BrokerError::UntrustedPeer {
            path: path.to_path_buf(),
        })
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
