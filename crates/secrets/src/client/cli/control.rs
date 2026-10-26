//! The broker control commands, which need no source-root state.
//!
//! Every refusal here names the socket it asked, so a reader never has to
//! guess which store on this machine answered.

use std::ffi::OsString;
use std::io::Write;
use std::path::PathBuf;

use super::super::error::CliError;
use super::super::{BrokerClient, BrokerResponse, ClientError};

/// Print the broker's active grants and pending requests.
pub(super) fn grants() -> Result<(), CliError> {
    let BrokerResponse::Bytes(bytes) = broker_call("GRANTS")? else {
        return Err(CliError::from_client(
            ClientError::InvalidResponse,
            socket_path(),
        ));
    };
    std::io::stdout()
        .lock()
        .write_all(&bytes)
        .map_err(CliError::Stdout)
}

/// Reject one pending request by id.
pub(super) fn deny(raw_id: &OsString) -> Result<(), CliError> {
    let id = raw_id
        .to_str()
        .ok_or(CliError::Usage)?
        .parse::<u64>()
        .map_err(|_| CliError::Usage)?;
    expect_ok(&format!("DENY\tid={id}"))
}

/// Wipe every grant and cached plaintext in the broker.
pub(super) fn lock() -> Result<(), CliError> {
    expect_ok("LOCK")
}

/// The broker socket this client contacts, for naming it in output.
pub(super) fn socket_path() -> PathBuf {
    BrokerClient::from_environment().socket_path().to_owned()
}

/// Send one request, mapping a failure onto the socket it was sent to.
pub(super) fn broker_call(request: &str) -> Result<BrokerResponse, CliError> {
    let broker = BrokerClient::from_environment();
    broker
        .call(request)
        .map_err(|error| CliError::from_client(error, broker.socket_path().to_owned()))
}

fn expect_ok(request: &str) -> Result<(), CliError> {
    match broker_call(request)? {
        BrokerResponse::Ok => Ok(()),
        BrokerResponse::Fields(_) | BrokerResponse::Bytes(_) => Err(CliError::from_client(
            ClientError::InvalidResponse,
            socket_path(),
        )),
    }
}
