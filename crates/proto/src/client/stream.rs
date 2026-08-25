use std::io::Write;
use std::os::unix::net::UnixStream;

use super::{APPROVAL_VERBS, BrokerClient, HelloFields};
use crate::response::{BrokerResponse, ClientError};
use crate::{MAX_FRAME_BYTES, PROTOCOL_VERSION};

impl BrokerClient {
    /// Complete a version handshake on a caller-supplied connection.
    ///
    /// This consumes the stream because the broker serves one request per
    /// connection. A caller that needs to pin and inspect the Unix peer does so
    /// before passing the stream here.
    pub fn hello_on(&self, stream: UnixStream) -> Result<HelloFields, ClientError> {
        let version = PROTOCOL_VERSION.to_string();
        let request = format!("HELLO\tversion={version}");
        let BrokerResponse::Fields(fields) = self.request_on(stream, &request)? else {
            return Err(ClientError::VersionHandshake);
        };
        // Fields this client does not consume are tolerated -- the daemon also
        // reports its instance id, which only a registering harness needs -- but
        // a missing or differing version must fail rather than degrade.
        if fields
            .split(' ')
            .any(|field| field.strip_prefix("version=") == Some(version.as_str()))
        {
            Ok(HelloFields(fields))
        } else {
            Err(ClientError::VersionHandshake)
        }
    }

    /// Send one request on a caller-supplied connection, without a handshake.
    ///
    /// [`BrokerClient::call`] is the usual entry point. This preserves the
    /// protocol's framing and per-verb deadline after a caller has identified
    /// the connected peer.
    pub fn request_on(
        &self,
        mut stream: UnixStream,
        request: &str,
    ) -> Result<BrokerResponse, ClientError> {
        let waits_for_approval = APPROVAL_VERBS.iter().any(|verb| request.starts_with(verb));
        let timeout = if waits_for_approval {
            self.get_timeout
        } else {
            self.control_timeout
        };
        stream
            .set_read_timeout(Some(timeout))
            .map_err(ClientError::Io)?;
        stream
            .set_write_timeout(Some(timeout))
            .map_err(ClientError::Io)?;
        write_request(&mut stream, request)?;
        // The deadline covers the whole reply, not each read of it.
        let deadline = std::time::Instant::now().checked_add(timeout);
        match crate::response::read_response_by(stream, deadline) {
            Err(ClientError::Io(error))
                if waits_for_approval
                    && matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
            {
                Err(ClientError::ApprovalTimeout)
            }
            other => other,
        }
    }
}

fn write_request(stream: &mut UnixStream, request: &str) -> Result<(), ClientError> {
    let request_is_valid = !request.is_empty()
        && request.len() <= MAX_FRAME_BYTES
        && request.is_ascii()
        && !request.contains(['\n', '\r', '\0']);
    if !request_is_valid {
        return Err(ClientError::InvalidRequest);
    }
    stream
        .write_all(request.as_bytes())
        .map_err(ClientError::Io)?;
    stream.write_all(b"\n").map_err(ClientError::Io)
}
