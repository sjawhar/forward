//! Server-side request parsing for wire protocol v4.
//!
//! The protocol vocabulary -- version, frame bound, error codes -- and the
//! client transport live in `crates/proto`, shared with forward. What stays
//! here is the half only a server needs: the `Request` grammar and its parser.

pub use proto::{
    ErrCode, MAX_FRAME_BYTES, PROTOCOL_VERSION, SUBSCRIBE_VERB, SUBSCRIBER_CAPACITY_RESPONSE,
    parse_ttl,
};

mod request;
mod response;

pub use request::{Request, parse_request};
pub use response::{Response, format_response};

#[cfg(test)]
mod tests;
