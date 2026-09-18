use subtle::ConstantTimeEq;

use crate::proto::ErrCode;

/// Length of a session token in bytes.
const TOKEN_LEN: usize = 32;

/// An unguessable per-session bearer token issued by trusted harness code.
#[derive(Clone, Copy)]
pub struct SessionToken([u8; TOKEN_LEN]);

impl SessionToken {
    /// Parse a 64-character lowercase or uppercase hex string.
    pub fn parse_hex(text: &str) -> Result<Self, ErrCode> {
        if text.len() != TOKEN_LEN * 2 {
            return Err(ErrCode::BadRequest);
        }
        let mut bytes = [0_u8; TOKEN_LEN];
        for (index, slot) in bytes.iter_mut().enumerate() {
            let start = index.checked_mul(2).ok_or(ErrCode::BadRequest)?;
            let end = start.checked_add(2).ok_or(ErrCode::BadRequest)?;
            let pair = text.get(start..end).ok_or(ErrCode::BadRequest)?;
            *slot = u8::from_str_radix(pair, 16).map_err(|_| ErrCode::BadRequest)?;
        }
        Ok(Self(bytes))
    }
}

impl PartialEq for SessionToken {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl Eq for SessionToken {}

impl std::fmt::Debug for SessionToken {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SessionToken(<redacted>)")
    }
}
