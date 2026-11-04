use std::io::{self, Read};

const MAX_REFUSAL_BYTES: usize = 32;

/// Read HTTP through EOF, but finish a recognized refusal at its newline.
pub(super) fn read_response(reader: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut body = Vec::with_capacity(MAX_REFUSAL_BYTES);
    for _ in 0..MAX_REFUSAL_BYTES {
        let mut byte = [0_u8];
        reader.read_exact(&mut byte)?;
        body.push(byte[0]);
        if !b"REFUSED".starts_with(&body) && !body.starts_with(b"REFUSED") {
            reader.read_to_end(&mut body)?;
            return Ok(body);
        }
        if byte[0] == b'\n' {
            // Closing a rejected socket with unread request bytes can reset it.
            // Only a complete known frame may finish before that close.
            return match body.as_slice() {
                b"REFUSED\n"
                | b"REFUSED PEER\n"
                | b"REFUSED DENIED\n"
                | b"REFUSED BUSY\n"
                | b"REFUSED UNARMED\n"
                | b"REFUSED FEED\n"
                | b"REFUSED TOKEN\n"
                | b"REFUSED TOKEN UPSTREAM 200\n"
                | b"REFUSED TOKEN UPSTREAM 503\n" => Ok(body),
                _ => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "malformed refusal frame",
                )),
            };
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "refusal frame exceeds 32 bytes",
    ))
}
