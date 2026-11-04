use std::io::{Read, Write};
use std::time::Instant;

use super::ProbeEvidence;
use crate::serve::{HEALTH_BODY, HEALTH_PATH};
use crate::target::url_host;

pub(super) fn probe(host: &str, port: u16) -> Result<ProbeEvidence, String> {
    let mut stream = super::connect(host, port)?;
    let request = format!(
        "GET {HEALTH_PATH} HTTP/1.0\r\nHost: {}\r\nConnection: close\r\n\r\n",
        url_host(host)
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|error| error.to_string())?;
    let deadline = Instant::now() + super::PROBE_TIMEOUT;
    let mut response = [0_u8; 4096];
    let mut used = 0;
    loop {
        let remaining_time = deadline
            .checked_duration_since(Instant::now())
            .filter(|duration| !duration.is_zero())
            .ok_or("preview health response deadline exceeded")?;
        stream
            .set_read_timeout(Some(remaining_time))
            .map_err(|error| error.to_string())?;
        let remaining = response
            .get_mut(used..)
            .filter(|bytes| !bytes.is_empty())
            .ok_or("preview health response exceeds 4096 bytes")?;
        let read = stream.read(remaining).map_err(|error| error.to_string())?;
        if read == 0 {
            break;
        }
        used += read;
    }
    classify(
        response
            .get(..used)
            .ok_or("invalid preview health response length")?,
    )
}

fn classify(response: &[u8]) -> Result<ProbeEvidence, String> {
    let separator = response
        .windows(4)
        .position(|bytes| bytes == b"\r\n\r\n")
        .ok_or("preview health response has no header separator")?;
    let headers = std::str::from_utf8(
        response
            .get(..separator)
            .ok_or("invalid preview health headers")?,
    )
    .map_err(|_| "preview health headers are not UTF-8")?;
    let mut lines = headers.split("\r\n");
    let status = lines
        .next()
        .ok_or("preview health response has no status")?;
    if status.bytes().any(|byte| byte.is_ascii_control()) {
        return Err("preview health status contains a control byte".to_owned());
    }
    let mut fields = status.splitn(3, ' ');
    match fields.next() {
        Some("HTTP/1.0" | "HTTP/1.1") => {}
        _ => return Err("preview health response has an invalid HTTP version".to_owned()),
    }
    let code = fields
        .next()
        .ok_or("preview health response has no status code")?;
    let reason = fields
        .next()
        .ok_or("preview health status has no reason separator")?;
    if reason.starts_with(' ') {
        return Err("preview health status has an invalid separator".to_owned());
    }
    match code {
        "403" => return Ok(ProbeEvidence::FileAccessRefused),
        "200" => {}
        _ => return Err(format!("{HEALTH_PATH} answered {status:?}")),
    }
    let mut length = None;
    for line in lines {
        let (name, value) = line
            .split_once(':')
            .ok_or("malformed preview health header")?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
        {
            return Err("invalid preview health header name".to_owned());
        }
        if value
            .bytes()
            .any(|byte| (byte < 32 && byte != b'\t') || byte == 127)
        {
            return Err("invalid control byte in preview health header".to_owned());
        }
        if name.eq_ignore_ascii_case("Transfer-Encoding") {
            return Err("preview health response must not use Transfer-Encoding".to_owned());
        }
        if name.eq_ignore_ascii_case("Content-Length") {
            let value = value.trim_matches([' ', '\t']);
            if length.is_some()
                || value.is_empty()
                || !value.bytes().all(|byte| byte.is_ascii_digit())
            {
                return Err("invalid or duplicate preview health Content-Length".to_owned());
            }
            length = Some(
                value
                    .parse::<usize>()
                    .map_err(|_| "invalid preview health Content-Length")?,
            );
        }
    }
    let body = response
        .get(separator + 4..)
        .ok_or("invalid preview health body")?;
    if length == Some(HEALTH_BODY.len()) && body == HEALTH_BODY.as_bytes() {
        Ok(ProbeEvidence::PreviewHealthy)
    } else {
        Err("preview health response has an unexpected length or body".to_owned())
    }
}
