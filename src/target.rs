use percent_encoding::{AsciiSet, CONTROLS, percent_encode};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use url::Url;

const PATH_SEGMENT: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'\\')
    .add(b'`')
    .add(b'{')
    .add(b'}');

#[derive(Debug, thiserror::Error)]
pub enum TargetError {
    #[error("forward: path not found: {0}")]
    NotFound(String),
    #[error("forward: cannot use target: {0}")]
    Invalid(String),
    #[error("forward: URL scheme is not openable: {0}")]
    UnsupportedScheme(String),
}

pub fn to_url(arg: &str, host: &str, files_port: u16) -> Result<Url, TargetError> {
    let mut path = PathBuf::from(arg);
    let mut fragment = None;
    if let Ok(url) = Url::parse(arg) {
        if url.cannot_be_a_base() {
            return Err(TargetError::UnsupportedScheme(url.scheme().to_owned()));
        }
        if url.scheme() != "file" {
            return Ok(url);
        }
        // The file is on this machine, so a file URL is only another way of
        // naming a path: it takes the same route to the same preview URL, and
        // the laptop still never sees a scheme it would drop.
        path = url
            .to_file_path()
            .map_err(|()| TargetError::Invalid(format!("{arg} is not a local file URL")))?;
        fragment = url.fragment().map(str::to_owned);
    }
    let abs = std::fs::canonicalize(&path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => TargetError::NotFound(path.display().to_string()),
        _ => TargetError::Invalid(format!("{}: {e}", path.display())),
    })?;
    let encoded = encode_path(&abs);
    let mut preview = Url::parse(&format!("http://{}:{files_port}/{encoded}", url_host(host)))
        .map_err(|e| TargetError::Invalid(e.to_string()))?;
    preview.set_fragment(fragment.as_deref());
    Ok(preview)
}

/// A configured `listen` address rendered as a URL authority.
///
/// `listen` holds a bare literal address, so an IPv6 one has to be bracketed
/// before a URL will parse. Anything else passes through untouched. Public
/// because `doctor` builds `Host` headers from the same addresses.
pub fn url_host(host: &str) -> String {
    if host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{host}]")
    } else {
        host.to_owned()
    }
}

fn encode_path(path: &Path) -> String {
    path.components()
        .filter_map(|c| match c {
            std::path::Component::RootDir => None,
            c => Some(percent_encode(c.as_os_str().as_bytes(), PATH_SEGMENT).to_string()),
        })
        .collect::<Vec<_>>()
        .join("/")
}

#[cfg(test)]
mod tests;
