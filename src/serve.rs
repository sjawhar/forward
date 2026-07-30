mod file_handler;
mod security;

use crate::config::Config;
use crate::render::{MARKDOWN_HEAD, MARKDOWN_STYLE, MARKDOWN_TAIL, encode_path, escape_html};
use comrak::Options;
use file_handler::file_reply;
use percent_encoding::percent_decode;
use security::{host_allowed, peer_allowed};
use std::ffi::OsString;
use std::fs;
use std::io;
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::path::{Path, PathBuf};
use tiny_http::{Header, Method, Request, Response, Server, StatusCode};
use url::Url;

const HTML_CONTENT_TYPE: &str = "text/html; charset=utf-8";
const TEXT_CONTENT_TYPE: &str = "text/plain; charset=utf-8";
const RESPONSE_SECURITY_HEADERS: [(&[u8], &[u8]); 4] = [
    (
        b"Content-Security-Policy",
        b"sandbox; default-src 'none'; img-src 'self' data:; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; font-src https://cdn.jsdelivr.net",
    ),
    (b"X-Content-Type-Options", b"nosniff"),
    (b"Cross-Origin-Resource-Policy", b"same-origin"),
    // Preview URLs carry absolute filesystem paths; rendered markdown can link
    // to external sites, and a click would otherwise leak that path as the
    // Referer.
    (b"Referrer-Policy", b"no-referrer"),
];

type HttpResponse = Response<std::io::Cursor<Vec<u8>>>;

#[derive(Debug, thiserror::Error)]
pub enum ServeError {
    #[error(transparent)]
    Config(#[from] crate::config::ConfigError),
    #[error("forward: could not bind file server on {address}: {source}")]
    Bind {
        address: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    #[error("forward: file server listener closed")]
    ListenerClosed,
}

struct Reply {
    status: u16,
    content_type: String,
    body: Vec<u8>,
    headers: Vec<Header>,
}

impl Reply {
    fn new(status: u16, content_type: impl Into<String>, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            content_type: content_type.into(),
            body: body.into(),
            headers: Vec::new(),
        }
    }

    fn with_header(mut self, header: Header) -> Self {
        self.headers.push(header);
        self
    }

    fn into_response(self) -> HttpResponse {
        let Self {
            status,
            content_type,
            body,
            headers,
        } = self;
        let response = Response::from_data(body).with_status_code(StatusCode(status));
        let response =
            RESPONSE_SECURITY_HEADERS
                .iter()
                .fold(
                    response,
                    |response, (name, value)| match Header::from_bytes(*name, *value) {
                        Ok(header) => response.with_header(header),
                        Err(()) => response,
                    },
                );
        match Header::from_bytes(b"Content-Type", content_type.as_bytes()) {
            Ok(header) => headers
                .into_iter()
                .fold(response.with_header(header), |response, header| {
                    response.with_header(header)
                }),
            Err(()) => headers
                .into_iter()
                .fold(response, |response, header| response.with_header(header)),
        }
    }
}

pub fn run(cfg: &Config, port: u16) -> Result<(), ServeError> {
    cfg.validate()?;
    let ip = cfg.listen_ip().map_err(|source| ServeError::Bind {
        address: cfg.listen.clone(),
        source: Box::new(source),
    })?;
    let server = Server::http((ip, port)).map_err(|source| ServeError::Bind {
        address: format!("{ip}:{port}"),
        source,
    })?;
    eprintln!("forward: file server listening on {}", server.server_addr());
    for request in server.incoming_requests() {
        let response = respond(cfg, &request).into_response();
        if let Err(error) = request.respond(response) {
            eprintln!("forward: client disconnected before response completed: {error}");
        }
    }
    Err(ServeError::ListenerClosed)
}

fn respond(cfg: &Config, request: &Request) -> Reply {
    if !peer_allowed(cfg, request) {
        eprintln!(
            "forward: file server refused peer {:?}",
            request.remote_addr()
        );
        return Reply::new(403, TEXT_CONTENT_TYPE, "Forbidden\n");
    }

    if request.method() != &Method::Get && request.method() != &Method::Head {
        let reply = Reply::new(405, TEXT_CONTENT_TYPE, "Method Not Allowed\n");
        return match Header::from_bytes(b"Allow", b"GET, HEAD") {
            Ok(header) => reply.with_header(header),
            Err(()) => reply,
        };
    }

    if !host_allowed(cfg, request) {
        return Reply::new(403, TEXT_CONTENT_TYPE, "Forbidden\n");
    }

    let (path, raw) = match request_path(request) {
        Ok(path) => path,
        Err(()) => return Reply::new(400, TEXT_CONTENT_TYPE, "Bad Request\n"),
    };

    match fs::metadata(&path) {
        Ok(metadata) if metadata.is_dir() => match directory_reply(&path) {
            Ok(reply) => reply,
            Err(_) => Reply::new(500, TEXT_CONTENT_TYPE, "Internal Server Error\n"),
        },
        Ok(metadata) if metadata.is_file() => file_reply(&path, raw, metadata.len()),
        Ok(_) => Reply::new(404, TEXT_CONTENT_TYPE, "Not Found\n"),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            Reply::new(404, TEXT_CONTENT_TYPE, "Not Found\n")
        }
        Err(_) => Reply::new(500, TEXT_CONTENT_TYPE, "Internal Server Error\n"),
    }
}

fn request_path(request: &Request) -> Result<(PathBuf, bool), ()> {
    let parsed =
        Url::parse(&format!("http://forward.invalid/{}", request.url())).map_err(|_| ())?;
    let encoded_path = parsed.path().strip_prefix('/').ok_or(())?;
    let path = PathBuf::from(OsString::from_vec(
        percent_decode(encoded_path.as_bytes()).collect(),
    ));
    if !path.is_absolute() {
        return Err(());
    }
    let raw = parsed
        .query_pairs()
        .any(|(key, value)| key == "raw" && value == "1");
    Ok((path, raw))
}

fn markdown_reply(path: &Path, source: &[u8]) -> Reply {
    let mut options = Options::default();
    options.extension.table = true;
    options.extension.strikethrough = true;
    options.extension.autolink = true;
    options.extension.tasklist = true;

    let title = path
        .file_name()
        .unwrap_or(path.as_os_str())
        .to_string_lossy();
    let body = comrak::markdown_to_html(&String::from_utf8_lossy(source), &options);
    let document = format!(
        "{MARKDOWN_HEAD}{}{MARKDOWN_STYLE}{body}\n{MARKDOWN_TAIL}",
        escape_html(&title)
    );
    Reply::new(200, HTML_CONTENT_TYPE, document)
}

fn directory_reply(path: &Path) -> Result<Reply, io::Error> {
    let mut entries = Vec::new();
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        entries.push((entry.file_type()?.is_dir(), entry.file_name(), entry.path()));
    }
    entries.sort_by(|left, right| {
        right
            .0
            .cmp(&left.0)
            .then_with(|| left.1.as_bytes().cmp(right.1.as_bytes()))
    });

    let mut document = String::from(
        "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>Index</title></head><body><ul>",
    );
    for (is_dir, name, entry_path) in entries {
        let suffix = if is_dir { "/" } else { "" };
        let href = encode_path(&entry_path);
        let label = escape_html(&name.to_string_lossy());
        document.push_str(&format!("<li><a href=\"{href}\">{label}{suffix}</a></li>"));
    }
    document.push_str("</ul></body></html>");
    Ok(Reply::new(200, HTML_CONTENT_TYPE, document))
}
