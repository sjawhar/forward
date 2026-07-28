use comrak::Options;
use percent_encoding::{NON_ALPHANUMERIC, percent_decode, percent_encode};
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io;
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::path::{Path, PathBuf};
use tiny_http::{Header, Method, Request, Response, Server, StatusCode};
use url::Url;

const HTML_CONTENT_TYPE: &str = "text/html; charset=utf-8";
const TEXT_CONTENT_TYPE: &str = "text/plain; charset=utf-8";
const MARKDOWN_HEAD: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>"#;
const MARKDOWN_STYLE: &str = r#"</title>
    <link rel="stylesheet"
          href="https://cdn.jsdelivr.net/npm/github-markdown-css@5/github-markdown-dark.css">
    <link rel="stylesheet"
          href="https://cdn.jsdelivr.net/gh/highlightjs/cdn-release@11/build/styles/github-dark.min.css">
    <script src="https://cdn.jsdelivr.net/gh/highlightjs/cdn-release@11/build/highlight.min.js"></script>
    <style>
        body {
            background: #0d1117;
            padding: 2rem;
            display: flex;
            justify-content: center;
        }
        .markdown-body {
            max-width: 980px;
            width: 100%;
            padding: 2rem;
        }
    </style>
</head>
<body>
    <article class="markdown-body">
"#;
const MARKDOWN_TAIL: &str = r#"    </article>
    <script>document.addEventListener('DOMContentLoaded',()=>hljs.highlightAll());</script>
</body>
</html>"#;

type HttpResponse = Response<std::io::Cursor<Vec<u8>>>;

#[derive(Debug, thiserror::Error)]
pub enum ServeError {
    #[error("forward: could not bind loopback server on port {port}: {source}")]
    Bind {
        port: u16,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    #[error("forward: loopback listener closed")]
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

pub fn run(port: u16) -> Result<(), ServeError> {
    let server =
        Server::http(("127.0.0.1", port)).map_err(|source| ServeError::Bind { port, source })?;
    for request in server.incoming_requests() {
        let response = respond(&request).into_response();
        if let Err(error) = request.respond(response) {
            eprintln!("forward: client disconnected before response completed: {error}");
        }
    }
    Err(ServeError::ListenerClosed)
}

fn respond(request: &Request) -> Reply {
    if request.method() != &Method::Get && request.method() != &Method::Head {
        let reply = Reply::new(405, TEXT_CONTENT_TYPE, "Method Not Allowed\n");
        return match Header::from_bytes(b"Allow", b"GET, HEAD") {
            Ok(header) => reply.with_header(header),
            Err(()) => reply,
        };
    }

    if !host_is_loopback(request) {
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
        Ok(metadata) if metadata.is_file() => file_reply(&path, raw),
        Ok(_) => Reply::new(404, TEXT_CONTENT_TYPE, "Not Found\n"),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            Reply::new(404, TEXT_CONTENT_TYPE, "Not Found\n")
        }
        Err(_) => Reply::new(500, TEXT_CONTENT_TYPE, "Internal Server Error\n"),
    }
}

fn host_is_loopback(request: &Request) -> bool {
    request
        .headers()
        .iter()
        .find(|header| header.field.equiv("Host"))
        .is_none_or(|header| {
            let host = header.value.as_str();
            matches!(host, "127.0.0.1" | "localhost" | "[::1]")
                || ["127.0.0.1:", "localhost:", "[::1]:"].iter().any(|prefix| {
                    host.strip_prefix(prefix)
                        .is_some_and(|port| port.parse::<u16>().is_ok())
                })
        })
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

fn file_reply(path: &Path, raw: bool) -> Reply {
    let body = match fs::read(path) {
        Ok(body) => body,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Reply::new(404, TEXT_CONTENT_TYPE, "Not Found\n");
        }
        Err(_) => return Reply::new(500, TEXT_CONTENT_TYPE, "Internal Server Error\n"),
    };

    if path
        .extension()
        .and_then(OsStr::to_str)
        .is_some_and(|extension| extension.eq_ignore_ascii_case("md"))
    {
        return if raw {
            Reply::new(200, TEXT_CONTENT_TYPE, body)
        } else {
            markdown_reply(path, &body)
        };
    }

    let content_type = mime_guess::from_path(path).first().map_or_else(
        || TEXT_CONTENT_TYPE.to_owned(),
        |mime| {
            let content_type = mime.essence_str();
            if content_type.starts_with("text/") {
                format!("{content_type}; charset=utf-8")
            } else {
                content_type.to_owned()
            }
        },
    );
    Reply::new(200, content_type, body)
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

fn encode_path(path: &Path) -> String {
    path.as_os_str()
        .as_bytes()
        .split(|byte| *byte == b'/')
        .map(|segment| percent_encode(segment, NON_ALPHANUMERIC).to_string())
        .collect::<Vec<_>>()
        .join("/")
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
