use percent_encoding::{NON_ALPHANUMERIC, percent_encode};
use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;

pub(crate) const MARKDOWN_HEAD: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>"#;
pub(crate) const MARKDOWN_STYLE: &str = r#"</title>
    <link rel="stylesheet"
          href="https://cdn.jsdelivr.net/npm/github-markdown-css@5/github-markdown-dark.css">
    <link rel="stylesheet"
          href="https://cdn.jsdelivr.net/gh/highlightjs/cdn-release@11/build/styles/github-dark.min.css">
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
pub(crate) const MARKDOWN_TAIL: &str = r#"    </article>
</body>
</html>"#;

pub(crate) fn encode_path(path: &Path) -> String {
    path.as_os_str()
        .as_bytes()
        .split(|byte| *byte == b'/')
        .map(|segment| percent_encode(segment, NON_ALPHANUMERIC).to_string())
        .collect::<Vec<_>>()
        .join("/")
}

pub(crate) fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
