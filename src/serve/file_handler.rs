use std::path::Path;
use std::{fs, io};

use super::{Reply, TEXT_CONTENT_TYPE, markdown_reply};

const MAX_FILE_SIZE: u64 = 64 * 1024 * 1024;

pub(super) fn file_reply(path: &Path, raw: bool, size: u64) -> Reply {
    if size > MAX_FILE_SIZE {
        eprintln!(
            "forward: refusing oversized file {} ({size} bytes)",
            path.display()
        );
        return Reply::new(413, TEXT_CONTENT_TYPE, "Payload Too Large\n");
    }
    let body = match fs::read(path) {
        Ok(body) => body,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Reply::new(404, TEXT_CONTENT_TYPE, "Not Found\n");
        }
        Err(_) => return Reply::new(500, TEXT_CONTENT_TYPE, "Internal Server Error\n"),
    };
    if path
        .extension()
        .and_then(|extension| extension.to_str())
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
