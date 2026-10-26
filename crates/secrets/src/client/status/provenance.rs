//! Where a key's value comes from, named the same way in every surface.
//!
//! A machine can run more than one secrets CLI, each with its own store, and
//! both answer the same key names. Neither the status object nor the injection
//! notice may leave the store to the reader's assumption.

use std::fmt::Write as _;
use std::path::PathBuf;

use crate::secret::SecretName;

pub(in crate::client) enum Provenance {
    /// Decrypted here from a sops dotenv file.
    Agent {
        /// Source-root label of the file.
        source: String,
        /// The file sops decrypted.
        path: PathBuf,
    },
    /// Brokered by the local secretsd daemon.
    Human {
        /// Source-root label of the `secrets.human.d` file this client's
        /// configuration resolves the key to; the daemon decrypts it.
        source: String,
        /// The daemon socket this client asked.
        socket: PathBuf,
        /// Whether this caller's scope holds a live grant.
        grant_active: bool,
        /// The grant's remaining lifetime when the broker reported one.
        ttl_secs: Option<u64>,
    },
}

impl Provenance {
    /// One-line prose naming the store, for the injection notice.
    pub(in crate::client) fn describe(&self) -> String {
        match self {
            Self::Agent { source, path } => {
                format!("agent tier, source {source} ({})", path.display())
            }
            Self::Human { source, socket, .. } => format!(
                "human tier, source {source}, granted by the secretsd daemon ({})",
                socket.display()
            ),
        }
    }

    /// The one-line JSON status object for this key.
    pub(in crate::client) fn status_json(&self, name: &SecretName) -> String {
        let mut line = String::new();
        // A key name is validated as [A-Za-z_][A-Za-z0-9_]*, so it needs no escaping.
        line.push_str(r#"{"key":""#);
        line.push_str(name.as_str());
        match self {
            Self::Agent { source, path } => {
                line.push_str(r#"","tier":"agent","store":"sops file","source":"#);
                push_json_string(&mut line, source);
                line.push_str(r#","path":"#);
                push_json_string(&mut line, &path.to_string_lossy());
            }
            Self::Human {
                source,
                socket,
                grant_active,
                ttl_secs,
            } => {
                line.push_str(r#"","tier":"human","store":"secretsd daemon","source":"#);
                push_json_string(&mut line, source);
                line.push_str(r#","socket":"#);
                push_json_string(&mut line, &socket.to_string_lossy());
                let ttl_json = ttl_secs.map_or_else(|| "null".to_owned(), |ttl| ttl.to_string());
                let _ = write!(line, r#","grant":{grant_active},"ttl":{ttl_json}"#);
            }
        }
        line.push('}');
        line
    }
}

/// Append a JSON string literal, escaping what RFC 8259 requires.
///
/// Source labels are bare words, but a configured path is whatever the operator
/// wrote, so the status object stays parseable for any of them.
fn push_json_string(out: &mut String, text: &str) {
    out.push('"');
    for character in text.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str(r"\\"),
            '\n' => out.push_str(r"\n"),
            '\r' => out.push_str(r"\r"),
            '\t' => out.push_str(r"\t"),
            control if control.is_control() => {
                let _ = write!(out, "\\u{:04x}", u32::from(control));
            }
            printable => out.push(printable),
        }
    }
    out.push('"');
}
