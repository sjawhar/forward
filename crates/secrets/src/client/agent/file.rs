//! One configured agent-tier file, with the source label it belongs to.

use std::path::PathBuf;

use crate::config::SourceRoot;

/// A sops dotenv file this client decrypts, and the source root it came from.
///
/// The label is what output and refusals name, so a reader can tell this store
/// from any other secrets CLI answering the same key names.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AgentFile {
    /// Source-root label, with a `.local` suffix for the machine-local file.
    pub label: String,
    /// Absolute path of the sops dotenv file.
    pub path: PathBuf,
}

impl AgentFile {
    /// Build a labelled agent-tier file.
    pub fn new(label: impl Into<String>, path: impl Into<PathBuf>) -> Self {
        Self {
            label: label.into(),
            path: path.into(),
        }
    }

    /// Render the file as `<label> (<path>)` for output and refusals.
    pub fn describe(&self) -> String {
        format!("{} ({})", self.label, self.path.display())
    }

    /// The agent-tier files of one root, in precedence order and labelled as
    /// `secrets list` labels a human-tier file of the same root.
    pub fn of_root(root: &SourceRoot) -> [Self; 2] {
        let [local, shared] = root.agent_files();
        [
            Self::new(format!("{}.local", root.name), local),
            Self::new(root.name.clone(), shared),
        ]
    }
}
