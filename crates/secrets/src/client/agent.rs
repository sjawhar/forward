//! Direct, daemon-independent access to agent-tier dotenv files.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};

use zeroize::Zeroize;

use super::CliError;
use crate::secret::{SecretBytes, SecretName};

mod file;
#[cfg(test)]
mod tests;

pub use file::AgentFile;

/// Decrypts the unattended agent tier without connecting to `secretsd`.
#[derive(Debug, Clone)]
pub struct AgentStore {
    files: Vec<AgentFile>,
    sops_bin: OsString,
}

/// One decrypted agent-tier value and the configured file that supplied it.
///
/// The borrow preserves the association without cloning a path or plaintext.
#[derive(Debug)]
pub struct ResolvedAgent<'a> {
    /// Decrypted secret bytes, zeroized when dropped.
    pub value: SecretBytes,
    /// The winning configured file for `value`.
    pub file: &'a AgentFile,
}

impl AgentStore {
    /// Decrypts an ordered list of sops dotenv files; earlier files win on duplicate names.
    pub fn new(files: Vec<AgentFile>, sops_bin: impl Into<OsString>) -> Self {
        Self {
            files,
            sops_bin: sops_bin.into(),
        }
    }

    /// Return a named agent-tier value and the file that supplied it.
    ///
    /// Value and provenance resolve in one decryption pass: a concurrent edit
    /// cannot make output name one file while a later pass reads another.
    pub fn resolve(&self, name: &SecretName) -> Result<ResolvedAgent<'_>, CliError> {
        self.resolve_all()?
            .remove(name)
            .ok_or_else(|| CliError::MissingSecret {
                name: name.clone(),
                searched: self.searched(),
            })
    }

    /// Return a named agent-tier value, with earlier files taking precedence.
    pub fn value(&self, name: &SecretName) -> Result<SecretBytes, CliError> {
        self.resolve(name).map(|resolved| resolved.value)
    }

    /// Return the file a key resolves to, without decrypting any value.
    ///
    /// This cheap filename lookup is for cross-tier ambiguity checks; callers
    /// that hand a value over use [`AgentStore::resolve`] instead.
    pub fn locate(&self, name: &SecretName) -> Result<Option<&AgentFile>, CliError> {
        for file in &self.files {
            if file.path.is_file() && Self::names_in(&file.path)?.contains(name) {
                return Ok(Some(file));
            }
        }
        Ok(None)
    }

    /// Check encrypted dotenv key names without decrypting their values.
    pub fn contains(&self, name: &SecretName) -> Result<bool, CliError> {
        self.locate(name).map(|file| file.is_some())
    }

    /// Resolve every agent-tier value with the file that supplied it.
    ///
    /// Earlier configured files win. The returned references keep each value
    /// bound to that same winning file without copying either provenance or
    /// plaintext.
    pub fn resolve_all(&self) -> Result<BTreeMap<SecretName, ResolvedAgent<'_>>, CliError> {
        let mut values = BTreeMap::new();
        for file in &self.files {
            if !file.path.is_file() {
                continue;
            }
            for (name, value) in self.decrypt_all(&file.path)? {
                values.entry(name).or_insert(ResolvedAgent { value, file });
            }
        }
        Ok(values)
    }

    /// Describe every file this store reads, for a not-found message.
    pub fn searched(&self) -> String {
        if self.files.is_empty() {
            return "no configured agent-tier files".to_owned();
        }
        let files: Vec<String> = self.files.iter().map(AgentFile::describe).collect();
        format!("agent-tier files {}", files.join(", "))
    }

    fn decrypt_all(&self, path: &Path) -> Result<BTreeMap<SecretName, SecretBytes>, CliError> {
        let mut output = Command::new(&self.sops_bin)
            .args(["-d", "--input-type", "dotenv", "--output-type", "dotenv"])
            .arg(path)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output()
            .map_err(|error| CliError::SopsStart {
                path: path.to_path_buf(),
                error,
            })?;
        if !output.status.success() {
            output.stdout.zeroize();
            return Err(CliError::SopsFailed(Some(path.to_path_buf())));
        }
        let parsed = parse_dotenv(&output.stdout).map_err(|error| error.in_file(path));
        output.stdout.zeroize();
        parsed
    }

    /// Read non-metadata agent-tier key names without decrypting their values.
    pub(crate) fn names_in(path: &Path) -> Result<Vec<SecretName>, CliError> {
        let encrypted = fs::read(path).map_err(|error| CliError::AgentKeySet {
            path: path.to_path_buf(),
            error,
        })?;
        Self::names_of(&encrypted).map_err(|error| error.in_file(path))
    }

    /// Non-metadata key names in dotenv bytes, ciphertext or plaintext (sops
    /// keeps dotenv names in the clear). Values are not looked at; a caller
    /// holding plaintext keeps it in its own zeroizing buffer.
    pub(crate) fn names_of(dotenv: &[u8]) -> Result<Vec<SecretName>, CliError> {
        let mut names = Vec::new();
        for line in assignment_lines(dotenv) {
            let (name, _) = parse_assignment_line(line)?;
            if !name.as_str().starts_with("sops_") {
                names.push(name);
            }
        }
        Ok(names)
    }
}

/// The non-empty, non-comment lines of a dotenv body, CR stripped.
fn assignment_lines(dotenv: &[u8]) -> impl Iterator<Item = &[u8]> {
    dotenv
        .split(|byte| *byte == b'\n')
        .map(|line| line.strip_suffix(b"\r").unwrap_or(line))
        .filter(|line| !line.is_empty() && line.first() != Some(&b'#'))
}

/// One `NAME=VALUE` line as a parsed name and its raw value bytes.
fn parse_assignment_line(line: &[u8]) -> Result<(SecretName, &[u8]), CliError> {
    let separator = line
        .iter()
        .position(|byte| *byte == b'=')
        .ok_or(CliError::InvalidDotenv(None))?;
    let (raw_name, raw_value) = line.split_at(separator);
    let name = std::str::from_utf8(raw_name).map_err(|_| CliError::InvalidDotenv(None))?;
    let name = SecretName::parse(name).map_err(|_| CliError::InvalidSecretName)?;
    let value = raw_value.get(1..).ok_or(CliError::InvalidDotenv(None))?;
    Ok((name, value))
}

fn parse_dotenv(plaintext: &[u8]) -> Result<BTreeMap<SecretName, SecretBytes>, CliError> {
    let mut values = BTreeMap::new();
    for line in assignment_lines(plaintext) {
        let (name, value) = parse_assignment_line(line)?;
        if value.contains(&b'\0') {
            return Err(CliError::InvalidDotenv(None));
        }
        values
            .entry(name)
            .or_insert_with(|| SecretBytes::from_vec(value.to_vec()));
    }
    Ok(values)
}
