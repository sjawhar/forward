//! The editor's plaintext scratch file: private, runtime-scoped, scrubbed on drop.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

use nix::unistd::Uid;
use tempfile::{Builder, TempPath};
use zeroize::Zeroize;

use super::super::{CliError, runtime_dir};
use crate::secret::SecretBytes;

const SCRUB_BLOCK: [u8; 8192] = [0; 8192];
const SCRUB_BLOCK_LEN: u64 = 8192;

/// A runtime-scoped plaintext edit file that is scrubbed before it is removed.
pub(super) struct PlaintextTemp {
    path: TempPath,
    original: File,
    edited: Option<File>,
}

impl PlaintextTemp {
    pub(super) fn create() -> Result<Self, CliError> {
        let file = Builder::new()
            .prefix(".secretsd-edit-")
            .tempfile_in(runtime_dir())
            .map_err(|_| CliError::EditTemp)?;
        file.as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|_| CliError::EditTemp)?;
        let (original, path) = file.into_parts();
        Ok(Self {
            path,
            original,
            edited: None,
        })
    }

    pub(super) fn path(&self) -> &Path {
        self.path.as_ref()
    }

    pub(super) fn write(&mut self, contents: &[u8]) -> Result<(), CliError> {
        self.original
            .write_all(contents)
            .and_then(|()| self.original.sync_data())
            .map_err(|_| CliError::EditTemp)
    }

    pub(super) fn reopen_after_editor(&mut self) -> Result<(), CliError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(&self.path)
            .map_err(|_| CliError::EditTemp)?;
        let metadata = file.metadata().map_err(|_| CliError::EditTemp)?;
        if !metadata.is_file() || metadata.uid() != Uid::effective().as_raw() {
            return Err(CliError::EditTemp);
        }
        if metadata.mode() & 0o777 != 0o600 {
            file.set_permissions(std::fs::Permissions::from_mode(0o600))
                .map_err(|_| CliError::EditTemp)?;
        }
        self.edited = Some(file);
        Ok(())
    }

    pub(super) fn read(&mut self) -> Result<SecretBytes, CliError> {
        let file = self.edited.as_mut().ok_or(CliError::EditTemp)?;
        file.seek(SeekFrom::Start(0))
            .map_err(|_| CliError::EditTemp)?;
        let mut bytes = Vec::new();
        if file.read_to_end(&mut bytes).is_err() {
            bytes.zeroize();
            return Err(CliError::EditTemp);
        }
        Ok(SecretBytes::from_vec(bytes))
    }

    pub(super) fn duplicate_at_start(&mut self) -> Result<File, CliError> {
        let file = self.edited.as_mut().ok_or(CliError::EditTemp)?;
        file.seek(SeekFrom::Start(0))
            .map_err(|_| CliError::EditTemp)?;
        file.try_clone().map_err(|_| CliError::EditTemp)
    }

    fn scrub(file: &mut File) {
        let Ok(length) = file.metadata().map(|metadata| metadata.len()) else {
            return;
        };
        if file.seek(SeekFrom::Start(0)).is_err() {
            return;
        }
        let mut remaining = length;
        while remaining > 0 {
            let amount = remaining.min(SCRUB_BLOCK_LEN);
            let Ok(chunk_len) = usize::try_from(amount) else {
                return;
            };
            let Some(chunk) = SCRUB_BLOCK.get(..chunk_len) else {
                return;
            };
            if file.write_all(chunk).is_err() {
                return;
            }
            let Some(next) = remaining.checked_sub(amount) else {
                return;
            };
            remaining = next;
        }
        let _ = file.sync_data();
    }
}

impl Drop for PlaintextTemp {
    fn drop(&mut self) {
        if let Some(edited) = self.edited.as_mut() {
            Self::scrub(edited);
        }
        Self::scrub(&mut self.original);
        let _ = std::fs::remove_file(self.path());
    }
}
