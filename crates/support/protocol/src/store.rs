use crate::wire::{WireError, canonical_deserialize, canonical_serialize};
use serde::{Serialize, de::DeserializeOwned};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Wire(#[from] WireError),
}

/// Minimal append-only protocol-required store.  It models the persistence
/// boundary needed by the paper state machine, not crash recovery machinery.
#[derive(Debug)]
pub struct ProtocolStore {
    path: PathBuf,
    file: File,
    bytes: u64,
}

impl ProtocolStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        let bytes = file.metadata()?.len();
        Ok(Self { path, file, bytes })
    }

    pub fn persist<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<u64, StoreError> {
        let encoded = canonical_serialize(value)?;
        let len = u64::try_from(encoded.len()).unwrap_or(u64::MAX);
        self.file.write_all(&len.to_le_bytes())?;
        self.file.write_all(&encoded)?;
        self.file.sync_data()?;
        self.bytes = self.bytes.saturating_add(8).saturating_add(len);
        Ok(8 + len)
    }

    /// Replay every complete append-only record, rejecting truncation and
    /// non-canonical payloads instead of silently accepting a partial state.
    pub fn replay<T: DeserializeOwned + Serialize>(
        path: impl AsRef<Path>,
    ) -> Result<Vec<T>, StoreError> {
        let path = path.as_ref();
        if !path.exists() {
            return Ok(Vec::new());
        }
        let mut file = File::open(path)?;
        let file_len = file.metadata()?.len();
        let mut consumed = 0u64;
        let mut records = Vec::new();
        while consumed < file_len {
            let mut length = [0u8; 8];
            file.read_exact(&mut length)?;
            consumed = consumed.saturating_add(8);
            let length = u64::from_le_bytes(length);
            if length > file_len.saturating_sub(consumed) {
                return Err(StoreError::Io(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated protocol-store record",
                )));
            }
            let length_usize = usize::try_from(length).map_err(|_| {
                StoreError::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "protocol-store record does not fit memory",
                ))
            })?;
            let mut encoded = vec![0u8; length_usize];
            file.read_exact(&mut encoded)?;
            consumed = consumed.saturating_add(length);
            records.push(canonical_deserialize(&encoded)?);
        }
        Ok(records)
    }

    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}
