//! Content-addressed local evidence store (Master Plan §18 `EvidenceObjectStore`).
//!
//! Immutable evidence blobs are written under a local directory, named by their
//! SHA-256 content address. Writes are atomic (temp file + rename) and
//! idempotent; reads verify the returned bytes against the requested address. An
//! S3-compatible adapter is Stage 8 and reuses the same port.

use std::path::{Path, PathBuf};

use async_trait::async_trait;

use crate::digest::ContentDigest;
use crate::error::{StorageError, StorageResult};
use crate::model::EvidenceDescriptor;
use crate::ports::EvidenceObjectStore;

/// A filesystem-backed content-addressed evidence store.
pub struct LocalEvidenceStore {
    root: PathBuf,
}

impl LocalEvidenceStore {
    /// Opens (creating if needed) an evidence store rooted at `root`.
    ///
    /// # Errors
    ///
    /// Returns a backend error if the directories cannot be created.
    pub fn open(root: impl Into<PathBuf>) -> StorageResult<Self> {
        let root = root.into();
        std::fs::create_dir_all(root.join("blobs"))?;
        std::fs::create_dir_all(root.join("descriptors"))?;
        Ok(Self { root })
    }

    fn blob_path(&self, digest: &ContentDigest) -> PathBuf {
        self.root.join("blobs").join(digest.to_hex())
    }

    fn descriptor_path(&self, digest: &ContentDigest) -> PathBuf {
        self.root.join("descriptors").join(digest.to_hex())
    }

    /// The root directory, for backup/restore operations.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }
}

fn atomic_write(path: &Path, bytes: &[u8]) -> StorageResult<()> {
    // Unique temp name in the same directory so the rename is atomic on one fs.
    let parent = path
        .parent()
        .ok_or_else(|| StorageError::Backend("evidence path has no parent".to_string()))?;
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| StorageError::Backend("evidence path has no name".to_string()))?;
    let tmp = parent.join(format!(".{file_name}.tmp-{}", std::process::id()));
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[async_trait]
impl EvidenceObjectStore for LocalEvidenceStore {
    async fn put(&self, bytes: &[u8]) -> StorageResult<ContentDigest> {
        let digest = ContentDigest::of(bytes);
        let path = self.blob_path(&digest);
        if path.exists() {
            // Immutable and content-addressed: identical bytes already present.
            return Ok(digest);
        }
        atomic_write(&path, bytes)?;
        Ok(digest)
    }

    async fn get(&self, digest: &ContentDigest) -> StorageResult<Option<Vec<u8>>> {
        let path = self.blob_path(digest);
        match std::fs::read(&path) {
            Ok(bytes) => {
                let found = ContentDigest::of(&bytes);
                if &found != digest {
                    return Err(StorageError::EvidenceDigestMismatch {
                        expected: *digest,
                        found,
                    });
                }
                Ok(Some(bytes))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    async fn put_descriptor(&self, descriptor: EvidenceDescriptor) -> StorageResult<()> {
        let line = format!(
            "{}\t{}\t{}\n",
            descriptor.digest.to_hex(),
            descriptor.media_type,
            descriptor.size_bytes
        );
        atomic_write(&self.descriptor_path(&descriptor.digest), line.as_bytes())
    }
}
