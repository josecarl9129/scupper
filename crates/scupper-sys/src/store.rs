//! Immutable validated configuration history with a durable compare-and-swap head.
//!
//! `head` alone publishes a version. Files above it are interrupted commits and
//! never enter reads or history. A retry archives those files before reusing the
//! next number. The internal store lock serializes CAS across handles/processes;
//! mutations require proof of the global writer lock across apply transactions.
//! Lock order is global, then store. Acquiring the same lock path twice can
//! deadlock even in one process; the two locks must use distinct directories.

use crate::{
    apply::{DurableStep, Fs, RealFs, durable_directory, durable_replace},
    lock::{WriterGuard, WriterLock},
};
use scupper_core::config::{parse_site, validate};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::{self, OpenOptions},
    io::{self, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

/// A monotonically increasing committed configuration version (starting at 1).
pub type Version = u64;

/// Attribution supplied by the actor committing a configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetaInput {
    /// Local authenticated actor identity.
    pub actor: String,
    /// Unix seconds of the change.
    pub at: u64,
    /// Operator-supplied reason.
    pub reason: String,
}

/// Immutable metadata stored beside a version's TOML.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Meta {
    /// Previous committed version, absent only for version 1.
    #[serde(deserialize_with = "required_parent")]
    pub parent: Option<Version>,
    /// Lowercase hexadecimal SHA-256 of the exact stored TOML bytes.
    pub sha256: String,
    /// Authenticated actor identity.
    pub actor: String,
    /// Unix seconds of the change.
    pub at: u64,
    /// Operator-supplied reason.
    pub reason: String,
}
fn required_parent<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<Version>, D::Error> {
    Option::deserialize(d)
}

/// Store failures; invalid TOML diagnostics never include its contents.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// The supplied parent no longer matches the current head.
    #[error("configuration conflict; head is {head:?}")]
    Conflict {
        /// Current authoritative head.
        head: Option<Version>,
    },
    /// TOML failed parsing or semantic validation.
    #[error("invalid site configuration")]
    InvalidConfig,
    /// Persisted data was malformed or its digest did not match.
    #[error("corrupt configuration store: {0}")]
    Corrupt(&'static str),
    /// An uncommitted or absent version was requested.
    #[error("configuration version {0} is not committed")]
    NotCommitted(Version),
    /// Filesystem or fault-injection failure. Head may already be published if
    /// the failure occurred after its rename; reread it before retrying.
    #[error("configuration store I/O: {0}")]
    Io(#[from] io::Error),
}

/// Mirror observation; it is never used as configuration input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MirrorStatus {
    /// Exact content digest of the current head.
    InSync,
    /// Mirror lags head, including a crash before the first mirror write.
    Stale {
        /// Older committed version with identical bytes, or `None` if absent.
        mirror_matches: Option<Version>,
    },
    /// Mirror bytes match no committed version.
    HandEdited,
    /// No mirror file and no committed head exist.
    Missing,
}

/// Completed commit steps, for deterministic interruption tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitStep {
    /// The exclusive version file exists.
    VersionCreated,
    /// Version bytes have been written.
    VersionWritten,
    /// Version content and permissions have been synchronized.
    VersionSynced,
    /// The versions directory has been synchronized.
    VersionDirectorySynced,
    /// The exclusive metadata file exists.
    MetaCreated,
    /// Metadata bytes have been written.
    MetaWritten,
    /// Metadata content and permissions have been synchronized.
    MetaSynced,
    /// Metadata's directory entry has been synchronized.
    MetaDirectorySynced,
    /// A step of the atomic head replacement.
    Head(DurableStep),
    /// A step of the mirror replacement, after head has been published.
    Mirror(DurableStep),
}

/// Configuration store rooted at `/var/lib/scupper` in production.
#[derive(Debug)]
pub struct VersionStore {
    root: PathBuf,
    mirror_root: PathBuf,
    interrupted: Vec<Version>,
}
impl VersionStore {
    /// Constructs a read-only view without creating directories, taking writer
    /// locks or recovering files. [`Self::head`] and [`Self::read`] still verify
    /// committed metadata, content digests and configuration before returning it.
    #[must_use]
    pub fn read_only(root: &Path, mirror_root: &Path) -> Self {
        Self {
            root: root.into(),
            mirror_root: mirror_root.into(),
            interrupted: Vec::new(),
        }
    }

    /// Opens a store with its mirror at `root/scupper.toml`.
    /// Use [`Self::open_with_mirror_root`] to select `/etc/scupper` in production.
    /// A global writer guard enables stale-temp cleanup and stale-mirror recovery.
    ///
    /// # Errors
    /// Returns directory, malformed head, or committed-head integrity errors.
    pub fn open(root: impl AsRef<Path>, writer: Option<&WriterGuard>) -> Result<Self, StoreError> {
        Self::open_with_mirror_root(root.as_ref(), root.as_ref(), writer)
    }

    /// Opens a store and independently configures the mirror directory.
    /// With a global writer guard, removes owned stale temporary files and
    /// refreshes stale mirrors under the store lock. Unknown mirror bytes remain
    /// available for hand-edit alerts. Without a guard, recovery does not mutate files.
    /// Interrupted versions are reported by [`Self::interrupted_versions`].
    ///
    /// # Errors
    /// Returns directory, malformed head, or committed-head integrity errors.
    pub fn open_with_mirror_root(
        root: impl AsRef<Path>,
        mirror_root: impl AsRef<Path>,
        writer: Option<&WriterGuard>,
    ) -> Result<Self, StoreError> {
        let mut store = Self {
            root: root.as_ref().into(),
            mirror_root: mirror_root.as_ref().into(),
            interrupted: Vec::new(),
        };
        durable_directory(&store.versions())?;
        durable_directory(&store.root.join("rendered"))?;
        // Persist the newly created directory hierarchy before publishing a head.
        RealFs.sync_dir(&store.config())?;
        RealFs.sync_dir(&store.root)?;
        let _guard = WriterLock::acquire(store.config())?;
        let head = store.head()?;
        store.interrupted = store.scan_interrupted(head)?;
        if let Some(writer) = writer {
            for directory in [
                store.config(),
                store.root.clone(),
                store.root.join("rendered"),
                store.mirror_root.clone(),
            ] {
                if directory.is_dir() {
                    RealFs.cleanup_stale(&directory)?;
                }
            }
            if matches!(store.mirror_status_locked()?, MirrorStatus::Stale { .. }) {
                store.refresh_mirror_locked(writer)?;
            }
        }
        Ok(store)
    }

    /// Versions above head found at open; these are excluded from all reads.
    #[must_use]
    pub fn interrupted_versions(&self) -> &[Version] {
        &self.interrupted
    }

    /// Reads the authoritative head and checks its metadata and content digest.
    ///
    /// # Errors
    /// Refuses corrupt head, missing committed files, or digest mismatches.
    pub fn head(&self) -> Result<Option<Version>, StoreError> {
        let head = self.head_number()?;
        if let Some(n) = head {
            self.read_version(n)?;
        }
        Ok(head)
    }

    /// Reads committed TOML and verified metadata. Stray versions are invisible.
    ///
    /// # Errors
    /// Returns uncommitted-version, integrity, or I/O errors.
    pub fn read(&self, n: Version) -> Result<(String, Meta), StoreError> {
        if n == 0 || self.head_number()?.is_none_or(|head| n > head) {
            return Err(StoreError::NotCommitted(n));
        }
        self.read_version(n)
    }

    /// Validates then commits a new immutable version using compare-and-swap.
    /// Updates the read-only mirror after durably publishing head. Mirror errors
    /// therefore can be returned after a successful authoritative commit.
    ///
    /// # Errors
    /// Returns validation, CAS, integrity, or durability errors.
    ///
    /// ```compile_fail
    /// # use scupper_sys::store::{VersionStore, MetaInput};
    /// fn unlocked(store: &VersionStore, meta: MetaInput) {
    ///     store.commit(None, "", meta);
    /// }
    /// ```
    pub fn commit(
        &self,
        writer: &WriterGuard,
        parent: Option<Version>,
        toml: &str,
        meta: MetaInput,
    ) -> Result<Version, StoreError> {
        self.commit_with_hook(writer, parent, toml, meta, &|_| Ok(()))
    }

    /// Commits with a callback after every version, metadata, head, and mirror step.
    /// Failure before head rename preserves old head; after it, new head is
    /// complete. Check head after any error before deciding whether to retry.
    ///
    /// # Errors
    /// Returns validation, CAS, filesystem, or injected errors.
    pub fn commit_with_hook(
        &self,
        writer: &WriterGuard,
        parent: Option<Version>,
        toml: &str,
        input: MetaInput,
        hook: &dyn Fn(CommitStep) -> io::Result<()>,
    ) -> Result<Version, StoreError> {
        check_config(toml)?;
        let _guard = WriterLock::acquire(self.config())?;
        let head = self.head()?;
        if parent != head {
            return Err(StoreError::Conflict { head });
        }
        let n = head
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(StoreError::Corrupt("version overflow"))?;
        let meta = Meta {
            parent,
            sha256: digest(toml.as_bytes()),
            actor: input.actor,
            at: input.at,
            reason: input.reason,
        };
        let bytes = serde_json::to_vec(&meta).map_err(io::Error::other)?;
        self.archive_interrupted(head)?;
        self.write_immutable(
            n,
            "toml",
            toml.as_bytes(),
            [
                CommitStep::VersionCreated,
                CommitStep::VersionWritten,
                CommitStep::VersionSynced,
                CommitStep::VersionDirectorySynced,
            ],
            hook,
        )?;
        self.write_immutable(
            n,
            "meta.json",
            &bytes,
            [
                CommitStep::MetaCreated,
                CommitStep::MetaWritten,
                CommitStep::MetaSynced,
                CommitStep::MetaDirectorySynced,
            ],
            hook,
        )?;
        durable_replace(
            &RealFs,
            &self.config().join("head"),
            format!("{n}\n").as_bytes(),
            0o640,
            &|_| Ok(()),
            &|step| hook(CommitStep::Head(step)),
        )?;
        self.write_mirror(writer, toml, &|step| hook(CommitStep::Mirror(step)))?;
        Ok(n)
    }

    /// Creates N+1 with an older version's content and current head as parent.
    ///
    /// # Errors
    /// Returns read, validation, CAS, or durability errors.
    ///
    /// ```compile_fail
    /// # use scupper_sys::store::{VersionStore, MetaInput};
    /// fn unlocked(store: &VersionStore, meta: MetaInput) {
    ///     store.rollback(1, meta);
    /// }
    /// ```
    pub fn rollback(
        &self,
        writer: &WriterGuard,
        to: Version,
        meta: MetaInput,
    ) -> Result<Version, StoreError> {
        let parent = self.head()?;
        let (toml, _) = self.read(to)?;
        self.commit(writer, parent, &toml, meta)
    }

    /// Returns metadata in ascending committed-version order, checking integrity.
    ///
    /// # Errors
    /// Returns corrupt or missing historical data rather than truncating history.
    pub fn history(&self) -> Result<Vec<Meta>, StoreError> {
        (1..=self.head()?.unwrap_or(0))
            .map(|n| self.read_version(n).map(|(_, meta)| meta))
            .collect()
    }

    /// Durably writes `rendered/NNNNNN.nft` for a committed version.
    ///
    /// # Errors
    /// Returns uncommitted-version, integrity, or filesystem errors.
    pub fn write_rendered(
        &self,
        _writer: &WriterGuard,
        n: Version,
        ruleset: &str,
    ) -> Result<(), StoreError> {
        self.read(n)?;
        durable_replace(
            &RealFs,
            &self.root.join("rendered").join(format!("{n:06}.nft")),
            ruleset.as_bytes(),
            0o640,
            &|_| Ok(()),
            &|_| Ok(()),
        )?;
        Ok(())
    }

    /// Compares mirror bytes with head's SHA-256; never accepts mirror input.
    ///
    /// # Errors
    /// Returns head integrity or mirror I/O errors, including symlink refusal.
    pub fn mirror_status(&self) -> Result<MirrorStatus, StoreError> {
        let _guard = WriterLock::acquire(self.config())?;
        self.mirror_status_locked()
    }

    // The store lock prevents a commit between observing head and mirror.
    fn mirror_status_locked(&self) -> Result<MirrorStatus, StoreError> {
        let head = self.head()?;
        let path = self.mirror_root.join("scupper.toml");
        RealFs.check_target(&path)?;
        let mirror = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(if head.is_some() {
                    MirrorStatus::Stale {
                        mirror_matches: None,
                    }
                } else {
                    MirrorStatus::Missing
                });
            }
            Err(error) => return Err(error.into()),
        };
        let sha256 = digest(&mirror);
        for n in (1..=head.unwrap_or(0)).rev() {
            if self.read_version(n)?.1.sha256 == sha256 {
                return Ok(if Some(n) == head {
                    MirrorStatus::InSync
                } else {
                    MirrorStatus::Stale {
                        mirror_matches: Some(n),
                    }
                });
            }
        }
        Ok(MirrorStatus::HandEdited)
    }

    /// Restores the mirror from authoritative head, including after interruption.
    ///
    /// # Errors
    /// Returns integrity or mirror durability errors. With no head, does nothing.
    pub fn refresh_mirror(&self, writer: &WriterGuard) -> Result<(), StoreError> {
        let _guard = WriterLock::acquire(self.config())?;
        self.refresh_mirror_locked(writer)
    }

    fn refresh_mirror_locked(&self, writer: &WriterGuard) -> Result<(), StoreError> {
        if let Some(head) = self.head()? {
            self.write_mirror(writer, &self.read_version(head)?.0, &|_| Ok(()))?;
        }
        Ok(())
    }

    fn config(&self) -> PathBuf {
        self.root.join("config")
    }
    fn versions(&self) -> PathBuf {
        self.config().join("versions")
    }
    fn version_path(&self, n: Version, extension: &str) -> PathBuf {
        self.versions().join(format!("{n:06}.{extension}"))
    }

    fn head_number(&self) -> Result<Option<Version>, StoreError> {
        let text = match RealFs.read(&self.config().join("head")) {
            Ok(text) => text,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let number = text.strip_suffix('\n').unwrap_or(&text);
        let n: u64 = number
            .parse()
            .map_err(|_| StoreError::Corrupt("invalid head"))?;
        if n == 0 || number != n.to_string() {
            return Err(StoreError::Corrupt("invalid head"));
        }
        Ok(Some(n))
    }
    fn read_version(&self, n: Version) -> Result<(String, Meta), StoreError> {
        let toml = RealFs.read(&self.version_path(n, "toml"))?;
        let meta: Meta = serde_json::from_str(&RealFs.read(&self.version_path(n, "meta.json"))?)
            .map_err(|_| StoreError::Corrupt("invalid metadata"))?;
        let expected_parent = n.checked_sub(1).filter(|n| *n > 0);
        if meta.parent != expected_parent {
            return Err(StoreError::Corrupt("nonlinear parent"));
        }
        if meta.sha256 != digest(toml.as_bytes()) {
            return Err(StoreError::Corrupt("version digest mismatch"));
        }
        check_config(&toml)?;
        Ok((toml, meta))
    }
    fn write_mirror(
        &self,
        _writer: &WriterGuard,
        toml: &str,
        hook: &dyn Fn(DurableStep) -> io::Result<()>,
    ) -> Result<(), StoreError> {
        durable_directory(&self.mirror_root)?;
        durable_replace(
            &RealFs,
            &self.mirror_root.join("scupper.toml"),
            toml.as_bytes(),
            0o444,
            &|_| Ok(()),
            hook,
        )?;
        Ok(())
    }
    fn write_immutable(
        &self,
        n: Version,
        extension: &str,
        bytes: &[u8],
        steps: [CommitStep; 4],
        hook: &dyn Fn(CommitStep) -> io::Result<()>,
    ) -> io::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o640)
            .open(self.version_path(n, extension))?;
        hook(steps[0])?;
        file.write_all(bytes)?;
        hook(steps[1])?;
        file.set_permissions(fs::Permissions::from_mode(0o640))?;
        file.sync_all()?;
        hook(steps[2])?;
        RealFs.sync_dir(&self.versions())?;
        hook(steps[3])
    }
    fn scan_interrupted(&self, head: Option<Version>) -> Result<Vec<Version>, StoreError> {
        let mut numbers = BTreeSet::new();
        for entry in fs::read_dir(self.versions())? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            let Some(number) = name
                .strip_suffix(".toml")
                .or_else(|| name.strip_suffix(".meta.json"))
            else {
                continue;
            };
            if let Ok(n) = number.parse::<Version>()
                && n > head.unwrap_or(0)
                && number == format!("{n:06}")
            {
                numbers.insert(n);
            }
        }
        Ok(numbers.into_iter().collect())
    }
    fn archive_interrupted(&self, head: Option<Version>) -> Result<(), StoreError> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let numbers = self.scan_interrupted(head)?;
        if numbers.is_empty() {
            return Ok(());
        }
        let archive = self.config().join("interrupted");
        fs::create_dir_all(&archive)?;
        let batch = loop {
            let path = archive.join(format!(
                "{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match fs::create_dir(&path) {
                Ok(()) => break path,
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        };
        // Make the archive directory durable before removing source entries.
        RealFs.sync_dir(&self.config())?;
        RealFs.sync_dir(&archive)?;
        for n in numbers {
            for extension in ["toml", "meta.json"] {
                let source = self.version_path(n, extension);
                match fs::rename(&source, batch.join(format!("{n:06}.{extension}"))) {
                    Ok(()) => {}
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
            }
        }
        RealFs.sync_dir(&batch)?;
        RealFs.sync_dir(&self.versions())?;
        Ok(())
    }
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn check_config(toml: &str) -> Result<(), StoreError> {
    let parsed = parse_site(toml).map_err(|_| StoreError::InvalidConfig)?;
    validate(parsed).map_err(|_| StoreError::InvalidConfig)?;
    Ok(())
}
