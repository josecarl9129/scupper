//! Confined gateway secret reads; diagnostics never retain secret contents.

use rustix::fs::{FileType, Mode, OFlags, fstat, open, openat};
use scupper_core::config::{SecretKind, SecretName, valid_https_url, valid_wg_secret};
use std::{fs::File, io::Read, path::Path};
use zeroize::Zeroizing;

/// Secret bytes cleared on drop. Deliberately has no formatting or serialization traits.
pub struct Secret(Zeroizing<Vec<u8>>);
impl Secret {
    /// Borrows secret bytes for the immediate consumer.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

/// A value-free failure naming only the reference and failed check.
#[derive(Debug, thiserror::Error)]
#[error("secret {reference}: {check}")]
pub struct SecretError {
    reference: String,
    check: &'static str,
}

/// Safe gateway file resolver rooted at `/etc/scupper` in production.
pub struct SecretFile;
impl SecretFile {
    /// Opens `root/secrets/<kind>/<ref>`, requiring root ownership.
    ///
    /// # Errors
    /// Refuses unsafe names, directories, files, permissions, or content.
    pub fn open(root: impl AsRef<Path>, name: &SecretName) -> Result<Secret, SecretError> {
        Self::open_with_owner(root, name, 0)
    }

    /// Opens a secret with an explicit expected owner for unprivileged tests.
    /// All other checks and filesystem operations are identical to production.
    ///
    /// # Errors
    /// Refuses any failed confinement, metadata, read, or content check.
    pub fn open_with_owner(
        root: impl AsRef<Path>,
        name: &SecretName,
        owner: u32,
    ) -> Result<Secret, SecretError> {
        let fd = Self::checked_file(root.as_ref(), name, owner)?;
        let failure = |check| SecretError {
            reference: name.name().into(),
            check,
        };
        let mut bytes = Zeroizing::new(Vec::with_capacity(4097));
        fd.take(4097)
            .read_to_end(&mut bytes)
            .map_err(|_| failure("read reference"))?;
        if bytes.len() > 4096 {
            return Err(failure("reference exceeds 4 KiB"));
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| failure("content must be UTF-8"))?;
        let valid = match name.kind() {
            SecretKind::Wg => valid_wg_secret(text.strip_suffix('\n').unwrap_or(text)),
            SecretKind::Url => valid_https_url(text),
        };
        if !valid {
            return Err(failure("invalid content for secret kind"));
        }
        Ok(Secret(bytes))
    }
    // Open and validate metadata without reading the value. Reconciliation uses
    // this for availability signals; only an actual configure step reads bytes.
    pub(crate) fn checked_file(
        root: &Path,
        name: &SecretName,
        owner: u32,
    ) -> Result<File, SecretError> {
        if !name.valid() {
            return Err(SecretError {
                reference: format!("<invalid ref; length {}>", name.name().len()),
                check: "invalid reference basename; expected [a-z0-9][a-z0-9-]{0,62}",
            });
        }
        let failure = |check| SecretError {
            reference: name.name().into(),
            check,
        };
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let root = open(root, flags, Mode::empty()).map_err(|_| failure("open root directory"))?;
        let stat = fstat(&root).map_err(|_| failure("stat root directory"))?;
        if stat.st_uid != owner {
            return Err(failure("root directory owner"));
        }
        if stat.st_mode & 0o022 != 0 {
            return Err(failure(
                "root directory must not be group- or world-writable",
            ));
        }
        let secrets = openat(&root, "secrets", flags, Mode::empty())
            .map_err(|_| failure("open secrets directory"))?;
        let stat = fstat(&secrets).map_err(|_| failure("stat secrets directory"))?;
        if stat.st_uid != owner {
            return Err(failure("secrets directory owner"));
        }
        if stat.st_mode & 0o7777 != 0o700 {
            return Err(failure("secrets directory mode must be 0700"));
        }
        let kind = match name.kind() {
            SecretKind::Wg => "wg",
            SecretKind::Url => "url",
        };
        let directory = openat(&secrets, kind, flags, Mode::empty())
            .map_err(|_| failure("open kind directory without symlinks"))?;
        let stat = fstat(&directory).map_err(|_| failure("stat kind directory"))?;
        if stat.st_uid != owner {
            return Err(failure("kind directory owner"));
        }
        if stat.st_mode & 0o7777 != 0o700 {
            return Err(failure("kind directory mode must be 0700"));
        }
        // NONBLOCK prevents an attacker-controlled FIFO from hanging before fstat.
        let fd = openat(
            &directory,
            name.name(),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK | OFlags::NOCTTY,
            Mode::empty(),
        )
        .map_err(|_| failure("open reference without symlinks"))?;
        let stat = fstat(&fd).map_err(|_| failure("stat reference"))?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
            return Err(failure("reference must be a regular file"));
        }
        if stat.st_uid != owner {
            return Err(failure("reference owner"));
        }
        if stat.st_mode & 0o7777 != 0o600 {
            return Err(failure("reference mode must be 0600"));
        }
        if !(0..=4096).contains(&stat.st_size) {
            return Err(failure("reference exceeds 4 KiB"));
        }
        Ok(fd.into())
    }
}
