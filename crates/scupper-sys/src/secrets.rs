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
        if name.kind() == SecretKind::Url && bytes.last() == Some(&b'\n') {
            bytes.pop();
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
    /// Resolve every configured secret before publishing a version.
    /// # Errors
    /// Names the reference whose confinement, metadata or content check failed.
    pub fn preflight(
        root: &Path,
        site: &scupper_core::config::SiteConfig,
        owner: u32,
    ) -> Result<(), SecretError> {
        let refs = site
            .identities
            .values()
            .map(|i| &i.private_key_ref)
            .chain(site.gateways.values().flat_map(|g| &g.exits).flat_map(|e| {
                std::iter::once(&e.private_key_ref).chain(e.preshared_key_ref.as_ref())
            }))
            .chain(
                site.alerts
                    .sinks
                    .values()
                    .map(scupper_core::config::AlertSink::url_ref),
            )
            .chain(site.heartbeat.as_ref().map(|h| &h.url_ref));
        for reference in refs {
            Self::open_with_owner(root, reference, owner)?;
        }
        Ok(())
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

impl SecretFile {
    /// Durably installs a new key with no replacement and confined directory FDs.
    /// Requires the effective owner (root in production); no key bytes enter errors.
    /// # Errors
    /// Refuses existing destinations, unsafe ownership/modes, links or invalid keys.
    pub fn write_new(root: &Path, name: &SecretName, bytes: &[u8]) -> std::io::Result<()> {
        Self::write_key(root, name, bytes, false)
    }

    /// Atomically replaces an unreferenced key. The caller must hold the writer
    /// lock and prove that no version from applied through head references it.
    /// # Errors
    /// Refuses unsafe directories, references, content, or failed durable writes.
    pub fn replace_unreferenced(
        root: &Path,
        name: &SecretName,
        bytes: &[u8],
    ) -> std::io::Result<()> {
        Self::write_key(root, name, bytes, true)
    }

    fn write_key(
        root: &Path,
        name: &SecretName,
        bytes: &[u8],
        replace: bool,
    ) -> std::io::Result<()> {
        use rustix::fs::{AtFlags, RenameFlags, fsync, renameat_with, unlinkat};
        use std::{
            io::Write,
            os::unix::fs::PermissionsExt,
            sync::atomic::{AtomicU64, Ordering},
        };
        static NEXT: AtomicU64 = AtomicU64::new(0);
        if !name.valid()
            || name.kind() != SecretKind::Wg
            || !std::str::from_utf8(bytes).is_ok_and(valid_wg_secret)
        {
            return Err(std::io::Error::other("invalid secret reference or key"));
        }
        let directory = Self::wg_directory(root)?;
        let temp = format!(
            ".scupper-{}-{}.tmp",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        let fd = openat(
            &directory,
            temp.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )?;
        let mut renamed = false;
        let result = (|| {
            let mut file = File::from(fd);
            file.write_all(bytes)?;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
            file.sync_all()?;
            renameat_with(
                &directory,
                temp.as_str(),
                &directory,
                name.name(),
                if replace {
                    RenameFlags::empty()
                } else {
                    RenameFlags::NOREPLACE
                },
            )?;
            renamed = true;
            fsync(&directory)?;
            Ok(())
        })();
        match unlinkat(&directory, temp.as_str(), AtFlags::empty()) {
            Ok(()) | Err(rustix::io::Errno::NOENT) => {}
            Err(error) => {
                return Err(std::io::Error::other(format!(
                    "temporary key cleanup failed: {error}"
                )));
            }
        }
        if result.is_err() && renamed {
            unlinkat(&directory, name.name(), AtFlags::empty())?;
            fsync(&directory)?;
        }
        result
    }

    fn wg_directory(root: &Path) -> std::io::Result<rustix::fd::OwnedFd> {
        use rustix::fs::{fsync, mkdirat};
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let owner = rustix::process::geteuid().as_raw();
        let root = open(root, flags, Mode::empty())?;
        let stat = fstat(&root)?;
        if stat.st_uid != owner || stat.st_mode & 0o022 != 0 {
            return Err(std::io::Error::other("unsafe secret root"));
        }
        let mut directory = root;
        for part in ["secrets", "wg"] {
            match mkdirat(&directory, part, Mode::from_raw_mode(0o700)) {
                Ok(()) => fsync(&directory)?,
                Err(rustix::io::Errno::EXIST) => {}
                Err(e) => return Err(e.into()),
            }
            directory = openat(&directory, part, flags, Mode::empty())?;
            let stat = fstat(&directory)?;
            if stat.st_uid != owner || stat.st_mode & 0o7777 != 0o700 {
                return Err(std::io::Error::other("unsafe secret directory"));
            }
        }
        Ok(directory)
    }

    /// Collects unreferenced historical exit refs, crashed import generations,
    /// at or below head, and temporary writes older than this run. Future
    /// generations may still be publishing and are never collected here.
    /// Caller must serialize imports and hold the writer lock; all candidates
    /// are checked before the first deletion.
    /// # Errors
    /// Refuses unsafe directories, files, ownership, modes or failed durable deletes.
    pub fn sweep_wg(
        root: &Path,
        historical_exits: &std::collections::BTreeSet<String>,
        referenced: &std::collections::BTreeSet<String>,
        head: u64,
        started: std::time::SystemTime,
    ) -> std::io::Result<()> {
        use rustix::fs::{AtFlags, Dir, FileType, statat, unlinkat};
        let directory = Self::wg_directory(root)?;
        let mut entries = Dir::read_from(&directory)?;
        let owner = rustix::process::geteuid().as_raw();
        let mut deletions = Vec::new();
        for entry in &mut entries {
            let entry = entry?;
            let name = entry.file_name();
            let Ok(text) = name.to_str() else { continue };
            let temporary = text.starts_with(".scupper-") && text.as_bytes().ends_with(b".tmp");
            let generation = import_generation(text);
            let key = generation.is_none_or(|n| n <= head)
                && (historical_exits.contains(text) || generation.is_some())
                && !referenced.contains(text);
            if !temporary && !key {
                continue;
            }
            let stat = statat(&directory, name, AtFlags::SYMLINK_NOFOLLOW)?;
            if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
                || stat.st_uid != owner
                || stat.st_mode & 0o7777 != 0o600
            {
                return Err(std::io::Error::other(format!(
                    "unsafe secret entry {text:?}: move it out of secrets/wg or restore a regular file owned by uid {owner} with mode 0600; no files swept"
                )));
            }
            if temporary {
                let seconds = u64::try_from(stat.st_mtime).map_err(std::io::Error::other)?;
                let nanos = u32::try_from(stat.st_mtime_nsec).map_err(std::io::Error::other)?;
                let modified = std::time::UNIX_EPOCH + std::time::Duration::new(seconds, nanos);
                if modified >= started {
                    continue;
                }
            }
            deletions.push(name.to_owned());
        }
        for name in deletions {
            unlinkat(&directory, &name, AtFlags::empty())?;
        }
        rustix::fs::fsync(&directory)?;
        Ok(())
    }

    /// Removes a validated, owned secret and synchronizes its directory.
    /// # Errors
    /// Refuses unsafe references, files or directories, or a failed durable delete.
    pub fn remove(root: &Path, name: &SecretName) -> std::io::Result<()> {
        if name.kind() != SecretKind::Wg {
            return Err(std::io::Error::other(
                "expected a WireGuard secret reference",
            ));
        }
        Self::checked_file(root, name, rustix::process::geteuid().as_raw())
            .map_err(std::io::Error::other)?;
        // All directory components are checked again without following links.
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let root = open(root, flags, Mode::empty())?;
        let secrets = openat(&root, "secrets", flags, Mode::empty())?;
        let directory = openat(&secrets, "wg", flags, Mode::empty())?;
        rustix::fs::unlinkat(&directory, name.name(), rustix::fs::AtFlags::empty())?;
        rustix::fs::fsync(&directory)?;
        Ok(())
    }
}

fn import_generation(name: &str) -> Option<u64> {
    let name = name.strip_suffix("-psk").unwrap_or(name);
    let (id, version) = name
        .strip_prefix("exit-")
        .and_then(|s| s.rsplit_once("-v"))?;
    let n = version.parse::<u64>().ok()?;
    (scupper_core::config::ExitId(id.into()).is_valid()
        && id.len() <= 32
        && n > 0
        && n.to_string() == version
        && SecretName::new(SecretKind::Wg, name).is_ok())
    .then_some(n)
}
