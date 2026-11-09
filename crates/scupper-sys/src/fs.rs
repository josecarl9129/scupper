//! Crash-safe file replacement shared by the M2 store, mirror and state.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

/// An open, exclusively created temporary file.
pub trait TempFile: Write {
    /// Flushes the file's content and metadata to stable storage.
    ///
    /// # Errors
    /// Returns the underlying synchronization error.
    fn sync_all(&self) -> io::Result<()>;

    /// Sets permissions on the open temporary file, before it is renamed.
    ///
    /// # Errors
    /// Returns the underlying permission update error.
    fn set_mode(&self, mode: u32) -> io::Result<()>;
}

impl TempFile for File {
    fn set_mode(&self, mode: u32) -> io::Result<()> {
        self.set_permissions(fs::Permissions::from_mode(mode))
    }

    fn sync_all(&self) -> io::Result<()> {
        Self::sync_all(self)
    }
}

/// Filesystem operations for durable persistence.
pub trait Fs {
    /// Refuses a symlink at the file destination, including dangling links.
    ///
    /// # Errors
    /// Returns a refusal or an inspection error; a missing target is allowed.
    fn check_target(&self, path: &Path) -> io::Result<()>;

    /// Removes only regular, current-user-owned `.scupper-<pid>-<counter>.tmp` files.
    ///
    /// # Errors
    /// Returns directory inspection or removal errors.
    fn cleanup_stale(&self, directory: &Path) -> io::Result<()>;

    /// Reads an existing file; a missing file must return `NotFound`.
    ///
    /// # Errors
    /// Returns read or UTF-8 decoding errors.
    fn read(&self, path: &Path) -> io::Result<String>;

    /// Exclusively creates a uniquely named file with mode 0600 in `directory`.
    /// On error, no new file may remain.
    ///
    /// # Errors
    /// Returns creation errors.
    fn create_temp(&self, directory: &Path) -> io::Result<(PathBuf, Box<dyn TempFile>)>;

    /// Atomically replaces `destination` with `source`, consuming `source`.
    ///
    /// # Errors
    /// Returns rename errors, leaving the source available for cleanup.
    fn rename(&self, source: &Path, destination: &Path) -> io::Result<()>;

    /// Synchronizes a directory after a rename.
    ///
    /// # Errors
    /// Returns directory open or synchronization errors.
    fn sync_dir(&self, directory: &Path) -> io::Result<()>;

    /// Removes a temporary file.
    ///
    /// # Errors
    /// Returns removal errors; a missing file may return `NotFound`.
    fn remove(&self, path: &Path) -> io::Result<()>;
}

/// Host filesystem implementation using `std::fs`.
#[derive(Debug, Default)]
pub struct RealFs;

impl Fs for RealFs {
    fn check_target(&self, path: &Path) -> io::Result<()> {
        match fs::symlink_metadata(path) {
            Ok(metadata) if metadata.is_symlink() => {
                Err(io::Error::other("refusing symlinked file"))
            }
            Ok(_) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }

    fn cleanup_stale(&self, directory: &Path) -> io::Result<()> {
        let uid = rustix::process::geteuid().as_raw();
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            if !entry.file_name().to_str().is_some_and(is_temp_name) {
                continue;
            }
            let metadata = fs::symlink_metadata(entry.path())?;
            if owned_regular_file(&metadata, uid) {
                fs::remove_file(entry.path())?;
            }
        }
        Ok(())
    }

    fn read(&self, path: &Path) -> io::Result<String> {
        self.check_target(path)?;
        fs::read_to_string(path)
    }

    fn create_temp(&self, directory: &Path) -> io::Result<(PathBuf, Box<dyn TempFile>)> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = directory.join(format!(
            ".scupper-{}-{}.tmp",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let file = create_temp_file(&path)?;
        Ok((path, Box::new(file)))
    }

    fn rename(&self, source: &Path, destination: &Path) -> io::Result<()> {
        self.check_target(destination)?;
        fs::rename(source, destination)
    }

    fn sync_dir(&self, directory: &Path) -> io::Result<()> {
        File::open(directory)?.sync_all()
    }

    fn remove(&self, path: &Path) -> io::Result<()> {
        fs::remove_file(path)
    }
}

fn create_temp_file(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

fn owned_regular_file(metadata: &fs::Metadata, uid: u32) -> bool {
    metadata.is_file() && metadata.uid() == uid
}

fn is_temp_name(name: &str) -> bool {
    name.strip_prefix(".scupper-")
        .and_then(|name| name.strip_suffix(".tmp"))
        .and_then(|name| name.split_once('-'))
        .is_some_and(|(pid, counter)| {
            [pid, counter]
                .iter()
                .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
        })
}

struct PendingTemp<'a> {
    fs: &'a dyn Fs,
    path: PathBuf,
    pending: bool,
}

impl PendingTemp<'_> {
    fn cleanup(&mut self) -> io::Result<()> {
        if self.pending {
            match self.fs.remove(&self.path) {
                Ok(()) => self.pending = false,
                Err(error) if error.kind() == io::ErrorKind::NotFound => self.pending = false,
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }
}

impl Drop for PendingTemp<'_> {
    fn drop(&mut self) {
        // Also retry a transient cleanup error after reporting it to the caller.
        let _ = self.cleanup();
    }
}

/// Completed steps of an atomic durable replacement, exposed for fault injection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DurableStep {
    /// The exclusive temporary file exists.
    Created,
    /// All content has been written to the temporary file.
    Written,
    /// Content has been synchronized, before optional validation.
    ContentSynced,
    /// Final permissions and content have been synchronized.
    FileSynced,
    /// The temporary file has atomically replaced the destination.
    Renamed,
    /// The containing directory has been synchronized.
    DirectorySynced,
}

// Persist every new directory entry, including a previously absent configured
// root. Merely syncing the new directory does not persist its entry in parent.
pub(crate) fn durable_directory(path: &Path) -> io::Result<()> {
    if path.as_os_str().is_empty() || path.is_dir() {
        return Ok(());
    }
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    durable_directory(parent)?;
    match fs::create_dir(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists && path.is_dir() => {}
        Err(error) => return Err(error),
    }
    RealFs.sync_dir(path)?;
    RealFs.sync_dir(parent)
}

// Shared by the config head and mirror, rendered files, and state.json.
// A failed pre-rename step removes its temporary file; post-rename errors leave
// the complete new file in place. `prepare` sees the synced, still-private file.
pub(crate) fn durable_replace(
    fs: &dyn Fs,
    destination: &Path,
    bytes: &[u8],
    mode: u32,
    prepare: &dyn Fn(&Path) -> io::Result<()>,
    hook: &dyn Fn(DurableStep) -> io::Result<()>,
) -> io::Result<()> {
    let directory = destination
        .parent()
        .ok_or_else(|| io::Error::other("missing parent directory"))?;
    let (path, mut file) = fs
        .create_temp(directory)
        .map_err(context("create temporary file"))?;
    let mut temp = PendingTemp {
        fs,
        path,
        pending: true,
    };
    let result = (|| {
        hook(DurableStep::Created)?;
        file.write_all(bytes)
            .map_err(context("write temporary file"))?;
        hook(DurableStep::Written)?;
        file.sync_all()
            .map_err(context("sync temporary file content"))?;
        hook(DurableStep::ContentSynced)?;
        prepare(&temp.path)?;
        file.set_mode(mode)
            .map_err(context("set temporary file permissions"))?;
        file.sync_all()
            .map_err(context("sync temporary file permissions"))?;
        hook(DurableStep::FileSynced)?;
        drop(file);
        fs.rename(&temp.path, destination)
            .map_err(context("rename temporary file"))?;
        temp.pending = false;
        hook(DurableStep::Renamed)?;
        fs.sync_dir(directory)
            .map_err(context("sync destination directory"))?;
        hook(DurableStep::DirectorySynced)
    })();
    match (result, temp.cleanup()) {
        (result, Ok(())) => result,
        (Ok(()), Err(error)) => Err(context("remove temporary file")(error)),
        (Err(original), Err(error)) => Err(io::Error::other(format!(
            "{original}; remove temporary file: {error}"
        ))),
    }
}

fn context(step: &'static str) -> impl FnOnce(io::Error) -> io::Error {
    move |error| io::Error::new(error.kind(), format!("{step}: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Each failure is injected at the filesystem operation, before its hook.
    struct FailingFs(&'static str);
    struct FailingFile(&'static str, std::cell::Cell<u8>);

    fn fail_if(actual: &str, requested: &str) -> io::Result<()> {
        if actual == requested {
            Err(io::Error::from(io::ErrorKind::StorageFull))
        } else {
            Ok(())
        }
    }
    impl Write for FailingFile {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            fail_if("write", self.0)?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    impl TempFile for FailingFile {
        fn sync_all(&self) -> io::Result<()> {
            let operation = if self.1.get() == 0 {
                "content sync"
            } else {
                "permissions sync"
            };
            self.1.set(self.1.get() + 1);
            fail_if(operation, self.0)
        }
        fn set_mode(&self, _: u32) -> io::Result<()> {
            fail_if("chmod", self.0)
        }
    }
    impl Fs for FailingFs {
        fn check_target(&self, _: &Path) -> io::Result<()> {
            Ok(())
        }
        fn cleanup_stale(&self, _: &Path) -> io::Result<()> {
            Ok(())
        }
        fn read(&self, _: &Path) -> io::Result<String> {
            Err(io::ErrorKind::NotFound.into())
        }
        fn create_temp(&self, directory: &Path) -> io::Result<(PathBuf, Box<dyn TempFile>)> {
            fail_if("create", self.0)?;
            Ok((
                directory.join(".fake"),
                Box::new(FailingFile(self.0, std::cell::Cell::new(0))),
            ))
        }
        fn rename(&self, _: &Path, _: &Path) -> io::Result<()> {
            fail_if("rename", self.0)
        }
        fn sync_dir(&self, _: &Path) -> io::Result<()> {
            fail_if("directory sync", self.0)
        }
        fn remove(&self, _: &Path) -> io::Result<()> {
            fail_if("remove", self.0)
        }
    }

    #[test]
    fn durability_errors_name_the_failed_operation() -> io::Result<()> {
        for (operation, diagnostic) in [
            ("create", "create temporary file"),
            ("write", "write temporary file"),
            ("content sync", "sync temporary file content"),
            ("chmod", "set temporary file permissions"),
            ("permissions sync", "sync temporary file permissions"),
            ("rename", "rename temporary file"),
            ("directory sync", "sync destination directory"),
        ] {
            let error = durable_replace(
                &FailingFs(operation),
                Path::new("unused/rules"),
                b"rules",
                0o644,
                &|_| Ok(()),
                &|_| Ok(()),
            )
            .err()
            .ok_or_else(|| io::Error::other("injected operation succeeded"))?;
            assert!(error.to_string().contains(diagnostic), "{error}");
            assert_eq!(error.kind(), io::ErrorKind::StorageFull);
        }
        let error = durable_replace(
            &FailingFs("remove"),
            Path::new("unused/rules"),
            b"rules",
            0o644,
            &|_| Err(io::Error::other("validation failed")),
            &|_| Ok(()),
        )
        .err()
        .ok_or_else(|| io::Error::other("injected remove succeeded"))?;
        assert!(error.to_string().contains("remove temporary file"));
        Ok(())
    }

    #[test]
    fn real_temp_creation_is_exclusive_and_cleanup_requires_ownership() -> io::Result<()> {
        struct Directory(PathBuf);
        impl Drop for Directory {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let directory = Directory(std::env::temp_dir().join(format!(
            "scupper-exclusive-test-{}-{}", std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
                .map_err(io::Error::other)?.as_nanos()
        )));
        fs::create_dir(&directory.0)?;
        let path = directory.0.join(".scupper-1-0.tmp");
        let mut file = create_temp_file(&path)?;
        file.write_all(b"must not be overwritten")?;
        assert_eq!(
            create_temp_file(&path).err().map(|error| error.kind()),
            Some(io::ErrorKind::AlreadyExists)
        );
        assert_eq!(fs::read_to_string(&path)?, "must not be overwritten");
        let metadata = fs::symlink_metadata(&path)?;
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        let uid = rustix::process::geteuid().as_raw();
        assert!(owned_regular_file(&metadata, uid));
        assert!(!owned_regular_file(&metadata, uid.wrapping_add(1)));
        RealFs.cleanup_stale(&directory.0)?;
        assert!(!path.exists());
        Ok(())
    }
}
