//! Validate and durably replace the v1 boot ruleset before loading it.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use crate::system::{EXEC_TIMEOUT, Program, System};

/// Fixed v1 boot ruleset destination.
pub const RULESET_PATH: &str = "/etc/nftables.conf";

/// An open, exclusively created temporary file.
pub trait TempFile: Write {
    /// Flushes the file's content and metadata to stable storage.
    ///
    /// # Errors
    /// Returns the underlying synchronization error.
    fn sync_all(&self) -> io::Result<()>;
}

impl TempFile for File {
    fn sync_all(&self) -> io::Result<()> {
        Self::sync_all(self)
    }
}

/// Filesystem operations needed for previewing and installing the ruleset.
pub trait Fs {
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

    /// Sets the installed file's Unix permission bits.
    ///
    /// # Errors
    /// Returns permission update errors.
    fn set_mode(&self, path: &Path, mode: u32) -> io::Result<()>;

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
    fn read(&self, path: &Path) -> io::Result<String> {
        fs::read_to_string(path)
    }

    fn create_temp(&self, directory: &Path) -> io::Result<(PathBuf, Box<dyn TempFile>)> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        loop {
            let path = directory.join(format!(
                ".scupper-{}-{}.tmp",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
            {
                Ok(file) => return Ok((path, Box::new(file))),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
        }
    }

    fn rename(&self, source: &Path, destination: &Path) -> io::Result<()> {
        fs::rename(source, destination)
    }

    fn set_mode(&self, path: &Path, mode: u32) -> io::Result<()> {
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
    }

    fn sync_dir(&self, directory: &Path) -> io::Result<()> {
        File::open(directory)?.sync_all()
    }

    fn remove(&self, path: &Path) -> io::Result<()> {
        fs::remove_file(path)
    }
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

/// Validates, installs, and loads the default boot ruleset.
///
/// The temporary file is removed on every failure before rename. Once renamed,
/// errors explicitly identify the new validated version that remains on disk.
///
/// # Errors
/// Returns a user-facing diagnostic for any filesystem or nft failure.
pub fn apply(sys: &dyn System, fs: &dyn Fs, rules: &str) -> Result<(), String> {
    let directory = Path::new("/etc");
    let destination = Path::new(RULESET_PATH);
    let (path, mut file) = fs
        .create_temp(directory)
        .map_err(|error| format!("create temporary ruleset: {error}"))?;
    let mut temp = PendingTemp {
        fs,
        path,
        pending: true,
    };
    let result = (|| {
        file.write_all(rules.as_bytes())
            .map_err(|error| format!("write temporary ruleset: {error}"))?;
        file.sync_all()
            .map_err(|error| format!("sync temporary ruleset: {error}"))?;
        drop(file);
        nft(sys, &["-c", "-f", &temp.path.to_string_lossy()])?;
        fs.rename(&temp.path, destination)
            .map_err(|error| format!("rename ruleset: {error}"))?;
        temp.pending = false;
        let installed = || -> Result<(), String> {
            fs.set_mode(destination, 0o644)
                .map_err(|error| format!("set ruleset permissions: {error}"))?;
            fs.sync_dir(directory)
                .map_err(|error| format!("sync ruleset directory: {error}"))?;
            nft(sys, &["-f", RULESET_PATH])
        };
        installed().map_err(|error| {
            format!("{error}; the file on disk at {RULESET_PATH} is the new, validated version")
        })
    })();
    match (result, temp.cleanup()) {
        (result, Ok(())) => result,
        (Ok(()), Err(error)) => Err(format!("remove temporary ruleset: {error}")),
        (Err(original), Err(error)) => {
            Err(format!("{original}; remove temporary ruleset: {error}"))
        }
    }
}

fn nft(sys: &dyn System, args: &[&str]) -> Result<(), String> {
    let output = sys
        .run(
            Program::Nft,
            &args.iter().map(|arg| (*arg).to_owned()).collect::<Vec<_>>(),
            EXEC_TIMEOUT,
        )
        .map_err(|error| format!("nft: {error}"))?;
    if output.status == Some(0) {
        Ok(())
    } else {
        let diagnostic = if args.first() == Some(&"-c") {
            output.stderr.lines().next().unwrap_or_default()
        } else {
            output.stderr.trim()
        };
        Err(format!(
            "nft failed (status {:?}): {diagnostic}",
            output.status
        ))
    }
}

/// Produces a unified diff containing one complete-file hunk.
///
/// Keeping the entire ruleset visible makes the small v1 policy reviewable.
#[must_use]
pub fn ruleset_diff(old: &str, new: &str) -> String {
    if old == new {
        return String::new();
    }
    let mut diff = format!(
        "--- {RULESET_PATH}\n+++ {RULESET_PATH} (generated)\n@@ -{} +{} @@\n",
        diff_range(old),
        diff_range(new)
    );
    for (prefix, contents) in [('-', old), ('+', new)] {
        for line in contents.split_inclusive('\n') {
            diff.push(prefix);
            diff.push_str(line);
            if !line.ends_with('\n') {
                diff.push_str("\n\\ No newline at end of file\n");
            }
        }
    }
    diff
}

fn diff_range(text: &str) -> String {
    match text.lines().count() {
        0 => "0,0".to_owned(),
        1 => "1".to_owned(),
        count => format!("1,{count}"),
    }
}
