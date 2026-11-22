//! Safe Darwin descriptor adapter. Root checks use an fd-relative nofollow walk.
use super::{Fault, Io, Metadata, OpenError, Workers, filename, open_read, read_bytes, write};
use crate::{
    platform::{Deadline, SysError, WriteOutcome},
    snapshot::{COPY_BYTES, Copy, CopyRead},
};
use rustix::{
    fs::{Mode, OFlags, open, openat},
    io::Errno,
};
use std::{
    fs::File,
    os::unix::fs::{FileExt, MetadataExt},
    path::{Component, Path, PathBuf},
    time::Duration,
};

const FAILED: SysError = SysError::Failed("storage: partial bytes may remain");
const DIRECTORY: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);
fn root(path: &Path) -> Result<File, Errno> {
    if !path.is_absolute() {
        return Err(Errno::INVAL);
    }
    let mut fd = open("/", DIRECTORY, Mode::empty())?;
    for component in path.components() {
        let stat = rustix::fs::fstat(&fd)?;
        if !crate::platform::runtime::protected_owner_mode(stat.st_uid, u32::from(stat.st_mode)) {
            return Err(Errno::PERM);
        }
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                fd = openat(&fd, name, DIRECTORY, Mode::empty())?;
            }
            _ => return Err(Errno::INVAL),
        }
    }
    let stat = rustix::fs::fstat(&fd)?;
    if !crate::platform::runtime::protected_owner_mode(stat.st_uid, u32::from(stat.st_mode)) {
        return Err(Errno::PERM);
    }
    Ok(fd.into())
}
fn metadata(file: &File) -> Result<Metadata, SysError> {
    let m = file.metadata().map_err(|_| FAILED)?;
    Ok(Metadata {
        regular: m.is_file(),
        uid: m.uid(),
        mode: m.mode(),
        nlink: m.nlink(),
        size: m.size(),
    })
}
fn read(path: &Path, copy: Copy) -> CopyRead {
    let file: File = match open_read(root(path).map_err(|_| FAILED), |directory| {
        let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
        openat(&directory, filename(copy), flags, Mode::empty())
            .map(File::from)
            .map_err(|error| {
                if error == Errno::NOENT {
                    OpenError::Missing
                } else {
                    OpenError::Unreadable
                }
            })
    }) {
        Ok(file) => file,
        Err(result) => return result,
    };
    read_bytes(metadata(&file), |bytes| {
        file.read_at(bytes, 0).map_err(|_| FAILED)
    })
}
struct DescriptorIo {
    path: PathBuf,
    copy: Copy,
    directory: Option<File>,
    file: Option<File>,
    created: bool,
    #[cfg(feature = "qualification")]
    failure: FailureObservation,
}
impl Io for DescriptorIo {
    fn open(&mut self, create: bool) -> Result<(), SysError> {
        let directory = root(&self.path).map_err(|_| FAILED)?;
        let mut flags = OFlags::WRONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
        if create {
            flags |= OFlags::CREATE | OFlags::EXCL;
        }
        let file: File = openat(
            &directory,
            filename(self.copy),
            flags,
            Mode::from_raw_mode(0o600),
        )
        .map_err(|_| FAILED)?
        .into();
        // Retain ownership before any fallible post-create operation so cleanup
        // also covers fchown/fchmod/stat failures.
        self.directory = Some(directory);
        self.file = Some(file);
        self.created = create;
        let file = self.file.as_ref().ok_or(FAILED)?;
        if create {
            rustix::fs::fchown(file, Some(rustix::fs::Uid::ROOT), None).map_err(|_| FAILED)?;
            rustix::fs::fchmod(file, Mode::from_raw_mode(0o600)).map_err(|_| FAILED)?;
            if !super::valid_created(metadata(file)?) {
                return Err(FAILED);
            }
        }
        Ok(())
    }
    fn cleanup_failed_create(&mut self) {
        if !self.created {
            return;
        }
        let (Some(file), Some(directory)) = (&self.file, &self.directory) else {
            return;
        };
        let Ok(opened) = rustix::fs::fstat(file) else {
            return;
        };
        let Ok(named) = rustix::fs::statat(
            directory,
            filename(self.copy),
            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        ) else {
            return;
        };
        if opened.st_dev != named.st_dev || opened.st_ino != named.st_ino {
            return;
        }
        // Qualification records the stage's bytes before mandatory cleanup changes
        // the externally visible state to Missing. This never suppresses cleanup.
        #[cfg(feature = "qualification")]
        if let Ok(mut failure) = self.failure.lock() {
            *failure = Some((opened.st_size.cast_unsigned(), read(&self.path, self.copy)));
        }
        if rustix::fs::unlinkat(directory, filename(self.copy), rustix::fs::AtFlags::empty())
            .is_ok()
        {
            let _ = scupper_darwin::full_sync(directory);
        }
    }
    fn stat(&mut self) -> Result<Metadata, SysError> {
        metadata(self.file.as_ref().ok_or(FAILED)?)
    }
    fn preallocate(&mut self) -> Result<(), SysError> {
        scupper_darwin::preallocate(
            self.file.as_ref().ok_or(FAILED)?,
            i64::try_from(COPY_BYTES).map_err(|_| FAILED)?,
        )
        .map_err(|_| FAILED)
    }
    fn pwrite(&mut self, bytes: &[u8]) -> Result<usize, SysError> {
        self.file
            .as_ref()
            .ok_or(FAILED)?
            .write_at(bytes, 0)
            .map_err(|_| FAILED)
    }
    fn full_sync(&mut self, directory: bool) -> Result<(), SysError> {
        let file = if directory {
            &self.directory
        } else {
            &self.file
        };
        scupper_darwin::full_sync(file.as_ref().ok_or(FAILED)?).map_err(|_| FAILED)
    }
}
#[cfg(feature = "qualification")]
type FailureObservation = std::sync::Arc<std::sync::Mutex<Option<(u64, CopyRead)>>>;

/// Adapter state; no hooks or pause gates exist in a non-qualification build.
#[derive(Default)]
pub(crate) struct Storage {
    workers: Workers,
    #[cfg(feature = "qualification")]
    pub(crate) fault: Fault,
    #[cfg(feature = "qualification")]
    pub(crate) read_gate: Option<std::sync::mpsc::Receiver<()>>,
    #[cfg(feature = "qualification")]
    pub(crate) write_gate: Option<std::sync::mpsc::Receiver<()>>,
    #[cfg(feature = "qualification")]
    failure: FailureObservation,
}
fn remaining(deadline: Deadline) -> impl Fn() -> Duration {
    move || Duration::from_secs(deadline.0).saturating_sub(scupper_darwin::monotonic_raw())
}
impl Storage {
    #[cfg(feature = "qualification")]
    pub(crate) fn take_failed_create(&mut self) -> Option<(u64, CopyRead)> {
        self.failure.lock().ok()?.take()
    }
    #[cfg(feature = "qualification")]
    pub(crate) fn readers_idle(&self) -> bool {
        self.workers.readers_idle()
    }
    pub(crate) fn poll(
        &mut self,
        path: PathBuf,
        copy: Copy,
        deadline: Deadline,
    ) -> std::task::Poll<CopyRead> {
        #[cfg(feature = "qualification")]
        let gate = if self.workers.can_start_read() && !remaining(deadline)().is_zero() {
            self.read_gate.take()
        } else {
            None
        };
        self.workers.poll_copy(copy, remaining(deadline), move || {
            #[cfg(feature = "qualification")]
            if let Some(gate) = gate {
                let _ = gate.recv();
            }
            read(&path, copy)
        })
    }
    pub(crate) fn abandon(&mut self) {
        self.workers.abandon();
    }
    pub(crate) fn wait(&mut self, deadline: Deadline) -> WriteOutcome {
        self.workers.wait_write(remaining(deadline))
    }
    pub(crate) fn start(
        &mut self,
        path: PathBuf,
        copy: Copy,
        bytes: &[u8; COPY_BYTES],
        create: bool,
        deadline: Deadline,
    ) -> WriteOutcome {
        #[cfg(feature = "qualification")]
        let fault = self.fault.take();
        #[cfg(not(feature = "qualification"))]
        let fault = Fault::None;
        #[cfg(feature = "qualification")]
        let gate = self.write_gate.take();
        #[cfg(feature = "qualification")]
        let failure = self.failure.clone();
        let bytes = *bytes;
        self.workers.start_write(remaining(deadline), move || {
            #[cfg(feature = "qualification")]
            if let Some(gate) = gate {
                let _ = gate.recv();
            }
            write(
                &mut DescriptorIo {
                    path,
                    copy,
                    directory: None,
                    file: None,
                    created: false,
                    #[cfg(feature = "qualification")]
                    failure,
                },
                create,
                &bytes,
                fault,
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Remove(PathBuf);
    impl Drop for Remove {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    #[test]
    fn cleanup_unlinks_only_the_exclusively_created_inode() -> Result<(), Box<dyn std::error::Error>>
    {
        let path = std::env::current_dir()?.join("target").join(format!(
            "cleanup-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos()
        ));
        std::fs::create_dir_all(&path)?;
        let _remove = Remove(path.clone());
        let name = path.join(filename(Copy::A));
        let make = |created| -> Result<DescriptorIo, std::io::Error> {
            Ok(DescriptorIo {
                path: path.clone(),
                copy: Copy::A,
                directory: Some(File::open(&path)?),
                file: Some(File::create(&name)?),
                created,
                #[cfg(feature = "qualification")]
                failure: FailureObservation::default(),
            })
        };
        let mut io = make(false)?;
        io.cleanup_failed_create();
        assert!(name.exists()); // An existing-copy failure cannot remove anything.
        let mut io = make(true)?;
        io.cleanup_failed_create();
        assert!(!name.exists());
        let mut io = make(true)?;
        let moved = path.join("moved");
        std::fs::rename(&name, &moved)?;
        std::fs::write(&name, b"replacement")?;
        io.cleanup_failed_create();
        assert_eq!(std::fs::read(&name)?, b"replacement");
        assert!(moved.exists());
        std::fs::remove_file(&name)?;
        std::os::unix::fs::symlink(&moved, &name)?;
        io.cleanup_failed_create();
        assert!(std::fs::symlink_metadata(&name)?.is_symlink());
        assert!(moved.exists());
        Ok(())
    }

    #[cfg(feature = "qualification")]
    #[test]
    fn polling_pending_read_preserves_the_next_read_gate() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut storage = Storage::default();
        let (first_tx, first_rx) = std::sync::mpsc::channel();
        let (next_tx, next_rx) = std::sync::mpsc::channel();
        let d = || Deadline(scupper_darwin::monotonic_raw().as_secs() + 1);
        storage.read_gate = Some(first_rx);
        assert_eq!(
            storage.poll("/".into(), Copy::A, d()),
            std::task::Poll::Pending
        );
        storage.read_gate = Some(next_rx);
        assert_eq!(
            storage.poll("/".into(), Copy::A, d()),
            std::task::Poll::Pending
        );
        assert!(storage.read_gate.is_some());
        first_tx.send(())?;
        assert!(matches!(
            storage.poll("/".into(), Copy::A, d()),
            std::task::Poll::Ready(_)
        ));
        assert!(storage.read_gate.is_some());
        assert_eq!(
            storage.poll("/".into(), Copy::B, d()),
            std::task::Poll::Pending
        );
        assert!(storage.read_gate.is_none());
        next_tx.send(())?;
        assert!(matches!(
            storage.poll("/".into(), Copy::B, d()),
            std::task::Poll::Ready(_)
        ));
        Ok(())
    }
}
