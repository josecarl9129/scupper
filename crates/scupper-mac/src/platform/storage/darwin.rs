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
}
impl Io for DescriptorIo {
    fn open(&mut self, create: bool) -> Result<(), SysError> {
        let directory = root(&self.path).map_err(|_| FAILED)?;
        let mut flags = OFlags::WRONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
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
        if create && file.metadata().map_err(|_| FAILED)?.uid() != 0 {
            rustix::fs::fchown(&file, Some(rustix::fs::Uid::ROOT), None).map_err(|_| FAILED)?;
        }
        self.directory = Some(directory);
        self.file = Some(file);
        Ok(())
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
}
fn remaining(deadline: Deadline) -> impl Fn() -> Duration {
    move || Duration::from_secs(deadline.0).saturating_sub(scupper_darwin::monotonic_raw())
}
impl Storage {
    pub(crate) fn poll(
        &mut self,
        path: PathBuf,
        copy: Copy,
        deadline: Deadline,
    ) -> std::task::Poll<CopyRead> {
        #[cfg(feature = "qualification")]
        let gate = self.read_gate.take();
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
                },
                create,
                &bytes,
                fault,
            )
        })
    }
}
