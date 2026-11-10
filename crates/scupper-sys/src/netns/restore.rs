//! Restore decisions use mountinfo as well as the visible namespace identity.
use super::{NetnsError, NetnsHandle, NetnsId, mountinfo};
use rustix::{
    fs::{FileType, Mode, OFlags, fstat, open},
    mount::{
        MountPropagationFlags, UnmountFlags, mount_bind, mount_bind_recursive, mount_change,
        unmount,
    },
};
use std::{
    fs::{self, OpenOptions},
    io,
    os::{
        fd::{AsRawFd, OwnedFd},
        unix::{fs::MetadataExt, fs::OpenOptionsExt},
    },
    path::{Path, PathBuf},
};

#[derive(Debug, PartialEq, Eq)]
enum Action {
    Keep,
    Bind,
    DetachThenBind,
}

fn decision(mounts: usize, identity: Option<NetnsId>, held: NetnsId) -> Result<Action, NetnsError> {
    match (mounts, identity == Some(held)) {
        (0, false) => Ok(Action::Bind),
        (1, true) => Ok(Action::Keep),
        (1, false) => Ok(Action::DetachThenBind),
        (_, held_inode) => Err(NetnsError::MountEscalation { mounts, held_inode }),
    }
}

fn state(path: &Path) -> Result<(usize, Option<NetnsId>), NetnsError> {
    let identity = match fs::symlink_metadata(path) {
        Ok(stat) if stat.is_file() && !stat.file_type().is_symlink() => {
            Some((stat.dev(), stat.ino()))
        }
        Ok(_) => return Err(io::Error::other("unsafe namespace mount point").into()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    Ok((
        mountinfo::count(&mountinfo::read("/proc/self/mountinfo")?, path)?,
        identity,
    ))
}

fn verify_restored(
    mounts: usize,
    identity: Option<NetnsId>,
    held: NetnsId,
) -> Result<(), NetnsError> {
    if mounts == 1 && identity == Some(held) {
        Ok(())
    } else {
        Err(NetnsError::MountEscalation {
            mounts,
            held_inode: identity == Some(held),
        })
    }
}

// Match iproute2's directory setup: make it recursively shared, with a
// recursive self-bind on EINVAL only. Serialize setup against ip netns add.
fn shared_parent(parent: &Path) -> Result<(), NetnsError> {
    let directory = open(
        parent,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    rustix::fs::flock(&directory, rustix::fs::FlockOperation::LockExclusive)?;
    let flags = MountPropagationFlags::SHARED | MountPropagationFlags::REC;
    match mount_change(parent, flags) {
        Ok(()) => {}
        Err(rustix::io::Errno::INVAL) => {
            mount_bind_recursive(parent, parent)?;
            mount_change(
                parent,
                MountPropagationFlags::PRIVATE | MountPropagationFlags::REC,
            )?;
            mount_change(parent, flags)?;
        }
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn target_fd(path: &Path) -> Result<OwnedFd, NetnsError> {
    let fd = open(
        path,
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    if FileType::from_raw_mode(fstat(&fd)?.st_mode) != FileType::RegularFile {
        return Err(io::Error::other("unsafe namespace mount point").into());
    }
    Ok(fd)
}

fn fd_path(fd: &OwnedFd) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", fd.as_raw_fd()))
}

/// Rebind a missing or hijacked name to the original held namespace descriptor.
/// The caller must hold the writer lock. An existing single mount of the held
/// inode is left alone; any foreign mount is detached before binding.
///
/// scupperd must share the host's `/run/netns` mount propagation. A successful
/// local readback cannot prove visibility in a private mount tree. After stopping
/// scupperd, one `ip netns delete scupper` must detach the sole mount and unlink
/// the name. While scupperd runs it restores that name on the next audit.
///
/// # Errors
/// Returns identity, unsafe mount-point, mountinfo, detach or bind failures.
/// Unexpected mount counts or a wrong post-bind inode require escalation.
pub fn restore_mount(
    held: &NetnsHandle,
    path: &Path,
    _writer: &crate::lock::WriterGuard,
) -> Result<(), NetnsError> {
    held.verify(held.identity())?;
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("namespace mount point has no parent"))?;
    fs::create_dir_all(parent)?;
    // mountinfo uses resolved paths, including when the caller uses /var/run.
    let path = fs::canonicalize(parent)?.join(
        path.file_name()
            .ok_or_else(|| io::Error::other("namespace mount point has no name"))?,
    );
    let (mounts, identity) = state(&path)?;
    match decision(mounts, identity, held.identity())? {
        Action::Keep => return Ok(()),
        Action::DetachThenBind => unmount(&path, UnmountFlags::DETACH)?,
        Action::Bind => {}
    }
    // Re-read after detach: never bind on a mount exposed underneath a hijack.
    shared_parent(
        path.parent()
            .ok_or_else(|| io::Error::other("namespace mount point has no parent"))?,
    )?;
    let (mounts, identity) = state(&path)?;
    if mounts != 0 || identity == Some(held.identity()) {
        return Err(NetnsError::MountEscalation {
            mounts,
            held_inode: identity == Some(held.identity()),
        });
    }
    if identity.is_none() {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(OFlags::NOFOLLOW.bits().cast_signed())
            .mode(0o600)
            .open(&path)?;
    }
    // Pin the final component. A replacement symlink cannot redirect mount(2).
    let target = target_fd(&path)?;
    let stat = fstat(&target)?;
    let (mounts, identity) = state(&path)?;
    if mounts != 0
        || identity == Some(held.identity())
        || identity != Some((stat.st_dev, stat.st_ino))
    {
        return Err(NetnsError::MountEscalation {
            mounts,
            held_inode: identity == Some(held.identity()),
        });
    }
    let target_path = fd_path(&target);
    mount_bind(held.child_fd_path().as_path(), &target_path)?;
    // Inspect a fresh descriptor at the name: the original O_PATH descriptor
    // continues to refer to the underlying file after the bind.
    let restored = target_fd(&path)?;
    let stat = fstat(&restored)?;
    let mounts = mountinfo::count(&mountinfo::read("/proc/self/mountinfo")?, &path)?;
    verify_restored(mounts, Some((stat.st_dev, stat.st_ino)), held.identity())
}

#[cfg(test)]
mod tests {
    use super::*;

    const HELD: NetnsId = (4, 42);

    #[test]
    fn restore_decisions_distinguish_mounts_from_visible_inodes() -> Result<(), NetnsError> {
        assert_eq!(decision(0, None, HELD)?, Action::Bind);
        assert_eq!(decision(0, Some((1, 2)), HELD)?, Action::Bind);
        assert!(matches!(
            decision(0, Some(HELD), HELD),
            Err(NetnsError::MountEscalation {
                mounts: 0,
                held_inode: true
            })
        ));
        assert_eq!(decision(1, Some(HELD), HELD)?, Action::Keep);
        assert_eq!(decision(1, Some((4, 43)), HELD)?, Action::DetachThenBind);
        // Even a mount of another filesystem must be detached before binding.
        assert_eq!(decision(1, Some((5, 43)), HELD)?, Action::DetachThenBind);
        for identity in [None, Some(HELD), Some((4, 43))] {
            assert!(matches!(
                decision(2, identity, HELD),
                Err(NetnsError::MountEscalation { mounts: 2, .. })
            ));
        }
        Ok(())
    }

    #[test]
    fn target_descriptor_pins_the_file_and_rejects_replacement_symlinks()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir =
            std::env::current_dir()?.join(format!("target/restore-target-{}", std::process::id()));
        fs::create_dir_all(&dir)?;
        let path = dir.join("name");
        fs::write(&path, b"target")?;
        let target = target_fd(&path)?;
        let before = fstat(&target)?;
        fs::rename(&path, dir.join("pinned"))?;
        fs::write(dir.join("other"), b"other")?;
        std::os::unix::fs::symlink(dir.join("other"), &path)?;
        assert!(target_fd(&path).is_err());
        let pinned = fs::metadata(fd_path(&target))?;
        assert_eq!((pinned.dev(), pinned.ino()), (before.st_dev, before.st_ino));
        assert_ne!(fs::metadata(&path)?.ino(), before.st_ino);
        fs::remove_file(&path)?;
        fs::create_dir(&path)?;
        assert!(target_fd(&path).is_err());
        fs::remove_dir_all(dir)?;
        Ok(())
    }

    #[test]
    fn readback_requires_exactly_one_mount_and_the_held_inode() {
        assert!(verify_restored(1, Some(HELD), HELD).is_ok());
        for mounts in [0, 1, 2, 3] {
            for identity in [None, Some(HELD), Some((4, 43))] {
                assert_eq!(
                    verify_restored(mounts, identity, HELD).is_ok(),
                    mounts == 1 && identity == Some(HELD)
                );
            }
        }
    }
}
