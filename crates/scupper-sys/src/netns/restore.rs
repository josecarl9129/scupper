//! Restore decisions use mountinfo as well as the visible namespace identity.
use super::{NetnsError, NetnsHandle, NetnsId, mountinfo};
use rustix::{
    fs::{FileType, FlockOperation, Mode, OFlags, flock, fstat, open},
    mount::{UnmountFlags, mount_bind, unmount},
};
use std::{
    fs::{self, OpenOptions},
    io,
    os::{
        fd::{AsFd, AsRawFd, OwnedFd},
        unix::{fs::MetadataExt, fs::OpenOptionsExt},
    },
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

fn direct_source(link: &Path, held: NetnsId) -> bool {
    link == Path::new(&format!("net:[{}]", held.1))
}

// A descriptor opened through a deleted bind mount retains that mount's
// MNT_UMOUNT state. Older kernels copy it into a new bind and later strip its
// shared peers during unmount. Obtain a source on the internal nsfs mount.
fn bind_source(held: &NetnsHandle, deadline: Instant) -> Result<OwnedFd, NetnsError> {
    if direct_source(&fs::read_link(held.fd_path())?, held.identity()) {
        return Ok(held.try_clone_file()?.into());
    }
    let file = held.try_clone_file()?;
    let identity = held.identity();
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("netns-bind-source".into())
        .spawn(move || {
            let result = (|| -> Result<OwnedFd, NetnsError> {
                // Network setns is per-thread. Never change the caller's network
                // namespace, or enter/unshare a mount namespace here.
                rustix::thread::move_into_link_name_space(
                    file.as_fd(),
                    Some(rustix::thread::LinkNameSpaceType::Network),
                )?;
                // /proc/self/ns/net would refer to the process leader instead.
                let source = open(
                    "/proc/thread-self/ns/net",
                    OFlags::RDONLY | OFlags::CLOEXEC,
                    Mode::empty(),
                )?;
                let stat = fstat(&source)?;
                if (stat.st_dev, stat.st_ino) != identity
                    || !direct_source(&fs::read_link(fd_path(&source))?, identity)
                {
                    return Err(NetnsError::IdentityMismatch);
                }
                Ok(source)
            })();
            let _ = sender.send(result);
        })?;
    receiver
        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .map_err(|error| io::Error::new(io::ErrorKind::TimedOut, error))?
}

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

fn propagation_ready(info: &str, parent: &Path) -> Result<(), NetnsError> {
    if !mountinfo::is_shared(info, parent)? {
        return Err(io::Error::other(
            "namespace parent mount is not shared; operator setup required",
        )
        .into());
    }
    Ok(())
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

// Serialize against ip netns add, without changing any mount's propagation.
fn lock_parent(parent: &Path, deadline: Instant) -> Result<OwnedFd, NetnsError> {
    let directory = open(
        parent,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    loop {
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "namespace directory lock timeout",
            )
            .into());
        }
        match flock(&directory, FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => return Ok(directory),
            Err(rustix::io::Errno::WOULDBLOCK | rustix::io::Errno::INTR) => {
                std::thread::sleep(
                    Duration::from_millis(5)
                        .min(deadline.saturating_duration_since(Instant::now())),
                );
            }
            Err(error) => return Err(error.into()),
        }
    }
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
/// Restore requires an already shared parent mount and never changes propagation.
///
/// # Errors
/// Returns identity, unsafe mount-point, mountinfo, detach or bind failures.
/// Unexpected mount counts or a wrong post-bind inode require escalation.
pub fn restore_mount(
    held: &NetnsHandle,
    path: &Path,
    writer: &crate::lock::WriterGuard,
) -> Result<(), NetnsError> {
    restore_mount_until(
        held,
        path,
        writer,
        Instant::now() + Duration::from_millis(100),
    )
}

/// Restore a namespace name with directory-lock retries bounded by `deadline`
/// and a 100 ms maximum wait. Existing mount propagation is never changed.
///
/// # Errors
/// Returns the same errors as [`restore_mount`], including lock timeout.
pub fn restore_mount_until(
    held: &NetnsHandle,
    path: &Path,
    _writer: &crate::lock::WriterGuard,
    deadline: Instant,
) -> Result<(), NetnsError> {
    let lock_deadline = deadline.min(Instant::now() + Duration::from_millis(100));
    held.verify(held.identity())?;
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("namespace mount point has no parent"))?;
    fs::create_dir_all(parent)?;
    // mountinfo uses resolved paths, including when the caller uses /var/run.
    let parent = fs::canonicalize(parent)?;
    let path = parent.join(
        path.file_name()
            .ok_or_else(|| io::Error::other("namespace mount point has no name"))?,
    );
    let _directory = lock_parent(&parent, lock_deadline)?;
    let (mounts, identity) = state(&path)?;
    let action = decision(mounts, identity, held.identity())?;
    if action == Action::Keep {
        return Ok(());
    }
    propagation_ready(&mountinfo::read("/proc/self/mountinfo")?, &parent)?;
    let source = bind_source(held, deadline)?;
    if action == Action::DetachThenBind {
        unmount(&path, UnmountFlags::DETACH | UnmountFlags::NOFOLLOW)?;
    }
    // Re-read after detach: never bind on a mount exposed underneath a hijack.
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
    if Instant::now() >= deadline {
        return Err(io::Error::new(io::ErrorKind::TimedOut, "namespace restore timeout").into());
    }
    mount_bind(fd_path(&source), &target_path)?;
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
    fn bind_source_decision_rejects_named_and_lazily_detached_mounts() {
        assert!(direct_source(Path::new("net:[42]"), HELD));
        for path in [
            "/run/netns/scupper",
            "/run/netns/scupper (deleted)",
            "/proc/123/fd/4",
            "net:[43]",
            "mnt:[42]",
        ] {
            assert!(!direct_source(Path::new(path), HELD), "{path}");
        }
    }

    #[test]
    fn direct_bind_source_keeps_identity_and_cloexec() -> Result<(), NetnsError> {
        let held = NetnsHandle::open_network("/proc/self/ns/net")?;
        let identity = held.identity();
        let source = bind_source(&held, Instant::now() + Duration::from_secs(1))?;
        drop(held);
        let stat = fstat(&source)?;
        assert_eq!((stat.st_dev, stat.st_ino), identity);
        assert!(direct_source(&fs::read_link(fd_path(&source))?, identity));
        assert!(rustix::io::fcntl_getfd(&source)?.contains(rustix::io::FdFlags::CLOEXEC));
        Ok(())
    }

    #[test]
    fn propagation_decision_requires_existing_shared_parent() -> Result<(), NetnsError> {
        let shared = "1 0 0:1 / / rw - tmpfs tmpfs rw\n\
            2 1 0:1 /netns /run/netns rw shared:12 - tmpfs tmpfs rw\n\
            3 2 0:5 net:[42] /run/netns/scupper rw shared:418 - nsfs nsfs rw\n";
        let parent = Path::new("/run/netns");
        propagation_ready(shared, parent)?;
        // A shared child cannot make its private parent suitable for restore.
        assert!(propagation_ready(&shared.replace("shared:12", ""), parent).is_err());
        // A private child must not cause restore to rewrite propagation.
        propagation_ready(&shared.replace("shared:418", ""), parent)?;
        let hidden = format!("{shared}4 2 0:1 / /run/netns rw - tmpfs tmpfs rw\n");
        assert!(propagation_ready(&hidden, parent).is_err());
        assert!(propagation_ready("invalid", parent).is_err());
        Ok(())
    }

    #[test]
    fn directory_lock_contention_and_expired_deadline_are_bounded()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir =
            std::env::current_dir()?.join(format!("target/restore-lock-{}", std::process::id()));
        fs::create_dir_all(&dir)?;
        let held = lock_parent(&dir, Instant::now() + Duration::from_secs(1))?;
        let started = Instant::now();
        let error = lock_parent(&dir, started + Duration::from_millis(20)).unwrap_err();
        assert!(
            matches!(error, NetnsError::Proc(error) if error.kind() == io::ErrorKind::TimedOut)
        );
        assert!(started.elapsed() < Duration::from_secs(1));
        drop(held);
        assert!(lock_parent(&dir, Instant::now()).is_err());
        drop(lock_parent(&dir, Instant::now() + Duration::from_secs(1))?);
        fs::remove_dir_all(dir)?;
        Ok(())
    }

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
