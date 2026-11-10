//! Restore decisions use mountinfo as well as the visible namespace identity.
use super::{NetnsError, NetnsHandle, NetnsId};
use rustix::{
    fs::OFlags,
    mount::{MountFlags, UnmountFlags, mount, unmount},
};
use std::{
    fs::{self, OpenOptions},
    io,
    os::unix::{ffi::OsStrExt, fs::MetadataExt, fs::OpenOptionsExt},
    path::Path,
};

#[derive(Debug, PartialEq, Eq)]
enum Action {
    Keep,
    Bind,
    DetachThenBind,
}

fn decision(mounts: usize, identity: Option<NetnsId>, held: NetnsId) -> Result<Action, NetnsError> {
    match (mounts, identity == Some(held)) {
        (0, _) => Ok(Action::Bind),
        (1, true) => Ok(Action::Keep),
        (1, false) => Ok(Action::DetachThenBind),
        (_, held_inode) => Err(NetnsError::MountEscalation { mounts, held_inode }),
    }
}

// Compare the escaped mountinfo field byte-for-byte.
fn mount_count(mountinfo: &str, path: &Path) -> io::Result<usize> {
    let mut escaped = Vec::new();
    for byte in path.as_os_str().as_bytes() {
        match byte {
            b' ' => escaped.extend_from_slice(b"\\040"),
            b'\t' => escaped.extend_from_slice(b"\\011"),
            b'\n' => escaped.extend_from_slice(b"\\012"),
            b'\\' => escaped.extend_from_slice(b"\\134"),
            byte => escaped.push(*byte),
        }
    }
    mountinfo.lines().try_fold(0, |count, line| {
        let point = line
            .split_whitespace()
            .nth(4)
            .ok_or_else(|| io::Error::other("malformed namespace mountinfo"))?;
        Ok(count + usize::from(point.as_bytes() == escaped))
    })
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
        mount_count(&fs::read_to_string("/proc/self/mountinfo")?, path)?,
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
    let (mounts, identity) = state(&path)?;
    if mounts != 0 {
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
    mount(
        held.child_fd_path().as_path(),
        &path,
        "",
        MountFlags::BIND,
        None::<&std::ffi::CStr>,
    )?;
    let (mounts, identity) = state(&path)?;
    verify_restored(mounts, identity, held.identity())
}

#[cfg(test)]
mod tests {
    use super::*;

    const HELD: NetnsId = (4, 42);

    #[test]
    fn restore_decisions_distinguish_mounts_from_visible_inodes() -> Result<(), NetnsError> {
        assert_eq!(decision(0, None, HELD)?, Action::Bind);
        assert_eq!(decision(0, Some((1, 2)), HELD)?, Action::Bind);
        assert_eq!(decision(0, Some(HELD), HELD)?, Action::Bind);
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

    #[test]
    fn mountinfo_counts_exact_paths_and_hidden_stacked_mounts() -> io::Result<()> {
        let info = "11 1 0:1 / /run/netns rw shared:1 - tmpfs tmpfs rw\n\
                    12 11 0:4 net:[42] /run/netns/scupper rw - nsfs nsfs rw\n\
                    13 11 0:4 net:[43] /run/netns/scupper rw - nsfs nsfs rw\n\
                    14 11 0:4 net:[44] /run/netns/scupper-other rw - nsfs nsfs rw\n\
                    15 11 0:4 net:[45] /run/netns/a\\040b\\134c rw - nsfs nsfs rw\n";
        assert_eq!(mount_count(info, Path::new("/run/netns/scupper"))?, 2);
        assert_eq!(mount_count(info, Path::new("/run/netns/scupper-other"))?, 1);
        assert_eq!(mount_count(info, Path::new("/run/netns/missing"))?, 0);
        assert_eq!(mount_count(info, Path::new("/run/netns/a b\\c"))?, 1);
        assert!(mount_count("invalid", Path::new("/run/netns/scupper")).is_err());
        Ok(())
    }
}
