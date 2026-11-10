//! Held namespace identities, independent of mutable namespace names.

use rustix::fs::{Mode, OFlags, fstat, open};
use std::os::unix::fs::MetadataExt;
use std::{
    fs::File,
    os::fd::AsRawFd,
    path::{Path, PathBuf},
};
use thiserror::Error;

pub mod mountinfo;
mod restore;
pub use restore::{restore_mount, restore_mount_until};

/// Failure to open, identify or restore a namespace, without retaining its path.
#[derive(Debug, Error)]
pub enum NetnsError {
    /// An open or stat operation failed.
    #[error("namespace I/O error: {0}")]
    Io(#[from] rustix::io::Errno),
    /// The descriptor does not belong to nsfs.
    #[error("namespace descriptor is not an nsfs file")]
    NotNsfs,
    /// The descriptor is another namespace type.
    #[error("descriptor is not a network namespace")]
    NotNetworkNamespace,
    /// A host namespace must never be a gateway target.
    #[error("refusing host network namespace")]
    IsHostNamespace,
    /// The held or procfs identity differs from the recorded identity.
    #[error("network namespace identity mismatch")]
    IdentityMismatch,
    /// A procfs read or stat failed.
    #[error("namespace procfs I/O error: {0}")]
    Proc(#[from] std::io::Error),
    /// A namespace name has an unexpected mount count or identity after restore.
    #[error("namespace restore escalation: mounts={mounts}, held_inode={held_inode}")]
    MountEscalation {
        /// Number of mounts on the namespace name.
        mounts: usize,
        /// Whether the visible inode is the held namespace.
        held_inode: bool,
    },
}

/// Stable namespace device/inode identity, suitable for a boot record.
pub type NetnsId = (u64, u64);

/// Owns a foreign network namespace descriptor and its device/inode identity.
///
/// Execution assumes `/proc` belongs to this process's PID namespace and the
/// process remains dumpable or holds `CAP_SYS_PTRACE` (`READ_FSCREDS` access).
/// nsenter changes only the network namespace: commands must never use `/sys`
/// to inspect network devices, because it still describes the host.
#[derive(Debug)]
pub struct NetnsHandle {
    file: File,
    dev: u64,
    ino: u64,
}

impl NetnsHandle {
    /// Opens a foreign network namespace, rejecting both caller and PID 1.
    ///
    /// # Errors
    /// Rejects non-network descriptors, host identities and I/O failures.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, NetnsError> {
        Self::open_expected(path, None)
    }

    /// Opens a foreign network namespace and checks an optional boot identity.
    /// All validation uses the opened descriptor, independent of name replacement.
    ///
    /// # Errors
    /// Rejects non-network descriptors, host identities and identity mismatches.
    pub fn open_expected(
        path: impl AsRef<Path>,
        expected: Option<NetnsId>,
    ) -> Result<Self, NetnsError> {
        let handle = Self::open_network(path)?;
        handle.verify(expected.unwrap_or_else(|| handle.identity()))?;
        Ok(handle)
    }

    /// Validates an inherited descriptor against a recorded foreign namespace.
    ///
    /// # Errors
    /// Rejects non-network descriptors, host namespaces and identity mismatches.
    pub fn from_file(file: File, expected: NetnsId) -> Result<Self, NetnsError> {
        let stat = fstat(&file)?;
        let reference = std::fs::metadata("/proc/self/ns/net")?;
        if stat.st_dev != reference.dev() {
            return Err(NetnsError::NotNsfs);
        }
        let handle = Self {
            file,
            dev: stat.st_dev,
            ino: stat.st_ino,
        };
        if let Ok(target) = std::fs::read_link(handle.fd_path())
            && !target.to_string_lossy().starts_with("net:")
            && target.to_string_lossy().contains(":[")
        {
            return Err(NetnsError::NotNetworkNamespace);
        }
        handle.verify(expected)?;
        Ok(handle)
    }

    /// Duplicates the held descriptor without changing its CLOEXEC flags.
    ///
    /// # Errors
    /// Returns a descriptor duplication error.
    pub fn try_clone_file(&self) -> std::io::Result<File> {
        self.file.try_clone()
    }

    fn open_network(path: impl AsRef<Path>) -> Result<Self, NetnsError> {
        let file = open(
            path.as_ref(),
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK | OFlags::NOCTTY,
            Mode::empty(),
        )?;
        let reference = std::fs::metadata("/proc/self/ns/net")?;
        let stat = fstat(&file)?;
        if stat.st_dev != reference.dev() {
            return Err(NetnsError::NotNsfs);
        }
        let handle = Self {
            file: file.into(),
            dev: stat.st_dev,
            ino: stat.st_ino,
        };
        // A `/proc/<pid>/ns/<type>` link names its type; a bind-mounted namespace file
        // (`/run/netns/<name>`) is not a link and its fd path shows the mount path. In
        // that case the type is enforced at every exec: nsenter's `--net` performs
        // setns(fd, CLONE_NEWNET), which fails for any other namespace type.
        if let Ok(target) = std::fs::read_link(path.as_ref())
            && target != Path::new(&format!("net:[{}]", handle.ino))
        {
            return Err(NetnsError::NotNetworkNamespace);
        }
        handle.verify_link(&handle.fd_path())?;
        Ok(handle)
    }

    fn verify_link(&self, path: &Path) -> Result<(), NetnsError> {
        let stat = std::fs::metadata(path)?;
        if (stat.dev(), stat.ino()) != self.identity() {
            return Err(NetnsError::IdentityMismatch);
        }
        Ok(())
    }

    /// Checks the recorded identity and the exact procfs path nsenter will open.
    /// Re-checks host identities so a test fixture or changed procfs cannot bypass it.
    ///
    /// # Errors
    /// Rejects host identities, changed descriptors and inaccessible procfs paths.
    pub fn verify(&self, expected: NetnsId) -> Result<(), NetnsError> {
        if !self.same_as(expected) {
            return Err(NetnsError::IdentityMismatch);
        }
        self.verify_link(&self.child_fd_path())?;
        for path in ["/proc/self/ns/net", "/proc/1/ns/net"] {
            match std::fs::metadata(path) {
                Ok(stat) if (stat.dev(), stat.ino()) == self.identity() => {
                    return Err(NetnsError::IsHostNamespace);
                }
                Err(error) if path == "/proc/self/ns/net" => return Err(error.into()),
                _ => {}
            }
        }
        Ok(())
    }

    /// Returns the namespace's device and inode.
    #[must_use]
    pub const fn identity(&self) -> NetnsId {
        (self.dev, self.ino)
    }

    /// Whether another recorded identity refers to this namespace.
    #[must_use]
    pub fn same_as(&self, other: NetnsId) -> bool {
        self.identity() == other
    }

    /// Inspection path in this process only; exec uses a parent-qualified path.
    #[must_use]
    pub fn fd_path(&self) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", self.file.as_raw_fd()))
    }

    #[cfg(test)]
    pub(crate) fn raw_fd(&self) -> std::os::fd::RawFd {
        self.file.as_raw_fd()
    }

    /// Parent-qualified path for root nsenter children. No descriptor inheritance
    /// or process-wide CLOEXEC changes are needed; the borrowed handle stays open
    /// until the bounded exec returns. `/proc` must belong to this process's PID
    /// namespace. The process must remain dumpable or hold `CAP_SYS_PTRACE` for
    /// procfs ptrace `READ_FSCREDS` access. Only the network namespace is entered:
    /// future commands must not inspect host network devices through `/sys`.
    pub(crate) fn child_fd_path(&self) -> PathBuf {
        PathBuf::from(format!(
            "/proc/{}/fd/{}",
            std::process::id(),
            self.file.as_raw_fd()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn namespace_identity_and_cloexec() -> Result<(), Box<dyn Error>> {
        let first = NetnsHandle::open_network("/proc/self/ns/net")?;
        let second = NetnsHandle::open_network("/proc/self/ns/net")?;
        assert!(first.same_as(second.identity()));
        assert!(!first.same_as((0, 0)));
        assert_eq!(
            std::fs::metadata(first.fd_path())?.ino(),
            first.identity().1
        );
        assert!(rustix::io::fcntl_getfd(&first.file)?.contains(rustix::io::FdFlags::CLOEXEC));
        Ok(())
    }

    #[test]
    fn rejects_host_other_namespaces_and_wrong_recorded_identity() -> Result<(), Box<dyn Error>> {
        assert!(matches!(
            NetnsHandle::open("/proc/self/ns/net"),
            Err(NetnsError::IsHostNamespace)
        ));
        if let Ok(stat) = std::fs::metadata("/proc/1/ns/net") {
            assert!(matches!(
                NetnsHandle::open("/proc/1/ns/net"),
                Err(NetnsError::IsHostNamespace)
            ));
            assert!(stat.ino() > 0);
        }
        for kind in ["mnt", "pid", "user", "uts", "ipc", "cgroup", "time"] {
            let path = format!("/proc/self/ns/{kind}");
            if std::fs::metadata(&path).is_ok() {
                assert!(
                    matches!(
                        NetnsHandle::open(&path),
                        Err(NetnsError::NotNetworkNamespace)
                    ),
                    "{kind}"
                );
            }
        }
        assert!(matches!(
            NetnsHandle::open_expected("/proc/self/ns/net", Some((0, 0))),
            Err(NetnsError::IdentityMismatch)
        ));
        let mut handle = NetnsHandle::open_network("/proc/self/ns/net")?;
        assert!(matches!(
            handle.verify((0, 0)),
            Err(NetnsError::IdentityMismatch)
        ));
        assert!(matches!(
            handle.verify(handle.identity()),
            Err(NetnsError::IsHostNamespace)
        ));
        handle.dev ^= 1;
        assert!(matches!(
            handle.verify(handle.identity()),
            Err(NetnsError::IdentityMismatch)
        ));
        Ok(())
    }

    #[test]
    fn planted_fifo_does_not_block_open() -> Result<(), Box<dyn Error>> {
        let path = std::env::temp_dir().join(format!("netns-fifo-{}", std::process::id()));
        assert!(
            std::process::Command::new("/usr/bin/mkfifo")
                .arg(&path)
                .status()?
                .success()
        );
        let started = std::time::Instant::now();
        let result = NetnsHandle::open(&path);
        std::fs::remove_file(&path)?;
        assert!(matches!(result, Err(NetnsError::NotNsfs)));
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
        Ok(())
    }

    #[test]
    fn regular_file_is_rejected() -> Result<(), Box<dyn Error>> {
        let path = std::env::temp_dir().join(format!("netns-test-{}", std::process::id()));
        let file = File::create(&path)?;
        let result = NetnsHandle::open(&path);
        drop(file);
        std::fs::remove_file(path)?;
        assert!(matches!(result, Err(NetnsError::NotNsfs)));
        Ok(())
    }
}

/// Synthetic handles for adapter tests; real execution still rejects host targets.
#[cfg(any(test, feature = "testing"))]
pub mod testing {
    use super::{NetnsError, NetnsHandle};
    /// Holds the caller's namespace for argument and fake-dispatch tests only.
    ///
    /// # Errors
    /// Returns an error if procfs is unavailable.
    pub fn handle() -> Result<NetnsHandle, NetnsError> {
        NetnsHandle::open_network("/proc/self/ns/net")
    }
}

/// Failure to inspect host UDP bindings. An unreadable table is never absence.
#[derive(Debug, thiserror::Error)]
pub enum UdpBoundError {
    /// A procfs read failed.
    #[error("cannot read host UDP socket table: {0}")]
    Io(#[from] std::io::Error),
    /// A procfs table is malformed.
    #[error(transparent)]
    Parse(#[from] scupper_core::parse::ParseError),
}

/// Whether a UDP port is bound in the caller's (host) namespace, in either family.
/// This performs no namespace switch; call it from the host process.
///
/// # Errors
/// Returns read/parse failures rather than claiming the port is unbound.
pub fn host_udp_bound(port: u16) -> Result<bool, UdpBoundError> {
    use scupper_core::parse::{parse_proc_net_udp, parse_proc_net_udp6, udp_port_bound};
    let v4 = parse_proc_net_udp(&std::fs::read_to_string("/proc/net/udp")?)?;
    let v6 = parse_proc_net_udp6(&std::fs::read_to_string("/proc/net/udp6")?)?;
    Ok(udp_port_bound(&v4, port) || udp_port_bound(&v6, port))
}

#[cfg(test)]
mod udp_binding_tests {
    #[test]
    fn host_udp_binding_is_visible() -> Result<(), Box<dyn std::error::Error>> {
        let socket = std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
        assert!(super::host_udp_bound(socket.local_addr()?.port())?);
        Ok(())
    }
}
