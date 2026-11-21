//! Portable spawn, signal, descriptor and fence rules used by the native adapter.
use super::{Child, Fence, KillOutcome, ProcInfo, ProcState, SysError, Tool, Unreaped};
use crate::snapshot::StartTime;

/// Reject self-dup2: Darwin `CLOEXEC_DEFAULT` does not inherit it at exec.
/// Sources must remain alive through the synchronous spawn call.
#[must_use]
pub fn valid_fd_action(source: i32, target: i32) -> bool {
    source >= 0 && target >= 0 && source != target
}

/// Bounded output retained while pipes continue to be drained.
#[derive(Default, Debug)]
pub struct Output {
    /// Retained bytes.
    pub bytes: Vec<u8>,
    /// At least one byte was discarded.
    pub truncated: bool,
}
impl Output {
    /// Account for a read, including reads after truncation.
    pub fn append(&mut self, bytes: &[u8], cap: usize) {
        let keep = bytes.len().min(cap.saturating_sub(self.bytes.len()));
        self.bytes.extend_from_slice(&bytes[..keep]);
        self.truncated |= keep != bytes.len();
    }
}

/// Evidence returned by an exact-PID nonblocking reap syscall.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reap {
    /// Child still exists, or the syscall failed without proving absence.
    Pending,
    /// The syscall returned the child's status.
    Status(i32),
    /// The syscall returned ECHILD; accepted by the platform contract.
    NoChild,
}
impl Reap {
    /// Only returned syscall evidence settles the record.
    #[must_use]
    pub fn settled(self) -> bool {
        matches!(self, Self::Status(_) | Self::NoChild)
    }
}

/// Spawn records separate tools from foreground children. R owns the native
/// exact-pid reap capability; there is no constructor for an arbitrary PID.
#[derive(Debug)]
pub struct Records<R> {
    /// All tools, including read-only tools, until a confirmed reap.
    pub tools: Vec<(Tool, R)>,
    /// Only spawn's foreground children; never a tool.
    pub children: Vec<R>,
    /// Child identities survive reaping, including partially observed spawns.
    pub history: Vec<Child>,
}
impl<R> Default for Records<R> {
    fn default() -> Self {
        Self {
            tools: Vec::new(),
            children: Vec::new(),
            history: Vec::new(),
        }
    }
}
impl<R> Records<R> {
    /// Snapshot only; never attempts a reap.
    pub fn fence(&self, pid: impl Fn(&R) -> u32) -> Fence {
        if self.tools.is_empty() {
            Fence::Closed
        } else {
            Fence::Open(
                self.tools
                    .iter()
                    .map(|(tool, r)| Unreaped {
                        tool: *tool,
                        pid: pid(r),
                    })
                    .collect(),
            )
        }
    }
    /// Nonblocking child-only reaping. Records persist separately in history.
    pub fn reap_children(&mut self, mut reap: impl FnMut(&mut R) -> Reap) {
        self.children.retain_mut(|r| !reap(r).settled());
    }
    /// Tool-only reaping, including observation tools.
    pub fn reap_tools(&mut self, mut reap: impl FnMut(&mut R) -> Reap) {
        self.tools.retain_mut(|(_, r)| !reap(r).settled());
    }
}

/// Pure start/group recheck decision. The caller signals immediately on None.
#[must_use]
pub fn kill_recheck(
    current: Option<&ProcInfo>,
    start: StartTime,
    pgid: Option<u32>,
) -> Option<KillOutcome> {
    match current {
        None => Some(KillOutcome::Gone),
        Some(p) if p.start != start || pgid.is_some_and(|g| p.pgid != g) => {
            Some(KillOutcome::StartChanged)
        }
        Some(p) if p.state == ProcState::Zombie => Some(KillOutcome::Gone),
        Some(_) => None,
    }
}

/// Root-owned file/directory permissions required for protected paths.
#[must_use]
pub fn protected_owner_mode(uid: u32, mode: u32) -> bool {
    uid == 0 && mode & 0o022 == 0
}

/// Lock fstat predicate, deliberately independent of host stat layouts.
#[must_use]
pub fn valid_lock(regular: bool, uid: u32, mode: u32, nlink: u64) -> bool {
    regular && uid == 0 && mode & 0o7777 == 0o600 && nlink == 1
}

/// Portable snapshot of every pin metadata field compared across lstat/open/hash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PinMetadata {
    /// Regular file, never a symlink.
    pub regular: bool,
    /// Owner uid.
    pub uid: u32,
    /// Full file mode.
    pub mode: u32,
    /// Reviewed vnode.
    pub exe: super::ExeId,
    /// File length.
    pub len: u64,
    /// Modification seconds/nanoseconds.
    pub modified: (i64, i64),
    /// Change seconds/nanoseconds.
    pub changed: (i64, i64),
}
impl PinMetadata {
    /// Extract a snapshot without following a path or opening another file.
    #[cfg(unix)]
    #[must_use]
    pub fn from_metadata(m: &std::fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt;
        Self {
            regular: m.is_file(),
            uid: m.uid(),
            mode: m.mode(),
            exe: super::ExeId {
                dev: m.dev(),
                ino: m.ino(),
            },
            len: m.len(),
            modified: (m.mtime(), m.mtime_nsec()),
            changed: (m.ctime(), m.ctime_nsec()),
        }
    }
}
/// Root-owned regular pins must not permit group/other writes.
#[must_use]
pub fn trusted_meta(meta: &PinMetadata) -> bool {
    meta.regular && protected_owner_mode(meta.uid, meta.mode)
}
/// Every identity/content-related field must remain stable across pin checks.
#[must_use]
pub fn same_meta(a: &PinMetadata, b: &PinMetadata) -> bool {
    trusted_meta(b) && a == b
}
/// Reviewed vnode must match before opening; digest must match after hashing.
#[must_use]
pub fn pin_identity(meta: &PinMetadata, exe: super::ExeId) -> bool {
    trusted_meta(meta) && meta.exe == exe
}
/// The computed hash must match the separately reviewed digest.
#[must_use]
pub fn pin_digest(actual: [u8; 32], reviewed: [u8; 32]) -> bool {
    actual == reviewed
}
/// A control-unit inference needs independent evidence from wireguard-go's socket.
///
/// # Errors
/// Missing or unprotected independent evidence cannot authorize a utun name.
pub fn utun_crosscheck(protected_socket: bool) -> Result<(), SysError> {
    if !protected_socket {
        return Err(SysError::Failed("native: utun cross-check unavailable"));
    }
    Ok(())
}

/// Update the image before any fallible post-spawn validation.
pub fn record_observation(child: &mut Child, observed: &ProcInfo) {
    let retained = if child.start_time == observed.start {
        child.image
    } else {
        None
    };
    child.start_time = observed.start;
    child.pgid = observed.pgid;
    // Exiting/zombie observations have no new image; retain the last validated
    // image for this identity so a partial failure cannot erase spawn history.
    child.image = observed.image.or(retained);
}

/// Derive a utun name only from an observed matching kernel-control socket.
#[must_use]
pub fn utun_name(name: &[u8], unit: u32) -> Option<String> {
    if name.split(|b| *b == 0).next()? != b"com.apple.net.utun_control" || !name.contains(&0) {
        return None;
    }
    unit.checked_sub(1).map(|index| format!("utun{index}"))
}

/// Map bounded tool evidence. Missing status or bytes cannot confirm an effect.
#[must_use]
pub fn tool_outcome(reap: Reap, incomplete: bool, stdout: Vec<u8>) -> super::ToolOutcome<Vec<u8>> {
    use super::ToolOutcome;
    let reaped = reap.settled();
    if !reaped || incomplete {
        ToolOutcome::Unknown { reaped }
    } else if reap == Reap::Status(0) {
        ToolOutcome::Ok(stdout)
    } else if matches!(reap, Reap::Status(_)) {
        ToolOutcome::Failed(SysError::Failed("native: tool exit failure"))
    } else {
        ToolOutcome::Unknown { reaped }
    }
}

/// Map a complete, reaped tool status; truncated bytes never prove success.
///
/// # Errors
/// Returns incomplete output or unsuccessful exit as an error.
pub fn complete_output(reap: Reap, truncated: bool, io_failed: bool) -> Result<(), SysError> {
    if reap == Reap::Status(0) && !truncated && !io_failed {
        Ok(())
    } else {
        Err(SysError::Failed("native: incomplete tool result"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    proptest! {
        #[test]
        fn actions_never_accept_self_dup(source in any::<i32>(), target in any::<i32>()) {
            prop_assert_eq!(valid_fd_action(source, target), source >= 0 && target >= 0 && source != target);
            prop_assert!(!valid_fd_action(source, source));
        }
        #[test]
        fn cap_accounts_all_bytes(chunks in prop::collection::vec(prop::collection::vec(any::<u8>(), 0..200), 0..30), cap in 0_usize..1000) {
            let all: Vec<_> = chunks.iter().flatten().copied().collect();
            let mut out = Output::default();
            for c in chunks { out.append(&c, cap); }
            prop_assert_eq!(&out.bytes, &all[..all.len().min(cap)]);
            prop_assert_eq!(out.truncated, all.len() > cap);
        }
        #[test]
        fn protected_modes(uid in any::<u32>(),mode in any::<u32>()) {
            prop_assert_eq!(protected_owner_mode(uid,mode),uid==0 && mode & 0o022==0);
        }
        #[test]
        fn lock_predicate_is_exact(uid in any::<u32>(), mode in any::<u32>(), links in any::<u64>(), regular in any::<bool>()) {
            prop_assert_eq!(valid_lock(regular, uid, mode, links), regular && uid == 0 && mode & 0o7777 == 0o600 && links == 1);
        }
    }
    #[test]
    fn protected_modes_reject_other_owners_and_writers() {
        assert!(protected_owner_mode(0, 0o100_755));
        assert!(!protected_owner_mode(1, 0o100_755));
        assert!(!protected_owner_mode(0, 0o100_775));
        assert!(!protected_owner_mode(0, 0o100_757));
    }
    #[test]
    fn lock_rejects_extra_links_and_permissions() {
        assert!(valid_lock(true, 0, 0o100_600, 1));
        assert!(!valid_lock(true, 0, 0o100_600, 2));
        for (regular, uid, mode) in [
            (false, 0, 0o600),
            (true, 1, 0o600),
            (true, 0, 0o660),
            (true, 0, 0o4600),
        ] {
            assert!(!valid_lock(regular, uid, mode, 1));
        }
    }
    #[test]
    fn only_reap_evidence_closes_fences_and_families_are_separate() {
        let mut r = Records::<u32>::default();
        r.tools.push((Tool::Pfctl, 30));
        r.children.push(40);
        r.reap_children(|pid| {
            assert_eq!(*pid, 40);
            Reap::Status(0)
        });
        assert_eq!(
            r.fence(|p| *p),
            Fence::Open(vec![Unreaped {
                tool: Tool::Pfctl,
                pid: 30
            }])
        );
        r.reap_tools(|pid| {
            assert_eq!(*pid, 30);
            Reap::Pending
        });
        assert!(matches!(r.fence(|p| *p), Fence::Open(_)));
        r.children.push(41);
        r.reap_tools(|_| Reap::NoChild);
        assert_eq!(r.children, [41]);
        assert_eq!(r.fence(|p| *p), Fence::Closed);
        assert!(complete_output(Reap::Pending, false, false).is_err());
        assert!(complete_output(Reap::NoChild, false, false).is_err());
        assert!(complete_output(Reap::Status(0), true, false).is_err());
        assert!(complete_output(Reap::Status(9), false, false).is_err());
        assert!(complete_output(Reap::Status(0), false, false).is_ok());
    }
    #[test]
    fn wrong_start_prevents_signal_and_partial_spawn_keeps_image()
    -> Result<(), Box<dyn std::error::Error>> {
        let p = crate::decode::proc::records(include_bytes!(
            "../../tests/fixtures/macos/layout/kinfo_proc.bin"
        ))?
        .remove(0);
        assert_eq!(
            kill_recheck(
                Some(&p),
                StartTime {
                    seconds: p.start.seconds + 1,
                    microseconds: p.start.microseconds
                },
                None
            ),
            Some(KillOutcome::StartChanged)
        );
        assert_eq!(kill_recheck(None, p.start, None), Some(KillOutcome::Gone));
        let mut p = p;
        p.state = ProcState::Running;
        assert_eq!(kill_recheck(Some(&p), p.start, None), None);
        assert_eq!(
            kill_recheck(Some(&p), p.start, Some(p.pgid + 1)),
            Some(KillOutcome::StartChanged)
        );
        p.image = Some(super::super::ImageId {
            uuid: [1; 16],
            uniqueid: 42,
        });
        let mut c = Child {
            boot: None,
            generation: 1,
            pid: p.pid,
            start_time: StartTime {
                seconds: 0,
                microseconds: 0,
            },
            exe: None,
            image: None,
            pgid: 0,
            utun: String::new(),
        };
        record_observation(&mut c, &p);
        assert_eq!(c.image, p.image);
        let retained = c.image;
        p.image = None;
        record_observation(&mut c, &p);
        assert_eq!(c.image, retained);
        p.start.seconds += 1;
        record_observation(&mut c, &p);
        assert_eq!(c.image, None);
        Ok(())
    }
    #[test]
    fn outcomes_require_status_and_complete_bytes() {
        use super::super::ToolOutcome;
        assert_eq!(
            tool_outcome(Reap::Pending, false, vec![]),
            ToolOutcome::Unknown { reaped: false }
        );
        assert_eq!(
            tool_outcome(Reap::NoChild, false, vec![]),
            ToolOutcome::Unknown { reaped: true }
        );
        assert_eq!(
            tool_outcome(Reap::Status(0), true, vec![]),
            ToolOutcome::Unknown { reaped: true }
        );
        assert_eq!(
            tool_outcome(Reap::Status(0), false, vec![1]),
            ToolOutcome::Ok(vec![1])
        );
        assert!(matches!(
            tool_outcome(Reap::Status(9), false, vec![]),
            ToolOutcome::Failed(_)
        ));
    }
    #[test]
    fn utun_requires_control_and_nonzero_unit() {
        assert_eq!(
            utun_name(b"com.apple.net.utun_control\0", 1),
            Some("utun0".into())
        );
        assert_eq!(utun_name(b"com.apple.net.utun_control\0", 0), None);
        assert_eq!(utun_name(b"other\0", 1), None);
    }
    #[test]
    fn self_dup_is_rejected() {
        assert!(!valid_fd_action(10, 10));
        assert!(valid_fd_action(10, 3));
    }
    #[test]
    fn utun_requires_independent_evidence() {
        assert!(utun_crosscheck(true).is_ok());
        assert!(utun_crosscheck(false).is_err());
    }
    fn metadata() -> PinMetadata {
        PinMetadata {
            regular: true,
            uid: 0,
            mode: 0o100_755,
            exe: super::super::ExeId { dev: 1, ino: 2 },
            len: 3,
            modified: (4, 5),
            changed: (6, 7),
        }
    }
    #[test]
    fn pinned_tools_reject_symlink_mode_owner_vnode_and_wrong_digest() {
        use sha2::{Digest, Sha256};
        let good = metadata();
        assert!(pin_identity(&good, good.exe));
        let mut bad = good.clone();
        bad.regular = false;
        assert!(!pin_identity(&bad, good.exe));
        bad = good.clone();
        bad.mode |= 0o020;
        assert!(!pin_identity(&bad, good.exe));
        bad = good.clone();
        bad.uid = 1;
        assert!(!pin_identity(&bad, good.exe));
        bad = good.clone();
        bad.exe.ino += 1;
        assert!(!pin_identity(&bad, good.exe));
        let actual: [u8; 32] = Sha256::digest(b"actual pinned file bytes").into();
        let mut wrong = actual;
        wrong[0] ^= 1;
        assert!(!pin_digest(actual, wrong));
        assert!(pin_digest(actual, actual));
        for field in 0..9 {
            let mut bad = good.clone();
            match field {
                0 => bad.regular = false,
                1 => bad.uid += 1,
                2 => bad.mode ^= 1,
                3 => bad.exe.dev += 1,
                4 => bad.exe.ino += 1,
                5 => bad.len += 1,
                6 => bad.modified.0 += 1,
                7 => bad.modified.1 += 1,
                _ => bad.changed.1 += 1,
            }
            assert!(!same_meta(&good, &bad), "changed pin field {field}");
        }
    }
    proptest! {
        #[test]
        fn pin_metadata_predicates(uid in any::<u32>(), mode in any::<u32>(), regular in any::<bool>(), len in any::<u64>()) {
            let mut m = metadata(); m.uid = uid; m.mode = mode; m.regular = regular;
            prop_assert_eq!(trusted_meta(&m), regular && uid == 0 && mode & 0o022 == 0);
            let mut changed = m.clone(); changed.len = len;
            prop_assert_eq!(same_meta(&m, &changed), trusted_meta(&changed) && m == changed);
        }
    }
    #[test]
    fn syscall_reaper_is_confined() -> Result<(), Box<dyn std::error::Error>> {
        let needles = ["pid", "4", "id"].map(|suffix| format!("wait{suffix}("));
        let wait = ["libc::", "wait", "("].concat();
        let needles = [&needles[0], &needles[1], &needles[2], &wait];
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(std::path::Path::parent)
            .ok_or("workspace root")?;
        let syscall_file = root.join("crates/scupper-darwin/src/sys.rs");
        let mut pending = vec![root.to_path_buf()];
        let mut exact_reaps = 0;
        while let Some(dir) = pending.pop() {
            for item in std::fs::read_dir(dir)? {
                let item = item?;
                if item.file_type()?.is_dir() {
                    if !["target", "dev", ".git"]
                        .iter()
                        .any(|name| item.file_name() == *name)
                    {
                        pending.push(item.path());
                    }
                } else if item.path().extension().is_some_and(|s| s == "rs") {
                    let source = std::fs::read_to_string(item.path())?;
                    // Ignore whitespace between a function name and its call.
                    let compact: String = source.chars().filter(|c| !c.is_whitespace()).collect();
                    for needle in &needles {
                        let mut count = compact.matches(needle.as_str()).count();
                        // These existing Linux lab/client reapers are unrelated to
                        // the macOS helper. Permit their typed rustix calls only;
                        // any libc/unqualified syscall in any crate still fails.
                        if [
                            "xtask/src/lab/daemon/heartbeat.rs",
                            "crates/scupper-sys/src/system.rs",
                        ]
                        .iter()
                        .any(|p| item.path() == root.join(p))
                        {
                            count -= compact
                                .matches(&format!("rustix::process::{needle}"))
                                .count();
                        }
                        if item.path() == syscall_file && needle == &needles[0] {
                            exact_reaps += count;
                        } else {
                            assert_eq!(
                                count,
                                0,
                                "reap syscall outside sole exact-pid call: {}",
                                item.path().display()
                            );
                        }
                    }
                }
            }
        }
        assert_eq!(exact_reaps, 1);
        Ok(())
    }
}
