//! Native macOS boundary. Construction remains qualification-only until the
//! install-record writer and production process identity are qualified.
use crate::{
    decode::proc,
    platform::{
        CheapObservation, Child, Collection, ConfigKey, Deadline, Enumeration, ExeId, Fence,
        InstallRecord, InstanceLockError, KillOutcome, LeaveRoutes, PfEnable, PfInfo, Platform,
        ProcInfo, ProcState, ProcessError, RefLine, ReferenceQualification, Release, Setting,
        SpawnAttributes, SysError, ToolOutcome, WriteOutcome,
    },
    snapshot::{BootId, COPY_BYTES, Copy, CopyRead, HelperIncarnation, StartTime},
};
use scupper_core::mac::{
    PhysicalInterface, Tunnel, TunnelGeneration, policy::AnchorText, verify::Observations,
};
use std::os::unix::fs::MetadataExt;
use std::{
    collections::BTreeSet,
    net::SocketAddrV4,
    path::{Path, PathBuf},
    time::Duration,
};

const UNIMPLEMENTED: SysError = SysError::Failed("native: not implemented");

/// Fixed native filesystem namespace; future methods derive their paths here.
#[derive(Clone, Debug)]
pub struct Paths {
    root: PathBuf,
}
impl Paths {
    /// Production namespace. This does not make the native platform constructible.
    #[must_use]
    pub fn production() -> Self {
        Self {
            root: PathBuf::from("/var/db/scupper"),
        }
    }
    /// Scratch namespace available only to qualification builds.
    #[cfg(feature = "qualification")]
    #[must_use]
    pub fn qualification(root: PathBuf) -> Self {
        Self { root }
    }
    /// Root of this namespace.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }
}

/// Native adapter with no production constructor in this slice.
pub struct NativePlatform {
    paths: Paths,
}
impl NativePlatform {
    /// Construct the adapter for runner qualification only.
    #[cfg(feature = "qualification")]
    #[must_use]
    pub fn new(paths: Paths) -> Self {
        Self { paths }
    }
    /// Filesystem namespace selected at construction.
    #[must_use]
    pub fn paths(&self) -> &Paths {
        &self.paths
    }

    fn expired(&mut self, deadline: Deadline) -> Result<(), SysError> {
        if self.now() >= deadline.0 {
            Err(SysError::TimedOut)
        } else {
            Ok(())
        }
    }
    fn process_list(&mut self, deadline: Deadline) -> Result<Vec<ProcInfo>, ProcessError> {
        self.expired(deadline)?;
        let pid = std::process::id();
        let own = scupper_darwin::sysctl_kern_proc_pid(pid)
            .map_err(process_error)?
            .ok_or(SysError::Failed("native: process table implausible"))?;
        let own = decode(&own)?;
        if own.pid != pid {
            return Err(SysError::Failed("native: process layout").into());
        }
        self.expired(deadline)?;
        let records = scupper_darwin::sysctl_kern_proc_all().map_err(process_error)?;
        let mut procs = Vec::with_capacity(records.len());
        for record in records {
            self.expired(deadline)?;
            if record.pid == 0 {
                continue;
            }
            let entry = decode(&record)?;
            if entry.state == ProcState::Zombie {
                procs.push(entry);
                continue;
            }
            let path = scupper_darwin::proc_pidpath(entry.pid);
            // Bracket every path read, including success, by (pid,start).
            // ESRCH/ENOENT alone never establish that a listed PID vanished.
            let current = scupper_darwin::sysctl_kern_proc_pid(entry.pid).map_err(process_error)?;
            let current = current.as_ref().map(decode).transpose()?;
            let Some(entry) = proc::resolve_path(entry, path.ok(), current)? else {
                continue;
            };
            procs.push(entry);
        }
        self.expired(deadline)?;
        proc::require_self(&procs, pid, own.start)?;
        Ok(procs)
    }
}
fn process_error(error: scupper_darwin::ProcError) -> ProcessError {
    ProcessError::from(SysError::Failed(match error {
        scupper_darwin::ProcError::Layout => "native: process layout",
        scupper_darwin::ProcError::Incomplete => "native: process churn incomplete",
        scupper_darwin::ProcError::Os(_) => "native: process sysctl failed",
    }))
}
fn decode(record: &scupper_darwin::KProc) -> Result<ProcInfo, ProcessError> {
    let pid = u32::try_from(record.pid)
        .map_err(|_| ProcessError::from(SysError::Failed("native: invalid pid")))?;
    let fields = || -> Result<ProcInfo, SysError> {
        Ok(ProcInfo {
            pid,
            ppid: u32::try_from(record.ppid)
                .map_err(|_| SysError::Failed("native: invalid ppid"))?,
            pgid: u32::try_from(record.pgid)
                .map_err(|_| SysError::Failed("native: invalid pgid"))?,
            start: proc::start(record.start.0, record.start.1)?,
            state: proc::state(record.stat)?,
            name: proc::name(&record.comm),
            path: None,
            exe: None,
        })
    };
    fields().map_err(ProcessError::from)
}

impl Platform for NativePlatform {
    fn write_copy(
        &mut self,
        _copy: Copy,
        _bytes: &[u8; COPY_BYTES],
        _deadline: Deadline,
    ) -> WriteOutcome {
        WriteOutcome::Failed(UNIMPLEMENTED)
    }
    fn create_copy(
        &mut self,
        _copy: Copy,
        _bytes: &[u8; COPY_BYTES],
        _deadline: Deadline,
    ) -> WriteOutcome {
        WriteOutcome::Failed(UNIMPLEMENTED)
    }
    fn now(&mut self) -> u64 {
        scupper_darwin::monotonic_raw().as_secs()
    }
    fn pause(&mut self, duration: Duration, deadline: Deadline) {
        let start = scupper_darwin::monotonic_raw();
        let end = start
            .saturating_add(duration)
            .min(Duration::from_secs(deadline.0));
        let lock = std::sync::Mutex::new(());
        let wake = std::sync::Condvar::new();
        let Ok(mut guard) = lock.lock() else {
            return;
        };
        loop {
            let now = scupper_darwin::monotonic_raw();
            if now >= end {
                return;
            }
            let slice = end.saturating_sub(now).min(Duration::from_millis(100));
            let Ok((next, _)) = wake.wait_timeout(guard, slice) else {
                return;
            };
            guard = next;
        }
    }
    fn boot_id(&mut self) -> Option<BootId> {
        let value = scupper_darwin::sysctl_string("kern.bootsessionuuid").ok()?;
        BootId::try_from(value.as_str()).ok()
    }
    fn incarnation(&mut self) -> HelperIncarnation {
        // Self cannot vanish. Returning an invented start would forge identity;
        // the infallible contract leaves termination as the fail-closed choice.
        let pid = std::process::id();
        let Ok(Some(record)) = scupper_darwin::sysctl_kern_proc_pid(pid) else {
            std::process::abort()
        };
        let Ok(entry) = decode(&record) else {
            std::process::abort()
        };
        HelperIncarnation {
            pid,
            pgid: entry.pgid,
            start: entry.start,
            boot: self.boot_id(),
        }
    }
    fn processes(&mut self, deadline: Deadline) -> Enumeration<Vec<ProcInfo>, ProcessError> {
        match self.process_list(deadline) {
            Ok(list) => Enumeration::Complete(list),
            Err(error) => Enumeration::Incomplete(error),
        }
    }
    fn executable_id(&mut self, path: &Path, deadline: Deadline) -> Result<ExeId, SysError> {
        self.expired(deadline)?;
        let meta = std::fs::symlink_metadata(path)
            .map_err(|_| SysError::Failed("native: executable lstat failed"))?;
        self.expired(deadline)?;
        if !meta.is_file() {
            return Err(SysError::Failed("native: executable is not a regular file"));
        }
        Ok(ExeId {
            dev: meta.dev(),
            ino: meta.ino(),
        })
    }
    fn acquire_instance_lock(&mut self) -> Result<(), InstanceLockError> {
        Err(InstanceLockError::Failed(UNIMPLEMENTED))
    }
    fn create_control_socket(&mut self) -> Result<(), SysError> {
        Err(UNIMPLEMENTED)
    }
    fn reference_qualification(&self) -> ReferenceQualification {
        ReferenceQualification::default()
    }
    fn read_install_record(&mut self, _deadline: Deadline) -> Result<InstallRecord, SysError> {
        Err(UNIMPLEMENTED)
    }
    fn read_copy(&mut self, _copy: Copy, _deadline: Deadline) -> CopyRead {
        CopyRead::Unreadable
    }
    fn poll_install_record(
        &mut self,
        _deadline: Deadline,
    ) -> std::task::Poll<Result<InstallRecord, SysError>> {
        std::task::Poll::Ready(Err(UNIMPLEMENTED))
    }
    fn poll_copy(&mut self, _copy: Copy, _deadline: Deadline) -> std::task::Poll<CopyRead> {
        std::task::Poll::Ready(CopyRead::Unreadable)
    }
    fn abandon_storage_read(&mut self) {}
    fn wait_write(&mut self, _deadline: Deadline) -> WriteOutcome {
        WriteOutcome::Failed(UNIMPLEMENTED)
    }
    fn enable_pf(&mut self, _deadline: Deadline) -> Result<PfEnable, SysError> {
        Err(UNIMPLEMENTED)
    }
    fn acquire(&mut self, _deadline: Deadline) -> ToolOutcome<(u64, u32)> {
        ToolOutcome::NotStarted(UNIMPLEMENTED)
    }
    fn release(&mut self, _token: u64, _deadline: Deadline) -> ToolOutcome<Release> {
        ToolOutcome::NotStarted(UNIMPLEMENTED)
    }
    fn references(&mut self, _deadline: Deadline) -> Enumeration<Vec<RefLine>> {
        Enumeration::Incomplete(UNIMPLEMENTED)
    }
    fn pf_info(&mut self, _deadline: Deadline) -> PfInfo {
        PfInfo::Incomplete(UNIMPLEMENTED)
    }
    fn kill_group(
        &mut self,
        _pgid: u32,
        _expect_pid: u32,
        _expect_start: StartTime,
        _deadline: Deadline,
    ) -> Result<KillOutcome, SysError> {
        Err(UNIMPLEMENTED)
    }
    fn kill_process(
        &mut self,
        _pid: u32,
        _expect_start: StartTime,
        _deadline: Deadline,
    ) -> Result<KillOutcome, SysError> {
        Err(UNIMPLEMENTED)
    }
    fn reap_children(&mut self, _deadline: Deadline) -> Result<(), SysError> {
        Err(UNIMPLEMENTED)
    }
    fn fence(&mut self) -> Fence {
        Fence::Closed
    }
    fn reap(&mut self, _deadline: Deadline) -> Fence {
        Fence::Closed
    }
    fn load_anchor(&mut self, _text: &AnchorText, _deadline: Deadline) -> Result<(), SysError> {
        Err(UNIMPLEMENTED)
    }
    fn read_anchor(&mut self, _deadline: Deadline) -> Result<Option<String>, SysError> {
        Err(UNIMPLEMENTED)
    }
    fn flush_states(&mut self, _deadline: Deadline) -> Result<(), SysError> {
        Err(UNIMPLEMENTED)
    }
    fn remove_interface_states(
        &mut self,
        _interfaces: &BTreeSet<PhysicalInterface>,
        _deadline: Deadline,
    ) -> Result<(), SysError> {
        Err(UNIMPLEMENTED)
    }
    fn check_tools(&mut self, _deadline: Deadline) -> Result<(), SysError> {
        Err(UNIMPLEMENTED)
    }
    fn check_pfctl(&mut self, _deadline: Deadline) -> Result<(), SysError> {
        Err(UNIMPLEMENTED)
    }
    fn spawned_children(&self) -> &[Child] {
        &[]
    }
    fn spawn(
        &mut self,
        _generation: TunnelGeneration,
        _attributes: SpawnAttributes,
        _deadline: Deadline,
    ) -> Result<Child, SysError> {
        Err(UNIMPLEMENTED)
    }
    fn configure(
        &mut self,
        _key: ConfigKey,
        _value: &Setting,
        _deadline: Deadline,
    ) -> Result<(), SysError> {
        Err(UNIMPLEMENTED)
    }
    fn read_config(
        &mut self,
        _key: ConfigKey,
        _deadline: Deadline,
    ) -> Result<Option<Setting>, SysError> {
        Err(UNIMPLEMENTED)
    }
    fn identity(&mut self, _child: &Child, _deadline: Deadline) -> Result<Tunnel, SysError> {
        Err(UNIMPLEMENTED)
    }
    fn cheap_check(
        &mut self,
        _child: Option<&Child>,
        _deadline: Deadline,
    ) -> Result<CheapObservation, SysError> {
        Err(UNIMPLEMENTED)
    }
    fn collect(
        &mut self,
        _collection: &Collection,
        _deadline: Deadline,
    ) -> Result<Observations, SysError> {
        Err(UNIMPLEMENTED)
    }
    fn firewall_qualification(&self) -> Option<scupper_core::mac::verify::Qualification> {
        None
    }
    fn collect_lockdown(
        &mut self,
        _context: scupper_core::mac::verify::Context,
        _states: scupper_core::mac::verify::StateEvidence,
        _deadline: Deadline,
    ) -> Result<Observations, SysError> {
        Err(UNIMPLEMENTED)
    }
    fn leave_routes(
        &mut self,
        _endpoint: Option<SocketAddrV4>,
        _deadline: Deadline,
    ) -> Result<LeaveRoutes, SysError> {
        Err(UNIMPLEMENTED)
    }
    fn cleanup_owned_routes(
        &mut self,
        _endpoint: Option<SocketAddrV4>,
        _deadline: Deadline,
    ) -> Result<(), SysError> {
        Err(UNIMPLEMENTED)
    }
    fn cleanup_routes(
        &mut self,
        _endpoint: SocketAddrV4,
        _deadline: Deadline,
    ) -> Result<(), SysError> {
        Err(UNIMPLEMENTED)
    }
    fn cleanup_dns(&mut self, _deadline: Deadline) -> Result<(), SysError> {
        Err(UNIMPLEMENTED)
    }
    fn managed_artifacts(&mut self, _deadline: Deadline) -> Enumeration<Vec<String>> {
        Enumeration::Incomplete(UNIMPLEMENTED)
    }
    fn cleanup_artifacts(&mut self, _deadline: Deadline) -> Result<(), SysError> {
        Err(UNIMPLEMENTED)
    }
    fn remove_anchor(&mut self, _deadline: Deadline) -> Result<(), SysError> {
        Err(UNIMPLEMENTED)
    }
}

#[cfg(all(test, feature = "qualification"))]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn invalid_decoded_records_and_sysctl_errors_do_not_name_a_pathless_pid() {
        let mut record = scupper_darwin::KProc {
            pid: 123,
            ppid: 1,
            pgid: 123,
            stat: 0,
            start: (456, 789),
            comm: [0; 17],
        };
        let error = decode(&record).err();
        assert!(error.is_some());
        assert_eq!(error.and_then(|e| e.pid), None);
        record.stat = 3;
        record.start.0 = -1;
        let error = decode(&record).err();
        assert!(error.is_some());
        assert_eq!(error.and_then(|e| e.pid), None);
        assert_eq!(
            process_error(scupper_darwin::ProcError::Incomplete).pid,
            None
        );
        assert_eq!(
            process_error(scupper_darwin::ProcError::Os(rustix::io::Errno::PERM)).pid,
            None
        );
    }

    #[test]
    fn now_uses_the_sleep_counting_raw_clock_and_incarnation_has_current_boot() {
        // A never-slept runner cannot distinguish the clocks by observation.
        // The pinned id and monotonic_raw -> clock(NOW_CLOCK_ID) select the clock;
        // this bracket checks only that now() reads it in seconds.
        assert_eq!(scupper_darwin::NOW_CLOCK_ID, 4);
        let mut platform = NativePlatform::new(Paths::production());
        let before = scupper_darwin::monotonic_raw().as_secs();
        let now = platform.now();
        let after = scupper_darwin::monotonic_raw().as_secs();
        assert!((before..=after).contains(&now));
        let own = platform.incarnation();
        assert_eq!(own.pid, std::process::id());
        assert_eq!(own.boot, platform.boot_id());
        assert!(own.start.microseconds < 1_000_000);
    }

    #[test]
    fn pause_caps_fractional_deadlines_and_returns_immediately_when_expired() {
        let mut platform = NativePlatform::new(Paths::production());
        let before = scupper_darwin::monotonic_raw();
        platform.pause(Duration::from_secs(30), Deadline(before.as_secs()));
        assert!(
            scupper_darwin::monotonic_raw().saturating_sub(before) < Duration::from_millis(500)
        );
        let d = Deadline(platform.now() + 2);
        let before = scupper_darwin::monotonic_raw();
        platform.pause(Duration::from_millis(20), d);
        assert!(
            scupper_darwin::monotonic_raw().saturating_sub(before) >= Duration::from_millis(20)
        );
        // Request longer than the fractional time remaining in this second.
        let d = Deadline(platform.now() + 1);
        platform.pause(Duration::from_secs(30), d);
        let after = scupper_darwin::monotonic_raw();
        assert!(after >= Duration::from_secs(d.0));
        assert!(after < Duration::from_secs(d.0 + 1));
    }

    #[test]
    fn executable_lstat_rejects_symlinks_and_production_cannot_read_install_record()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!("scupper-native-base-{}", std::process::id()));
        std::fs::create_dir(&root)?;
        let check = (|| -> Result<(), Box<dyn std::error::Error>> {
            let pin = root.join("pin");
            let alias = root.join("alias");
            let link = root.join("link");
            std::fs::write(&pin, b"fixture")?;
            std::fs::hard_link(&pin, &alias)?;
            symlink(&pin, &link)?;
            let mut platform = NativePlatform::new(Paths::production());
            let d = Deadline(platform.now() + 5);
            let first = platform.executable_id(&pin, d)?;
            assert_eq!(platform.executable_id(&alias, d)?, first);
            assert!(platform.executable_id(&link, d).is_err());
            assert!(platform.executable_id(&root, d).is_err());
            assert!(platform.executable_id(&root.join("absent"), d).is_err());
            let expired = Deadline(platform.now());
            assert_eq!(
                platform.executable_id(&pin, expired),
                Err(SysError::TimedOut)
            );
            assert!(matches!(
                platform.read_install_record(d),
                Err(UNIMPLEMENTED)
            ));
            assert!(matches!(
                platform.poll_install_record(d),
                std::task::Poll::Ready(Err(UNIMPLEMENTED))
            ));
            assert!(platform.firewall_qualification().is_none());
            Ok(())
        })();
        std::fs::remove_dir_all(root)?;
        check
    }
}
