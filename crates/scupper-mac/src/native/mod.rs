//! Native macOS boundary. Construction remains qualification-only until the
//! install-record writer and production process identity are qualified.
pub mod tool;
use crate::platform::{
    Tool,
    runtime::{Records, kill_recheck, record_observation, valid_lock},
};
use crate::{
    decode::{image, proc},
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
use std::{
    mem::ManuallyDrop,
    os::fd::AsFd,
    os::unix::{fs::OpenOptionsExt, net::UnixListener},
};

const UNIMPLEMENTED: SysError = SysError::Failed("native: not implemented");

/// Fixed native filesystem namespace; future methods derive their paths here.
#[derive(Clone, Debug)]
pub struct Paths {
    root: PathBuf,
    lock: PathBuf,
    control: PathBuf,
}
impl Paths {
    /// Production namespace. This does not make the native platform constructible.
    #[must_use]
    pub fn production() -> Self {
        Self {
            root: PathBuf::from("/private/var/db/scupper"),
            lock: PathBuf::from("/private/var/run/scupper.lock"),
            control: PathBuf::from("/private/var/run/scupper.sock"),
        }
    }
    /// Scratch namespace available only to qualification builds.
    #[cfg(feature = "qualification")]
    #[must_use]
    pub fn qualification(root: PathBuf) -> Self {
        Self {
            lock: root.join("instance.lock"),
            control: root.join("control.sock"),
            root,
        }
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
    lock: Option<ManuallyDrop<std::fs::File>>,
    control: Option<UnixListener>,
    records: Records<scupper_darwin::Spawned>,
    pins: Vec<TrustedExecutable>,
    child_pin: PathBuf,
}
impl NativePlatform {
    /// Construct the adapter for runner qualification only.
    #[cfg(feature = "qualification")]
    #[must_use]
    pub fn new(paths: Paths) -> Self {
        Self {
            paths,
            lock: None,
            control: None,
            records: Records::default(),
            pins: Vec::new(),
            child_pin: crate::engine::CHILD_PATH.into(),
        }
    }
    /// Supply reviewed digests/vnodes for qualification until R5 provides them.
    /// Production pins remain the fixed engine paths. A staged child override is
    /// allowed only in this qualification constructor.
    #[cfg(feature = "qualification")]
    #[must_use]
    pub fn with_pins(mut self, pins: Vec<TrustedExecutable>, child: PathBuf) -> Self {
        self.pins = pins;
        self.child_pin = child;
        self
    }
    /// Exercise the common native runner with a harmless pinned qualification tool.
    ///
    /// # Errors
    /// Rejects untrusted paths and exhausted deadlines before spawn.
    #[cfg(feature = "qualification")]
    pub fn run_tool(
        &mut self,
        family: Tool,
        path: &Path,
        argv: &[&str],
        input: &[u8],
        cap: usize,
        deadline: Deadline,
    ) -> Result<tool::ToolResult, SysError> {
        if !matches!(
            path.to_str(),
            Some("/usr/bin/true" | "/bin/sleep" | "/bin/cat")
        ) && !self.pins.iter().any(|p| p.path == path)
        {
            return Err(SysError::Failed("native: qualification tool not pinned"));
        }
        if self.pins.iter().any(|p| p.path == path) {
            self.check_pin(path, deadline)?;
        }
        tool::run(&mut self.records, family, path, argv, input, cap, deadline)
    }
    fn check_pin(&mut self, path: &Path, deadline: Deadline) -> Result<(), SysError> {
        use sha2::{Digest, Sha256};
        use std::io::Read;
        self.expired(deadline)?;
        let pin = self
            .pins
            .iter()
            .find(|p| p.path == path)
            .cloned()
            .ok_or(SysError::Failed("native: install digest unavailable"))?;
        let before =
            std::fs::symlink_metadata(path).map_err(|_| SysError::Failed("native: pin lstat"))?;
        if !trusted_meta(&before)
            || (ExeId {
                dev: before.dev(),
                ino: before.ino(),
            }) != pin.exe
        {
            return Err(SysError::Failed("native: untrusted pin"));
        }
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(0x100 | 0x0100_0000 | 0x4)
            .open(path)
            .map_err(|_| SysError::Failed("native: pin open"))?;
        let opened = file
            .metadata()
            .map_err(|_| SysError::Failed("native: pin fstat"))?;
        if !same_meta(&before, &opened) {
            return Err(SysError::Failed("native: pin changed"));
        }
        let mut digest = Sha256::new();
        let mut buffer = [0_u8; 16384];
        loop {
            self.expired(deadline)?;
            let n = match file.read(&mut buffer) {
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => return Err(SysError::Failed("native: pin hash read")),
            };
            if n == 0 {
                break;
            }
            digest.update(&buffer[..n]);
        }
        let after = file
            .metadata()
            .map_err(|_| SysError::Failed("native: pin fstat"))?;
        let path_after =
            std::fs::symlink_metadata(path).map_err(|_| SysError::Failed("native: pin lstat"))?;
        self.expired(deadline)?;
        if !same_meta(&before, &after)
            || !same_meta(&before, &path_after)
            || <[u8; 32]>::from(digest.finalize()) != pin.sha256
        {
            return Err(SysError::Failed("native: pin digest/identity mismatch"));
        }
        Ok(())
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
    /// Qualification-only single-process image bracket, also used by the
    /// pathless adapter. This does not grant ownership or certify a full inventory.
    ///
    /// # Errors
    /// Returns the live PID for invalid image brackets, or an observation error.
    #[cfg(feature = "qualification")]
    pub fn observe_image(
        &mut self,
        pid: u32,
        deadline: Deadline,
    ) -> Result<Option<ProcInfo>, ProcessError> {
        self.expired(deadline)?;
        let record = scupper_darwin::sysctl_kern_proc_pid(pid).map_err(process_error)?;
        let Some(record) = record else {
            return Ok(None);
        };
        let result = observe_image(decode(&record)?)?;
        self.expired(deadline)?;
        Ok(result)
    }
    /// Return the exact exec version validated by the image bracket, for Q-PROC.
    ///
    /// # Errors
    /// Returns observation errors, retaining the PID when the bracket fails.
    #[cfg(feature = "qualification")]
    pub fn observe_image_version(
        &mut self,
        pid: u32,
        deadline: Deadline,
    ) -> Result<(Option<ProcInfo>, Option<i32>), ProcessError> {
        self.expired(deadline)?;
        let record = scupper_darwin::sysctl_kern_proc_pid(pid).map_err(process_error)?;
        let Some(record) = record else {
            return Ok((None, None));
        };
        let result = observe_image_detail(decode(&record)?)?;
        self.expired(deadline)?;
        Ok(result)
    }
    fn finish_spawn(
        &mut self,
        index: usize,
        before: Option<ExeId>,
        pin: &Path,
        deadline: Deadline,
    ) -> Result<Child, SysError> {
        let pid = self.records.history[index].pid;
        let expected_group = self.records.history[index].pgid;
        // Preserve every observation before any subsequent fallible check.
        self.records.history[index].boot = self.boot_id();
        let record = scupper_darwin::sysctl_kern_proc_pid(pid)
            .map_err(|_| SysError::Failed("native: spawned identity"))?
            .ok_or(SysError::Failed("native: spawned child disappeared"))?;
        if record.translated {
            // Preserve any obtainable image, but no observation error may bypass
            // killing an owned child already known to be translated.
            if let Ok(entry) = decode(&record) {
                record_observation(&mut self.records.history[index], &entry);
                if let Ok(Some(entry)) = observe_image(entry) {
                    record_observation(&mut self.records.history[index], &entry);
                }
            }
            let _ = self
                .records
                .children
                .last_mut()
                .map(scupper_darwin::Spawned::kill);
            return Err(SysError::Failed("native: translated child refused"));
        }
        let observed = decode(&record).map_err(|_| SysError::Failed("native: spawned identity"))?;
        record_observation(&mut self.records.history[index], &observed);
        let image =
            observe_image(observed).map_err(|_| SysError::Failed("native: spawned image"))?;
        if let Some(observed) = image {
            record_observation(&mut self.records.history[index], &observed);
        }
        if self.records.history[index].pgid != expected_group
            || record.ppid
                != i32::try_from(std::process::id())
                    .map_err(|_| SysError::Failed("native: own pid range"))?
        {
            return Err(SysError::Failed("native: child left helper group/parent"));
        }
        let after = self.executable_id(pin, deadline).ok();
        self.records.history[index].exe = before.filter(|id| Some(*id) == after);
        // Re-read translation after the image bracket; no guessed host UUID.
        let latest = scupper_darwin::sysctl_kern_proc_pid(pid)
            .map_err(|_| SysError::Failed("native: translation read"))?
            .ok_or(SysError::Failed("native: child disappeared"))?;
        if record.translated || latest.translated {
            let _ = self
                .records
                .children
                .last_mut()
                .map(scupper_darwin::Spawned::kill);
            return Err(SysError::Failed("native: translated child refused"));
        }
        self.expired(deadline)?;
        if self.records.history[index].image.is_none() || latest.start != record.start {
            return Err(SysError::Failed("native: spawned image unavailable"));
        }
        self.observe_child_utun(index, deadline)
    }
    fn observe_child_utun(&mut self, index: usize, deadline: Deadline) -> Result<Child, SysError> {
        let pid = self.records.history[index].pid;
        let version = scupper_darwin::proc_identifier(pid)
            .ok()
            .and_then(|bytes| image::identifier(&bytes).ok())
            .ok_or(SysError::Failed("native: child exec version"))?;
        if self.records.history[index]
            .image
            .is_none_or(|i| i != version.image)
        {
            return Err(SysError::Failed("native: child exec changed"));
        }
        loop {
            self.expired(deadline)?;
            let mut names = BTreeSet::new();
            for fd in scupper_darwin::proc_fds(pid)
                .map_err(|_| SysError::Failed("native: child fd inventory"))?
            {
                if let Ok(Some(control)) = scupper_darwin::proc_control(pid, fd)
                    && let Some(name) =
                        crate::platform::runtime::utun_name(&control.name, control.unit)
                {
                    names.insert(name);
                }
            }
            if names.len() > 1 {
                return Err(SysError::Failed("native: ambiguous child utun"));
            }
            if let Some(name) = names.into_iter().next() {
                let current = scupper_darwin::sysctl_kern_proc_pid(pid)
                    .map_err(|_| SysError::Failed("native: utun identity"))?
                    .ok_or(SysError::Failed("native: child gone"))?;
                if current.translated {
                    let _ = self
                        .records
                        .children
                        .last_mut()
                        .map(scupper_darwin::Spawned::kill);
                    return Err(SysError::Failed("native: translated child refused"));
                }
                let observed = observe_image(
                    decode(&current).map_err(|_| SysError::Failed("native: child identity"))?,
                )
                .map_err(|_| SysError::Failed("native: child image"))?
                .ok_or(SysError::Failed("native: child image disappeared"))?;
                let unchanged = observed.start == self.records.history[index].start_time
                    && observed.image == self.records.history[index].image
                    && observed.pgid == self.records.history[index].pgid
                    && observed.ppid == std::process::id();
                record_observation(&mut self.records.history[index], &observed);
                if !unchanged {
                    return Err(SysError::Failed("native: utun child changed"));
                }
                let after = scupper_darwin::proc_identifier(pid)
                    .ok()
                    .and_then(|bytes| image::identifier(&bytes).ok())
                    .ok_or(SysError::Failed("native: child exec version"))?;
                if after != version {
                    return Err(SysError::Failed("native: child exec changed"));
                }
                self.records.history[index].utun = name;
                self.expired(deadline)?;
                if self.records.history[index].boot.is_none() {
                    return Err(SysError::Failed("native: spawned boot unknown"));
                }
                return Ok(self.records.history[index].clone());
            }
            self.pause(Duration::from_millis(10), deadline);
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
            let resolved = if path.as_ref().is_err_and(|e| e.raw_os_error() == 2) {
                observe_image(entry)
            } else {
                // ESRCH alone proves no exit; bracket successful paths too.
                let current =
                    scupper_darwin::sysctl_kern_proc_pid(entry.pid).map_err(process_error)?;
                proc::resolve_path(entry, path.ok(), current.as_ref().map(decode).transpose()?)
            };
            let Some(entry) = resolved? else {
                continue;
            };
            procs.push(entry);
        }
        self.expired(deadline)?;
        proc::require_self(&procs, pid, own.start)?;
        Ok(procs)
    }
}
fn observe_image(entry: ProcInfo) -> Result<Option<ProcInfo>, ProcessError> {
    observe_image_detail(entry).map(|(entry, _)| entry)
}
fn observe_image_detail(entry: ProcInfo) -> Result<(Option<ProcInfo>, Option<i32>), ProcessError> {
    let pid = entry.pid;
    let mut version = None;
    let result = proc::observe_image(
        entry,
        || {
            let id = scupper_darwin::proc_identifier(pid)
                .ok()
                .and_then(|bytes| image::identifier(&bytes).ok());
            version = id.map(|id| id.idversion);
            id
        },
        || {
            scupper_darwin::sysctl_kern_proc_pid(pid)
                .map_err(process_error)?
                .as_ref()
                .map(decode)
                .transpose()
        },
    )?;
    Ok((result, version))
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
            image: None,
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
    fn image_uuid(&mut self, path: &Path, deadline: Deadline) -> Result<[u8; 16], SysError> {
        use std::os::unix::fs::{FileExt, OpenOptionsExt};
        self.expired(deadline)?;
        if !cfg!(target_arch = "aarch64") {
            return Err(SysError::Failed("native: image architecture unsupported"));
        }
        // Darwin O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK; all actual foreign calls remain in sys.rs.
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(0x100 | 0x0100_0000 | 0x4)
            .open(path)
            .map_err(|_| SysError::Failed("native: image open"))?;
        let meta = file
            .metadata()
            .map_err(|_| SysError::Failed("native: image fstat"))?;
        self.expired(deadline)?;
        if !meta.is_file() {
            return Err(SysError::Failed("native: image type"));
        }
        image::read_macho_uuid(meta.len(), |offset, length| {
            self.expired(deadline)?;
            let mut bytes = vec![0; length];
            let mut done = 0;
            while done < length {
                self.expired(deadline)?;
                match file.read_at(&mut bytes[done..], offset + done as u64) {
                    Ok(0) => return Err(SysError::Failed("native: image short read")),
                    Ok(n) => done += n,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(_) => return Err(SysError::Failed("native: image read")),
                }
            }
            self.expired(deadline)?;
            Ok(bytes)
        })
    }

    fn acquire_instance_lock(&mut self) -> Result<(), InstanceLockError> {
        if self.lock.is_some() {
            return Ok(());
        }
        let acquire = || -> Result<std::fs::File, InstanceLockError> {
            validate_ancestors(&self.paths.lock).map_err(InstanceLockError::Failed)?;
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .mode(0o600)
                .custom_flags(0x0100_0000 | 0x100)
                .open(&self.paths.lock)
                .map_err(|_| InstanceLockError::Failed(SysError::Failed("native: lock open")))?;
            let meta = file
                .metadata()
                .map_err(|_| InstanceLockError::Failed(SysError::Failed("native: lock fstat")))?;
            if !valid_lock(meta.is_file(), meta.uid(), meta.mode(), meta.nlink()) {
                return Err(InstanceLockError::Failed(SysError::Failed(
                    "native: lock metadata",
                )));
            }
            match rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive) {
                Ok(()) => Ok(file),
                Err(rustix::io::Errno::WOULDBLOCK) => Err(InstanceLockError::Contended),
                Err(rustix::io::Errno::INTR) => Err(InstanceLockError::Interrupted),
                Err(_) => Err(InstanceLockError::Failed(SysError::Failed("native: flock"))),
            }
        };
        // Deliberately never close this descriptor, even if the adapter is dropped.
        self.lock = Some(ManuallyDrop::new(acquire()?));
        Ok(())
    }
    fn create_control_socket(&mut self) -> Result<(), SysError> {
        use std::os::unix::fs::FileTypeExt;
        if self.lock.is_none() {
            return Err(SysError::Failed("native: socket requires lock"));
        }
        if self.control.is_some() {
            return Ok(());
        }
        validate_ancestors(&self.paths.control)?;
        match std::fs::symlink_metadata(&self.paths.control) {
            Ok(meta) if meta.file_type().is_socket() && meta.uid() == 0 => {
                std::fs::remove_file(&self.paths.control)
                    .map_err(|_| SysError::Failed("native: stale socket unlink"))?;
            }
            Ok(_) => return Err(SysError::Failed("native: unsafe socket path")),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(SysError::Failed("native: socket lstat")),
        }
        let socket = UnixListener::bind(&self.paths.control)
            .map_err(|_| SysError::Failed("native: socket bind"))?;
        socket
            .set_nonblocking(true)
            .map_err(|_| SysError::Failed("native: socket nonblocking"))?;
        self.control = Some(socket);
        Ok(())
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
        pgid: u32,
        expect_pid: u32,
        expect_start: StartTime,
        deadline: Deadline,
    ) -> Result<KillOutcome, SysError> {
        let own = self.incarnation();
        if !crate::platform::group_kill_allowed(pgid, own.pgid)
            || !crate::platform::process_kill_allowed(expect_pid, own.pid)
        {
            return Err(SysError::Failed("native: forbidden group kill"));
        }
        let os_group = crate::platform::checked_os_pid(pgid)
            .ok_or(SysError::Failed("native: invalid pgid"))?;
        crate::platform::checked_os_pid(expect_pid)
            .ok_or(SysError::Failed("native: invalid pid"))?;
        self.expired(deadline)?;
        let all = scupper_darwin::sysctl_kern_proc_all()
            .map_err(|_| SysError::Failed("native: group inventory"))?;
        let live = all.iter().any(|p| p.pgid == os_group && p.stat != 5);
        self.expired(deadline)?;
        if !live {
            return Ok(KillOutcome::Gone);
        }
        // The last syscall before kill is the expected leader's start/group lookup.
        let record = scupper_darwin::sysctl_kern_proc_pid(expect_pid)
            .map_err(|_| SysError::Failed("native: kill recheck"))?;
        let current = record
            .as_ref()
            .map(decode)
            .transpose()
            .map_err(|_| SysError::Failed("native: kill identity"))?;
        if let Some(outcome) = kill_recheck(current.as_ref(), expect_start, Some(pgid)) {
            // A zombie leader may still have live group members.
            if outcome != KillOutcome::Gone || current.is_none() {
                return Ok(outcome);
            }
        }
        map_kill(scupper_darwin::signal_kill(os_group, true))
    }
    fn kill_process(
        &mut self,
        pid: u32,
        expect_start: StartTime,
        deadline: Deadline,
    ) -> Result<KillOutcome, SysError> {
        if !crate::platform::process_kill_allowed(pid, std::process::id()) {
            return Err(SysError::Failed("native: forbidden process kill"));
        }
        let os_pid =
            crate::platform::checked_os_pid(pid).ok_or(SysError::Failed("native: invalid pid"))?;
        self.expired(deadline)?;
        let record = scupper_darwin::sysctl_kern_proc_pid(pid)
            .map_err(|_| SysError::Failed("native: kill recheck"))?;
        let current = record
            .as_ref()
            .map(decode)
            .transpose()
            .map_err(|_| SysError::Failed("native: kill identity"))?;
        if let Some(outcome) = kill_recheck(current.as_ref(), expect_start, None) {
            return Ok(outcome);
        }
        map_kill(scupper_darwin::signal_kill(os_pid, false))
    }
    fn reap_children(&mut self, deadline: Deadline) -> Result<(), SysError> {
        self.expired(deadline)?;
        let mut error = false;
        let end = Duration::from_secs(deadline.0);
        let mut expired = false;
        self.records.reap_children(|r| {
            if scupper_darwin::monotonic_raw() >= end {
                expired = true;
                return crate::platform::runtime::Reap::Pending;
            }
            match r.try_reap() {
                Ok(scupper_darwin::Wait::Pending) => crate::platform::runtime::Reap::Pending,
                Ok(scupper_darwin::Wait::Status(s)) => crate::platform::runtime::Reap::Status(s),
                Ok(scupper_darwin::Wait::NoChild) => crate::platform::runtime::Reap::NoChild,
                Err(_) => {
                    error = true;
                    crate::platform::runtime::Reap::Pending
                }
            }
        });
        if expired {
            return Err(SysError::TimedOut);
        }
        if error {
            Err(SysError::Failed("native: child reap"))
        } else {
            Ok(())
        }
    }
    fn fence(&mut self) -> Fence {
        self.records.fence(scupper_darwin::Spawned::pid)
    }
    fn reap(&mut self, deadline: Deadline) -> Fence {
        while scupper_darwin::monotonic_raw() < Duration::from_secs(deadline.0)
            && !self.records.tools.is_empty()
        {
            self.records.reap_tools(|r| {
                if scupper_darwin::monotonic_raw() < Duration::from_secs(deadline.0) {
                    tool::reap(r)
                } else {
                    crate::platform::runtime::Reap::Pending
                }
            });
            if self.records.tools.is_empty() {
                break;
            }
            self.pause(Duration::from_millis(5), deadline);
        }
        self.fence()
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
    fn check_tools(&mut self, deadline: Deadline) -> Result<(), SysError> {
        for pin in crate::engine::PINNED_TOOLS {
            self.check_pin(Path::new(pin), deadline)?;
        }
        let child = self.child_pin.clone();
        self.check_pin(&child, deadline)
    }
    fn check_pfctl(&mut self, deadline: Deadline) -> Result<(), SysError> {
        self.check_pin(Path::new("/sbin/pfctl"), deadline)
    }
    fn spawned_children(&self) -> &[Child] {
        &self.records.history
    }
    fn spawn(
        &mut self,
        generation: TunnelGeneration,
        attributes: SpawnAttributes,
        deadline: Deadline,
    ) -> Result<Child, SysError> {
        self.expired(deadline)?;
        let own = self.incarnation();
        let own_proc = scupper_darwin::sysctl_kern_proc_pid(own.pid)
            .map_err(|_| SysError::Failed("native: spawn parent"))?
            .ok_or(SysError::Failed("native: spawn parent absent"))?;
        if own.pgid != own.pid
            || own_proc.ppid != 1
            || rustix::process::Pid::as_raw(rustix::process::getppid()) != 1
        {
            return Err(SysError::Failed(
                "native: spawn requires launchd group leader",
            ));
        }
        if !attributes.default_signals
            || !attributes.empty_signal_mask
            || !attributes.cloexec_default
            || !attributes.synchronous
        {
            return Err(SysError::Failed("native: spawn attributes"));
        }
        let pin = self.child_pin.clone();
        self.check_pin(&pin, deadline)?;
        let before = self.executable_id(&pin, deadline).ok();
        let null = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/null")
            .map_err(|_| SysError::Failed("native: child stdio"))?;
        let null = scupper_darwin::high_fd(null.into())
            .map_err(|_| SysError::Failed("native: child stdio fd"))?;
        let actions = [0, 1, 2].map(|target| scupper_darwin::FdAction {
            source: null.as_fd(),
            target,
        });
        self.expired(deadline)?;
        let child = scupper_darwin::spawn_launch(&pin, &CHILD_LAUNCH, &actions)
            .map_err(|_| SysError::Failed("native: child spawn"))?;
        let pid = child.pid();
        self.records.children.push(child);
        let index = self.records.history.len();
        self.records.history.push(Child {
            pid,
            boot: None,
            generation: generation.value(),
            start_time: StartTime {
                seconds: 0,
                microseconds: 0,
            },
            exe: None,
            image: None,
            pgid: own.pgid,
            utun: String::new(),
        });
        self.finish_spawn(index, before, &pin, deadline)
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
            translated: false,
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
            assert!(platform.image_uuid(&link, d).is_err());
            assert!(platform.image_uuid(&root, d).is_err());
            assert!(platform.image_uuid(&pin, d).is_err()); // not Mach-O
            let bytes = include_bytes!("../../tests/fixtures/macos/layout/thin-arm64-header.bin");
            std::fs::write(&pin, bytes)?;
            assert_eq!(platform.image_uuid(&pin, d)?, image::macho_uuid(bytes)?);
            let expired_image = Deadline(platform.now());
            assert_eq!(
                platform.image_uuid(&pin, expired_image),
                Err(SysError::TimedOut)
            );
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

/// Fixed provisional foreground argv/environment. R8 changes this one launch
/// definition for OD5(a), in addition to adding the actual utun fd action.
const CHILD_LAUNCH: scupper_darwin::Launch = scupper_darwin::Launch {
    argv: &[crate::engine::CHILD_PATH, "-f", "utun"],
    env: &scupper_darwin::SPAWN_ENV,
};

/// Root-owned installation digest and vnode. Only qualification can supply it
/// until R5 defines the protected install-record storage reader.
#[derive(Clone, Debug)]
pub struct TrustedExecutable {
    /// Absolute pinned path.
    pub path: PathBuf,
    /// Reviewed vnode identity.
    pub exe: ExeId,
    /// Reviewed SHA256 digest.
    pub sha256: [u8; 32],
}
fn trusted_meta(meta: &std::fs::Metadata) -> bool {
    meta.is_file() && crate::platform::runtime::protected_owner_mode(meta.uid(), meta.mode())
}
fn same_meta(a: &std::fs::Metadata, b: &std::fs::Metadata) -> bool {
    trusted_meta(b)
        && (
            a.dev(),
            a.ino(),
            a.len(),
            a.mode(),
            a.uid(),
            a.mtime(),
            a.mtime_nsec(),
            a.ctime(),
            a.ctime_nsec(),
        ) == (
            b.dev(),
            b.ino(),
            b.len(),
            b.mode(),
            b.uid(),
            b.mtime(),
            b.mtime_nsec(),
            b.ctime(),
            b.ctime_nsec(),
        )
}
fn validate_ancestors(path: &Path) -> Result<(), SysError> {
    if !path.is_absolute()
        || path.components().any(|c| {
            matches!(
                c,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
    {
        return Err(SysError::Failed("native: invalid protected path"));
    }
    for ancestor in path
        .parent()
        .ok_or(SysError::Failed("native: missing parent"))?
        .ancestors()
    {
        let meta = std::fs::symlink_metadata(ancestor)
            .map_err(|_| SysError::Failed("native: ancestor lstat"))?;
        if !meta.is_dir()
            || !crate::platform::runtime::protected_owner_mode(meta.uid(), meta.mode())
        {
            return Err(SysError::Failed("native: unsafe ancestor"));
        }
    }
    Ok(())
}
fn map_kill(result: Result<(), rustix::io::Errno>) -> Result<KillOutcome, SysError> {
    match result {
        Ok(()) => Ok(KillOutcome::Signalled),
        Err(rustix::io::Errno::SRCH) => Ok(KillOutcome::Gone),
        Err(_) => Err(SysError::Failed("native: kill failed")),
    }
}
