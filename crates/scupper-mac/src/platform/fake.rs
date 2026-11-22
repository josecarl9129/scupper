//! Deterministic resource model for the platform contract.
use super::{
    CheapObservation, Child, Collection, Config, ConfigKey, Deadline, Enumeration, ExeId, Fence,
    InstallRecord, KillOutcome, PfInfo, Platform, ProcInfo, ProcState, ProcessError, RefLine,
    Release, Setting, SpawnAttributes, SysError, Timings, Tool, ToolOutcome, Unreaped,
    WriteOutcome,
};
use crate::snapshot::{BootId, COPY_BYTES, Copy, CopyRead, HelperIncarnation, StartTime};
use scupper_core::mac::{
    self, DhcpPhase, HopLimitPolicy, Inputs, PhysicalInterface, Tunnel, TunnelGeneration, parse,
    policy::AnchorText,
    verify::{
        self, AnchorObservation, IdentityEvidence, LiveTree, Normalization, Observations,
        SelectedPath, StepOutcome, ToolIntegrity, Transport,
    },
};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    net::{Ipv4Addr, SocketAddrV4},
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

/// Exact child executable used by the synthetic install.
pub const CHILD_PATH: &str = "/opt/scupper/wireguard-go";
/// Named calls, including identities needed for ordering and signal assertions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Call {
    /// Nonblocking lifetime instance lock.
    AcquireInstanceLock,
    /// Create/unlink the control socket under the lock.
    CreateControlSocket,
    /// Clock read.
    Now,
    /// Boot UUID read.
    BootId,
    /// Own identity read.
    Incarnation,
    /// Setup record read.
    Install,
    /// One copy read.
    Read(Copy),
    /// One copy write.
    Write(Copy),
    /// Exclusive copy creation.
    Create(Copy),
    /// Acquire pf token.
    Acquire,
    /// Emergency enable with the anonymous reference.
    EnablePf,
    /// Release exact pf token.
    Release(u64),
    /// Reference enumeration.
    References,
    /// pf status.
    PfInfo,
    /// Stat a pinned executable.
    ExecutableId,
    /// Parse the pinned executable image.
    ImageUuid,
    /// Process enumeration.
    Processes,
    /// Guarded kill attempt (not necessarily a signal).
    Kill(u32, StartTime),
    /// Guarded individual PID kill.
    KillProcess(u32, StartTime),
    /// Reap foreground children.
    ReapChildren,
    /// Fence observation.
    Fence,
    /// Reap attempt.
    Reap,
    /// Retry pause.
    Pause(Duration),
    /// Anchor write.
    LoadAnchor,
    /// Anchor observation.
    ReadAnchor,
    /// Global state reset.
    Flush,
    /// Scoped state reset.
    InterfaceStates,
    /// Integrity verification.
    CheckTools,
    /// Integrity verification of pfctl alone.
    CheckPfctl,
    /// Child creation.
    Spawn,
    /// Configuration write.
    Configure(ConfigKey),
    /// Configuration observation.
    ReadConfig(ConfigKey),
    /// Child identity check.
    Identity,
    /// Positive monitor.
    Cheap,
    /// Raw observation collection.
    Collect,
    /// Complete live leave-route inventory.
    LeaveRoutes,
    /// Explicit host endpoint cleanup.
    CleanupRoutes(SocketAddrV4),
    /// Fixed DNS cleanup.
    CleanupDns,
    /// Managed run artifact inventory.
    Artifacts,
    /// Run directory cleanup.
    CleanupArtifacts,
    /// Fixed anchor cleanup.
    RemoveAnchor,
    /// Helper death.
    Crash,
    /// New helper incarnation.
    Restart,
    /// External mutation.
    Mutation(Mutation),
    /// Complete a storage write after its timeout.
    CompleteLate(Copy, bool),
    /// Allow stuck tool reaping.
    ReleaseUnreaped,
}
/// One-shot fault, selected by named call and occurrence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    /// Interrupted lock syscall.
    LockInterrupted,
    /// Structural lock error with a bounded diagnostic kind.
    LockTimedOut,
    /// Unclassified structural lock error.
    LockUnknown,
    /// Persist this prefix of the new copy, leaving the old suffix.
    TornWrite(usize),
    /// Failed exclusive create whose cleanup was lost; retain a short crash stub.
    CreateStub {
        /// Visible stub prefix length.
        len: usize,
        /// Whether the failed create's name survives reboot.
        durable_name: bool,
    },
    /// New bytes are lost before sync; return failure.
    LostBeforeSync,
    /// pwrite fails before changing bytes.
    WriteFail,
    /// pwrite lands in pending memory; sync remains outstanding.
    WriteHang,
    /// Storage operation completes after this many 50 ms ticks, across polls.
    StorageDelay(u64),
    /// Returns Failed after new bytes became durable.
    FailedDurable,
    /// Returns Failed with new bytes visible in the page cache.
    FailedPending,
    /// Spawn times out, optionally leaving a child.
    SpawnHang {
        /// Whether a child was created.
        child: bool,
    },
    /// A pin replacement races spawn, which fails or times out after an exec.
    SpawnPinChange {
        /// New pin UUID, or unreadable replacement.
        uuid: Option<[u8; 16]>,
        /// Leave an unconfirmed child and return a timeout.
        timeout: bool,
    },
    /// Entry exits during lookup; own children remain zombies until reaped.
    ExitRace(u32),
    /// Delay process exit by this many 50 ms ticks.
    KillDelay(u64),
    /// Read attempt fails.
    ReadFail,
    /// A successful configuration observation returns no matching setting.
    ReadbackDiffers,
    /// Allocation/write fails without changing bytes.
    NoSpace,
    /// Bounded observation cannot be completed/parsed.
    Incomplete,
    /// PID is reused immediately before the guarded kill.
    PidReused(u32),
    /// Pinned child path is atomically replaced during process enumeration.
    ReplaceExecutable(ExeId),
    /// Group changes during the guard lookup, then changes back before next poll.
    GroupRace,
    /// Spawn/exec fails before any ioctl.
    NotStarted,
    /// Spawn deadline expired before exec; no ioctl and no reference.
    NotStartedTimeout,
    /// A token present at enumeration vanishes just before the release ioctl,
    /// which returns the qualified invalid-token result.
    TokenGoneBeforeRelease,
    /// DIOCSTART adds the anonymous reference while running, then reports EEXIST.
    EnableExists,
    /// Tool exits nonzero after optionally applying its effect.
    ToolFail {
        /// Failure may have applied the mutation.
        effect: bool,
    },
    /// Unreaped tool applies its deferred effect on reap or at a chosen tick.
    ToolLate {
        /// Relative 50 ms ticks after timeout returns; None applies on final reap.
        ticks: Option<u64>,
    },
    /// Tool times out, with optional effect and optional successful reap.
    ToolHang {
        /// Reap succeeded before returning.
        reaped: bool,
        /// Apply the effect before returning Unknown.
        effect: bool,
    },
}
/// Independent changes to the kernel/storage oracle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mutation {
    /// Another holder enables pf with its own token/fingerprint.
    ForeignEnable,
    /// Another actor releases a numeric token.
    ForeignRelease(u64),
    /// DIOCSTOP, invalidating tokens only when the kernel switch models \[X\].
    PfDisable,
    /// Disable on a kernel that retains references, independent of qualification.
    PfDisableKeepTokens,
    /// Remove the loaded anchor independently of the engine.
    AnchorLoss,
    /// Replace Lockdown with a foreign policy.
    AnchorChange,
    /// Refuse pfctl capacity for this many ticks (test-only fence model).
    #[cfg(test)]
    PfctlCapacity(u64),
    /// Arm a foreign write at the next own load's post-load capture.
    #[cfg(test)]
    CaptureRace(bool),
    /// Corrupt a durable byte inside the authenticated portion.
    CopyRot(Copy),
    /// Remove a copy completely.
    MissingCopy(Copy),
    /// Boot UUID cannot be read.
    BootIdUnavailable,
    /// New boot: retain durable copies, lose processes/pf/pending storage.
    Reboot,
}
/// A completed firewall operation, including the state-table generation.
#[cfg(test)]
#[derive(Clone, Debug)]
pub struct FirewallEvent {
    /// Completed operation.
    pub call: Call,
    /// Completion time in model milliseconds.
    pub at: u64,
    /// Kernel anchor after the operation.
    pub anchor: Option<String>,
    /// Kernel pf enablement after the operation.
    pub enabled: bool,
    /// Highest created state generation.
    pub created: u64,
    /// Highest generation removed by a flush.
    pub flushed: u64,
    /// Whether the command returned success.
    pub succeeded: bool,
    /// Whether storage was outstanding at completion.
    pub guarded: bool,
}
/// Physical durable data and volatile, unsynced pwrite contents.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CopyState {
    /// Survives power loss; None means no durable contents yet.
    pub durable: Option<Box<[u8; COPY_BYTES]>>,
    /// Visible page-cache bytes: survive helper death, lost on reboot.
    pub pending: Option<Box<[u8; COPY_BYTES]>>,
    /// Durable length of a short create stub; pending full writes take precedence.
    pub stub_len: Option<usize>,
    /// Failed create name may disappear on reboot until a repair syncs it.
    pub volatile_name: bool,
}
#[derive(Clone, Debug)]
struct Injection {
    call: Call,
    remaining: usize,
    fault: Fault,
    persistent: bool,
}
#[derive(Debug, Default)]
struct InstanceLease {
    locked: Arc<AtomicBool>,
    held: bool,
}
// Ordinary fake clones are independent model universes. competing_instance
// explicitly shares the lock and storage for simultaneous-incarnation tests.
impl Clone for InstanceLease {
    fn clone(&self) -> Self {
        Self::default()
    }
}
impl InstanceLease {
    fn release(&mut self) {
        if self.held {
            self.locked.store(false, Ordering::SeqCst);
            self.held = false;
        }
    }
}
impl Drop for InstanceLease {
    fn drop(&mut self) {
        self.release();
    }
}

/// One shared state for copies, pf, processes and the simplified effect oracle.
#[derive(Clone, Debug)]
#[allow(clippy::struct_excessive_bools)] // Independent external facts, not lifecycle state.
pub struct FakePlatform {
    /// Record firewall ordering and create states under a permissive anchor.
    #[cfg(test)]
    pub model_firewall: bool,
    /// Ordered firewall completions and foreign writes.
    #[cfg(test)]
    pub firewall_events: Vec<FirewallEvent>,
    #[cfg(test)]
    states_created: u64,
    #[cfg(test)]
    states_flushed: u64,
    #[cfg(test)]
    capacity_until: u64,
    #[cfg(test)]
    capture_race: Option<bool>,
    #[cfg(test)]
    capture_at: Option<(Call, usize)>,
    #[cfg(test)]
    capture_before: bool,
    #[cfg(test)]
    captured: Option<Box<Self>>,
    /// Override a complete collection at a verifier boundary.
    #[cfg(test)]
    pub observation_override: Option<Observations>,
    /// Model status changes between the two enablement observations.
    #[cfg(test)]
    pub pf_info_script: VecDeque<PfInfo>,
    /// Model malformed successful acquisition output.
    #[cfg(test)]
    pub acquire_zero: bool,
    // Refuse the next fence after a named observation, independent of other fences.
    #[cfg(test)]
    fence_after: Option<(Call, usize, Fault)>,
    instance: InstanceLease,
    shared_copies: Option<Arc<Mutex<[CopyState; 2]>>>,
    /// Attributes requested for every synchronous foreground spawn.
    pub spawn_attributes: Vec<SpawnAttributes>,
    /// A and B, in writer order.
    pub copies: [CopyState; 2],
    /// Single outstanding write under the fence, global across both copies.
    pub outstanding: Option<Copy>,
    read_pending: Option<(Call, Option<u64>)>,
    // Detached read workers retain their lifetime, but own no write fence/result.
    abandoned_reads: Vec<Option<u64>>,
    write_ready_at: Option<u64>,
    /// pf enablement.
    pub enabled: bool,
    /// Single anonymous enable reference, cleared only by global disable/reboot.
    pub anonymous_enabled: bool,
    /// All references, including foreign holders.
    pub tokens: BTreeMap<u64, RefLine>,
    /// Reissue the lowest freed token value first (default on).
    pub reuse_tokens: bool,
    /// Readable pinned executable stats; removing a path models stat failure.
    pub executables: BTreeMap<std::path::PathBuf, ExeId>,
    /// Synthetic symlink pins; their targets must never supply an executable id.
    pub executable_symlinks: BTreeSet<std::path::PathBuf>,
    /// Kernel switch: disable invalidates tokens under assumption \[X\].
    pub disable_invalidates_tokens: bool,
    /// Stored qualification input for the engine; never consulted here.
    pub x_qualified: bool,
    /// Process table, including self, foreign processes and unreaped zombies.
    pub procs: BTreeMap<u32, ProcInfo>,
    /// Override pin UUID reads, including unknown images.
    pub image_uuids: BTreeMap<std::path::PathBuf, Option<[u8; 16]>>,
    /// Override the next spawned child's observed image.
    pub spawn_image: Option<super::ImageId>,
    /// Processes that ignore kill; their survival prevents confirmation.
    pub unkillable: BTreeSet<u32>,
    /// Outstanding mutating children; only reap closes this incarnation’s fence.
    pub unreaped: Vec<Unreaped>,
    /// Confirmed signals, separate from guarded kill attempts.
    pub signals: Vec<(u32, StartTime)>,
    /// Whether retry pauses advance model time (disable to audit poll scheduling).
    pub pause_advances_clock: bool,
    /// Every Platform call in order; control mutations are included too.
    pub calls: Vec<Call>,
    /// Secret-free startup safety logs.
    pub safety_events: Vec<super::SafetyEvent>,
    scheduled_mutations: BTreeMap<u64, Mutation>,
    /// Firewall qualification independent of the install-record qualification.
    pub firewall_qualification: Option<verify::Qualification>,
    /// Independently readable install/config record.
    pub install: InstallRecord,
    /// Current incarnation, with live boot lookup consistency.
    pub helper: HelperIncarnation,
    /// Current readable boot id.
    pub boot: Option<BootId>,
    /// Fixed helper anchor.
    pub anchor: Option<String>,
    /// Override only the command read-back, retaining the kernel anchor oracle.
    pub anchor_readback: Option<String>,
    /// Command returns no anchor even after a successful own load.
    pub anchor_readback_absent: bool,
    /// One stray kernel write immediately before the next command read-back.
    pub anchor_write_before_readback: Option<String>,
    /// External raw write after returning the first read, before the second.
    pub anchor_write_between_readbacks: Option<String>,
    /// Model time of the latest disabled-to-enabled effect.
    pub pf_enabled_at: Option<u64>,
    /// Most recent external anchor loss, in model seconds.
    pub anchor_lost_at: Option<u64>,
    /// Most recent successful anchor load, in model seconds.
    pub anchor_loaded_at: Option<u64>,
    /// Latest pf disable through any modelled release or external mutation.
    pub pf_disabled_at: Option<u64>,
    /// Report a changing interface inventory during full verification.
    pub inventory_race: bool,
    /// Independently mutable main rules for hook/precedence drift tests.
    pub main_rules: String,
    /// Independently mutable pf skip flags.
    pub skipped: BTreeSet<mac::Interface>,
    /// Global state oracle.
    pub states: Vec<bool>,
    /// Interface-bound state oracle.
    pub interface_states: BTreeMap<PhysicalInterface, Vec<bool>>,
    /// Physical default route, independent of the configured static host route.
    pub default_route_present: bool,
    /// Live typed configuration (including the static host route).
    pub settings: BTreeMap<ConfigKey, Setting>,
    /// Supervised child identities.
    pub children: BTreeMap<u32, Child>,
    /// Managed removable files; the lifetime lock/control socket are separate.
    pub artifacts: BTreeSet<String>,
    /// launchd `AbandonProcessGroup` setting; false kills only the helper group.
    pub abandon_process_group: bool,
    /// Apply a group-killed tool's pending effect at crash (default: true).
    /// False models SIGKILL arriving before its pending kernel mutation.
    pub launchd_kill_applies_pending: bool,
    /// Caller precondition violations, recorded without preventing effects.
    pub violations: Vec<&'static str>,
    spawned_records: Vec<Child>,
    spawned_ever: BTreeSet<(u32, (u64, u32))>,
    reapable: BTreeSet<u32>,
    deferred: BTreeMap<u32, (Effect, Option<u64>)>,
    defer_next: Option<LateWhen>,
    exits: BTreeMap<u32, u64>,
    orphan_zombies: BTreeMap<u32, u64>,
    tick: u64,
    running: bool,
    faults: VecDeque<Injection>,
    millis: u64,
    wall_millis: u64,
    boot_sequence: u64,
    freed_tokens: BTreeSet<u64>,
    next_timestamp: u64,
    next_token: u64,
    next_pid: u32,
}

#[derive(Clone, Debug)]
enum LateWhen {
    Reap,
    Tick(u64),
}

#[derive(Clone, Debug)]
enum Effect {
    EnablePf,
    Acquire(u32),
    Release(u64),
    Anchor(Option<String>),
    Flush,
    InterfaceStates(BTreeSet<PhysicalInterface>),
    Configure(ConfigKey, Setting),
    CleanupRoutes(SocketAddrV4),
    CleanupDns,
}

fn index(copy: Copy) -> usize {
    match copy {
        Copy::A => 0,
        Copy::B => 1,
    }
}
impl FakePlatform {
    /// Build a synthetic, explicitly unqualified host with missing copies.
    ///
    /// # Errors
    /// Invalid synthetic fixture values are returned, never silently qualified.
    pub fn new() -> Result<Self, SysError> {
        Self::fixture().map_err(|_| SysError::Failed("platform fixture"))
    }
    fn fixture() -> Result<Self, mac::Error> {
        let tunnel = Tunnel {
            name: "utun6".parse()?,
            generation: TunnelGeneration::new(1)?,
        };
        let inputs = Inputs::new(
            "en0".parse()?,
            "198.51.100.7:51820".parse()?,
            BTreeMap::from([(
                "en0".parse()?,
                DhcpPhase::Bound {
                    server: "192.0.2.1".parse()?,
                },
            )]),
            tunnel,
            HopLimitPolicy::QualifiedLimitation,
        )?;
        let qualification = verify::Qualification {
            os_build: "synthetic-unqualified".into(),
            main: parse::pf_rules("anchor \"com.apple/*\" all\n")?,
            main_translation: parse::translation("")?,
            siblings: BTreeMap::new(),
            anchor_translation: BTreeMap::new(),
            physical: inputs.physical().keys().cloned().collect(),
            normalization: Normalization {
                expanded_lists: true,
                named_icmp: true,
                implicit_tcp_flags: true,
            },
            hop_limit: HopLimitPolicy::QualifiedLimitation,
        };
        let transport = Transport {
            local_address: Ipv4Addr::new(192, 0, 2, 2),
            endpoint_route: parse::route(
                "route to: 198.51.100.7\ndestination: default\ngateway: 192.0.2.1\ninterface: en0\n",
            )?,
        };
        let boot = Self::boot_uuid(1);
        let helper = HelperIncarnation {
            pid: 100,
            start: StartTime {
                seconds: 100,
                microseconds: 0,
            },
            pgid: 100,
            boot: boot.clone(),
        };
        let own = ProcInfo {
            pid: helper.pid,
            start: helper.start,
            pgid: helper.pgid,
            ppid: 1,
            state: ProcState::Running,
            name: Some("helper".into()),
            path: Some("/opt/scupper/helper".into()),
            exe: Some(ExeId { dev: 1, ino: 1 }),
            image: None,
        };
        Ok(Self {
            #[cfg(test)]
            model_firewall: false,
            #[cfg(test)]
            firewall_events: Vec::new(),
            #[cfg(test)]
            states_created: 0,
            #[cfg(test)]
            states_flushed: 0,
            #[cfg(test)]
            capacity_until: 0,
            #[cfg(test)]
            capture_race: None,
            #[cfg(test)]
            capture_at: None,
            #[cfg(test)]
            capture_before: false,
            #[cfg(test)]
            captured: None,
            #[cfg(test)]
            observation_override: None,
            #[cfg(test)]
            pf_info_script: VecDeque::new(),
            #[cfg(test)]
            acquire_zero: false,
            #[cfg(test)]
            fence_after: None,
            instance: InstanceLease::default(),
            shared_copies: None,
            spawn_attributes: Vec::new(),
            copies: std::array::from_fn(|_| CopyState::default()),
            outstanding: None,
            read_pending: None,
            abandoned_reads: Vec::new(),
            write_ready_at: None,
            enabled: false,
            anonymous_enabled: false,
            tokens: BTreeMap::new(),
            reuse_tokens: true,
            executables: [
                "/opt/scupper/helper",
                CHILD_PATH,
                "/sbin/pfctl",
                "/sbin/route",
                "/usr/sbin/scutil",
                "/sbin/ifconfig",
            ]
            .into_iter()
            .enumerate()
            .map(|(index, path)| {
                (
                    path.into(),
                    ExeId {
                        dev: 1,
                        ino: u64::try_from(index).unwrap_or(0) + 1,
                    },
                )
            })
            .collect(),
            image_uuids: BTreeMap::new(),
            spawn_image: None,
            disable_invalidates_tokens: true,
            executable_symlinks: BTreeSet::new(),
            x_qualified: false,
            procs: {
                let mut procs = BTreeMap::from([(own.pid, own.clone())]);
                for (pid, ppid, seconds, state, path) in [
                    (1, 0, 1, ProcState::Sleeping, Some("/sbin/launchd")),
                    (
                        10,
                        1,
                        50,
                        ProcState::Sleeping,
                        Some("/usr/bin/foreign-sleeper"),
                    ),
                    (
                        11,
                        10,
                        60,
                        ProcState::Stopped,
                        Some("/usr/bin/foreign-stopped"),
                    ),
                    (
                        12,
                        1,
                        99,
                        ProcState::Running,
                        Some("/usr/bin/foreign-orphan"),
                    ),
                    (
                        13,
                        10,
                        101,
                        ProcState::Running,
                        Some("/usr/bin/foreign-new"),
                    ),
                    (
                        14,
                        1,
                        101,
                        ProcState::Sleeping,
                        Some("/usr/bin/foreign-host"),
                    ),
                ] {
                    let mut proc = own.clone();
                    proc.pid = pid;
                    proc.pgid = pid;
                    proc.ppid = ppid;
                    proc.start.seconds = seconds;
                    proc.state = state;
                    proc.path = path.map(Into::into);
                    proc.name = path
                        .and_then(|p| Path::new(p).file_name())
                        .map(|n| n.to_string_lossy().into_owned());
                    proc.exe = Some(ExeId {
                        dev: 99,
                        ino: u64::from(pid),
                    });
                    procs.insert(pid, proc);
                }
                procs
            },
            unkillable: BTreeSet::new(),
            unreaped: Vec::new(),
            signals: Vec::new(),
            calls: Vec::new(),
            pause_advances_clock: true,
            safety_events: Vec::new(),
            scheduled_mutations: BTreeMap::new(),
            firewall_qualification: Some(qualification.clone()),
            install: InstallRecord {
                owner_uid: 501,
                installation: "synthetic-platform".into(),
                config: Config {
                    inputs,
                    qualification,
                    timings: Timings::default(),
                    transport,
                    mtu: 1420,
                    addresses: vec![Ipv4Addr::new(10, 99, 0, 2).into()],
                    dns: vec![Ipv4Addr::new(10, 99, 0, 1).into()],
                },
            },
            helper,
            boot,
            anchor: None,
            anchor_readback: None,
            anchor_readback_absent: false,
            anchor_write_before_readback: None,
            anchor_write_between_readbacks: None,
            pf_enabled_at: None,
            anchor_lost_at: None,
            anchor_loaded_at: None,
            pf_disabled_at: None,
            inventory_race: false,
            main_rules: "anchor \"com.apple/*\" all\n".into(),
            skipped: BTreeSet::new(),
            states: Vec::new(),
            interface_states: BTreeMap::new(),
            default_route_present: true,
            settings: BTreeMap::new(),
            children: BTreeMap::new(),
            artifacts: BTreeSet::new(),
            abandon_process_group: false,
            launchd_kill_applies_pending: true,
            spawned_records: Vec::new(),
            spawned_ever: BTreeSet::new(),
            violations: Vec::new(),
            reapable: BTreeSet::new(),
            deferred: BTreeMap::new(),
            defer_next: None,
            exits: BTreeMap::new(),
            orphan_zombies: BTreeMap::new(),
            tick: 0,
            running: true,
            faults: VecDeque::new(),
            millis: 100_000,
            wall_millis: 100_000,
            boot_sequence: 1,
            freed_tokens: BTreeSet::new(),
            next_timestamp: 0,
            next_token: 900,
            next_pid: 1000,
        })
    }
    fn boot_uuid(sequence: u64) -> Option<BootId> {
        BootId::try_from(format!("00000000-0000-0000-0000-{sequence:012X}").as_str()).ok()
    }
    /// Inject a fault on the nth future matching call (one means next).
    pub fn inject(&mut self, call: Call, nth: usize, fault: Fault) {
        self.faults.push_back(Injection {
            call,
            remaining: nth.max(1),
            fault,
            persistent: false,
        });
    }
    /// Repeat a fault on every matching call until cleared or the helper exits.
    pub fn inject_persistent(&mut self, call: Call, fault: Fault) {
        self.faults.push_back(Injection {
            call,
            remaining: 1,
            fault,
            persistent: true,
        });
    }
    /// Remove injected faults without changing modeled host state.
    pub fn clear_faults(&mut self) {
        self.faults.clear();
        #[cfg(test)]
        {
            self.fence_after = None;
        }
    }
    /// Inject at the first fence after the nth future named observation.
    #[cfg(test)]
    pub fn inject_fence_after(&mut self, call: Call, nth: usize, fault: Fault) {
        self.fence_after = Some((call, nth.max(1), fault));
    }
    fn begin(&mut self, call: Call) -> Option<Fault> {
        #[cfg(test)]
        self.capture_boundary(call, true);
        self.calls.push(call);
        // Read-only calls do not change kernel/storage truth between dispatch
        // and return. Capture their post-read prefix before returning evidence.
        #[cfg(test)]
        if matches!(
            call,
            Call::Install
                | Call::Read(_)
                | Call::References
                | Call::PfInfo
                | Call::ReadAnchor
                | Call::ReadConfig(_)
                | Call::CheckTools
                | Call::CheckPfctl
                | Call::Identity
                | Call::Cheap
                | Call::Collect
                | Call::LeaveRoutes
                | Call::Artifacts
                | Call::Processes
                | Call::ExecutableId
                | Call::ImageUuid
                | Call::Fence
        ) {
            self.capture_completed(call);
        }
        #[cfg(test)]
        if let Some((after, remaining, fault)) = &mut self.fence_after {
            if call == Call::Fence && *remaining == 0 {
                let fault = *fault;
                self.fence_after = None;
                return Some(fault);
            }
            if call == *after {
                *remaining = remaining.saturating_sub(1);
            }
        }
        let position = self.faults.iter().position(|f| f.call == call)?;
        let injection = &mut self.faults[position];
        if injection.persistent {
            return Some(injection.fault);
        }
        injection.remaining -= 1;
        if injection.remaining != 0 {
            return None;
        }
        self.faults.remove(position).map(|f| f.fault)
    }
    fn expired(&self, deadline: Deadline) -> bool {
        self.millis / 1000 >= deadline.0
    }
    fn wait_to(&mut self, deadline: Deadline) {
        let end = deadline.0.saturating_mul(1000);
        while end.saturating_sub(self.millis) >= 50 {
            self.tick();
        }
        self.advance(end.saturating_sub(self.millis));
    }
    fn advance(&mut self, millis: u64) {
        self.millis = self.millis.saturating_add(millis);
        self.wall_millis = self.wall_millis.saturating_add(millis);
    }
    fn process_start(&self) -> StartTime {
        StartTime {
            seconds: self.wall_millis / 1000,
            microseconds: u32::try_from(self.wall_millis % 1000 * 1000).unwrap_or(0),
        }
    }
    fn checked(&mut self, call: Call, deadline: Deadline) -> Result<(), SysError> {
        let fault = self.begin(call);
        if self.expired(deadline) {
            return Err(SysError::TimedOut);
        }
        match fault {
            Some(Fault::ReadbackDiffers) if matches!(call, Call::ReadConfig(_)) => Ok(()),
            Some(Fault::ToolHang { .. } | Fault::WriteHang) => {
                self.wait_to(deadline);
                Err(SysError::TimedOut)
            }
            Some(_) => Err(SysError::Failed("injected observation failure")),
            None => Ok(()),
        }
    }
    fn mutation(
        &mut self,
        call: Call,
        tool: Tool,
        deadline: Deadline,
        stateless: bool,
    ) -> ToolOutcome<()> {
        // Leave deliberately attempts idempotent removal before drainage, but
        // cannot acknowledge Left until the fence closes and cleanup is rechecked.
        let leave_cleanup = matches!(
            call,
            Call::RemoveAnchor | Call::CleanupRoutes(_) | Call::CleanupDns
        ) && self
            .durable_snapshot()
            .is_some_and(|snapshot| snapshot.machine.leaving || snapshot.machine.leave_requested);
        if !stateless && !leave_cleanup && self.unreaped.iter().any(|child| child.tool == tool) {
            self.violations
                .push("mutation before same-family writer reaped");
        }
        let fault = self.begin(call);
        if self.expired(deadline) {
            return ToolOutcome::NotStarted(SysError::TimedOut);
        }
        if fault == Some(Fault::NotStartedTimeout) {
            return ToolOutcome::NotStarted(SysError::TimedOut);
        }
        if fault == Some(Fault::NotStarted) {
            return ToolOutcome::NotStarted(SysError::Failed("exec failed"));
        }
        self.allocate_pid();
        match fault {
            Some(Fault::ToolHang { .. } | Fault::ToolLate { .. }) => {
                let reaped = matches!(fault, Some(Fault::ToolHang { reaped: true, .. }));
                if let Some(Fault::ToolLate { ticks }) = fault {
                    self.defer_next = Some(ticks.map_or(LateWhen::Reap, LateWhen::Tick));
                }
                self.wait_to(deadline);
                if !reaped {
                    let pid = self.next_pid;
                    let path = match tool {
                        Tool::Pfctl => "/sbin/pfctl",
                        Tool::Route => "/sbin/route",
                        Tool::Scutil => "/usr/sbin/scutil",
                        Tool::Ifconfig => "/sbin/ifconfig",
                    };
                    self.procs.insert(
                        pid,
                        ProcInfo {
                            pid,
                            start: self.process_start(),
                            pgid: self.helper.pgid,
                            ppid: self.helper.pid,
                            state: ProcState::Running,
                            name: Path::new(path)
                                .file_name()
                                .map(|n| n.to_string_lossy().into_owned()),
                            path: Some(path.into()),
                            exe: self.executables.get(Path::new(path)).copied(),
                            image: None,
                        },
                    );
                    self.unkillable.insert(pid);
                    self.unreaped.push(Unreaped { tool, pid });
                }
                ToolOutcome::Unknown { reaped }
            }
            Some(Fault::EnableExists) => {
                ToolOutcome::Failed(SysError::Failed("pf already enabled"))
            }
            Some(Fault::TokenGoneBeforeRelease) | None => ToolOutcome::Ok(()),
            Some(_) => ToolOutcome::Failed(SysError::Failed("tool failure")),
        }
    }
    fn apply(&mut self, effect: Effect) {
        match effect {
            Effect::EnablePf => {
                self.anonymous_enabled = true;
                if !self.enabled {
                    self.pf_enabled_at = Some(self.millis / 1000);
                }
                self.enabled = true;
            }
            Effect::Acquire(pid) => {
                self.add_token(pid);
            }
            Effect::Release(token) => {
                self.free_token(token);
                if self.tokens.is_empty() && !self.anonymous_enabled {
                    self.enabled = false;
                    self.pf_disabled_at = Some(self.millis / 1000);
                }
            }
            Effect::Anchor(anchor) => {
                if anchor.is_some() {
                    self.anchor_loaded_at = Some(self.millis / 1000);
                }
                self.anchor = anchor;
            }
            Effect::Flush => {
                #[cfg(test)]
                {
                    self.states_flushed = self.states_created;
                }
                self.states.clear();
                self.interface_states.clear();
            }
            Effect::InterfaceStates(interfaces) => {
                self.interface_states.retain(|i, _| !interfaces.contains(i));
            }
            Effect::Configure(key, value) => {
                self.settings.insert(key, value);
            }
            Effect::CleanupRoutes(endpoint) => {
                if self.settings.get(&ConfigKey::EndpointRoute).is_some_and(|setting| {
                    matches!(setting, Setting::Route { destination, .. } if *destination == std::net::IpAddr::V4(*endpoint.ip()))
                }) { self.settings.remove(&ConfigKey::EndpointRoute); }
                self.settings.remove(&ConfigKey::SplitRoutes);
            }
            Effect::CleanupDns => {
                self.settings.remove(&ConfigKey::Dns);
            }
        }
    }
    fn settle_effect(&mut self, outcome: &ToolOutcome<()>, immediate: bool, effect: Effect) {
        if matches!(outcome, ToolOutcome::Ok(()))
            || (immediate
                && matches!(
                    outcome,
                    ToolOutcome::Failed(_) | ToolOutcome::Unknown { .. }
                ))
        {
            self.apply(effect);
        } else if let Some(when) = self.defer_next.take() {
            let at_tick = match when {
                LateWhen::Reap => None,
                LateWhen::Tick(ticks) => Some(self.tick.saturating_add(ticks)),
            };
            self.deferred.insert(self.next_pid, (effect, at_tick));
        }
    }
    fn effect(
        &mut self,
        call: Call,
        tool: Tool,
        deadline: Deadline,
        effect: Effect,
    ) -> Result<(), SysError> {
        let immediate = self.effect_injected(&call);
        // D-3 explicitly permits exact stateless containment beside stale
        // writers. State flushes were also exempt in the legacy checker.
        let stateless = matches!(effect, Effect::EnablePf | Effect::Flush)
            || matches!(&effect, Effect::Anchor(Some(text)) if text == scupper_core::mac::policy::render_lockdown().as_str());
        let outcome = self.mutation(call, tool, deadline, stateless);
        self.settle_effect(&outcome, immediate, effect);
        #[cfg(test)]
        {
            self.record_firewall(call, matches!(outcome, ToolOutcome::Ok(())));
            self.capture_completed(call);
        }
        match outcome {
            ToolOutcome::Ok(()) => Ok(()),
            ToolOutcome::NotStarted(error) | ToolOutcome::Failed(error) => Err(error),
            ToolOutcome::Unknown { reaped: true } => Err(SysError::TimedOut),
            ToolOutcome::Unknown { reaped: false } => Err(SysError::Unknown),
        }
    }
    fn effect_injected(&self, call: &Call) -> bool {
        self.faults
            .iter()
            .find(|f| &f.call == call)
            .is_some_and(|f| {
                f.remaining == 1
                    && matches!(
                        f.fault,
                        Fault::ToolHang { effect: true, .. }
                            | Fault::ToolFail { effect: true }
                            | Fault::EnableExists
                    )
            })
    }
    fn poll_read(
        &mut self,
        call: Call,
        deadline: Deadline,
    ) -> std::task::Poll<Result<(), SysError>> {
        if let Some((pending, _)) = self.read_pending {
            if pending != call {
                return std::task::Poll::Ready(Err(SysError::Failed("different pending read")));
            }
        } else {
            self.abandoned_reads
                .retain(|ready| ready.is_none_or(|at| self.tick < at));
            if self.abandoned_reads.len() >= 2 {
                return std::task::Poll::Ready(Err(SysError::Failed("storage read busy")));
            }
            let fault = self.begin(call);
            if self.expired(deadline) {
                return std::task::Poll::Ready(Err(SysError::TimedOut));
            }
            let ready = match fault {
                Some(Fault::StorageDelay(ticks)) => Some(self.tick.saturating_add(ticks)),
                Some(Fault::WriteHang | Fault::ToolHang { .. }) => None,
                Some(_) => {
                    return std::task::Poll::Ready(Err(SysError::Failed("storage read failed")));
                }
                None => return std::task::Poll::Ready(Ok(())),
            };
            self.read_pending = Some((call, ready));
        }
        let ready = self.read_pending.and_then(|(_, at)| at);
        while self.millis / 1000 < deadline.0 {
            if ready.is_some_and(|at| self.tick >= at) {
                self.read_pending = None;
                return std::task::Poll::Ready(Ok(()));
            }
            self.tick();
        }
        if ready.is_some_and(|at| self.tick >= at) {
            self.read_pending = None;
            std::task::Poll::Ready(Ok(()))
        } else {
            std::task::Poll::Pending
        }
    }
    fn storage(
        &mut self,
        copy: Copy,
        bytes: &[u8; COPY_BYTES],
        deadline: Deadline,
        create: bool,
    ) -> WriteOutcome {
        self.pull_shared_copies();
        let outcome = self.storage_inner(copy, bytes, deadline, create);
        self.publish_shared_copies();
        #[cfg(test)]
        self.capture_completed(if create {
            Call::Create(copy)
        } else {
            Call::Write(copy)
        });
        outcome
    }
    fn storage_inner(
        &mut self,
        copy: Copy,
        bytes: &[u8; COPY_BYTES],
        deadline: Deadline,
        create: bool,
    ) -> WriteOutcome {
        let fault = self.begin(if create {
            Call::Create(copy)
        } else {
            Call::Write(copy)
        });
        if self.outstanding.is_some() {
            return WriteOutcome::Busy;
        }
        if self.expired(deadline) {
            return WriteOutcome::NotStarted(SysError::TimedOut);
        }
        let slot = &mut self.copies[index(copy)];
        if create && (slot.durable.is_some() || slot.pending.is_some()) {
            return WriteOutcome::Failed(SysError::Failed("copy exists"));
        }
        if !create && slot.durable.is_none() && slot.pending.is_none() {
            return WriteOutcome::Failed(SysError::Failed("copy missing"));
        }
        match fault {
            Some(Fault::CreateStub { len, durable_name }) if create => {
                let length = len.min(COPY_BYTES - 1);
                let mut stub = Box::new([0; COPY_BYTES]);
                stub[..length].copy_from_slice(&bytes[..length]);
                slot.durable = Some(stub);
                slot.stub_len = Some(length);
                slot.volatile_name = !durable_name;
                WriteOutcome::Failed(SysError::Failed("create stub; cleanup lost"))
            }
            Some(Fault::WriteHang | Fault::StorageDelay(_)) => {
                slot.pending = Some(Box::new(*bytes));
                self.outstanding = Some(copy);
                self.write_ready_at = match fault {
                    Some(Fault::StorageDelay(ticks)) => Some(self.tick.saturating_add(ticks)),
                    _ => None,
                };
                self.wait_write(deadline)
            }
            Some(Fault::FailedDurable) => {
                slot.stub_len = None;
                slot.volatile_name = false;
                slot.durable = Some(Box::new(*bytes));
                slot.pending = None;
                WriteOutcome::Failed(SysError::Failed("sync failed after durability"))
            }
            Some(Fault::FailedPending) => {
                slot.pending = Some(Box::new(*bytes));
                WriteOutcome::Failed(SysError::Failed("sync failed with page cache"))
            }
            Some(Fault::TornWrite(prefix)) => {
                let mut torn = slot
                    .durable
                    .clone()
                    .unwrap_or_else(|| Box::new([0; COPY_BYTES]));
                let prefix = prefix.min(COPY_BYTES);
                torn[..prefix].copy_from_slice(&bytes[..prefix]);
                slot.stub_len = slot
                    .stub_len
                    .map(|length| length.max(prefix))
                    .filter(|length| *length < COPY_BYTES);
                slot.durable = Some(torn);
                WriteOutcome::Failed(SysError::Failed("torn write"))
            }
            Some(Fault::LostBeforeSync | Fault::WriteFail | Fault::NoSpace) => {
                slot.pending = None;
                WriteOutcome::Failed(SysError::Failed("write/sync failed"))
            }
            Some(_) => WriteOutcome::Failed(SysError::Failed("storage failure")),
            None => {
                slot.stub_len = None;
                slot.volatile_name = false;
                slot.durable = Some(Box::new(*bytes));
                slot.pending = None;
                WriteOutcome::Synced
            }
        }
    }
    /// Finish only the matching outstanding write. Non-durable completion loses
    /// pending bytes; durable completion survives crash and remains readable.
    pub fn complete_late(&mut self, copy: Copy, durable: bool) {
        self.calls.push(Call::CompleteLate(copy, durable));
        if self.outstanding != Some(copy) {
            return;
        }
        let slot = &mut self.copies[index(copy)];
        let pending = slot.pending.take();
        if durable {
            slot.stub_len = None;
            slot.volatile_name = false;
            slot.durable = pending;
        }
        self.outstanding = None;
        self.write_ready_at = None;
        self.publish_shared_copies();
    }
    #[cfg(test)]
    fn create_permissive_state(&mut self) {
        if self.model_firewall && self.enabled && self.anchor.as_deref() == Some("pass quick all\n")
        {
            self.states.push(true);
            self.states_created += 1;
        }
    }
    #[cfg(test)]
    fn record_firewall(&mut self, call: Call, succeeded: bool) {
        if self.model_firewall {
            self.firewall_events.push(FirewallEvent {
                call,
                at: self.millis,
                anchor: self.anchor.clone(),
                enabled: self.enabled,
                created: self.states_created,
                flushed: self.states_flushed,
                succeeded,
                guarded: self.outstanding.is_some(),
            });
        }
    }
    /// Capture the exact kernel/storage state after a selected boundary, before
    /// the caller can proceed. Restarting the capture models a crash at that point.
    #[cfg(test)]
    pub fn capture_after(&mut self, call: Call, occurrence: usize) {
        self.capture_at = Some((call, occurrence));
        self.capture_before = false;
        self.captured = None;
    }
    #[cfg(test)]
    fn capture_completed(&mut self, call: Call) {
        self.capture_boundary(call, false);
    }
    /// Capture before a call has changed kernel or storage state.
    #[cfg(test)]
    pub fn capture_before(&mut self, call: Call, occurrence: usize) {
        self.capture_at = Some((call, occurrence));
        self.capture_before = true;
        self.captured = None;
    }
    #[cfg(test)]
    fn capture_boundary(&mut self, call: Call, before: bool) {
        if before != self.capture_before {
            return;
        }
        if let Some((target, left)) = &mut self.capture_at
            && *target == call
        {
            *left -= 1;
            if *left == 0 {
                self.capture_at = None;
                self.captured = Some(Box::new(self.clone()));
            }
        }
    }
    #[cfg(test)]
    fn check_release(&mut self, token: u64) {
        use scupper_core::mac::lifecycle::ReferenceEntry;
        if let Some(snapshot) = self.durable_snapshot() {
            let machine = &snapshot.machine;
            // Trusted Left may still contain references awaiting reconciliation.
            if machine.join_intended
                && machine.pf_reference == Some(token)
                && !machine.leaving
                && !machine.leave_requested
            {
                self.violations
                    .push("current reference released before durable Leave");
            }
            if snapshot.references.iter().flatten().any(|entry| {
                entry.key == ReferenceEntry::Token(token)
                    && (self.boot.is_none() || entry.boot.is_none() || entry.boot != self.boot)
            }) {
                self.violations
                    .push("reference released without same-boot evidence");
            }
        }
    }
    fn durable_snapshot(&self) -> Option<crate::snapshot::Snapshot> {
        use crate::snapshot::{CopyClass, classify_copy};
        // Inspect synced bytes independently of the engine's commit cache.
        // A is authoritative when valid; B is the fallback after a torn A.
        self.copies.iter().find_map(|copy| {
            if copy.stub_len.is_some() {
                return None;
            }
            let bytes = copy.durable.as_ref()?;
            match classify_copy(CopyRead::Bytes(bytes.to_vec())) {
                CopyClass::V { snapshot, .. } => Some(snapshot),
                _ => None,
            }
        })
    }
    /// Retrieve a captured prefix; the live fake is otherwise unchanged.
    #[cfg(test)]
    pub fn take_capture(&mut self) -> Option<Self> {
        self.captured.take().map(|capture| *capture)
    }
    /// A second process with the same backing copies and lock. Ordinary Clone
    /// remains an independent model universe for existing crash-prefix fixtures.
    /// Kernel observations are copied; a refused contender cannot mutate them.
    #[must_use]
    pub fn competing_instance(&mut self) -> Self {
        if self.shared_copies.is_none() {
            self.shared_copies = Some(Arc::new(Mutex::new(self.copies.clone())));
        }
        let mut other = self.clone();
        other.instance.locked = Arc::clone(&self.instance.locked);
        other.running = false;
        other.restart();
        other.calls.clear();
        other.signals.clear();
        other
    }
    fn pull_shared_copies(&mut self) {
        if let Some(copies) = &self.shared_copies {
            self.copies.clone_from(
                &copies
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner),
            );
        }
    }
    fn publish_shared_copies(&self) {
        if let Some(copies) = &self.shared_copies {
            copies
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone_from(&self.copies);
        }
    }
    /// Helper death ends its in-process state, retaining kernel state/page cache.
    /// launchd kills killable members of the helper group unless abandoned.
    /// The foreground wireguard-go shares that group and is killed too.
    /// With abandonment (also modelling cleanup still in flight), it survives
    /// in the previous helper's group as an orphan until the start fence.
    pub fn crash(&mut self) {
        self.calls.push(Call::Crash);
        self.read_pending = None;
        self.abandoned_reads.clear();
        self.instance.release();
        // A contender's cached view must never overwrite a live owner's writes.
        self.pull_shared_copies();
        let old = self.helper.clone();
        self.procs.remove(&old.pid);
        let mut pending = Vec::new();
        for proc in self.procs.values_mut() {
            if !self.abandon_process_group
                && proc.pgid == old.pgid
                && proc.state != ProcState::Zombie
                && !self.unkillable.contains(&proc.pid)
            {
                proc.state = ProcState::Zombie;
                if let Some((effect, _)) = self.deferred.remove(&proc.pid)
                    && self.launchd_kill_applies_pending
                {
                    pending.push(effect);
                }
            }
            if proc.ppid == old.pid {
                proc.ppid = 1;
            }
            if proc.ppid == 1 && proc.state == ProcState::Zombie {
                self.orphan_zombies.insert(proc.pid, self.tick + 1);
            }
        }
        for effect in pending {
            self.apply(effect);
        }
        self.unreaped.clear();
        self.reapable.clear();
        self.spawned_records.clear();
        self.children.clear();
        self.outstanding = None;
        self.clear_faults();
        self.defer_next = None;
        self.running = false;
    }
    /// Start a new helper on the same boot, with a new PID/start/group and fence.
    /// May be called directly to model death followed immediately by restart.
    pub fn restart(&mut self) {
        if self.running {
            self.crash();
        }
        self.calls.push(Call::Restart);
        self.advance(1);
        let pid = self.allocate_pid();
        let start = self.process_start();
        self.helper = HelperIncarnation {
            pid,
            pgid: pid,
            start,
            boot: self.boot.clone(),
        };
        self.procs.insert(
            pid,
            ProcInfo {
                pid,
                pgid: pid,
                ppid: 1,
                start,
                state: ProcState::Running,
                name: Some("helper".into()),
                path: Some("/opt/scupper/helper".into()),
                exe: Some(ExeId { dev: 1, ino: 1 }),
                image: None,
            },
        );
        self.running = true;
    }
    /// OS page-cache writeback, independent of a dead helper's storage worker.
    pub fn writeback(&mut self, copy: Copy) {
        let slot = &mut self.copies[index(copy)];
        if let Some(pending) = slot.pending.take() {
            slot.stub_len = None;
            // Data writeback alone does not establish directory-entry durability.
            slot.durable = Some(pending);
        }
        self.publish_shared_copies();
    }
    /// Only mark outstanding tools reapable. The fence remains open until reap.
    pub fn release_unreaped(&mut self) {
        self.calls.push(Call::ReleaseUnreaped);
        self.reapable
            .extend(self.unreaped.iter().map(|child| child.pid));
    }
    /// Finish an orphaned stuck tool, optionally applying its deferred effect.
    /// Exits now; launchd reaps it on the next tick. Current tools use `reap`.
    pub fn orphan_finish(&mut self, pid: u32, apply_effect: bool) {
        if !self.procs.get(&pid).is_some_and(|proc| {
            proc.ppid == 1 && proc.state != ProcState::Zombie && self.unkillable.contains(&pid)
        }) {
            return;
        }
        if let Some((effect, _)) = self.deferred.remove(&pid)
            && apply_effect
        {
            self.apply(effect);
        }
        self.unkillable.remove(&pid);
        self.exits.remove(&pid);
        self.zombie(pid);
    }
    fn zombie(&mut self, pid: u32) {
        // The kernel reparents descendants as soon as their parent exits.
        for proc in self.procs.values_mut() {
            if proc.ppid == pid {
                proc.ppid = 1;
                if proc.state == ProcState::Zombie {
                    self.orphan_zombies.insert(proc.pid, self.tick + 1);
                }
            }
        }
        if let Some(proc) = self.procs.get_mut(&pid) {
            proc.state = ProcState::Zombie;
            if proc.ppid == 1 {
                self.orphan_zombies.insert(pid, self.tick + 1);
            }
        }
        // A process that exited cannot cause a deferred effect.
        self.deferred.remove(&pid);
    }
    /// Schedule foreign interference during a blocking platform call.
    pub fn mutate_after_ticks(&mut self, ticks: u64, mutation: Mutation) {
        self.scheduled_mutations
            .insert(self.tick.saturating_add(ticks), mutation);
    }
    /// Advance one deterministic 50 ms tick, including launchd reaping orphans.
    pub fn tick(&mut self) {
        self.tick += 1;
        self.advance(50);
        self.abandoned_reads
            .retain(|ready| ready.is_none_or(|at| at > self.tick));
        if let Some(mutation) = self.scheduled_mutations.remove(&self.tick) {
            self.mutate(mutation);
        }
        #[cfg(test)]
        {
            self.create_permissive_state();
            if self.tick == self.capacity_until {
                self.record_firewall(Call::Mutation(Mutation::PfctlCapacity(0)), true);
            }
        }
        let exits: Vec<_> = self
            .exits
            .iter()
            .filter(|(_, at)| **at <= self.tick)
            .map(|(pid, _)| *pid)
            .collect();
        for pid in exits {
            self.exits.remove(&pid);
            self.zombie(pid);
        }
        let effects: Vec<_> = self
            .deferred
            .iter()
            .filter(|(_, (_, at))| at.is_some_and(|at| at <= self.tick))
            .map(|(pid, _)| *pid)
            .collect();
        for pid in effects {
            if let Some((effect, _)) = self.deferred.remove(&pid) {
                self.apply(effect);
            }
        }
        let reaped: Vec<_> = self
            .orphan_zombies
            .iter()
            .filter(|(_, at)| **at <= self.tick)
            .map(|(pid, _)| *pid)
            .collect();
        for pid in reaped {
            self.orphan_zombies.remove(&pid);
            self.procs.remove(&pid);
            self.unkillable.remove(&pid);
        }
    }
    /// Apply an external mutation without consulting executor ownership.
    pub fn mutate(&mut self, mutation: Mutation) {
        self.calls.push(Call::Mutation(mutation));
        match mutation {
            Mutation::ForeignEnable => {
                self.add_token(77);
            }
            Mutation::ForeignRelease(token) => {
                self.free_token(token);
                if self.tokens.is_empty() && !self.anonymous_enabled {
                    self.enabled = false;
                    self.pf_disabled_at = Some(self.millis / 1000);
                }
            }
            Mutation::PfDisable => {
                self.anonymous_enabled = false;
                self.enabled = false;
                self.pf_disabled_at = Some(self.millis / 1000);
                if self.disable_invalidates_tokens {
                    self.freed_tokens.extend(self.tokens.keys().copied());
                    self.tokens.clear();
                }
            }
            Mutation::PfDisableKeepTokens => {
                self.anonymous_enabled = false;
                self.enabled = false;
                self.pf_disabled_at = Some(self.millis / 1000);
            }
            Mutation::AnchorLoss => {
                self.anchor_lost_at = Some(self.millis / 1000);
                self.anchor = None;
            }
            Mutation::AnchorChange => {
                self.anchor_lost_at = Some(self.millis / 1000);
                self.anchor = Some("pass quick all\n".into());
            }
            #[cfg(test)]
            Mutation::PfctlCapacity(ticks) => {
                self.capacity_until = self.tick.saturating_add(ticks);
            }
            #[cfg(test)]
            Mutation::CaptureRace(between) => {
                self.capture_race = Some(between);
            }
            Mutation::CopyRot(copy) => {
                if let Some(bytes) = &mut self.copies[index(copy)].durable {
                    bytes[24] ^= 1;
                }
            }
            Mutation::MissingCopy(copy) => {
                self.copies[index(copy)] = CopyState::default();
                // Unlinking a path does not finish its outstanding storage worker.
                // Its eventual sync affects an unlinked inode, not a recreated path.
            }
            Mutation::BootIdUnavailable => {
                self.boot = None;
                self.helper.boot = None;
            }
            Mutation::Reboot => {
                self.crash();
                for slot in &mut self.copies {
                    slot.pending = None;
                    if slot.volatile_name {
                        *slot = CopyState::default();
                    }
                }
                self.anonymous_enabled = false;
                self.boot_sequence += 1;
                self.boot = Self::boot_uuid(self.boot_sequence);
                self.enabled = false;
                self.pf_disabled_at = Some(self.millis / 1000);
                self.tokens.clear();
                self.freed_tokens.clear();
                self.next_token = 900;
                self.next_timestamp = 0;
                self.millis = 0;
                // Process start time is wall time, independent of per-boot now().
                self.wall_millis += 1;
                self.next_pid = 100;
                self.tick = 0;
                self.procs.clear();
                self.children.clear();
                self.unreaped.clear();
                self.unkillable.clear();
                self.anchor = None;
                self.states.clear();
                self.interface_states.clear();
                self.settings.clear();
                self.exits.clear();
                self.orphan_zombies.clear();
                self.deferred.clear();
                self.artifacts.clear();
                self.restart();
            }
        }
        #[cfg(test)]
        {
            self.create_permissive_state();
            self.record_firewall(Call::Mutation(mutation), true);
        }
    }
    fn allocate_pid(&mut self) -> u32 {
        self.next_pid += 1;
        while self.procs.contains_key(&self.next_pid)
            || self.procs.values().any(|proc| proc.pgid == self.next_pid)
        {
            self.next_pid += 1;
        }
        self.next_pid
    }
    fn free_token(&mut self, token: u64) {
        if self.tokens.remove(&token).is_some() {
            self.freed_tokens.insert(token);
        }
    }
    fn add_token(&mut self, pid: u32) -> (u64, u32) {
        #[cfg(test)]
        if self.acquire_zero {
            return (0, pid);
        }
        let token = if self.reuse_tokens {
            self.freed_tokens.pop_first()
        } else {
            None
        }
        .unwrap_or_else(|| {
            self.next_token += 1;
            self.next_token
        });
        // Synthetic subsecond kernel timestamps distinguish immediate reacquires.
        // Like the per-boot clock this sequence resets at Reboot.
        self.next_timestamp = self
            .next_timestamp
            .saturating_add(1)
            .max(self.millis.saturating_mul(1000));
        self.tokens.insert(
            token,
            RefLine {
                token,
                pid,
                timestamp: self.next_timestamp,
            },
        );
        if !self.enabled {
            self.pf_enabled_at = Some(self.millis / 1000);
        }
        self.enabled = true;
        (token, pid)
    }
    #[allow(clippy::similar_names)] // Kernel process/group identifiers.
    fn signal(
        &mut self,
        pgid: u32,
        pid: u32,
        start: StartTime,
        deadline: Deadline,
        group: bool,
    ) -> Result<KillOutcome, SysError> {
        let result = self.signal_inner(pgid, pid, start, deadline, group);
        #[cfg(test)]
        self.capture_completed(if group {
            Call::Kill(pid, start)
        } else {
            Call::KillProcess(pid, start)
        });
        result
    }
    #[allow(clippy::similar_names)] // Kernel process/group identifiers.
    fn signal_inner(
        &mut self,
        pgid: u32,
        pid: u32,
        start: StartTime,
        deadline: Deadline,
        group: bool,
    ) -> Result<KillOutcome, SysError> {
        let call = if group {
            Call::Kill(pid, start)
        } else {
            Call::KillProcess(pid, start)
        };
        let fault = self.begin(call);
        if self.expired(deadline) {
            return Err(SysError::TimedOut);
        }
        if fault == Some(Fault::Incomplete) {
            return Err(SysError::Failed("kill failed"));
        }
        if fault == Some(Fault::WriteHang) {
            self.wait_to(deadline);
            return Err(SysError::TimedOut);
        }
        if let Some(Fault::PidReused(reused)) = fault
            && let Some(proc) = self.procs.get_mut(&reused)
        {
            proc.start.microseconds = (proc.start.microseconds + 1) % 1_000_000;
        }
        if fault == Some(Fault::GroupRace) {
            return Ok(KillOutcome::StartChanged);
        }
        let Some(proc) = self.procs.get(&pid) else {
            return Ok(KillOutcome::Gone);
        };
        if proc.start != start || (group && proc.pgid != pgid) {
            return Ok(KillOutcome::StartChanged);
        }
        if proc.state == ProcState::Zombie
            && (!group
                || !self
                    .procs
                    .values()
                    .any(|member| member.pgid == pgid && member.state != ProcState::Zombie))
        {
            return Ok(KillOutcome::Gone);
        }
        self.signals.push((pid, start));
        let delay = if let Some(Fault::KillDelay(ticks)) = fault {
            ticks.max(1)
        } else {
            1
        };
        for proc in self.procs.values() {
            if ((group && proc.pgid == pgid) || (!group && proc.pid == pid))
                && proc.state != ProcState::Zombie
                && !self.unkillable.contains(&proc.pid)
            {
                self.exits.insert(proc.pid, self.tick + delay);
            }
        }
        Ok(KillOutcome::Signalled)
    }
    fn child_alive(&self, child: &Child) -> bool {
        self.children.get(&child.pid) == Some(child)
            && self.procs.get(&child.pid).is_some_and(|proc| {
                proc.start == child.start_time
                    && proc.state != ProcState::Zombie
                    && proc.pgid == child.pgid
                    && proc.path.as_deref() == Some(std::path::Path::new(CHILD_PATH))
            })
    }
}

impl Platform for FakePlatform {
    fn report_safety(&mut self, event: super::SafetyEvent) {
        self.safety_events.push(event);
    }
    fn acquire_instance_lock(&mut self) -> Result<(), super::InstanceLockError> {
        match self.begin(Call::AcquireInstanceLock) {
            Some(Fault::LockInterrupted) => return Err(super::InstanceLockError::Interrupted),
            Some(Fault::LockTimedOut) => {
                return Err(super::InstanceLockError::Failed(SysError::TimedOut));
            }
            Some(Fault::LockUnknown) => {
                return Err(super::InstanceLockError::Failed(SysError::Unknown));
            }
            Some(_) => {
                return Err(super::InstanceLockError::Failed(SysError::Failed(
                    "instance lock",
                )));
            }
            None => {}
        }
        if self.instance.held {
            return Ok(());
        }
        if self
            .instance
            .locked
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err(super::InstanceLockError::Contended);
        }
        self.instance.held = true;
        self.pull_shared_copies();
        Ok(())
    }
    fn create_control_socket(&mut self) -> Result<(), SysError> {
        if !self.instance.held {
            return Err(SysError::Failed("socket without instance lock"));
        }
        if self.begin(Call::CreateControlSocket).is_some() {
            return Err(SysError::Failed("control socket"));
        }
        Ok(())
    }

    fn reference_qualification(&self) -> super::ReferenceQualification {
        super::ReferenceQualification {
            disable_voids_references: self.x_qualified,
            fingerprints: true,
        }
    }
    fn now(&mut self) -> u64 {
        self.calls.push(Call::Now);
        self.millis / 1000
    }
    fn boot_id(&mut self) -> Option<BootId> {
        self.calls.push(Call::BootId);
        self.boot.clone()
    }
    fn incarnation(&mut self) -> HelperIncarnation {
        self.calls.push(Call::Incarnation);
        self.helper.clone()
    }
    fn read_install_record(&mut self, deadline: Deadline) -> Result<InstallRecord, SysError> {
        match self.poll_install_record(deadline) {
            std::task::Poll::Ready(result) => result,
            std::task::Poll::Pending => {
                self.abandon_storage_read();
                Err(SysError::TimedOut)
            }
        }
    }
    fn read_copy(&mut self, copy: Copy, deadline: Deadline) -> CopyRead {
        match self.poll_copy(copy, deadline) {
            std::task::Poll::Ready(result) => result,
            std::task::Poll::Pending => {
                self.abandon_storage_read();
                CopyRead::Unreadable
            }
        }
    }
    fn poll_install_record(
        &mut self,
        deadline: Deadline,
    ) -> std::task::Poll<Result<InstallRecord, SysError>> {
        self.poll_read(Call::Install, deadline)
            .map(|result| result.map(|()| self.install.clone()))
    }
    fn poll_copy(&mut self, copy: Copy, deadline: Deadline) -> std::task::Poll<CopyRead> {
        self.poll_read(Call::Read(copy), deadline).map(|result| {
            if result.is_err() {
                return CopyRead::Unreadable;
            }
            self.pull_shared_copies();
            let slot = &self.copies[index(copy)];
            slot.pending
                .as_ref()
                .or(slot.durable.as_ref())
                .map_or(CopyRead::Missing, |bytes| {
                    let mut bytes = bytes.to_vec();
                    if let Some(length) = slot.stub_len.filter(|_| slot.pending.is_none()) {
                        bytes[length..].fill(0);
                        CopyRead::Short(bytes)
                    } else {
                        CopyRead::Bytes(bytes)
                    }
                })
        })
    }
    fn abandon_storage_read(&mut self) {
        if let Some((_, ready)) = self.read_pending.take() {
            self.abandoned_reads.push(ready);
        }
    }
    fn wait_write(&mut self, deadline: Deadline) -> WriteOutcome {
        let Some(copy) = self.outstanding else {
            return WriteOutcome::Failed(SysError::Failed("no outstanding write"));
        };
        while self.millis / 1000 < deadline.0 {
            if self.write_ready_at.is_some_and(|at| self.tick >= at) {
                self.complete_late(copy, true);
                return WriteOutcome::Synced;
            }
            self.tick();
        }
        if self.write_ready_at.is_some_and(|at| self.tick >= at) {
            self.complete_late(copy, true);
            WriteOutcome::Synced
        } else {
            WriteOutcome::TimedOut
        }
    }
    fn write_copy(
        &mut self,
        copy: Copy,
        bytes: &[u8; COPY_BYTES],
        deadline: Deadline,
    ) -> WriteOutcome {
        self.storage(copy, bytes, deadline, false)
    }
    fn create_copy(
        &mut self,
        copy: Copy,
        bytes: &[u8; COPY_BYTES],
        deadline: Deadline,
    ) -> WriteOutcome {
        self.storage(copy, bytes, deadline, true)
    }
    fn enable_pf(&mut self, deadline: Deadline) -> Result<super::PfEnable, SysError> {
        let running = self.enabled;
        match self.effect(Call::EnablePf, Tool::Pfctl, deadline, Effect::EnablePf) {
            Ok(()) if running => Ok(super::PfEnable::AlreadyRunning),
            Ok(()) => Ok(super::PfEnable::Started),
            Err(SysError::Failed("pf already enabled")) => Ok(super::PfEnable::AlreadyRunning),
            Err(error) => Err(error),
        }
    }
    fn acquire(&mut self, deadline: Deadline) -> ToolOutcome<(u64, u32)> {
        let immediate = self.effect_injected(&Call::Acquire);
        let outcome = self.mutation(Call::Acquire, Tool::Pfctl, deadline, false);
        let pid = self.next_pid;
        let result = match outcome {
            ToolOutcome::Ok(()) => ToolOutcome::Ok(self.add_token(pid)),
            ToolOutcome::NotStarted(e) => ToolOutcome::NotStarted(e),
            ToolOutcome::Failed(e) => {
                self.settle_effect(
                    &ToolOutcome::Failed(e.clone()),
                    immediate,
                    Effect::Acquire(pid),
                );
                ToolOutcome::Failed(e)
            }
            ToolOutcome::Unknown { reaped } => {
                self.settle_effect(
                    &ToolOutcome::Unknown { reaped },
                    immediate,
                    Effect::Acquire(pid),
                );
                ToolOutcome::Unknown { reaped }
            }
        };
        #[cfg(test)]
        self.capture_completed(Call::Acquire);
        result
    }
    fn release(&mut self, token: u64, deadline: Deadline) -> ToolOutcome<Release> {
        #[cfg(test)]
        self.check_release(token);
        let call = Call::Release(token);
        let vanished = self
            .faults
            .iter()
            .find(|f| f.call == call)
            .is_some_and(|f| f.remaining == 1 && f.fault == Fault::TokenGoneBeforeRelease);
        let immediate = self.effect_injected(&call);
        let outcome = self.mutation(call, Tool::Pfctl, deadline, false);
        if vanished {
            self.free_token(token);
        }
        let existed = self.tokens.contains_key(&token);
        self.settle_effect(&outcome, immediate, Effect::Release(token));
        #[cfg(test)]
        self.capture_completed(call);
        match outcome {
            ToolOutcome::Ok(()) => ToolOutcome::Ok(if existed {
                Release::Released
            } else {
                Release::TokenInvalid
            }),
            ToolOutcome::NotStarted(e) => ToolOutcome::NotStarted(e),
            ToolOutcome::Failed(e) => ToolOutcome::Failed(e),
            ToolOutcome::Unknown { reaped } => ToolOutcome::Unknown { reaped },
        }
    }
    fn references(&mut self, deadline: Deadline) -> Enumeration<Vec<RefLine>> {
        match self.checked(Call::References, deadline) {
            Ok(()) => Enumeration::Complete(self.tokens.values().cloned().collect()),
            Err(e) => Enumeration::Incomplete(e),
        }
    }
    fn pf_info(&mut self, deadline: Deadline) -> PfInfo {
        #[cfg(test)]
        if let Some(info) = self.pf_info_script.pop_front() {
            self.calls.push(Call::PfInfo);
            return info;
        }
        match self.checked(Call::PfInfo, deadline) {
            Ok(()) if self.enabled => PfInfo::Enabled,
            Ok(()) => PfInfo::Disabled,
            Err(e) => PfInfo::Incomplete(e),
        }
    }
    fn processes(&mut self, deadline: Deadline) -> Enumeration<Vec<ProcInfo>, ProcessError> {
        let fault = self.begin(Call::Processes);
        if self.expired(deadline) {
            return Enumeration::Incomplete(SysError::TimedOut.into());
        }
        match fault {
            Some(Fault::ToolHang { .. } | Fault::WriteHang) => {
                self.wait_to(deadline);
                return Enumeration::Incomplete(SysError::TimedOut.into());
            }
            Some(Fault::ReplaceExecutable(exe)) => {
                self.executables.insert(CHILD_PATH.into(), exe);
            }
            Some(Fault::ExitRace(pid)) => {
                let own_child = self
                    .procs
                    .get(&pid)
                    .is_some_and(|proc| proc.ppid == self.helper.pid);
                self.zombie(pid);
                if !own_child {
                    self.procs.remove(&pid);
                    self.orphan_zombies.remove(&pid);
                }
                self.exits.remove(&pid);
            }
            Some(_) => {
                return Enumeration::Incomplete(
                    SysError::Failed("process enumeration failed").into(),
                );
            }
            None => {}
        }
        if let Some(proc) = self.procs.values().find(|proc| {
            proc.pid != 0
                && proc.state != ProcState::Zombie
                && proc.path.is_none()
                && proc
                    .image
                    .is_none_or(|image| image.uuid == [0; 16] || image.uniqueid == 0)
        }) {
            return Enumeration::Incomplete(ProcessError {
                pid: Some(proc.pid),
                error: SysError::Failed("live process executable unreadable"),
            });
        }
        Enumeration::Complete(
            self.procs
                .values()
                .filter(|proc| proc.pid != 0)
                .cloned()
                .collect(),
        )
    }
    fn image_uuid(&mut self, path: &Path, deadline: Deadline) -> Result<[u8; 16], SysError> {
        self.checked(Call::ImageUuid, deadline)?;
        if self.executable_symlinks.contains(path) {
            return Err(SysError::Failed("symlink executable pin"));
        }
        let uuid = match self.image_uuids.get(path) {
            Some(uuid) => *uuid,
            None => self.executables.get(path).map(|exe| {
                let mut uuid = [1; 16];
                uuid[..8].copy_from_slice(&exe.ino.to_le_bytes());
                uuid
            }),
        };
        uuid.filter(|uuid| *uuid != [0; 16])
            .ok_or(SysError::Failed("pin UUID unknown"))
    }
    fn executable_id(&mut self, path: &Path, deadline: Deadline) -> Result<ExeId, SysError> {
        self.checked(Call::ExecutableId, deadline)?;
        if self.executable_symlinks.contains(path) {
            return Err(SysError::Failed("symlink executable pin"));
        }
        self.executables
            .get(path)
            .copied()
            .ok_or(SysError::Failed("stat executable"))
    }
    fn kill_group(
        &mut self,
        pgid: u32,
        expect_pid: u32,
        start: StartTime,
        deadline: Deadline,
    ) -> Result<KillOutcome, SysError> {
        if !super::group_kill_allowed(pgid, self.helper.pgid)
            || super::checked_os_pid(pgid).is_none()
            || !super::process_kill_allowed(expect_pid, self.helper.pid)
        {
            return Err(SysError::Failed("unsafe process group"));
        }
        self.signal(pgid, expect_pid, start, deadline, true)
    }
    fn kill_process(
        &mut self,
        pid: u32,
        start: StartTime,
        deadline: Deadline,
    ) -> Result<KillOutcome, SysError> {
        if !super::process_kill_allowed(pid, self.helper.pid)
            || super::checked_os_pid(pid).is_none()
        {
            return Err(SysError::Failed("unsafe process id"));
        }
        self.signal(0, pid, start, deadline, false)
    }
    fn reap_children(&mut self, deadline: Deadline) -> Result<(), SysError> {
        self.checked(Call::ReapChildren, deadline)?;
        let own = self.helper.pid;

        self.procs.retain(|pid, proc| {
            !(proc.ppid == own
                && proc.state == ProcState::Zombie
                && self.children.contains_key(pid))
        });
        self.children.retain(|pid, _| self.procs.contains_key(pid));
        #[cfg(test)]
        self.capture_completed(Call::ReapChildren);
        Ok(())
    }
    fn fence(&mut self) -> Fence {
        if self.begin(Call::Fence) == Some(Fault::Incomplete) {
            return Fence::Open(vec![
                Unreaped {
                    tool: Tool::Pfctl,
                    pid: 8001,
                },
                Unreaped {
                    tool: Tool::Pfctl,
                    pid: 8002,
                },
            ]);
        }
        #[cfg(test)]
        if self.tick < self.capacity_until {
            return Fence::Open(vec![
                Unreaped {
                    tool: Tool::Pfctl,
                    pid: 8001,
                },
                Unreaped {
                    tool: Tool::Pfctl,
                    pid: 8002,
                },
            ]);
        }
        if self.unreaped.is_empty() {
            Fence::Closed
        } else {
            Fence::Open(self.unreaped.clone())
        }
    }
    fn reap(&mut self, deadline: Deadline) -> Fence {
        #[cfg(test)]
        self.capture_boundary(Call::Reap, true);
        self.calls.push(Call::Reap);
        loop {
            if self.expired(deadline) {
                return self.fence();
            }
            let ready: Vec<_> = self
                .unreaped
                .iter()
                .filter(|child| {
                    self.reapable.contains(&child.pid)
                        || self
                            .procs
                            .get(&child.pid)
                            .is_none_or(|proc| proc.state == ProcState::Zombie)
                })
                .map(|child| child.pid)
                .collect();
            for pid in &ready {
                if let Some((effect, _)) = self.deferred.remove(pid)
                    && self
                        .procs
                        .get(pid)
                        .is_some_and(|proc| proc.state != ProcState::Zombie)
                {
                    self.apply(effect);
                }
                self.procs.remove(pid);
                self.unkillable.remove(pid);
                self.reapable.remove(pid);
                self.exits.remove(pid);
            }
            self.unreaped.retain(|child| !ready.contains(&child.pid));
            if self.unreaped.is_empty() {
                let fence = self.fence();
                #[cfg(test)]
                self.capture_completed(Call::Reap);
                return fence;
            }
            let end = deadline.0.saturating_mul(1000);
            let remaining = end.saturating_sub(self.millis);
            if remaining == 0 {
                return self.fence();
            }
            if remaining < 50 {
                self.advance(remaining);
            } else {
                self.tick();
            }
        }
    }
    fn pause(&mut self, duration: Duration, deadline: Deadline) {
        self.calls.push(Call::Pause(duration));
        if !self.pause_advances_clock {
            return;
        }
        let remaining = deadline.0.saturating_mul(1000).saturating_sub(self.millis);
        let millis = u64::try_from(duration.as_millis())
            .unwrap_or(u64::MAX)
            .min(remaining);
        for _ in 0..millis / 50 {
            self.tick();
        }
        self.advance(millis % 50);
    }
    fn load_anchor(&mut self, text: &AnchorText, deadline: Deadline) -> Result<(), SysError> {
        #[cfg(test)]
        if let Some(between) = self.capture_race.take() {
            if between {
                self.anchor_write_between_readbacks = Some("pass quick all\n".into());
            } else {
                self.anchor_write_before_readback = Some("pass quick all\n".into());
            }
        }
        self.effect(
            Call::LoadAnchor,
            Tool::Pfctl,
            deadline,
            Effect::Anchor(Some(text.as_str().into())),
        )
    }
    fn read_anchor(&mut self, deadline: Deadline) -> Result<Option<String>, SysError> {
        self.checked(Call::ReadAnchor, deadline)?;
        if let Some(text) = self.anchor_write_before_readback.take() {
            self.anchor = Some(text);
            #[cfg(test)]
            {
                self.create_permissive_state();
                self.record_firewall(Call::Mutation(Mutation::AnchorChange), true);
            }
        }
        let observed = if self.anchor_readback_absent {
            None
        } else {
            self.anchor_readback.clone().or_else(|| self.anchor.clone())
        };
        if let Some(text) = self.anchor_write_between_readbacks.take() {
            self.anchor = Some(text);
            #[cfg(test)]
            {
                self.create_permissive_state();
                self.record_firewall(Call::Mutation(Mutation::AnchorChange), true);
            }
        }
        Ok(observed)
    }
    fn flush_states(&mut self, deadline: Deadline) -> Result<(), SysError> {
        self.effect(Call::Flush, Tool::Pfctl, deadline, Effect::Flush)
    }
    fn remove_interface_states(
        &mut self,
        interfaces: &BTreeSet<PhysicalInterface>,
        deadline: Deadline,
    ) -> Result<(), SysError> {
        self.effect(
            Call::InterfaceStates,
            Tool::Pfctl,
            deadline,
            Effect::InterfaceStates(interfaces.clone()),
        )
    }
    fn check_tools(&mut self, deadline: Deadline) -> Result<(), SysError> {
        self.checked(Call::CheckTools, deadline)?;
        if !self.executable_symlinks.is_empty() {
            return Err(SysError::Failed("symlink executable pin"));
        }
        Ok(())
    }
    fn check_pfctl(&mut self, deadline: Deadline) -> Result<(), SysError> {
        self.checked(Call::CheckPfctl, deadline)?;
        let path = Path::new("/sbin/pfctl");
        if self.executable_symlinks.contains(path) || !self.executables.contains_key(path) {
            return Err(SysError::Failed("pfctl pin unavailable"));
        }
        Ok(())
    }
    fn spawned_children(&self) -> &[Child] {
        &self.spawned_records
    }
    fn spawn(
        &mut self,
        generation: TunnelGeneration,
        attributes: SpawnAttributes,
        deadline: Deadline,
    ) -> Result<Child, SysError> {
        let fault = match self.begin(Call::Spawn) {
            Some(Fault::SpawnPinChange { uuid, timeout }) => {
                self.image_uuids.insert(CHILD_PATH.into(), uuid);
                Some(if timeout {
                    Fault::SpawnHang { child: true }
                } else {
                    Fault::ReadFail
                })
            }
            fault => fault,
        };
        self.spawn_attributes.push(attributes);
        if self.expired(deadline) {
            return Err(SysError::TimedOut);
        }
        if matches!(fault, Some(Fault::SpawnHang { child: false })) {
            self.wait_to(deadline);
            return Err(SysError::TimedOut);
        }
        if fault.is_some() && !matches!(fault, Some(Fault::SpawnHang { child: true })) {
            return Err(SysError::Failed("spawn failed"));
        }
        if self.procs.values().any(|proc| {
            self.spawned_ever
                .contains(&(proc.pid, super::start_key(proc.start)))
                && proc.state != ProcState::Zombie
        }) {
            self.violations.push("spawn before confirmed sweep");
        }
        let pid = self.allocate_pid();
        let start = self.process_start();
        let image = self.spawn_image.take().or_else(|| {
            let uuid = self.image_uuid(Path::new(CHILD_PATH), deadline).ok()?;
            Some(super::ImageId {
                uuid,
                uniqueid: u64::from(pid),
            })
        });
        let child = Child {
            boot: self.boot.clone(),
            generation: generation.value(),
            pid,
            start_time: start,
            exe: self.executables.get(Path::new(CHILD_PATH)).copied(),
            image,
            pgid: self.helper.pgid,
            utun: "utun6".into(),
        };
        self.procs.insert(
            pid,
            ProcInfo {
                pid,
                start,
                pgid: self.helper.pgid,
                ppid: self.helper.pid,
                state: ProcState::Running,
                name: Some("wireguard-go".into()),
                path: Some(CHILD_PATH.into()),
                exe: self.executables.get(Path::new(CHILD_PATH)).copied(),
                image,
            },
        );
        self.children.insert(pid, child.clone());
        self.spawned_records.push(child.clone());
        self.spawned_ever.insert((pid, super::start_key(start)));
        #[cfg(test)]
        self.capture_completed(Call::Spawn);
        if fault.is_some() {
            self.wait_to(deadline);
            return Err(SysError::TimedOut);
        }
        Ok(child)
    }
    fn configure(
        &mut self,
        key: ConfigKey,
        value: &Setting,
        deadline: Deadline,
    ) -> Result<(), SysError> {
        let tool = match key {
            ConfigKey::Uapi => {
                self.checked(Call::Configure(key), deadline)?;
                self.settings.insert(key, value.clone());
                #[cfg(test)]
                self.capture_completed(Call::Configure(key));
                return Ok(());
            }
            ConfigKey::Dns => Tool::Scutil,
            ConfigKey::EndpointRoute | ConfigKey::SplitRoutes => Tool::Route,
            ConfigKey::Addresses | ConfigKey::Mtu => Tool::Ifconfig,
        };
        self.effect(
            Call::Configure(key),
            tool,
            deadline,
            Effect::Configure(key, value.clone()),
        )
    }
    fn read_config(
        &mut self,
        key: ConfigKey,
        deadline: Deadline,
    ) -> Result<Option<Setting>, SysError> {
        let differs = self
            .faults
            .iter()
            .find(|f| f.call == Call::ReadConfig(key))
            .is_some_and(|f| f.remaining == 1 && f.fault == Fault::ReadbackDiffers);
        self.checked(Call::ReadConfig(key), deadline)?;
        if differs {
            return Ok(None);
        }
        Ok(self.settings.get(&key).cloned())
    }
    fn identity(&mut self, child: &Child, deadline: Deadline) -> Result<Tunnel, SysError> {
        self.checked(Call::Identity, deadline)?;
        if !self.child_alive(child) {
            return Err(SysError::Failed("stale child identity"));
        }
        Ok(Tunnel {
            name: child.utun.parse().map_err(|_| SysError::Failed("utun"))?,
            generation: TunnelGeneration::new(child.generation)
                .map_err(|_| SysError::Failed("generation"))?,
        })
    }
    fn cheap_check(
        &mut self,
        child: Option<&Child>,
        deadline: Deadline,
    ) -> Result<CheapObservation, SysError> {
        self.checked(Call::Cheap, deadline)?;
        Ok(CheapObservation {
            pf_enabled: self.enabled,
            anchor_present: self.anchor.is_some()
                && self.main_rules.contains("anchor \"com.apple/*\""),
            child_alive: child.is_some_and(|c| self.child_alive(c)),
            route_present: self.settings.contains_key(&ConfigKey::EndpointRoute),
        })
    }
    fn collect(
        &mut self,
        collection: &Collection,
        deadline: Deadline,
    ) -> Result<Observations, SysError> {
        self.checked(Call::Collect, deadline)?;
        #[cfg(test)]
        if let Some(observation) = &self.observation_override {
            return Ok(observation.clone());
        }
        let inventory = parse::anchor_list("com.apple/scupper\n")
            .map_err(|_| SysError::Failed("inventory fixture"))?;
        let tree = LiveTree {
            before: inventory.clone(),
            after: inventory,
            complete: true,
            anchors: BTreeMap::from([(
                "com.apple/scupper".into(),
                AnchorObservation {
                    rules: parse::pf_rules(self.anchor.as_deref().unwrap_or("")),
                    translation: parse::translation(""),
                },
            )]),
        };
        let interfaces =
            parse::ifconfig_list(if self.children.values().any(|c| self.child_alive(c)) {
                "lo0 en0 utun6\n"
            } else {
                "lo0 en0\n"
            })
            .map_err(|_| SysError::Failed("interfaces fixture"))?;
        Ok(Observations {
            started_at: verify::required_reads(&tree)
                .into_iter()
                .map(|r| (r, self.millis / 1000))
                .collect(),
            states: if self.states.iter().any(|permissive| *permissive)
                || self
                    .interface_states
                    .values()
                    .flatten()
                    .any(|permissive| *permissive)
            {
                verify::StateEvidence::Unproven
            } else {
                collection.states.clone()
            },
            os_build: self.install.config.qualification.os_build.clone(),
            pf: Ok(parse::PfInfo {
                enabled: self.enabled,
            }),
            anchor: self.anchor.as_deref().map(parse::pf_rules).transpose(),
            main: parse::pf_rules(&self.main_rules),
            translation: parse::translation(""),
            live_tree: Ok(tree),
            skips: Ok(interfaces
                .iter()
                .filter(|i| !self.inventory_race || i.is_loopback())
                .cloned()
                .map(|i| {
                    let skip = self.skipped.contains(&i);
                    (i, skip)
                })
                .collect()),
            interfaces: Ok(interfaces),
            dns: parse::dns(include_str!("../../tests/fixtures/dns.txt")),
            local_address: Ok(self.install.config.transport.local_address),
            // Static host routes beat tunnel split routes. Without either, the
            // physical default route is usable; anchor text cannot create routes.
            route: if self.settings.contains_key(&ConfigKey::EndpointRoute)
                || (self.default_route_present
                    && !self.settings.contains_key(&ConfigKey::SplitRoutes))
            {
                Ok(self.install.config.transport.endpoint_route.clone())
            } else {
                Err(mac::Error("endpoint route missing"))
            },
            policy_inputs: Ok(collection.inputs.clone()),
            identity: collection
                .child
                .as_ref()
                .filter(|c| {
                    self.child_alive(c)
                        && c.generation == collection.inputs.tunnel().generation.value()
                        && c.utun == collection.inputs.tunnel().name.to_string()
                })
                .map_or(IdentityEvidence::LostOrStale, |_| {
                    IdentityEvidence::CurrentGeneration(collection.inputs.tunnel().clone())
                }),
            selected_path: SelectedPath::Selected,
            tool_integrity: ToolIntegrity::Match,
            external_hop_limit_verified: false,
            step: if self.unreaped.is_empty() {
                StepOutcome::Complete
            } else {
                StepOutcome::Failed("unreaped tool")
            },
        })
    }
    fn firewall_qualification(&self) -> Option<verify::Qualification> {
        self.firewall_qualification.clone()
    }
    fn collect_lockdown(
        &mut self,
        context: verify::Context,
        states: verify::StateEvidence,
        deadline: Deadline,
    ) -> Result<Observations, SysError> {
        let collection = Collection {
            context,
            states,
            inputs: self.install.config.inputs.clone(),
            child: None,
        };
        let mut observation = self.collect(&collection, deadline)?;
        let required = verify::required_lockdown_reads(
            observation
                .live_tree
                .as_ref()
                .map_err(|_| SysError::Failed("global tree incomplete"))?,
        );
        observation
            .started_at
            .retain(|key, _| required.contains(key));
        observation.policy_inputs = Err(mac::Error("no installation inputs"));
        observation.route = Err(mac::Error("no endpoint"));
        observation.local_address = Err(mac::Error("no selected address"));
        observation.dns = Err(mac::Error("no DNS expectation"));
        Ok(observation)
    }
    fn leave_routes(
        &mut self,
        endpoint: Option<SocketAddrV4>,
        deadline: Deadline,
    ) -> Result<super::LeaveRoutes, SysError> {
        self.checked(Call::LeaveRoutes, deadline)?;
        Ok(super::LeaveRoutes {
            split_owned: self.settings.contains_key(&ConfigKey::SplitRoutes),
            endpoint_host: endpoint.is_some_and(|endpoint| self.settings.get(&ConfigKey::EndpointRoute).is_some_and(|setting|
                matches!(setting, Setting::Route { destination, .. } if *destination == std::net::IpAddr::V4(*endpoint.ip())))),
        })
    }
    fn cleanup_owned_routes(
        &mut self,
        endpoint: Option<SocketAddrV4>,
        deadline: Deadline,
    ) -> Result<(), SysError> {
        if let Some(endpoint) = endpoint {
            return self.cleanup_routes(endpoint, deadline);
        }
        self.checked(Call::LeaveRoutes, deadline)?;
        self.settings.remove(&ConfigKey::SplitRoutes);
        Ok(())
    }
    fn cleanup_routes(
        &mut self,
        endpoint: SocketAddrV4,
        deadline: Deadline,
    ) -> Result<(), SysError> {
        self.effect(
            Call::CleanupRoutes(endpoint),
            Tool::Route,
            deadline,
            Effect::CleanupRoutes(endpoint),
        )
    }
    fn cleanup_dns(&mut self, deadline: Deadline) -> Result<(), SysError> {
        self.effect(Call::CleanupDns, Tool::Scutil, deadline, Effect::CleanupDns)
    }
    fn managed_artifacts(&mut self, deadline: Deadline) -> Enumeration<Vec<String>> {
        match self.checked(Call::Artifacts, deadline) {
            Ok(()) => Enumeration::Complete(self.artifacts.iter().cloned().collect()),
            Err(error) => Enumeration::Incomplete(error),
        }
    }
    fn cleanup_artifacts(&mut self, deadline: Deadline) -> Result<(), SysError> {
        self.checked(Call::CleanupArtifacts, deadline)?;
        self.artifacts.clear();
        #[cfg(test)]
        self.capture_completed(Call::CleanupArtifacts);
        Ok(())
    }
    fn remove_anchor(&mut self, deadline: Deadline) -> Result<(), SysError> {
        self.effect(
            Call::RemoveAnchor,
            Tool::Pfctl,
            deadline,
            Effect::Anchor(None),
        )
    }
}
