//! Resource-model platform contract and adapter-independent protocols.
//!
//! The later macOS adapter must pass the same generic contract suite in
//! `platform/tests.rs` as the fake, using a scratch copy directory and supervised
//! test processes. The fake is a model, not macOS qualification for \[K\], \[P\], or \[X\].
//!
//! Complete observations require exit 0, bounded untruncated output and every line
//! parsed. Incomplete reads prove no absence. Freeing evidence additionally requires
//! that its read started after both the start fence and mutation fence closed.
//! D-3 exempts only fixed-argument pinned-pfctl Lockdown loads, reference-free
//! `-e`, verification and state-only flushes from the start and mutation fences
//! and tool-family serialization.
//! No rule/anchor flush is exempt. Sweeps and reaping continue while open;
//! emergency tools enter the eventual quiescence proof. `-E`, reference writes
//! and release, ordinary policy, tunnel spawn and Leave's `RemoveAnchor` remain
//! gated. Removal additionally needs authorized Leave or startup's trusted-Left
//! containment cleanup, reconciled ownership, and termination/reaping of all
//! emergency writers. Repair reloads, verifies
//! with pf enabled, then flushes states; a reload alone proves no leakage bound.
//! Tool calls include execution, timeout kill and reap in their deadline. Their
//! reap phase waits at most two seconds and never beyond the remaining budget. An
//! unreaped child remains in `fence`; no freeing or plain Left is then permitted.
//! Callers serialize each tool family except Leave cleanup and the four D-3
//! operations above. Concurrent pfctl transaction/ticket or EBUSY errors are
//! ordinary tool failures; retry containment on its own one-second cadence.
//! Read-only tool children must be reaped synchronously or included in the own
//! tool fence until reaped, so the emergency pfctl capacity limit includes them.
//! Storage writes have a separate single-thread fence: `Busy` until an outstanding write finishes.
//! Once the native start fence is closed, `PersistBlocked` may create N-class tool
//! children before its helper record commits. The next start fence must kill
//! every older orphan of a pinned tool before ordinary effects, even if that tool's
//! helper incarnation was never committed. Foreground tunnel spawn still needs
//! committed helper identity and generation reservations.
//! Native qualification must cover reliable boot-session UUID reads, the single
//! anonymous enable reference (including an applied DIOCSTART returning EEXIST),
//! and ioctl-level reference enumeration completeness. Reaping scutil must also
//! exclude configd applying a queued DNS mutation after the final readback.
//! Recovery entries with unknown acquisition boots remain accounting debt unless
//! qualified disable evidence settles them or setup resets recovery storage.
//! Helpers cap each call by `Timings::command_deadline` and the caller’s overall
//! deadline. Retry pauses are bounded by that budget and never sleep in the fake.
//! Existing path, exact-record, previous-group and ambiguity rules take precedence
//! over image evidence. Image UUID equality never selects or kills. A pathless
//! live process is provably foreign only with validated image identity, known
//! durable spawned-image history for this boot, every current pin UUID known,
//! a UUID different from every history/pin UUID, and a name other than wireguard-go.
//! Otherwise uncertainty withholds sweep/quiescence with its PID. A foreign
//! pathless process sharing a recorded or pinned build UUID blocks until it exits.
//! A translated foreign process is compared by its own main-image UUID only.
//! A survivor still parented to a lingering old helper (ppid != 1) is not matched
//! by ambiguity. Name matching only withholds the fence; it never owns a process.
//! The macOS adapter must fill `name` from `p_comm` (`MAXCOMLEN` accommodates
//! wireguard-go), and map SSLEEP and SSTOP to live Sleeping/Stopped states.
//! With an unreadable pin, ordinary sweeps also withhold closure for sleeping
//! pathless processes. Upgrades must account for that availability residual.
use crate::snapshot::{
    BootId, COPY_BYTES, Copy, CopyRead, HelperIncarnation, ImageHistory, StartTime,
};
pub mod types;
use scupper_core::mac::{
    PhysicalInterface, Tunnel, TunnelGeneration, policy::AnchorText, verify::Observations,
};
use std::{collections::BTreeSet, net::SocketAddrV4, path::Path, time::Duration};
pub use types::{
    CheapObservation, Config, ConfigKey, Deadline, InstallRecord, InstallRecordReader,
    OWNED_DNS_KEY, Setting, SysError, Timings,
};

#[cfg(feature = "testing")]
pub mod fake;
#[cfg(test)]
mod image_tests;
#[cfg(feature = "testing")]
pub mod tests;

/// Confirmed reference-free enable outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PfEnable {
    /// Filtering was started with an anonymous reference.
    Started,
    /// DIOCSTART established the anonymous reference and reported EEXIST.
    AlreadyRunning,
}

/// Complete observation or a reason that absence cannot be trusted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Enumeration<T, E = SysError> {
    /// Every entry was obtained and parsed within bounds.
    Complete(T),
    /// Includes nonzero exit, timeout, truncation, parse failure or enumeration gaps.
    Incomplete(E),
}
/// Deadline-bounded mutating tool result; errors never imply rollback.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ToolOutcome<T> {
    /// Effect confirmed and child reaped.
    Ok(T),
    /// Spawn/exec failed before any ioctl; no effect occurred.
    NotStarted(SysError),
    /// Tool ran, reported failure and was reaped; partial effects are possible.
    Failed(SysError),
    /// An effect may have occurred. A reaped tool can have no later effect; an
    /// unreaped tool may still act until reaped and keeps the fence open.
    Unknown {
        /// Whether the child has been reaped.
        reaped: bool,
    },
}
/// Single storage-thread write result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WriteOutcome {
    /// Deadline expired before starting: no effect and nothing outstanding.
    NotStarted(SysError),
    /// All bytes written at offset zero and checked `F_FULLFSYNC` succeeded.
    Synced,
    /// Write/sync failed; old, partial or new bytes may remain.
    Failed(SysError),
    /// Write is outstanding; a late completion may make the bytes durable.
    TimedOut,
    /// A previous timed-out write has not returned; this write never started.
    Busy,
}
/// Complete pf state read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PfInfo {
    /// Enabled at the read.
    Enabled,
    /// Disabled at the read; freeing under \[X\] also needs qualification and fences.
    Disabled,
    /// No conclusion about enablement or token absence.
    Incomplete(SysError),
}
/// Parsed reference fingerprint. Token values recur after release; only the full
/// (token, pid, timestamp) fingerprint identifies a reference, never token alone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefLine {
    /// Opaque numeric token.
    pub token: u64,
    /// Acquiring pfctl process.
    pub pid: u32,
    /// Qualified kernel timestamp.
    pub timestamp: u64,
}
/// Confirmed release or qualified invalid-token response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Release {
    /// Token released.
    Released,
    /// Token was already absent.
    TokenInvalid,
}
/// Separately qualified reference-kernel behavior; defaults grant no assumptions.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReferenceQualification {
    /// Assumption \[X\]: disabling pf invalidates every outstanding token.
    pub disable_voids_references: bool,
    /// Timestamp/pid fingerprints are qualified for numeric-release ownership.
    pub fingerprints: bool,
}
/// Executable vnode identity, stable across rename/unlink on this boot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ExeId {
    /// Filesystem device.
    pub dev: u64,
    /// Inode number.
    pub ino: u64,
}
/// Incomplete process observation, retaining the offending PID when known.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessError {
    /// Live process whose path/image evidence or ownership is uncertain.
    pub pid: Option<u32>,
    /// Underlying observation, signalling or reap failure.
    pub error: SysError,
}
impl From<SysError> for ProcessError {
    fn from(error: SysError) -> Self {
        Self { pid: None, error }
    }
}
/// Main-image build identity. Equality never establishes process ownership.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImageId {
    /// Mach-O `LC_UUID` (nonzero).
    pub uuid: [u8; 16],
    /// Kernel reuse-free process identifier.
    pub uniqueid: u64,
}
/// One entry from complete process enumeration, including foreign processes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcInfo {
    /// Process id.
    pub pid: u32,
    /// PID reuse identity: kernel wall-clock start time, independent of `now()`.
    pub start: StartTime,
    /// Process group id.
    pub pgid: u32,
    /// Parent process id.
    pub ppid: u32,
    /// Live state or exited but not yet reaped.
    pub state: ProcState,
    /// Kernel process name; absence never matches a binary name.
    pub name: Option<String>,
    /// Exact executable path, possibly unreadable after unlink or during exit/exec.
    pub path: Option<std::path::PathBuf>,
    /// Executable vnode identity; adds ownership matches independently of path.
    pub exe: Option<ExeId>,
    /// Validated main-image identity; negative evidence only.
    pub image: Option<ImageId>,
}
/// Observable process lifecycle state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcState {
    /// Can still produce effects.
    Running,
    /// Live, waiting for an event.
    Sleeping,
    /// Live, suspended by a signal or debugger.
    Stopped,
    /// Exited; cannot produce further effects.
    Zombie,
}
/// Required `posix_spawn` attributes, recorded independently of child identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)] // Independent OS spawn attributes, not lifecycle state.
pub struct SpawnAttributes {
    /// All catchable signal dispositions are reset to default.
    pub default_signals: bool,
    /// The child starts with no blocked signals.
    pub empty_signal_mask: bool,
    /// All inherited descriptors close on exec except explicit fd actions.
    pub cloexec_default: bool,
    /// Spawn runs on the calling thread, with no detached worker.
    pub synchronous: bool,
}

/// Resource-model child identity, including subsecond PID reuse protection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Child {
    /// Boot of this in-memory record; never persisted in the snapshot.
    pub boot: Option<BootId>,
    /// Reserved generation.
    pub generation: u64,
    /// Process identifier.
    pub pid: u32,
    /// Full kernel wall-clock start identity, including microseconds.
    pub start_time: StartTime,
    /// Child's own text-vnode identity captured after spawn, for qualification.
    pub exe: Option<ExeId>,
    /// Validated main-image identity; negative evidence only.
    pub image: Option<ImageId>,
    /// Helper's process group, shared by the foreground child.
    pub pgid: u32,
    /// Kernel utun name.
    pub utun: String,
}
/// Resource-model observation request with an explicit child identity.
#[derive(Clone, Debug)]
pub struct Collection {
    /// Verification context.
    pub context: scupper_core::mac::verify::Context,
    /// Expected policy inputs.
    pub inputs: scupper_core::mac::Inputs,
    /// State cleanliness evidence.
    pub states: scupper_core::mac::verify::StateEvidence,
    /// Expected child identity.
    pub child: Option<Child>,
}
/// Result of guarded process-group signalling; not confirmation of exit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KillOutcome {
    /// Group was signalled after rechecking the expected process identity.
    Signalled,
    /// PID or group identity changed; no signal sent.
    StartChanged,
    /// Expected PID is absent; no signal sent.
    Gone,
}
/// A mutating tool family, named in open-fence status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tool {
    /// pfctl.
    Pfctl,
    /// route.
    Route,
    /// scutil.
    Scutil,
    /// ifconfig.
    Ifconfig,
}
/// Tool that could still produce a late effect.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Unreaped {
    /// Tool family.
    pub tool: Tool,
    /// Child process id.
    pub pid: u32,
}
/// In-process tool mutation fence (storage is fenced by `WriteOutcome::Busy`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Fence {
    /// All mutating tool children reaped.
    Closed,
    /// Listed children may still produce effects.
    Open(Vec<Unreaped>),
}

/// Complete route inventory used by `ClearIntent`, independent of configuration
/// caches. A false field certifies absence only after a complete kernel walk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LeaveRoutes {
    /// A split route still uses one of our tunnel interfaces.
    pub split_owned: bool,
    /// A static host route to the known endpoint still exists.
    pub endpoint_host: bool,
}
/// Failure to obtain exclusive ownership of the helper's shared state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InstanceLockError {
    /// Another live helper holds the lock; the caller must exit immediately.
    Contended,
    /// Interrupted lock syscall; retry immediately.
    Interrupted,
    /// Validation, open or flock failed; read-only intent, stateless blocking,
    /// and timeout cancellation/reaping of exact own tool children are allowed.
    Failed(SysError),
}

/// Logs from best-effort startup safety, independent of transport and storage.
#[derive(Clone, Debug)]
pub enum SafetyEvent {
    /// Emergency spawning is paused until own pfctl children can be reaped.
    PfctlCapacity {
        /// Number of own unreaped pfctl children.
        unreaped: usize,
    },
    /// Control socket will be retried while safety proceeds.
    SocketFailed(SysError),
    /// Structural lock failure; stateless safety is attempted.
    LockFailed(SysError),
    /// Full global Lockdown verification result, for logs only.
    LocklessVerdict(Box<Result<scupper_core::mac::verify::Verdict, SysError>>),
}

/// One platform boundary without a durable resource inventory.
///
/// Methods marked **mutating tool** participate in the mutation fence. Their
/// successful results mean complete, reaped operations. For the carried
/// `Result<_, SysError>` effects, any error can leave partial effects; `Unknown`
/// may leave an unreaped tool, discoverable through `fence`. `TimedOut` means the
/// child was reaped. A failed observation never certifies absence. UAPI writes
/// close their socket on timeout; any late child effect is covered by the sweep.
///
/// macOS leaves executable vnode identity absent (OD4 A). Pathless live entries
/// use an exec-sensitive image bracket as negative evidence only (OD4 B-neg).
/// A `proc_pidpath` failure alone proves no exit.
#[allow(clippy::missing_errors_doc)] // Each method states its uncertainty contract.
pub trait Platform {
    /// Log a secret-free safety diagnostic; grants no enforcement/publication claim.
    fn report_safety(&mut self, event: SafetyEvent) {
        eprintln!("scupper safety: {event:?}");
    }

    /// First platform call at startup: take `flock(LOCK_EX | LOCK_NB)` on a file
    /// outside removable state, in a root-owned directory with checked ancestors.
    /// Open with `O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW`; fstat must show a
    /// regular file, root owner, mode 0600 and exactly one link. Never unlink or
    /// replace the lock file. Hold the fd for the entire process lifetime,
    /// including shutdown cleanup. Children must not inherit it or call `LOCK_UN`.
    /// Contention permits no further platform call. EINTR must be returned as
    /// Interrupted. Other failures permit read-only intent and stateless Lockdown,
    /// never storage writes, sweeps, signals, tunnel spawn, references or socket.
    /// Structural failures retry in 1 to 5 seconds, without replacing the file.
    /// Success is retained by the platform until process exit, even after Exit0.
    fn acquire_instance_lock(&mut self) -> Result<(), InstanceLockError>;
    /// Create the control socket, unlinking a stale path only while holding the
    /// instance lock. Errors fail closed. No transport may accept requests before
    /// the lock is held. This is a local socket operation, not a mutating tool.
    fn create_control_socket(&mut self) -> Result<(), SysError>;
    /// Qualification record for reference freeing and fingerprint checks.
    /// Infallible and read-only; the default disables both optional assumptions.
    fn reference_qualification(&self) -> ReferenceQualification {
        ReferenceQualification::default()
    }
    /// Read monotonic, sleep-counting seconds per boot, never wall time. Values
    /// are meaningless across boots and must never be persisted. Always complete;
    /// infallible, read-only, and produces no mutation or timeout uncertainty.
    fn now(&mut self) -> u64;
    /// Current boot UUID. `None` is a complete report of unknown identity and frees
    /// nothing; infallible/read-only, never substitutes a boot timestamp.
    fn boot_id(&mut self) -> Option<BootId>;
    /// Own PID/start/group identity; boot is the current lookup, including None.
    /// At helper start `incarnation().boot == boot_id()`. Infallible,
    /// read-only; success establishes no identity for another process.
    fn incarnation(&mut self) -> HelperIncarnation;
    /// Read and validate setup metadata completely. Error/timeout means unavailable,
    /// never fresh installation; read-only and produces no effects.
    fn read_install_record(&mut self, deadline: Deadline) -> Result<InstallRecord, SysError>;
    /// One bounded read attempt. Bytes are untrusted until classified; Missing is
    /// confirmed absence, Unreadable proves nothing. Read-only, no retry or mutation.
    fn read_copy(&mut self, copy: Copy, deadline: Deadline) -> CopyRead;
    /// Continue one install read across deadline slices. Pending retains the same
    /// operation; Ready consumes its result. Pending returns only at the slice
    /// deadline. Only one read result may be active at a time. Each read runs in
    /// an abandonable worker independent of the write fence; an abandoned worker
    /// may finish alongside a later operation, but its result is discarded. At most
    /// two read workers (active plus abandoned) may remain alive. At capacity,
    /// new reads return Busy (install: Failed("storage read busy"), copy:
    /// Unreadable), starting no worker.
    /// Writes remain independent and may proceed while those workers are alive.
    fn poll_install_record(
        &mut self,
        deadline: Deadline,
    ) -> std::task::Poll<Result<InstallRecord, SysError>>;
    /// Continue one copy read across deadline slices, without restarting it.
    /// Pending returns only at the slice deadline, retaining the same read.
    fn poll_copy(&mut self, copy: Copy, deadline: Deadline) -> std::task::Poll<CopyRead>;
    /// Abandon a pending read at its total budget. Its eventual result must be
    /// discarded; it cannot be consumed by a later read or block storage writes.
    fn abandon_storage_read(&mut self);
    /// Wait on the same outstanding write, starting no new operation. Synced
    /// refers only to that write; `TimedOut` retains it under the storage fence.
    fn wait_write(&mut self, deadline: Deadline) -> WriteOutcome;
    /// pwrite at zero then checked `F_FULLFSYNC`. Only Synced is complete. Errors may
    /// leave partial bytes; never creates a missing copy. `NotStarted` means an
    /// expired deadline with no effect; Failed has no outstanding worker.
    /// `TimedOut` stays outstanding, Busy starts nothing. Storage
    /// mutation (separate fence), not a mutating tool; late sync may become durable.
    fn write_copy(
        &mut self,
        copy: Copy,
        bytes: &[u8; COPY_BYTES],
        deadline: Deadline,
    ) -> WriteOutcome;
    /// Exclusively create with `O_CREAT|O_EXCL|O_NOFOLLOW`, mode 0600/root ownership,
    /// preallocate, sync file then directory with checked `F_FULLFSYNC`. Synced is
    /// complete; existing copy fails unchanged. Other errors may leave a file;
    /// timeout/outstanding/Busy obey `write_copy`'s storage fence, not the tool fence.
    fn create_copy(
        &mut self,
        copy: Copy,
        bytes: &[u8; COPY_BYTES],
        deadline: Deadline,
    ) -> WriteOutcome;
    /// Direct **mutating tool**: pfctl -e, taking the single anonymous enable
    /// reference, without a token. Repeated calls do not accumulate references.
    /// No token release removes it: it persists until global disable or reboot,
    /// including after Leave. The helper never globally disables pf.
    /// EEXIST confirms the anonymous reference was added while pf was running;
    /// command failure does not prove absence of the effect. Verify independently.
    /// Success is reaped; failures may leave a tool in the mutation fence.
    fn enable_pf(&mut self, deadline: Deadline) -> Result<PfEnable, SysError>;
    /// **Mutating tool**: pfctl -E. Ok confirms token and acquiring PID, reaped.
    /// `NotStarted` proves no ioctl; Failed/Unknown may have acquired a reference;
    /// Unknown{reaped:false} is incomplete and keeps the mutation fence open.
    fn acquire(&mut self, deadline: Deadline) -> ToolOutcome<(u64, u32)>;
    /// **Mutating tool**: pfctl -X token. Ok is complete/reaped; `TokenInvalid` is
    /// qualified absence. `NotStarted` changes nothing; other errors/timeouts may
    /// release it. Unknown{reaped:false} keeps the mutation fence open.
    fn release(&mut self, token: u64, deadline: Deadline) -> ToolOutcome<Release>;
    /// Read-only References enumeration. Complete requires exit 0, bounded output,
    /// every line parsed; Incomplete/error/timeout proves no absence. Only reads
    /// begun after fences close can be used as freeing evidence. Completeness
    /// must be established at the ioctl boundary: XNU may silently truncate and
    /// omit oldest tokens. Exit 0 and fully parsed text alone are insufficient.
    fn references(&mut self, deadline: Deadline) -> Enumeration<Vec<RefLine>>;
    /// Read-only pf info. Enabled/Disabled require exit 0, bounded output, every
    /// line parsed. Incomplete/error/timeout proves nothing; Disabled frees only
    /// under qualified \[X\] with a read begun after fences close.
    fn pf_info(&mut self, deadline: Deadline) -> PfInfo;
    /// Read-only `KERN_PROC_ALL` plus executable paths and text-vnode identities,
    /// including self/foreign processes, excluding pid 0. Retry the table-size
    /// race internally. A vanished entry is one whose `KERN_PROC_PID` re-lookup is
    /// absent, has a different start, or is a zombie (which may instead be listed).
    /// A path lookup ESRCH alone does not establish vanishing of a listed live PID.
    /// Zombies need no image. Pathless live entries require a validated image;
    /// otherwise the observation is
    /// Incomplete with its PID. For ENOENT, read the image identifier before
    /// the PID/start re-lookup and repeat it after: UUID, uniqueid and exec-sensitive
    /// idversion must match. Short reads, zero UUID, errno or bracket mismatch
    /// withhold completeness for a confirmed live PID. Image UUIDs never own it.
    /// Other observation failures carry
    /// no PID when unknown. Incomplete proves no absence.
    fn processes(&mut self, deadline: Deadline) -> Enumeration<Vec<ProcInfo>, ProcessError>;
    /// Obtain a regular pinned executable's vnode identity with lstat semantics:
    /// never follow symlinks, and reject a symlink pin (also in `check_tools`).
    /// Read-only; failure/timeout grants no current identity. Paths and exact
    /// recorded (pid, start) pairs independently match. Re-stat every sweep poll.
    fn executable_id(&mut self, path: &Path, deadline: Deadline) -> Result<ExeId, SysError>;
    /// Read-only pin `LC_UUID`: open `O_RDONLY | O_NOFOLLOW | O_CLOEXEC`, fstat a
    /// regular file, parse native arm64/arm64e Mach-O load commands. Reject
    /// missing/zero UUIDs, parse failures and unresolved fat-slice disagreement.
    /// Failure means unknown. No UUID equality establishes ownership.
    fn image_uuid(&mut self, path: &Path, deadline: Deadline) -> Result<[u8; 16], SysError>;
    /// Signal only pgid > 1 and different from the helper's own group; otherwise
    /// return error without signalling. Adapters must call `group_kill_allowed`.
    /// Recheck `expect_pid`'s start AND group.
    /// Empty groups or groups containing only zombies yield Gone.
    /// Does not wait for exit or reap: Signalled only confirms sending SIGKILL.
    /// The generic suite qualifies a five-second disappearance bound for its
    /// supervised killable children, including `reap_children`. A caller can
    /// choose a shorter confirmation budget; timeout then proves no absence.
    /// Error/timeout may have signalled. Direct mutation, no tool fence entry.
    fn kill_group(
        &mut self,
        pgid: u32,
        expect_pid: u32,
        expect_start: StartTime,
        deadline: Deadline,
    ) -> Result<KillOutcome, SysError>;
    /// Signal just this PID after rechecking its full start identity; never self,
    /// pid 0 or 1, or values outside the OS pid range. Adapters must call
    /// `process_kill_allowed` and convert with `checked_os_pid`, never `as`.
    /// Does not wait for exit/reap; outcomes obey `kill_group`.
    /// `StopChild` and ordinary child sweeps use this, never group signalling.
    /// Residual: PID reuse between the recheck and kill is accepted; the two
    /// syscalls are not atomic. This residual does not apply to our own unreaped
    /// child: its pid cannot be reused before waitpid. `StopChild` signals before
    /// reaping, and reaping must never run concurrently with a kill.
    /// The foreground tunnel child must never fork.
    fn kill_process(
        &mut self,
        pid: u32,
        expect_start: StartTime,
        deadline: Deadline,
    ) -> Result<KillOutcome, SysError>;
    /// Reap only exited children created through `spawn`, including uncertain
    /// spawns. The adapter must record the PID before any blocking step after
    /// `posix_spawn` succeeds. Never consume tool child status: their reap belongs to the fence.
    /// Nonblocking except for the bounded syscall; does not close tool fences.
    fn reap_children(&mut self, deadline: Deadline) -> Result<(), SysError>;
    /// Read-only, complete live list of unreaped mutating tools. Closed confirms
    /// quiescence of this incarnation only; Open is incomplete quiescence evidence.
    /// Infallible and never changes tool effects or the separate storage fence.
    fn fence(&mut self) -> Fence;
    /// Wait until deadline for unreaped mutating children. Closed is complete;
    /// Open on timeout retains every outstanding child (late effects possible).
    /// Reaping itself is not a mutating tool and starts no new effect. ECHILD
    /// counts as reaped: a missing child cannot produce a later effect.
    fn reap(&mut self, deadline: Deadline) -> Fence;
    /// Pause for at most the requested interval, capped at deadline even when
    /// `now()` truncates subsecond time. Expired deadlines return immediately.
    /// Infallible/read-only, no effect or tool fence; included in caller's budget.
    fn pause(&mut self, duration: Duration, deadline: Deadline);
    /// **Mutating tool**: load fixed helper anchor; success complete/reaped.
    /// Error/timeout may leave old, partial or new rules; Unknown may keep fence open.
    fn load_anchor(&mut self, text: &AnchorText, deadline: Deadline) -> Result<(), SysError>;
    /// Read-only bounded independent anchor read. Success complete, None confirms
    /// absence; error/timeout is incomplete and proves neither contents nor absence.
    fn read_anchor(&mut self, deadline: Deadline) -> Result<Option<String>, SysError>;
    /// **Mutating tool**: flush all states, success complete/reaped. Error/timeout
    /// may have flushed some/all states; Unknown may leave the fence open.
    fn flush_states(&mut self, deadline: Deadline) -> Result<(), SysError>;
    /// **Mutating tool**: remove states on these vanished interfaces and confirm
    /// absence. Success complete/reaped; error/timeout may partially remove states,
    /// proves no cleanliness, and Unknown may leave the fence open.
    fn remove_interface_states(
        &mut self,
        interfaces: &BTreeSet<PhysicalInterface>,
        deadline: Deadline,
    ) -> Result<(), SysError>;
    /// Read-only ownership/hash verification; reject symlink executable pins.
    /// Success is complete for every pinned
    /// executable. Error/timeout is incomplete and grants no tool trust; no effects.
    fn check_tools(&mut self, deadline: Deadline) -> Result<(), SysError>;
    /// Check only the pinned pfctl executable, including ownership, mode, vnode
    /// and digest. Stateless safety must not depend on the tunnel or other tools.
    fn check_pfctl(&mut self, deadline: Deadline) -> Result<(), SysError>;
    /// All children spawned in this incarnation, including uncertain spawns and
    /// reaped children. Record PID before any blocking post-spawn step, and record
    /// boot, start and the child's own text-vnode identity as soon as available.
    /// These records are in memory only; helper death discards them. Matching uses
    /// exact (pid, start), never this record's executable identity or group.
    /// Infallible, read-only, and never drops records when children are reaped.
    fn spawned_children(&self) -> &[Child];
    /// Spawn wireguard-go with `-f` in the helper's own process group, without
    /// setsid/setpgid, after reserved generation and confirmed sweep. The child
    /// must not fork. launchd must use AbandonProcessGroup=false so every helper
    /// exit kills this group; the start fence covers cleanup still in flight.
    /// Run `posix_spawn` synchronously on the calling thread. Reset all catchable
    /// signal dispositions with `POSIX_SPAWN_SETSIGDEF`, set an empty signal mask
    /// with `POSIX_SPAWN_SETSIGMASK`, and use `POSIX_SPAWN_CLOEXEC_DEFAULT` with
    /// explicit fd actions. No inherited storage lock or snapshot fd may survive
    /// exec. The helper must lead its group and have launchd (pid 1) as parent.
    /// The caller durably records the pin UUID in boot-scoped spawned-image
    /// history before every call; a history write failure forbids spawning.
    /// Success includes the child's observed main-image identity. Owned children
    /// must be native: refuse translated (Rosetta) children by checking
    /// `proc_translated/P_TRANSLATED` before reporting success (native R4).
    /// Success returns complete identity; error/timeout may
    /// leave a child, requiring sweep. Process mutation, not a tool fence child.
    fn spawn(
        &mut self,
        generation: TunnelGeneration,
        attributes: SpawnAttributes,
        deadline: Deadline,
    ) -> Result<Child, SysError>;
    /// Write typed configuration. **Mutating tool** for addresses/MTU/routes/DNS;
    /// UAPI is a cancellable socket write. Success complete/reaped (or socket
    /// closed); error/timeout may leave partial settings; Unknown may open fence.
    fn configure(
        &mut self,
        key: ConfigKey,
        value: &Setting,
        deadline: Deadline,
    ) -> Result<(), SysError>;
    /// Read-only independent bounded configuration read. Success complete, None
    /// confirms absence; error/timeout is incomplete, proves nothing, has no effects.
    fn read_config(
        &mut self,
        key: ConfigKey,
        deadline: Deadline,
    ) -> Result<Option<Setting>, SysError>;
    /// Read-only current child/utun identity verification. Success complete; error
    /// or timeout is incomplete and cannot establish ownership; no effects.
    fn identity(&mut self, child: &Child, deadline: Deadline) -> Result<Tunnel, SysError>;
    /// Read-only cheap facts, complete only for these positive checks, never a full
    /// proof. Error/timeout is incomplete, proves no absence, and has no effects.
    fn cheap_check(
        &mut self,
        child: Option<&Child>,
        deadline: Deadline,
    ) -> Result<CheapObservation, SysError>;
    /// Read-only raw qualified observations, not a verdict. Success may contain
    /// individually incomplete reads; each carries its error. Outer error/timeout
    /// is incomplete and proves nothing; no effects or mutation fence changes.
    fn collect(
        &mut self,
        collection: &Collection,
        deadline: Deadline,
    ) -> Result<Observations, SysError>;
    /// Reviewed firewall qualification independent of installation metadata.
    /// Missing qualification refuses lockdown verification.
    fn firewall_qualification(&self) -> Option<scupper_core::mac::verify::Qualification> {
        None
    }
    /// Complete global pf observation with no installation inputs. Endpoint and
    /// tunnel fields may be errors; global fields and start times remain required.
    fn collect_lockdown(
        &mut self,
        _context: scupper_core::mac::verify::Context,
        _states: scupper_core::mac::verify::StateEvidence,
        _deadline: Deadline,
    ) -> Result<Observations, SysError> {
        Err(SysError::Failed("lockdown collection unavailable"))
    }
    /// Complete live route walk; no cached settings can certify absence.
    fn leave_routes(
        &mut self,
        endpoint: Option<SocketAddrV4>,
        deadline: Deadline,
    ) -> Result<LeaveRoutes, SysError>;
    /// Remove owned split routes even when the endpoint is unknown. The unknown
    /// endpoint is reported, and grants no authority to remove other host routes.
    fn cleanup_owned_routes(
        &mut self,
        endpoint: Option<SocketAddrV4>,
        deadline: Deadline,
    ) -> Result<(), SysError> {
        self.cleanup_routes(
            endpoint.ok_or(SysError::Failed("endpoint route unknown"))?,
            deadline,
        )
    }
    /// **Mutating tool**: remove static host route to explicit endpoint and confirm
    /// split-route absence after sweep. Complete absence is idempotent success;
    /// error/timeout may partially clean, Unknown may keep fence open.
    fn cleanup_routes(
        &mut self,
        endpoint: SocketAddrV4,
        deadline: Deadline,
    ) -> Result<(), SysError>;
    /// **Mutating tool**: remove fixed DNS key, confirming absence (already absent
    /// also complete). Error/timeout may remove it; Unknown may keep fence open.
    fn cleanup_dns(&mut self, deadline: Deadline) -> Result<(), SysError>;
    /// Complete inventory of helper-managed run artifacts, including generation
    /// name files, child sockets and partial/temporary files. Exclude the lifetime
    /// instance lock and control socket needed to serve requests. Unknown entries
    /// in the managed namespace and enumeration errors/truncation prove no absence.
    fn managed_artifacts(&mut self, deadline: Deadline) -> Enumeration<Vec<String>>;
    /// Remove the managed artifacts enumerated by `managed_artifacts`, retaining
    /// the lifetime lock and control socket. Already absent is complete.
    /// Filesystem mutation, no tool child. Error/timeout may partially remove files;
    /// never implies complete cleanup or rollback.
    fn cleanup_artifacts(&mut self, deadline: Deadline) -> Result<(), SysError>;
    /// **Mutating tool**: flush fixed anchor and confirm absence, already absent
    /// counts as complete. Error/timeout may remove rules; Unknown may open fence.
    fn remove_anchor(&mut self, deadline: Deadline) -> Result<(), SysError>;
}

/// Process absence is independent of the current tool mutation fence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Sweep {
    /// Owned processes gone; callers inspect the separate tool fence as needed.
    Swept,
    /// Matching live/own-zombie processes survived the budget; identifies each PID.
    Survivors(Vec<ProcInfo>),
    /// Enumeration, signalling or reaping failed; absence cannot be established.
    Incomplete(ProcessError),
}
/// Typed startup fence status, preserving process identity in diagnostics.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StartFence {
    /// The engine has not durably installed its new helper incarnation.
    /// Quiescence alone cannot authorize effects: this is an open startup fence.
    Uncommitted,
    /// No targeted survivor and no unreaped mutating tool.
    Closed,
    /// Targeted processes remain or observation failed.
    Processes(Sweep),
    /// Processes are gone but this incarnation has outstanding tool children.
    Tools(Vec<Unreaped>),
}
/// Two-copy commit result; effects must not be exposed on failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Commit {
    /// A then B both fully synced.
    Committed,
    /// Stopped at first non-Synced result.
    Failed {
        /// A was fully synced (B may still be outstanding).
        after_a: bool,
    },
}

fn deadline(p: &mut impl Platform, timings: &Timings, overall: Deadline) -> Deadline {
    Deadline(
        p.now()
            .saturating_add(timings.command_deadline)
            .min(overall.0),
    )
}
fn start_key(start: StartTime) -> (u64, u32) {
    (start.seconds, start.microseconds)
}
#[derive(Clone, Copy)]
enum Target {
    Group,
    Process,
    Ambiguous,
}
/// Shared refusal rule; adapters must use this before issuing any group signal.
#[must_use]
pub const fn group_kill_allowed(pgid: u32, own_pgid: u32) -> bool {
    process_kill_allowed(pgid, own_pgid)
}
/// Largest representable positive OS pid (`pid_t` is signed 32-bit on macOS).
pub const OS_PID_MAX: u32 = 2_147_483_647;
/// Shared refusal rule for every individual pid signal.
#[must_use]
pub const fn process_kill_allowed(pid: u32, own_pid: u32) -> bool {
    pid > 1 && pid != own_pid && pid <= OS_PID_MAX
}
/// Checked conversion to the OS pid type; signalling also requires the guard.
#[must_use]
pub fn checked_os_pid(pid: u32) -> Option<i32> {
    i32::try_from(pid).ok()
}
#[allow(clippy::too_many_lines, clippy::too_many_arguments)] // One bounded enumeration/signal/confirmation protocol.
fn sweep_matching(
    p: &mut impl Platform,
    pinned_paths: &[&Path],
    image_paths: &[&Path],
    recorded_children: &[Child],
    timings: &Timings,
    overall: Deadline,
    poll: bool,
    history: &ImageHistory,
    target: impl Fn(&ProcInfo, &[ProcInfo], bool) -> Option<Target>,
) -> Sweep {
    let own = p.incarnation();
    let mut signalled = BTreeSet::new();
    let mut observed_complete = false;
    let mut poll_rounds = 0;
    let mut last = Sweep::Incomplete(SysError::TimedOut.into());
    loop {
        if p.now() >= overall.0 {
            return last;
        }
        poll_rounds += 1;
        let d = deadline(p, timings, overall);
        if let Err(e) = p.reap_children(d) {
            last = Sweep::Incomplete(e.into());
            if poll {
                return last;
            }
            let d = deadline(p, timings, overall);
            p.pause(Duration::from_millis(50), d);
            continue;
        }
        let (identities, unknown_pin) = pinned_identities(p, pinned_paths, timings, overall);
        let pin_uuids: Option<Vec<_>> = image_paths
            .iter()
            .map(|path| {
                let d = deadline(p, timings, overall);
                p.image_uuid(path, d).ok().filter(|uuid| *uuid != [0; 16])
            })
            .collect();
        let records: BTreeSet<_> = recorded_children
            .iter()
            .filter(|child| child.boot.is_some() && child.boot == own.boot)
            .chain(p.spawned_children())
            .map(|child| (child.pid, start_key(child.start_time)))
            .collect();
        let select = |proc: &ProcInfo, procs: &[ProcInfo]| {
            target(
                proc,
                procs,
                matches_executable(proc, pinned_paths, &identities)
                    || records.contains(&(proc.pid, start_key(proc.start))),
            )
        };
        let boot = p.boot_id();
        let d = deadline(p, timings, overall);
        let processes = p.processes(d);
        match qualify_pathless(
            processes,
            unknown_pin,
            history,
            boot.as_ref(),
            pin_uuids.as_deref(),
            |proc, procs| {
                // Only otherwise-unmatched candidates can hide a pinned process.
                select(proc, procs).is_none()
            },
        ) {
            Enumeration::Incomplete(e) => {
                last = Sweep::Incomplete(e);
            }
            Enumeration::Complete(procs) => {
                let survivors: Vec<_> = procs
                    .iter()
                    .filter(|proc| {
                        select(proc, &procs).is_some()
                            && (proc.state != ProcState::Zombie || proc.ppid == own.pid)
                    })
                    .cloned()
                    .collect();
                let had_complete = std::mem::replace(&mut observed_complete, true);
                if survivors.is_empty() {
                    if had_complete {
                        return Sweep::Swept;
                    }
                    // Preserve the second-read requirement even when initially empty.
                    continue;
                }
                let ambiguous = survivors
                    .iter()
                    .find(|proc| matches!(select(proc, &procs), Some(Target::Ambiguous)));
                last = ambiguous.map_or_else(
                    || Sweep::Survivors(survivors.clone()),
                    |proc| {
                        Sweep::Incomplete(ProcessError {
                            pid: Some(proc.pid),
                            error: SysError::Failed(
                                "previous helper unknown: process ownership undecidable",
                            ),
                        })
                    },
                );
                // Nothing can change through signalling in this round. Return
                // promptly and re-enumerate at the caller's retry cadence.
                if survivors
                    .iter()
                    .all(|proc| matches!(select(proc, &procs), Some(Target::Ambiguous)))
                    || p.now() >= overall.0
                {
                    return last;
                }
                for proc in &survivors {
                    let key = (proc.pid, start_key(proc.start), proc.pgid);
                    if proc.state == ProcState::Zombie || signalled.contains(&key) {
                        continue;
                    }
                    let d = deadline(p, timings, overall);
                    let result = match select(proc, &procs) {
                        Some(Target::Group) => {
                            if !group_kill_allowed(proc.pgid, own.pgid) {
                                return Sweep::Survivors(vec![proc.clone()]);
                            }
                            p.kill_group(proc.pgid, proc.pid, proc.start, d)
                        }
                        Some(Target::Process) => {
                            if !process_kill_allowed(proc.pid, own.pid) {
                                return Sweep::Survivors(vec![proc.clone()]);
                            }
                            p.kill_process(proc.pid, proc.start, d)
                        }
                        Some(Target::Ambiguous) | None => continue,
                    };
                    match result {
                        Ok(KillOutcome::Signalled) => {
                            signalled.insert(key);
                        }
                        Err(e) if ambiguous.is_none() => last = Sweep::Incomplete(e.into()),
                        Ok(KillOutcome::StartChanged | KillOutcome::Gone) | Err(_) => {}
                    }
                }
            }
        }
        if poll {
            // One immediate confirmation after signalling preserves prompt
            // closure for tools that exited; survivors yield without sleeping.
            if poll_rounds >= 2 || signalled.is_empty() {
                return last;
            }
            continue;
        }
        let d = deadline(p, timings, overall);
        p.pause(Duration::from_millis(50), d);
    }
}
fn pinned_identities(
    p: &mut impl Platform,
    paths: &[&Path],
    timings: &Timings,
    overall: Deadline,
) -> (BTreeSet<ExeId>, bool) {
    let mut identities = BTreeSet::new();
    let mut unknown_pin = false;
    // A rename may replace a pinned vnode between any two polls.
    for path in paths {
        let d = deadline(p, timings, overall);
        match p.executable_id(path, d) {
            Ok(exe) => {
                identities.insert(exe);
            }
            Err(_) => unknown_pin = true,
        }
    }
    (identities, unknown_pin)
}
/// Apply the engine's pathless uncertainty rule after ownership/ambiguity selection.
/// The predicate must be true exactly for entries left unselected by those rules.
pub fn qualify_pathless(
    processes: Enumeration<Vec<ProcInfo>, ProcessError>,
    unknown_pin: bool,
    history: &ImageHistory,
    boot: Option<&BootId>,
    pin_uuids: Option<&[[u8; 16]]>,
    unmatched_candidate: impl Fn(&ProcInfo, &[ProcInfo]) -> bool,
) -> Enumeration<Vec<ProcInfo>, ProcessError> {
    if let Enumeration::Complete(procs) = &processes
        && let Some(proc) = procs.iter().find(|proc| {
            proc.state != ProcState::Zombie
                && proc.path.is_none()
                && unmatched_candidate(proc, procs)
                && !provably_foreign(proc, history, boot, pin_uuids)
        })
    {
        return Enumeration::Incomplete(ProcessError {
            pid: Some(proc.pid),
            error: SysError::Failed(if unknown_pin {
                "pinned identity unavailable for pathless process"
            } else {
                "pathless image ownership undecidable"
            }),
        });
    }
    processes
}
/// Negative evidence only, after all existing ownership and ambiguity rules
/// have returned no selection. UUID equality never selects or signals a process.
/// Missing names also withhold certainty because the extra name guard is unknown.
#[must_use]
pub fn provably_foreign(
    proc: &ProcInfo,
    history: &ImageHistory,
    boot: Option<&BootId>,
    pin_uuids: Option<&[[u8; 16]]>,
) -> bool {
    let (Some(image), Some(pins)) = (proc.image, pin_uuids) else {
        return false;
    };
    history.known_on(boot)
        && image.uuid != [0; 16]
        && image.uniqueid != 0
        && !history.uuids.contains(&image.uuid)
        && pins
            .iter()
            .all(|uuid| *uuid != [0; 16] && *uuid != image.uuid)
        && proc
            .name
            .as_deref()
            .is_some_and(|name| name != "wireguard-go")
}
fn matches_executable(proc: &ProcInfo, paths: &[&Path], identities: &BTreeSet<ExeId>) -> bool {
    proc.exe.is_some_and(|exe| identities.contains(&exe))
        || proc
            .path
            .as_deref()
            .is_some_and(|path| paths.contains(&path))
}
/// Guarded PID kill, then bounded 50 ms re-polling until the caller's deadline.
/// Ownership is the union of current pinned identity, pinned path, and recorded
/// exact (pid, start) pairs. Records are in memory only; their exe and pgid never
/// select processes. Supplied records require a known matching boot; the adapter's
/// own incarnation-local records also work when the boot lookup is unavailable.
/// Hard links elsewhere also run the owned binary, but only their PID
/// is killed, preserving group peers (including the helper).
/// Existing ownership is evaluated first. Every otherwise unmatched live pathless
/// entry requires the negative-only image rule; unknown history/pin UUIDs or any
/// equal UUID withhold completeness with its PID. This wrapper has unknown history.
/// Reap own zombies first; foreign zombies cannot act and count as gone. Retry
/// incomplete enumerations/reaps/kills and signal new/changed targets each poll.
/// A second complete enumeration is required, even if initially empty; every
/// signal requires a later complete enumeration. Tool fences are separate.
pub fn sweep(
    p: &mut impl Platform,
    pinned_path: &Path,
    recorded_children: &[Child],
    timings: &Timings,
    overall: Deadline,
) -> Sweep {
    sweep_with_history(
        p,
        pinned_path,
        recorded_children,
        &ImageHistory::default(),
        &[],
        timings,
        overall,
    )
}
/// Sweep with durable boot-scoped spawned-image history. Unknown evidence fails closed.
/// Additional current pins are compared only for negative evidence, never ownership.
pub fn sweep_with_history(
    p: &mut impl Platform,
    pinned_path: &Path,
    recorded_children: &[Child],
    history: &ImageHistory,
    additional_image_pins: &[&Path],
    timings: &Timings,
    overall: Deadline,
) -> Sweep {
    let image_paths: Vec<_> = std::iter::once(pinned_path)
        .chain(additional_image_pins.iter().copied())
        .collect();
    sweep_matching(
        p,
        &[pinned_path],
        &image_paths,
        recorded_children,
        timings,
        overall,
        false,
        history,
        |_, _, owned| owned.then_some(Target::Process),
    )
}
/// Trust in the previous helper, independent of whether a snapshot is initial.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PreviousHelper {
    /// Checksum-valid previous incarnation.
    Known(HelperIncarnation),
    /// Valid initial snapshot: no child could have been spawned.
    None,
    /// Recovery with no checksum-valid helper in either copy.
    Unknown,
}
/// Close startup quiescence over the previous helper's group and older orphaned
/// pinned tools. `child_path` is mandatory, so wireguard-go cannot be forgotten.
/// Ownership uses the same union as `sweep`, including hard links. After helper
/// restart pass no records: launchd's group cleanup and the previous-group rule
/// cover the foreground child even after binary replacement. No durable child
/// record is added. Existing ownership and ambiguity are evaluated before image
/// evidence. Otherwise unmatched pathless live entries require known boot-scoped
/// history and all pin UUIDs, a differing UUID, and the name guard; uncertainty
/// withholds startup with the PID. This wrapper supplies unknown history.
/// Orphans are killed individually after start recheck, never by group. Self is
/// excluded. Known different boots skip the previous-group rule.
///
/// Decision (spec 7b narrowing): previous-group members must start at/after the
/// previous helper and before this helper. A leader that started after
/// `previous.start`, in any state, proves pgid reuse and disables that rule.
/// Corrupt previous == current pgid fails closed instead of signalling our group.
///
/// Residual (N4): a reused group's leader may already have exited while its
/// members started before this helper; unknown boots also permit reuse after a
/// reboot. The rule may then kill foreign group members. Older foreign orphans
/// at pinned executable identities or paths may also be killed.
/// Deferred R4g-N2: previous-group members forked at/after this helper's start are
/// excluded, even when an old survivor forked them. Current helper tools do not fork.
/// Start ordering assumes assumption \[P\]; these are not ownership proofs.
/// Only Recovery without a checksum-valid helper uses the ambiguity rule: an
/// otherwise unowned live orphan older than this helper with an unreadable path
/// or the child's binary name withholds closure, without establishing ownership.
/// Valid initial snapshots have no previous helper and no ambiguity rule: tunnel
/// spawning required a committed helper generation. N-class tools can precede a
/// failed helper commit, so pinned-tool orphan ownership is independent of the
/// previous helper record. The new helper is committed only after Closed,
/// preserving Recovery uncertainty across subsequent restarts.
#[allow(clippy::needless_pass_by_value)]
pub fn start_fence(
    p: &mut impl Platform,
    previous: PreviousHelper,
    pinned_tools: &[&Path],
    child_path: &Path,
    recorded_children: &[Child],
    timings: &Timings,
    overall: Deadline,
) -> StartFence {
    start_fence_inner(
        p,
        previous,
        pinned_tools,
        child_path,
        recorded_children,
        timings,
        overall,
        false,
        &ImageHistory::default(),
    )
}

/// One sweep round without retry sleeps; confirmation still needs two complete reads.
#[allow(clippy::too_many_arguments)]
#[cfg(test)]
pub(crate) fn poll_start_fence(
    p: &mut impl Platform,
    previous: PreviousHelper,
    pinned_tools: &[&Path],
    child_path: &Path,
    recorded_children: &[Child],
    timings: &Timings,
    overall: Deadline,
) -> StartFence {
    poll_start_fence_with_history(
        p,
        previous,
        pinned_tools,
        child_path,
        recorded_children,
        &ImageHistory::default(),
        timings,
        overall,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn poll_start_fence_with_history(
    p: &mut impl Platform,
    previous: PreviousHelper,
    pinned_tools: &[&Path],
    child_path: &Path,
    recorded_children: &[Child],
    history: &ImageHistory,
    timings: &Timings,
    overall: Deadline,
) -> StartFence {
    start_fence_inner(
        p,
        previous,
        pinned_tools,
        child_path,
        recorded_children,
        timings,
        overall,
        true,
        history,
    )
}

#[allow(clippy::too_many_arguments, clippy::needless_pass_by_value)]
fn start_fence_inner(
    p: &mut impl Platform,
    previous: PreviousHelper,
    pinned_tools: &[&Path],
    child_path: &Path,
    recorded_children: &[Child],
    timings: &Timings,
    overall: Deadline,
    poll: bool,
    history: &ImageHistory,
) -> StartFence {
    let own = p.incarnation();
    let pinned: Vec<_> = pinned_tools
        .iter()
        .copied()
        .chain(std::iter::once(child_path))
        .collect();
    let result = sweep_matching(
        p,
        &pinned,
        &pinned,
        recorded_children,
        timings,
        overall,
        poll,
        history,
        |proc, procs, owned| {
            if proc.pid == own.pid {
                return None;
            }
            if matches!(&previous, PreviousHelper::Known(prev) if {
                !(prev.boot.is_some() && own.boot.is_some() && prev.boot != own.boot)
                    && proc.pgid == prev.pgid
                    && start_key(proc.start) >= start_key(prev.start)
                    && (prev.pgid == own.pgid
                        || (start_key(proc.start) < start_key(own.start)
                            && !procs.iter().any(|leader| {
                                leader.pid == prev.pgid
                                    && start_key(leader.start) > start_key(prev.start)
                            })))
            }) {
                return Some(Target::Group);
            }
            if proc.ppid == 1 && owned && start_key(proc.start) < start_key(own.start) {
                return Some(Target::Process);
            }
            if previous == PreviousHelper::Unknown
                && !owned
                && proc.ppid == 1
                && proc.state != ProcState::Zombie
                && start_key(proc.start) < start_key(own.start)
                && (proc.path.is_none()
                    || proc.name.as_deref().is_some_and(|name| {
                        Some(name) == child_path.file_name().and_then(|n| n.to_str())
                    }))
            {
                return Some(Target::Ambiguous);
            }
            None
        },
    );
    if result != Sweep::Swept {
        return StartFence::Processes(result);
    }
    match p.fence() {
        Fence::Closed => StartFence::Closed,
        Fence::Open(tools) => StartFence::Tools(tools),
    }
}
/// Retry unreadability at most three times, with two budgeted 100 ms pauses.
/// Missing and bytes return immediately; classification belongs to snapshot.
pub fn read_copy_with_retry(
    p: &mut impl Platform,
    copy: Copy,
    timings: &Timings,
    overall: Deadline,
) -> CopyRead {
    for attempt in 0..3 {
        let d = deadline(p, timings, overall);
        let read = p.read_copy(copy, d);
        if read != CopyRead::Unreadable || attempt == 2 {
            return read;
        }
        if p.now() >= overall.0 {
            return CopyRead::Unreadable;
        }
        let d = deadline(p, timings, overall);
        p.pause(Duration::from_millis(100), d);
    }
    CopyRead::Unreadable
}
/// Commit A then B, stopping at first non-Synced. Worst case is the smaller of
/// 2 × `timings.command_deadline` and the caller's overall budget; no effects may be
/// exposed on failure. A zero budget starts no storage operation (Leave can use it).
pub fn commit(
    p: &mut impl Platform,
    bytes: &[u8; COPY_BYTES],
    timings: &Timings,
    overall: Deadline,
) -> Commit {
    let d = deadline(p, timings, overall);
    if p.write_copy(Copy::A, bytes, d) != WriteOutcome::Synced {
        return Commit::Failed { after_a: false };
    }
    let d = deadline(p, timings, overall);
    if p.write_copy(Copy::B, bytes, d) != WriteOutcome::Synced {
        return Commit::Failed { after_a: true };
    }
    Commit::Committed
}
