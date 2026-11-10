//! Bounded command execution behind an injectable clock and kernel interface.

use std::{
    io::{Read, Write},
    os::unix::process::CommandExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use rustix::process::{Pid, Signal, kill_process_group};
use thiserror::Error;

use crate::netns::NetnsHandle;

/// Default deadline for each kernel command.
pub const EXEC_TIMEOUT: Duration = Duration::from_secs(3);
/// Deadline for starting or stopping a tunnel unit.
pub const SYSTEMCTL_TIMEOUT: Duration = Duration::from_secs(30);
const OUTPUT_CAP: usize = 1024 * 1024;

/// A kernel utility selected without a shell or PATH lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
pub enum Program {
    /// Read fixed public procfs socket tables inside a namespace.
    Cat,
    /// `WireGuard` inspection.
    Wg,
    /// Link and routing inspection.
    Ip,
    /// Firewall inspection.
    Nft,
    /// Traffic-control inspection.
    Tc,
    /// Enter a held network namespace.
    Nsenter,
    /// Namespace sysctl access.
    Sysctl,
    /// Connection tracking maintenance.
    Conntrack,
    /// Create an anonymous network namespace for ruleset canonicalization.
    Unshare,
    /// Start and stop the exit tunnel unit.
    Systemctl,
}

impl Program {
    /// The absolute executable path used unless explicitly overridden.
    #[must_use]
    pub const fn default_path(self) -> &'static str {
        match self {
            Self::Cat => "/usr/bin/cat",
            Self::Nsenter => "/usr/bin/nsenter",
            Self::Sysctl => "/usr/sbin/sysctl",
            Self::Conntrack => "/usr/sbin/conntrack",
            Self::Wg => "/usr/bin/wg",
            Self::Ip => "/usr/sbin/ip",
            Self::Nft => "/usr/sbin/nft",
            Self::Tc => "/usr/sbin/tc",
            Self::Unshare => "/usr/bin/unshare",
            Self::Systemctl => "/usr/bin/systemctl",
        }
    }
}

/// Validated executable paths; private fields prevent relative-path injection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Programs {
    cat: PathBuf,
    wg: PathBuf,
    ip: PathBuf,
    nft: PathBuf,
    tc: PathBuf,
    systemctl: PathBuf,
    unshare: PathBuf,
    nsenter: PathBuf,
    sysctl: PathBuf,
    conntrack: PathBuf,
}

impl Default for Programs {
    fn default() -> Self {
        Self {
            cat: Program::Cat.default_path().into(),
            wg: Program::Wg.default_path().into(),
            ip: Program::Ip.default_path().into(),
            nft: Program::Nft.default_path().into(),
            tc: Program::Tc.default_path().into(),
            systemctl: Program::Systemctl.default_path().into(),
            unshare: Program::Unshare.default_path().into(),
            nsenter: Program::Nsenter.default_path().into(),
            sysctl: Program::Sysctl.default_path().into(),
            conntrack: Program::Conntrack.default_path().into(),
        }
    }
}

impl Programs {
    /// Applies absolute-path overrides to the defaults (last override wins).
    ///
    /// Callers must use paths from code defaults or root-owned configuration only,
    /// never from command-line arguments or environment variables.
    ///
    /// # Errors
    ///
    /// Returns a bounded [`ExecError::Spawn`] if any override is relative.
    pub fn new<P: AsRef<Path>>(
        overrides: impl IntoIterator<Item = (Program, P)>,
    ) -> Result<Self, ExecError> {
        let mut paths = Self::default();
        for (program, path) in overrides {
            if !path.as_ref().is_absolute() {
                return Err(ExecError::spawn("program path must be absolute"));
            }
            let destination = match program {
                Program::Cat => &mut paths.cat,
                Program::Nsenter => &mut paths.nsenter,
                Program::Sysctl => &mut paths.sysctl,
                Program::Conntrack => &mut paths.conntrack,
                Program::Wg => &mut paths.wg,
                Program::Ip => &mut paths.ip,
                Program::Nft => &mut paths.nft,
                Program::Tc => &mut paths.tc,
                Program::Unshare => &mut paths.unshare,
                Program::Systemctl => &mut paths.systemctl,
            };
            path.as_ref().clone_into(destination);
        }
        Ok(paths)
    }

    /// Borrows the validated executable path.
    #[must_use]
    pub fn path(&self, program: Program) -> &Path {
        match program {
            Program::Cat => &self.cat,
            Program::Nsenter => &self.nsenter,
            Program::Sysctl => &self.sysctl,
            Program::Conntrack => &self.conntrack,
            Program::Wg => &self.wg,
            Program::Ip => &self.ip,
            Program::Nft => &self.nft,
            Program::Tc => &self.tc,
            Program::Systemctl => &self.systemctl,
            Program::Unshare => &self.unshare,
        }
    }
}

/// A completed command, including unsuccessful or signal-terminated commands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecOutput {
    /// Exit code, or `None` for termination without an exit code.
    pub status: Option<i32>,
    /// UTF-8 standard output, at most 1 MiB.
    pub stdout: String,
    /// UTF-8 standard error, at most 1 MiB.
    pub stderr: String,
}

/// Command output stream identified by a bounded read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stream {
    /// Standard output.
    Stdout,
    /// Standard error.
    Stderr,
}

/// Execution failed before a trustworthy complete output was available.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ExecError {
    /// Spawn, pipe or wait failure; stored by [`Self::spawn`] with bounded text.
    #[error("exec I/O error: {}", bounded(.0))]
    Spawn(String),
    /// The deadline expired; the process group was killed and reaping requested.
    #[error("exec timed out after {after:?}")]
    Timeout {
        /// The requested execution budget.
        after: Duration,
    },
    /// Either output stream exceeded 1 MiB.
    #[error("exec {stream:?} exceeded 1 MiB")]
    OutputTooLarge {
        /// The stream that exceeded the output cap.
        stream: Stream,
    },
    /// Either output stream was not valid UTF-8.
    #[error("exec output is not UTF-8")]
    NonUtf8,
    /// Namespace identity verification failed before spawning.
    #[error("namespace identity verification failed")]
    NamespaceIdentity,
    /// nsenter itself failed, independently of the target program.
    #[error("namespace entry failed (status {status:?})")]
    NamespaceEnter {
        /// nsenter exit status, without retaining untrusted diagnostics.
        status: Option<i32>,
    },
    /// A shared filesystem socket could redirect wg to a host userspace device.
    #[error("refusing userspace WireGuard socket: {}", .0.display())]
    UserspaceWireguardSocket(PathBuf),
}

fn bounded(message: &str) -> String {
    message.chars().take(200).collect()
}

impl ExecError {
    /// Bounds retained I/O diagnostics to 200 Unicode characters.
    #[must_use]
    pub fn spawn(message: &str) -> Self {
        Self::Spawn(bounded(message))
    }
}

/// Where a command observes or changes kernel state.
#[derive(Debug, Clone, Copy)]
pub enum ExecTarget<'a> {
    /// The caller's network namespace.
    Host,
    /// A namespace pinned by its open descriptor, never by name.
    Netns(&'a NetnsHandle),
}

/// The only command and wall-clock operations needed by collectors.
///
/// Adapters implement host execution; namespace execution fails closed by default.
/// An adapter without an executor cannot compile:
///
/// ```compile_fail
/// use scupper_sys::system::System;
/// struct MissingExecutor;
/// impl System for MissingExecutor {
///     fn now_unix_secs(&self) -> u64 { 0 }
/// }
/// ```
pub trait System {
    /// Optional process-local canonical cache and the exact nft executable path.
    fn canon_cache(&self) -> Option<(&std::cell::RefCell<crate::canon::CanonCache>, &Path)> {
        None
    }

    /// Executes one utility with literal arguments and a hard deadline.
    ///
    /// # Errors
    ///
    /// Returns an execution error rather than partial or lossy output.
    fn run(
        &self,
        program: Program,
        args: &[String],
        timeout: Duration,
    ) -> Result<ExecOutput, ExecError>;

    /// Executes in a pinned namespace or on the host.
    ///
    /// The default supports existing host-only adapters and fails closed for
    /// namespace targets. Adapters supporting namespaces must override it.
    ///
    /// # Errors
    /// Returns an execution error or an unsupported-target error.
    fn run_in(
        &self,
        target: ExecTarget<'_>,
        program: Program,
        args: &[String],
        timeout: Duration,
    ) -> Result<ExecOutput, ExecError> {
        match target {
            ExecTarget::Host => self.run(program, args, timeout),
            ExecTarget::Netns(_) => Err(ExecError::spawn("namespace execution unsupported")),
        }
    }

    /// Writes input bytes and closes stdin within the command's hard deadline.
    /// Input is never added to argv, diagnostics or the environment.
    /// The caller owns and must zeroize secret input bytes.
    ///
    /// # Errors
    /// Returns an execution error; host-only legacy adapters reject stdin.
    fn run_with_stdin(
        &self,
        _target: ExecTarget<'_>,
        _program: Program,
        _args: &[String],
        _stdin: &[u8],
        _timeout: Duration,
    ) -> Result<ExecOutput, ExecError> {
        Err(ExecError::spawn("stdin execution unsupported"))
    }

    /// Shared filesystem UAPI directories to check before namespace wg access.
    fn wireguard_socket_dirs(&self) -> Vec<PathBuf> {
        vec!["/var/run/wireguard".into(), "/run/wireguard".into()]
    }

    /// Reads the host namespace UDP socket inventory; never called after setns.
    ///
    /// # Errors
    /// Returns procfs read errors, including a missing IPv6 socket inventory.
    fn read_host_udp(&self, ipv6: bool) -> std::io::Result<String> {
        std::fs::read_to_string(if ipv6 {
            "/proc/net/udp6"
        } else {
            "/proc/net/udp"
        })
    }

    /// Whole Unix seconds, saturating at zero before the epoch.
    fn now_unix_secs(&self) -> u64;
}

/// Refuses any shared UAPI pathname, including dangling symlinks. Read failures
/// also fail closed. Namespace wg commands must name a single interface.
pub(crate) fn check_wg_args(
    sys: &(impl System + ?Sized),
    args: &[String],
) -> Result<(), ExecError> {
    if args.first().is_some_and(|s| s == "pubkey") {
        return Ok(());
    }
    let ifname = args
        .get(1)
        .ok_or_else(|| ExecError::spawn("wg interface required"))?;
    scupper_core::rules::IfName::new(ifname)
        .map_err(|_| ExecError::spawn("invalid wg interface"))?;
    for dir in sys.wireguard_socket_dirs() {
        let path = dir.join(format!("{ifname}.sock"));
        match std::fs::symlink_metadata(&path) {
            Ok(_) => return Err(ExecError::UserspaceWireguardSocket(path)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(ExecError::spawn(&error.to_string())),
        }
    }
    Ok(())
}

/// Executes the configured absolute paths in a minimal fixed environment.
#[derive(Debug, Default)]
pub struct RealSystem {
    canon_cache: std::cell::RefCell<crate::canon::CanonCache>,
    programs: Programs,
    wireguard_dirs: Option<Vec<PathBuf>>,
}

impl RealSystem {
    /// Uses validated executable paths, including any distro-specific overrides.
    #[must_use]
    pub fn new(programs: Programs) -> Self {
        Self {
            programs,
            canon_cache: std::cell::RefCell::default(),
            wireguard_dirs: None,
        }
    }

    /// Overrides the shared UAPI directories, primarily for isolated tests.
    #[must_use]
    pub fn with_wireguard_socket_dirs(mut self, dirs: Vec<PathBuf>) -> Self {
        self.wireguard_dirs = Some(dirs);
        self
    }

    fn command(&self, target: ExecTarget<'_>, program: Program, args: &[String]) -> Command {
        let mut command = match target {
            ExecTarget::Host => Command::new(self.programs.path(program)),
            ExecTarget::Netns(handle) => {
                let mut command = Command::new(self.programs.path(Program::Nsenter));
                command
                    .arg(format!("--net={}", handle.child_fd_path().display()))
                    .arg("--")
                    .arg(self.programs.path(program));
                command
            }
        };
        command
            .args(args)
            .env_clear()
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .env("LC_ALL", "C")
            .current_dir("/")
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
    }
}

// Never block the caller on a child in uninterruptible kernel sleep. A detached
// reaper owns it after a bounded poll, so it can be reaped if it eventually exits.
fn terminate(mut child: Child, deadline: Instant) {
    if let Some(pgid) = Pid::from_raw(child.id().cast_signed()) {
        let _ = kill_process_group(pgid, Signal::KILL);
    }
    let reap_deadline = (Instant::now() + Duration::from_millis(500)).min(deadline);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return,
            Err(_) => break,
            Ok(None) => {}
        }
        if Instant::now() >= reap_deadline {
            break;
        }
        thread::sleep(
            Duration::from_millis(2).min(reap_deadline.saturating_duration_since(Instant::now())),
        );
    }
    let _ = thread::Builder::new()
        .name("exec-reaper".into())
        .spawn(move || {
            let _ = child.wait();
        });
}

fn join_readers(readers: Vec<thread::JoinHandle<()>>, deadline: Instant) {
    while readers.iter().any(|reader| !reader.is_finished()) && Instant::now() < deadline {
        thread::sleep(
            Duration::from_millis(2).min(deadline.saturating_duration_since(Instant::now())),
        );
    }
    for reader in readers {
        if reader.is_finished() {
            let _ = reader.join();
        }
        // Dropping an unfinished handle detaches the reader. Its bounded buffer
        // and pipe are released when the killed process group's pipes close.
    }
}

fn read_pipe(pipe: impl Read, stream: Stream) -> Result<String, ExecError> {
    let mut bytes = Vec::new();
    pipe.take((OUTPUT_CAP + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| ExecError::spawn(&error.to_string()))?;
    if bytes.len() > OUTPUT_CAP {
        return Err(ExecError::OutputTooLarge { stream });
    }
    String::from_utf8(bytes).map_err(|_| ExecError::NonUtf8)
}

fn collect(
    child: &mut Child,
    started: Instant,
    timeout: Duration,
    readers: &mut Vec<thread::JoinHandle<()>>,
    mut input: Option<&[u8]>,
) -> Result<ExecOutput, ExecError> {
    // Nonblocking writes are interleaved with output draining and deadline
    // checks. A full stdin pipe cannot block this thread or outlive the budget.
    let mut stdin = child.stdin.take();
    if let Some(pipe) = &stdin {
        let flags = rustix::fs::fcntl_getfl(pipe)
            .and_then(|flags| rustix::fs::fcntl_setfl(pipe, flags | rustix::fs::OFlags::NONBLOCK));
        flags.map_err(|error| ExecError::spawn(&error.to_string()))?;
    }
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| ExecError::spawn("stdout pipe unavailable"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| ExecError::spawn("stderr pipe unavailable"))?;
    let (sender, receiver) = mpsc::channel();
    let err_sender = sender.clone();
    // The deadline covers EOF, including pipes inherited by descendants.
    // Keep the handles so readers can be joined within the cleanup budget.
    readers.push(
        thread::Builder::new()
            .name("exec-stdout".into())
            .spawn(move || {
                let _ = sender.send((0, read_pipe(stdout, Stream::Stdout)));
            })
            .map_err(|error| ExecError::spawn(&error.to_string()))?,
    );
    readers.push(
        thread::Builder::new()
            .name("exec-stderr".into())
            .spawn(move || {
                let _ = err_sender.send((1, read_pipe(stderr, Stream::Stderr)));
            })
            .map_err(|error| ExecError::spawn(&error.to_string()))?,
    );

    let mut streams = [None, None];
    loop {
        if started.elapsed() >= timeout {
            return Err(ExecError::Timeout { after: timeout });
        }
        if let (Some(pipe), Some(bytes)) = (&mut stdin, &mut input) {
            if bytes.is_empty() {
                stdin.take(); // EOF is part of the stdin contract.
            } else {
                match pipe.write(&bytes[..bytes.len().min(64 * 1024)]) {
                    Ok(0) => return Err(ExecError::spawn("stdin write made no progress")),
                    Ok(count) => *bytes = &bytes[count..],
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                        ) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => {
                        stdin.take();
                    }
                    Err(error) => return Err(ExecError::spawn(&error.to_string())),
                }
            }
        }
        while let Ok((index, result)) = receiver.try_recv() {
            streams[index] = Some(result?);
        }
        let status = child
            .try_wait()
            .map_err(|error| ExecError::spawn(&error.to_string()))?;
        if let (Some(status), [Some(stdout), Some(stderr)]) = (status, &mut streams)
            && stdin.is_none()
        {
            return Ok(ExecOutput {
                status: status.code(),
                stdout: std::mem::take(stdout),
                stderr: std::mem::take(stderr),
            });
        }
        thread::sleep(Duration::from_millis(2).min(timeout.saturating_sub(started.elapsed())));
    }
}

impl RealSystem {
    fn execute(
        &self,
        target: ExecTarget<'_>,
        program: Program,
        args: &[String],
        input: Option<&[u8]>,
        timeout: Duration,
    ) -> Result<ExecOutput, ExecError> {
        if let ExecTarget::Netns(handle) = target {
            handle
                .verify(handle.identity())
                .map_err(|_| ExecError::NamespaceIdentity)?;
            if program == Program::Wg {
                check_wg_args(self, args)?;
            }
        }
        self.execute_verified(target, program, args, input, timeout)
    }

    // Only reached after identity/socket checks. Kept separate so unprivileged
    // unit tests can exercise nsenter failures with a synthetic held descriptor.
    fn execute_verified(
        &self,
        target: ExecTarget<'_>,
        program: Program,
        args: &[String],
        input: Option<&[u8]>,
        timeout: Duration,
    ) -> Result<ExecOutput, ExecError> {
        let started = Instant::now();
        let mut command = self.command(target, program, args);
        if input.is_some() {
            command.stdin(Stdio::piped());
        }
        let mut child = command
            .spawn()
            .map_err(|error| ExecError::spawn(&error.to_string()))?;
        let deadline = started + timeout + Duration::from_millis(900);
        let mut readers = Vec::with_capacity(2);
        let result = collect(&mut child, started, timeout, &mut readers, input);
        if result.is_err() {
            terminate(child, deadline);
        }
        join_readers(readers, deadline);
        namespace_result(target, result)
    }
}

// The probe has its own single-threaded namespace entry; its stdin is a file,
// never a request pipe. Reuse the same capture/deadline/group-kill machinery.
/// Runs an explicitly selected executable with an inherited file on stdin.
/// Applies the same output cap, environment, process-group termination and wall
/// deadline as kernel-command execution. Paths must come from trusted code.
///
/// # Errors
/// Returns spawn, capture, output-limit or timeout errors.
pub fn execute_file_command(
    mut command: Command,
    file: std::fs::File,
    timeout: Duration,
) -> Result<ExecOutput, ExecError> {
    command
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LC_ALL", "C")
        .current_dir("/")
        .process_group(0)
        .stdin(Stdio::from(file))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let started = Instant::now();
    let mut child = command
        .spawn()
        .map_err(|error| ExecError::spawn(&error.to_string()))?;
    let deadline = started + timeout + Duration::from_millis(900);
    let mut readers = Vec::with_capacity(2);
    let result = collect(&mut child, started, timeout, &mut readers, None);
    if result.is_err() {
        terminate(child, deadline);
    }
    join_readers(readers, deadline);
    result
}

fn namespace_result(
    target: ExecTarget<'_>,
    result: Result<ExecOutput, ExecError>,
) -> Result<ExecOutput, ExecError> {
    let output = result?;
    if matches!(target, ExecTarget::Netns(_))
        && output.status != Some(0)
        && output.stderr.starts_with("nsenter:")
    {
        return Err(ExecError::NamespaceEnter {
            status: output.status,
        });
    }
    Ok(output)
}

impl System for RealSystem {
    fn canon_cache(&self) -> Option<(&std::cell::RefCell<crate::canon::CanonCache>, &Path)> {
        Some((&self.canon_cache, self.programs.path(Program::Nft)))
    }

    fn run(
        &self,
        program: Program,
        args: &[String],
        timeout: Duration,
    ) -> Result<ExecOutput, ExecError> {
        self.run_in(ExecTarget::Host, program, args, timeout)
    }

    fn run_in(
        &self,
        target: ExecTarget<'_>,
        program: Program,
        args: &[String],
        timeout: Duration,
    ) -> Result<ExecOutput, ExecError> {
        self.execute(target, program, args, None, timeout)
    }

    fn run_with_stdin(
        &self,
        target: ExecTarget<'_>,
        program: Program,
        args: &[String],
        stdin: &[u8],
        timeout: Duration,
    ) -> Result<ExecOutput, ExecError> {
        self.execute(target, program, args, Some(stdin), timeout)
    }

    fn wireguard_socket_dirs(&self) -> Vec<PathBuf> {
        self.wireguard_dirs
            .clone()
            .unwrap_or_else(|| vec!["/var/run/wireguard".into(), "/run/wireguard".into()])
    }

    fn now_unix_secs(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

/// Scripted test support, available only with the `testing` feature.
#[cfg(feature = "testing")]
pub mod testing {
    use std::{cell::RefCell, collections::BTreeMap, collections::VecDeque, time::Duration};

    use super::{ExecError, ExecOutput, ExecTarget, Program, System};

    /// One recorded command, including its execution budget.
    #[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
    pub struct Call {
        /// The selected executable.
        pub program: Program,
        /// Literal command arguments.
        pub args: Vec<String>,
        /// Pinned namespace identity, or None for the host.
        pub target_identity: Option<(u64, u64)>,
        /// Input length only; secret input bytes are never recorded.
        pub stdin_len: Option<usize>,
        /// Requested deadline.
        pub timeout: Duration,
    }

    type ScriptKey = (Option<(u64, u64)>, Program, Vec<String>);
    type Scripts = BTreeMap<ScriptKey, VecDeque<Result<ExecOutput, ExecError>>>;

    /// Fixed clock and FIFO responses keyed by program and exact argv.
    #[derive(Debug)]
    pub struct FakeSystem {
        now: u64,
        scripts: RefCell<Scripts>,
        calls: RefCell<Vec<Call>>,
        wireguard_dirs: Option<Vec<std::path::PathBuf>>,
    }

    impl FakeSystem {
        /// Creates an empty script with a fixed Unix clock.
        #[must_use]
        pub fn new(now_unix_secs: u64) -> Self {
            Self {
                now: now_unix_secs,
                scripts: RefCell::new(BTreeMap::new()),
                calls: RefCell::new(Vec::new()),
                wireguard_dirs: None,
            }
        }

        /// Sets isolated shared UAPI directories for dispatch tests.
        #[must_use]
        pub fn with_wireguard_socket_dirs(mut self, dirs: Vec<std::path::PathBuf>) -> Self {
            self.wireguard_dirs = Some(dirs);
            self
        }

        /// Appends a response for one exact command.
        pub fn push(
            &self,
            program: Program,
            args: &[String],
            response: Result<ExecOutput, ExecError>,
        ) {
            self.push_in(ExecTarget::Host, program, args, response);
        }

        /// Appends a response for an exact namespace identity and command.
        pub fn push_in(
            &self,
            target: ExecTarget<'_>,
            program: Program,
            args: &[String],
            response: Result<ExecOutput, ExecError>,
        ) {
            self.scripts
                .borrow_mut()
                .entry((identity(target), program, args.to_vec()))
                .or_default()
                .push_back(response);
        }

        #[allow(clippy::panic)] // An unscripted command is a test failure by contract.
        fn dispatch(
            &self,
            target: ExecTarget<'_>,
            program: Program,
            args: &[String],
            stdin_len: Option<usize>,
            timeout: Duration,
        ) -> Result<ExecOutput, ExecError> {
            let target_identity = identity(target);
            self.calls.borrow_mut().push(Call {
                program,
                args: args.to_vec(),
                timeout,
                target_identity,
                stdin_len,
            });
            self.scripts
                .borrow_mut()
                .get_mut(&(target_identity, program, args.to_vec()))
                .and_then(VecDeque::pop_front)
                .unwrap_or_else(|| panic!("unexpected or exhausted command: {program:?} {args:?}"))
        }

        /// Returns the ordered call history, including unexpected calls.
        #[must_use]
        pub fn calls(&self) -> Vec<Call> {
            self.calls.borrow().clone()
        }
    }

    /// Records literal argv and input lengths around a real or fake executor.
    pub struct RecordingSystem<'a> {
        inner: &'a dyn System,
        calls: RefCell<Vec<Call>>,
    }
    impl<'a> RecordingSystem<'a> {
        /// Wraps an executor without changing its namespace or secret handling.
        #[must_use]
        pub fn new(inner: &'a dyn System) -> Self {
            Self {
                inner,
                calls: RefCell::default(),
            }
        }
        /// Returns public command metadata; stdin bytes are never retained.
        #[must_use]
        pub fn calls(&self) -> Vec<Call> {
            self.calls.borrow().clone()
        }
        fn record(
            &self,
            target: ExecTarget<'_>,
            program: Program,
            args: &[String],
            stdin_len: Option<usize>,
            timeout: Duration,
        ) {
            self.calls.borrow_mut().push(Call {
                program,
                args: args.to_vec(),
                target_identity: identity(target),
                stdin_len,
                timeout,
            });
        }
    }
    impl System for RecordingSystem<'_> {
        fn run(
            &self,
            program: Program,
            args: &[String],
            timeout: Duration,
        ) -> Result<ExecOutput, ExecError> {
            self.run_in(ExecTarget::Host, program, args, timeout)
        }
        fn run_in(
            &self,
            target: ExecTarget<'_>,
            program: Program,
            args: &[String],
            timeout: Duration,
        ) -> Result<ExecOutput, ExecError> {
            self.record(target, program, args, None, timeout);
            self.inner.run_in(target, program, args, timeout)
        }
        fn run_with_stdin(
            &self,
            target: ExecTarget<'_>,
            program: Program,
            args: &[String],
            stdin: &[u8],
            timeout: Duration,
        ) -> Result<ExecOutput, ExecError> {
            self.record(target, program, args, Some(stdin.len()), timeout);
            self.inner
                .run_with_stdin(target, program, args, stdin, timeout)
        }
        fn now_unix_secs(&self) -> u64 {
            self.inner.now_unix_secs()
        }
        fn wireguard_socket_dirs(&self) -> Vec<std::path::PathBuf> {
            self.inner.wireguard_socket_dirs()
        }
        fn read_host_udp(&self, ipv6: bool) -> std::io::Result<String> {
            self.inner.read_host_udp(ipv6)
        }
    }

    fn identity(target: ExecTarget<'_>) -> Option<(u64, u64)> {
        match target {
            ExecTarget::Host => None,
            ExecTarget::Netns(handle) => Some(handle.identity()),
        }
    }

    impl System for FakeSystem {
        fn run(
            &self,
            program: Program,
            args: &[String],
            timeout: Duration,
        ) -> Result<ExecOutput, ExecError> {
            self.run_in(ExecTarget::Host, program, args, timeout)
        }

        fn run_in(
            &self,
            target: ExecTarget<'_>,
            program: Program,
            args: &[String],
            timeout: Duration,
        ) -> Result<ExecOutput, ExecError> {
            self.dispatch(target, program, args, None, timeout)
        }

        fn run_with_stdin(
            &self,
            target: ExecTarget<'_>,
            program: Program,
            args: &[String],
            stdin: &[u8],
            timeout: Duration,
        ) -> Result<ExecOutput, ExecError> {
            self.dispatch(target, program, args, Some(stdin.len()), timeout)
        }

        fn wireguard_socket_dirs(&self) -> Vec<std::path::PathBuf> {
            self.wireguard_dirs
                .clone()
                .unwrap_or_else(|| vec!["/var/run/wireguard".into(), "/run/wireguard".into()])
        }

        fn now_unix_secs(&self) -> u64 {
            self.now
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::{error::Error, io::Write};

    use super::*;

    fn system(path: &str) -> Result<RealSystem, ExecError> {
        Ok(RealSystem::new(Programs::new([(Program::Wg, path)])?))
    }

    fn args(args: &[&str]) -> Vec<String> {
        args.iter().map(|arg| (*arg).into()).collect()
    }

    #[test]
    fn adapter_defaults_preserve_host_and_reject_unsupported_netns() -> Result<(), Box<dyn Error>> {
        struct TargetAware;
        impl System for TargetAware {
            fn run(
                &self,
                program: Program,
                args: &[String],
                timeout: Duration,
            ) -> Result<ExecOutput, ExecError> {
                self.run_in(ExecTarget::Host, program, args, timeout)
            }
            fn run_in(
                &self,
                target: ExecTarget<'_>,
                _program: Program,
                _args: &[String],
                _timeout: Duration,
            ) -> Result<ExecOutput, ExecError> {
                assert!(matches!(target, ExecTarget::Host));
                Ok(ExecOutput {
                    status: Some(0),
                    stdout: String::new(),
                    stderr: String::new(),
                })
            }
            fn now_unix_secs(&self) -> u64 {
                0
            }
        }
        struct Legacy;
        impl System for Legacy {
            fn run(
                &self,
                program: Program,
                args: &[String],
                timeout: Duration,
            ) -> Result<ExecOutput, ExecError> {
                TargetAware.run(program, args, timeout)
            }
            fn now_unix_secs(&self) -> u64 {
                0
            }
        }
        assert_eq!(
            TargetAware.run(Program::Ip, &[], EXEC_TIMEOUT)?.status,
            Some(0)
        );
        assert_eq!(
            Legacy
                .run_in(ExecTarget::Host, Program::Ip, &[], EXEC_TIMEOUT)?
                .status,
            Some(0)
        );
        let handle = crate::netns::testing::handle()?;
        assert!(
            Legacy
                .run_in(ExecTarget::Netns(&handle), Program::Ip, &[], EXEC_TIMEOUT)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn target_argv_is_exact() -> Result<(), Box<dyn Error>> {
        use std::os::unix::fs::MetadataExt;
        let handle = crate::netns::testing::handle()?;
        let literal_path = format!("/proc/{}/fd/{}", std::process::id(), handle.raw_fd());
        let stat = std::fs::metadata(&literal_path)?;
        assert_eq!((stat.dev(), stat.ino()), handle.identity());
        let sys = RealSystem::new(Programs::new([
            (Program::Ip, "/custom/ip"),
            (Program::Nsenter, "/custom/nsenter"),
        ])?);
        let arguments = args(&["-j", "link", "show"]);
        let host = sys.command(ExecTarget::Host, Program::Ip, &arguments);
        assert_eq!(host.get_program(), "/custom/ip");
        assert_eq!(host.get_args().collect::<Vec<_>>(), ["-j", "link", "show"]);
        let ns = sys.command(ExecTarget::Netns(&handle), Program::Ip, &arguments);
        assert_eq!(ns.get_program(), "/custom/nsenter");
        assert_eq!(
            ns.get_args()
                .map(|s| s.to_string_lossy().into_owned())
                .collect::<Vec<_>>(),
            [
                format!("--net=/proc/{}/fd/{}", std::process::id(), handle.raw_fd()),
                "--".into(),
                "/custom/ip".into(),
                "-j".into(),
                "link".into(),
                "show".into(),
            ]
        );
        Ok(())
    }

    #[test]
    fn refuses_host_identity_before_exec() -> Result<(), Box<dyn Error>> {
        let handle = crate::netns::testing::handle()?;
        let sys = RealSystem::new(Programs::new([(Program::Nsenter, "/missing/nsenter")])?);
        for input in [None, Some(b"secret".as_slice())] {
            assert_eq!(
                sys.execute(
                    ExecTarget::Netns(&handle),
                    Program::Ip,
                    &[],
                    input,
                    EXEC_TIMEOUT
                ),
                Err(ExecError::NamespaceIdentity)
            );
        }
        Ok(())
    }

    #[test]
    fn nsenter_failure_is_not_a_target_failure() -> Result<(), Box<dyn Error>> {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("nsenter-test-{}", std::process::id()));
        std::fs::create_dir(&dir)?;
        let script = dir.join("nsenter");
        let handle = crate::netns::testing::handle()?;
        let sys = RealSystem::new(Programs::new([(Program::Nsenter, &script)])?);
        for (stderr, code, expected) in [
            (
                "nsenter: cannot enter namespace: device absent",
                1,
                Some(ExecError::NamespaceEnter { status: Some(1) }),
            ),
            ("Unable to access interface: No such device", 1, None),
            ("nsenter: harmless output", 0, None),
        ] {
            std::fs::write(
                &script,
                format!("#!/bin/sh\nprintf '%s' '{stderr}' >&2\nexit {code}\n"),
            )?;
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700))?;
            let result = sys.execute_verified(
                ExecTarget::Netns(&handle),
                Program::Ip,
                &[],
                None,
                EXEC_TIMEOUT,
            );
            if let Some(error) = expected {
                assert_eq!(result, Err(error));
            } else {
                let output = result?;
                assert_eq!(output.status, Some(code));
                assert_eq!(output.stderr, stderr);
            }
        }
        std::fs::remove_dir_all(dir)?;
        Ok(())
    }

    #[test]
    fn broken_stdin_pipe_preserves_child_diagnostics() -> Result<(), Box<dyn Error>> {
        let output = system("/bin/sh")?.run_with_stdin(
            ExecTarget::Host,
            Program::Wg,
            &args(&[
                "-c",
                "exec 0<&-; printf 'invalid ruleset\\n' >&2; printf 'partial output\\n'; exit 7",
            ]),
            &vec![b'x'; 2 * OUTPUT_CAP],
            EXEC_TIMEOUT,
        )?;
        assert_eq!(output.status, Some(7));
        assert_eq!(output.stdout, "partial output\n");
        assert_eq!(output.stderr, "invalid ruleset\n");
        Ok(())
    }

    #[test]
    fn stdin_delivery_eof_and_nonreader_deadline() -> Result<(), Box<dyn Error>> {
        use std::os::unix::fs::PermissionsExt;
        struct Scripts(PathBuf);
        impl Drop for Scripts {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let scripts =
            Scripts(std::env::temp_dir().join(format!("stdin-test-{}", std::process::id())));
        std::fs::create_dir(&scripts.0)?;
        let read = scripts.0.join("read");
        let ignore = scripts.0.join("ignore");
        for (path, body) in [
            (&read, "#!/bin/sh\nexec /usr/bin/cat\n"),
            (&ignore, "#!/bin/sh\nexec /usr/bin/sleep 30\n"),
        ] {
            std::fs::write(path, body)?;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
        }
        let sys = RealSystem::new(Programs::new([(Program::Wg, &read)])?);
        for bytes in [Vec::new(), b"hello\n".to_vec(), vec![b'x'; 512 * 1024]] {
            let output =
                sys.run_with_stdin(ExecTarget::Host, Program::Wg, &[], &bytes, EXEC_TIMEOUT)?;
            assert_eq!(output.status, Some(0));
            assert_eq!(output.stdout.as_bytes(), bytes);
        }
        let sys = RealSystem::new(Programs::new([(Program::Wg, &ignore)])?);
        let timeout = Duration::from_millis(100);
        let started = Instant::now();
        assert_eq!(
            sys.run_with_stdin(
                ExecTarget::Host,
                Program::Wg,
                &[],
                &vec![b'x'; 2 * OUTPUT_CAP],
                timeout
            ),
            Err(ExecError::Timeout { after: timeout })
        );
        assert!(started.elapsed() < timeout + Duration::from_secs(1));
        Ok(())
    }

    #[test]
    fn exec_success_and_status() -> Result<(), Box<dyn Error>> {
        for (path, code) in [("/usr/bin/true", 0), ("/usr/bin/false", 1)] {
            let output = system(path)?.run(Program::Wg, &[], EXEC_TIMEOUT)?;
            assert_eq!(output.status, Some(code));
            assert_eq!(output.stdout, "");
            assert_eq!(output.stderr, "");
        }
        Ok(())
    }

    #[test]
    fn exec_timeout_kills_child() -> Result<(), Box<dyn Error>> {
        let sys = system("/usr/bin/sleep")?;
        let timeout = Duration::from_millis(200);
        let started = Instant::now();
        let mut child = sys
            .command(ExecTarget::Host, Program::Wg, &args(&["5"]))
            .spawn()?;
        let pid = child.id();
        let mut readers = vec![];
        assert_eq!(
            collect(&mut child, started, timeout, &mut readers, None),
            Err(ExecError::Timeout { after: timeout })
        );
        let deadline = started + timeout + Duration::from_millis(900);
        terminate(child, deadline);
        join_readers(readers, deadline);
        assert!(started.elapsed() < timeout + Duration::from_secs(1));
        // kill -0 fails for a process that has been killed AND reaped (including
        // on non-Linux Unix systems, where /proc is not available).
        let exists = Command::new("/usr/bin/kill")
            .args(["-0", &pid.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;
        assert!(!exists.success(), "timed-out child {pid} still exists");
        Ok(())
    }

    #[test]
    fn exec_stdin_is_null() -> Result<(), Box<dyn Error>> {
        let started = Instant::now();
        let output = system("/usr/bin/cat")?.run(Program::Wg, &[], EXEC_TIMEOUT)?;
        assert_eq!(
            output,
            ExecOutput {
                status: Some(0),
                stdout: String::new(),
                stderr: String::new()
            }
        );
        assert!(started.elapsed() < Duration::from_secs(1));
        Ok(())
    }

    #[test]
    fn exec_cwd_is_root() -> Result<(), Box<dyn Error>> {
        let output = system("/usr/bin/pwd")?.run(Program::Wg, &[], EXEC_TIMEOUT)?;
        assert_eq!(output.status, Some(0));
        assert_eq!(output.stdout, "/\n");
        Ok(())
    }

    fn assert_grandchild_killed(tail: &str, expected: ExecError) -> Result<(), Box<dyn Error>> {
        struct PidFile(PathBuf);
        impl Drop for PidFile {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(&self.0);
            }
        }
        // This helper runs only in an isolated harness subprocess. Adopt the
        // orphan on Linux so the test does not depend on container PID 1 reaping.
        #[cfg(target_os = "linux")]
        rustix::process::set_child_subreaper(Some(Pid::INIT))
            .map_err(|error| std::io::Error::from_raw_os_error(error.raw_os_error()))?;
        let file = PidFile(std::env::temp_dir().join(format!(
            "exec-grandchild-{}-{}.pid",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
        )));
        let timeout = Duration::from_millis(200);
        let started = Instant::now();
        // A shell is used only in this test to arrange an inherited-pipe tree.
        let script = format!("/usr/bin/sleep 30 & printf '%s' \"$!\" > \"$1\"; {tail}");
        let result = system("/bin/sh")?.run(
            Program::Wg,
            &[
                "-c".into(),
                script,
                "exec-test".into(),
                file.0.to_string_lossy().into_owned(),
            ],
            timeout,
        );
        assert_eq!(result, Err(expected));
        assert!(started.elapsed() < timeout + Duration::from_secs(1));
        let pid = std::fs::read_to_string(&file.0)?;
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            #[cfg(target_os = "linux")]
            let _ = rustix::process::waitpid(
                Pid::from_raw(pid.parse()?),
                rustix::process::WaitOptions::NOHANG,
            );
            let exists = Command::new("/usr/bin/kill")
                .args(["-0", &pid])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()?
                .success();
            if !exists {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "grandchild {pid} survived group cleanup"
            );
            thread::sleep(Duration::from_millis(10));
        }
        Ok(())
    }

    #[test]
    fn exec_timeout_kills_process_group() -> Result<(), Box<dyn Error>> {
        group_fixture("system::tests::timeout_process_group_fixture")
    }

    #[test]
    #[ignore = "subprocess fixture"]
    fn timeout_process_group_fixture() -> Result<(), Box<dyn Error>> {
        assert_grandchild_killed(
            "exec /usr/bin/sleep 30",
            ExecError::Timeout {
                after: Duration::from_millis(200),
            },
        )
    }

    #[test]
    fn exec_timeout_covers_inherited_pipes_after_child_exit() -> Result<(), Box<dyn Error>> {
        group_fixture("system::tests::inherited_pipes_fixture")
    }

    #[test]
    #[ignore = "subprocess fixture"]
    fn inherited_pipes_fixture() -> Result<(), Box<dyn Error>> {
        assert_grandchild_killed(
            "exit 0",
            ExecError::Timeout {
                after: Duration::from_millis(200),
            },
        )
    }

    #[test]
    fn exec_output_error_kills_process_group() -> Result<(), Box<dyn Error>> {
        group_fixture("system::tests::output_error_process_group_fixture")
    }

    fn group_fixture(name: &str) -> Result<(), Box<dyn Error>> {
        let output = fixture(name)?;
        assert_eq!(output.status, Some(0), "{}{}", output.stdout, output.stderr);
        Ok(())
    }

    #[test]
    #[ignore = "subprocess fixture"]
    fn output_error_process_group_fixture() -> Result<(), Box<dyn Error>> {
        assert_grandchild_killed(
            "exec /usr/bin/yes",
            ExecError::OutputTooLarge {
                stream: Stream::Stdout,
            },
        )
    }

    #[test]
    fn exec_reader_join_is_bounded() -> Result<(), Box<dyn Error>> {
        let (release, blocked) = mpsc::channel();
        let (done, finished) = mpsc::channel();
        let reader = thread::Builder::new().spawn(move || {
            let _ = blocked.recv();
            let _ = done.send(());
        })?;
        let started = Instant::now();
        join_readers(vec![reader], started + Duration::from_millis(30));
        assert!(started.elapsed() < Duration::from_secs(1));
        release.send(())?;
        finished.recv_timeout(Duration::from_secs(1))?;
        Ok(())
    }

    #[test]
    fn exec_output_cap() -> Result<(), Box<dyn Error>> {
        let started = Instant::now();
        assert_eq!(
            system("/usr/bin/yes")?.run(Program::Wg, &[], EXEC_TIMEOUT),
            Err(ExecError::OutputTooLarge {
                stream: Stream::Stdout
            })
        );
        assert!(started.elapsed() < Duration::from_secs(2));
        Ok(())
    }

    #[test]
    fn exec_env_is_clean() -> Result<(), Box<dyn Error>> {
        let output = system("/usr/bin/env")?.run(Program::Wg, &[], EXEC_TIMEOUT)?;
        let mut lines: Vec<_> = output.stdout.lines().collect();
        lines.sort_unstable();
        assert_eq!(lines, ["LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"]);
        Ok(())
    }

    #[test]
    fn exec_relative_path_rejected() {
        for path in ["wg", "./wg", "", "../usr/bin/wg"] {
            assert!(Programs::new([(Program::Wg, path)]).is_err());
        }
        for program in [
            Program::Cat,
            Program::Wg,
            Program::Ip,
            Program::Nft,
            Program::Tc,
            Program::Systemctl,
            Program::Unshare,
            Program::Nsenter,
            Program::Sysctl,
            Program::Conntrack,
        ] {
            assert!(Programs::new([(program, "relative")]).is_err());
            assert_eq!(
                Programs::default().path(program),
                Path::new(program.default_path())
            );
        }
    }

    // Test-harness subprocesses exercise both pipes, malformed bytes, and
    // process-wide test setup without exposing an escape hatch in the library.
    fn fixture(name: &str) -> Result<ExecOutput, Box<dyn Error>> {
        let sys = RealSystem::new(Programs::new([(Program::Wg, std::env::current_exe()?)])?);
        Ok(sys.run(
            Program::Wg,
            &args(&["--ignored", "--exact", name, "--nocapture"]),
            EXEC_TIMEOUT,
        )?)
    }

    #[test]
    #[ignore = "subprocess fixture"]
    fn both_pipes_fixture() -> Result<(), Box<dyn Error>> {
        let block = vec![b'x'; 256 * 1024];
        std::io::stdout().write_all(&block)?;
        std::io::stderr().write_all(&block)?;
        Ok(())
    }

    #[test]
    fn exec_drains_both_pipes() -> Result<(), Box<dyn Error>> {
        let output = fixture("system::tests::both_pipes_fixture")?;
        assert_eq!(output.status, Some(0));
        assert!(output.stdout.len() >= 256 * 1024);
        assert_eq!(output.stderr.len(), 256 * 1024);
        Ok(())
    }

    #[test]
    #[ignore = "subprocess fixture"]
    fn stderr_cap_fixture() -> Result<(), Box<dyn Error>> {
        std::io::stderr().write_all(&vec![b'x'; OUTPUT_CAP + 1])?;
        Ok(())
    }

    #[test]
    #[ignore = "subprocess fixture"]
    fn non_utf8_fixture() -> Result<(), Box<dyn Error>> {
        std::io::stdout().write_all(&[0xff])?;
        Ok(())
    }

    #[test]
    fn exec_rejects_stderr_overflow_and_non_utf8() -> Result<(), Box<dyn Error>> {
        for (fixture_name, expected) in [
            (
                "system::tests::stderr_cap_fixture",
                ExecError::OutputTooLarge {
                    stream: Stream::Stderr,
                },
            ),
            ("system::tests::non_utf8_fixture", ExecError::NonUtf8),
        ] {
            let error = fixture(fixture_name).err().ok_or("fixture succeeded")?;
            assert_eq!(error.downcast_ref::<ExecError>(), Some(&expected));
        }
        Ok(())
    }

    #[test]
    fn exec_diagnostics_are_bounded() {
        let message = "界".repeat(1_000);
        assert_eq!(
            ExecError::spawn(&message),
            ExecError::Spawn("界".repeat(200))
        );
        assert!(ExecError::Spawn(message).to_string().chars().count() < 220);
    }

    #[test]
    #[cfg(feature = "testing")]
    #[should_panic(expected = "unexpected or exhausted command: Ip")]
    fn fake_rejects_unknown_calls() {
        let fake = testing::FakeSystem::new(1_000);
        let _ = fake.run(Program::Ip, &args(&["route"]), EXEC_TIMEOUT);
    }
}
