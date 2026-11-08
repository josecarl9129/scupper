//! Bounded command execution behind an injectable clock and kernel interface.

use std::{
    io::Read,
    os::unix::process::CommandExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use rustix::process::{Pid, Signal, kill_process_group};
use thiserror::Error;

/// Default deadline for each kernel command.
pub const EXEC_TIMEOUT: Duration = Duration::from_secs(3);
/// Deadline for starting or stopping a tunnel unit.
pub const SYSTEMCTL_TIMEOUT: Duration = Duration::from_secs(30);
const OUTPUT_CAP: usize = 1024 * 1024;

/// A kernel utility selected without a shell or PATH lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Program {
    /// `WireGuard` inspection.
    Wg,
    /// Link and routing inspection.
    Ip,
    /// Firewall inspection.
    Nft,
    /// Traffic-control inspection.
    Tc,
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
    wg: PathBuf,
    ip: PathBuf,
    nft: PathBuf,
    tc: PathBuf,
    systemctl: PathBuf,
    unshare: PathBuf,
}

impl Default for Programs {
    fn default() -> Self {
        Self {
            wg: Program::Wg.default_path().into(),
            ip: Program::Ip.default_path().into(),
            nft: Program::Nft.default_path().into(),
            tc: Program::Tc.default_path().into(),
            systemctl: Program::Systemctl.default_path().into(),
            unshare: Program::Unshare.default_path().into(),
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
    #[error("exec output exceeded 1 MiB per stream")]
    OutputTooLarge,
    /// Either output stream was not valid UTF-8.
    #[error("exec output is not UTF-8")]
    NonUtf8,
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

/// The only command and wall-clock operations needed by collectors.
pub trait System {
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

    /// Whole Unix seconds, saturating at zero before the epoch.
    fn now_unix_secs(&self) -> u64;
}

/// Executes the configured absolute paths in a minimal fixed environment.
#[derive(Debug, Default)]
pub struct RealSystem {
    programs: Programs,
}

impl RealSystem {
    /// Uses validated executable paths, including any distro-specific overrides.
    #[must_use]
    pub const fn new(programs: Programs) -> Self {
        Self { programs }
    }

    fn command(&self, program: Program, args: &[String]) -> Command {
        let mut command = Command::new(self.programs.path(program));
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

fn read_pipe(pipe: impl Read) -> Result<String, ExecError> {
    let mut bytes = Vec::new();
    pipe.take((OUTPUT_CAP + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| ExecError::spawn(&error.to_string()))?;
    if bytes.len() > OUTPUT_CAP {
        return Err(ExecError::OutputTooLarge);
    }
    String::from_utf8(bytes).map_err(|_| ExecError::NonUtf8)
}

fn collect(
    child: &mut Child,
    started: Instant,
    timeout: Duration,
    readers: &mut Vec<thread::JoinHandle<()>>,
) -> Result<ExecOutput, ExecError> {
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
                let _ = sender.send((0, read_pipe(stdout)));
            })
            .map_err(|error| ExecError::spawn(&error.to_string()))?,
    );
    readers.push(
        thread::Builder::new()
            .name("exec-stderr".into())
            .spawn(move || {
                let _ = err_sender.send((1, read_pipe(stderr)));
            })
            .map_err(|error| ExecError::spawn(&error.to_string()))?,
    );

    let mut streams = [None, None];
    loop {
        if started.elapsed() >= timeout {
            return Err(ExecError::Timeout { after: timeout });
        }
        while let Ok((index, result)) = receiver.try_recv() {
            streams[index] = Some(result?);
        }
        let status = child
            .try_wait()
            .map_err(|error| ExecError::spawn(&error.to_string()))?;
        if let (Some(status), [Some(stdout), Some(stderr)]) = (status, &mut streams) {
            return Ok(ExecOutput {
                status: status.code(),
                stdout: std::mem::take(stdout),
                stderr: std::mem::take(stderr),
            });
        }
        thread::sleep(Duration::from_millis(2).min(timeout.saturating_sub(started.elapsed())));
    }
}

impl System for RealSystem {
    fn run(
        &self,
        program: Program,
        args: &[String],
        timeout: Duration,
    ) -> Result<ExecOutput, ExecError> {
        let started = Instant::now();
        let mut child = self
            .command(program, args)
            .spawn()
            .map_err(|error| ExecError::spawn(&error.to_string()))?;
        // Reserve less than the permitted extra second for bounded cleanup.
        let deadline = started + timeout + Duration::from_millis(900);
        let mut readers = Vec::with_capacity(2);
        let result = collect(&mut child, started, timeout, &mut readers);
        if result.is_err() {
            terminate(child, deadline);
        }
        join_readers(readers, deadline);
        result
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

    use super::{ExecError, ExecOutput, Program, System};

    /// One recorded command, including its execution budget.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Call {
        /// The selected executable.
        pub program: Program,
        /// Literal command arguments.
        pub args: Vec<String>,
        /// Requested deadline.
        pub timeout: Duration,
    }

    type Scripts = BTreeMap<(Program, Vec<String>), VecDeque<Result<ExecOutput, ExecError>>>;

    /// Fixed clock and FIFO responses keyed by program and exact argv.
    #[derive(Debug)]
    pub struct FakeSystem {
        now: u64,
        scripts: RefCell<Scripts>,
        calls: RefCell<Vec<Call>>,
    }

    impl FakeSystem {
        /// Creates an empty script with a fixed Unix clock.
        #[must_use]
        pub fn new(now_unix_secs: u64) -> Self {
            Self {
                now: now_unix_secs,
                scripts: RefCell::new(BTreeMap::new()),
                calls: RefCell::new(Vec::new()),
            }
        }

        /// Appends a response for one exact command.
        pub fn push(
            &self,
            program: Program,
            args: &[String],
            response: Result<ExecOutput, ExecError>,
        ) {
            self.scripts
                .borrow_mut()
                .entry((program, args.to_vec()))
                .or_default()
                .push_back(response);
        }

        /// Returns the ordered call history, including unexpected calls.
        #[must_use]
        pub fn calls(&self) -> Vec<Call> {
            self.calls.borrow().clone()
        }
    }

    impl System for FakeSystem {
        #[allow(clippy::panic)] // An unscripted command is a test failure by contract.
        fn run(
            &self,
            program: Program,
            args: &[String],
            timeout: Duration,
        ) -> Result<ExecOutput, ExecError> {
            self.calls.borrow_mut().push(Call {
                program,
                args: args.to_vec(),
                timeout,
            });
            self.scripts
                .borrow_mut()
                .get_mut(&(program, args.to_vec()))
                .and_then(VecDeque::pop_front)
                .unwrap_or_else(|| panic!("unexpected or exhausted command: {program:?} {args:?}"))
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
        let mut child = sys.command(Program::Wg, &args(&["5"])).spawn()?;
        let pid = child.id();
        let mut readers = vec![];
        assert_eq!(
            collect(&mut child, started, timeout, &mut readers),
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
        let file = PidFile(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("target")
                .join(format!(
                    "exec-grandchild-{}-{}.pid",
                    std::process::id(),
                    SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
                )),
        );
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
        assert_grandchild_killed("exec /usr/bin/yes", ExecError::OutputTooLarge)
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
            Err(ExecError::OutputTooLarge)
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
            Program::Wg,
            Program::Ip,
            Program::Nft,
            Program::Tc,
            Program::Systemctl,
            Program::Unshare,
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
                ExecError::OutputTooLarge,
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
