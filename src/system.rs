//! Bounded command execution behind an injectable clock and kernel interface.

use std::{
    io::Read,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use thiserror::Error;

/// Default deadline for each kernel command.
pub const EXEC_TIMEOUT: Duration = Duration::from_secs(3);
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
}

impl Default for Programs {
    fn default() -> Self {
        Self {
            wg: Program::Wg.default_path().into(),
            ip: Program::Ip.default_path().into(),
            nft: Program::Nft.default_path().into(),
            tc: Program::Tc.default_path().into(),
        }
    }
}

impl Programs {
    /// Applies absolute-path overrides to the defaults (last override wins).
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
    /// The child was killed and reaped after the deadline expired.
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
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
    }
}

// Every return path, including reader setup and wait errors, reaps the child.
struct ReapChild(Child);

impl Drop for ReapChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
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
    child: &mut ReapChild,
    started: Instant,
    timeout: Duration,
) -> Result<ExecOutput, ExecError> {
    let stdout = child
        .0
        .stdout
        .take()
        .ok_or_else(|| ExecError::spawn("stdout pipe unavailable"))?;
    let stderr = child
        .0
        .stderr
        .take()
        .ok_or_else(|| ExecError::spawn("stderr pipe unavailable"))?;
    let (sender, receiver) = mpsc::channel();
    let err_sender = sender.clone();
    // Never join a blocking pipe reader: the deadline also covers EOF, including
    // a pipe inherited by a descendant. Each reader retains at most cap + 1.
    thread::Builder::new()
        .name("exec-stdout".into())
        .spawn(move || {
            let _ = sender.send((0, read_pipe(stdout)));
        })
        .map_err(|error| ExecError::spawn(&error.to_string()))?;
    thread::Builder::new()
        .name("exec-stderr".into())
        .spawn(move || {
            let _ = err_sender.send((1, read_pipe(stderr)));
        })
        .map_err(|error| ExecError::spawn(&error.to_string()))?;

    let mut streams = [None, None];
    loop {
        if started.elapsed() >= timeout {
            return Err(ExecError::Timeout { after: timeout });
        }
        while let Ok((index, result)) = receiver.try_recv() {
            streams[index] = Some(result?);
        }
        let status = child
            .0
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
        let child = self
            .command(program, args)
            .spawn()
            .map_err(|error| ExecError::spawn(&error.to_string()))?;
        collect(&mut ReapChild(child), started, timeout)
    }

    fn now_unix_secs(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

/// Scripted test support, public so integration and downstream tests can use it
/// without enabling a feature or changing the production execution path.
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
        let mut child = ReapChild(sys.command(Program::Wg, &args(&["5"])).spawn()?);
        let pid = child.0.id();
        assert_eq!(
            collect(&mut child, started, timeout),
            Err(ExecError::Timeout { after: timeout })
        );
        drop(child);
        assert!(started.elapsed() < Duration::from_secs(2));
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
        for program in [Program::Wg, Program::Ip, Program::Nft, Program::Tc] {
            assert_eq!(
                Programs::default().path(program),
                Path::new(program.default_path())
            );
        }
    }

    // These helpers are test-harness subprocesses: no shell or production-only
    // escape hatch is needed to exercise both pipes and malformed bytes.
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
    #[should_panic(expected = "unexpected or exhausted command: Ip")]
    fn fake_rejects_unknown_calls() {
        let fake = testing::FakeSystem::new(1_000);
        let _ = fake.run(Program::Ip, &args(&["route"]), EXEC_TIMEOUT);
    }
}
