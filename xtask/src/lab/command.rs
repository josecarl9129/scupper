//! Bounded argv-only processes, including namespace entry and background ownership.
use std::{
    fs::File,
    io::{Read, Write},
    os::unix::process::{CommandExt, ExitStatusExt},
    path::Path,
    process::{Child, Command, ExitStatus, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

use super::{Result, fail};
use rustix::process::{Pid, Signal, kill_process_group};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Invocation {
    pub program: String,
    pub args: Vec<String>,
}
impl Invocation {
    pub fn new(namespace: &str, program: &str, args: &[&str]) -> Self {
        let mut words = Vec::new();
        let executable = match namespace {
            "" => program,
            "gwhost" => {
                words.extend([
                    "--net=/run/netns/gwhost".into(),
                    "--".into(),
                    program.into(),
                ]);
                "nsenter"
            }
            ns => {
                words.extend(["netns".into(), "exec".into(), ns.into(), program.into()]);
                "ip"
            }
        };
        words.extend(args.iter().map(|word| (*word).into()));
        Self {
            program: executable.into(),
            args: words,
        }
    }
    // GNU timeout also bounds descendants if the supervising process disappears.
    pub fn timed(&self, seconds: u64) -> Vec<String> {
        let mut args = vec![
            "--signal=TERM".into(),
            "--kill-after=2".into(),
            seconds.to_string(),
            self.program.clone(),
        ];
        args.extend(self.args.clone());
        args
    }
}

pub(super) struct Runner {
    pub cancel: Arc<AtomicBool>,
    pub whole: Instant,
    pub phase: Instant,
    pub cleanup: bool,
    pub probe_ca: Option<String>,
    pub boot_point: Option<String>,
    pub boot_marker: Option<String>,
    pub wg_fixture: Option<std::path::PathBuf>,
    trace: File,
    last_stderr: String,
    background_groups: Vec<u32>,
}
impl Runner {
    pub fn new(trace: File, cancel: Arc<AtomicBool>) -> Self {
        let now = Instant::now();
        Self {
            cancel,
            whole: now + Duration::from_secs(1900),
            phase: now + Duration::from_secs(180),
            cleanup: false,
            probe_ca: None,
            boot_point: None,
            boot_marker: None,
            wg_fixture: None,
            trace,
            last_stderr: String::new(),
            background_groups: Vec::new(),
        }
    }
    pub fn check(&self) -> Result<()> {
        if !self.cleanup && self.cancel.load(Ordering::Relaxed) {
            return fail("run interrupted");
        }
        if Instant::now() >= self.whole || Instant::now() >= self.phase {
            return fail("lab deadline exceeded");
        }
        Ok(())
    }
    pub fn dwell(&self, duration: Duration) -> Result<()> {
        let until = Instant::now() + duration;
        while Instant::now() < until {
            self.check()?;
            thread::sleep(Duration::from_millis(25));
        }
        Ok(())
    }
    fn command(&mut self, invocation: &Invocation, seconds: u64) -> Result<Command> {
        self.check()?;
        let wrapped;
        let invocation = if let Some(fixture) = &self.wg_fixture
            && invocation.program == "nsenter"
            && invocation
                .args
                .get(if invocation.args.get(2).is_some_and(|arg| arg == "env") {
                    4
                } else {
                    2
                })
                .is_some_and(|arg| {
                    matches!(
                        Path::new(arg).file_name().and_then(|name| name.to_str()),
                        Some("scupper" | "scupperd")
                    )
                }) {
            wrapped = super::transport::overlay(invocation, fixture);
            &wrapped
        } else {
            invocation
        };
        writeln!(
            self.trace,
            "{}",
            serde_json::json!({"argv": invocation.timed(seconds)})
        )?;
        self.trace.flush()?;
        let mut cmd = Command::new("timeout");
        cmd.args(invocation.timed(seconds)).process_group(0);
        cmd.env("LC_ALL", "C");
        cmd.env_remove("SCUPPER_TEST_BOOT_MARKER");
        if let Some(marker) = &self.boot_marker {
            cmd.env("SCUPPER_TEST_BOOT_MARKER", marker);
        }
        cmd.env_remove("SCUPPER_TEST_BOOT_POINT");
        if let Some(point) = &self.boot_point {
            cmd.env("SCUPPER_TEST_BOOT_POINT", point);
        }
        cmd.env_remove("SCUPPER_TEST_CA_DER");
        if let Some(ca) = &self.probe_ca {
            cmd.env("SCUPPER_TEST_CA_DER", ca);
        }
        Ok(cmd)
    }
    pub fn output(
        &mut self,
        invocation: &Invocation,
        input: Option<&[u8]>,
    ) -> Result<(ExitStatus, String)> {
        self.output_timeout(invocation, input, 15)
    }
    pub fn output_timeout(
        &mut self,
        invocation: &Invocation,
        input: Option<&[u8]>,
        seconds: u64,
    ) -> Result<(ExitStatus, String)> {
        let mut cmd = self.command(invocation, seconds)?;
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
        cmd.stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        });
        let mut group = Group {
            child: cmd.spawn()?,
            done: false,
        };
        // Drain concurrently: an ip/nft JSON response can exceed pipe capacity.
        let stdout = group.child.stdout.take().ok_or("missing stdout")?;
        let stderr = group.child.stderr.take().ok_or("missing stderr")?;
        let (out_tx, out_rx) = mpsc::channel();
        let (err_tx, err_rx) = mpsc::channel();
        thread::spawn(move || {
            let _ = out_tx.send(read(stdout));
        });
        thread::spawn(move || {
            let _ = err_tx.send(read(stderr));
        });
        if let Some(bytes) = input {
            group
                .child
                .stdin
                .take()
                .ok_or("missing stdin")?
                .write_all(bytes)?;
        }
        // A descendant may retain a pipe after the leader exits. Keep the
        // process-group guard armed and bound pipe draining as well as wait.
        let deadline = Instant::now() + Duration::from_secs(seconds + 2);
        let mut status = None;
        let mut stdout = None;
        let mut stderr = None;
        while status.is_none() || stdout.is_none() || stderr.is_none() {
            self.check()?;
            if Instant::now() >= deadline {
                return fail("command or inherited-pipe deadline exceeded");
            }
            if status.is_none() {
                status = group.child.try_wait()?;
            }
            if stdout.is_none() {
                stdout = receive(&out_rx)?;
            }
            if stderr.is_none() {
                stderr = receive(&err_rx)?;
            }
            thread::sleep(Duration::from_millis(20));
        }
        let status = status.ok_or("missing command status")?;
        let stdout = stdout.ok_or("missing command stdout")?;
        let stderr = stderr.ok_or("missing command stderr")?;
        group.done = true;
        self.last_stderr = String::from_utf8_lossy(&stderr).into_owned();
        if !status.success() {
            writeln!(
                self.trace,
                "{}",
                serde_json::json!({"exit": status.to_string(), "stderr": String::from_utf8_lossy(&stderr)})
            )?;
        }
        Ok((status, String::from_utf8(stdout)?))
    }
    pub fn run(&mut self, invocation: &Invocation) -> Result<String> {
        self.input(invocation, None)
    }
    pub fn input(&mut self, invocation: &Invocation, input: Option<&[u8]>) -> Result<String> {
        let (status, stdout) = self.output(invocation, input)?;
        if !status.success() {
            return fail(format!(
                "command failed ({status}): {invocation:?}; {}; see commands.jsonl",
                self.last_stderr
            ));
        }
        Ok(stdout)
    }
    pub fn background(&mut self, invocation: &Invocation, log: &Path) -> Result<Group> {
        // Services must live through the whole suite, including fault recovery.
        let seconds = self
            .whole
            .saturating_duration_since(Instant::now())
            .as_secs()
            + 2;
        let mut cmd = self.command(invocation, seconds)?;
        cmd.stdin(Stdio::null())
            .stdout(File::create(log)?)
            .stderr(File::create(log.with_extension("stderr"))?);
        let child = cmd.spawn()?;
        self.background_groups.push(child.id());
        Ok(Group { child, done: false })
    }
    pub fn background_checkpoint(&self) -> usize {
        self.background_groups.len()
    }
    pub fn assert_background_released(&self, checkpoint: usize) -> Result<()> {
        for entry in std::fs::read_dir("/proc")? {
            let path = entry?.path().join("stat");
            let Ok(stat) = std::fs::read_to_string(path) else {
                continue;
            };
            let Some((_, fields)) = stat.rsplit_once(") ") else {
                continue;
            };
            let fields = fields.split_whitespace().collect::<Vec<_>>();
            if fields.first() == Some(&"Z") {
                continue;
            }
            if let Some(group) = fields.get(2).and_then(|value| value.parse::<u32>().ok())
                && self.background_groups[checkpoint..].contains(&group)
            {
                return fail(format!("daemon suite left process group {group} running"));
            }
        }
        Ok(())
    }
}
fn receive(channel: &mpsc::Receiver<std::io::Result<Vec<u8>>>) -> Result<Option<Vec<u8>>> {
    match channel.try_recv() {
        Ok(data) => Ok(Some(data?)),
        Err(mpsc::TryRecvError::Empty) => Ok(None),
        Err(mpsc::TryRecvError::Disconnected) => fail("command pipe reader failed"),
    }
}
fn read(mut stream: impl Read) -> std::io::Result<Vec<u8>> {
    let mut data = Vec::new();
    stream.read_to_end(&mut data)?;
    Ok(data)
}

pub(super) struct Group {
    child: Child,
    done: bool,
}
impl Group {
    pub(super) fn supervised_pid(&self) -> Result<Option<u32>> {
        if self.done {
            return Ok(None);
        }
        let pid = self.child.id();
        let children = std::fs::read_to_string(format!("/proc/{pid}/task/{pid}/children"))?;
        let mut children = children.split_whitespace();
        let child = children.next().ok_or("supervisor has no child")?.parse()?;
        if children.next().is_some() {
            return fail("supervisor has multiple direct children");
        }
        Ok(Some(child))
    }

    pub(super) fn signal(&self, signal: Signal) {
        if let Some(pid) = Pid::from_raw(self.child.id().cast_signed()) {
            let _ = kill_process_group(pid, signal);
        }
    }
    pub fn assert_not_stopped(&self) -> Result<()> {
        // timeout supervises the daemon; inspect its descendants as well.
        let pid = self.child.id();
        let children = std::fs::read_to_string(format!("/proc/{pid}/task/{pid}/children"))?;
        if children.split_whitespace().next().is_none() {
            return fail("daemon supervisor has no child");
        }
        for child in children.split_whitespace() {
            let stat = std::fs::read_to_string(format!("/proc/{child}/stat"))?;
            if stat
                .rsplit_once(") ")
                .is_none_or(|(_, tail)| tail.starts_with(['T', 't', 'Z']))
            {
                return fail("daemon is stopped or exited during tick-only stall");
            }
        }
        Ok(())
    }
    pub fn alive(&mut self) -> Result<()> {
        if let Some(status) = self.child.try_wait()? {
            self.signal(Signal::KILL);
            self.done = true;
            return fail(format!("background process exited: {status}"));
        }
        Ok(())
    }
    pub(super) fn try_wait(&mut self) -> Result<Option<std::process::ExitStatus>> {
        let status = self.child.try_wait()?;
        if status.is_some() {
            self.signal(Signal::KILL);
            self.done = true;
        }
        Ok(status)
    }
    /// Wait for completion without sending a signal; retain the cleanup guard.
    pub(super) fn wait_timeout(&mut self, timeout: Duration) -> Result<std::process::ExitStatus> {
        let until = Instant::now() + timeout;
        loop {
            if let Some(status) = self.child.try_wait()? {
                self.signal(Signal::KILL);
                self.done = true;
                return Ok(status);
            }
            if Instant::now() >= until {
                return fail("background completion deadline exceeded");
            }
            thread::sleep(Duration::from_millis(20));
        }
    }
    pub fn stop(&mut self, signal: Signal) -> Result<()> {
        self.stop_timeout(signal, Duration::from_secs(3))
    }
    pub(super) fn stop_timeout(&mut self, signal: Signal, timeout: Duration) -> Result<()> {
        if self.done {
            return Ok(());
        }
        self.alive()?;
        self.signal(signal);
        let until = Instant::now() + timeout;
        while Instant::now() < until {
            if let Some(status) = self.child.try_wait()? {
                self.signal(Signal::KILL);
                self.done = true;
                // GNU timeout may return 124 after forwarding our explicit
                // stop signal; only this requested-stop path accepts it.
                if status.success()
                    || status.code() == Some(124)
                    || status.signal() == Some(signal.as_raw())
                    || status.code() == Some(128 + signal.as_raw())
                {
                    return Ok(());
                }
                return fail(format!("background shutdown failed: {status}"));
            }
            thread::sleep(Duration::from_millis(25));
        }
        self.signal(Signal::KILL);
        self.child.wait()?;
        self.done = true;
        fail("background process needed SIGKILL")
    }
}
impl Drop for Group {
    fn drop(&mut self) {
        if !self.done {
            self.signal(Signal::KILL);
            let _ = self.child.wait();
        }
    }
}
