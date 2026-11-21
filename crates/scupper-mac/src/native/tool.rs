//! Serialized tool execution. No workers, wildcard reap, or process-group changes.
use crate::platform::{
    Deadline, SysError, Tool,
    runtime::{Output, Reap, Records, valid_fd_action},
};
use rustix::{io::Errno, pipe::pipe};
use scupper_darwin::{FdAction, Spawned, Wait};
use std::{
    os::fd::{AsFd, OwnedFd},
    path::Path,
    time::Duration,
};

/// Retained tool evidence. Absence is trustworthy only after `complete()`.
#[derive(Debug)]
pub struct ToolResult {
    /// Spawned pid (recorded before polling, writing, or observing identity).
    pub pid: u32,
    /// Exact reap evidence; Pending keeps the fence open.
    pub reap: Reap,
    /// Bounded stdout.
    pub stdout: Output,
    /// Bounded stderr.
    pub stderr: Output,
    /// Execution deadline triggered SIGKILL.
    pub timed_out: bool,
    /// A pipe or poll operation failed.
    pub io_failed: bool,
    /// Time spent between SIGKILL and the final reap poll.
    pub kill_reap_ms: Option<u128>,
    /// The spawned pid was in the fence before the timeout kill.
    pub fence_open_at_kill: bool,
}
impl ToolResult {
    /// Whether every byte was drained, exit was zero and status was reaped.
    ///
    /// # Errors
    /// Timeout, truncation and any missing evidence are incomplete.
    pub fn complete(&self) -> Result<(), SysError> {
        if !self.reap.settled() {
            return Err(SysError::Unknown);
        }
        if self.timed_out {
            return Err(SysError::TimedOut);
        }
        crate::platform::runtime::complete_output(
            self.reap,
            self.stdout.truncated || self.stderr.truncated,
            self.io_failed,
        )
    }
    /// Map bounded evidence to the mutating-tool contract. Truncation and I/O
    /// gaps remain Unknown even after a reap; they never imply rollback.
    #[must_use]
    pub fn into_outcome(self) -> crate::platform::ToolOutcome<Vec<u8>> {
        crate::platform::runtime::tool_outcome(
            self.reap,
            self.timed_out || self.io_failed || self.stdout.truncated || self.stderr.truncated,
            self.stdout.bytes,
        )
    }
}
pub(super) fn reap(record: &mut Spawned) -> Reap {
    match record.try_reap() {
        Ok(Wait::Status(s)) => Reap::Status(s),
        Ok(Wait::NoChild) => Reap::NoChild,
        Ok(Wait::Pending) | Err(_) => Reap::Pending,
    }
}
fn failure(_: Errno) -> SysError {
    SysError::Failed("native: tool syscall")
}
fn high_pipe() -> Result<(OwnedFd, OwnedFd), SysError> {
    let (read, write) = pipe().map_err(failure)?;
    Ok((
        scupper_darwin::high_fd(read).map_err(failure)?,
        scupper_darwin::high_fd(write).map_err(failure)?,
    ))
}
/// Create pipe-backed stdio with every source above fd 9. The general handoff
/// still rejects self-dup2; this normalization also handles initially closed 0/1/2.
pub(super) fn stdio() -> Result<[(OwnedFd, OwnedFd); 3], SysError> {
    Ok([high_pipe()?, high_pipe()?, high_pipe()?])
}
pub(super) fn actions(pipes: &[(OwnedFd, OwnedFd); 3]) -> Result<[FdAction<'_>; 3], SysError> {
    use std::os::fd::AsRawFd;
    let sources = [&pipes[0].0, &pipes[1].1, &pipes[2].1];
    let mut result = Vec::new();
    for (source, target) in sources.into_iter().zip(0..3) {
        if !valid_fd_action(source.as_raw_fd(), target) {
            return Err(SysError::Failed("native: self dup2"));
        }
        result.push(FdAction {
            source: source.as_fd(),
            target,
        });
    }
    result
        .try_into()
        .map_err(|_| SysError::Failed("native: stdio actions"))
}

pub(super) fn run(
    records: &mut Records<Spawned>,
    family: Tool,
    path: &Path,
    argv: &[&str],
    input: &[u8],
    cap: usize,
    deadline: Deadline,
) -> Result<ToolResult, SysError> {
    let end = Duration::from_secs(deadline.0);
    let now = scupper_darwin::monotonic_raw();
    if now >= end {
        return Err(SysError::TimedOut);
    }
    let pipes = stdio()?;
    let fd_actions = actions(&pipes)?;
    if scupper_darwin::monotonic_raw() >= end {
        return Err(SysError::TimedOut);
    }
    let child = scupper_darwin::spawn(path, argv, &fd_actions).map_err(failure)?;
    let pid = child.pid();
    // This push is the first post-spawn action: even later setup errors retain it.
    records.tools.push((family, child));
    let [
        (stdin_read, stdin_write),
        (stdout_read, stdout_write),
        (stderr_read, stderr_write),
    ] = pipes;
    drop((stdin_read, stdout_write, stderr_write));
    let mut streams = [Some(stdin_write), Some(stdout_read), Some(stderr_read)];
    let mut result = ToolResult {
        pid,
        reap: Reap::Pending,
        stdout: Output::default(),
        stderr: Output::default(),
        timed_out: false,
        io_failed: false,
        kill_reap_ms: None,
        fence_open_at_kill: false,
    };
    for (i, fd) in streams.iter().enumerate() {
        if let Some(fd) = fd {
            result.io_failed |= scupper_darwin::nonblocking_pipe(fd.as_fd(), i == 0).is_err();
        }
    }
    let index = records.tools.len() - 1;
    // Reserve a reap window inside the absolute caller budget, never add it on.
    let remaining = end.saturating_sub(scupper_darwin::monotonic_raw());
    let execution_end = end.saturating_sub(Duration::from_secs(2).min(remaining / 2));
    let mut sent = 0;
    loop {
        if sent == input.len() {
            streams[0] = None;
        }
        result.reap = reap(&mut records.tools[index].1);
        if result.reap.settled() && streams.iter().all(Option::is_none) {
            break;
        }
        let now = scupper_darwin::monotonic_raw();
        if now >= execution_end || result.io_failed {
            result.timed_out = now >= execution_end;
            result.fence_open_at_kill =
                matches!(records.fence(Spawned::pid), crate::platform::Fence::Open(_));
            let kill_started = std::time::Instant::now();
            let _ = records.tools[index].1.kill();
            // No reap may overlap kill: both require the exclusive spawn record.
            let reap_end = end.min(scupper_darwin::monotonic_raw() + Duration::from_secs(2));
            while scupper_darwin::monotonic_raw() < reap_end {
                result.reap = reap(&mut records.tools[index].1);
                if result.reap.settled() {
                    break;
                }
                std::thread::sleep(
                    Duration::from_millis(5)
                        .min(reap_end.saturating_sub(scupper_darwin::monotonic_raw())),
                );
            }
            result.kill_reap_ms = Some(kill_started.elapsed().as_millis());
            if streams[1].is_some() || streams[2].is_some() {
                result.io_failed = true;
            }
            break;
        }
        let ready = match scupper_darwin::poll_pipes(
            streams.each_ref().map(|fd| fd.as_ref().map(AsFd::as_fd)),
            Duration::from_millis(10).min(execution_end.saturating_sub(now)),
        ) {
            Ok(ready) => ready,
            Err(Errno::INTR) => continue,
            Err(_) => {
                result.io_failed = true;
                continue;
            }
        };
        pump(&mut streams, ready, input, &mut sent, &mut result, cap);
    }
    if result.reap.settled() {
        records.tools.remove(index);
    }
    Ok(result)
}

fn pump(
    streams: &mut [Option<OwnedFd>; 3],
    ready: [bool; 3],
    input: &[u8],
    sent: &mut usize,
    result: &mut ToolResult,
    cap: usize,
) {
    for i in 0..3 {
        if !ready[i] {
            continue;
        }
        let Some(fd) = streams[i].as_ref() else {
            continue;
        };
        if i == 0 {
            match rustix::io::write(
                fd,
                &input[*sent..input.len().min((*sent).saturating_add(8192))],
            ) {
                Ok(0) => {
                    result.io_failed = true;
                    streams[i] = None;
                }
                Ok(n) => *sent += n,
                Err(Errno::AGAIN | Errno::INTR) => {}
                Err(_) => {
                    result.io_failed = true;
                    streams[i] = None;
                }
            }
        } else {
            let mut bytes = [0_u8; 8192];
            match rustix::io::read(fd, &mut bytes) {
                Ok(0) => streams[i] = None,
                Ok(n) => {
                    if i == 1 {
                        result
                            .stdout
                            .append(&bytes[..n], cap.saturating_sub(result.stderr.bytes.len()));
                    } else {
                        result
                            .stderr
                            .append(&bytes[..n], cap.saturating_sub(result.stdout.bytes.len()));
                    }
                }
                Err(Errno::AGAIN | Errno::INTR) => {}
                Err(_) => {
                    result.io_failed = true;
                    streams[i] = None;
                }
            }
        }
    }
}
