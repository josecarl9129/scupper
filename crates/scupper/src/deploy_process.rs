//! Deadline includes stdin, output EOF, and descendants holding pipes open.
use std::{
    io::{Read, Write},
    os::unix::process::CommandExt,
    process::{Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

const OUTPUT_CAP: u64 = 1024 * 1024;

pub(crate) fn execute(
    mut command: Command,
    input: &[u8],
    timeout: Duration,
) -> Result<(u8, String), String> {
    let started = Instant::now();
    let mut child = command
        .process_group(0)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;
    let result = (|| {
        let mut stdin = child.stdin.take();
        if let Some(pipe) = &stdin {
            let flags = rustix::fs::fcntl_getfl(pipe).map_err(|e| e.to_string())?;
            rustix::fs::fcntl_setfl(pipe, flags | rustix::fs::OFlags::NONBLOCK)
                .map_err(|e| e.to_string())?;
        }
        let (sender, receiver) = mpsc::channel();
        let stdout = child.stdout.take().ok_or("missing child stdout")?;
        let stderr = child.stderr.take().ok_or("missing child stderr")?;
        for (index, pipe) in [
            (0, Box::new(stdout) as Box<dyn Read + Send>),
            (1, Box::new(stderr) as Box<dyn Read + Send>),
        ] {
            let sender = sender.clone();
            thread::Builder::new()
                .name("deploy-output".into())
                .spawn(move || {
                    let mut bytes = Vec::new();
                    let result = pipe
                        .take(OUTPUT_CAP + 1)
                        .read_to_end(&mut bytes)
                        .map_err(|e| e.to_string())
                        .and_then(|_| {
                            if bytes.len() as u64 > OUTPUT_CAP {
                                Err("child output exceeds limit".into())
                            } else {
                                Ok(String::from_utf8_lossy(&bytes).into_owned())
                            }
                        });
                    let _ = sender.send((index, result));
                })
                .map_err(|e| e.to_string())?;
        }
        let mut remaining = input;
        let mut streams = [None, None];
        loop {
            if started.elapsed() >= timeout {
                return Err(format!("timed out after {}s", timeout.as_secs_f64()));
            }
            if let Some(pipe) = &mut stdin {
                if remaining.is_empty() {
                    stdin.take();
                } else {
                    match pipe.write(&remaining[..remaining.len().min(65536)]) {
                        Ok(0) => return Err("child stdin made no progress".into()),
                        Ok(n) => remaining = &remaining[n..],
                        Err(e)
                            if matches!(
                                e.kind(),
                                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                            ) => {}
                        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {
                            stdin.take();
                        }
                        Err(e) => return Err(e.to_string()),
                    }
                }
            }
            while let Ok((index, result)) = receiver.try_recv() {
                streams[index] = Some(result?);
            }
            if let Some(status) = child.try_wait().map_err(|e| e.to_string())?
                && let [Some(stdout), Some(stderr)] = &mut streams
                && stdin.is_none()
            {
                let code = status
                    .code()
                    .and_then(|c| u8::try_from(c).ok())
                    .unwrap_or(1);
                if code != 0 {
                    return Err(format!("child exited {code}\n{stdout}{stderr}"));
                }
                return Ok((code, std::mem::take(stdout)));
            }
            thread::sleep(Duration::from_millis(5).min(timeout.saturating_sub(started.elapsed())));
        }
    })();
    if result.is_err() {
        if let Some(pgid) = rustix::process::Pid::from_raw(child.id().cast_signed()) {
            let _ = rustix::process::kill_process_group(pgid, rustix::process::Signal::KILL);
        }
        // Reap without extending a deadline for a child stuck in kernel I/O.
        let _ = thread::Builder::new()
            .name("deploy-reaper".into())
            .spawn(move || {
                let _ = child.wait();
            });
    }
    result
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    #[test]
    fn stalled_input_and_descendant_output_obey_deadline() {
        for (script, input) in [
            ("sleep 10", vec![0; 1024 * 1024]),
            ("sleep 10 & exit 0", Vec::new()),
        ] {
            let mut command = Command::new("sh");
            command.args(["-c", script]);
            let start = Instant::now();
            let error = execute(command, &input, Duration::from_millis(50)).unwrap_err();
            assert!(error.contains("timed out"), "{error}");
            assert!(start.elapsed() < Duration::from_secs(2));
        }
    }
}
