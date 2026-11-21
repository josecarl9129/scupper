use std::{
    io::{Read, Write},
    process::{Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use super::{Evidence, redact};

// The SC kill-window census retains every 5 ms poll, including a 10 s tail.
const OUTPUT_LIMIT: usize = 1024 * 1024;

pub(super) fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// Drain even beyond the cap, so a verbose child cannot deadlock on a full pipe.
// Readers own their pipes; on deadline they may finish after the caller returns.
fn reader(mut pipe: impl Read + Send + 'static) -> mpsc::Receiver<(String, bool)> {
    let (send, receive) = mpsc::channel();
    thread::spawn(move || {
        let mut bytes = Vec::new();
        let mut truncated = false;
        let mut buffer = [0_u8; 8192];
        loop {
            match pipe.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => {
                    let keep = n.min(OUTPUT_LIMIT.saturating_sub(bytes.len()));
                    bytes.extend_from_slice(&buffer[..keep]);
                    truncated |= keep < n;
                }
                Err(_) => {
                    truncated = true;
                    break;
                }
            }
        }
        // If truncation bisected a key assignment, the entire last line is
        // discarded before redaction. No retained partial key line is exposed.
        if truncated {
            if let Some(last_newline) = bytes.iter().rposition(|byte| *byte == b'\n') {
                bytes.truncate(last_newline + 1);
            } else {
                bytes.clear();
            }
        }
        let _ = send.send((redact(&String::from_utf8_lossy(&bytes)), truncated));
    });
    receive
}

fn spawn_command(
    program: &str,
    args: &[&str],
    has_input: bool,
) -> std::io::Result<std::process::Child> {
    Command::new(program)
        .args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("LC_ALL", "C")
        // Needed only by the self-invocation testing the guard. No secrets or
        // caller-controlled environment is inherited by external tools.
        .env(
            "GITHUB_ACTIONS",
            std::env::var("GITHUB_ACTIONS").unwrap_or_default(),
        )
        .env(
            "RUNNER_ENVIRONMENT",
            std::env::var("RUNNER_ENVIRONMENT").unwrap_or_default(),
        )
        .stdin(if has_input {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
}

pub(super) fn command(
    program: &str,
    args: &[&str],
    input: Option<&str>,
    budget: Duration,
) -> Evidence {
    let started = Instant::now();
    let mut evidence = Evidence {
        command: std::iter::once(program)
            .chain(args.iter().copied())
            .map(redact)
            .collect(),
        stdin: input.map(redact),
        pid: None,
        exit_code: None,
        started_unix_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis(),
        elapsed_ms: 0,
        timed_out: false,
        truncated: false,
        stdout: String::new(),
        stderr: String::new(),
    };
    if budget.is_zero() {
        evidence.timed_out = true;
        evidence.stderr = "case deadline exhausted before spawning command".into();
        return evidence;
    }
    let child = spawn_command(program, args, input.is_some());
    let mut child = match child {
        Ok(child) => child,
        Err(error) => {
            evidence.stderr = redact(&error.to_string());
            evidence.elapsed_ms = started.elapsed().as_millis();
            return evidence;
        }
    };
    evidence.pid = Some(child.id());
    let stdout = child.stdout.take().map(reader);
    let stderr = child.stderr.take().map(reader);
    if let Some(input) = input {
        // Inputs are fixed, tiny read-only scutil queries. Even a stalled stdin
        // must not block the controller: a separate thread owns it.
        let input = input.to_owned();
        if let Some(mut stdin) = child.stdin.take() {
            thread::spawn(move || {
                let _ = stdin.write_all(input.as_bytes());
            });
        }
    }
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                evidence.exit_code = status.code();
                break;
            }
            Ok(None) if started.elapsed() < budget => thread::sleep(Duration::from_millis(20)),
            result => {
                evidence.timed_out = started.elapsed() >= budget;
                if let Err(error) = result {
                    evidence.stderr = redact(&error.to_string());
                }
                let _ = child.kill();
                // Never wait indefinitely, including on a kernel-stalled tool.
                let reap = Instant::now();
                while reap.elapsed() < Duration::from_secs(2) {
                    if let Ok(Some(status)) = child.try_wait() {
                        evidence.exit_code = status.code();
                        break;
                    }
                    thread::sleep(Duration::from_millis(20));
                }
                break;
            }
        }
    }
    for (receive, output) in [
        (stdout, &mut evidence.stdout),
        (stderr, &mut evidence.stderr),
    ] {
        if let Some(receive) = receive {
            match receive.recv_timeout(Duration::from_secs(1)) {
                Ok((text, truncated)) => {
                    output.push_str(&text);
                    evidence.truncated |= truncated;
                }
                Err(_) => evidence.truncated = true,
            }
        } else {
            evidence.truncated = true;
        }
    }
    evidence.elapsed_ms = started.elapsed().as_millis();
    evidence
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_evidence_redacts_both_pipes_and_arguments() {
        let evidence = command(
            "/bin/sh",
            &[
                "-c",
                "printf 'ok\\nprivate_key=fixture-private\\n'; printf 'preshared_key=fixture-shared\\n' >&2",
            ],
            None,
            Duration::from_secs(2),
        );
        assert_eq!(evidence.exit_code, Some(0));
        assert!(!evidence.timed_out);
        assert!(!evidence.truncated);
        assert!(evidence.stdout.contains("ok"));
        let json = serde_json::to_string(&evidence).expect("serialize evidence");
        assert!(!json.contains("fixture-"));
        assert!(!json.contains("private_key="));
        assert!(!json.contains("preshared_key="));
        assert!(unix_seconds() > 0);
    }

    #[test]
    fn cap_is_bounded_while_child_is_fully_drained() {
        let count = (OUTPUT_LIMIT + 1024).to_string();
        let evidence = command(
            "/usr/bin/head",
            &["-c", &count, "/dev/zero"],
            None,
            Duration::from_secs(2),
        );
        assert_eq!(evidence.exit_code, Some(0));
        assert!(evidence.truncated);
        assert!(evidence.stdout.len() <= OUTPUT_LIMIT);
        assert!(!evidence.timed_out);
    }

    #[test]
    fn expired_budget_never_spawns_and_stalled_command_is_bounded() {
        let expired = command("/bin/sh", &["-c", "exit 0"], None, Duration::ZERO);
        assert!(expired.timed_out);
        assert!(expired.pid.is_none());
        let started = Instant::now();
        let stalled = command(
            "/bin/sh",
            &["-c", "exec sleep 5"],
            None,
            Duration::from_millis(50),
        );
        assert!(stalled.timed_out);
        assert!(started.elapsed() < Duration::from_secs(4));
    }
}
