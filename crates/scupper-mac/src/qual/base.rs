//! Base qualification runs only inside the guarded, root-owned harness.
use super::{
    CaseResult, Digest, DirBuilderExt, Duration, EnvironmentIssue, Instant, Manifest,
    OpenOptionsExt, Path, Result, Sha256, TOOL_BUDGET, Value, Verdict, Write, Writer, command,
    environment_issue, executable_sha256, fs, json, protected_path, read_json, require_ack,
    save_case, thread, write_json,
};
use crate::{
    decode::proc,
    native::{NativePlatform, Paths},
    platform::{Deadline, Enumeration, Platform, ProcState},
    snapshot::BootId,
};
use std::process::{Child, Command, Stdio};

struct Supervised(Child);
impl Supervised {
    fn spawn(out: &Path, program: &Path, args: &[&str], output: &str) -> Result<Self> {
        let stdout = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(out.join(output))?;
        let child = Command::new(program)
            .env_clear()
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
            .env("LC_ALL", "C")
            .args(args)
            .stdin(Stdio::null())
            .stdout(stdout)
            .stderr(Stdio::null())
            .spawn()?;
        let guard = Self(child);
        let record = scupper_darwin::sysctl_kern_proc_pid(guard.0.id())?
            .ok_or("base child disappeared before identity read")?;
        // Persist the child identity independently of the controller list:
        // dispatch clears that list after run, but restoration must retain any
        // child whose bounded reap did not complete.
        let mut journal = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(out.join("resources.jsonl"))?;
        writeln!(
            journal,
            "{}",
            json!({"kind": "child", "pid": guard.0.id(), "start": format!("{}:{}", record.start.0, record.start.1)})
        )?;
        journal.sync_all()?;
        let mut writers: Vec<Writer> = read_json(&out.join("writers.json"))?;
        writers.push(Writer {
            pid: guard.0.id(),
            start: format!("{}:{}", record.start.0, record.start.1),
        });
        write_json(out, "writers.json", &writers)?;
        Ok(guard)
    }
}
impl Drop for Supervised {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let until = Instant::now() + Duration::from_secs(2);
        while Instant::now() < until {
            if self.0.try_wait().ok().flatten().is_some() {
                return;
            }
            thread::sleep(Duration::from_millis(10));
        }
        // Keep its identity in writers.json for the independent dead-man.
    }
}

pub(super) fn run(out: &Path) -> Result<()> {
    if !Manifest::bundled()?.budgets_fit() {
        return Err("base manifest exceeds budget".into());
    }
    let mut platform = NativePlatform::new(Paths::qualification(out.to_path_buf()));
    let mut results = Vec::new();
    for (id, operation) in [
        (
            "Q-BOOT",
            boot as fn(&Path, &mut NativePlatform, &mut CaseResult) -> Result<()>,
        ),
        ("Q-PROC", processes),
        ("Q-CAPTURE-BASE", capture_processes),
    ] {
        require_ack(out)?;
        if out.join(format!("{id}.json")).exists() {
            return Err("base case already recorded; use a fresh directory".into());
        }
        let mut result = CaseResult {
            case: id.into(),
            binary_sha256: executable_sha256()?,
            verdict: Verdict::AssumptionHolds,
            iterations: 0,
            detail: "base contract exercised; no assumptions promoted".into(),
            evidence: Vec::new(),
        };
        if let Err(error) = operation(out, &mut platform, &mut result) {
            result.verdict = if error.is::<EnvironmentIssue>() {
                Verdict::Inconclusive
            } else {
                Verdict::ContractViolation
            };
            result.detail = error.to_string();
        }
        save_case(out, &result)?;
        results.push(result);
    }
    let violation = results
        .iter()
        .any(|r| r.verdict == Verdict::ContractViolation);
    write_json(out, "verdicts.json", &results)?;
    if violation {
        Err("base contract violation; see case evidence".into())
    } else {
        Ok(())
    }
}

fn churn(out: &Path, seconds: &str, output: &str) -> Result<Supervised> {
    let bin = std::env::current_exe()?.with_file_name("base-churn");
    protected_path(&bin, false)?;
    Supervised::spawn(out, &bin, &[seconds], output)
}

fn boot(out: &Path, platform: &mut NativePlatform, result: &mut CaseResult) -> Result<()> {
    let start = Instant::now();
    let oracle = command(
        "/usr/sbin/sysctl",
        &["-n", "kern.bootsessionuuid"],
        None,
        TOOL_BUDGET,
    );
    let valid = oracle.complete();
    let expected = BootId::try_from(oracle.stdout.trim());
    result.evidence.push(oracle);
    if !valid {
        return Err(environment_issue("boot UUID command unavailable"));
    }
    let expected = expected?;
    let mut load = churn(out, "180", "boot-churn.log")?;
    let mut latency = Vec::with_capacity(100_000);
    for iteration in 0..100_000 {
        if iteration % 1000 == 0 && load.0.try_wait()?.is_some() {
            return Err(environment_issue(
                "boot churn exited before boot reads completed",
            ));
        }
        if start.elapsed() >= Duration::from_secs(180) {
            return Err("Q-BOOT adapter exceeded three-minute budget".into());
        }
        let before = scupper_darwin::monotonic_raw();
        let got = platform.boot_id();
        latency.push(
            scupper_darwin::monotonic_raw()
                .saturating_sub(before)
                .as_nanos(),
        );
        if got.as_ref() != Some(&expected) {
            return Err("Q-BOOT UUID absent, invalid, changed or unequal to sysctl".into());
        }
        result.iterations += 1;
    }
    if load.0.try_wait()?.is_some() {
        return Err(environment_issue("boot churn exited during boot reads"));
    }
    latency.sort_unstable();
    write_json(
        out,
        "base-boot.json",
        &json!({"boot": expected, "reads": result.iterations,
        "latency_ns": {"p50": latency[50_000], "p90": latency[90_000], "p99": latency[99_000], "max": latency[99_999]},
        "elapsed_ms": start.elapsed().as_millis()}),
    )?;
    Ok(())
}

#[allow(clippy::too_many_lines)] // One bounded churn campaign, with its oracle lifetimes in scope.
fn processes(out: &Path, platform: &mut NativePlatform, result: &mut CaseResult) -> Result<()> {
    let case_start = Instant::now();
    let mut children = Vec::new();
    for i in 0..8 {
        children.push(Supervised::spawn(
            out,
            Path::new("/bin/sleep"),
            &["360"],
            &format!("oracle-{i}.log"),
        )?);
    }
    let oracle = children
        .iter()
        .map(|c| {
            scupper_darwin::sysctl_kern_proc_pid(c.0.id())?.ok_or(scupper_darwin::ProcError::Layout)
        })
        .collect::<std::result::Result<Vec<_>, _>>()?;
    write_json(
        out,
        "base-oracle.json",
        &oracle
            .iter()
            .map(|p| json!({"pid": p.pid, "start": p.start}))
            .collect::<Vec<_>>(),
    )?;
    let own = platform.incarnation();
    if own.pid != std::process::id() || own.boot != platform.boot_id() {
        return Err("native incarnation mismatch".into());
    }
    let mut churn = churn(out, "60", "proc-churn.json")?;
    let start = scupper_darwin::monotonic_raw();
    let mut complete = 0;
    let mut incomplete = Vec::new();
    let mut census = Vec::new();
    for iteration in 0..500_u32 {
        if case_start.elapsed() >= Duration::from_secs(360) {
            return Err("Q-PROC adapter exceeded six-minute budget".into());
        }
        let d = Deadline(platform.now() + 5);
        match platform.processes(d) {
            Enumeration::Complete(list) => {
                complete += 1;
                for p in &oracle {
                    if !list.iter().any(|got| {
                        i32::try_from(got.pid).ok() == Some(p.pid)
                            && proc::start(p.start.0, p.start.1).ok() == Some(got.start)
                    }) {
                        return Err(format!("Complete inventory missing oracle {}", p.pid).into());
                    }
                }
                if list
                    .iter()
                    .any(|p| p.exe.is_some() || (p.state != ProcState::Zombie && p.path.is_none()))
                {
                    return Err("Complete violates OD4/pathless rule".into());
                }
            }
            Enumeration::Incomplete(error) => {
                if error.error == crate::platform::SysError::Failed("native: process layout") {
                    return Err("integral length or process layout violated".into());
                }
                incomplete.push(json!({"iteration": iteration, "pid": error.pid, "error": error.error.to_string()}));
            }
        }
        // Independent census records every live pathless entry, even when a
        // foreign pathless process prevents the adapter from completing a read.
        if iteration.is_multiple_of(50) {
            for p in scupper_darwin::sysctl_kern_proc_all()? {
                if p.pid <= 0 || proc::state(p.stat)? == ProcState::Zombie {
                    continue;
                }
                let pid = u32::try_from(p.pid)?;
                if let Err(error) = scupper_darwin::proc_pidpath(pid) {
                    let current = scupper_darwin::sysctl_kern_proc_pid(pid)?;
                    if current
                        .as_ref()
                        .is_some_and(|q| q.start == p.start && q.stat != 5)
                    {
                        census.push(json!({"iteration": iteration, "pid": pid, "errno": error.raw_os_error()}));
                    }
                }
            }
        }
        result.iterations += 1;
        // Spread the 500 observations over the full 60-second churn window.
        let target = start + Duration::from_millis(u64::from(iteration + 1) * 120);
        let remaining = target.saturating_sub(scupper_darwin::monotonic_raw());
        let d = Deadline(platform.now() + 2);
        platform.pause(remaining, d);
    }
    let reap_until = Instant::now() + Duration::from_secs(2);
    let status = loop {
        if let Some(status) = churn.0.try_wait()? {
            break status;
        }
        if Instant::now() >= reap_until {
            return Err(environment_issue(
                "fork churn did not finish within its bound",
            ));
        }
        thread::sleep(Duration::from_millis(10));
    };
    if !status.success() {
        return Err(environment_issue("fork churn failed"));
    }
    let measurement: Value = serde_json::from_slice(&fs::read(out.join("proc-churn.json"))?)?;
    let forks = measurement["forks"].as_u64().ok_or("missing churn count")?;
    let elapsed = measurement["elapsed_seconds"]
        .as_f64()
        .ok_or("missing churn duration")?;
    write_json(
        out,
        "base-processes.json",
        &json!({"complete": complete, "incomplete": incomplete, "pathless_census": census, "churn": measurement}),
    )?;
    if forks < 10_000 || elapsed < 60.0 {
        return Err(environment_issue(
            "runner did not sustain approximately 200 forks/s for 60 seconds",
        ));
    }
    stopped(out, &children[0], platform)?;
    path_changes(out, platform)?;
    if complete == 0 {
        result.verdict = Verdict::Inconclusive;
        result.detail = "500 observations, no Complete inventory; oracle completeness remains unqualified; see pathless census and per-read errors".into();
    }
    if case_start.elapsed() >= Duration::from_secs(360) {
        return Err("Q-PROC exceeded its six-minute case deadline".into());
    }
    Ok(())
}

fn stopped(out: &Path, child: &Supervised, platform: &mut NativePlatform) -> Result<()> {
    let pid =
        rustix::process::Pid::from_raw(i32::try_from(child.0.id())?).ok_or("invalid oracle pid")?;
    rustix::process::kill_process(pid, rustix::process::Signal::STOP)?;
    let until = scupper_darwin::monotonic_raw() + Duration::from_secs(2);
    let check = (|| -> Result<()> {
        loop {
            let p = scupper_darwin::sysctl_kern_proc_pid(child.0.id())?
                .ok_or("stopped oracle vanished")?;
            if proc::state(p.stat)? == ProcState::Stopped {
                break;
            }
            if scupper_darwin::monotonic_raw() >= until {
                return Err("SSTOP not observed".into());
            }
            let d = Deadline(platform.now() + 1);
            platform.pause(Duration::from_millis(10), d);
        }
        let d = Deadline(platform.now() + 2);
        let inventory = platform.processes(d);
        if let Enumeration::Complete(list) = &inventory
            && !list
                .iter()
                .any(|p| p.pid == child.0.id() && p.state == ProcState::Stopped)
        {
            return Err("native inventory omitted or misclassified stopped oracle".into());
        }
        write_json(
            out,
            "base-stopped-inventory.json",
            &json!({"inventory": format!("{inventory:?}")}),
        )?;
        Ok(())
    })();
    let resumed = rustix::process::kill_process(pid, rustix::process::Signal::CONT);
    check?;
    resumed?;
    write_json(
        out,
        "base-stopped.json",
        &json!({"pid": child.0.id(), "state": "Stopped", "resumed": true}),
    )
}

fn path_changes(out: &Path, platform: &mut NativePlatform) -> Result<()> {
    let source = out.join("base-sleep");
    let renamed = out.join("base-renamed-sleep");
    fs::copy("/bin/sleep", &source)?;
    let d = Deadline(platform.now() + 2);
    let identity = platform.executable_id(&source, d)?;
    let child = Supervised::spawn(out, &source, &["120"], "path-oracle.log")?;
    let before = scupper_darwin::proc_pidpath(child.0.id())?;
    fs::rename(&source, &renamed)?;
    let after_rename = scupper_darwin::proc_pidpath(child.0.id());
    let d = Deadline(platform.now() + 2);
    if platform.executable_id(&renamed, d)? != identity {
        return Err("executable identity changed on rename".into());
    }
    fs::remove_file(&renamed)?;
    let after_unlink = scupper_darwin::proc_pidpath(child.0.id());
    let d = Deadline(platform.now() + 2);
    let inventory = platform.processes(d);
    if let Enumeration::Complete(list) = &inventory
        && after_unlink.is_err()
        && (list.iter().any(|p| p.pid == child.0.id())
            || scupper_darwin::sysctl_kern_proc_pid(child.0.id())?.is_some_and(|p| p.stat != 5))
    {
        return Err("Complete included live pathless oracle".into());
    }
    write_json(
        out,
        "base-paths.json",
        &json!({"pid": child.0.id(), "before": before,
        "after_rename": after_rename.as_ref().map(|p| p.to_string_lossy()).map_err(|e| e.raw_os_error()),
        "after_unlink": after_unlink.as_ref().map(|p| p.to_string_lossy()).map_err(|e| e.raw_os_error()),
        "enumeration": format!("{inventory:?}")}),
    )
}

fn capture_processes(
    out: &Path,
    _platform: &mut NativePlatform,
    result: &mut CaseResult,
) -> Result<()> {
    let start = Instant::now();
    let records = scupper_darwin::sysctl_kern_proc_all()?;
    let mut bytes = Vec::new();
    for p in &records {
        let mut b = [0_u8; proc::RECORD_BYTES];
        b[..8].copy_from_slice(&p.start.0.to_le_bytes());
        b[8..12].copy_from_slice(&p.start.1.to_le_bytes());
        b[36] = p.stat;
        b[40..44].copy_from_slice(&p.pid.to_le_bytes());
        b[243..260].copy_from_slice(&p.comm);
        if let Some(end) = p.comm.iter().position(|byte| *byte == 0) {
            b[243 + end..260].fill(0);
        }
        b[560..564].copy_from_slice(&p.ppid.to_le_bytes());
        b[564..568].copy_from_slice(&p.pgid.to_le_bytes());
        bytes.extend_from_slice(&b);
    }
    // Preserve the exact consumed kernel bytes; redact all opaque SDK fields,
    // including addresses/credentials, instead of exposing struct padding.
    let decoded = proc::records(&bytes)?;
    let source = records.iter().filter(|p| p.pid != 0).collect::<Vec<_>>();
    if decoded.len() != source.len() {
        return Err("fixture decoder lost kernel records".into());
    }
    for (got, raw) in decoded.iter().zip(source) {
        if got.pid != u32::try_from(raw.pid)?
            || got.ppid != u32::try_from(raw.ppid)?
            || got.pgid != u32::try_from(raw.pgid)?
            || got.start != proc::start(raw.start.0, raw.start.1)?
            || got.state != proc::state(raw.stat)?
            || got.name != proc::name(&raw.comm)
            || got.path.is_some()
            || got.exe.is_some()
        {
            return Err("fixture decoder disagrees with typed kernel fields".into());
        }
    }
    let build = scupper_darwin::sysctl_string("kern.osversion")?;
    if !build.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return Err("invalid build fixture component".into());
    }
    let fixture = out.join("fixtures").join("macos").join(&build);
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&fixture)?;
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(fixture.join("kinfo_proc.bin"))?;
    file.write_all(&bytes)?;
    write_json(
        &fixture,
        "kinfo_proc.json",
        &json!({"build": build, "stride": proc::RECORD_BYTES,
        "bytes": bytes.len(), "records": records.len(), "decoded": decoded.len(), "sha256": format!("{:x}", Sha256::digest(&bytes)),
        "redaction": "all bytes except start, stat, pid, NUL-terminated comm, ppid, pgid zeroed"}),
    )?;
    if start.elapsed() >= Duration::from_secs(60) {
        return Err("base capture exceeded one-minute budget".into());
    }
    result.iterations = 1;
    result.detail = "redacted raw sysctl fields saved as portable Linux fixtures; opaque addresses and credentials zeroed".into();
    Ok(())
}
