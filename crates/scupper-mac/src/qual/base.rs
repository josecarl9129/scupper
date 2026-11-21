//! Base qualification runs only inside the guarded, root-owned harness.
use super::{
    CaseResult, Digest, DirBuilderExt, Duration, EnvironmentIssue, Instant, Manifest,
    OpenOptionsExt, Path, Result, Sha256, TOOL_BUDGET, Value, Verdict, Write, Writer, command,
    compare_process_layout, environment_issue, executable_sha256, fs, json, probe_path,
    protected_path, read_json, require_ack, save_case, thread, write_json,
};
use crate::qual::base_check::{self, Oracle};
use crate::{
    decode::{image, proc},
    native::{NativePlatform, Paths},
    platform::{Deadline, Enumeration, Platform, ProcState},
    snapshot::{BootId, ImageHistory},
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
        let record = scupper_darwin::sysctl_kern_proc_pid(guard.0.id())
            .map_err(harness_process_error)?
            .ok_or_else(|| environment_issue("base child disappeared before identity read"))?;
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

// Churn and OS failures in the harness prove nothing about the adapter.
// Malformed successful kernel replies remain contract violations.
fn harness_process_error(error: scupper_darwin::ProcError) -> Box<dyn std::error::Error> {
    match error {
        scupper_darwin::ProcError::Incomplete | scupper_darwin::ProcError::Os(_) => {
            environment_issue(error)
        }
        scupper_darwin::ProcError::Layout => Box::new(error),
    }
}

fn check_layout(out: &Path) -> Result<()> {
    require_ack(out)?;
    let probe = probe_path()?;
    protected_path(&probe, false)?;
    let evidence = command(
        probe.to_str().ok_or("non-UTF8 probe path")?,
        &[],
        None,
        TOOL_BUDGET,
    );
    write_json(out, "base-abi-command.json", &evidence)?;
    if !evidence.complete() {
        return Err(environment_issue(
            "base SDK ABI probe unavailable; see base-abi-command.json",
        ));
    }
    let abi: Value = serde_json::from_str(&evidence.stdout)?;
    write_json(out, "base-abi.json", &abi)?;
    compare_process_layout(&abi)
}

pub(super) fn run(out: &Path) -> Result<()> {
    if !Manifest::bundled()?.budgets_fit() {
        return Err("base manifest exceeds budget".into());
    }
    // This gate belongs to this cell: no measurement may rely on another
    // matrix cell having checked the SDK first.
    let layout = check_layout(out);
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
        let measured = match &layout {
            Ok(()) => operation(out, &mut platform, &mut result),
            Err(error) if error.is::<EnvironmentIssue>() => Err(environment_issue(error)),
            Err(error) => Err(format!("base ABI gate: {error}").into()),
        };
        if let Err(error) = measured {
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
    let final_oracle = command(
        "/usr/sbin/sysctl",
        &["-n", "kern.bootsessionuuid"],
        None,
        TOOL_BUDGET,
    );
    let valid = final_oracle.complete();
    let final_expected = BootId::try_from(final_oracle.stdout.trim());
    result.evidence.push(final_oracle);
    if !valid {
        return Err(environment_issue("final boot UUID command unavailable"));
    }
    if final_expected? != expected {
        return Err("boot UUID oracle changed during Q-BOOT".into());
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
    let boot = platform.boot_id();
    // This guarded, fresh scratch setup has no engine storage/install record and
    // enables no helper. Persist the same initial state that setup will write.
    let initial = crate::snapshot::Snapshot::initial(None, boot.clone());
    let bytes = crate::snapshot::encode(1, &initial)?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(out.join("base-initial-snapshot.bin"))?;
    file.write_all(bytes.as_ref())?;
    file.sync_all()?;
    fs::File::open(out)?.sync_all()?;
    write_json(out, "base-initial-snapshot.json", &initial)?;
    let crate::snapshot::CopyClass::V {
        snapshot: decoded, ..
    } = crate::snapshot::classify_copy(crate::snapshot::CopyRead::Bytes(fs::read(
        out.join("base-initial-snapshot.bin"),
    )?))
    else {
        return Err("written initial snapshot failed engine decoding".into());
    };
    if !decoded.image_history.known_on(boot.as_ref()) {
        return Err(environment_issue(
            "initial history lacks proven current boot",
        ));
    }
    let history = decoded.image_history;
    let child_path = std::env::current_exe()?.with_file_name("wireguard-go");
    let mut pin_results = Vec::new();
    let mut pins = Vec::new();
    let mut pin_errors = Vec::new();
    for path in crate::engine::PINNED_TOOLS
        .iter()
        .map(Path::new)
        .chain(std::iter::once(child_path.as_path()))
    {
        let d = Deadline(platform.now() + 5);
        match platform.image_uuid(path, d) {
            Ok(uuid) => {
                pins.push((path.display().to_string(), uuid));
                pin_results.push(json!({"path": path, "uuid": hex_uuid(uuid)}));
            }
            Err(error) => {
                pin_errors.push(format!("image_uuid {}: {error}", path.display()));
                pin_results.push(json!({"path": path, "error": error.to_string()}));
            }
        }
    }
    write_json(out, "base-pin-images.json", &pin_results)?;
    if boot.is_none() {
        pin_errors.push("synthetic empty history: current boot unavailable".into());
        return Err(environment_issue(pin_errors.join("; ")));
    }
    let pin_uuids = pin_errors
        .is_empty()
        .then(|| pins.iter().map(|(_, uuid)| *uuid).collect::<Vec<_>>());

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
            scupper_darwin::sysctl_kern_proc_pid(c.0.id())
                .map_err(harness_process_error)?
                .ok_or_else(|| environment_issue("oracle vanished before identity read"))
        })
        .collect::<Result<Vec<_>>>()?;
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
                for p in list
                    .iter()
                    .filter(|p| p.state != ProcState::Zombie && p.path.is_none())
                {
                    census.push(json!({"iteration": iteration, "source": "complete_inventory",
                        "pid": p.pid, "ppid": p.ppid, "uid": scupper_darwin::proc_uid(p.pid).ok(),
                        "p_comm": p.name, "start": [p.start.seconds, u64::from(p.start.microseconds)],
                        "uuid": p.image.map(|i| hex_uuid(i.uuid)), "uniqueid": p.image.map(|i| i.uniqueid),
                        "classification": base_check::census_classification(p, &history, boot.as_ref(), &pins, pin_uuids.as_deref())}));
                }
                for p in &oracle {
                    if !list.iter().any(|got| {
                        i32::try_from(got.pid).ok() == Some(p.pid)
                            && proc::start(p.start.0, p.start.1).ok() == Some(got.start)
                    }) {
                        return Err(format!("Complete inventory missing oracle {}", p.pid).into());
                    }
                }
                if list.iter().any(|p| {
                    p.exe.is_some()
                        || (p.state != ProcState::Zombie
                            && p.path.is_none()
                            && p.image
                                .is_none_or(|image| image.uuid == [0; 16] || image.uniqueid == 0))
                }) {
                    return Err("Complete violates OD4/pathless rule".into());
                }
            }
            Enumeration::Incomplete(error) => {
                base_check::inventory(
                    &Enumeration::Incomplete(error.clone()),
                    Oracle::Stopped(children[0].0.id()),
                )?;
                incomplete.push(json!({"iteration": iteration, "pid": error.pid, "error": error.error.to_string()}));
            }
        }
        // Independent census records every live pathless entry, even when a
        // foreign pathless process prevents the adapter from completing a read.
        if iteration.is_multiple_of(50) {
            let observed = (|| -> Result<()> {
                for p in scupper_darwin::sysctl_kern_proc_all().map_err(harness_process_error)? {
                    if p.pid <= 0 || proc::state(p.stat)? == ProcState::Zombie {
                        continue;
                    }
                    let pid = u32::try_from(p.pid)?;
                    if let Err(error) = scupper_darwin::proc_pidpath(pid) {
                        let current = scupper_darwin::sysctl_kern_proc_pid(pid)
                            .map_err(harness_process_error)?;
                        if current
                            .as_ref()
                            .is_some_and(|q| q.start == p.start && q.stat != 5)
                        {
                            let d = Deadline(platform.now() + 2);
                            let observed = platform.observe_image(pid, d);
                            let image = observed
                                .as_ref()
                                .ok()
                                .and_then(|p| p.as_ref())
                                .and_then(|p| p.image);
                            let classification =
                                observed.as_ref().ok().and_then(|p| p.as_ref()).map_or_else(
                                    || "withheld: image unknown".into(),
                                    |p| {
                                        base_check::census_classification(
                                            p,
                                            &history,
                                            boot.as_ref(),
                                            &pins,
                                            pin_uuids.as_deref(),
                                        )
                                    },
                                );
                            census.push(json!({"iteration": iteration, "pid": pid, "ppid": p.ppid,
                                "uid": scupper_darwin::proc_uid(pid).ok(), "p_comm": proc::name(&p.comm),
                                "start": p.start, "errno": error.raw_os_error(),
                                "uuid": image.map(|i| hex_uuid(i.uuid)), "uniqueid": image.map(|i| i.uniqueid),
                                "classification": classification}));
                        }
                    }
                }
                Ok(())
            })();
            if let Err(error) = observed {
                if !error.is::<EnvironmentIssue>() {
                    return Err(error);
                }
                incomplete
                    .push(json!({"iteration": iteration, "harness_census": error.to_string()}));
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
    let mut unqualified = pin_errors;
    unqualified.extend(base_check::withheld_persistent_pathless(&census, complete));
    let remaining = Duration::from_secs(360).saturating_sub(case_start.elapsed());
    let until = scupper_darwin::monotonic_raw() + remaining;
    record_subcheck(
        stopped(out, &children[0], platform, until),
        "stopped",
        &mut unqualified,
    )?;
    record_subcheck(
        path_changes(out, platform, until),
        "path changes",
        &mut unqualified,
    )?;
    record_subcheck(
        image_cases(out, platform, until),
        "image UUID",
        &mut unqualified,
    )?;
    if incomplete
        .iter()
        .any(|entry| entry.get("harness_census").is_some())
    {
        unqualified.push(
            "harness census encountered transient process reads; see base-processes.json".into(),
        );
    }
    if !unqualified.is_empty() {
        result.verdict = Verdict::Inconclusive;
        result.detail = unqualified.join("; ");
    }
    if complete == 0 {
        result.verdict = Verdict::Inconclusive;
        result.detail = format!(
            "500 observations, no Complete inventory; oracle completeness remains unqualified; see pathless census and per-read errors; {}",
            unqualified.join("; ")
        );
    }
    if case_start.elapsed() >= Duration::from_secs(360) {
        return Err(environment_issue(
            "Q-PROC subchecks exhausted the six-minute case budget",
        ));
    }
    Ok(())
}

fn record_subcheck(check: Result<()>, label: &str, unqualified: &mut Vec<String>) -> Result<()> {
    if let Err(error) = check {
        if !error.is::<EnvironmentIssue>() {
            return Err(error);
        }
        unqualified.push(format!("{label}: {error}"));
    }
    Ok(())
}

fn stopped(
    out: &Path,
    child: &Supervised,
    platform: &mut NativePlatform,
    case_until: Duration,
) -> Result<()> {
    if scupper_darwin::monotonic_raw() >= case_until {
        return Err(environment_issue(
            "stopped subcheck has no remaining case budget",
        ));
    }
    let pid =
        rustix::process::Pid::from_raw(i32::try_from(child.0.id())?).ok_or("invalid oracle pid")?;
    rustix::process::kill_process(pid, rustix::process::Signal::STOP)?;
    let until = (scupper_darwin::monotonic_raw() + Duration::from_secs(2)).min(case_until);
    let check = (|| -> Result<()> {
        loop {
            let p = scupper_darwin::sysctl_kern_proc_pid(child.0.id())
                .map_err(harness_process_error)?
                .ok_or_else(|| environment_issue("stopped oracle vanished"))?;
            if proc::state(p.stat)? == ProcState::Stopped {
                break;
            }
            if scupper_darwin::monotonic_raw() >= until {
                return Err(environment_issue("SSTOP not observed within budget"));
            }
            let d = Deadline(platform.now() + 1);
            platform.pause(Duration::from_millis(10), d);
        }
        retry_inventory(
            out,
            "base-stopped-inventory.json",
            platform,
            Oracle::Stopped(child.0.id()),
            case_until,
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

fn path_changes(out: &Path, platform: &mut NativePlatform, case_until: Duration) -> Result<()> {
    if scupper_darwin::monotonic_raw() >= case_until {
        return Err(environment_issue(
            "path subcheck has no remaining case budget",
        ));
    }
    let source = out.join("base-sleep");
    let renamed = out.join("base-renamed-sleep");
    fs::copy("/bin/sleep", &source)?;
    let d = Deadline(platform.now() + 2);
    let identity = platform.executable_id(&source, d)?;
    let child = Supervised::spawn(out, &source, &["120"], "path-oracle.log")?;
    let before = scupper_darwin::proc_pidpath(child.0.id()).map_err(environment_issue)?;
    fs::rename(&source, &renamed)?;
    let after_rename = scupper_darwin::proc_pidpath(child.0.id());
    let d = Deadline(platform.now() + 2);
    if platform.executable_id(&renamed, d)? != identity {
        return Err("executable identity changed on rename".into());
    }
    fs::remove_file(&renamed)?;
    let after_unlink = scupper_darwin::proc_pidpath(child.0.id());
    let check = if after_unlink.is_ok() {
        Err(environment_issue(
            "unlink rule not exercised: proc_pidpath still succeeds",
        ))
    } else {
        let current =
            scupper_darwin::sysctl_kern_proc_pid(child.0.id()).map_err(harness_process_error)?;
        if current.is_none_or(|p| p.stat == 5) {
            Err(environment_issue("unlink oracle no longer live"))
        } else {
            retry_inventory(
                out,
                "base-unlinked-inventory.json",
                platform,
                Oracle::Pathless(child.0.id()),
                case_until,
            )
        }
    };
    write_json(
        out,
        "base-paths.json",
        &json!({"pid": child.0.id(), "before": before,
        "after_rename": after_rename.as_ref().map(|p| p.to_string_lossy()).map_err(|e| e.raw_os_error()),
        "after_unlink": after_unlink.as_ref().map(|p| p.to_string_lossy()).map_err(|e| e.raw_os_error()),
        "check": check.as_ref().map_err(ToString::to_string)}),
    )?;
    check
}

fn retry_inventory(
    out: &Path,
    evidence: &str,
    platform: &mut NativePlatform,
    oracle: Oracle,
    case_until: Duration,
) -> Result<()> {
    let until = (scupper_darwin::monotonic_raw() + Duration::from_secs(15)).min(case_until);
    let mut attempts = Vec::new();
    for _ in 0..5 {
        if scupper_darwin::monotonic_raw() >= until {
            break;
        }
        let deadline = Deadline((platform.now() + 2).min(until.as_secs()));
        let inventory = platform.processes(deadline);
        attempts.push(format!("{inventory:?}"));
        write_json(out, evidence, &attempts)?;
        if base_check::inventory(&inventory, oracle)? {
            return Ok(());
        }
        let deadline = Deadline((platform.now() + 1).min(until.as_secs()));
        platform.pause(Duration::from_millis(50), deadline);
    }
    Err(environment_issue(format!(
        "oracle inventory incomplete after bounded retries; see {evidence}"
    )))
}

fn capture_processes(
    out: &Path,
    _platform: &mut NativePlatform,
    result: &mut CaseResult,
) -> Result<()> {
    let start = Instant::now();
    let records = scupper_darwin::sysctl_kern_proc_all().map_err(harness_process_error)?;
    let mut bytes = Vec::new();
    for p in &records {
        let mut b = [0_u8; proc::RECORD_BYTES];
        b[proc::START_SEC..proc::START_SEC + 8].copy_from_slice(&p.start.0.to_le_bytes());
        b[proc::START_USEC..proc::START_USEC + 4].copy_from_slice(&p.start.1.to_le_bytes());
        b[proc::STAT] = p.stat;
        b[proc::PID..proc::PID + 4].copy_from_slice(&p.pid.to_le_bytes());
        b[proc::COMM..=proc::COMM + proc::MAXCOMLEN].copy_from_slice(&p.comm);
        if let Some(end) = p.comm.iter().position(|byte| *byte == 0) {
            b[proc::COMM + end..=proc::COMM + proc::MAXCOMLEN].fill(0);
        }
        b[proc::PPID..proc::PPID + 4].copy_from_slice(&p.ppid.to_le_bytes());
        b[proc::PGID..proc::PGID + 4].copy_from_slice(&p.pgid.to_le_bytes());
        bytes.extend_from_slice(&b);
    }
    // Reconstruct consumed typed fields at SDK-checked decoder offsets. This
    // value regression corpus is not a raw buffer capture or a layout oracle.
    // Opaque SDK fields (including addresses/credentials) remain zeroed.
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
    let build = scupper_darwin::sysctl_string("kern.osversion").map_err(environment_issue)?;
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
        "encoding": "consumed typed fields reconstructed at SDK-checked decoder offsets",
        "redaction": "all bytes except start, stat, pid, NUL-terminated comm, ppid, pgid zeroed"}),
    )?;
    if start.elapsed() >= Duration::from_secs(60) {
        return Err("base capture exceeded one-minute budget".into());
    }
    result.iterations = 1;
    result.detail = "consumed typed sysctl fields reconstructed as portable value fixtures; opaque fields zeroed".into();
    Ok(())
}

fn hex_uuid(uuid: [u8; 16]) -> String {
    use std::fmt::Write as _;
    uuid.into_iter()
        .fold(String::with_capacity(32), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}
fn ready(out: &Path, output: &str, until: Duration) -> Result<()> {
    loop {
        if fs::read(out.join(output)).is_ok_and(|bytes| bytes.starts_with(b"ready-")) {
            return Ok(());
        }
        if scupper_darwin::monotonic_raw() >= until {
            return Err(environment_issue("image child readiness deadline"));
        }
        thread::sleep(Duration::from_millis(1));
    }
}
fn identifier(pid: u32) -> Result<image::Identifier> {
    Ok(image::identifier(
        &scupper_darwin::proc_identifier(pid).map_err(environment_issue)?,
    )?)
}
#[allow(clippy::too_many_lines)] // Bounded unlink/classification and exec-race campaign with oracle guards.
fn image_cases(out: &Path, platform: &mut NativePlatform, case_until: Duration) -> Result<()> {
    let a = std::env::current_exe()?.with_file_name("base-image-a");
    let b = a.with_file_name("base-image-b");
    protected_path(&a, false)?;
    protected_path(&b, false)?;
    let d = Deadline(platform.now() + 2);
    let uuid_a = platform.image_uuid(&a, d)?;
    let uuid_b = platform.image_uuid(&b, d)?;
    if uuid_a == uuid_b {
        return Err("exec oracles unexpectedly share LC_UUID".into());
    }
    let scratch = out.join("unlinked-image");
    fs::copy(&a, &scratch)?;
    let child = Supervised::spawn(out, &scratch, &[], "image-unlink.log")?;
    ready(
        out,
        "image-unlink.log",
        case_until.min(scupper_darwin::monotonic_raw() + Duration::from_secs(2)),
    )?;
    fs::remove_file(&scratch)?;
    retry_inventory(
        out,
        "base-image-inventory.json",
        platform,
        Oracle::Pathless(child.0.id()),
        case_until,
    )?;
    let d = Deadline(platform.now() + 5);
    let observed = platform
        .observe_image(child.0.id(), d)
        .map_err(|e| environment_issue(format!("image bracket: {e:?}")))?
        .ok_or("image child vanished")?;
    if observed.image.is_none_or(|i| i.uuid != uuid_a) {
        return Err("unlinked image differs from parsed LC_UUID".into());
    }
    let boot = platform
        .boot_id()
        .ok_or_else(|| environment_issue("image case boot unknown"))?;
    let mut history = ImageHistory::empty_for_boot(boot.clone());
    history.record(uuid_a);
    let same = crate::platform::provably_foreign(&observed, &history, Some(&boot), Some(&[uuid_b]));
    history = ImageHistory::empty_for_boot(boot.clone());
    history.record(uuid_b);
    let different =
        crate::platform::provably_foreign(&observed, &history, Some(&boot), Some(&[uuid_b]));
    if same || !different {
        return Err("negative-only history classification failed".into());
    }
    let inventory = Enumeration::Complete(vec![observed.clone()]);
    let foreign = crate::platform::qualify_pathless(
        inventory.clone(),
        false,
        &history,
        Some(&boot),
        Some(&[uuid_b]),
        |_, _| true,
    );
    history.record(uuid_a);
    let blocked = crate::platform::qualify_pathless(
        inventory,
        false,
        &history,
        Some(&boot),
        Some(&[uuid_b]),
        |_, _| true,
    );
    if !matches!(foreign, Enumeration::Complete(_))
        || !matches!(blocked, Enumeration::Incomplete(ref e) if e.pid == Some(observed.pid))
    {
        return Err("engine pathless classification failed".into());
    }
    let mut rejected = 0;
    let mut accepted = 0;
    let mut measurements = Vec::new();
    for iteration in 0..200 {
        if scupper_darwin::monotonic_raw() >= case_until {
            return Err(environment_issue("exec campaign case deadline"));
        }
        let trigger = out.join(format!("exec-trigger-{iteration}"));
        let output = format!("exec-{iteration}.log");
        let child = Supervised::spawn(
            out,
            &a,
            &[
                b.to_str().ok_or("binary path")?,
                trigger.to_str().ok_or("trigger path")?,
            ],
            &output,
        )?;
        let until = case_until.min(scupper_darwin::monotonic_raw() + Duration::from_secs(2));
        ready(out, &output, until)?;
        let before = identifier(child.0.id())?;
        if before.image.uuid != uuid_a {
            return Err("pre-exec oracle mismatch".into());
        }
        fs::write(&trigger, b"exec")?;
        // Every attempt invokes the same ordered bracket as pathless enumeration.
        // The final identifier distinguishes exec (same pid/start and uniqueid,
        // changed idversion) from the initial image. Validate both pairings.
        let mut saw_post = false;
        while scupper_darwin::monotonic_raw() < until {
            let first = identifier(child.0.id())?;
            let d = Deadline(platform.now() + 2);
            let entry = platform.observe_image_version(child.0.id(), d);
            let last = identifier(child.0.id())?;
            match entry {
                Ok((Some(entry), Some(version))) if entry.image.is_some() => {
                    accepted += 1;
                    let image = entry.image.ok_or("missing image")?;
                    if (version == before.idversion && image.uuid != uuid_a)
                        || (version != before.idversion && image.uuid != uuid_b)
                        || image.uniqueid != before.image.uniqueid
                        || (first.idversion != before.idversion && image.uuid != uuid_b)
                        || (last.idversion == before.idversion && image.uuid != uuid_a)
                        || ![uuid_a, uuid_b].contains(&image.uuid)
                    {
                        return Err(
                            "exec bracket paired pre-exec UUID with post-exec identity".into()
                        );
                    }
                }
                Err(_) => rejected += 1,
                _ => return Err("exec child unexpectedly vanished or lacked image".into()),
            }
            if last.image.uuid == uuid_b {
                saw_post = true;
                break;
            }
        }
        fs::remove_file(trigger)?;
        if !saw_post {
            return Err(environment_issue("exec transition not observed"));
        }
        measurements.push(
            json!({"iteration": iteration, "pid": child.0.id(), "pre_idversion": before.idversion}),
        );
    }
    write_json(
        out,
        "base-images.json",
        &json!({"uuid_a": hex_uuid(uuid_a), "uuid_b": hex_uuid(uuid_b),
        "unlink_pid": observed.pid, "same_history": "incomplete", "unrelated_history": "foreign",
        "exec_iterations": 200, "accepted": accepted, "bracket_rejections": rejected, "measurements": measurements}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn harness_churn_is_environment_noise_but_layout_is_a_violation() {
        assert!(
            harness_process_error(scupper_darwin::ProcError::Incomplete).is::<EnvironmentIssue>()
        );
        assert!(
            harness_process_error(scupper_darwin::ProcError::Os(rustix::io::Errno::NOMEM))
                .is::<EnvironmentIssue>()
        );
        assert!(!harness_process_error(scupper_darwin::ProcError::Layout).is::<EnvironmentIssue>());
    }

    #[test]
    fn subchecks_keep_environment_noise_without_suppressing_violations() -> Result<()> {
        let mut missing = Vec::new();
        record_subcheck(
            Err(environment_issue("incomplete")),
            "stopped",
            &mut missing,
        )?;
        record_subcheck(Ok(()), "path changes", &mut missing)?;
        assert_eq!(missing, ["stopped: incomplete"]);
        assert!(record_subcheck(Err("adapter breach".into()), "stopped", &mut missing).is_err());
        Ok(())
    }
}
