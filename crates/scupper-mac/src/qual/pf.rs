//! R6 disposable pf campaign. A journaled launchd group contains every writer;
//! its bootout precedes harness-only global disable during independent restore.
use super::{
    CaseResult, Evidence, Result, Snapshot, TOOL_BUDGET, Verdict, environment_issue,
    executable_sha256, invoke_before, read_json, require_ack, save_case, write_json,
};
use crate::{
    decode::{
        pftext,
        pftoken::{self, Assumption, Assumptions, Classification, STRIDE},
    },
    native::{NativePlatform, Paths, TrustedExecutable},
    platform::{
        Deadline, Enumeration, ExeId, Fence, PfEnable, PfInfo, Platform, RefLine, Release,
        SysError, Tool, ToolOutcome, runtime::Reap,
    },
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    os::{
        fd::AsFd,
        unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    },
    path::Path,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

fn ensure(ok: bool, detail: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(detail.to_owned().into())
    }
}
fn append(out: &Path, value: &Value) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(out.join("resources.jsonl"))?;
    writeln!(file, "{value}")?;
    file.sync_all()?;
    Ok(())
}
fn gates() -> Assumptions {
    Assumptions {
        pf_token_layout: Assumption::Established,
        eexist_establishes_anonymous: Assumption::Established,
        disable_voids_references: Assumption::Established,
        fingerprints: Assumption::Established,
    }
}
fn platform(out: &Path, qualified: bool) -> Result<NativePlatform> {
    let path = Path::new("/sbin/pfctl");
    super::protected_path(path, false)?;
    let meta = fs::symlink_metadata(path)?;
    let pin = TrustedExecutable {
        path: path.into(),
        exe: ExeId {
            dev: meta.dev(),
            ino: meta.ino(),
        },
        sha256: Sha256::digest(fs::read(path)?).into(),
    };
    let mut p = NativePlatform::new(Paths::qualification(out.into()))?
        .with_pins(vec![pin], crate::engine::CHILD_PATH.into());
    if qualified {
        p.reference_assumptions(gates());
    }
    Ok(p)
}
fn deadline(end: Instant) -> Result<Deadline> {
    let left = end.saturating_duration_since(Instant::now());
    if left.is_zero() {
        return Err(environment_issue("pf case deadline expired"));
    }
    Ok(Deadline(
        scupper_darwin::monotonic_raw().as_secs() + left.as_secs().min(8),
    ))
}
fn refs(p: &mut NativePlatform, end: Instant) -> Result<Vec<RefLine>> {
    match p.references(deadline(end)?) {
        Enumeration::Complete(lines) => Ok(lines),
        Enumeration::Incomplete(e) => {
            Err(environment_issue(format!("references incomplete: {e:?}")))
        }
    }
}
fn info(p: &mut NativePlatform, expected: &PfInfo, end: Instant) -> Result<()> {
    let actual = p.pf_info(deadline(end)?);
    if let PfInfo::Incomplete(e) = actual {
        return Err(environment_issue(format!("pf info incomplete: {e:?}")));
    }
    ensure(&actual == expected, "pf state differs from expected")
}
fn acquire(p: &mut NativePlatform, end: Instant) -> Result<u64> {
    acquire_sample(p, end).map(|sample| sample.0)
}
fn acquire_sample(p: &mut NativePlatform, end: Instant) -> Result<(u64, u32, u64, u64)> {
    let before = super::super::command::unix_seconds();
    let ToolOutcome::Ok((token, pid)) = p.acquire(deadline(end)?) else {
        return Err(environment_issue(
            "unrecognized/incomplete -E; inspect pf-text captures",
        ));
    };
    let after = super::super::command::unix_seconds();
    if after.saturating_add(1) < before.saturating_sub(1) {
        return Err(environment_issue("wall clock stepped across acquisition"));
    }
    let lines = refs(p, end)?;
    ensure(
        lines.iter().any(|r| {
            r.token == token
                && r.pid == pid
                && r.timestamp >= before.saturating_sub(1)
                && r.timestamp <= after.saturating_add(1)
        }),
        "acquisition PID/calendar timestamp fingerprint mismatch",
    )?;
    Ok((token, pid, before, after))
}
fn release(p: &mut NativePlatform, token: u64, end: Instant) -> Result<()> {
    ensure(p.fence() == Fence::Closed, "release fence open")?;
    ensure(
        refs(p, end)?.iter().any(|r| r.token == token),
        "release token missing",
    )?;
    if p.release(token, deadline(end)?) == ToolOutcome::Ok(Release::Released) {
        Ok(())
    } else {
        Err(environment_issue(
            "release result unrecognized; inspect full Q-ENABLE text",
        ))
    }
}
fn raw(out: &Path, p: &mut NativePlatform, args: &[&str], end: Instant) -> Result<Evidence> {
    let started = Instant::now();
    let wall = super::super::command::unix_seconds();
    let command_line: Vec<_> = std::iter::once("/sbin/pfctl")
        .chain(args.iter().copied())
        .collect();
    let result = p.run_tool(
        Tool::Pfctl,
        Path::new("/sbin/pfctl"),
        &command_line,
        &[],
        1024 * 1024,
        deadline(end)?,
    )?;
    let evidence = Evidence {
        command: command_line.iter().map(|s| (*s).into()).collect(),
        stdin: None,
        pid: Some(result.pid),
        exit_code: match result.reap {
            Reap::Status(s) if s.trailing_zeros() >= 7 => Some((s >> 8) & 255),
            _ => None,
        },
        started_unix_ms: u128::from(wall) * 1000,
        elapsed_ms: started.elapsed().as_millis(),
        timed_out: result.timed_out,
        truncated: result.io_failed
            || result.stdout.truncated
            || result.stderr.truncated
            || result.stdin_unsent != 0,
        stdout: String::from_utf8(result.stdout.bytes)?,
        stderr: String::from_utf8(result.stderr.bytes)?,
    };
    write_json(
        out,
        &format!("{}.json", super::unique("pf-text")),
        &evidence,
    )?;
    if evidence.exit_code.is_none() || evidence.timed_out || evidence.truncated {
        return Err(environment_issue("raw pfctl incomplete"));
    }
    Ok(evidence)
}
/// Global disable is exclusive to the disposable harness and journaled restore.
fn reset(out: &Path, p: &mut NativePlatform, end: Instant) -> Result<()> {
    ensure(
        p.reap(deadline(end)?) == Fence::Closed,
        "reset with outstanding pfctl",
    )?;
    if p.pf_info(deadline(end)?) == PfInfo::Enabled {
        ensure(
            raw(out, p, &["-d"], end)?.complete(),
            "harness disable failed",
        )?;
    }
    info(p, &PfInfo::Disabled, end)?;
    ensure(refs(p, end)?.is_empty(), "disable retained tokens")
}
fn baseline(out: &Path) -> Result<()> {
    let before: Snapshot = read_json(&out.join("preflight.json"))?;
    ensure(before.inconclusive.is_empty(), "preflight inconclusive")?;
    ensure(
        super::super::restore_check::pf_status(&before.observations) == Some(false),
        "pf campaign requires disabled preflight",
    )?;
    let tokens = before
        .observations
        .get("pf-references")
        .ok_or("no preflight references")?;
    ensure(
        tokens.complete()
            && super::super::guard::no_foreign_references(&tokens.stdout, &tokens.stderr),
        "pf campaign requires no preflight references",
    )
}

pub(super) fn run(out: &Path, group: &str) -> Result<()> {
    require_ack(out)?;
    baseline(out)?;
    // Persist the global-state intent BEFORE any adapter/harness mutator starts.
    append(out, &json!({"kind":"r6-pf"}))?;
    append(
        out,
        &json!({"kind":"r4-tree","path":out.join("r4-fixtures")}),
    )?;
    fs::DirBuilder::new()
        .mode(0o700)
        .create(out.join("r4-fixtures"))?;
    let (service, record) = super::tool::launch_job(out, group, false)?;
    let stop = super::invoke("/bin/launchctl", &["bootout", &service]);
    ensure(stop.complete(), "pf worker bootout failed")?;
    stop_groups(out, Instant::now() + Duration::from_secs(5))?;
    ensure(record["finished"] == true, "pf worker did not finish")?;
    ensure(
        record["failed"] == false,
        "pf qualification failed; inspect case verdicts",
    )
}
pub(super) fn worker(out: &Path, group: &str) -> Result<()> {
    baseline(out)?;
    let own =
        scupper_darwin::sysctl_kern_proc_pid(std::process::id())?.ok_or("pf worker absent")?;
    ensure(
        own.ppid == 1 && own.pid == own.pgid,
        "pf worker must lead a launchd group",
    )?;
    append(
        out,
        &json!({"kind":"r6-group","pid":own.pid,"start":format!("{}:{}",own.start.0,own.start.1)}),
    )?;
    let abi = invoke_before(
        super::probe_path()?.to_str().ok_or("probe path")?,
        &[],
        Instant::now() + TOOL_BUDGET,
    );
    ensure(abi.complete(), "pf ABI probe incomplete")?;
    let value: Value = serde_json::from_str(&abi.stdout)?;
    compare_layout(&value)?;
    write_json(out, "pf-abi.json", &value)?;
    let mut p = platform(out, true)?;
    let mut results = Vec::new();
    for (id, minutes, iterations, operation) in if group == "pf" {
        vec![
            (
                "Q-ENABLE",
                2,
                50,
                enable as fn(&Path, &mut NativePlatform, Instant, &mut CaseResult) -> Result<()>,
            ),
            ("Q-EEXIST", 2, 50, eexist),
            ("Q-REFS", 8, 2000, references),
        ]
    } else if group == "pf-x" {
        vec![(
            "Q-X",
            2,
            3,
            x as fn(&Path, &mut NativePlatform, Instant, &mut CaseResult) -> Result<()>,
        )]
    } else {
        vec![(
            "Q-X-STALE",
            2,
            1,
            x_stale as fn(&Path, &mut NativePlatform, Instant, &mut CaseResult) -> Result<()>,
        )]
    } {
        let mut result = CaseResult {
            case: id.into(),
            binary_sha256: executable_sha256()?,
            verdict: Verdict::AssumptionHolds,
            iterations: 0,
            detail: "Disposable-runner evidence only; no production assumption promotion".into(),
            evidence: vec![],
        };
        let end = Instant::now() + Duration::from_secs(minutes * 60);
        if let Err(error) = operation(out, &mut p, end, &mut result) {
            result.verdict = if error.is::<super::EnvironmentIssue>() {
                Verdict::Inconclusive
            } else if result.verdict == Verdict::AssumptionRefuted {
                Verdict::AssumptionRefuted
            } else {
                Verdict::ContractViolation
            };
            result.detail = error.to_string();
        } else if result.iterations < iterations {
            result.verdict = Verdict::Inconclusive;
            result.detail = "required iterations were not reached".into();
        }
        let stop = matches!(
            result.verdict,
            Verdict::AssumptionRefuted | Verdict::ContractViolation
        );
        save_case(out, &result)?;
        results.push(result);
        if stop {
            break;
        } // OD10: stop immediately on a refuted EEXIST assumption.
    }
    let failed = results.iter().any(|r| {
        matches!(
            r.verdict,
            Verdict::ContractViolation | Verdict::AssumptionRefuted
        )
    });
    write_json(out, "verdicts.json", &results)?;
    write_json(
        out,
        &format!("tool-worker-{group}.json"),
        &json!({"finished":true,"failed":failed}),
    )
}
fn compare_layout(abi: &Value) -> Result<()> {
    for (name, size, fields) in [
        (
            "pfioc_token",
            scupper_darwin::PF_TOKEN_SIZE,
            vec![
                ("token", 0),
                ("timestamp", 8),
                ("pid", 16),
                ("proc_name", 20),
            ],
        ),
        (
            "pfioc_tokens",
            scupper_darwin::PF_TOKENS_SIZE,
            vec![("size", 0), ("buffer", 8)],
        ),
    ] {
        ensure(
            abi[name]["size"].as_u64() == Some(size as u64),
            "pf ABI size mismatch",
        )?;
        for (field, offset) in fields {
            ensure(
                abi[name]["fields"][field].as_u64() == Some(offset),
                "pf ABI field mismatch",
            )?;
        }
    }
    ensure(
        abi["DIOCGETSTARTERS"].as_u64() == Some(u64::from(pftoken::GETSTARTERS))
            && pftoken::GETSTARTERS == scupper_darwin::DIOCGETSTARTERS,
        "pf ioctl mismatch",
    )
}
#[allow(clippy::too_many_lines)] // Preserve full text captures and the anonymous-reference cycle ordering.
fn enable(out: &Path, p: &mut NativePlatform, end: Instant, result: &mut CaseResult) -> Result<()> {
    let build = scupper_darwin::sysctl_string("kern.osversion")?;
    for _ in 0..50 {
        reset(out, p, end)?;
        let raw_enable = raw(out, p, &["-e"], end)?;
        ensure(
            pftext::enable(
                &build,
                raw_enable.exit_code.unwrap_or(-1),
                raw_enable.stdout.as_bytes(),
                raw_enable.stderr.as_bytes(),
                gates(),
            ) == Ok(PfEnable::Started),
            "enable text table mismatch",
        )?;
        reset(out, p, end)?;
        ensure(
            p.enable_pf(deadline(end)?) == Ok(PfEnable::Started),
            "disabled enable not Started",
        )?;
        for _ in 0..5 {
            ensure(
                p.enable_pf(deadline(end)?) == Ok(PfEnable::AlreadyRunning),
                "qualified EEXIST not AlreadyRunning",
            )?;
            let mut unknown = platform(out, false)?;
            ensure(
                unknown.enable_pf(deadline(end)?) == Err(SysError::Unknown),
                "ungated EEXIST accepted",
            )?;
            ensure(
                matches!(
                    unknown.references(deadline(end)?),
                    Enumeration::Incomplete(_)
                ),
                "unknown layout enumerated",
            )?;
        }
        let raw_eexist = raw(out, p, &["-e"], end)?;
        ensure(
            pftext::enable(
                &build,
                raw_eexist.exit_code.unwrap_or(-1),
                raw_eexist.stdout.as_bytes(),
                raw_eexist.stderr.as_bytes(),
                gates(),
            ) == Ok(PfEnable::AlreadyRunning),
            "EEXIST full text table mismatch",
        )?;
        let raw_acquire = raw(out, p, &["-E"], end)?;
        let token = pftext::acquire(
            &build,
            raw_acquire.exit_code.unwrap_or(-1),
            raw_acquire.stdout.as_bytes(),
            raw_acquire.stderr.as_bytes(),
        )
        .map_err(|_| environment_issue("-E text table mismatch; full capture saved"))?;
        let raw_release = raw(out, p, &["-X", &token.to_string()], end)?;
        ensure(
            pftext::release(
                &build,
                raw_release.exit_code.unwrap_or(-1),
                raw_release.stdout.as_bytes(),
                raw_release.stderr.as_bytes(),
                token,
            ) == Ok(Release::Released),
            "-X text table mismatch",
        )?;
        let token = acquire(p, end)?;
        release(p, token, end)?;
        let foreign = acquire(p, end)?;
        ensure(
            raw(out, p, &["-X", &foreign.to_string()], end)?.complete(),
            "foreign -X failed",
        )?;
        let process = invoke_before(
            std::env::current_exe()?.to_str().ok_or("exe")?,
            &[
                "r6-enable",
                "--out",
                out.to_str().ok_or("out")?,
                "--disposable-runner",
            ],
            end,
        );
        ensure(process.complete(), "new adapter process enable failed")?;
        ensure(
            refs(p, end)?.is_empty(),
            "anonymous reference appeared in token list",
        )?;
        reset(out, p, end)?;
        let from_disabled = raw(out, p, &["-E"], end)?;
        let last_token = pftext::acquire(
            &build,
            from_disabled.exit_code.unwrap_or(-1),
            from_disabled.stdout.as_bytes(),
            from_disabled.stderr.as_bytes(),
        )
        .map_err(|_| environment_issue("disabled -E text table mismatch; full capture saved"))?;
        let last_release = raw(out, p, &["-X", &last_token.to_string()], end)?;
        ensure(
            pftext::release(
                &build,
                last_release.exit_code.unwrap_or(-1),
                last_release.stdout.as_bytes(),
                last_release.stderr.as_bytes(),
                last_token,
            ) == Ok(Release::Released),
            "last -X full text table mismatch",
        )?;
        info(p, &PfInfo::Disabled, end)?;
        let token = acquire(p, end)?;
        release(p, token, end)?;
        info(p, &PfInfo::Disabled, end)?;
        result.iterations += 1;
    }
    Ok(())
}
fn eexist(out: &Path, p: &mut NativePlatform, end: Instant, result: &mut CaseResult) -> Result<()> {
    for _ in 0..50 {
        reset(out, p, end)?;
        let token = acquire(p, end)?;
        if p.enable_pf(deadline(end)?) != Ok(PfEnable::AlreadyRunning) {
            return Err(environment_issue(
                "EEXIST text unrecognized; assumption remains inconclusive",
            ));
        }
        release(p, token, end)?;
        // Only this post-release state can refute the EEXIST assumption.
        match p.pf_info(deadline(end)?) {
            PfInfo::Enabled => (),
            PfInfo::Disabled => {
                result.verdict = Verdict::AssumptionRefuted;
                return Err("EEXIST did not preserve anonymous enable after token release".into());
            }
            PfInfo::Incomplete(e) => {
                return Err(environment_issue(format!(
                    "post-release info incomplete: {e:?}"
                )));
            }
        }
        ensure(refs(p, end)?.is_empty(), "anonymous reference enumerated")?;
        reset(out, p, end)?;
        let token = acquire(p, end)?;
        release(p, token, end)?;
        info(p, &PfInfo::Disabled, end)?;
        result.iterations += 1;
    }
    Ok(())
}

#[allow(clippy::too_many_lines)] // Keep the ordered raw, quiescent, fingerprint and churn experiments together.
fn references(
    out: &Path,
    p: &mut NativePlatform,
    end: Instant,
    result: &mut CaseResult,
) -> Result<()> {
    reset(out, p, end)?;
    let fd = scupper_darwin::pf_open()?;
    let mut observations = Vec::new();
    for n in [1_usize, 2, 3, 8, 64] {
        let mut tokens = Vec::new();
        for _ in 0..n {
            tokens.push(acquire(p, end)?);
        }
        tokens.reverse(); // kernel copies newest first, drops oldest on overflow
        for capacity in [
            STRIDE - 1,
            STRIDE,
            STRIDE + 1,
            2 * STRIDE - 1,
            2 * STRIDE,
            n * STRIDE,
            n * STRIDE + STRIDE,
        ] {
            let mut bytes = vec![0; capacity];
            let returned = scupper_darwin::pf_starters(fd.as_fd(), &mut bytes)?;
            ensure(
                returned <= capacity && returned.is_multiple_of(STRIDE),
                "raw pf returned an invalid copy length",
            )?;
            ensure(
                bytes[..returned]
                    .as_chunks::<STRIDE>()
                    .0
                    .iter()
                    .all(|record| &record[20..26] == b"pfctl\0"),
                "owned raw starter process name differs from pfctl",
            )?;
            let copied = pftoken::decode(&bytes[..returned])?;
            let expected: Vec<_> = tokens.iter().take(capacity / STRIDE).copied().collect();
            ensure(
                copied.iter().map(|r| r.token).collect::<Vec<_>>() == expected,
                "XNU copy-loop model mismatch",
            )?;
            let complete =
                pftoken::classify(capacity, returned, STRIDE) == Classification::Complete;
            ensure(
                complete == (capacity / STRIDE > n),
                "completeness predicate differs from XNU copy loop",
            )?;
            observations.push(json!({"n":n,"capacity":capacity,"returned":returned,"complete":complete,
                "tokens":copied.iter().map(|r|json!({"token":r.token,"pid":r.pid,"timestamp":r.timestamp})).collect::<Vec<_>>()}));
        }
        let need = scupper_darwin::pf_starters(fd.as_fd(), &mut [])?;
        let wall = super::super::command::unix_seconds();
        let text = raw(out, p, &["-s", "References"], end)?;
        ensure(text.complete(), "References text incomplete")?;
        let parsed = super::super::journal::text_tokens(&text.stdout, wall)?;
        ensure(
            text.stdout
                .lines()
                .skip(2)
                .filter(|l| !l.trim().is_empty())
                .all(|l| l.split_whitespace().nth(1) == Some("pfctl")),
            "References text process name differs from kernel name",
        )?;
        let lines = refs(p, end)?;
        ensure(
            need == n * STRIDE && parsed.len() == n && lines.len() == n,
            "quiescent size/text count mismatch",
        )?;
        for line in lines {
            ensure(
                parsed.iter().any(|r| {
                    r.value == line.token
                        && r.pid == u64::from(line.pid)
                        && r.timestamp.abs_diff(line.timestamp) <= 1
                }),
                "quiescent text/ioctl fields differ",
            )?;
        }
        for token in tokens {
            release(p, token, end)?;
        }
    }
    write_json(out, "pf-raw-capacities.json", &observations)?;
    let mut values = BTreeMap::<u64, u32>::new();
    let mut fingerprints = Vec::new();
    for _ in 0..500 {
        let (token, spawned_pid, before, after) = acquire_sample(p, end)?;
        let line = refs(p, end)?
            .into_iter()
            .find(|r| r.token == token)
            .ok_or("fingerprint absent")?;
        *values.entry(token).or_default() += 1;
        fingerprints.push(json!({"token":token,"pid":line.pid,"spawned_pid":spawned_pid,"timestamp":line.timestamp,"wall_before":before,"wall_after":after}));
        release(p, token, end)?;
    }
    write_json(
        out,
        "pf-fingerprints.json",
        &json!({"acquisitions":fingerprints,"value_counts":values,
        "repeated_values":values.values().filter(|n| **n > 1).count(),"claim":"calendar seconds only; no monotonicity or uniqueness claim"}),
    )?;
    let mut held = Vec::new();
    for _ in 0..8 {
        held.push(acquire(p, end)?);
    }
    let mut workers = Workers(vec![]);
    for i in 0..4 {
        workers.0.push(
            Command::new(std::env::current_exe()?)
                .args([
                    "r6-churn",
                    "--out",
                    out.to_str().ok_or("out")?,
                    "--name",
                    &i.to_string(),
                    "--disposable-runner",
                ])
                .env_clear()
                .env("GITHUB_ACTIONS", "true")
                .env("RUNNER_ENVIRONMENT", "github-hosted")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()?,
        );
    }
    for i in 0..4 {
        while !out.join(format!("pf-churn-ready-{i}")).exists() {
            let _ = deadline(end)?;
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    let start = Instant::now();
    let mut complete = 0_u32;
    let mut incomplete = 0_u32;
    let mut subruns = Vec::new();
    let mut coverage_missing = false;
    for (spare, reads) in [(16, 1000), (0, 500), (1, 500)] {
        p.reference_spare_slots(spare);
        let _ = p.reference_copy_decisions();
        let mut sub_complete = 0_u32;
        let mut sub_incomplete = 0_u32;
        for _ in 0..reads {
            match p.references(deadline(end)?) {
                Enumeration::Complete(lines) => {
                    ensure(
                        held.iter()
                            .all(|token| lines.iter().any(|r| r.token == *token)),
                        "Complete omitted a long-lived token (including oldest)",
                    )?;
                    sub_complete += 1;
                }
                Enumeration::Incomplete(_) => sub_incomplete += 1,
            }
            result.iterations += 1;
        }
        let decisions = p.reference_copy_decisions();
        let retries = decisions
            .iter()
            .filter(|d| **d == Classification::Retry)
            .count();
        coverage_missing |= spare < 16 && (retries == 0 || sub_complete == 0);
        subruns.push(json!({"spare_slots":spare,"reads":reads,"retry":retries,
            "complete":sub_complete,"incomplete":sub_incomplete}));
        complete += sub_complete;
        incomplete += sub_incomplete;
    }
    p.reference_spare_slots(16);
    for child in &mut workers.0 {
        ensure(
            child.try_wait()?.is_none(),
            "churn worker exited before all enumerations finished",
        )?;
    }
    fs::write(out.join("pf-churn-stop"), b"stop")?;
    let wait_end = end.min(Instant::now() + Duration::from_secs(10));
    for child in &mut workers.0 {
        while child.try_wait()?.is_none() {
            ensure(Instant::now() < wait_end, "churn worker did not stop")?;
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    let mut counts = Vec::new();
    for i in 0..4 {
        let count: Value = read_json(&out.join(format!("pf-churn-{i}.json")))?;
        ensure(
            count["iterations"].as_u64().unwrap_or(0) > 0 && count["error"].is_null(),
            "churn worker made no successful progress",
        )?;
        counts.push(count);
    }
    coverage_missing |= complete == 0;
    let capacities = p.reference_capacities();
    ensure(
        !capacities.is_empty()
            && capacities.iter().any(|c| *c > 0)
            && capacities.iter().all(|c| c.is_multiple_of(STRIDE)),
        "adapter passed an unaligned ioctl capacity or supplied no capacity evidence",
    )?;
    write_json(out, "pf-adapter-capacities.json", &capacities)?;
    write_json(
        out,
        "pf-churn.json",
        &json!({"complete":complete,"incomplete":incomplete,
        "workers":counts,"burst":4,"subruns":subruns,
        "elapsed_ms":start.elapsed().as_millis(),"long_lived":held}),
    )?;
    for token in held {
        release(p, token, end)?;
    }
    if coverage_missing {
        return Err(environment_issue(
            "small-spare churn requires Retry > 0 and Complete > 0 for each sub-run; inspect pf-churn.json",
        ));
    }
    Ok(())
}
struct Workers(Vec<Child>);
impl Drop for Workers {
    fn drop(&mut self) {
        for child in &mut self.0 {
            let _ = child.kill();
        }
        let end = Instant::now() + Duration::from_secs(2);
        for child in &mut self.0 {
            while Instant::now() < end {
                if child.try_wait().ok().flatten().is_some() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        }
        // launchd retains group cleanup responsibility if a child is unreaped.
    }
}
pub(super) fn auxiliary(out: &Path, mode: &str, name: &str) -> Result<()> {
    require_ack(out)?;
    let mut p = platform(out, true)?;
    let end = Instant::now() + Duration::from_secs(if mode == "r6-churn" { 120 } else { 8 });
    if mode == "r6-enable" {
        return ensure(
            p.enable_pf(deadline(end)?) == Ok(PfEnable::AlreadyRunning),
            "new-process anonymous enable failed",
        );
    }
    ensure(
        ["0", "1", "2", "3"].contains(&name),
        "invalid churn worker id",
    )?;
    let mut iterations = 0_u32;
    let outcome = (|| -> Result<()> {
        while !out.join("pf-churn-stop").exists() && Instant::now() < end {
            // Each worker acquires four before releasing: bursts exceed spare 0/1.
            let mut burst = Vec::new();
            for _ in 0..4 {
                burst.push(acquire(&mut p, end)?);
            }
            for token in burst {
                release(&mut p, token, end)?;
            }
            iterations += 1;
            if iterations == 1 {
                fs::write(out.join(format!("pf-churn-ready-{name}")), b"ready")?;
            }
        }
        Ok(())
    })();
    write_json(
        out,
        &format!("pf-churn-{name}.json"),
        &json!({"iterations":iterations,
        "error":outcome.as_ref().err().map(ToString::to_string)}),
    )?;
    outcome
}
fn x(out: &Path, p: &mut NativePlatform, end: Instant, result: &mut CaseResult) -> Result<()> {
    let mut observations = Vec::new();
    for scenario in ["X1", "X1-anonymous", "X2"] {
        reset(out, p, end)?;
        let old = acquire(p, end)?;
        if scenario.starts_with("X1") {
            let _second = acquire(p, end)?;
            if scenario == "X1-anonymous" {
                ensure(
                    p.enable_pf(deadline(end)?) == Ok(PfEnable::AlreadyRunning),
                    "X1 anonymous enable",
                )?;
            }
            reset(out, p, end)?;
        } else {
            release(p, old, end)?;
        }
        info(p, &PfInfo::Disabled, end)?;
        ensure(
            refs(p, end)?.is_empty(),
            "old references survive disable/last release",
        )?;
        let invalid = raw(out, p, &["-X", &old.to_string()], end)?;
        // R2 measured this response only while pf is disabled. Never promote it
        // to TokenInvalid for a numeric release racing a reissued holder.
        ensure(
            invalid.exit_code == Some(1)
                && invalid.stdout.is_empty()
                && invalid.stderr == "pfctl: pf not enabled\n",
            "disabled stale -X text differs from R2",
        )?;
        let new = acquire(p, end)?;
        let lines = refs(p, end)?;
        ensure(
            lines.len() == 1 && lines[0].token == new,
            "new acquisition list differs from singleton",
        )?;
        observations.push(json!({"scenario":scenario,"old":old,"new":new,"recurrence":old==new,"invalid":invalid}));
        release(p, new, end)?;
        result.iterations += 1;
    }
    write_json(out, "pf-x-contract.json", &observations)?;
    reset(out, p, end)
}
fn x_stale(
    out: &Path,
    p: &mut NativePlatform,
    end: Instant,
    result: &mut CaseResult,
) -> Result<()> {
    // Successful stale-value trials are measurements and support no assumptions.
    result.verdict = Verdict::Measurement;
    let mut observations = Vec::new();
    reset(out, p, end)?;
    let stale = acquire(p, end)?;
    release(p, stale, end)?;
    let blocker = acquire(p, end)?;
    // If the blocker itself recurs, it is already a re-issued live holder.
    let mut recurred = blocker == stale;
    for attempt in 0..200 {
        let current = acquire(p, end)?;
        let before = refs(p, end)?;
        let response = raw(out, p, &["-X", &stale.to_string()], end)?;
        let after = refs(p, end)?;
        let removed =
            before.iter().any(|r| r.token == stale) && !after.iter().any(|r| r.token == stale);
        recurred |= current == stale;
        observations.push(json!({"attempt":attempt,"stale":stale,"current":current,"blocker":blocker,
            "reissued":recurred,"released_reissued_holder":removed,"response":response,
            "before":before.iter().map(|r|r.token).collect::<Vec<_>>(),"after":after.iter().map(|r|r.token).collect::<Vec<_>>()}));
        if after.iter().any(|r| r.token == current) {
            release(p, current, end)?;
        }
        if recurred {
            break;
        }
    }
    write_json(
        out,
        "pf-x-observations.json",
        &json!({"observations":observations,"recurrence_observed":recurred}),
    )?;
    result.iterations = 1;
    result.verdict = Verdict::Measurement;
    result.detail = format!(
        "stale -X while enabled is measurement only; recurrence observed={recurred}; no invalid-token row promoted"
    );
    reset(out, p, end)
}

// Bootout initiates group cleanup; only a complete census with no members can
// close it. Never restore pf while a group member could still enable it later.
pub(super) fn groups_gone(out: &Path) -> Result<bool> {
    let groups: Vec<_> = super::resources::entries(out)?
        .into_iter()
        .filter(|e| e.kind == "r6-group")
        .map(|e| e.pid)
        .collect();
    if groups.is_empty() {
        return Ok(true);
    }
    let processes = scupper_darwin::sysctl_kern_proc_all().map_err(|e| e.to_string())?;
    Ok(!processes
        .iter()
        .any(|p| u32::try_from(p.pgid).is_ok_and(|g| groups.contains(&g))))
}
pub(super) fn stop_groups(out: &Path, end: Instant) -> Result<()> {
    while !groups_gone(out)? {
        ensure(
            Instant::now() < end,
            "pf launchd group members survived; global restore withheld",
        )?;
        std::thread::sleep(Duration::from_millis(20));
    }
    Ok(())
}
