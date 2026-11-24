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
fn ensure_text(ok: bool, detail: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(environment_issue(format!(
            "{detail}; inspect saved pf-text captures"
        )))
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
    let seconds = super::super::pf_check::deadline_seconds(left).map_err(environment_issue)?;
    Ok(Deadline(
        scupper_darwin::monotonic_raw().as_secs() + seconds,
    ))
}
fn enable_expected(p: &mut NativePlatform, end: Instant, expected: PfEnable) -> Result<()> {
    let (actual, timed_out) = p.enable_pf_observed(deadline(end)?);
    super::super::pf_check::enable_result(&actual, expected, timed_out).map_err(environment_issue)
}
fn refs(p: &mut NativePlatform, end: Instant) -> Result<Vec<RefLine>> {
    super::super::pf_check::references_result(
        p.references(deadline(end)?),
        "pf case deadline expired",
    )
    .map_err(environment_issue)
}
fn info(p: &mut NativePlatform, expected: &PfInfo, end: Instant) -> Result<()> {
    let actual = p.pf_info(deadline(end)?);
    if actual == PfInfo::Incomplete(SysError::TimedOut) {
        return Err(environment_issue("pf case deadline expired: info TimedOut"));
    }
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
    let outcome = p.acquire(deadline(end)?);
    let ToolOutcome::Ok((token, pid)) = outcome else {
        if matches!(
            outcome,
            ToolOutcome::NotStarted(SysError::TimedOut) | ToolOutcome::Failed(SysError::TimedOut)
        ) {
            return Err(environment_issue(format!(
                "pf case deadline expired: {outcome:?}"
            )));
        }
        return Err(environment_issue(format!(
            "unrecognized/incomplete -E: {outcome:?}; inspect pf-text captures"
        )));
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
    release_owned(p, token, None, end)
}
fn release_owned(
    p: &mut NativePlatform,
    token: u64,
    expected: Option<&RefLine>,
    end: Instant,
) -> Result<()> {
    ensure(
        p.reference_qualification().fingerprints,
        "release fingerprints unqualified",
    )?;
    ensure(p.fence() == Fence::Closed, "release fence open")?;
    let before = refs(p, end)?
        .into_iter()
        .find(|r| r.token == token)
        .ok_or_else(|| environment_issue("release token missing"))?;
    ensure_text(
        expected.is_none_or(|expected| expected == &before),
        "release pre-fingerprint changed",
    )?;
    let outcome = p.release(token, deadline(end)?);
    if matches!(
        outcome,
        ToolOutcome::NotStarted(SysError::TimedOut) | ToolOutcome::Failed(SysError::TimedOut)
    ) {
        return Err(environment_issue(format!(
            "pf case deadline expired: {outcome:?}"
        )));
    }
    let acknowledged = outcome == ToolOutcome::Ok(Release::Requested);
    let after = refs(p, end)?;
    check_release(acknowledged, !after.contains(&before)).map_err(|error| {
        if error.is::<super::EnvironmentIssue>() {
            environment_issue(format!("{error}: {outcome:?}"))
        } else {
            error
        }
    })
}
fn check_release(acknowledged: bool, absent: bool) -> Result<()> {
    super::super::pf_check::release_result(acknowledged, absent).map_err(|(environment, detail)| {
        if environment {
            environment_issue(detail)
        } else {
            detail.into()
        }
    })
}
fn live_build() -> Result<pftext::Build> {
    pftext::Build::system().map_err(|e| environment_issue(format!("OS build unavailable: {e:?}")))
}
// Save the isolated sole-release evidence before evaluating the verdict.
fn sole_release(out: &Path, p: &mut NativePlatform, token: u64, end: Instant) -> Result<()> {
    let before = refs(p, end)?;
    let response = raw(out, p, &["-X", &token.to_string()], end)?;
    let inventory = raw(out, p, &["-s", "References"], end)?;
    let state = raw(out, p, &["-s", "info"], end)?;
    write_json(
        out,
        &format!("{}.json", super::unique("pf-last-reference")),
        &json!({"response":response,"inventory":inventory,"state":state,"expected_row":"SoleReleased"}),
    )?;
    let after = refs(p, end)?;
    ensure_text(
        before.iter().any(|r| r.token == token),
        "sole release pre-fingerprint missing",
    )?;
    check_release(
        super::super::pf_check::sole_release_text(
            &live_build()?,
            response.exit_code.unwrap_or(-1),
            response.stdout.as_bytes(),
            response.stderr.as_bytes(),
            token,
        ),
        after.is_empty()
            && before
                .iter()
                .filter(|r| r.token == token)
                .all(|r| !after.contains(r)),
    )?;
    info(p, &PfInfo::Disabled, end)
}
// Save every raw capture before evaluating any release verdict.
fn release_probe(out: &Path, p: &mut NativePlatform, end: Instant) -> Result<()> {
    reset(out, p, end)?;
    let first = acquire(p, end)?;
    let second = acquire(p, end)?;
    let before = refs(p, end)?;
    let response = raw(out, p, &["-X", &first.to_string()], end)?;
    // A separate pfctl process acquires between release and post-read.
    let foreign = acquire(p, end)?;
    let inventory = raw(out, p, &["-s", "References"], end)?;
    let after = refs(p, end)?;
    write_json(
        out,
        &format!("{}.json", super::unique("pf-release-post-read")),
        &json!({"response":response,"inventory":inventory,"foreign":foreign,
            "before":before.iter().map(|r|json!({"token":r.token,"pid":r.pid,"timestamp":r.timestamp})).collect::<Vec<_>>(),
            "after":after.iter().map(|r|json!({"token":r.token,"pid":r.pid,"timestamp":r.timestamp})).collect::<Vec<_>>() }),
    )?;
    ensure_text(
        pftext::release(
            &live_build()?,
            response.exit_code.unwrap_or(-1),
            response.stdout.as_bytes(),
            response.stderr.as_bytes(),
            first,
        ) == Ok(Release::Requested),
        "two-reference release text unrecognized",
    )?;
    let owned = before
        .iter()
        .find(|r| r.token == first)
        .ok_or("first fingerprint missing")?;
    let survivor = before
        .iter()
        .find(|r| r.token == second)
        .ok_or("second fingerprint missing")?;
    ensure(
        !after.contains(owned)
            && after.contains(survivor)
            && after.iter().any(|r| r.token == foreign),
        "post-release fingerprint/survivor mismatch",
    )?;
    // Choose an actually absent number, regardless of token recurrence.
    let absent = (1..=u64::MAX)
        .find(|n| !after.iter().any(|r| r.token == *n))
        .ok_or("no absent token")?;
    let response = raw(out, p, &["-X", &absent.to_string()], end)?;
    let _inventory = raw(out, p, &["-s", "References"], end)?;
    let _state = raw(out, p, &["-s", "info"], end)?;
    // No matching pre-call fingerprint exists: the result is Unknown regardless
    // of the captured wording or status, even if it resembles an acknowledgement.
    write_json(
        out,
        &format!("{}.json", super::unique("pf-absent-release")),
        &json!({"response":response,"interpretation":"Unknown: no owned pre-call fingerprint"}),
    )?;
    ensure(refs(p, end)? == after, "absent release changed inventory")?;
    info(p, &PfInfo::Enabled, end)?;
    reset(out, p, end)?;
    let _disabled = raw(out, p, &["-X", &absent.to_string()], end)?;
    let _inventory = raw(out, p, &["-s", "References"], end)?;
    let _state = raw(out, p, &["-s", "info"], end)?;
    let sole = acquire(p, end)?;
    sole_release(out, p, sole, end)
}
fn raw(out: &Path, p: &mut NativePlatform, args: &[&str], end: Instant) -> Result<Evidence> {
    raw_input(out, p, args, &[], end)
}
pub(super) fn raw_input(
    out: &Path,
    p: &mut NativePlatform,
    args: &[&str],
    input: &[u8],
    end: Instant,
) -> Result<Evidence> {
    let build = match live_build() {
        Ok(build) => Some(build),
        Err(error) if args == ["-d"] => {
            // A missing build withholds interpretation, never baseline restoration.
            eprintln!("disable capture OS build unavailable: {error}");
            None
        }
        Err(error) => return Err(error),
    };
    let started = Instant::now();
    let wall = super::super::command::unix_seconds();
    let command_line: Vec<_> = std::iter::once("/sbin/pfctl")
        .chain(args.iter().copied())
        .collect();
    let result = p.run_tool(
        Tool::Pfctl,
        Path::new("/sbin/pfctl"),
        &command_line,
        input,
        1024 * 1024,
        deadline(end)?,
    )?;
    let evidence = Evidence {
        command: command_line.iter().map(|s| (*s).into()).collect(),
        stdin: (!input.is_empty()).then(|| String::from_utf8_lossy(input).into_owned()),
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
        stdout: String::from_utf8_lossy(&result.stdout.bytes).into_owned(),
        stderr: String::from_utf8_lossy(&result.stderr.bytes).into_owned(),
    };
    write_json(
        out,
        &format!("{}.json", super::unique("pf-text")),
        &evidence.pf_text_capture(
            build.as_ref().map_or("unavailable", pftext::Build::as_str),
            &result.stdout.bytes,
            &result.stderr.bytes,
        )?,
    )?;
    if evidence.timed_out {
        return Err(environment_issue(
            "pf case deadline expired: raw pfctl timed out",
        ));
    }
    if evidence.exit_code.is_none()
        || evidence.timed_out
        || evidence.truncated
        || std::str::from_utf8(&result.stdout.bytes).is_err()
        || std::str::from_utf8(&result.stderr.bytes).is_err()
    {
        return Err(environment_issue("raw pfctl incomplete"));
    }
    Ok(evidence)
}
/// Global disable is exclusive to the disposable harness and journaled restore.
fn reset(out: &Path, p: &mut NativePlatform, end: Instant) -> Result<()> {
    if !p.reference_injection_quiescent() {
        return Err(environment_issue(
            "injected writer not quiescent; group restore required before reset",
        ));
    }
    ensure(
        p.reap(deadline(end)?) == Fence::Closed,
        "reset with outstanding pfctl",
    )?;
    let status = p.pf_info(deadline(end)?);
    if matches!(status, PfInfo::Incomplete(_)) {
        eprintln!("reset pf status unknown ({status:?}); attempting baseline disable");
    }
    if status != PfInfo::Disabled {
        let disabled = raw(out, p, &["-d"], end)?;
        if pftext::disable(
            &live_build()?,
            disabled.exit_code.unwrap_or(-1),
            disabled.stdout.as_bytes(),
            disabled.stderr.as_bytes(),
        )
        .is_err()
        {
            return Err(environment_issue(
                "harness disable text unexpected; full capture saved",
            ));
        }
    }
    info(p, &PfInfo::Disabled, end)?;
    ensure(refs(p, end)?.is_empty(), "disable retained tokens")
}
pub(super) fn baseline(out: &Path) -> Result<()> {
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
            && super::super::guard::pf_build(&before.observations).is_some_and(|build| {
                super::super::guard::no_foreign_references(&build, &tokens.stdout, &tokens.stderr)
            }),
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
#[allow(clippy::too_many_lines)] // Keep case ordering, budgets and saved verdicts together.
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
    for (id, minutes, iterations, operation) in match group {
        "pf" => vec![
            (
                "Q-ENABLE",
                4,
                50,
                enable as fn(&Path, &mut NativePlatform, Instant, &mut CaseResult) -> Result<()>,
            ),
            ("Q-EEXIST", 3, 50, eexist),
            ("Q-REFS", 15, 2000, references),
        ],
        "pf-x" => vec![(
            "Q-X",
            2,
            3,
            x as fn(&Path, &mut NativePlatform, Instant, &mut CaseResult) -> Result<()>,
        )],
        "pf-x-stale" => vec![(
            "Q-X-STALE",
            2,
            1,
            x_stale as fn(&Path, &mut NativePlatform, Instant, &mut CaseResult) -> Result<()>,
        )],
        _ => return Err("unknown pf worker group".into()),
    } {
        let mut result = CaseResult {
            elapsed_ms: None,
            case: id.into(),
            binary_sha256: executable_sha256()?,
            verdict: Verdict::AssumptionHolds,
            iterations: 0,
            detail: "Disposable-runner evidence only; no production assumption promotion".into(),
            evidence: vec![],
        };
        p.capture_pf_text(Some(out.into()));
        let started = Instant::now();
        let end = started + Duration::from_secs(minutes * 60);
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
        result.elapsed_ms = Some(started.elapsed().as_millis());
        for failure in p.take_pf_capture_failures() {
            result.detail.push_str("; ");
            result.detail.push_str(&failure);
            if result.verdict == Verdict::AssumptionHolds {
                result.verdict = Verdict::Inconclusive;
            }
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
    let build = live_build()?;
    for iteration in 0..50 {
        reset(out, p, end)?;
        let raw_enable = raw(out, p, &["-e"], end)?;
        if iteration == 0 {
            let _enabled_info = raw(out, p, &["-s", "info"], end)?;
        }
        ensure_text(
            pftext::enable(
                &build,
                raw_enable.exit_code.unwrap_or(-1),
                raw_enable.stdout.as_bytes(),
                raw_enable.stderr.as_bytes(),
                gates(),
            ) == Ok(PfEnable::Started),
            "enable text table mismatch",
        )?;
        if iteration == 0 {
            release_probe(out, p, end)?;
        }
        reset(out, p, end)?;
        enable_expected(p, end, PfEnable::Started)?;
        for _ in 0..5 {
            enable_expected(p, end, PfEnable::AlreadyRunning)?;
            let mut unknown = platform(out, false)?;
            unknown.capture_pf_text(Some(out.into()));
            let (outcome, timed_out) = unknown.enable_pf_observed(deadline(end)?);
            let failures = unknown.take_pf_capture_failures();
            for failure in &failures {
                result.detail.push_str("; ");
                result.detail.push_str(failure);
            }
            ensure_text(failures.is_empty(), &failures.join("; "))?;
            if timed_out || outcome == Err(SysError::TimedOut) {
                return Err(environment_issue(format!(
                    "pf case deadline expired: {outcome:?}"
                )));
            }
            ensure(
                outcome == Err(SysError::Unknown),
                &format!("ungated EEXIST accepted: {outcome:?}"),
            )?;
            match unknown.references(deadline(end)?) {
                Enumeration::Incomplete(SysError::TimedOut) => {
                    return Err(environment_issue(
                        "pf case deadline expired: unqualified references TimedOut",
                    ));
                }
                Enumeration::Incomplete(_) => (),
                Enumeration::Complete(_) => return Err("unknown layout enumerated".into()),
            }
        }
        let raw_eexist = raw(out, p, &["-e"], end)?;
        ensure_text(
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
        let before_release = refs(p, end)?;
        ensure_text(
            before_release.iter().any(|r| r.token == token),
            "raw release pre-fingerprint missing",
        )?;
        let raw_release = raw(out, p, &["-X", &token.to_string()], end)?;
        let _post_text = raw(out, p, &["-s", "References"], end)?;
        let post_release = refs(p, end)?;
        ensure(
            !before_release
                .iter()
                .filter(|r| r.token == token)
                .any(|r| post_release.contains(r)),
            "raw release fingerprint still present",
        )?;
        ensure_text(
            pftext::release(
                &build,
                raw_release.exit_code.unwrap_or(-1),
                raw_release.stdout.as_bytes(),
                raw_release.stderr.as_bytes(),
                token,
            ) == Ok(Release::Requested),
            "-X text table mismatch",
        )?;
        let token = acquire(p, end)?;
        release(p, token, end)?;
        let foreign = acquire(p, end)?;
        ensure_text(
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
        ensure_text(
            process.complete(),
            &format!("new adapter process enable failed; {}", process.stderr),
        )?;
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
        sole_release(out, p, last_token, end)?;
        result.iterations += 1;
    }
    Ok(())
}
fn eexist(out: &Path, p: &mut NativePlatform, end: Instant, result: &mut CaseResult) -> Result<()> {
    for _ in 0..50 {
        reset(out, p, end)?;
        let token = acquire(p, end)?;
        enable_expected(p, end, PfEnable::AlreadyRunning)?;
        let response = raw(out, p, &["-X", &token.to_string()], end)?;
        let _inventory = raw(out, p, &["-s", "References"], end)?;
        let _state = raw(out, p, &["-s", "info"], end)?;
        // Only this post-release state can refute the EEXIST assumption.
        match p.pf_info(deadline(end)?) {
            PfInfo::Enabled => (),
            PfInfo::Disabled => {
                result.verdict = Verdict::AssumptionRefuted;
                return Err("EEXIST did not preserve anonymous enable after token release".into());
            }
            PfInfo::Incomplete(SysError::TimedOut) => {
                return Err(environment_issue(
                    "pf case deadline expired: post-release info TimedOut",
                ));
            }
            PfInfo::Incomplete(e) => {
                return Err(environment_issue(format!(
                    "post-release info incomplete: {e:?}"
                )));
            }
        }
        ensure_text(
            pftext::release(
                &live_build()?,
                response.exit_code.unwrap_or(-1),
                response.stdout.as_bytes(),
                response.stderr.as_bytes(),
                token,
            ) == Ok(Release::Requested),
            "EEXIST release text unrecognized",
        )?;
        ensure(refs(p, end)?.is_empty(), "anonymous reference enumerated")?;
        reset(out, p, end)?;
        let token = acquire(p, end)?;
        sole_release(out, p, token, end)?;
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
    let outcome = references_inner(out, p, end, result);
    let cleanup = reset(out, p, end.max(Instant::now() + Duration::from_secs(8)));
    outcome.and(cleanup)
}
#[allow(clippy::too_many_lines)]
fn references_inner(
    out: &Path,
    p: &mut NativePlatform,
    end: Instant,
    result: &mut CaseResult,
) -> Result<()> {
    release_probe(out, p, end)?;
    reset(out, p, end)?;
    enable_expected(p, end, PfEnable::Started)?;
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
    let held_fingerprints = refs(p, end)?;
    let held_fingerprints: Vec<_> = held
        .iter()
        .map(|token| {
            held_fingerprints
                .iter()
                .find(|r| r.token == *token)
                .cloned()
                .ok_or("held fingerprint absent")
        })
        .collect::<std::result::Result<_, _>>()?;
    deterministic_injections(out, p, end, &held_fingerprints)?;
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
            check_worker_records(out)?;
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    let start = Instant::now();
    let mut complete = 0_u32;
    let mut incomplete = 0_u32;
    let mut subruns = Vec::new();
    for (spare, reads) in [(16, 1000), (0, 500), (1, 500)] {
        p.reference_spare_slots(spare);
        let _ = p.reference_copy_decisions();
        let mut sub_complete = 0_u32;
        let mut sub_incomplete = 0_u32;
        for _ in 0..reads {
            match p.references(deadline(end)?) {
                Enumeration::Complete(lines) => {
                    ensure(
                        held_fingerprints
                            .iter()
                            .all(|fingerprint| lines.contains(fingerprint)),
                        "Complete omitted a long-lived fingerprint (including oldest)",
                    )?;
                    sub_complete += 1;
                }
                Enumeration::Incomplete(SysError::TimedOut) => {
                    return Err(environment_issue(
                        "pf case deadline expired: references TimedOut",
                    ));
                }
                Enumeration::Incomplete(_) => sub_incomplete += 1,
            }
            result.iterations += 1;
        }
        let decisions = p.reference_copy_decisions();
        let retries = decisions
            .iter()
            .filter(|d| **d == pftoken::EnumerationEvent::Copy(Classification::Retry))
            .count();
        let growth_events = decisions
            .iter()
            .filter(|d| **d == pftoken::EnumerationEvent::GrowthPastCopyCapacity)
            .count();
        subruns.push(json!({"spare_slots":spare,"reads":reads,"retry":retries,"growth_past_copy_capacity":growth_events,
            "complete":sub_complete,"incomplete":sub_incomplete}));
        complete += sub_complete;
        incomplete += sub_incomplete;
    }
    p.reference_spare_slots(16);
    for child in &mut workers.0 {
        if child.try_wait()?.is_some() {
            check_worker_records(out)?;
            return Err(environment_issue(
                "churn worker exited before all enumerations finished",
            ));
        }
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
        check_worker_error(&count)?;
        ensure(
            count["iterations"].as_u64().unwrap_or(0) > 0,
            "churn worker made no successful progress",
        )?;
        counts.push(count);
    }
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
    Ok(())
}
// Each callback uses the ordinary native -E adapter and fsyncs its token before
// any subsequent acquisition/read. The r6-pf intent and restore -d cover even a
// crash between the tool returning and its token append.
#[allow(clippy::too_many_lines)] // Keep each hook, saved observation and release scope together.
fn deterministic_injections(
    out: &Path,
    p: &mut NativePlatform,
    end: Instant,
    held: &[RefLine],
) -> Result<()> {
    use std::sync::{Arc, Mutex};
    let mut observations = Vec::new();
    for spare in [0, 1, 16] {
        for k in super::super::pf_check::scenarios(spare) {
            let injected = Arc::new(Mutex::new(Vec::<RefLine>::new()));
            let acquired = injected.clone();
            let hook_error = Arc::new(Mutex::new(None::<String>));
            let failed = hook_error.clone();
            let dir = out.to_path_buf();
            let mut injector = platform(out, true)?;
            injector.capture_pf_text(Some(dir.clone()));
            p.reference_spare_slots(spare);
            let _ = p.reference_copy_decisions();
            p.reference_injection(Box::new(move || {
                let run = || -> Result<()> {
                    for sequence in 0..k {
                        let wall_before = super::super::command::unix_seconds();
                        let outcome = injector.acquire(deadline(end)?);
                        let ToolOutcome::Ok((token, pid)) = outcome else {
                            let prefix = if matches!(outcome, ToolOutcome::NotStarted(SysError::TimedOut) | ToolOutcome::Failed(SysError::TimedOut)) { "pf case deadline expired" } else { "injected -E" };
                            return Err(environment_issue(format!("{prefix}: {outcome:?}")));
                        };
                        let wall_after = super::super::command::unix_seconds();
                        append(&dir, &json!({"kind":"token","token":token,"pid":pid,"sequence":sequence,"spare":spare,"k":k,"wall_before":wall_before,"wall_after":wall_after}))?;
                        let fingerprint = refs(&mut injector, end)?.into_iter()
                            .find(|r| r.token == token && r.pid == pid
                                && r.timestamp >= wall_before.saturating_sub(1)
                                && r.timestamp <= wall_after.saturating_add(1))
                            .ok_or("injected PID/calendar timestamp fingerprint missing")?;
                        acquired.lock().map_err(|_| "injection lock")?.push(fingerprint);
                    }
                    ensure_text(injector.take_pf_capture_failures().is_empty(), "injection capture failed")
                };
                let mut run = run;
                run().map_err(|error| {
                    if let Ok(mut failure) = failed.lock() {
                        *failure = Some(error.to_string());
                    }
                    eprintln!("pf injection failed: {error}");
                    if error.to_string().contains("pf case deadline expired") { SysError::TimedOut }
                    else { SysError::Failed("pf injection environment issue") }
                })
            }));
            let scenario_started = Instant::now();
            super::super::pf_check::injection_scope(
                p,
                |p| {
                    let platform = std::cell::RefCell::new(p);
                    super::super::pf_check::injection_trial(
                        || -> Result<()> {
                            let left = end.saturating_duration_since(Instant::now());
                            let seconds = super::super::pf_check::injection_seconds(left, k)
                                .map_err(environment_issue)?;
                            let read_deadline =
                                Deadline(scupper_darwin::monotonic_raw().as_secs() + seconds);
                            let read = platform.borrow_mut().references(read_deadline);
                            let hook_error =
                                hook_error.lock().map_err(|_| "injection error lock")?;
                            let complete = super::super::pf_check::injection_result(
                                read,
                                hook_error.as_deref(),
                            );
                            let events = platform.borrow_mut().reference_copy_decisions();
                            let injected = injected.lock().map_err(|_| "injection lock")?;
                            let copies: Vec<_> = events.iter().map(|e| match e {
                                pftoken::EnumerationEvent::FirstCopyFailed => json!({"first_copy_failed":true}),
                                pftoken::EnumerationEvent::Copy(c) => json!({"copy":format!("{c:?}")}),
                                pftoken::EnumerationEvent::GrowthPastCopyCapacity => json!({"growth_past_copy_capacity":true}),
                                pftoken::EnumerationEvent::FirstCopy { capacity, records } => json!({"first_capacity":capacity,"records":fingerprints_json(records)}),
                            }).collect();
                            observations.push(json!({"spare":spare,"k":k,"copies":copies,
                                "elapsed_ms":scenario_started.elapsed().as_millis(),"read_budget_seconds":seconds,
                                "injected":fingerprints_json(&injected),
                                "complete":complete.as_ref().ok().map(|lines| fingerprints_json(lines)),
                                "error":complete.as_ref().err()}));
                            write_json(out, "pf-injection.json", &observations)?;
                            let complete = complete.map_err(environment_issue)?;
                            super::super::pf_check::first_copy_result(&events)
                                .map_err(environment_issue)?;
                            super::super::pf_check::check_injection(
                                spare, k, held, &injected, &events, &complete,
                            )
                            .map_err(Into::into)
                        },
                        || -> Result<()> {
                            // Keep acquisition order; kernel token numbers are not ordered.
                            let injected = injected.lock().map_err(|_| "injection lock")?;
                            for fingerprint in injected.iter() {
                                release_owned(
                                    &mut platform.borrow_mut(),
                                    fingerprint.token,
                                    Some(fingerprint),
                                    end,
                                )?;
                                ensure(
                                    !refs(&mut platform.borrow_mut(), end)?.contains(fingerprint),
                                    "injected release fingerprint survived independent read",
                                )?;
                            }
                            Ok(())
                        },
                    )
                },
                NativePlatform::disarm_reference_injection,
            )?;
        }
    }
    p.reference_spare_slots(16);
    Ok(())
}
fn fingerprints_json(lines: &[RefLine]) -> Value {
    json!(
        lines
            .iter()
            .map(|r| json!({"token":r.token,"pid":r.pid,"timestamp":r.timestamp}))
            .collect::<Vec<_>>()
    )
}
fn check_worker_error(count: &Value) -> Result<()> {
    super::super::pf_check::worker_error(count).map_err(|(environment, detail)| {
        if environment {
            environment_issue(detail)
        } else {
            detail.into()
        }
    })
}
fn check_worker_records(out: &Path) -> Result<()> {
    for i in 0..4 {
        let path = out.join(format!("pf-churn-{i}.json"));
        if path.exists() {
            check_worker_error(&read_json(&path)?)?;
        }
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
        p.capture_pf_text(Some(out.into()));
        let (outcome, timed_out) = p.enable_pf_observed(deadline(end)?);
        let failures = p.take_pf_capture_failures();
        super::super::pf_check::enable_result(&outcome, PfEnable::AlreadyRunning, timed_out)
            .map_err(environment_issue)?;
        return ensure_text(
            failures.is_empty(),
            &format!(
                "new-process anonymous enable failed; {}",
                failures.join("; ")
            ),
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
        "error":outcome.as_ref().err().map(ToString::to_string),
        "environment_error":outcome.as_ref().err().is_some_and(|e| e.is::<super::EnvironmentIssue>())}),
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
                enable_expected(p, end, PfEnable::AlreadyRunning)?;
            }
            reset(out, p, end)?;
        } else {
            sole_release(out, p, old, end)?;
        }
        info(p, &PfInfo::Disabled, end)?;
        ensure(
            refs(p, end)?.is_empty(),
            "old references survive disable/last release",
        )?;
        let invalid = raw(out, p, &["-X", &old.to_string()], end)?;
        // R2 measured this response only while pf is disabled. Never promote it
        // to an absence acknowledgement for a numeric release racing a reissued holder.
        ensure(
            invalid.exit_code == Some(1)
                && invalid.stdout.is_empty()
                && pftext::stderr(&live_build()?, invalid.stderr.as_bytes())
                    == b"pfctl: pf not enabled\n",
            "disabled stale -X text differs from R2",
        )?;
        let new = acquire(p, end)?;
        let lines = refs(p, end)?;
        ensure(
            lines.len() == 1 && lines[0].token == new,
            "new acquisition list differs from singleton",
        )?;
        observations.push(json!({"scenario":scenario,"old":old,"new":new,"recurrence":old==new,"invalid":invalid}));
        sole_release(out, p, new, end)?;
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
    sole_release(out, p, stale, end)?;
    enable_expected(p, end, PfEnable::Started)?;
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
