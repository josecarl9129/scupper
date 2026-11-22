//! Q-STORE: native error handling only; no crash/power-loss durability claim.
use super::super::store_check::{Phases, caused_by, valid_race_read};
use super::{
    CaseResult, Result, Verdict, environment_issue, executable_sha256, require_ack, save_case,
    write_json,
};
use crate::{
    native::{NativePlatform, Paths},
    platform::{
        Deadline, Platform, WriteOutcome,
        storage::{Fault, filename},
    },
    snapshot::{self, COPY_BYTES, Copy, CopyClass, CopyRead, Snapshot},
};
use serde_json::{Value, json};
use std::{
    fmt::Write as _,
    fs,
    io::Write,
    os::unix::fs::{DirBuilderExt, FileExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::mpsc,
    task::Poll,
    time::{Duration, Instant},
};

fn ensure(ok: bool, reason: &str) -> Result<()> {
    if ok { Ok(()) } else { Err(reason.into()) }
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
fn tree(out: &Path) -> PathBuf {
    out.join("r5-fixtures")
}
fn deadline(end: u64, seconds: u64) -> Deadline {
    Deadline((scupper_darwin::monotonic_raw().as_secs() + seconds).min(end))
}
fn check_budget(end: u64) -> Result<()> {
    if scupper_darwin::monotonic_raw().as_secs() < end {
        Ok(())
    } else {
        Err(environment_issue("Q-STORE seven-minute budget expired"))
    }
}
fn invoke(out: &Path, name: &str, args: &[&str], end: Instant) -> Result<()> {
    let evidence = super::super::command::gated_command(
        "/usr/bin/hdiutil",
        args,
        end.saturating_duration_since(Instant::now()),
        |pid| {
            let record = scupper_darwin::sysctl_kern_proc_pid(pid)
                .map_err(|e| e.to_string())?
                .ok_or("image writer disappeared before journal")?;
            if u32::try_from(record.pid) != Ok(pid)
                || record.start.0 <= 0
                || !(0..1_000_000).contains(&record.start.1)
            {
                return Err("image writer start identity invalid".into());
            }
            append(out, &json!({"kind":"probe", "pid":pid, "start":format!("{}:{}",record.start.0, record.start.1)})).map_err(|e| e.to_string())
        },
    );
    write_json(out, name, &evidence)?;
    if evidence.complete() {
        Ok(())
    } else {
        Err(environment_issue(
            "APFS image setup failed or exceeded two minutes",
        ))
    }
}
fn setup_inner(out: &Path, case_end: u64) -> Result<Vec<PathBuf>> {
    check_budget(case_end)?;
    let left = Duration::from_secs(case_end).saturating_sub(scupper_darwin::monotonic_raw());
    let end = Instant::now() + left.min(Duration::from_secs(120));
    let root = tree(out);
    ensure(!root.exists(), "R5 fixture already exists")?;
    append(out, &json!({"kind":"r5-tree", "path":root}))?;
    fs::DirBuilder::new().mode(0o700).create(&root)?;
    let mut roots = Vec::new();
    for (label, image_size) in [("unfilled", "256m"), ("full", "4m")] {
        let directory = root.join(label);
        fs::DirBuilder::new().mode(0o700).create(&directory)?;
        let image = directory.join("storage.dmg");
        let mount = directory.join("storage-mount");
        append(out, &json!({"kind":"image", "path":image}))?;
        let image_text = image.to_str().ok_or("image path")?;
        invoke(
            out,
            &format!("store-create-{label}.json"),
            &[
                "create",
                "-size",
                image_size,
                "-fs",
                "APFS",
                "-volname",
                "scupper-store",
                image_text,
            ],
            end,
        )?;
        append(out, &json!({"kind":"mount", "path":mount}))?;
        fs::DirBuilder::new().mode(0o700).create(&mount)?;
        invoke(
            out,
            &format!("store-attach-{label}.json"),
            &[
                "attach",
                "-nobrowse",
                "-owners",
                "on",
                "-mountpoint",
                mount.to_str().ok_or("mount path")?,
                image_text,
            ],
            end,
        )?;
        fs::set_permissions(&mount, fs::Permissions::from_mode(0o700))?;
        roots.push(mount);
    }
    Ok(roots)
}
fn setup(out: &Path, end: u64) -> Result<Vec<PathBuf>> {
    let operation = setup_inner(out, end);
    save_case(out, &CaseResult {
        case: "Q-STORE-SETUP".into(), binary_sha256: executable_sha256()?,
        verdict: if operation.is_ok() { Verdict::Measurement } else { Verdict::Inconclusive },
        iterations: if operation.is_ok() { 2 } else { 0 },
        detail: operation.as_ref().map_or_else(ToString::to_string, |_| "256 MiB unfilled and 4 MiB full APFS images attached within the two-minute setup budget; journaled for 30-second detach then forced retry".into()),
        evidence: Vec::new(),
    })?;
    operation
}

fn class(read: CopyRead) -> &'static str {
    match snapshot::classify_copy(read) {
        CopyClass::V { .. } => "V",
        CopyClass::I { .. } => "I",
        CopyClass::X => "X",
        CopyClass::T => "T",
        CopyClass::M => "M",
        CopyClass::U => "U",
    }
}
fn observe(p: &mut NativePlatform, end: u64, old: &[u8], new: &[u8]) -> Result<Value> {
    let mut classes = Vec::new();
    for copy in [Copy::A, Copy::B] {
        let read = p.read_copy(copy, deadline(end, 5));
        ensure(
            valid_race_read(&read, old, new),
            "racing read classified bytes other than old/new snapshot as valid",
        )?;
        classes.push(class(read));
    }
    Ok(json!(classes))
}
fn settle(p: &mut NativePlatform, outcome: &WriteOutcome, end: u64) -> Result<WriteOutcome> {
    let final_outcome = if *outcome == WriteOutcome::TimedOut {
        p.wait_write(deadline(end, 5))
    } else {
        outcome.clone()
    };
    ensure(
        matches!(
            final_outcome,
            WriteOutcome::Synced | WriteOutcome::Failed(_)
        ),
        "storage write did not settle",
    )?;
    Ok(final_outcome)
}

fn synced(
    p: &mut NativePlatform,
    root: &Path,
    copy: Copy,
    bytes: &[u8; COPY_BYTES],
    create: bool,
    end: u64,
) -> Result<()> {
    let outcome = if create {
        p.create_copy(copy, bytes, deadline(end, 5))
    } else {
        p.write_copy(copy, bytes, deadline(end, 5))
    };
    ensure(
        outcome == WriteOutcome::Synced,
        "ordinary copy operation did not return Synced",
    )?;
    ensure(
        fs::File::open(root.join(filename(copy)))?
            .metadata()?
            .size()
            == COPY_BYTES as u64,
        "Synced copy has wrong fstat size",
    )
}
fn remove(root: &Path, copy: Copy) -> Result<()> {
    match fs::remove_file(root.join(filename(copy))) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}
fn fill(file: &fs::File, offset: &mut u64, end: u64) -> Result<Value> {
    loop {
        check_budget(end)?;
        match file.write_at(&[0x9b; COPY_BYTES], *offset) {
            Ok(COPY_BYTES) => *offset += COPY_BYTES as u64,
            Err(e) if e.raw_os_error() == Some(rustix::io::Errno::NOSPC.raw_os_error()) => {
                return Ok(
                    json!({"definition":"ENOSPC on block write", "errno":e.raw_os_error(), "offset":offset}),
                );
            }
            result => {
                return Err(environment_issue(format!(
                    "full-image block write was neither complete nor ENOSPC: {result:?}"
                )));
            }
        }
    }
}
fn event_log(out: &Path, full: bool) -> Result<fs::File> {
    Ok(fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(out.join(if full {
            "store-full-iterations.jsonl"
        } else {
            "store-unfilled-iterations.jsonl"
        }))?)
}
fn check_create_hook(
    p: &mut NativePlatform,
    root: &Path,
    fault: Fault,
    before_cleanup: Option<&(u64, CopyRead)>,
    new: &[u8; COPY_BYTES],
    end: u64,
) -> Result<()> {
    let size = match fault {
        Fault::Open | Fault::Preallocate => 0,
        Fault::HalfWrite => COPY_BYTES / 2,
        Fault::FileSync | Fault::DirectorySync => COPY_BYTES,
        Fault::None => return Err("unexpected create hook".into()),
    };
    let mut bytes = vec![0; COPY_BYTES];
    bytes[..size].copy_from_slice(&new[..size]);
    let expected = if size < COPY_BYTES {
        CopyRead::Short(bytes)
    } else {
        CopyRead::Bytes(bytes)
    };
    ensure(
        before_cleanup
            .is_some_and(|(actual_size, read)| *actual_size == size as u64 && *read == expected),
        "create hook pre-cleanup size/bytes differ from completed stage",
    )?;
    // Failed creates now unlink their own inode, even after file/directory
    // sync; the externally observable post-state is Missing at every hook.
    ensure(
        p.read_copy(Copy::B, deadline(end, 5)) == CopyRead::Missing,
        "faulted create did not clean up its inode",
    )?;
    ensure(
        !root.join(filename(Copy::B)).try_exists()?,
        "failed create path remains",
    )?;
    Ok(())
}
fn check_overwrite_hook(
    p: &mut NativePlatform,
    fault: Fault,
    old: &[u8; COPY_BYTES],
    new: &[u8; COPY_BYTES],
    end: u64,
) -> Result<()> {
    let mut expected = old.to_vec();
    match fault {
        Fault::Open => {}
        Fault::HalfWrite => {
            expected[..COPY_BYTES / 2].copy_from_slice(&new[..COPY_BYTES / 2]);
        }
        Fault::FileSync => expected.copy_from_slice(&new[..]),
        _ => return Err("unexpected overwrite hook".into()),
    }
    ensure(
        p.read_copy(Copy::A, deadline(end, 5)) == CopyRead::Bytes(expected),
        "overwrite hook post-state differs from completed stage",
    )?;
    Ok(())
}
fn failed_hook_outcome(
    p: &mut NativePlatform,
    outcome: &WriteOutcome,
    end: u64,
) -> Result<WriteOutcome> {
    ensure(
        matches!(outcome, WriteOutcome::Failed(_) | WriteOutcome::TimedOut),
        "faulted operation returned success or did not start",
    )?;
    let final_outcome = settle(p, outcome, end)?;
    ensure(
        matches!(final_outcome, WriteOutcome::Failed(_)),
        "faulted write settled as Synced",
    )?;
    Ok(final_outcome)
}
fn fixtures(root: &Path, old: &[u8; COPY_BYTES], end: u64) -> Result<(NativePlatform, fs::File)> {
    let mut p = NativePlatform::new(Paths::qualification(root.into()))?;
    synced(&mut p, root, Copy::A, old, true, end)?;
    // B stays absent on both images: the race's Busy check never touches B, and
    // the fault loops need B absent. Creating it here would force an unlink on
    // the full image, a namespace change APFS may refuse with ENOSPC.
    let filler = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(root.join("filler"))?;
    Ok((p, filler))
}

/// Obtain a settled read after bounded drainage of abandoned readers.
fn final_race_read(p: &mut NativePlatform, end: u64) -> Result<CopyRead> {
    // A timed-out racing read retains its reader slot until its syscall returns.
    // Drain it before comparing settled bytes; capacity exhaustion is no product failure.
    let drain_end = end.min(scupper_darwin::monotonic_raw().as_secs().saturating_add(5));
    while !p.storage_readers_idle() {
        if scupper_darwin::monotonic_raw().as_secs() >= drain_end {
            return Err(environment_issue(
                "full race final reader capacity unavailable: readers did not drain",
            ));
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    let attempt_deadline = deadline(end, 5);
    let after = p.read_copy(Copy::A, attempt_deadline);
    if after == CopyRead::Unreadable {
        return Err(environment_issue(format!(
            "full race final read unavailable after reader drain: attempt=read_copy(A, {attempt_deadline:?}), result={after:?}"
        )));
    }
    Ok(after)
}

/// One race at the ENOSPC-defined full state, before any destructive fault loop.
fn full_race(
    out: &Path,
    p: &mut NativePlatform,
    old: &[u8; COPY_BYTES],
    new: &[u8; COPY_BYTES],
    end: u64,
    result: &mut CaseResult,
) -> Result<()> {
    check_budget(end)?;
    let started = Instant::now();
    let (tx, rx) = mpsc::channel();
    p.storage_gate(true, rx);
    ensure(
        p.write_copy(Copy::A, new, deadline(end, 1)) == WriteOutcome::TimedOut,
        "full race overwrite did not remain outstanding",
    )?;
    ensure(
        p.create_copy(Copy::B, new, Deadline(0)) == WriteOutcome::Busy,
        "full race outstanding write did not return Busy",
    )?;
    ensure(
        p.wait_write(deadline(end, 1)) == WriteOutcome::TimedOut,
        "full race wait lost the outstanding write",
    )?;
    let mut reads = Vec::new();
    let mut valid_racing = 0_u32;
    let before = p.read_copy(Copy::A, deadline(end, 5));
    ensure(
        before == CopyRead::Bytes(old.to_vec()),
        "gated full race changed A",
    )?;
    reads.push(json!({"class":class(before),"exact":"old"}));
    // Start a reader while the overwrite is outstanding; release both workers
    // together so their real I/O races. The following reads are bounded too.
    let (read_tx, read_rx) = mpsc::channel();
    p.storage_gate(false, read_rx);
    ensure(
        p.poll_copy(Copy::A, deadline(end, 1)) == Poll::Pending,
        "full race reader did not remain outstanding",
    )?;
    tx.send(())?;
    read_tx.send(())?;
    for _ in 0..8 {
        check_budget(end)?;
        let read = p.read_copy(Copy::A, deadline(end, 5));
        ensure(
            valid_race_read(&read, old, new),
            "full race returned a valid third snapshot",
        )?;
        if matches!(
            crate::snapshot::classify_copy(read.clone()),
            crate::snapshot::CopyClass::V { .. }
        ) {
            valid_racing += 1;
        }
        reads.push(json!({"class":class(read.clone()), "exact":if read == CopyRead::Bytes(old.to_vec()) {"old"} else if read == CopyRead::Bytes(new.to_vec()) {"new"} else {"neither"}}));
    }
    let outcome = p.wait_write(deadline(end, 5));
    ensure(
        matches!(outcome, WriteOutcome::Synced | WriteOutcome::Failed(_)),
        "full race overwrite did not settle",
    )?;
    let errno = p.storage_write_errno();
    let enospc = matches!(outcome, WriteOutcome::Failed(_))
        && errno == Some(rustix::io::Errno::NOSPC.raw_os_error());
    let coverage = if enospc { "exercised" } else { "not exercised" };
    write!(result.detail, "; \"enospc_failure_race\":\"{coverage}\"")?;
    if valid_racing == 0 {
        // No racing read classified valid: the old/new-only rule was not exercised.
        write!(
            result.detail,
            "; \"racing_valid_reads\":\"none (coverage gap)\""
        )?;
    }
    ensure(
        p.wait_write(Deadline(0))
            == WriteOutcome::Failed(crate::platform::SysError::Failed("no outstanding write")),
        "full race Busy did not clear after settlement",
    )?;
    let after = final_race_read(p, end)?;
    ensure(
        valid_race_read(&after, old, new),
        "full race settled as a valid third snapshot",
    )?;
    if outcome == WriteOutcome::Synced {
        ensure(
            after == CopyRead::Bytes(new.to_vec()),
            "Synced full race did not leave exact new bytes",
        )?;
    }
    let bytes = match &after {
        CopyRead::Bytes(bytes) | CopyRead::Short(bytes) => Some(bytes),
        _ => None,
    };
    write_json(
        out,
        "store-full-race.json",
        &json!({
            "image_state":"full: ENOSPC on block write; no reclaim",
            "overwrite":format!("{outcome:?}"),"errno":errno,
            "enospc_failure_race":coverage,"elapsed_seconds":started.elapsed().as_secs_f64(),
            "reads":reads,"racing_valid_reads":valid_racing,"post_class":class(after.clone()),"post_bytes":bytes,
            "busy_cleared":true
        }),
    )?;
    ensure(
        p.read_copy(Copy::A, deadline(end, 5)) == after,
        "fault loops did not start with the bytes left by the full race",
    )
}

fn fault_loops(
    out: &Path,
    root: &Path,
    full: bool,
    end: u64,
    result: &mut CaseResult,
    counts: &mut [u32; 2],
    phases: &mut Phases,
) -> Result<()> {
    let label = if full { "full" } else { "unfilled" };
    let old = snapshot::encode(1, &Snapshot::initial(Some(0), None))?;
    let new = snapshot::encode(2, &Snapshot::initial(Some(0), None))?;
    let (mut p, filler) = phase(phases, out, &format!("{label}/fixtures"), |_| {
        fixtures(root, &old, end)
    })?;
    let mut observations = Vec::new();
    let mut offset = 0;
    let mut event_log = event_log(out, full)?;
    if full {
        observations.push(phase(phases, out, "full/fill", |_| {
            fill(&filler, &mut offset, end)
        })?);
        phase(phases, out, "full/race", |_| {
            full_race(out, &mut p, &old, &new, end, result)
        })?;
    }
    phase(phases, out, &format!("{label}/fault_loop"), |_| {
        for fault in [
            Fault::Open,
            Fault::Preallocate,
            Fault::HalfWrite,
            Fault::FileSync,
            Fault::DirectorySync,
        ] {
            for iteration in 0..if full { 50 } else { 100 } {
                check_budget(end)?;
                remove(root, Copy::B)?;
                if full {
                    let _ = fill(&filler, &mut offset, end)?;
                }
                p.storage_fault(fault);
                let outcome = p.create_copy(Copy::B, &new, deadline(end, 5));
                let final_outcome = failed_hook_outcome(&mut p, &outcome, end)?;
                let reached = fault.credit(&final_outcome, &mut result.iterations);
                counts[usize::from(!reached)] += 1;
                let before_cleanup = p.storage_failed_create();
                if !full {
                    ensure(reached, "unfilled create did not reach its selected hook")?;
                    check_create_hook(&mut p, root, fault, before_cleanup.as_ref(), &new, end)?;
                }
                observations.push(json!({"fault":format!("{fault:?}"), "iteration":iteration, "operation":"create", "reached":reached, "credited":reached, "post_state_policy":"failed create inode removed", "before_cleanup":format!("{:?}",before_cleanup.as_ref().map(|(size,read)| (*size,class(read.clone())))), "outcome":format!("{outcome:?}"), "settled":format!("{final_outcome:?}"), "copies":observe(&mut p, end, &old[..], &new[..])?, "detail":"partial bytes may remain; a full image may fail before the selected hook"}));
                if let Some(event) = observations.last() {
                    writeln!(event_log, "{event}")?;
                }
                if matches!(fault, Fault::Open | Fault::HalfWrite | Fault::FileSync) {
                    let reset = if fault == Fault::HalfWrite {
                        &[0xa5; COPY_BYTES]
                    } else {
                        &old
                    };
                    if !full {
                        synced(&mut p, root, Copy::A, reset, false, end)?;
                    }
                    p.storage_fault(fault);
                    let outcome = p.write_copy(Copy::A, &new, deadline(end, 5));
                    let final_outcome = failed_hook_outcome(&mut p, &outcome, end)?;
                    let reached = fault.credit(&final_outcome, &mut result.iterations);
                    counts[usize::from(!reached)] += 1;
                    if !full {
                        ensure(
                            reached,
                            "unfilled overwrite did not reach its selected hook",
                        )?;
                        check_overwrite_hook(&mut p, fault, reset, &new, end)?;
                    }
                    observations.push(json!({"fault":format!("{fault:?}"), "iteration":iteration, "operation":"overwrite", "reached":reached, "credited":reached, "outcome":format!("{outcome:?}"), "settled":format!("{final_outcome:?}"), "copies":observe(&mut p, end, &old[..], &new[..])?, "detail":"partial bytes may remain"}));
                    if let Some(event) = observations.last() {
                        writeln!(event_log, "{event}")?;
                    }
                }
            }
        }
        Ok(())
    })?;
    // Actual full-volume create and overwrite outcomes, without injected errors.
    phase(phases, out, &format!("{label}/ordinary_fullness"), |_| {
        remove(root, Copy::B)?;
        if full {
            let _ = fill(&filler, &mut offset, end)?;
        }
        observations.push(ordinary(&mut p, root, &new, end, full)?);
        Ok(())
    })?;
    phase(phases, out, &format!("{label}/iteration_evidence"), |_| {
        write_json(
            out,
            if full {
                "store-full.json"
            } else {
                "store-unfilled.json"
            },
            &observations,
        )
    })?;
    if !full {
        phase(phases, out, "unfilled/concurrency", |_| {
            concurrency(out, &mut p, root, &old, &new, end)
        })?;
    }
    Ok(())
}

fn ordinary(
    p: &mut NativePlatform,
    root: &Path,
    new: &[u8; COPY_BYTES],
    end: u64,
    full: bool,
) -> Result<Value> {
    let create = p.create_copy(Copy::B, new, deadline(end, 5));
    let final_create = settle(p, &create, end)?;
    if final_create == WriteOutcome::Synced {
        ensure(
            fs::File::open(root.join(filename(Copy::B)))?
                .metadata()?
                .size()
                == COPY_BYTES as u64,
            "Synced create has wrong fstat size",
        )?;
    }
    // ENOSPC on a filler block does not freeze APFS reclamation. A natural
    // create may still succeed, but only through the complete checked protocol.
    let overwrite = p.write_copy(Copy::A, new, deadline(end, 5));
    let final_overwrite = settle(p, &overwrite, end)?;
    if full {
        // Full APFS images may refuse an overwrite as well as a create. Failed
        // remains a recorded error-handling outcome, never evidence of Synced.
        ensure(
            matches!(
                final_overwrite,
                WriteOutcome::Synced | WriteOutcome::Failed(_)
            ),
            "unexpected full-image overwrite outcome",
        )?;
    } else {
        ensure(
            final_create == WriteOutcome::Synced && final_overwrite == WriteOutcome::Synced,
            "ordinary unfilled operation did not return Synced",
        )?;
    }
    if final_overwrite == WriteOutcome::Synced {
        ensure(
            fs::metadata(root.join(filename(Copy::A)))?.size() == COPY_BYTES as u64,
            "Synced overwrite has wrong fstat size",
        )?;
    }
    let directory = fs::OpenOptions::new()
        .read(true)
        .custom_flags(i32::try_from(rustix::fs::OFlags::DIRECTORY.bits())?)
        .open(root)?;
    let sync = scupper_darwin::full_sync(&directory);
    Ok(
        json!({"ordinary_create":format!("{create:?}"), "settled_create":format!("{final_create:?}"), "overwrite":format!("{overwrite:?}"), "settled_overwrite":format!("{final_overwrite:?}"), "full_image_failure_expected":full, "directory_fullfsync_rc":if sync.is_ok() {0} else {-1}, "directory_fullfsync_errno":sync.err().map_or(0, rustix::io::Errno::raw_os_error)}),
    )
}
fn concurrency(
    out: &Path,
    p: &mut NativePlatform,
    root: &Path,
    old: &[u8; COPY_BYTES],
    new: &[u8; COPY_BYTES],
    end: u64,
) -> Result<()> {
    synced(p, root, Copy::A, old, false, end)?;
    synced(p, root, Copy::B, new, false, end)?;
    let (tx, rx) = mpsc::channel();
    p.storage_gate(true, rx);
    let outcome = p.write_copy(Copy::A, new, deadline(end, 1));
    ensure(
        outcome == WriteOutcome::TimedOut,
        "blocked write did not time out",
    )?;
    ensure(
        p.create_copy(Copy::B, old, Deadline(0)) == WriteOutcome::Busy,
        "outstanding write did not return Busy",
    )?;
    ensure(
        p.wait_write(deadline(end, 1)) == WriteOutcome::TimedOut,
        "wait_write lost the blocked operation",
    )?;
    ensure(
        p.read_copy(Copy::A, deadline(end, 5)) == CopyRead::Bytes(old.to_vec()),
        "read did not proceed independently of storage fence",
    )?;
    tx.send(())?;
    let race = observe(p, end, old, new)?;
    ensure(
        p.wait_write(deadline(end, 5)) == WriteOutcome::Synced,
        "wait_write did not consume the same write",
    )?;
    ensure(
        p.write_copy(Copy::A, old, Deadline(0))
            == WriteOutcome::NotStarted(crate::platform::SysError::TimedOut),
        "expired write started",
    )?;
    // Repeated natural races, each starting with an outstanding gated write.
    for iteration in 0..50 {
        check_budget(end)?;
        let (tx, rx) = mpsc::channel();
        p.storage_gate(true, rx);
        let bytes = if iteration % 2 == 0 { old } else { new };
        ensure(
            p.write_copy(Copy::A, bytes, deadline(end, 1)) == WriteOutcome::TimedOut,
            "race write did not remain outstanding",
        )?;
        tx.send(())?;
        let _ = observe(p, end, old, new)?;
        ensure(
            p.wait_write(deadline(end, 5)) == WriteOutcome::Synced,
            "race write failed",
        )?;
    }
    synced(p, root, Copy::A, old, false, end)?;
    let (first_tx, first_rx) = mpsc::channel();
    let (second_tx, second_rx) = mpsc::channel();
    p.storage_gate(false, first_rx);
    ensure(
        p.poll_copy(Copy::A, deadline(end, 1)) == Poll::Pending,
        "first read did not stay pending",
    )?;
    p.abandon_storage_read();
    p.storage_gate(false, second_rx);
    ensure(
        p.poll_copy(Copy::B, deadline(end, 1)) == Poll::Pending,
        "second read did not stay pending",
    )?;
    p.abandon_storage_read();
    ensure(
        p.poll_copy(Copy::A, deadline(end, 5)) == Poll::Ready(CopyRead::Unreadable),
        "third live reader was not Busy",
    )?;
    first_tx.send(())?;
    second_tx.send(())?;
    while !p.storage_readers_idle() {
        check_budget(end)?;
        std::thread::sleep(Duration::from_millis(5));
    }
    ensure(
        p.read_copy(Copy::A, deadline(end, 5)) == CopyRead::Bytes(old.to_vec()),
        "reader capacity was not released",
    )?;
    // Neither abandoned A=old nor B=new can satisfy this third fixture.
    let third = snapshot::encode(3, &Snapshot::initial(Some(0), None))?;
    synced(p, root, Copy::B, &third, false, end)?;
    ensure(
        p.read_copy(Copy::B, deadline(end, 5)) == CopyRead::Bytes(third.to_vec()),
        "abandoned result was reused by the next read",
    )?;
    write_json(
        out,
        "store-unfilled-concurrency.json",
        &json!({"image_state":"unfilled; comprehensive concurrency suite runs only here", "abandon_expected_sequence":3, "racing_classes":race, "races":50, "write_timeout_busy_wait":true, "read_capacity":2, "third_busy":true, "abandon_discard":true}),
    )
}

fn path_checks(out: &Path, mount: &Path, end: u64) -> Result<()> {
    let bytes = snapshot::encode(1, &Snapshot::initial(Some(0), None))?;
    let safe = mount.join("path-checks");
    fs::DirBuilder::new().mode(0o700).create(&safe)?;
    let mut p = NativePlatform::new(Paths::qualification(safe.clone()))?;
    ensure(
        p.read_copy(Copy::A, deadline(end, 5)) == CopyRead::Missing,
        "checked-root absence was not Missing",
    )?;
    ensure(
        matches!(
            p.write_copy(Copy::A, &bytes, deadline(end, 5)),
            WriteOutcome::Failed(_)
        ),
        "overwrite created a missing copy",
    )?;
    ensure(
        !safe.join(filename(Copy::A)).exists(),
        "missing overwrite left a file",
    )?;
    synced(&mut p, &safe, Copy::A, &bytes, true, end)?;
    ensure(
        matches!(
            p.create_copy(Copy::A, &bytes, deadline(end, 5)),
            WriteOutcome::Failed(_)
        ),
        "exclusive create replaced a copy",
    )?;
    ensure(
        p.read_copy(Copy::A, deadline(end, 5)) == CopyRead::Bytes(bytes.to_vec()),
        "EEXIST changed the existing copy",
    )?;
    copy_checks(&mut p, &safe, &bytes, end)?;
    root_checks(&safe, &bytes, end)?;
    write_json(
        out,
        "store-paths.json",
        &json!({"checked_missing":true, "missing_symlink_nonroot_writable_root":true, "writable_ancestor":true, "hard_link_mode_size_symlink_copy":true, "existing_create_unchanged":true}),
    )
}
fn copy_checks(
    p: &mut NativePlatform,
    safe: &Path,
    bytes: &[u8; COPY_BYTES],
    end: u64,
) -> Result<()> {
    use std::os::unix::fs::symlink;
    let alias = safe.join("alias");
    fs::hard_link(safe.join(filename(Copy::A)), &alias)?;
    ensure(
        p.read_copy(Copy::A, deadline(end, 5)) == CopyRead::Unreadable,
        "hard-linked copy returned bytes",
    )?;
    ensure(
        matches!(
            p.write_copy(Copy::A, bytes, deadline(end, 5)),
            WriteOutcome::Failed(_)
        ),
        "hard-linked write was accepted",
    )?;
    fs::remove_file(alias)?;
    for mode in [0o640, 0o666, 0o4600] {
        fs::set_permissions(
            safe.join(filename(Copy::A)),
            fs::Permissions::from_mode(mode),
        )?;
        ensure(
            p.read_copy(Copy::A, deadline(end, 5)) == CopyRead::Unreadable,
            "wrong-mode copy returned bytes",
        )?;
        ensure(
            matches!(
                p.write_copy(Copy::A, bytes, deadline(end, 5)),
                WriteOutcome::Failed(_)
            ),
            "wrong-mode copy write accepted",
        )?;
    }
    fs::set_permissions(
        safe.join(filename(Copy::A)),
        fs::Permissions::from_mode(0o600),
    )?;
    symlink(safe.join(filename(Copy::A)), safe.join(filename(Copy::B)))?;
    ensure(
        p.read_copy(Copy::B, deadline(end, 5)) == CopyRead::Unreadable,
        "symlink copy returned bytes",
    )?;
    ensure(
        matches!(
            p.write_copy(Copy::B, bytes, deadline(end, 5)),
            WriteOutcome::Failed(_)
        ),
        "symlink copy write accepted",
    )?;
    remove(safe, Copy::B)?;
    for length in [0, (COPY_BYTES / 2) as u64, (COPY_BYTES + 1) as u64] {
        let file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(safe.join(filename(Copy::B)))?;
        file.set_len(length)?;
        if length < COPY_BYTES as u64 {
            ensure(
                p.read_copy(Copy::B, deadline(end, 5)) == CopyRead::Short(vec![0; COPY_BYTES]),
                "short stub was not zero-padded",
            )?;
            synced(p, safe, Copy::B, bytes, false, end)?;
            ensure(
                p.read_copy(Copy::B, deadline(end, 5)) == CopyRead::Bytes(bytes.to_vec()),
                "short stub was not repaired",
            )?;
        } else {
            ensure(
                p.read_copy(Copy::B, deadline(end, 5)) == CopyRead::Unreadable,
                "long copy returned bytes",
            )?;
            ensure(
                matches!(
                    p.write_copy(Copy::B, bytes, deadline(end, 5)),
                    WriteOutcome::Failed(_)
                ),
                "long copy write accepted",
            )?;
        }
        remove(safe, Copy::B)?;
    }
    Ok(())
}
fn root_checks(safe: &Path, bytes: &[u8; COPY_BYTES], end: u64) -> Result<()> {
    use std::os::unix::fs::symlink;
    let mut p = NativePlatform::new(Paths::qualification(safe.to_path_buf()))?;
    // Validate the root and its ancestors even when the requested copy is absent.
    let missing = safe.join("missing");
    let link = safe.join("linked-root");
    symlink(safe, &link)?;
    for root in [&missing, &link] {
        let mut bad = NativePlatform::new(Paths::qualification(root.clone()))?;
        ensure(
            bad.read_copy(Copy::B, deadline(end, 5)) == CopyRead::Unreadable,
            "unsafe/missing root proved absence",
        )?;
        ensure(
            matches!(
                bad.create_copy(Copy::B, bytes, deadline(end, 5)),
                WriteOutcome::Failed(_)
            ),
            "unsafe/missing root allowed create",
        )?;
    }
    for mode in [0o720, 0o702] {
        fs::set_permissions(safe, fs::Permissions::from_mode(mode))?;
        ensure(
            p.read_copy(Copy::B, deadline(end, 5)) == CopyRead::Unreadable,
            "writable root proved absence",
        )?;
        ensure(
            matches!(
                p.create_copy(Copy::B, bytes, deadline(end, 5)),
                WriteOutcome::Failed(_)
            ),
            "writable root allowed create",
        )?;
    }
    fs::set_permissions(safe, fs::Permissions::from_mode(0o700))?;
    rustix::fs::chown(safe, Some(rustix::fs::Uid::from_raw(60001)), None)?;
    ensure(
        p.read_copy(Copy::B, deadline(end, 5)) == CopyRead::Unreadable,
        "non-root-owned root proved absence",
    )?;
    ensure(
        matches!(
            p.create_copy(Copy::B, bytes, deadline(end, 5)),
            WriteOutcome::Failed(_)
        ),
        "non-root-owned root allowed create",
    )?;
    rustix::fs::chown(safe, Some(rustix::fs::Uid::ROOT), None)?;
    let child = safe.join("child");
    fs::DirBuilder::new().mode(0o700).create(&child)?;
    let mut nested = NativePlatform::new(Paths::qualification(child))?;
    fs::set_permissions(safe, fs::Permissions::from_mode(0o722))?;
    ensure(
        nested.read_copy(Copy::B, deadline(end, 5)) == CopyRead::Unreadable,
        "writable ancestor proved absence",
    )?;
    ensure(
        matches!(
            nested.create_copy(Copy::B, bytes, deadline(end, 5)),
            WriteOutcome::Failed(_)
        ),
        "writable ancestor allowed create",
    )?;
    fs::set_permissions(safe, fs::Permissions::from_mode(0o700))?;
    ensure(!missing.exists(), "helper created the root")?;
    Ok(())
}

// All evidence paths are host-side. Mounted images contain fixtures only.
fn publish_phase(out: &Path, value: &Value) -> Result<()> {
    let mut value = value.clone();
    super::clean_value(&mut value);
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(out.join("store-phases.jsonl"))?;
    writeln!(file, "{value}")?;
    file.sync_all()?;
    Ok(())
}

fn phase<T>(
    phases: &mut Phases,
    out: &Path,
    name: &str,
    work: impl FnOnce(&mut Phases) -> Result<T>,
) -> Result<T> {
    phases.run(name, |value| publish_phase(out, value), work)
}

fn check_abi(out: &Path, result: &mut CaseResult, end: u64) -> Result<()> {
    check_budget(end)?;
    let probe = super::probe_path()?;
    let evidence = super::invoke(probe.to_str().ok_or("ABI probe path")?, &[]);
    ensure(evidence.complete(), "ABI probe incomplete")?;
    let abi: Value = serde_json::from_str(&evidence.stdout)?;
    result.evidence.push(evidence);
    write_json(out, "store-abi.json", &abi)?;
    ensure(
        abi["F_FULLFSYNC"].as_i64() == Some(i64::from(scupper_darwin::FULLFSYNC_COMMAND)),
        "F_FULLFSYNC command differs from SDK",
    )?;
    ensure(
        abi["fstore_t"]["size"].as_u64() == Some(scupper_darwin::FSTORE_SIZE as u64),
        "fstore_t size mismatch",
    )?;
    for (field, offset) in scupper_darwin::FSTORE_FIELDS {
        ensure(
            abi["fstore_t"]["fields"][field].as_u64() == Some(offset as u64),
            "fstore_t field mismatch",
        )?;
    }
    Ok(())
}

pub(super) fn run(out: &Path) -> Result<()> {
    let end = scupper_darwin::monotonic_raw().as_secs() + 420;
    let mut phases = Phases::default();
    let mut counts = [0u32; 2]; // reached, unreached, including overwrites
    let hash = phase(&mut phases, out, "acknowledgement", |_| {
        require_ack(out)?;
        executable_sha256()
    })?;
    let mut result = CaseResult { case:"Q-STORE".into(), binary_sha256:hash, verdict:Verdict::AssumptionHolds, iterations:0, detail:"Error handling only; partial bytes may remain after every failure. Synced creates and short-copy repairs require checked file and directory F_FULLFSYNC. Crash and power-loss durability are not established.".into(), evidence:Vec::new() };
    let operation = (|| -> Result<()> {
        phase(&mut phases, out, "abi", |_| {
            check_abi(out, &mut result, end)
        })?;
        let roots = phase(&mut phases, out, "setup", |_| setup(out, end))?;
        phase(&mut phases, out, "evidence_location", |_| {
            let evidence = out.canonicalize()?;
            for root in &roots {
                ensure(
                    !evidence.starts_with(root.canonicalize()?)
                        && fs::metadata(out)?.dev() != fs::metadata(root)?.dev(),
                    "harness evidence must be outside both APFS images",
                )?;
            }
            write_json(
                out,
                "store-image-sizes.json",
                &json!({"unfilled_bytes":256 * 1024 * 1024,
                "full_bytes":4 * 1024 * 1024, "evidence_outside_images":true,
                "image_state":"full: ENOSPC on block write; filler retained until detach; no reclaim",
                "full_concurrency":"targeted full/race only; comprehensive suite on unfilled image"}),
            )
        })?;
        phase(&mut phases, out, "path_checks", |_| {
            path_checks(out, &roots[0], end)
        })?;
        for (index, root) in roots.iter().enumerate() {
            phase(
                &mut phases,
                out,
                if index == 0 { "unfilled" } else { "full" },
                |phases| fault_loops(out, root, index == 1, end, &mut result, &mut counts, phases),
            )?;
        }
        phase(&mut phases, out, "minimum_credit", |_| {
            check_budget(end)?;
            ensure(
                result.iterations >= 500,
                "fewer than 500 reached hook iterations",
            )
        })
    })();
    if let Err(error) = &operation {
        result.verdict = if caused_by::<super::EnvironmentIssue>(&**error)
            || caused_by::<std::io::Error>(&**error)
        {
            Verdict::Inconclusive
        } else {
            Verdict::ContractViolation
        };
        result.detail = format!("{error}; {}", result.detail);
    }
    write!(
        result.detail,
        "; hooks reached={}, unreached={}, credited={}",
        counts[0], counts[1], result.iterations
    )?;
    phase(&mut phases, out, "hook_counts_evidence", |phases| {
        write_json(
            out,
            "store-hook-counts.json",
            &json!({"reached":counts[0], "unreached":counts[1],
            "credited":result.iterations, "minimum_reached":500, "budget_seconds":420,
            "setup_budget_seconds":120, "ci_step_seconds":600, "phases":phases.records}),
        )
    })?;
    phase(&mut phases, out, "case_evidence", |_| {
        save_case(out, &result)
    })?;
    phase(&mut phases, out, "verdict_evidence", |_| {
        let mut results = Vec::new();
        if out.join("Q-STORE-SETUP.json").exists() {
            results.push(super::read_json::<CaseResult>(
                &out.join("Q-STORE-SETUP.json"),
            )?);
        }
        results.push(result);
        write_json(out, "verdicts.json", &results)
    })?;
    operation
}

/// Remove only the exact journaled tree, after all fixture images were detached.
pub(super) fn restore_tree(
    out: &Path,
    entries: &[super::super::journal::Entry],
    actions: &mut Vec<String>,
    failures: &mut Vec<String>,
) {
    for entry in entries.iter().filter(|e| e.kind == "r5-tree") {
        if Path::new(&entry.path) != tree(out) {
            failures.push("invalid R5 tree intent".into());
            continue;
        }
        match fs::remove_dir_all(&entry.path) {
            Ok(()) => actions.push("removed R5 files/images/mountpoints after detach".into()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => failures.push(e.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budget_expiry_remains_environment_through_phase_context() {
        let mut phases = Phases::default();
        let error = phases
            .run("unfilled/fault_loop", |_| Ok(()), |_| check_budget(0))
            .err()
            .unwrap_or_else(|| unreachable!());
        assert!(caused_by::<super::super::EnvironmentIssue>(&*error));
        assert!(error.to_string().contains("phase unfilled/fault_loop"));
        assert_eq!(phases.records[0]["outcome"], "error");
    }
}
