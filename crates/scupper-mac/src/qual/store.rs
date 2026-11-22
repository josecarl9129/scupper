//! Q-STORE: native error handling only; no crash/power-loss durability claim.
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
    ensure(
        scupper_darwin::monotonic_raw().as_secs() < end,
        "Q-STORE seven-minute budget expired",
    )
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
fn setup_inner(out: &Path) -> Result<Vec<PathBuf>> {
    let end = Instant::now() + Duration::from_secs(120);
    let root = tree(out);
    ensure(!root.exists(), "R5 fixture already exists")?;
    append(out, &json!({"kind":"r5-tree", "path":root}))?;
    fs::DirBuilder::new().mode(0o700).create(&root)?;
    let mut roots = Vec::new();
    for label in ["unfilled", "full"] {
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
                "4m",
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
fn setup(out: &Path) -> Result<Vec<PathBuf>> {
    let operation = setup_inner(out);
    save_case(out, &CaseResult {
        case: "Q-STORE-SETUP".into(), binary_sha256: executable_sha256()?,
        verdict: if operation.is_ok() { Verdict::Measurement } else { Verdict::Inconclusive },
        iterations: if operation.is_ok() { 2 } else { 0 },
        detail: operation.as_ref().map_or_else(ToString::to_string, |_| "Two 4 MiB APFS images attached within the two-minute setup budget; journaled for 30-second detach then forced retry".into()),
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
        if let CopyClass::V { bytes, .. } = snapshot::classify_copy(read.clone()) {
            ensure(
                bytes == old || bytes == new,
                "racing read classified bytes other than old/new snapshot as valid",
            )?;
        }
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
                return Err(format!(
                    "full-image block write was neither complete nor ENOSPC: {result:?}"
                )
                .into());
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
fn fault_loops(
    out: &Path,
    root: &Path,
    full: bool,
    end: u64,
    result: &mut CaseResult,
) -> Result<()> {
    let old = snapshot::encode(1, &Snapshot::initial(Some(0), None))?;
    let new = snapshot::encode(2, &Snapshot::initial(Some(0), None))?;
    let mut p = NativePlatform::new(Paths::qualification(root.into()))?;
    synced(&mut p, root, Copy::A, &old, true, end)?;
    // Keep B's allocation out of the copy namespace during full-volume creates.
    // Renaming it back later permits the same concurrency checks while still full.
    let reserved_b = root.join("reserved-b");
    if full {
        synced(&mut p, root, Copy::B, &new, true, end)?;
        fs::rename(root.join(filename(Copy::B)), &reserved_b)?;
    }
    let filler = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(root.join("filler"))?;
    let mut offset = 0;
    let mut observations = Vec::new();
    let mut event_log = event_log(out, full)?;
    if full {
        observations.push(fill(&filler, &mut offset, end)?);
    }
    for fault in [
        Fault::Open,
        Fault::Preallocate,
        Fault::HalfWrite,
        Fault::FileSync,
        Fault::DirectorySync,
    ] {
        for iteration in 0..50 {
            check_budget(end)?;
            remove(root, Copy::B)?;
            if full {
                let _ = fill(&filler, &mut offset, end)?;
            }
            p.storage_fault(fault);
            let outcome = p.create_copy(Copy::B, &new, deadline(end, 5));
            ensure(
                matches!(outcome, WriteOutcome::Failed(_) | WriteOutcome::TimedOut),
                "faulted create returned success or did not start",
            )?;
            let final_outcome = settle(&mut p, &outcome, end)?;
            ensure(
                matches!(final_outcome, WriteOutcome::Failed(_)),
                "faulted write settled as Synced",
            )?;
            observations.push(json!({"fault":format!("{fault:?}"), "iteration":iteration, "operation":"create", "outcome":format!("{outcome:?}"), "settled":format!("{final_outcome:?}"), "copies":observe(&mut p, end, &old[..], &new[..])?, "detail":"partial bytes may remain; a full image may fail before the selected hook"}));
            if let Some(event) = observations.last() {
                writeln!(event_log, "{event}")?;
            }
            if matches!(fault, Fault::Open | Fault::HalfWrite | Fault::FileSync) {
                p.storage_fault(fault);
                let outcome = p.write_copy(Copy::A, &new, deadline(end, 5));
                ensure(
                    matches!(outcome, WriteOutcome::Failed(_) | WriteOutcome::TimedOut),
                    "faulted overwrite returned success or did not start",
                )?;
                let final_outcome = settle(&mut p, &outcome, end)?;
                ensure(
                    matches!(final_outcome, WriteOutcome::Failed(_)),
                    "faulted write settled as Synced",
                )?;
                observations.push(json!({"fault":format!("{fault:?}"), "iteration":iteration, "operation":"overwrite", "outcome":format!("{outcome:?}"), "settled":format!("{final_outcome:?}"), "copies":observe(&mut p, end, &old[..], &new[..])?, "detail":"partial bytes may remain"}));
                if let Some(event) = observations.last() {
                    writeln!(event_log, "{event}")?;
                }
            }
            result.iterations += 1;
        }
    }
    // Actual full-volume create and overwrite outcomes, without injected errors.
    remove(root, Copy::B)?;
    if full {
        let _ = fill(&filler, &mut offset, end)?;
    }
    observations.push(ordinary(&mut p, root, &new, end)?);
    write_json(
        out,
        if full {
            "store-full.json"
        } else {
            "store-unfilled.json"
        },
        &observations,
    )?;
    if full {
        remove(root, Copy::B)?;
        fs::rename(reserved_b, root.join(filename(Copy::B))).map_err(environment_issue)?;
        let _ = fill(&filler, &mut offset, end)?;
    }
    concurrency(out, &mut p, root, &old, &new, end, full)?;
    Ok(())
}
fn ordinary(
    p: &mut NativePlatform,
    root: &Path,
    new: &[u8; COPY_BYTES],
    end: u64,
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
    synced(p, root, Copy::A, new, false, end)?;
    let directory = fs::OpenOptions::new()
        .read(true)
        .custom_flags(i32::try_from(rustix::fs::OFlags::DIRECTORY.bits())?)
        .open(root)?;
    let sync = scupper_darwin::full_sync(&directory);
    Ok(
        json!({"ordinary_create":format!("{create:?}"), "settled_create":format!("{final_create:?}"), "overwrite":"Synced", "directory_fullfsync_rc":if sync.is_ok() {0} else {-1}, "directory_fullfsync_errno":sync.err().map_or(0, rustix::io::Errno::raw_os_error)}),
    )
}
fn concurrency(
    out: &Path,
    p: &mut NativePlatform,
    root: &Path,
    old: &[u8; COPY_BYTES],
    new: &[u8; COPY_BYTES],
    end: u64,
    full: bool,
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
    synced(p, root, Copy::A, old, false, end)?;
    first_tx.send(())?;
    second_tx.send(())?;
    let mut read = CopyRead::Unreadable;
    for _ in 0..100 {
        read = p.read_copy(Copy::B, deadline(end, 5));
        if read != CopyRead::Unreadable {
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    ensure(
        read == CopyRead::Bytes(new.to_vec()),
        "abandoned result was reused by the next read",
    )?;
    write_json(
        out,
        if full {
            "store-full-concurrency.json"
        } else {
            "store-unfilled-concurrency.json"
        },
        &json!({"racing_classes":race, "races":50, "write_timeout_busy_wait":true, "read_capacity":2, "third_busy":true, "abandon_discard":true}),
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
        ensure(
            p.read_copy(Copy::B, deadline(end, 5)) == CopyRead::Unreadable,
            "wrong-size copy returned bytes",
        )?;
        ensure(
            matches!(
                p.write_copy(Copy::B, bytes, deadline(end, 5)),
                WriteOutcome::Failed(_)
            ),
            "wrong-size copy write accepted",
        )?;
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

pub(super) fn run(out: &Path) -> Result<()> {
    require_ack(out)?;
    let mut result = CaseResult { case:"Q-STORE".into(), binary_sha256:executable_sha256()?, verdict:Verdict::AssumptionHolds, iterations:0, detail:"Error handling only; partial bytes may remain after every failure. Synced creates require checked file and directory F_FULLFSYNC. Crash and power-loss durability are not established.".into(), evidence:Vec::new() };
    let operation = (|| -> Result<()> {
        let probe = super::probe_path()?;
        let evidence = super::invoke(probe.to_str().ok_or("ABI probe path")?, &[]);
        ensure(evidence.complete(), "ABI probe incomplete")?;
        let abi: Value = serde_json::from_str(&evidence.stdout)?;
        result.evidence.push(evidence);
        write_json(out, "store-abi.json", &abi)?;
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
        let roots = setup(out)?;
        let end = scupper_darwin::monotonic_raw().as_secs() + 420;
        path_checks(out, &roots[0], end)?;
        for (index, root) in roots.iter().enumerate() {
            fault_loops(out, root, index == 1, end, &mut result)?;
        }
        Ok(())
    })();
    if let Err(error) = &operation {
        result.verdict = if error.is::<super::EnvironmentIssue>() {
            Verdict::Inconclusive
        } else {
            Verdict::ContractViolation
        };
        result.detail = format!(
            "{error}; error handling only; partial bytes may remain; crash and power-loss durability are not established"
        );
    }
    save_case(out, &result)?;
    let mut results = Vec::new();
    if out.join("Q-STORE-SETUP.json").exists() {
        results.push(super::read_json::<CaseResult>(
            &out.join("Q-STORE-SETUP.json"),
        )?);
    }
    results.push(result);
    write_json(out, "verdicts.json", &results)?;
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
