//! R4 tool/lock/launchd cell. All fixture paths and jobs have write-ahead intents.
use super::{
    CaseResult, Result, Verdict, command, executable_sha256, fs, invoke, json, protected_path,
    read_json, require_ack, save_case, thread, unique, write_json,
};
use crate::{
    native::{NativePlatform, Paths, TrustedExecutable},
    platform::{
        Deadline, ExeId, Fence, InstanceLockError, KillOutcome, Platform, SpawnAttributes,
        SysError, Tool,
        runtime::{Reap, Records},
    },
    snapshot::StartTime,
};
use scupper_darwin::{FdAction, Spawned, Wait};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    io::Write,
    os::{
        fd::{AsFd, AsRawFd, OwnedFd},
        unix::fs::{
            DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt, symlink,
        },
    },
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

fn deadline(seconds: u64) -> Deadline {
    Deadline(scupper_darwin::monotonic_raw().as_secs() + seconds)
}
fn ensure(ok: bool, detail: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(detail.to_owned().into())
    }
}
fn fixture(out: &Path) -> PathBuf {
    out.join("r4-fixtures")
}
fn helper() -> Result<PathBuf> {
    Ok(std::env::current_exe()?.with_file_name("tool-child"))
}
fn pin(path: &Path) -> Result<TrustedExecutable> {
    protected_path(path, false)?;
    let m = fs::symlink_metadata(path)?;
    Ok(TrustedExecutable {
        path: path.into(),
        exe: ExeId {
            dev: m.dev(),
            ino: m.ino(),
        },
        sha256: Sha256::digest(fs::read(path)?).into(),
    })
}
fn platform(out: &Path, child: &Path) -> Result<NativePlatform> {
    Ok(
        NativePlatform::new(Paths::qualification(fixture(out).join("valid")))?
            .with_pins(vec![pin(child)?], child.into()),
    )
}
fn append(out: &Path, value: &Value) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .open(out.join("resources.jsonl"))?;
    let mut line = serde_json::to_vec(value)?;
    line.push(b'\n');
    file.write_all(&line)?;
    file.sync_all()?;
    Ok(())
}
fn journal_child(out: &Path, pid: u32) -> Result<()> {
    if let Some(p) = scupper_darwin::sysctl_kern_proc_pid(pid)? {
        append(
            out,
            &json!({"kind":"child","pid":pid,"start":format!("{}:{}",p.start.0,p.start.1)}),
        )?;
    }
    Ok(())
}
struct Own(Spawned);
impl Drop for Own {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let end = Instant::now() + Duration::from_secs(2);
        while Instant::now() < end {
            if matches!(self.0.try_reap(), Ok(Wait::Status(_) | Wait::NoChild)) {
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
    }
}
fn null() -> Result<OwnedFd> {
    Ok(scupper_darwin::high_fd(
        fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/null")?
            .into(),
    )?)
}
fn raw_record(out: &Path, args: &[&str]) -> Result<Spawned> {
    let fd = null()?;
    let actions = [0, 1, 2].map(|target| FdAction {
        source: fd.as_fd(),
        target,
    });
    let child = scupper_darwin::spawn(&helper()?, args, &actions)?;
    journal_child(out, child.pid())?;
    Ok(child)
}
fn raw(out: &Path, args: &[&str]) -> Result<Own> {
    raw_record(out, args).map(Own)
}
fn settled(child: &mut Spawned) -> Reap {
    match child.try_reap() {
        Ok(Wait::Status(s)) => Reap::Status(s),
        Ok(Wait::NoChild) => Reap::NoChild,
        _ => Reap::Pending,
    }
}

pub(super) fn run(out: &Path) -> Result<()> {
    require_ack(out)?;
    let abi = invoke(super::probe_path()?.to_str().ok_or("ABI probe path")?, &[]);
    ensure(abi.complete(), "ABI probe incomplete")?;
    let layout: Value = serde_json::from_str(&abi.stdout)?;
    super::compare_process_layout(&layout)?;
    for (field, value) in scupper_darwin::CONTROL_FIELDS {
        let observed = if field == "size" {
            layout["socket_fdinfo"]["size"].as_u64()
        } else if field == "SOCKINFO_KERN_CTL" {
            layout[field].as_u64()
        } else {
            layout["socket_fdinfo"]["fields"][field].as_u64()
        };
        ensure(
            observed == Some(value as u64),
            &format!("socket SDK layout mismatch: {field}"),
        )?;
    }
    write_json(out, "tool-abi.json", &layout)?;
    let tree = fixture(out);
    ensure(!tree.exists(), "R4 fixture already exists")?;
    append(out, &json!({"kind":"r4-tree","path":tree}))?;
    fs::DirBuilder::new().mode(0o700).create(&tree)?;
    fs::DirBuilder::new()
        .mode(0o700)
        .create(tree.join("valid"))?;
    let start = Instant::now();
    let mut results = Vec::new();
    for (id, operation) in [
        ("Q-LOCK", locks as fn(&Path, &mut CaseResult) -> Result<()>),
        ("Q-TOOL", tools),
        ("Q-LAUNCHD", launchd),
    ] {
        let mut result = CaseResult {
            case: id.into(),
            binary_sha256: executable_sha256()?,
            verdict: Verdict::AssumptionHolds,
            iterations: 0,
            detail: "R4 native checks observed; no production assumptions promoted".into(),
            evidence: Vec::new(),
        };
        if let Err(e) = operation(out, &mut result) {
            result.verdict = if e.is::<super::EnvironmentIssue>() {
                Verdict::Inconclusive
            } else {
                Verdict::ContractViolation
            };
            result.detail = e.to_string();
        }
        if start.elapsed() > Duration::from_secs(600) {
            result.verdict = Verdict::ContractViolation;
            result.detail = "tool cell exceeded ten-minute budget".into();
        }
        save_case(out, &result)?;
        results.push(result);
    }
    let failed = results
        .iter()
        .any(|r| r.verdict == Verdict::ContractViolation);
    write_json(out, "verdicts.json", &results)?;
    ensure(!failed, "R4 qualification contract violation")
}
// Model absent installer directories only inside the journaled qualification tree.
// Never create or relax a production ancestor from the helper/qualification code.
fn production_ancestors(out: &Path) -> Result<()> {
    let production = Paths::production();
    let lock = production.lock_path();
    let control = production.control_path();
    let model = fixture(out).join("production-run-model");
    fs::DirBuilder::new().mode(0o755).create(&model)?;
    fs::set_permissions(&model, fs::Permissions::from_mode(0o755))?;
    rustix::fs::chown(
        &model,
        Some(rustix::fs::Uid::ROOT),
        Some(rustix::fs::Gid::ROOT),
    )?;
    let model_meta = fs::symlink_metadata(&model)?;
    let mut measurements = Vec::new();
    let mut would_pass = true;
    for ancestor in lock.parent().ok_or("production parent")?.ancestors() {
        match fs::symlink_metadata(ancestor) {
            Ok(m) => {
                let strict =
                    m.is_dir() && crate::platform::runtime::protected_owner_mode(m.uid(), m.mode());
                would_pass &= strict;
                measurements.push(json!({"path":ancestor,"uid":m.uid(),"gid":m.gid(),"mode":format!("{:04o}",m.mode() & 0o7777),"strict":strict,"exists":true}));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Only the installer-owned scupper/run chain may be modeled.
                let planned =
                    ancestor == production.root() || ancestor == lock.parent().ok_or("parent")?;
                would_pass &= planned;
                measurements.push(json!({"path":ancestor,"exists":false,"uid":null,"gid":null,"mode":null,"installer_model":planned,"model_uid":model_meta.uid(),"model_gid":model_meta.gid(),"model_mode":format!("{:04o}", model_meta.mode() & 0o7777)}));
            }
            Err(e) => return Err(e.into()),
        }
    }
    let observed_lock = NativePlatform::qualification_ancestors(lock);
    let observed_control = NativePlatform::qualification_ancestors(control);
    NativePlatform::qualification_ancestors(&model.join("scupper.lock"))?;
    write_json(
        out,
        "tool-production-ancestors.json",
        &json!({"ancestors":measurements,"lock_check":format!("{observed_lock:?}"),"control_check":format!("{observed_control:?}"),"strict_after_installer_root_wheel_0755":would_pass,"model":model}),
    )?;
    save_case(
        out,
        &CaseResult {
            case: "Q-LOCK-PRODUCTION-ANCESTORS".into(),
            binary_sha256: executable_sha256()?,
            verdict: Verdict::Measurement,
            iterations: u32::try_from(measurements.len())?,
            detail: format!(
                "Every production lock/socket ancestor measured; strict check after installer-owned root:wheel 0755 scupper/run directories: {would_pass}; absent directories modeled only in journaled scratch"
            ),
            evidence: Vec::new(),
        },
    )
}

pub(super) fn mutation_tools(out: &Path) -> Result<()> {
    require_ack(out)?;
    let tree = fixture(out);
    ensure(!tree.exists(), "mutation fixture already exists")?;
    append(out, &json!({"kind":"r4-tree","path":tree}))?;
    fs::DirBuilder::new().mode(0o700).create(&tree)?;
    fs::DirBuilder::new()
        .mode(0o700)
        .create(tree.join("valid"))?;
    let mut result = CaseResult {
        case: "Q-TOOL-MUTATION".into(),
        binary_sha256: executable_sha256()?,
        verdict: Verdict::AssumptionHolds,
        iterations: 0,
        detail: "Native mutation baseline".into(),
        evidence: Vec::new(),
    };
    let outcome = tools(out, &mut result);
    if let Err(ref error) = outcome {
        result.verdict = Verdict::ContractViolation;
        result.detail = error.to_string();
    }
    save_case(out, &result)?;
    outcome
}

fn locks(out: &Path, result: &mut CaseResult) -> Result<()> {
    production_ancestors(out)?;
    let mut p = platform(out, &helper()?)?;
    p.acquire_instance_lock()
        .map_err(|e| format!("first lock: {e:?}"))?;
    let exe = std::env::current_exe()?;
    let second = command(
        exe.to_str().ok_or("harness path")?,
        &[
            "r4-lock",
            "--out",
            out.to_str().ok_or("out path")?,
            "--disposable-runner",
        ],
        None,
        Duration::from_secs(5),
    );
    ensure(
        second.complete(),
        "second process did not observe Contended",
    )?;
    result.evidence.push(second);
    for variant in ["symlink", "mode", "links", "owner", "ancestor"] {
        let root = fixture(out).join(variant);
        fs::DirBuilder::new().mode(0o700).create(&root)?;
        let lock = root.join("instance.lock");
        if variant == "symlink" {
            symlink(fixture(out).join("valid/instance.lock"), &lock)?;
        } else {
            fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&lock)?;
            match variant {
                "mode" => fs::set_permissions(&lock, fs::Permissions::from_mode(0o640))?,
                "links" => fs::hard_link(&lock, root.join("second-link"))?,
                "owner" => rustix::fs::chown(&lock, Some(rustix::fs::Uid::from_raw(1)), None)?,
                "ancestor" => fs::set_permissions(&root, fs::Permissions::from_mode(0o770))?,
                _ => {}
            }
        }
        let mut bad = NativePlatform::new(Paths::qualification(root.clone()))?;
        let expected = match variant {
            "symlink" => "native: lock open",
            "ancestor" => "native: unsafe ancestor",
            _ => "native: lock metadata",
        };
        ensure(
            bad.acquire_instance_lock()
                == Err(InstanceLockError::Failed(SysError::Failed(expected))),
            &format!("lock rejection reason differed for {variant}: expected {expected}"),
        )?;
        // Restore protected traversal for the independent dead-man.
        fs::set_permissions(root, fs::Permissions::from_mode(0o700))?;
        result.iterations += 1;
    }
    // Socket must refuse a file/symlink, preserve it, and replace a root socket.
    let socket = fixture(out).join("valid/control.sock");
    fs::write(&socket, b"keep")?;
    ensure(
        p.create_control_socket().is_err() && fs::read(&socket)? == b"keep",
        "socket replaced a regular file",
    )?;
    fs::remove_file(&socket)?;
    symlink("instance.lock", &socket)?;
    ensure(
        p.create_control_socket().is_err()
            && fs::symlink_metadata(&socket)?.file_type().is_symlink(),
        "socket followed symlink",
    )?;
    fs::remove_file(&socket)?;
    drop(std::os::unix::net::UnixListener::bind(&socket)?);
    p.create_control_socket()?;
    write_json(
        out,
        "tool-lock.json",
        &json!({"contended":true,"rejected":["symlink","mode","links","owner","ancestor"],"socket_checked":true}),
    )?;
    result.iterations += 1;
    Ok(())
}
pub(super) fn lock_contender(out: &Path) -> Result<()> {
    let mut p = platform(out, &helper()?)?;
    ensure(
        matches!(p.acquire_instance_lock(), Err(InstanceLockError::Contended)),
        "expected Contended",
    )
}
fn tools(out: &Path, result: &mut CaseResult) -> Result<()> {
    // Every native runner child belongs to this journaled launchd job. A crash
    // before a per-pid journal write is covered by AbandonProcessGroup=false.
    let (service, record) = launch_job(out, "tools", false)?;
    let observed: CaseResult = serde_json::from_value(record["result"].clone())?;
    result.iterations = observed.iterations;
    result.detail = observed.detail;
    result.evidence = observed.evidence;
    let stop = invoke("/bin/launchctl", &["bootout", &service]);
    ensure(stop.complete(), "tool job bootout failed")?;
    result.evidence.push(stop);
    Ok(())
}
#[allow(clippy::too_many_lines)] // Linear qualification observations retain their evidence ordering.
fn tools_worker(out: &Path, result: &mut CaseResult) -> Result<()> {
    let lock_root = fixture(out).join("tool-lock");
    fs::DirBuilder::new().mode(0o700).create(&lock_root)?;
    let mut lock = NativePlatform::new(Paths::qualification(lock_root))?;
    lock.acquire_instance_lock()
        .map_err(|e| format!("tool parent lock: {e:?}"))?;
    let scratch = fs::File::create(fixture(out).join("non-cloexec"))?;
    let planted = scupper_darwin::qual_inheritable_fd(scratch.as_fd(), 40)?;
    let lock_dup =
        scupper_darwin::qual_inheritable_fd(lock.qualification_lock_fd().ok_or("lock fd")?, 41)?;
    let planted_fds = [planted.as_raw_fd(), lock_dup.as_raw_fd()];
    ensure(
        !rustix::io::fcntl_getfd(&planted)?.contains(rustix::io::FdFlags::CLOEXEC)
            && !rustix::io::fcntl_getfd(&lock_dup)?.contains(rustix::io::FdFlags::CLOEXEC),
        "planted descriptors still have CLOEXEC",
    )?;
    ensure(
        planted_fds[0] != planted_fds[1],
        "planted descriptors collided",
    )?;
    let mut p = platform(out, &helper()?)?;
    let h = helper()?;
    ensure(
        scupper_darwin::qual_sigchld_refusals(&h).is_ok(),
        "SIGCHLD unsafe disposition allowed spawn",
    )?;
    pin_rejections(out, result)?;
    utun_without_crosscheck(out)?;
    let hs = h.to_str().ok_or("helper path")?;
    let signals = fixture(out).join("signals.json");
    let output = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&signals)?;
    let output = scupper_darwin::high_fd(output.into())?;
    let fd = null()?;
    let fds = [
        FdAction {
            source: fd.as_fd(),
            target: 0,
        },
        FdAction {
            source: output.as_fd(),
            target: 1,
        },
        FdAction {
            source: fd.as_fd(),
            target: 2,
        },
    ];
    let mut child = Own(scupper_darwin::spawn_signal_probe(
        &h,
        &[hs, "signals"],
        &fds,
    )?);
    let end = Instant::now() + Duration::from_secs(3);
    let status = loop {
        let status = child.0.try_reap()?;
        if status != Wait::Pending || Instant::now() >= end {
            break status;
        }
        thread::sleep(Duration::from_millis(5));
    };
    ensure(status == Wait::Status(0), "signal probe exit")?;
    let observed: Value = serde_json::from_slice(&fs::read(signals)?)?;
    let signals = observed["signals"]
        .as_array()
        .ok_or("signal observations")?;
    ensure(
        signals.len() == 29
            && signals
                .iter()
                .all(|s| s["blocked"] == 0 && s["default"] == true),
        "signal mask/dispositions not reset for every catchable signal",
    )?;
    let child = raw(out, &[hs, "hold"])?;
    thread::sleep(Duration::from_millis(100));
    let mut fds = scupper_darwin::proc_fds(child.0.pid())?;
    fds.sort_unstable();
    let raw_isolated = fds == [0, 1, 2];
    drop(child);
    let table = p.run_tool(
        Tool::Pfctl,
        &h,
        &[hs, "hold-fds"],
        b"input",
        4096,
        deadline(5),
    )?;
    table.complete()?;
    let tool_fds: Vec<i32> = serde_json::from_slice(&table.stdout.bytes)?;
    let tool_isolated =
        tool_fds == [0, 1, 2] && planted_fds.iter().all(|fd| !tool_fds.contains(fd));
    let spawn = p.spawn(
        scupper_core::mac::TunnelGeneration::new(2)?,
        SpawnAttributes {
            default_signals: true,
            empty_signal_mask: true,
            cloexec_default: true,
            synchronous: true,
        },
        deadline(2),
    );
    ensure(spawn.is_err(), "fixture unexpectedly opened utun")?;
    let child = p
        .spawned_children()
        .last()
        .ok_or("partial child missing")?
        .clone();
    journal_child(out, child.pid)?;
    let mut native_fds = scupper_darwin::proc_fds(child.pid)?;
    native_fds.sort_unstable();
    let native_isolated =
        native_fds == [0, 1, 2] && planted_fds.iter().all(|fd| !native_fds.contains(fd));
    write_json(
        out,
        "tool-fd-isolation.json",
        &json!({"raw":fds,"tool":tool_fds,"native":native_fds,"planted":planted_fds,"raw_isolated":raw_isolated,"tool_isolated":tool_isolated,"native_isolated":native_isolated}),
    )?;
    ensure(
        raw_isolated && tool_isolated && native_isolated,
        "CLOEXEC_DEFAULT assertion: raw/tool/NativePlatform inherited planted fd or lock dup",
    )?;
    p.kill_process(child.pid, child.start_time, deadline(2))?;
    let until = Instant::now() + Duration::from_secs(2);
    while Instant::now() < until && scupper_darwin::sysctl_kern_proc_pid(child.pid)?.is_some() {
        p.reap_children(deadline(1))?;
        thread::sleep(Duration::from_millis(5));
    }
    let invalid = FdAction {
        source: fd.as_fd(),
        target: std::os::fd::AsRawFd::as_raw_fd(&fd),
    };
    ensure(
        scupper_darwin::spawn(&h, &[hs, "hold"], &[invalid]).is_err(),
        "self dup2 accepted",
    )?;
    let source = fixture(out).join("handoff");
    fs::write(&source, b"handoff")?;
    let source = rustix::io::fcntl_dupfd_cloexec(fs::File::open(source)?, 20)?;
    let actions = [FdAction {
        source: source.as_fd(),
        target: 12,
    }];
    let mut handoff = Own(scupper_darwin::spawn(&h, &[hs, "handoff"], &actions)?);
    let end = Instant::now() + Duration::from_secs(3);
    let status = loop {
        let s = handoff.0.try_reap()?;
        if s != Wait::Pending || Instant::now() >= end {
            break s;
        }
        thread::sleep(Duration::from_millis(5));
    };
    ensure(
        status == Wait::Status(0),
        "explicit fd handoff did not deliver live fd 12",
    )?;
    for (path, args, input, cap, complete) in [
        (
            Path::new("/usr/bin/true"),
            vec!["true"],
            Vec::new(),
            1024,
            true,
        ),
        (
            Path::new("/bin/cat"),
            vec!["cat"],
            b"roundtrip".to_vec(),
            1024,
            true,
        ),
        (h.as_path(), vec![hs, "cap"], Vec::new(), 4096, false),
        (
            h.as_path(),
            vec![hs, "late"],
            vec![1; 1024 * 1024],
            1024,
            true,
        ),
    ] {
        let observed = p.run_tool(Tool::Pfctl, path, &args, &input, cap, deadline(8))?;
        ensure(
            observed.complete().is_ok() == complete,
            "runner output completion mismatch",
        )?;
        if path == Path::new("/bin/cat") {
            ensure(
                observed.stdout.bytes == input,
                "cat stdin was not fully written/closed",
            )?;
        }
        if args.contains(&"cap") {
            ensure(
                observed.stdout.truncated && observed.reap.settled(),
                "cap was not observed/reaped",
            )?;
        }
        result.iterations += 1;
    }
    let started = Instant::now();
    let stalled = p.run_tool(
        Tool::Route,
        &h,
        &[hs, "stall"],
        &vec![1; 4 * 1024 * 1024],
        1024,
        deadline(3),
    )?;
    ensure(
        stalled.timed_out
            && stalled.reap == Reap::Status(9)
            && matches!(&stalled.fence_at_kill, Some(Fence::Open(entries)) if entries.iter().any(|e| e.pid == stalled.pid && e.tool == Tool::Route))
            && stalled.kill_reap_ms.is_some_and(|ms| ms <= 2000)
            && started.elapsed() < Duration::from_secs(4),
        "stalled stdin kill/reap budget",
    )?;
    // Actual exact-pid statuses and separate lists, including an open->closed fence.
    let mut records = Records::default();
    let a = raw_record(out, &[hs, "hold"])?;
    let b = raw_record(out, &[hs, "hold"])?;
    records.tools.push((Tool::Pfctl, a));
    records.children.push(b);
    ensure(
        matches!(records.fence(Spawned::pid), Fence::Open(_)),
        "missing open tool fence",
    )?;
    records.children[0].kill()?;
    thread::sleep(Duration::from_millis(50));
    records.reap_children(settled);
    ensure(
        records.children.is_empty() && records.tools.len() == 1,
        "child reap consumed tool status",
    )?;
    let other_child = raw_record(out, &[hs, "exit0"])?;
    let other_pid = other_child.pid();
    records.children.push(other_child);
    let zombie_end = Instant::now() + Duration::from_secs(2);
    while Instant::now() < zombie_end
        && scupper_darwin::sysctl_kern_proc_pid(other_pid)?.is_none_or(|p| p.stat != 5)
    {
        thread::sleep(Duration::from_millis(5));
    }
    ensure(
        scupper_darwin::sysctl_kern_proc_pid(other_pid)?.is_some_and(|p| p.stat == 5),
        "child did not exit before tool-only reap",
    )?;
    records.tools[0].1.kill()?;
    let end = Instant::now() + Duration::from_secs(2);
    while Instant::now() < end && !records.tools.is_empty() {
        records.reap_tools(settled);
        thread::sleep(Duration::from_millis(5));
    }
    ensure(
        records.fence(Spawned::pid) == Fence::Closed && p.fence() == Fence::Closed,
        "tool fence did not close on syscall evidence",
    )?;
    ensure(
        records.children.len() == 1 && records.children[0].try_reap()? == Wait::Status(0),
        "tool reap consumed a foreground child status",
    )?;
    records.reap_children(settled);
    write_json(
        out,
        "tool-observations.json",
        &json!({"fd_table":fds,"signals":observed,"stalled_elapsed_ms":started.elapsed().as_millis(),"stalled_reap":format!("{:?}",stalled.reap),"kill_reap_ms":stalled.kill_reap_ms,"fence_at_kill":format!("{:?}",stalled.fence_at_kill),"planted_fds":planted_fds,"tool_fd_table":tool_fds,"native_fd_table":native_fds,"sigchld_refusals":true,"self_dup_rejected":true,"fd12_live":true}),
    )?;
    result.iterations += 1;
    Ok(())
}

fn utun_without_crosscheck(out: &Path) -> Result<()> {
    let path = helper()?.with_file_name("tool-child-utun");
    let mut p = platform(out, &path)?;
    let outcome = p.spawn(
        scupper_core::mac::TunnelGeneration::new(3)?,
        SpawnAttributes {
            default_signals: true,
            empty_signal_mask: true,
            cloexec_default: true,
            synchronous: true,
        },
        deadline(2),
    );
    let child = p
        .spawned_children()
        .last()
        .ok_or("utun fixture history missing")?
        .clone();
    journal_child(out, child.pid)?;
    // Gather positive control-socket evidence as well: a dead/unstarted fixture
    // must not get credit for refusing an uncorroborated utun.
    let mut names = Vec::new();
    for fd in scupper_darwin::proc_socket_fds(child.pid)? {
        if let Some(control) = scupper_darwin::proc_control(child.pid, fd)?
            && let Some(name) = crate::platform::runtime::utun_name(&control.name, control.unit)
        {
            names.push(name);
        }
    }
    ensure(
        names.len() == 1,
        "utun negative fixture did not expose exactly one live utun",
    )?;
    let socket = Path::new("/var/run/wireguard").join(format!("{}.sock", names[0]));
    ensure(
        fs::symlink_metadata(&socket).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
        "utun negative fixture unexpectedly has corroborating socket",
    )?;
    p.kill_process(child.pid, child.start_time, deadline(2))?;
    let until = Instant::now() + Duration::from_secs(2);
    while Instant::now() < until && scupper_darwin::sysctl_kern_proc_pid(child.pid)?.is_some() {
        p.reap_children(deadline(1))?;
        thread::sleep(Duration::from_millis(5));
    }
    write_json(
        out,
        "tool-utun-crosscheck-negative.json",
        &json!({"pid":child.pid,"names":names,"socket_absent":true,"spawn_refused":outcome.is_err(),"utun_retained":child.utun}),
    )?;
    ensure(
        outcome.is_err() && child.utun.is_empty(),
        "utun cross-check assertion: uncorroborated control-unit name accepted",
    )
}

fn pin_rejections(out: &Path, result: &mut CaseResult) -> Result<()> {
    let directory = fixture(out).join("pin-rejections");
    fs::DirBuilder::new().mode(0o700).create(&directory)?;
    let mut evidence = Vec::new();
    for variant in ["symlink", "mode", "owner", "vnode", "digest"] {
        let path = directory.join(variant);
        fs::copy(helper()?, &path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755))?;
        let mut reviewed = pin(&path)?;
        match variant {
            "symlink" => {
                fs::rename(&path, path.with_extension("real"))?;
                symlink(path.with_extension("real"), &path)?;
            }
            "mode" => fs::set_permissions(&path, fs::Permissions::from_mode(0o775))?,
            "owner" => rustix::fs::chown(&path, Some(rustix::fs::Uid::from_raw(1)), None)?,
            "vnode" => {
                fs::rename(&path, path.with_extension("old"))?;
                fs::copy(helper()?, &path)?;
            }
            "digest" => {
                reviewed.sha256[0] ^= 1;
                ensure(
                    reviewed.sha256 != <[u8; 32]>::from(Sha256::digest(fs::read(&path)?)),
                    "wrong digest equals actual digest",
                )?;
            }
            _ => return Err("unknown pin variant".into()),
        }
        let expected = if variant == "digest" {
            "native: pin digest/identity mismatch"
        } else {
            "native: untrusted pin"
        };
        let mut p = NativePlatform::new(Paths::qualification(directory.clone()))?
            .with_pins(vec![reviewed], path.clone());
        // Use the same pin checker as check_tools, check_pfctl and spawn; no child may launch.
        let observed = p.run_tool(
            Tool::Pfctl,
            &path,
            &["tool-child", "exit0"],
            b"",
            1024,
            deadline(2),
        );
        ensure(
            matches!(observed, Err(SysError::Failed(text)) if text == expected),
            &format!("pin {variant} rejected for wrong reason"),
        )?;
        ensure(
            p.fence() == Fence::Closed && p.spawned_children().is_empty(),
            "rejected pin spawned a process",
        )?;
        evidence.push(json!({"variant":variant,"rejection":expected}));
        result.iterations += 1;
    }
    write_json(out, "tool-pin-rejections.json", &json!(evidence))
}

#[allow(clippy::too_many_lines)] // Each worker preserves spawn, observation and reporting order.
pub(super) fn worker(out: &Path, mode: &str) -> Result<()> {
    let incarnation = NativePlatform::new(Paths::qualification(fixture(out)))?.incarnation();
    let own = scupper_darwin::sysctl_kern_proc_pid(incarnation.pid)?.ok_or("worker absent")?;
    ensure(
        own.ppid == 1 && incarnation.pid == incarnation.pgid,
        "qualification job not parented to launchd/group leader",
    )?;
    journal_child(out, incarnation.pid)?;
    if mode == "tools" {
        let mut result=CaseResult {case:"Q-TOOL".into(),binary_sha256:executable_sha256()?,verdict:Verdict::AssumptionHolds,iterations:0,detail:"signal mask/dispositions, fd table/handoff, lock noninheritance, capped output, stalled-stdin SIGKILL/reap and separate syscall statuses observed".into(),evidence:Vec::new()};
        tools_worker(out, &mut result)?;
        write_json(
            out,
            "tool-worker-tools.json",
            &json!({"pid":incarnation.pid,"pgid":incarnation.pgid,"result":result}),
        )?;
        return Ok(());
    }
    if mode == "exit" {
        return record_exit(out, incarnation.pid);
    }
    if mode == "rosetta" {
        return rosetta_worker(out, incarnation.pid, incarnation.pgid);
    }
    let child_pin = if mode == "real" {
        std::env::current_exe()?.with_file_name("wireguard-go")
    } else {
        helper()?
    };
    let mut p = platform(out, &child_pin)?;
    let expected_image = p.image_uuid(&child_pin, deadline(5))?;
    let expected_exe = p.executable_id(&child_pin, deadline(5))?;
    let outcome = p.spawn(
        scupper_core::mac::TunnelGeneration::new(1)?,
        SpawnAttributes {
            default_signals: true,
            empty_signal_mask: true,
            cloexec_default: true,
            synchronous: true,
        },
        deadline(5),
    );
    if mode == "real" {
        ensure(
            outcome.is_ok(),
            "native wireguard spawn did not return complete child identity",
        )?;
    }
    let child = p
        .spawned_children()
        .last()
        .ok_or("spawn did not retain partial child")?
        .clone();
    journal_child(out, child.pid)?;
    ensure(
        child.image.is_some_and(|i| i.uuid == expected_image) && child.exe == Some(expected_exe),
        "spawn image/exe differed from staged pin",
    )?;
    let mut checks = json!({});
    if mode == "real" {
        let socket = Path::new("/var/run/wireguard").join(format!("{}.sock", child.utun));
        let m = fs::symlink_metadata(&socket)?;
        ensure(
            m.file_type().is_socket() && m.uid() == 0,
            "utun name lacks independent wireguard socket",
        )?;
        checks = json!({"utun_crosscheck_socket":socket,"uid":m.uid(),"socket":true});
    }
    if mode == "process" {
        let wrong = StartTime {
            seconds: child.start_time.seconds + 1,
            microseconds: child.start_time.microseconds,
        };
        let changed = p.kill_process(child.pid, wrong, deadline(2))?;
        ensure(
            changed == KillOutcome::StartChanged
                && scupper_darwin::sysctl_kern_proc_pid(child.pid)?.is_some(),
            "wrong start signalled child",
        )?;
        let signalled = p.kill_process(child.pid, child.start_time, deadline(2))?;
        ensure(
            signalled == KillOutcome::Signalled,
            "kill_process not signalled",
        )?;
        let end = Instant::now() + Duration::from_secs(5);
        while Instant::now() < end && scupper_darwin::sysctl_kern_proc_pid(child.pid)?.is_some() {
            p.reap_children(deadline(1))?;
            thread::sleep(Duration::from_millis(5));
        }
        ensure(
            p.kill_process(child.pid, child.start_time, deadline(2))? == KillOutcome::Gone,
            "kill_process did not become Gone",
        )?;
        checks = json!({"wrong_start":format!("{changed:?}"),"kill":format!("{signalled:?}"),"gone":true});
    }
    write_json(
        out,
        &format!("tool-worker-{mode}.json"),
        &json!({"pid":incarnation.pid,"pgid":incarnation.pgid,"start":[incarnation.start.seconds,incarnation.start.microseconds],"child":child.pid,"child_start":[child.start_time.seconds,child.start_time.microseconds],"image":child.image.map(|i|i.uuid),"expected_image":expected_image,"exe_matches":child.exe==Some(expected_exe),"spawn":format!("{outcome:?}"),"utun":child.utun,"checks":checks}),
    )?;
    // Bounded even if a controller disappears before its journal sync.
    let end = Instant::now() + Duration::from_secs(110);
    while Instant::now() < end {
        thread::sleep(Duration::from_millis(100));
    }
    Ok(())
}
fn rosetta_worker(out: &Path, own_pid: u32, own_group: u32) -> Result<()> {
    let path = helper()?.with_file_name("tool-child-x86_64");
    let mut p = platform(out, &path)?;
    let outcome = p.spawn(
        scupper_core::mac::TunnelGeneration::new(1)?,
        SpawnAttributes {
            default_signals: true,
            empty_signal_mask: true,
            cloexec_default: true,
            synchronous: true,
        },
        deadline(5),
    );
    ensure(
        matches!(
            outcome,
            Err(SysError::Failed("native: translated child refused"))
        ),
        "Rosetta child was not explicitly refused",
    )?;
    let child = p
        .spawned_children()
        .last()
        .ok_or("translated history missing")?
        .clone();
    journal_child(out, child.pid)?;
    ensure(
        child.pid > 1 && child.image.is_some(),
        "translated pid/image history missing before refusal",
    )?;
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(5)
        && scupper_darwin::sysctl_kern_proc_pid(child.pid)?.is_some()
    {
        p.reap_children(deadline(1))?;
        thread::sleep(Duration::from_millis(5));
    }
    ensure(
        scupper_darwin::sysctl_kern_proc_pid(child.pid)?.is_none(),
        "translated child not killed/reaped within five seconds",
    )?;
    write_json(
        out,
        "tool-worker-rosetta.json",
        &json!({"pid":own_pid,"pgid":own_group,"child":child.pid,"image":child.image.map(|i|i.uuid),"refused":true,"gone_ms":started.elapsed().as_millis()}),
    )
}
fn record_exit(out: &Path, pid: u32) -> Result<()> {
    let mut f = fs::OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .open(fixture(out).join("exits.jsonl"))?;
    writeln!(
        f,
        "{}",
        json!({"pid":pid,"at_ms":std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_millis()})
    )?;
    f.sync_all()?;
    Ok(())
}
fn gated_bootstrap(out: &Path, plist: &Path) -> Result<Value> {
    use rustix::pipe::pipe;
    let started = Instant::now();
    let (read, write) = pipe()?;
    let read = rustix::io::fcntl_dupfd_cloexec(read, 20)?;
    let output = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(out.join(format!("{}.log", unique("tool-bootstrap"))))?;
    let output = scupper_darwin::high_fd(output.into())?;
    let stdin = null()?;
    let actions = [
        FdAction {
            source: stdin.as_fd(),
            target: 0,
        },
        FdAction {
            source: output.as_fd(),
            target: 1,
        },
        FdAction {
            source: output.as_fd(),
            target: 2,
        },
        FdAction {
            source: read.as_fd(),
            target: 12,
        },
    ];
    let helper = helper()?;
    let mut child = Own(scupper_darwin::spawn(
        &helper,
        &[
            helper.to_str().ok_or("helper path")?,
            "bootstrap",
            plist.to_str().ok_or("plist path")?,
        ],
        &actions,
    )?);
    drop(read);
    let record = scupper_darwin::sysctl_kern_proc_pid(child.0.pid())?
        .ok_or("gated bootstrap disappeared")?;
    append(
        out,
        &json!({"kind":"probe","pid":child.0.pid(),"start":format!("{}:{}",record.start.0,record.start.1)}),
    )?;
    // The exec gate cannot open before both service intent and PID/start fsync.
    rustix::io::write(&write, b"G")?;
    drop(write);
    let until = Instant::now() + Duration::from_secs(8);
    let status = loop {
        let status = child.0.try_reap()?;
        if status != Wait::Pending || Instant::now() >= until {
            break status;
        }
        thread::sleep(Duration::from_millis(5));
    };
    let value = json!({"pid":child.0.pid(),"status":format!("{status:?}"),"elapsed_ms":started.elapsed().as_millis()});
    ensure(
        status == Wait::Status(0),
        &format!("launchctl bootstrap failed: {value}"),
    )?;
    Ok(value)
}
fn launch_job(out: &Path, mode: &str, keep_alive: bool) -> Result<(String, Value)> {
    let label = format!("net.scupper.qual.r4-{mode}");
    let service = format!("system/{label}");
    append(out, &json!({"kind":"r4-job","path":service}))?;
    let exe = super::xml(std::env::current_exe()?.to_str().ok_or("exe path")?);
    let output = super::xml(out.to_str().ok_or("out path")?);
    let plist = fixture(out).join(format!("{mode}.plist"));
    fs::write(
        &plist,
        format!(
            r#"<?xml version="1.0"?><plist version="1.0"><dict>
<key>Label</key><string>{label}</string><key>ProgramArguments</key><array><string>{exe}</string><string>r4-worker</string><string>--out</string><string>{output}</string><string>--name</string><string>{mode}</string><string>--disposable-runner</string></array>
<key>RunAtLoad</key><true/><key>AbandonProcessGroup</key><false/>
<key>KeepAlive</key><{keep}/><key>ThrottleInterval</key><integer>3</integer>
<key>EnvironmentVariables</key><dict><key>GITHUB_ACTIONS</key><string>true</string><key>RUNNER_ENVIRONMENT</key><string>github-hosted</string></dict>
<key>StandardErrorPath</key><string>{output}/tool-worker-{mode}.stderr.log</string>
</dict></plist>"#,
            keep = if keep_alive { "true" } else { "false" }
        ),
    )?;
    let boot = gated_bootstrap(out, &plist)?;
    write_json(out, &format!("tool-bootstrap-{mode}.json"), &boot)?;
    if mode == "exit" {
        return Ok((service, json!({})));
    }
    let until = Instant::now() + Duration::from_secs(45);
    let record = out.join(format!("tool-worker-{mode}.json"));
    while Instant::now() < until {
        if record.exists() {
            return Ok((service, read_json(&record)?));
        }
        thread::sleep(Duration::from_millis(20));
    }
    Err(format!("launchd {mode} worker did not report; inspect stderr").into())
}
fn group_gone(pgid: u32) -> Result<bool> {
    let group = i32::try_from(pgid)?;
    Ok(!scupper_darwin::sysctl_kern_proc_all()?
        .iter()
        .any(|p| p.pgid == group))
}
#[allow(clippy::too_many_lines)] // Each supervised experiment records before/after group evidence.
fn launchd(out: &Path, result: &mut CaseResult) -> Result<()> {
    for mode in ["bootout", "kill9", "group", "process", "real"] {
        if mode == "real" {
            let directory = Path::new("/private/var/run/wireguard");
            let existed = match fs::symlink_metadata(directory) {
                Ok(m)
                    if m.is_dir()
                        && m.uid() == 0
                        && m.mode() & 0o022 == 0
                        && fs::read_dir(directory)?.next().is_none() =>
                {
                    true
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
                _ => {
                    return Err(super::environment_issue(
                        "wireguard runtime directory must be absent or protected and empty",
                    ));
                }
            };
            append(
                out,
                &json!({"kind":if existed {"r4-wireguard-sockets"} else {"r4-wireguard-created"},"path":directory}),
            )?;
        }
        let (service, record) = launch_job(out, mode, false)?;
        let pid = u32::try_from(record["pid"].as_u64().ok_or("job pid")?)?;
        let child = u32::try_from(record["child"].as_u64().ok_or("job child")?)?;
        let group_id = u32::try_from(record["pgid"].as_u64().ok_or("job group")?)?;
        ensure(pid == group_id, "job did not lead own group")?;
        if mode != "process" {
            ensure(
                scupper_darwin::sysctl_kern_proc_pid(child)?
                    .is_some_and(|p| p.pgid == i32::try_from(group_id).unwrap_or(-1)),
                "long-lived child missing before job termination",
            )?;
        }
        if mode == "real" {
            write_json(out, "tool-wireguard-image.json", &record)?;
        }
        let started = Instant::now();
        if mode == "group" {
            let start = StartTime {
                seconds: record["start"][0].as_u64().ok_or("start")?,
                microseconds: u32::try_from(record["start"][1].as_u64().ok_or("usec")?)?,
            };
            let mut p = platform(out, &helper()?)?;
            let wrong = StartTime {
                seconds: start.seconds + 1,
                ..start
            };
            ensure(
                p.kill_group(group_id, pid, wrong, deadline(2))? == KillOutcome::StartChanged
                    && scupper_darwin::sysctl_kern_proc_pid(child)?.is_some(),
                "wrong group start signalled",
            )?;
            ensure(
                p.kill_group(group_id, pid, start, deadline(2))? == KillOutcome::Signalled,
                "kill_group did not signal",
            )?;
        } else if mode == "kill9" {
            scupper_darwin::qual_signal_kill(i32::try_from(pid)?, false)?;
        } else {
            let stop = invoke("/bin/launchctl", &["bootout", &service]);
            ensure(stop.complete(), "job bootout failed")?;
            result.evidence.push(stop);
        }
        while started.elapsed() < Duration::from_secs(5) && !group_gone(group_id)? {
            thread::sleep(Duration::from_millis(10));
        }
        ensure(
            group_gone(group_id)?,
            "launchd left a group member after five seconds",
        )?;
        write_json(
            out,
            &format!("tool-launchd-{mode}.json"),
            &json!({"record":record,"group_gone_ms":started.elapsed().as_millis()}),
        )?;
        if matches!(mode, "kill9" | "group") {
            let _ = invoke("/bin/launchctl", &["bootout", &service]);
        }
        result.iterations += 1;
    }
    let mut rosetta = CaseResult {
        case: "Q-LAUNCHD-ROSETTA".into(),
        binary_sha256: executable_sha256()?,
        verdict: Verdict::Inconclusive,
        iterations: 0,
        detail: "Rosetta unavailable; native refusal not observed".into(),
        evidence: Vec::new(),
    };
    if cfg!(target_arch = "aarch64") && Path::new("/usr/libexec/rosetta").exists() {
        let (service, record) = launch_job(out, "rosetta", false)?;
        ensure(
            record["refused"] == true && record["gone_ms"].as_u64().is_some_and(|ms| ms < 5000),
            "Rosetta refusal evidence incomplete",
        )?;
        let _ = invoke("/bin/launchctl", &["bootout", &service]);
        rosetta.verdict = Verdict::AssumptionHolds;
        rosetta.iterations = 1;
        rosetta.detail = "x86_64 child explicitly refused, killed before Err, reaped within five seconds with pid/image history".into();
    }
    save_case(out, &rosetta)?;
    let (service, _) = launch_job(out, "exit", true)?;
    let until = Instant::now() + Duration::from_secs(25);
    let mut exits = Vec::<Value>::new();
    while Instant::now() < until {
        if let Ok(text) = fs::read_to_string(fixture(out).join("exits.jsonl")) {
            exits = text
                .lines()
                .map(serde_json::from_str)
                .collect::<std::result::Result<_, _>>()?;
        }
        if exits.len() >= 3 {
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }
    let stop = invoke("/bin/launchctl", &["bootout", &service]);
    ensure(stop.complete(), "Exit0 job bootout")?;
    ensure(
        exits.len() >= 2,
        "KeepAlive measurement did not observe respawn",
    )?;
    let measurement = CaseResult {
        case: "Q-LAUNCHD-THROTTLE".into(),
        binary_sha256: executable_sha256()?,
        verdict: Verdict::Measurement,
        iterations: u32::try_from(exits.len())?,
        detail: format!(
            "KeepAlive Exit0 respawn timestamps (ThrottleInterval=3): {exits:?}; measurement only for 5a3"
        ),
        evidence: vec![stop],
    };
    save_case(out, &measurement)?;
    result.detail="launchd bootout/SIGKILL group disappearance measured; image/exe and guarded kills observed; child-owned utun control socket independently cross-checked against root-owned wireguard socket; non-real fixtures deliberately time out after 5 s without utun and cover retained partial identity; R8 handoff remains provisional; Exit0 throttle is measurement only".into();
    Ok(())
}

// Stop restartable jobs before the global writer census, including after crashes.
pub(super) fn stop_jobs(out: &Path, deadline: Instant) -> Result<()> {
    let mut actions = Vec::new();
    let mut failures = Vec::new();
    let entries = super::resources::entries(out)?;
    restore_jobs(out, &entries, deadline, &mut actions, &mut failures)?;
    ensure(
        failures.is_empty(),
        &format!("R4 job restore: {failures:?}"),
    )
}
fn restore_jobs(
    out: &Path,
    entries: &[super::super::journal::Entry],
    deadline: Instant,
    actions: &mut Vec<String>,
    failures: &mut Vec<String>,
) -> Result<()> {
    for entry in entries.iter().filter(|e| e.kind == "r4-job") {
        if !matches!(
            entry.path.as_str(),
            "system/net.scupper.qual.r4-tools"
                | "system/net.scupper.qual.r4-bootout"
                | "system/net.scupper.qual.r4-kill9"
                | "system/net.scupper.qual.r4-group"
                | "system/net.scupper.qual.r4-process"
                | "system/net.scupper.qual.r4-real"
                | "system/net.scupper.qual.r4-rosetta"
                | "system/net.scupper.qual.r4-exit"
        ) {
            failures.push("unknown R4 job intent".into());
            continue;
        }
        let status = super::invoke_before("/bin/launchctl", &["print", &entry.path], deadline);
        if status.exit_code == Some(113) && !status.timed_out && !status.truncated {
            continue;
        }
        if !status.complete() {
            failures.push("R4 job inventory incomplete".into());
            continue;
        }
        let stop = super::invoke_before("/bin/launchctl", &["bootout", &entry.path], deadline);
        write_json(out, &format!("{}.json", unique("tool-restore-job")), &stop)?;
        if stop.complete() {
            actions.push(format!("bootout {}", entry.path));
        } else {
            failures.push(format!("R4 bootout failed: {}", entry.path));
        }
    }
    Ok(())
}
pub(super) fn restore(
    out: &Path,
    entries: &[super::super::journal::Entry],
    deadline: Instant,
    actions: &mut Vec<String>,
    failures: &mut Vec<String>,
) -> Result<()> {
    restore_jobs(out, entries, deadline, actions, failures)?;
    for entry in entries.iter().filter(|e| {
        matches!(
            e.kind.as_str(),
            "r4-wireguard-sockets" | "r4-wireguard-created"
        )
    }) {
        let directory = Path::new("/private/var/run/wireguard");
        if Path::new(&entry.path) != directory {
            failures.push("invalid R4 wireguard scope".into());
            continue;
        }
        match fs::symlink_metadata(directory) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Ok(m) if m.is_dir() && m.uid() == 0 && m.mode() & 0o022 == 0 => {}
            _ => {
                failures.push("unsafe R4 wireguard runtime directory".into());
                continue;
            }
        }
        for item in fs::read_dir(directory)? {
            let item = item?;
            let meta = fs::symlink_metadata(item.path())?;
            let name = item.file_name();
            let name = name.to_string_lossy();
            let valid = name
                .strip_prefix("utun")
                .and_then(|s| s.strip_suffix(".sock"))
                .is_some_and(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()));
            if valid && meta.file_type().is_socket() && meta.uid() == 0 {
                fs::remove_file(item.path())?;
                actions.push(format!("remove fixture socket {name}"));
            } else {
                failures.push(format!("unexpected R4 wireguard artifact: {name}"));
            }
        }
        if entry.kind == "r4-wireguard-created" && fs::read_dir(directory)?.next().is_none() {
            fs::remove_dir(directory)?;
            actions.push("remove fixture wireguard directory".into());
        }
    }
    for entry in entries.iter().filter(|e| e.kind == "r4-tree") {
        if Path::new(&entry.path) != fixture(out) {
            failures.push("invalid R4 fixture tree intent".into());
            continue;
        }
        match fs::remove_dir_all(&entry.path) {
            Ok(()) => actions.push("removed R4 fixture tree after writers stopped".into()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => failures.push(e.to_string()),
        }
    }
    Ok(())
}
