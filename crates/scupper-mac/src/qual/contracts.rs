//! R7 launchd contract and raw measurement campaign. The qualification anchor is
//! unhooked; its contents supply no blocking, reachability or ordering evidence.
use super::{
    CaseResult, Evidence, Result, Verdict, environment_issue, executable_sha256, invoke_before,
    json, protected_path, require_ack, save_case, write_json,
};
use crate::{
    decode::{
        pfanchor, pftext,
        pftoken::{Assumption, Assumptions},
    },
    engine::Engine,
    native::{NativePlatform, Paths, TrustedExecutable},
    platform::{
        Child, Deadline, Enumeration, ExeId, Fence, Platform, ProcInfo, SpawnAttributes, SysError,
        WriteOutcome,
        tests::{
            ContractHarness, ExeIdentity, Readback, SelectiveInterfaceStates, pretunnel_fixture,
            run_anchor_contracts, run_core_contracts,
        },
    },
    snapshot::{self, Copy, CopyClass, Snapshot},
};
use scupper_core::mac::{TunnelGeneration, policy, verify};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream, UdpSocket},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};

const ANCHOR: &str = "scupper-qual/scupper";
const HOOKED: &str = "com.apple/scupper";
const SENTINEL: &str = "com.apple/scupper-qual";
fn ensure(ok: bool, reason: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(reason.to_owned().into())
    }
}
fn env(ok: bool, reason: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(environment_issue(reason))
    }
}
fn deadline() -> Deadline {
    let seconds = CASE_END.with(|limit| {
        limit.get().map_or(5, |limit| {
            limit
                .saturating_duration_since(Instant::now())
                .as_secs()
                .min(5)
        })
    });
    Deadline(scupper_darwin::monotonic_raw().as_secs() + seconds)
}
thread_local! { static CASE_END: std::cell::Cell<Option<Instant>> = const { std::cell::Cell::new(None) }; }
fn end() -> Instant {
    let end = Instant::now() + Duration::from_secs(8);
    CASE_END.with(|limit| limit.get().map_or(end, |limit| limit.min(end)))
}
fn append(out: &Path, value: &Value) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .open(out.join("resources.jsonl"))?;
    writeln!(file, "{value}")?;
    file.sync_all()?;
    Ok(())
}
fn pin(path: &Path) -> Result<TrustedExecutable> {
    protected_path(path, false)?;
    let meta = fs::symlink_metadata(path)?;
    Ok(TrustedExecutable {
        path: path.into(),
        exe: ExeId {
            dev: meta.dev(),
            ino: meta.ino(),
        },
        sha256: Sha256::digest(fs::read(path)?).into(),
    })
}
fn platform(out: &Path, root: &Path, child: &Path) -> Result<NativePlatform> {
    let mut pins = crate::engine::PINNED_TOOLS
        .iter()
        .map(|p| pin(Path::new(p)))
        .collect::<Result<Vec<_>>>()?;
    pins.push(pin(child)?);
    let mut p =
        NativePlatform::new(Paths::qualification(root.into()))?.with_pins(pins, child.into());
    p.capture_contract_pf_text(out.into());
    // R6 campaign-only assumptions. This grants no R7 text/golden review status.
    p.reference_assumptions(Assumptions {
        pf_token_layout: Assumption::Established,
        eexist_establishes_anonymous: Assumption::Established,
        disable_voids_references: Assumption::Established,
        fingerprints: Assumption::Established,
    });
    Ok(p)
}
fn child_pin() -> Result<PathBuf> {
    Ok(std::env::current_exe()?.with_file_name("wireguard-go"))
}
fn raw(out: &Path, p: &mut NativePlatform, args: &[&str], input: &[u8]) -> Result<Evidence> {
    super::pf::raw_input(out, p, args, input, end())
}
fn scoped(out: &Path, p: &mut NativePlatform, path: &str) -> Result<()> {
    super::resources::recheck_foreign_tokens(out, end())?;
    for class in ["rules", "nat", "Tables", "dummynet"] {
        let e = raw(out, p, &["-a", path, "-F", class], &[])?;
        env(e.complete(), "scoped flush incomplete; inspect raw capture")?;
    }
    Ok(())
}
fn case(out: &Path, id: &str, f: impl FnOnce(&mut CaseResult) -> Result<()>) -> Result<CaseResult> {
    let mut result=CaseResult {case:id.into(),binary_sha256:executable_sha256()?,verdict:Verdict::Inconclusive,iterations:0,elapsed_ms:None,detail:"pass 1: R7 rows and readback goldens are proposed/unreviewed; no qualification promoted".into(),evidence:vec![]};
    let start = Instant::now();
    if id == "Q-ANCHOR" {
        CASE_END.with(|limit| limit.set(Some(start + Duration::from_secs(180))));
    }
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(&mut result))) {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            result.verdict = if error.is::<super::EnvironmentIssue>() {
                Verdict::Inconclusive
            } else {
                Verdict::ContractViolation
            };
            result.detail = error.to_string();
        }
        Err(panic) => {
            result.verdict = Verdict::ContractViolation;
            result.detail = format!(
                "contract_violation: {}",
                panic.downcast_ref::<String>().map_or_else(
                    || panic
                        .downcast_ref::<&str>()
                        .copied()
                        .unwrap_or("contract panic"),
                    String::as_str
                )
            );
        }
    }
    if id == "Q-ANCHOR" {
        CASE_END.with(|limit| limit.set(None));
        if start.elapsed() >= Duration::from_secs(180)
            && result.verdict != Verdict::ContractViolation
        {
            result.verdict = Verdict::Inconclusive;
            result.detail = "Q-ANCHOR stopped at its measured 180-second case budget".into();
        }
    }
    result.elapsed_ms = Some(start.elapsed().as_millis());
    save_case(out, &result)?;
    Ok(result)
}
pub(super) fn run(out: &Path) -> Result<()> {
    require_ack(out)?;
    super::pf::baseline(out)?;
    append(out, &json!({"kind":"r6-pf"}))?;
    append(
        out,
        &json!({"kind":"r4-tree","path":out.join("r4-fixtures")}),
    )?;
    fs::DirBuilder::new()
        .mode(0o700)
        .create(out.join("r4-fixtures"))?;
    let (service, record) = super::tool::launch_job(out, "contracts", false)?;
    let stop = invoke_before("/bin/launchctl", &["bootout", &service], end());
    ensure(stop.complete(), "contracts launchd bootout failed")?;
    super::pf::stop_groups(out, end())?;
    ensure(
        record["finished"] == true && record["failed"] == false,
        "contracts cell failed; inspect case verdicts",
    )
}
pub(super) fn worker(out: &Path) -> Result<()> {
    super::pf::baseline(out)?;
    let own = scupper_darwin::sysctl_kern_proc_pid(std::process::id())?
        .ok_or("contracts worker absent")?;
    ensure(
        own.ppid == 1 && own.pid == own.pgid,
        "contracts require ppid 1 and group leader",
    )?;
    append(
        out,
        &json!({"kind":"r6-group","pid":own.pid,"start":format!("{}:{}",own.start.0,own.start.1)}),
    )?;
    write_json(
        out,
        "contracts-context.json",
        &json!({"pid":own.pid,"pgid":own.pgid,"ppid":own.ppid,"AbandonProcessGroup":false,"anchor":ANCHOR,"unhooked":true,"claim":"load/read/flush/inventory only"}),
    )?;
    let mut results = vec![];
    for (id, operation) in [
        (
            "Q-ANCHOR",
            anchors as fn(&Path, &mut CaseResult) -> Result<()>,
        ),
        ("Q-CONTRACTS", contracts),
        ("Q-E2E", e2e),
        ("Q-FLUSH", flush),
    ] {
        results.push(case(out, id, |r| operation(out, r))?);
        let mut p = platform(out, &out.join("r4-fixtures"), &child_pin()?)?;
        let entries = super::resources::entries(out)?;
        for path in [ANCHOR, HOOKED, SENTINEL] {
            if entries.iter().any(|e| e.kind == "anchor" && e.path == path) {
                // Cleanup authority comes only from the original absence check.
                // Preserve failed cleanup as evidence; independent restore retries.
                let cleanup = scoped(out, &mut p, path);
                write_json(
                    out,
                    &format!("{}.json", super::unique("contracts-between-cases")),
                    &json!({"case":id,"anchor":path,"cleanup":format!("{cleanup:?}"),"absence":format!("{:?}",super::resources::anchor_read(out,path,end()))}),
                )?;
            }
        }
    }
    let failed = results
        .iter()
        .any(|r| r.verdict == Verdict::ContractViolation);
    write_json(out, "verdicts.json", &results)?;
    write_json(
        out,
        "tool-worker-contracts.json",
        &json!({"finished":true,"failed":failed}),
    )
}

struct Harness {
    p: NativePlatform,
    own: PathBuf,
    scratch: PathBuf,
    build: String,
}
impl ContractHarness<NativePlatform> for Harness {
    fn platform(&mut self) -> &mut NativePlatform {
        &mut self.p
    }
    fn enumerated_exe_identity(&self) -> ExeIdentity {
        ExeIdentity::Unavailable
    }
    fn selective_interface_states(&self) -> SelectiveInterfaceStates {
        SelectiveInterfaceStates::Unsupported
    }
    fn readback(&self, intended: &policy::AnchorText, observed: &str) -> Readback {
        super::super::contract_check::readback(&self.build, intended, observed)
    }
    fn own_executable(&self) -> &Path {
        &self.own
    }
    fn scratch_executable(&self) -> &Path {
        &self.scratch
    }
    fn unlink_scratch_executable(&mut self) -> std::result::Result<(), SysError> {
        fs::remove_file(&self.scratch).map_err(|_| SysError::Failed("scratch unlink"))
    }
    fn scratch_child(&mut self) -> std::result::Result<Child, SysError> {
        self.p.spawn(
            TunnelGeneration::new(1).map_err(|_| SysError::Unknown)?,
            SpawnAttributes {
                default_signals: true,
                empty_signal_mask: true,
                cloexec_default: true,
                synchronous: true,
            },
            deadline(),
        )
    }
    fn scratch_process(&mut self) -> std::result::Result<ProcInfo, SysError> {
        let child = self.scratch_child()?;
        match self.p.processes(deadline()) {
            Enumeration::Complete(procs) => procs
                .into_iter()
                .find(|p| p.pid == child.pid)
                .ok_or(SysError::Unknown),
            Enumeration::Incomplete(e) => Err(e.error),
        }
    }
}
fn contracts(out: &Path, r: &mut CaseResult) -> Result<()> {
    super::resources::recheck_foreign_tokens(out, end())?;
    let root = out.join("r4-fixtures/contract-storage");
    fs::DirBuilder::new().mode(0o700).create(&root)?;
    let scratch = root.join("contract-executable");
    fs::copy(child_pin()?, &scratch)?;
    write_json(
        out,
        "contract-copy-identities.json",
        &json!({"source_name":"wireguard-go","source_sha256":format!("{:x}",Sha256::digest(fs::read(child_pin()?)?)),"copy_sha256":format!("{:x}",Sha256::digest(fs::read(&scratch)?))}),
    )?;
    super::tool::prepare_wireguard_directory(out)?;
    let p = platform(out, &root, &scratch)?;
    let mut h = Harness {
        p,
        own: std::env::current_exe()?,
        scratch,
        build: pftext::Build::system()?.as_str().into(),
    };
    let core = case(out, "Q-CONTRACTS-core", |r| {
        run_core_contracts(&mut h)?;
        env(
            !h.p.call_trace()
                .iter()
                .any(|s| s == crate::decode::qualification_trace::OVERFLOW),
            "core contract trace overflow",
        )?;
        r.verdict = Verdict::AssumptionHolds;
        r.detail =
            "storage, reference and process contracts completed independently of anchors".into();
        r.iterations = 1;
        Ok(())
    })?;
    let anchors = case(out, "Q-CONTRACTS-anchor", |r| {
        super::resources::journal_anchor(out, ANCHOR, end())?;
        if let Err(error) = run_anchor_contracts(&mut h) {
            if super::super::contract_check::anchor_error_is_inconclusive(&error) {
                return Err(environment_issue(format!("anchor suite stopped: {error}")));
            }
            return Err(error.into());
        }
        r.verdict = Verdict::AssumptionHolds;
        r.detail = "anchor contracts completed with reviewed independent readback".into();
        r.iterations = 1;
        Ok(())
    })?;
    write_json(
        out,
        "native-contract-trace.json",
        &json!({"trace":h.p.call_trace(),"core":core,"anchors":anchors}),
    )?;
    let failures = h.p.take_pf_capture_failures();
    ensure(
        failures.is_empty(),
        &format!("capture failures: {failures:?}"),
    )?;
    env(
        !h.p.call_trace()
            .iter()
            .any(|s| s == crate::decode::qualification_trace::OVERFLOW),
        "native contracts trace overflow",
    )?;
    ensure(
        core.verdict != Verdict::ContractViolation && anchors.verdict != Verdict::ContractViolation,
        "shared native contract violation; inspect separate core and anchor verdicts",
    )?;
    env(
        core.verdict == Verdict::AssumptionHolds && anchors.verdict == Verdict::AssumptionHolds,
        "shared native suite incomplete; inspect separate verdicts",
    )?;
    r.iterations = 1;
    r.verdict = Verdict::AssumptionHolds;
    r.detail = "shared native contract suite completed with reviewed independent readbacks".into();
    Ok(())
}

fn seed(p: &mut NativePlatform, join: bool) -> Result<()> {
    let mut state = Snapshot::initial(Some(501), p.boot_id());
    state.machine.join_intended = join;
    state.machine.hold = join;
    let bytes = snapshot::encode(1, &state)?;
    for copy in [Copy::A, Copy::B] {
        env(
            p.create_copy(copy, &bytes, deadline()) == WriteOutcome::Synced,
            "Q-E2E stopped at fresh-state storage seed before acquisition",
        )?;
    }
    Ok(())
}
fn engine(out: &Path, name: &str, join: bool) -> Result<Engine<NativePlatform>> {
    let root = out.join("r4-fixtures").join(name);
    fs::DirBuilder::new().mode(0o700).create(&root)?;
    let mut p = platform(out, &root, &child_pin()?)?;
    env(
        p.boot_id().is_some(),
        "Q-E2E stopped at boot identity before acquisition",
    )?;
    seed(&mut p, join)?;
    Engine::start(p)
        .map_err(|e| environment_issue(format!("engine startup refused: {:?}", e.outcome)))
}
fn mutations(trace: &[String]) -> Vec<&str> {
    trace
        .iter()
        .filter_map(|s| s.strip_prefix("pfctl:"))
        .map(|s| s.split(":stdin_sha256=").next().unwrap_or(s))
        .filter(|command| {
            command
                .split_whitespace()
                .any(|arg| matches!(arg, "-e" | "-E" | "-X" | "-f" | "-F" | "-d"))
        })
        .collect()
}
fn snapshot_pair(p: &mut NativePlatform) -> Result<[Snapshot; 2]> {
    let mut snapshots = vec![];
    for copy in [Copy::A, Copy::B] {
        let read = p.read_copy(copy, deadline());
        let CopyClass::V { snapshot, .. } = snapshot::classify_copy(read) else {
            return Err(environment_issue("engine durable copy incomplete"));
        };
        snapshots.push(snapshot);
    }
    snapshots
        .try_into()
        .map_err(|_| "snapshot pair length".into())
}
#[allow(clippy::too_many_lines)] // Preserve the two engine scenarios and their positive/negative evidence in order.
fn e2e(out: &Path, r: &mut CaseResult) -> Result<()> {
    let mut left = engine(out, "engine-left", false)?;
    let start = Instant::now();
    while Instant::now() < start + Duration::from_secs(10) {
        left.run_until_quiescent(1);
        let own = left.platform_mut().incarnation();
        if left.snapshot().helper.as_ref() == Some(&own)
            && left.mode() == crate::engine::Mode::Normal
            && left.is_quiescent()
        {
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    let trace = left.platform().call_trace();
    ensure(mutations(&trace).is_empty(), "Left engine mutated pf")?;
    ensure(!trace.iter().any(|c| c == "spawn"), "Left engine spawned")?;
    let own = left.platform_mut().incarnation();
    let copies = snapshot_pair(left.platform_mut())?;
    let committed = copies.iter().all(|s| s.helper.as_ref() == Some(&own));
    let census = left.platform_mut().processes(deadline());
    let complete = match &census {
        Enumeration::Complete(procs) => !procs.iter().any(|p| {
            p.pid != own.pid
                && (p.pgid == own.pgid
                    || p.path.as_deref() == Some(Path::new(crate::engine::CHILD_PATH))
                    || crate::engine::PINNED_TOOLS
                        .iter()
                        .any(|pin| p.path.as_deref() == Some(Path::new(pin))))
        }),
        Enumeration::Incomplete(_) => false,
    };
    let needs = trace.iter().find_map(|c| {
        c.strip_prefix("failed:")
            .and_then(|s| s.strip_suffix(":native: not implemented"))
    });
    write_json(
        out,
        "e2e-left.json",
        &json!({"trace":trace,"committed_incarnation":committed,"complete_no_owned_survivors":complete,"census":format!("{census:?}"),"audit_methods":crate::platform::tests::LEFT_METHODS,"needs":needs}),
    )?;
    // Always run scenario 2 as well; scenario 1 uncertainty cannot pass it vacuously.
    let left_problem = trace
        .iter()
        .any(|s| s == crate::decode::qualification_trace::OVERFLOW)
        .then(|| "Left trace overflow".to_owned())
        .or_else(|| needs.map(|m| format!("needs {m} (R8–R11)")))
        .or_else(|| (!committed || !complete).then(|| "Left startup/census incomplete".into()));
    drop(left);
    super::resources::journal_anchor(out, ANCHOR, end())
        .map_err(|e| environment_issue(e.to_string()))?;
    let mut join = engine(out, "engine-join", true)?;
    let started = join.platform_mut().now();
    let ticking_started = Instant::now();
    let bounded = ticking_started + Duration::from_secs(110);
    let mut ticks = 0_u64;
    let mut acquisition_step_reached = false;
    while (join.platform_mut().now() < started + 60
        || ticking_started.elapsed() < Duration::from_secs(60))
        && Instant::now() < bounded
    {
        acquisition_step_reached |=
            join.machine().pending() == Some(scupper_core::mac::lifecycle::Step::AcquireReference);
        join.run_until_quiescent(1);
        ensure(
            !matches!(join.status().enforcement, verify::Verdict::Protected(_)),
            "install-failed engine published Protected",
        )?;
        if join.mode() != crate::engine::Mode::Starting {
            ensure(
                join.snapshot().machine.hold,
                "install-failed engine cleared durable hold",
            )?;
        }
        ticks += 1;
        thread::sleep(Duration::from_millis(20));
    }
    let seconds = join.platform_mut().now().saturating_sub(started);
    let trace = join.platform().call_trace();
    write_json(
        out,
        "e2e-join-precheck.json",
        &json!({"trace":trace,"mode":format!("{:?}",join.mode()),"restore_limitation":"-E-to-journal gap relies only on runner exclusivity and restoring the preflight pf state"}),
    )?;
    ensure(!trace.iter().any(|c| c == "spawn"), "Q-E2E spawned")?;
    env(
        !trace
            .iter()
            .any(|s| s == crate::decode::qualification_trace::OVERFLOW),
        "Q-E2E stopped at trace overflow",
    )?;
    ensure(
        super::super::contract_check::join_snapshot_writes_held(&trace),
        "Q-E2E durable write escaped hold before environment classification",
    )?;
    if join.mode() == crate::engine::Mode::Starting {
        return Err(environment_issue(
            "startup ownership/census incomplete; input-free Lockdown decision not established",
        ));
    }
    env(
        !trace.iter().any(|s| s.starts_with("failed:processes:")),
        "Q-E2E stopped at incomplete process census",
    )?;

    let first_stub = trace.iter().find(|c| c.starts_with("failed:"));
    let first = trace
        .iter()
        .find(|c| c.starts_with("failed:") || (c.starts_with("anchor:") && c.contains(":Err(")));
    ensure(
        !trace.iter().any(|c| c == "spawn"),
        "install-failed engine spawned",
    )?;
    let lockdown_load = format!("/sbin/pfctl -a {ANCHOR} -f -");
    for command in mutations(&trace) {
        ensure(
            command == lockdown_load
                || command.starts_with("/sbin/pfctl -X ")
                || matches!(
                    command,
                    "/sbin/pfctl -F states" | "/sbin/pfctl -e" | "/sbin/pfctl -E"
                ),
            "install-failed engine used an unexpected pf mutation",
        )?;
    }
    let load_prefix = format!("pfctl:{lockdown_load}:stdin_sha256=");
    let expected_load = format!(
        "{load_prefix}{:x}",
        Sha256::digest(policy::render_lockdown().as_str().as_bytes())
    );
    ensure(
        trace
            .iter()
            .filter(|s| s.starts_with(&load_prefix))
            .all(|s| *s == expected_load),
        "install-failed engine loaded a policy other than input-free Lockdown",
    )?;
    let copies = snapshot_pair(join.platform_mut())?;
    let durable_held = copies
        .iter()
        .all(|s| s.machine.hold && s.machine.previous_generation.is_none());
    let acquisition_audit = crate::decode::qualification_trace::acquisitions(&trace, &copies);
    let worker_context: Value = super::read_json(&out.join("contracts-context.json"))?;
    let every_write_held = super::super::contract_check::join_snapshot_writes_held(&trace);
    let load = trace
        .iter()
        .filter(|c| c.starts_with("anchor:Load:"))
        .collect::<Vec<_>>();
    let read = trace
        .iter()
        .filter(|c| c.starts_with("anchor:Inventory:") || c.starts_with("anchor:Filter:"))
        .collect::<Vec<_>>();
    write_json(
        out,
        "e2e-join.json",
        &json!({"trace":trace,"ticks":ticks,"engine_seconds":seconds,"selected_policy":format!("{:?}",join.machine().pre_tunnel_policy()),"install_failure":"install record: no writer before 5a3","first_failure":first,"first_stub_failure":first_stub,"wall_tick_ms":ticking_started.elapsed().as_millis(),"load_outcomes":load,"readback_outcomes":read,"snapshot_pair":copies,"durable_held":durable_held,"every_write_held":every_write_held,"status":format!("{:?}",join.status()),"ppid":worker_context["ppid"],"group_leader":worker_context["pid"] == worker_context["pgid"],"acquisition_audit":acquisition_audit,"acquisition_step_reached":acquisition_step_reached,"restore_limitation":"returned -E tokens journaled; pre-return/journal gap covered only by runner exclusivity and restoration of preflight pf state"}),
    )?;
    let capture_failures = join.platform_mut().take_pf_capture_failures();
    ensure(
        capture_failures.is_empty(),
        &format!("Q-E2E capture/journal failures: {capture_failures:?}"),
    )?;
    let acquisitions =
        acquisition_audit.map_err(|e| format!("reference acquisition contract: {e}"))?;
    acquisition_step_reached |= trace.iter().any(|c| c == "acquire");
    if acquisition_step_reached {
        ensure(
            acquisitions > 0,
            "fresh-state acquisition step reached without reserved counted -E",
        )?;
    }
    env(
        acquisitions > 0,
        &format!(
            "Q-E2E stopped before acquisition at {first:?}; fresh-state counted acquisition not observed"
        ),
    )?;
    ensure(
        durable_held && every_write_held,
        "durable snapshot escaped install-failure hold",
    )?;
    ensure(
        join.machine().pre_tunnel_policy() == policy::Kind::Lockdown,
        "install failure did not select input-free Lockdown",
    )?;
    env(
        seconds >= 60 && ticks > 0 && ticking_started.elapsed() >= Duration::from_secs(60),
        "engine did not complete sixty seconds of ticks",
    )?;
    env(
        !load.is_empty() && !read.is_empty(),
        "Lockdown load/readback not both reached; unreviewed rows or later native stubs prevent complete Q-E2E",
    )?;
    r.iterations = 1;
    env(
        first == first_stub,
        "the startup D-3 containment load failed on proposed/unpinned text before install refusal; exact first-failure condition unqualified (contract requires early containment)",
    )?;
    ensure(
        first_stub.is_some_and(|c| {
            c == "failed:poll_install_record:install record: no writer before 5a3"
                || c == "failed:read_install_record:install record: no writer before 5a3"
        }),
        "an earlier stub failure replaced the expected install refusal",
    )?;
    if left_problem.is_none() && pfanchor::reviewed(&pftext::Build::system()?) {
        r.verdict = Verdict::AssumptionHolds;
    }
    r.detail = format!(
        "Left: {}; Join: install refusal and input-free Lockdown positively observed for {seconds}s; reserved counted acquisition audited; no spawn/Protected; proposed load/read outcomes retained. Unhooked path supplies no blocking claim.",
        left_problem
            .unwrap_or_else(|| "committed, zero pf mutations/spawn, complete owned absence".into())
    );
    Ok(())
}

fn inventory(out: &Path, p: &mut NativePlatform, path: &str) -> Result<Value> {
    let parent = path.split_once('/').ok_or("anchor parent")?.0;
    let mut reads = vec![];
    for args in [
        vec!["-a", parent, "-sA"],
        vec!["-sA"],
        vec!["-a", path, "-sr"],
        vec!["-a", path, "-sn"],
        vec!["-a", path, "-sT"],
        vec!["-a", path, "-sA"],
        vec!["-a", path, "-sd"],
    ] {
        reads.push(raw(out, p, &args, &[])?);
    }
    Ok(serde_json::to_value(reads)?)
}
fn measure_remove(out: &Path, p: &mut NativePlatform, path: &str) -> Result<Value> {
    // Pass 1 adapter removal refuses unreviewed rows. The harness separately
    // measures exactly the adapter's four scoped flushes, never substitutes
    // that measurement for an adapter success.
    if path != ANCHOR {
        scoped(out, p, path)?;
        let absence = super::resources::anchor_read(out, path, end());
        return Ok(
            json!({"absence":format!("{absence:?}"),"gone":absence.is_ok_and(|a|a.is_none()),"inventory":inventory(out,p,path)?}),
        );
    }
    let adapter = p.remove_anchor(deadline());
    scoped(out, p, path)?;
    let absence = super::resources::anchor_read(out, path, end());
    Ok(
        json!({"adapter_ok":adapter.is_ok(),"adapter_result":format!("{adapter:?}"),"absence":format!("{absence:?}"),"gone":absence.is_ok_and(|a|a.is_none()),"inventory":inventory(out,p,path)?}),
    )
}
#[allow(clippy::too_many_lines)] // Keep both lifecycle conditions, their counters and qualification gates together.
fn anchors(out: &Path, r: &mut CaseResult) -> Result<()> {
    let mut p = platform(out, &out.join("r4-fixtures"), &child_pin()?)?;
    // Capture dummynet even if the later absence/journal step stops pass 1.
    for path in [ANCHOR, HOOKED] {
        let dummynet = raw(out, &mut p, &["-a", path, "-sd"], &[])?;
        write_json(
            out,
            &format!("{}.json", super::unique("anchor-dummynet-prejournal")),
            &json!({"anchor":path,"proposed_unreviewed":true,"evidence":dummynet}),
        )?;
    }
    let missing_parent = vec![
        raw(out, &mut p, &["-a", "scupper-qual", "-sA"], &[])?,
        raw(out, &mut p, &["-sA"], &[])?,
    ];
    write_json(
        out,
        "anchor-missing-parent.json",
        &json!({"proposed_unreviewed":true,"evidence":missing_parent}),
    )?;
    super::resources::journal_anchor(out, ANCHOR, end())
        .map_err(|e| environment_issue(e.to_string()))?;
    let first = policy::render_lockdown();
    let second = pretunnel_fixture()?;
    let mut gone_every_time = true;
    let mut adapter_every_time = true;
    let mut states_every_time = true;
    let reviewed = pfanchor::reviewed(&pftext::Build::system()?);
    for iteration in 0..20 {
        env(Instant::now() < end(), "Q-ANCHOR case budget exhausted")?;
        let a = p.load_anchor(&first, deadline());
        let a_read = p.read_anchor(deadline());
        let a_raw = inventory(out, &mut p, ANCHOR)?;
        let b = p.load_anchor(&second, deadline());
        let b_read = p.read_anchor(deadline());
        let b_raw = inventory(out, &mut p, ANCHOR)?;
        let remove = measure_remove(out, &mut p, ANCHOR)?;
        gone_every_time &= remove["gone"] == true;
        adapter_every_time &= a.is_ok()
            && a_read.as_ref().is_ok_and(Option::is_some)
            && b.is_ok()
            && b_read.as_ref().is_ok_and(Option::is_some)
            && remove["adapter_ok"] == true;
        write_json(
            out,
            &format!("anchor-lifecycle-{iteration:02}.json"),
            &json!({"a_source":first.as_str(),"a_load":format!("{a:?}"),"a_read":format!("{a_read:?}"),"a_read_raw":a_raw,"b_source":second.as_str(),"b_load":format!("{b:?}"),"b_read":format!("{b_read:?}"),"b_read_raw":b_raw,"remove":remove,"unhooked":true,"proposed_unreviewed":true}),
        )?;
        ensure(p.fence() == Fence::Closed, "lifecycle tool not reaped")?;
        r.iterations += 1;
    }
    write_json(
        out,
        "anchor-lifecycle-summary.json",
        &json!({"gone_after_every_remove":gone_every_time,"qualification_eligible":false,"reason":"proposed unreviewed rows; raw measurement cannot stand in for adapter success"}),
    )?;
    if !gone_every_time {
        r.detail.push_str("; emptied child persisted at least once (contract change would be required; none made)");
    }
    // The hooked case creates the only harness pass rule reached via stock hook.
    let traffic = hooked(out, &mut p)?;
    for iteration in 0..20 {
        env(Instant::now() < end(), "Q-ANCHOR case budget exhausted")?;
        if iteration != 0 {
            let rule = hook_rule(traffic.port);
            raw(out, &mut p, &["-a", HOOKED, "-f", "-"], rule.as_bytes())?;
            traffic.send_ten()?;
        }
        let before = inventory(out, &mut p, HOOKED)?;
        let states = raw(out, &mut p, &["-s", "states", "-v"], &[])?;
        let known = known_id(
            &states,
            traffic.source,
            traffic.receiver.local_addr()?,
            None,
        );
        let with_states = measure_remove(out, &mut p, HOOKED)?;
        let rule = hook_rule(traffic.port);
        raw(out, &mut p, &["-a", HOOKED, "-f", "-"], rule.as_bytes())?;
        traffic.send_ten()?;
        let counters = raw(out, &mut p, &["-a", HOOKED, "-vsr"], &[])?;
        let state_flush = p.flush_states(deadline());
        let after_flush = measure_remove(out, &mut p, HOOKED)?;
        states_every_time &= known.is_some();
        gone_every_time &= with_states["gone"] == true && after_flush["gone"] == true;
        states_every_time &= state_flush.is_ok();
        write_json(
            out,
            &format!("anchor-hooked-{iteration:02}.json"),
            &json!({"exact_rule":rule,"datagrams_per_load":10,"before":before,"known_state_id":known,"with_states":with_states,"counters_after_second_load":counters,"state_flush":format!("{state_flush:?}"),"after_state_flush":after_flush,"claim":"counter/state measurement only; no ordering or blocking qualification"}),
        )?;
    }
    fall_scope(out, &mut p, &traffic)?;
    env(
        !p.call_trace()
            .iter()
            .any(|s| s == crate::decode::qualification_trace::OVERFLOW),
        "Q-ANCHOR trace overflow",
    )?;
    if reviewed {
        r.verdict = if !gone_every_time {
            Verdict::AssumptionRefuted
        } else if adapter_every_time && states_every_time {
            Verdict::AssumptionHolds
        } else {
            Verdict::Inconclusive
        };
        r.detail = format!(
            "anchor removal lifetime only: gone_every_time={gone_every_time}; adapter_every_time={adapter_every_time}; states_every_time={states_every_time}; no reachability, ordering or blocking claim"
        );
    }
    write_json(
        out,
        "anchor-removal-all-conditions.json",
        &json!({"reviewed":reviewed,"gone_every_time":gone_every_time,"adapter_every_time":adapter_every_time,"states_every_time":states_every_time}),
    )?;
    Ok(())
}
struct UdpTraffic {
    sender: UdpSocket,
    receiver: UdpSocket,
    port: u16,
    source: SocketAddr,
}
impl UdpTraffic {
    fn send_ten(&self) -> Result<()> {
        for _ in 0..10 {
            self.sender
                .send_to(b"scupper-qual", self.receiver.local_addr()?)?;
        }
        let mut buffer = [0_u8; 128];
        for _ in 0..10 {
            self.receiver.recv_from(&mut buffer)?;
        }
        Ok(())
    }
}
fn hook_rule(port: u16) -> String {
    format!(
        "pass quick on lo0 inet proto udp from 127.0.0.1 to 127.0.0.1 port {port} keep state label \"scupper-qual\"\n"
    )
}
fn hooked(out: &Path, p: &mut NativePlatform) -> Result<UdpTraffic> {
    super::resources::journal_anchor(out, HOOKED, end())
        .map_err(|e| environment_issue(e.to_string()))?;
    let receiver = UdpSocket::bind("127.0.0.1:0")?;
    receiver.set_read_timeout(Some(Duration::from_secs(2)))?;
    let sender = UdpSocket::bind("127.0.0.1:0")?;
    sender.set_write_timeout(Some(Duration::from_secs(2)))?;
    let port = receiver.local_addr()?.port();
    let source = sender.local_addr()?;
    let rule = hook_rule(port);
    let load = raw(out, p, &["-a", HOOKED, "-f", "-"], rule.as_bytes())?;
    env(load.complete(), "hooked raw rule load incomplete")?;
    let enabled = p.enable_pf(deadline());
    let traffic = UdpTraffic {
        sender,
        receiver,
        port,
        source,
    };
    traffic.send_ten()?;
    let counters = raw(out, p, &["-a", HOOKED, "-vsr"], &[])?;
    let states = raw(out, p, &["-s", "states", "-v"], &[])?;
    write_json(
        out,
        &format!("{}.json", super::unique("hooked-traffic")),
        &json!({"rule":rule,"load":load,"anonymous_enable":format!("{enabled:?}"),"source":source,"destination_port":port,"datagrams":10,"counters":counters,"states":states}),
    )?;
    Ok(traffic)
}
fn fall_scope(out: &Path, p: &mut NativePlatform, traffic: &UdpTraffic) -> Result<()> {
    super::resources::journal_anchor(out, SENTINEL, end())
        .map_err(|e| environment_issue(e.to_string()))?;
    let sentinel=b"table <scupper_qual_sentinel> persist { 192.0.2.123 }\nblock drop quick from <scupper_qual_sentinel> to any\n";
    let loaded = raw(out, p, &["-a", SENTINEL, "-f", "-"], sentinel)?;
    env(loaded.complete(), "sentinel load incomplete")?;
    // Create known state traffic with the hooked rule, after a checked absence.
    super::resources::journal_anchor(out, HOOKED, end())
        .map_err(|e| environment_issue(e.to_string()))?;
    let rule = hook_rule(traffic.port);
    raw(out, p, &["-a", HOOKED, "-f", "-"], rule.as_bytes())?;
    traffic.send_ten()?;
    // Measure -F all on an existing child, rather than an absent ruleset that
    // might reject the request before reaching any global flush implementation.
    let target = raw(
        out,
        p,
        &["-a", ANCHOR, "-f", "-"],
        policy::render_lockdown().as_str().as_bytes(),
    )?;
    env(target.complete(), "F-all target load incomplete")?;
    let rule_args = ["-a", SENTINEL, "-sr"];
    let table_args = ["-a", SENTINEL, "-t", "scupper_qual_sentinel", "-T", "show"];
    let sentinel_rule_before = raw(out, p, &rule_args, &[])?;
    let sentinel_table_before = raw(out, p, &table_args, &[])?;
    let states_before = raw(out, p, &["-s", "states", "-v"], &[])?;
    let known_before = known_id(
        &states_before,
        traffic.source,
        traffic.receiver.local_addr()?,
        None,
    );
    let before = json!({"target":inventory(out,p,ANCHOR)?,"sentinel":inventory(out,p,SENTINEL)?,"sentinel_rule":sentinel_rule_before,"sentinel_table_entries":sentinel_table_before,"states":states_before,"known_state_id":known_before,"info":raw(out,p,&["-s","info"],&[])?,"counters":raw(out,p,&["-a",HOOKED,"-vsr"],&[])?});
    super::resources::recheck_foreign_tokens(out, end())?;
    let all = raw(out, p, &["-a", ANCHOR, "-F", "all"], &[])?;
    let sentinel_rule_after = raw(out, p, &rule_args, &[])?;
    let sentinel_table_after = raw(out, p, &table_args, &[])?;
    let states_after = raw(out, p, &["-s", "states", "-v"], &[])?;
    let known_survived = known_before
        .as_ref()
        .and_then(|id| state_ids(&states_after).ok().map(|ids| ids.contains(id)));
    let after = json!({"target":inventory(out,p,ANCHOR)?,"sentinel":inventory(out,p,SENTINEL)?,"sentinel_rule":sentinel_rule_after,"sentinel_table_entries":sentinel_table_after,"states":states_after,"known_state_survived":known_survived,"info":raw(out,p,&["-s","info"],&[])?,"counters":raw(out,p,&["-a",HOOKED,"-vsr"],&[])?});
    let changed_rule =
        super::super::contract_check::sentinel_changed(&sentinel_rule_before, &sentinel_rule_after);
    let changed_table = super::super::contract_check::sentinel_changed(
        &sentinel_table_before,
        &sentinel_table_after,
    );
    write_json(
        out,
        "anchor-F-all-scope.json",
        &json!({"before":before,"command":all,"after":after,"changed":{"foreign_rule":changed_rule,"foreign_table_entries":changed_table,"known_state_removed":known_survived.map(|survived| !survived),"info_output":before["info"]["stdout"]!=after["info"]["stdout"],"hooked_rule_counters":before["counters"]["stdout"]!=after["counters"]["stdout"]},"measurement_only":true}),
    )?;
    scoped(out, p, ANCHOR)?;
    scoped(out, p, SENTINEL)?;
    scoped(out, p, HOOKED)?;
    Ok(())
}

struct TcpTraffic {
    client: TcpStream,
    server: TcpStream,
    listener: TcpListener,
    source: SocketAddr,
    destination: SocketAddr,
}
fn tcp(listener: TcpListener, feth: bool) -> Result<TcpTraffic> {
    use std::os::fd::AsFd;
    let destination = listener.local_addr()?;
    let socket = socket2::Socket::new(
        if destination.is_ipv4() {
            socket2::Domain::IPV4
        } else {
            socket2::Domain::IPV6
        },
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;
    if feth {
        let index = scupper_darwin::interface_index("feth0")?;
        scupper_darwin::qual_ipv4_bound_interface(socket.as_fd(), index)?;
        socket.bind(&"198.18.0.1:0".parse::<SocketAddr>()?.into())?;
    }
    socket.connect_timeout(&destination.into(), Duration::from_secs(2))?;
    let mut client: TcpStream = socket.into();
    client.set_write_timeout(Some(Duration::from_secs(2)))?;
    client.write_all(b"scupper-qual")?;
    listener.set_nonblocking(true)?;
    let until = Instant::now() + Duration::from_secs(2);
    let server = loop {
        match listener.accept() {
            Ok((server, _)) => break server,
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < until =>
            {
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(error.into()),
        }
    };
    server.set_read_timeout(Some(Duration::from_secs(2)))?;
    let mut server = server;
    let mut bytes = [0_u8; 12];
    server.read_exact(&mut bytes)?;
    thread::sleep(Duration::from_millis(250));
    let source = client.local_addr()?;
    Ok(TcpTraffic {
        client,
        server,
        listener,
        source,
        destination,
    })
}
fn state_rows(e: &Evidence) -> Result<Vec<super::super::state_measure::State>> {
    env(e.complete(), "unfiltered state listing incomplete")?;
    let build = pftext::Build::system()?;
    env(
        pftext::BUILDS.contains(&build.as_str()),
        "state measurement build unknown",
    )?;
    pftext::read(&build, 0, e.stdout.as_bytes(), e.stderr.as_bytes())
        .map_err(|_| environment_issue("unfiltered state listing diagnostics unpinned"))?;
    super::super::state_measure::parse(&e.stdout).map_err(environment_issue)
}
fn state_ids(e: &Evidence) -> Result<BTreeSet<String>> {
    Ok(state_rows(e)?.into_iter().map(|s| s.identity).collect())
}
fn known_id(
    e: &Evidence,
    source: SocketAddr,
    destination: SocketAddr,
    interface: Option<&str>,
) -> Option<String> {
    super::super::state_measure::known(&state_rows(e).ok()?, source, destination, interface)
}
fn feth(out: &Path, p: &mut NativePlatform) -> Result<()> {
    let list = invoke_before("/sbin/ifconfig", &["-l"], end());
    env(
        list.complete()
            && !list
                .stdout
                .split_whitespace()
                .any(|s| matches!(s, "feth0" | "feth1")),
        "feth0/feth1 already present or inventory incomplete",
    )?;
    for name in ["feth0", "feth1"] {
        append(out, &json!({"kind":"feth","path":name}))?;
        let e = invoke_before("/sbin/ifconfig", &[name, "create"], end());
        write_json(out, &format!("{name}-create.json"), &e)?;
        env(e.complete(), "feth create unavailable")?;
    }
    for args in [
        vec!["feth0", "peer", "feth1"],
        vec!["feth0", "inet", "198.18.0.1/30", "up"],
        vec!["feth1", "inet", "198.18.0.2/30", "up"],
    ] {
        let e = invoke_before("/sbin/ifconfig", &args, end());
        write_json(out, &format!("{}.json", super::unique("feth-config")), &e)?;
        env(e.complete(), "feth configuration unavailable")?;
    }
    // Raw, unhooked qualification anchor never supplies connectivity proof.
    // Stock rules decide whether these local TCP packets create floating states.
    let info = raw(out, p, &["-s", "info"], &[])?;
    write_json(out, "feth-pf-before.json", &info)?;
    Ok(())
}
#[allow(clippy::too_many_lines)] // Keep socket lifetimes, pre-call identities, flush and post-call inventory together.
fn flush(out: &Path, r: &mut CaseResult) -> Result<()> {
    let mut p = platform(out, &out.join("r4-fixtures"), &child_pin()?)?;
    let udp = hooked(out, &mut p)?;
    feth(out, &mut p)?;
    super::resources::journal_anchor(out, SENTINEL, end())
        .map_err(|e| environment_issue(e.to_string()))?;
    let listen4 = TcpListener::bind("127.0.0.1:0")?;
    let listen6 = TcpListener::bind("[::1]:0")?;
    let listen_feth = TcpListener::bind("198.18.0.2:0")?;
    let rules = format!(
        "pass quick on lo0 inet proto tcp from 127.0.0.1 to 127.0.0.1 port {} keep state label \"scupper-qual-tcp4\"\npass quick on lo0 inet6 proto tcp from ::1 to ::1 port {} keep state label \"scupper-qual-tcp6\"\npass quick on feth0 inet proto tcp from 198.18.0.1 to 198.18.0.2 port {} keep state label \"scupper-qual-feth\"\n",
        listen4.local_addr()?.port(),
        listen6.local_addr()?.port(),
        listen_feth.local_addr()?.port()
    );
    let load = raw(out, &mut p, &["-a", SENTINEL, "-f", "-"], rules.as_bytes())?;
    env(load.complete(), "TCP measurement rules failed to load")?;
    let ipv4 = tcp(listen4, false)
        .map_err(|e| environment_issue(format!("IPv4 TCP fixture unavailable: {e}")))?;
    let ipv6 = tcp(listen6, false)
        .map_err(|e| environment_issue(format!("IPv6 TCP fixture unavailable: {e}")))?;
    let feth_traffic = tcp(listen_feth, true)
        .map_err(|e| environment_issue(format!("bound feth TCP fixture unavailable: {e}")))?;
    let counters = raw(out, &mut p, &["-a", SENTINEL, "-vvsr"], &[])?;
    write_json(
        out,
        "flush-tcp-counters.json",
        &json!({"rules":rules,"counters":counters,"feth_source_bound_interface":"feth0"}),
    )?;
    let before = raw(out, &mut p, &["-s", "states", "-v"], &[])?;
    let flows = [
        ("udp-lo0", udp.source, udp.receiver.local_addr()?, None),
        ("tcp-lo0-v4", ipv4.source, ipv4.destination, None),
        ("tcp-lo0-v6", ipv6.source, ipv6.destination, None),
        (
            "tcp-feth",
            feth_traffic.source,
            feth_traffic.destination,
            None,
        ),
    ];
    let mut known = BTreeSet::new();
    let mut missing = vec![];
    for (name, source, destination, interface) in flows {
        if let Some(id) = known_id(&before, source, destination, interface) {
            known.insert(id);
        } else {
            missing.push(name);
        }
    }
    // Keep all sockets alive but quiescent through every state measurement.
    let keep_alive = (
        &ipv4.client,
        &ipv4.server,
        &ipv4.listener,
        &ipv6.client,
        &ipv6.server,
        &ipv6.listener,
        &feth_traffic.client,
        &feth_traffic.server,
        &feth_traffic.listener,
    );
    let all_before = state_ids(&before)?;
    let attempted = missing.is_empty() && known.len() == 4;
    let result = if attempted {
        p.flush_states(deadline())
    } else {
        Err(SysError::Failed(
            "known test state absent; adapter flush not attempted",
        ))
    };
    ensure(p.fence() == Fence::Closed, "state flush tool not reaped")?;
    let after = raw(out, &mut p, &["-s", "states", "-v"], &[])?;
    let remaining = state_ids(&after)?;
    write_json(
        out,
        "flush-known-states.json",
        &json!({"known_ids":known,"missing_known_flows":missing,"all_before":all_before,"before":before,"adapter_call_attempted":attempted,"adapter_result":format!("{result:?}"),"after":after,"known_survivors":known.intersection(&remaining).collect::<Vec<_>>(),"all_sockets_quiescent":true,"ownership_exception":"foreign states destroyed irreversibly; restore cannot return them"}),
    )?;
    // Measurement only, never adapter interface removal. Generate fresh states
    // before each selector, retain both unfiltered listings and raw results.
    for args in [
        vec!["-i", "feth0", "-F", "states"],
        vec!["-k", "198.18.0.1"],
    ] {
        let fresh = tcp(feth_traffic.listener.try_clone()?, true).map_err(|e| {
            environment_issue(format!("fresh bound feth TCP fixture unavailable: {e}"))
        })?;
        let pre = raw(out, &mut p, &["-s", "states", "-v"], &[])?;
        let id = known_id(&pre, fresh.source, fresh.destination, Some("all"));
        if id.is_none() {
            write_json(
                out,
                "floating-state-unproven.json",
                &json!({"before":pre,"source":fresh.source,"destination":fresh.destination,"selector":args}),
            )?;
            return Err(environment_issue(
                "floating feth state not positively identified before selector measurement",
            ));
        }
        let effect = raw(out, &mut p, &args, &[])?;
        let post = raw(out, &mut p, &["-s", "states", "-v"], &[])?;
        write_json(
            out,
            &format!("{}.json", super::unique("floating-state-selector")),
            &json!({"known_feth_id":id,"before":pre,"measurement":effect,"after":post,"measurement_only":true}),
        )?;
        drop(fresh);
    }
    let _ = keep_alive;
    scoped(out, &mut p, HOOKED)?;
    scoped(out, &mut p, SENTINEL)?;
    env(
        missing.is_empty() && known.len() == 4,
        "not every known flow was proven present by state id immediately before flush; no vacuous success",
    )?;
    env(
        known.is_disjoint(&remaining),
        "known states survived global flush",
    )?;
    env(
        result.is_ok(),
        "global flush row proposed/unreviewed; capture retained, pass 2 required",
    )?;
    r.iterations = 1;
    r.verdict = Verdict::AssumptionHolds;
    env(
        !p.call_trace()
            .iter()
            .any(|s| s == crate::decode::qualification_trace::OVERFLOW),
        "Q-FLUSH trace overflow",
    )?;
    r.detail="reviewed global flush completed; each of four positively identified known states absent in complete post-call inventory; foreign states cannot be restored".into();
    Ok(())
}
