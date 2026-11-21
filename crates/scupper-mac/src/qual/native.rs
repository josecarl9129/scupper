use std::{
    collections::BTreeMap,
    error::Error,
    fs,
    io::Write,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::{
    CaseResult, Evidence, Manifest, Verdict,
    command::{command, unix_seconds},
    guard::{Ack, MAX_ARM_SECONDS, check_environment, preflight_conditions},
    redact,
    restore_check::{self, RestoreEffects},
};

type Result<T> = std::result::Result<T, Box<dyn Error>>;
const LABEL: &str = "net.scupper.qual.restore";
const SERVICE: &str = "system/net.scupper.qual.restore";
#[path = "resources.rs"]
mod resources;

const TOOL_BUDGET: Duration = Duration::from_secs(8);

struct Options {
    action: String,
    out: PathBuf,
    group: String,
    after: u64,
    name: Option<String>,
    disposable: bool,
}

impl Options {
    fn parse(args: &[String]) -> Result<Self> {
        let mut args = args.iter();
        let action = args.next().ok_or("usage: scupper-mac-qual <preflight|arm|run|restore|capture> --out DIR --disposable-runner")?.clone();
        let mut options = Self {
            action,
            out: PathBuf::from("qual-out"),
            group: "smoke".into(),
            after: MAX_ARM_SECONDS,
            disposable: false,
            name: None,
        };
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--disposable-runner" => options.disposable = true,
                "--out" => {
                    options.out = PathBuf::from(args.next().ok_or("--out requires a directory")?);
                }
                "--group" => options
                    .group
                    .clone_from(args.next().ok_or("--group requires a value")?),
                "--name" => {
                    options.name = Some(args.next().ok_or("--name requires a probe")?.clone());
                }
                "--after" => {
                    options.after = args.next().ok_or("--after requires seconds")?.parse()?;
                }
                _ => return Err(format!("unknown argument: {arg}").into()),
            }
        }
        if !matches!(
            options.action.as_str(),
            "preflight" | "arm" | "run" | "restore" | "capture" | "deadman" | "probe"
        ) {
            return Err("unknown subcommand".into());
        }
        if !matches!(options.group.as_str(), "smoke" | "probe" | "probe-hijack")
            || options.after == 0
            || options.after > MAX_ARM_SECONDS
        {
            return Err(
                "group must be smoke/probe/probe-hijack; --after must be 1..1080 seconds".into(),
            );
        }
        if options.action == "probe"
            && !options
                .name
                .as_deref()
                .is_some_and(|name| super::probe::NAMES.contains(&name))
        {
            return Err("probe requires a known --name".into());
        }
        if options.action == "probe"
            && options.name.as_deref() == Some("dns-default")
            && options.group != "probe-hijack"
        {
            return Err("dns-default requires --group probe-hijack".into());
        }
        Ok(options)
    }
}

pub(super) fn dispatch(args: &[String]) -> Result<()> {
    let mut options = Options::parse(args)?;
    check_environment(
        &std::env::var("GITHUB_ACTIONS").unwrap_or_default(),
        &std::env::var("RUNNER_ENVIRONMENT").unwrap_or_default(),
        rustix::process::geteuid().is_root(),
        options.disposable,
    )?;
    // Refuse runner-writable code and paths before creating or loading evidence.
    // Stage the harness and probe as root before the first privileged invocation.
    protected_path(&std::env::current_exe()?, false)?;
    protected_path(&probe_path()?, false)?;
    if !options.out.is_absolute() {
        return Err("--out must be an absolute path under a root-owned directory".into());
    }
    let parent = options
        .out
        .parent()
        .ok_or("artifact directory needs a parent")?;
    protected_path(parent, true)?;
    if !options.out.exists() {
        fs::DirBuilder::new().mode(0o700).create(&options.out)?;
    }
    protected_path(&options.out, true)?;
    options.out = options.out.canonicalize()?;
    for entry in fs::read_dir(&options.out)? {
        let entry = entry?;
        // A mounted APFS root has filesystem-selected ownership/mode. Validate
        // its protected mountpoint parent, then detach by journaled image path.
        if entry.file_name() == "storage-mount" && entry.file_type()?.is_dir() {
            continue;
        }
        protected_path(&entry.path(), entry.file_type()?.is_dir())?;
    }
    if options.out.join("preflight.json").exists() {
        let baseline: Snapshot = read_json(&options.out.join("preflight.json"))?;
        if baseline.binary_sha256 != executable_sha256()? {
            return Err("executed harness SHA256 differs from preflight".into());
        }
    }
    match options.action.as_str() {
        "preflight" => preflight(&options.out),
        "arm" => arm(&options),
        "run" | "probe" => {
            require_ack(&options.out)?;
            let own = process_identity(&options.out, std::process::id())?;
            write_json(
                &options.out,
                "writers.json",
                &vec![Writer {
                    pid: own.pid,
                    start: own.start,
                }],
            )?;
            let result = if options.action == "probe" {
                run_probe(&options.out, options.name.as_deref().ok_or("missing name")?)
            } else if options.group == "smoke" {
                run_smoke(&options.out)
            } else {
                run_probes(&options.out, &options.group)
            };
            write_json(&options.out, "writers.json", &Vec::<Writer>::new())?;
            result
        }
        "capture" => {
            require_ack(&options.out)?;
            capture(&options.out).map(|_| ())
        }
        "restore" => restore_checked(&options.out),
        "deadman" => deadman(&options),
        _ => Err("unknown subcommand".into()),
    }
}

// lstat each component, including ancestors: a protected file inside a writable
// directory can still be replaced. Never follow a caller-planted symlink.
fn protected_path(path: &Path, directory: bool) -> Result<()> {
    if !path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
    {
        return Err("protected paths must be absolute without dot components".into());
    }
    for component in path.ancestors() {
        let meta = fs::symlink_metadata(component)?;
        let needs_directory = component != path || directory;
        if meta.uid() != 0
            || meta.mode() & 0o022 != 0
            || (needs_directory && !meta.is_dir())
            || (!needs_directory && !meta.is_file())
        {
            return Err(format!(
                "{} must be root-owned, non-writable by other users, and a regular {}",
                component.display(),
                if needs_directory { "directory" } else { "file" }
            )
            .into());
        }
    }
    Ok(())
}

fn probe_path() -> Result<PathBuf> {
    Ok(std::env::current_exe()?
        .parent()
        .ok_or("executable needs a parent")?
        .join("abi-probe"))
}

fn executable_sha256() -> Result<String> {
    Ok(format!(
        "{:x}",
        Sha256::digest(fs::read(std::env::current_exe()?)?)
    ))
}

fn monotonic_seconds() -> Result<u64> {
    Ok(
        rustix::time::clock_gettime(rustix::time::ClockId::Monotonic)
            .tv_sec
            .try_into()?,
    )
}

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
struct EnvironmentIssue(String);

fn environment_issue(error: impl std::fmt::Display) -> Box<dyn Error> {
    Box::new(EnvironmentIssue(error.to_string()))
}

fn clean_value(value: &mut Value) {
    match value {
        Value::String(text) => *text = redact(text),
        Value::Array(values) => values.iter_mut().for_each(clean_value),
        Value::Object(values) => values.values_mut().for_each(clean_value),
        _ => (),
    }
}

fn write_json(out: &Path, name: &str, value: &impl Serialize) -> Result<()> {
    let mut value = serde_json::to_value(value)?;
    clean_value(&mut value);
    let path = out.join(name);
    let temp = path.with_extension(format!("{}.tmp", std::process::id()));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp)?;
    file.write_all(&serde_json::to_vec_pretty(&value)?)?;
    fs::rename(temp, path)?;
    Ok(())
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    protected_path(path, false)?;
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

fn unique(prefix: &str) -> String {
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    format!(
        "{prefix}-{}-{}-{}",
        unix_seconds(),
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    )
}

fn invoke_before(program: &str, args: &[&str], deadline: Instant) -> Evidence {
    command(
        program,
        args,
        None,
        TOOL_BUDGET.min(deadline.saturating_duration_since(Instant::now())),
    )
}

fn invoke(program: &str, args: &[&str]) -> Evidence {
    command(program, args, None, TOOL_BUDGET)
}

#[derive(Serialize, Deserialize)]
struct Snapshot {
    at: u64,
    image: BTreeMap<String, String>,
    binary_sha256: String,
    observations: BTreeMap<String, Evidence>,
    inconclusive: Vec<String>,
}

fn snapshot(out: &Path, phase: &str, deadline: Instant) -> Result<Snapshot> {
    let mut observations = BTreeMap::new();
    for (name, program, args) in [
        ("pf-info", "/sbin/pfctl", vec!["-s", "info"]),
        ("pf-references", "/sbin/pfctl", vec!["-s", "References"]),
        ("pf-rules", "/sbin/pfctl", vec!["-sr"]),
        ("pf-anchors", "/sbin/pfctl", vec!["-vv", "-sA"]),
        (
            "pf-apple-anchors",
            "/sbin/pfctl",
            vec!["-a", "com.apple", "-s", "Anchors"],
        ),
        ("pf-nat", "/sbin/pfctl", vec!["-s", "nat"]),
        ("routes", "/usr/sbin/netstat", vec!["-rn"]),
        ("interfaces", "/sbin/ifconfig", vec!["-a"]),
        (
            "osversion",
            "/usr/sbin/sysctl",
            vec!["-n", "kern.osversion"],
        ),
        ("kernel-uuid", "/usr/sbin/sysctl", vec!["-n", "kern.uuid"]),
        ("machine", "/usr/sbin/sysctl", vec!["-n", "hw.machine"]),
        (
            "translated",
            "/usr/sbin/sysctl",
            vec!["-n", "sysctl.proc_translated"],
        ),
        ("sdk", "/usr/bin/xcrun", vec!["--show-sdk-version"]),
        (
            "tool-sha256",
            "/usr/bin/shasum",
            vec![
                "-a",
                "256",
                "/sbin/pfctl",
                "/usr/sbin/scutil",
                "/sbin/route",
                "/sbin/ifconfig",
            ],
        ),
    ] {
        let evidence = invoke_before(program, &args, deadline);
        write_json(out, &format!("{phase}-{name}.json"), &evidence)?;
        observations.insert(name.into(), evidence);
    }
    let binary = std::env::current_exe()?;
    observations.insert(
        "binary-arch".into(),
        invoke_before(
            "/usr/bin/lipo",
            &["-archs", binary.to_str().ok_or("non-UTF8 executable path")?],
            deadline,
        ),
    );
    observations.insert(
        "scutil-keys".into(),
        command(
            "/usr/sbin/scutil",
            &[],
            Some("list\nquit\n"),
            TOOL_BUDGET.min(deadline.saturating_duration_since(Instant::now())),
        ),
    );
    for name in ["binary-arch", "scutil-keys"] {
        write_json(out, &format!("{phase}-{name}.json"), &observations[name])?;
    }
    let inconclusive = preflight_conditions(&observations, cfg!(target_arch = "aarch64"));
    let image = [
        "ImageOS",
        "ImageVersion",
        "RUNNER_NAME",
        "GITHUB_RUN_ID",
        "GITHUB_SHA",
    ]
    .into_iter()
    .map(|key| (key.into(), std::env::var(key).unwrap_or_default()))
    .collect();
    Ok(Snapshot {
        at: unix_seconds(),
        image,
        binary_sha256: executable_sha256()?,
        observations,
        inconclusive,
    })
}

fn preflight(out: &Path) -> Result<()> {
    if out.join("preflight.json").exists() {
        return Err(
            "preflight already exists; use a new artifact directory for a new campaign".into(),
        );
    }
    let snapshot = snapshot(out, "preflight", Instant::now() + Duration::from_secs(90))?;
    write_json(out, "preflight.json", &snapshot)?;
    write_json(out, "writers.json", &Vec::<Writer>::new())?;
    write_json(out, "manifest.json", &Manifest::bundled()?)?;
    if !snapshot.inconclusive.is_empty() {
        eprintln!(
            "inconclusive preflight: {}",
            snapshot.inconclusive.join("; ")
        );
    }
    Ok(())
}

#[derive(Deserialize)]
struct ProcessIdentity {
    pid: u32,
    ppid: u32,
    pgid: u32,
    start: String,
    status: u32,
}

fn lookup_identity(out: &Path, pid: u32) -> Result<Option<ProcessIdentity>> {
    lookup_identity_before(out, pid, Instant::now() + TOOL_BUDGET)
}

fn lookup_identity_before(
    out: &Path,
    pid: u32,
    deadline: Instant,
) -> Result<Option<ProcessIdentity>> {
    let probe = probe_path()?;
    let evidence = invoke_before(
        probe.to_str().ok_or("non-UTF8 probe path")?,
        &["--process-identity", &pid.to_string()],
        deadline,
    );
    // Preserve each lookup, including failed or short kernel reads.
    write_json(
        out,
        &format!("{}.json", unique(&format!("identity-{pid}"))),
        &evidence,
    )?;
    if evidence.exit_code == Some(3) && !evidence.timed_out && !evidence.truncated {
        let error: Value = serde_json::from_str(&evidence.stdout)?;
        if error["error"].as_i64() == Some(i64::from(rustix::io::Errno::SRCH.raw_os_error())) {
            return Ok(None);
        }
    }
    if !evidence.complete() {
        return Err(format!(
            "cannot establish microsecond process identity for pid {pid}; see identity evidence"
        )
        .into());
    }
    let identity: ProcessIdentity = serde_json::from_str(&evidence.stdout)?;
    if identity.pid != pid || identity.start.is_empty() {
        return Err("process identity probe returned a mismatched or empty identity".into());
    }
    Ok(Some(identity))
}

fn process_identity(out: &Path, pid: u32) -> Result<ProcessIdentity> {
    lookup_identity(out, pid)?.ok_or_else(|| format!("process {pid} is absent").into())
}

fn require_ack(out: &Path) -> Result<Ack> {
    let ack: Ack = read_json(&out.join("ack.json"))
        .map_err(|error| format!("fresh dead-man acknowledgement required: {error}"))?;
    let boot = scupper_darwin::sysctl_string("kern.bootsessionuuid")?;
    if !ack.fresh(monotonic_seconds()?, &boot) || process_identity(out, ack.pid)?.start != ack.start
    {
        return Err(
            "dead-man acknowledgement is stale, expired or has a different process/boot identity"
                .into(),
        );
    }
    if process_identity(out, std::process::id())?.pgid == ack.pgid {
        return Err("dead-man shares the controller process group".into());
    }
    let job = invoke("/bin/launchctl", &["print", SERVICE]);
    write_json(out, "deadman-status.json", &job)?;
    if !job.complete()
        || !job
            .stdout
            .lines()
            .any(|line| line.trim() == format!("pid = {}", ack.pid))
    {
        return Err("acknowledged dead-man pid is not the running launchd service".into());
    }
    Ok(ack)
}

fn xml(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn arm(options: &Options) -> Result<()> {
    let _: Snapshot = read_json(&options.out.join("preflight.json"))?;
    if options.out.join("ack.json").exists() {
        return Err("dead-man already armed; use a fresh campaign directory".into());
    }
    let exe = xml(std::env::current_exe()?
        .to_str()
        .ok_or("non-UTF8 executable path")?);
    let out = xml(options.out.to_str().ok_or("non-UTF8 artifact path")?);
    // launchd starts the worker independently of the controller's process group.
    // RunAtLoad, no KeepAlive: a successful restore must not restart it.
    let plist = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>{LABEL}</string>
<key>ProgramArguments</key><array><string>{exe}</string><string>deadman</string><string>--after</string><string>{after}</string><string>--out</string><string>{out}</string><string>--disposable-runner</string></array>
<key>RunAtLoad</key><true/>
<key>AbandonProcessGroup</key><false/>
<key>EnvironmentVariables</key><dict><key>GITHUB_ACTIONS</key><string>true</string><key>RUNNER_ENVIRONMENT</key><string>github-hosted</string></dict>
<key>StandardOutPath</key><string>{out}/deadman.stdout.log</string>
<key>StandardErrorPath</key><string>{out}/deadman.stderr.log</string>
</dict></plist>
"#,
        after = options.after
    );
    let path = options.out.join("restore.plist");
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)?;
    file.write_all(plist.as_bytes())?;
    rustix::fs::chown(
        &path,
        Some(rustix::fs::Uid::ROOT),
        Some(rustix::fs::Gid::ROOT),
    )?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?;
    protected_path(&path, false)?;
    let bootstrap = invoke(
        "/bin/launchctl",
        &[
            "bootstrap",
            "system",
            path.to_str().ok_or("non-UTF8 plist path")?,
        ],
    );
    write_json(&options.out, "deadman-bootstrap.json", &bootstrap)?;
    if !bootstrap.complete() {
        arm_diagnostics(&options.out)?;
        return Err(
            "launchctl bootstrap failed; see deadman-bootstrap.json and deadman diagnostics".into(),
        );
    }
    let wait = Instant::now();
    while wait.elapsed() < Duration::from_secs(10) {
        if options.out.join("ack.json").exists() {
            require_ack(&options.out)?;
            return Ok(());
        }
        thread::sleep(Duration::from_millis(100));
    }
    arm_diagnostics(&options.out)?;
    Err("launchd dead-man did not acknowledge within 10 seconds; see worker logs and bootstrap evidence".into())
}

fn arm_diagnostics(out: &Path) -> Result<()> {
    write_json(
        out,
        "deadman-failed-status.json",
        &invoke("/bin/launchctl", &["print", SERVICE]),
    )?;
    let plist = out.join("restore.plist");
    write_json(
        out,
        "deadman-plist-lint.json",
        &invoke(
            "/usr/bin/plutil",
            &["-lint", plist.to_str().ok_or("non-UTF8 plist path")?],
        ),
    )?;
    write_json(
        out,
        "deadman-launchd-log.json",
        &invoke(
            "/usr/bin/log",
            &[
                "show",
                "--style",
                "compact",
                "--last",
                "2m",
                "--predicate",
                r#"process == "launchd" AND eventMessage CONTAINS "net.scupper.qual.restore""#,
            ],
        ),
    )
}

fn deadman(options: &Options) -> Result<()> {
    let identity = process_identity(&options.out, std::process::id())?;
    if identity.ppid != 1 || identity.pgid != identity.pid {
        return Err("dead-man must be a launchd child and process group leader".into());
    }
    let armed_at = unix_seconds();
    let armed_monotonic = monotonic_seconds()?;
    let ack = Ack {
        pid: std::process::id(),
        start: identity.start,
        pgid: identity.pgid,
        ppid: identity.ppid,
        armed_at,
        armed_monotonic,
        fire_monotonic: armed_monotonic + options.after,
        fire_at: armed_at + options.after,
        boot_session: scupper_darwin::sysctl_string("kern.bootsessionuuid")?,
    };
    // Acknowledgement is written by the running launchd worker, never by arm.
    write_json(&options.out, "ack.json", &ack)?;
    let deadline = Instant::now() + Duration::from_secs(options.after);
    while Instant::now() < deadline {
        thread::sleep(Duration::from_millis(100));
    }
    restore_checked(&options.out)
}

#[derive(Serialize, Deserialize)]
struct Writer {
    pid: u32,
    start: String,
}

fn stop_writers(out: &Path, deadline: Instant) -> Result<Vec<Evidence>> {
    let controllers: Vec<Writer> = read_json(&out.join("writers.json"))?;
    let mut stopped = stop_writer_list(out, controllers, deadline)?;
    // Stop probe controllers before the final child census. Their exec gates
    // close on death, so an uncommitted child cannot become a late writer.
    stopped.extend(stop_writer_list(
        out,
        resources::writers(out, true)?,
        deadline,
    )?);
    stopped.extend(stop_writer_list(
        out,
        resources::writers(out, false)?,
        deadline,
    )?);
    Ok(stopped)
}

fn stop_writer_list(
    out: &Path,
    mut writers: Vec<Writer>,
    deadline: Instant,
) -> Result<Vec<Evidence>> {
    writers.sort_by_key(|writer| writer.pid);
    writers.dedup_by(|a, b| a.pid == b.pid && a.start == b.start);
    let mut stopped = Vec::new();
    for writer in writers {
        // An in-process smoke restore excludes its own controller. An external
        // restore/dead-man stops that controller before inspecting post-state.
        if writer.pid == std::process::id() {
            continue;
        }
        let Some(identity) = lookup_identity_before(out, writer.pid, deadline)? else {
            continue;
        };
        if identity.start != writer.start || identity.status == 5 {
            continue;
        }
        let kill = invoke_before("/bin/kill", &["-KILL", &writer.pid.to_string()], deadline);
        let complete = kill.complete();
        stopped.push(kill);
        write_json(out, "writer-stop.json", &stopped)?;
        let wait = Instant::now();
        loop {
            if lookup_identity_before(out, writer.pid, deadline)?
                .is_none_or(|live| live.start != writer.start || live.status == 5)
            {
                break;
            }
            if wait.elapsed() >= Duration::from_secs(2) || Instant::now() >= deadline {
                return Err(
                    "matching harness writer survived stop deadline; see writer-stop.json".into(),
                );
            }
            if !complete {
                return Err(
                    "failed to stop a matching harness writer; see writer-stop.json".into(),
                );
            }
            thread::sleep(Duration::from_millis(20));
        }
    }
    Ok(stopped)
}

#[derive(Serialize, Deserialize)]
struct Restore {
    already_restored: bool,
    network_mutations: Vec<String>,
    writer_stop_evidence: Vec<Evidence>,
    changed_observations: Vec<String>,
    post_state: Snapshot,
    violations: Vec<String>,
}

fn restore(out: &Path, deadline: Instant) -> Result<Restore> {
    let before: Snapshot = read_json(&out.join("preflight.json"))?;
    let stopped = stop_writers(out, deadline)?;
    let _lock = resources::restore_lock(out, deadline)?;
    let mut actions = Vec::new();
    let mut violations = Vec::new();
    let mut stopped = stopped;
    // Stop every scoped writer before any network cleanup, including when the
    // dead-man interrupts a probe between its exec grant and token append.
    let mut scopes = Vec::new();
    for name in super::probe::NAMES {
        let scope = out.join(format!("scope-{name}"));
        if !scope.join("preflight.json").exists() {
            continue;
        }
        protected_path(&scope, true)?;
        match stop_writers(&scope, deadline) {
            Ok(evidence) => stopped.extend(evidence),
            Err(error) => violations.push(format!("{name}: stop writers: {error}")),
        }
        scopes.push((name, scope));
    }
    // Final/dead-man recovery visits all independent journals. An inventory
    // failure in one scope cannot suppress cleanup in another scope.
    for (name, scope) in scopes
        .into_iter()
        .chain(std::iter::once(("campaign", out.to_path_buf())))
    {
        let _scope_lock = if scope == out {
            None
        } else {
            Some(resources::restore_lock(&scope, deadline)?)
        };
        // Release scoped references before restoring the campaign's PF state.
        // A scoped restore (with no children) still restores its own PF state.
        match resources::undo(&scope, &before, deadline, scope == out) {
            Ok((undo, problems)) => {
                actions.extend(undo);
                violations.extend(
                    problems
                        .into_iter()
                        .map(|problem| format!("{name}: {problem}")),
                );
            }
            Err(error) => violations.push(format!("{name}: restore: {error}")),
        }
    }
    let post = snapshot(out, &unique("post"), deadline)?;
    let changed = restore_check::state_diff(&before.observations, &post.observations);
    violations.extend(changed.iter().cloned());
    let result = Restore {
        already_restored: out.join("restored.json").exists(),
        network_mutations: actions,
        writer_stop_evidence: stopped,
        changed_observations: changed,
        post_state: post,
        violations,
    };
    write_json(out, &format!("{}.json", unique("restore")), &result)?;
    write_json(out, "restored.json", &result)?;
    Ok(result)
}

fn save_case(out: &Path, result: &CaseResult) -> Result<()> {
    write_json(out, &format!("{}.json", result.case), result)?;
    eprintln!(
        "{}: {:?}: {}",
        result.case,
        result.verdict,
        redact(&result.detail)
    );
    Ok(())
}

fn capture(out: &Path) -> Result<CaseResult> {
    let snapshot = snapshot(
        out,
        &unique("capture"),
        Instant::now() + Duration::from_secs(60),
    )?;
    let verdict = if snapshot.inconclusive.is_empty() {
        Verdict::AssumptionHolds
    } else {
        Verdict::Inconclusive
    };
    write_json(out, "capture.json", &snapshot)?;
    let result = CaseResult {
        case: "Q-CAPTURE".into(),
        binary_sha256: snapshot.binary_sha256,
        verdict,
        iterations: 1,
        detail: if snapshot.inconclusive.is_empty() {
            "raw inventory and available system-tool SHA256 evidence captured".into()
        } else {
            snapshot.inconclusive.join("; ")
        },
        evidence: snapshot.observations.into_values().collect(),
    };
    save_case(out, &result)?;
    Ok(result)
}

fn valid_uuid(text: &str) -> bool {
    text.len() == 36
        && text.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}

fn run_smoke(out: &Path) -> Result<()> {
    let manifest = Manifest::bundled()?;
    if !manifest.budgets_fit() {
        return Err("manifest exceeds harness budget".into());
    }
    let baseline: Snapshot = read_json(&out.join("preflight.json"))?;
    let started = Instant::now();
    let mut result = CaseResult {
        case: "Q-SMOKE".into(), binary_sha256: executable_sha256()?, verdict: Verdict::AssumptionHolds, iterations: 0,
        detail: "ABI layout evidence, guard refusal, independent dead-man ack, restore actions/available static observations unchanged and 1000 stable boot UUID reads; no native assumptions promoted".into(),
        evidence: Vec::new(),
    };
    let smoke = smoke_checks(out, &mut result, started);
    if let Err(error) = smoke {
        result.verdict = if error.is::<EnvironmentIssue>() {
            Verdict::Inconclusive
        } else {
            Verdict::ContractViolation
        };
        result.detail = error.to_string();
    } else if !baseline.inconclusive.is_empty() {
        result.verdict = Verdict::Inconclusive;
        result.detail = baseline.inconclusive.join("; ");
    }
    save_case(out, &result)?;
    let captured = capture(out)?;
    write_json(out, "verdicts.json", &json!([&result, &captured]))?;
    if result.verdict == Verdict::ContractViolation {
        return Err("Q-SMOKE contract violation; see case evidence".into());
    }
    Ok(())
}

fn smoke_checks(out: &Path, result: &mut CaseResult, started: Instant) -> Result<()> {
    let probe = probe_path()?;
    let abi = invoke(probe.to_str().ok_or("non-UTF8 probe path")?, &[]);
    let complete = abi.complete();
    let parsed = serde_json::from_str::<Value>(&abi.stdout);
    result.evidence.push(abi);
    if !complete {
        return Err(environment_issue(
            "SDK ABI probe failed; see command evidence",
        ));
    }
    let abi = parsed?;
    for name in [
        "kinfo_proc",
        "proc_bsdinfo",
        "proc_fdinfo",
        "socket_fdinfo",
        "rt_msghdr2",
        "kern_ctl_info",
        "vnode_info_path",
    ] {
        if abi[name]["size"].as_u64().is_none_or(|size| size == 0)
            || !abi[name]["fields"].is_object()
        {
            return Err(format!("ABI probe missing size/fields for {name}").into());
        }
    }
    write_json(out, "abi.json", &abi)?;
    let exe = std::env::current_exe()?;
    let refused = invoke(
        exe.to_str().ok_or("non-UTF8 executable path")?,
        &[
            "preflight",
            "--out",
            out.to_str().ok_or("non-UTF8 artifact path")?,
        ],
    );
    let guard_works = refused.exit_code == Some(1)
        && refused.stderr.contains("--disposable-runner")
        && !refused.timed_out
        && !refused.truncated;
    result.evidence.push(refused);
    if !guard_works {
        return Err(
            "missing --disposable-runner did not produce the required guard refusal".into(),
        );
    }
    let ack = require_ack(out).map_err(environment_issue)?;
    write_json(out, "smoke-ack.json", &ack)?;
    let deadline = started + Duration::from_secs(180);
    let first = restore(out, deadline)?;
    write_json(out, "smoke-restore-first.json", &first)?;
    let second = restore(out, deadline)?;
    write_json(out, "smoke-restore-second.json", &second)?;
    let comparison = restore_check::compare(
        &RestoreEffects {
            already_restored: first.already_restored,
            network_mutations: &first.network_mutations,
            writer_stop_count: first.writer_stop_evidence.len(),
            observations: &first.post_state.observations,
        },
        &RestoreEffects {
            already_restored: second.already_restored,
            network_mutations: &second.network_mutations,
            writer_stop_count: second.writer_stop_evidence.len(),
            observations: &second.post_state.observations,
        },
    );
    write_json(out, "smoke-restore-comparison.json", &comparison)?;
    if !comparison.violations.is_empty() {
        return Err(format!(
            "restore idempotence contract violation: {}; see smoke-restore-comparison.json",
            comparison.violations.join("; ")
        )
        .into());
    }
    // Optional inventory failures stay diagnostic. Incomplete pf observations
    // prevent an idempotence verdict even when they do not gate preflight.
    if comparison
        .unavailable_observations
        .iter()
        .any(|name| name.starts_with("pf-"))
    {
        result.verdict = Verdict::Inconclusive;
        result.detail = format!(
            "restore comparison incomplete: {:?}; see smoke-restore-comparison.json",
            comparison.unavailable_observations
        );
    }
    if !first.post_state.inconclusive.is_empty() || !second.post_state.inconclusive.is_empty() {
        result.verdict = Verdict::Inconclusive;
        result.detail = format!(
            "restore observation incomplete: first={:?}; second={:?}",
            first.post_state.inconclusive, second.post_state.inconclusive
        );
    }
    boot_reads(out, result, started)
}

fn boot_reads(out: &Path, result: &mut CaseResult, started: Instant) -> Result<()> {
    let boot = scupper_darwin::sysctl_string("kern.bootsessionuuid").map_err(environment_issue)?;
    if !valid_uuid(&boot) {
        return Err("kern.bootsessionuuid is not a valid UUID".into());
    }
    let mut reads = Vec::with_capacity(1000);
    let mut journal = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(out.join("boot-reads.jsonl"))?;
    for iteration in 0..1000 {
        if started.elapsed() >= Duration::from_secs(180) {
            return Err(environment_issue(
                "Q-SMOKE exceeded its three-minute case deadline",
            ));
        }
        writeln!(
            journal,
            "{}",
            json!({"iteration": iteration, "event": "started", "elapsed_ms": started.elapsed().as_millis()})
        )?;
        let value = scupper_darwin::sysctl_string("kern.bootsessionuuid");
        let observation = json!({"iteration": iteration, "elapsed_ms": started.elapsed().as_millis(), "result": value.as_ref().map(String::as_str).map_err(ToString::to_string)});
        writeln!(journal, "{observation}")?;
        reads.push(observation);
        if value.map_err(environment_issue)? != boot {
            return Err("boot-session UUID changed within the smoke case".into());
        }
        result.iterations += 1;
    }
    write_json(out, "boot-reads.json", &reads)?;
    write_json(
        out,
        "sysctl-strings.json",
        &json!({
            "kern.bootsessionuuid": boot,
            "kern.osversion": scupper_darwin::sysctl_string("kern.osversion").map_err(|error| error.to_string()),
            "kern.uuid": scupper_darwin::sysctl_string("kern.uuid").map_err(|error| error.to_string()),
            "hw.machine": scupper_darwin::sysctl_string("hw.machine").map_err(|error| error.to_string()),
            // This OID is an integer, not a string: its raw command result (and
            // expected ENOENT on native arm64) lives in preflight/capture.
            "sysctl.proc_translated": "see preflight.json and capture.json"
        }),
    )?;
    Ok(())
}

fn restore_checked(out: &Path) -> Result<()> {
    let result = restore(out, Instant::now() + Duration::from_secs(90))?;
    let prior = out.join("Q-RESTORE.json");
    let earlier_violation =
        prior.exists() && read_json::<CaseResult>(&prior)?.verdict == Verdict::ContractViolation;
    let violation = !result.violations.is_empty() || earlier_violation;
    save_case(
        out,
        &CaseResult {
            case: "Q-RESTORE".into(),
            binary_sha256: executable_sha256()?,
            verdict: if violation {
                Verdict::ContractViolation
            } else {
                Verdict::AssumptionHolds
            },
            iterations: 1,
            detail: if violation {
                format!(
                    "earlier_violation={earlier_violation}; {}",
                    result.violations.join("; ")
                )
            } else {
                "restored journaled resources; required post-state equals preflight".into()
            },
            evidence: Vec::new(),
        },
    )?;
    if violation {
        return Err("restore post-state contract violation; see Q-RESTORE.json".into());
    }
    Ok(())
}

fn run_probes(out: &Path, group: &str) -> Result<()> {
    let manifest = Manifest::bundled()?;
    if !manifest.budgets_fit() {
        return Err("manifest exceeds harness budget".into());
    }
    let failures = super::probe::run_all(
        super::probe::NAMES
            .into_iter()
            .filter(|name| (*name == "dns-default") == (group == "probe-hijack")),
        |name| run_probe(out, name),
        || probe_restore_checks(out, "final", Instant::now() + Duration::from_secs(90)),
    );
    write_json(out, "probe-cell-failures.json", &failures)?;
    if failures.is_empty() {
        Ok(())
    } else {
        Err(format!("probe cell failures: {}", failures.join("; ")).into())
    }
}

fn run_probe(out: &Path, name: &str) -> Result<()> {
    let started = Instant::now();
    if !super::probe::NAMES.contains(&name) {
        return Err("unknown probe".into());
    }
    let case = format!("Q-PROBE-{}", name.to_ascii_uppercase());
    if out.join(format!("{case}.json")).exists() {
        return Err("probe already recorded; use a fresh evidence directory for a rerun".into());
    }
    let mut result = CaseResult {
        case,
        binary_sha256: executable_sha256()?,
        verdict: Verdict::Inconclusive,
        iterations: 0,
        detail: "prerequisite unavailable".into(),
        evidence: Vec::new(),
    };
    let scope = out.join(format!("scope-{name}"));
    if let Err(error) = measure_probe(out, &scope, name, &mut result) {
        result.verdict = Verdict::ContractViolation;
        result.detail = format!("probe failed: {error}");
    }
    let save_error = save_case(out, &result).err();
    // Restore even when execution, output decoding or classification failed.
    if scope.join("preflight.json").exists() {
        let deadline = started + Duration::from_secs(if name == "dns-default" { 60 } else { 120 });
        if let Err(error) = probe_restore_checks(&scope, name, deadline) {
            result.verdict = Verdict::ContractViolation;
            result.detail = format!("{}; probe restore failed: {error}", result.detail);
        }
    }
    if let Some(error) = save_error {
        result.verdict = Verdict::ContractViolation;
        result.detail = format!("{}; saving probe evidence failed: {error}", result.detail);
    }
    save_case(out, &result)?;
    if result.verdict == Verdict::ContractViolation {
        return Err(result.detail.into());
    }
    Ok(())
}

fn measure_probe(out: &Path, scope: &Path, name: &str, result: &mut CaseResult) -> Result<()> {
    require_ack(out)?;
    let before: Snapshot = read_json(&out.join("preflight.json"))?;
    let problems = probe_prerequisites(&before);
    if !problems.is_empty() {
        result.detail = problems.join("; ");
        return Ok(());
    }
    let bin = std::env::current_exe()?.with_file_name(format!("probe-{name}"));
    protected_path(&bin, false)?;
    let wg = std::env::current_exe()?.with_file_name("wireguard-go");
    if matches!(name, "proc-identity" | "utun-handoff") {
        protected_path(&wg, false)?;
    }
    fs::DirBuilder::new().mode(0o700).create(scope)?;
    write_json(scope, "writers.json", &Vec::<Writer>::new())?;
    write_json(scope, "preflight.json", &before)?;
    write_json(
        out,
        &format!("probe-identity-{name}.json"),
        &json!({
            "name": name, "sha256": format!("{:x}", Sha256::digest(fs::read(&bin)?)),
            "wireguard_sha256": if matches!(name, "proc-identity" | "utun-handoff") { Some(format!("{:x}", Sha256::digest(fs::read(&wg)?))) } else { None },
        }),
    )?;
    let args = [
        scope.to_str().ok_or("invalid output path")?,
        wg.to_str().ok_or("invalid wireguard path")?,
    ];
    let count = if matches!(name, "proc-identity" | "utun-handoff") {
        2
    } else {
        1
    };
    let evidence = command(
        bin.to_str().ok_or("invalid probe path")?,
        &args[..count],
        None,
        Duration::from_secs(if name == "dns-default" { 10 } else { 90 }),
    );
    let classification = classify_probe(out, name, &evidence, result);
    result.evidence.push(evidence);
    classification
}

fn classify_probe(
    out: &Path,
    name: &str,
    evidence: &Evidence,
    result: &mut CaseResult,
) -> Result<()> {
    let parsed = serde_json::from_str::<Value>(&evidence.stdout);
    let pf_violation = matches!(name, "pf-starters" | "pf-eexist")
        && parsed
            .as_ref()
            .is_ok_and(super::probe::pf_contract_violation);
    if evidence.complete() {
        if let Ok(value) = &parsed {
            if let Ok(questions) = super::probe::questions(value) {
                result.verdict = Verdict::Measurement;
                result.iterations = 1;
                result.detail = "raw C capability measurement; no assumption promotion; question verdicts are separate artifacts".into();
                for (id, verdict, iterations) in questions {
                    let verdict = if pf_violation && id == "Q-REFS-readonly" {
                        Verdict::ContractViolation
                    } else {
                        verdict
                    };
                    save_case(
                        out,
                        &CaseResult {
                            case: id,
                            binary_sha256: executable_sha256()?,
                            verdict,
                            iterations,
                            detail: format!(
                                "bounded hypothesis tested by {name}; see {}.json for raw observations; does not qualify a build",
                                result.case
                            ),
                            evidence: Vec::new(),
                        },
                    )?;
                }
                if name == "pf-starters" {
                    let (verdict, iterations) = super::probe::pf_size_query(value);
                    save_case(out, &CaseResult {
                        case: "Q-REFS-size-query".into(), binary_sha256: executable_sha256()?, verdict, iterations,
                        detail: "zero-capacity size queries recorded separately from token copies; returned allocation size must contain whole records".into(), evidence: Vec::new(),
                    })?;
                    save_case(out, &CaseResult { case: "Q-REFS-layout".into(), binary_sha256: executable_sha256()?, verdict: super::probe::pf_layout(value), iterations: super::probe::pf_read_count(value),
                        detail: "84-byte stride, 16-byte request, ioctl number and nonzero-capacity size/order observations compared with whole-record newest-first copy-loop hypothesis".into(), evidence: Vec::new() })?;
                }
            } else {
                result.detail = "malformed question output; never qualifies".into();
            }
        } else {
            result.detail = "probe did not emit one complete JSON object".into();
        }
    } else {
        result.detail =
            "probe failed, exceeded its internal deadline, or produced incomplete output".into();
    }
    if pf_violation {
        result.verdict = Verdict::ContractViolation;
        result.detail =
            "pf probe ABI contract violation: O_RDONLY EACCES or ENODEV; see raw observations"
                .into();
    }
    Ok(())
}

fn probe_prerequisites(before: &Snapshot) -> Vec<String> {
    let mut problems = before.inconclusive.clone();
    for key in restore_check::REQUIRED {
        if before.observations.get(key).is_none_or(|e| !e.complete()) {
            problems.push(format!("missing complete preflight {key}"));
        }
    }
    if restore_check::pf_status(&before.observations).is_none() {
        problems.push("unknown preflight pf status".into());
    }
    if !before
        .observations
        .get("scutil-keys")
        .is_some_and(restore_check::valid_key_list)
    {
        problems.push("unrecognized scutil key inventory".into());
    }
    if before.observations.get("scutil-keys").is_some_and(|e| {
        restore_check::key_list(&e.stdout)
            .iter()
            .any(|key| key.starts_with("State:/Network/Service/scupper-qual-"))
    }) {
        problems.push("pre-existing harness SystemConfiguration key".into());
    }
    problems
}

fn probe_restore_checks(out: &Path, name: &str, deadline: Instant) -> Result<()> {
    let first = restore(out, deadline)?;
    let second = restore(out, deadline)?;
    let comparison = restore_check::compare(
        &RestoreEffects {
            already_restored: first.already_restored,
            network_mutations: &first.network_mutations,
            writer_stop_count: first.writer_stop_evidence.len(),
            observations: &first.post_state.observations,
        },
        &RestoreEffects {
            already_restored: second.already_restored,
            network_mutations: &second.network_mutations,
            writer_stop_count: second.writer_stop_evidence.len(),
            observations: &second.post_state.observations,
        },
    );
    write_json(out, &format!("restore-{name}-comparison.json"), &comparison)?;
    if !first.violations.is_empty()
        || !second.violations.is_empty()
        || !comparison.violations.is_empty()
    {
        return Err(format!(
            "restore contract violation: {:?}; {:?}; {:?}",
            first.violations, second.violations, comparison.violations
        )
        .into());
    }
    Ok(())
}
