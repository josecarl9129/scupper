//! Write-ahead fixture recovery, used by both the dead-man and always-step.
use super::{
    Result, Snapshot, TOOL_BUDGET, Writer, command, invoke_before, protected_path, restore_check,
    unique, unix_seconds, write_json,
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fmt::Write as _,
    fs,
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::Path,
    thread,
    time::{Duration, Instant},
};

use super::super::journal::{self, Entry};
use super::super::recovery::Completed;
use crate::decode::pfanchor::{Commands, Operation, Text};

fn completed(out: &Path) -> Result<Completed> {
    let path = out.join("completed-resources.json");
    if path.exists() {
        super::read_json(&path)
    } else {
        Ok(Completed::default())
    }
}

fn update_completed(
    out: &Path,
    deadline: Instant,
    update: impl FnOnce(&mut Completed),
) -> Result<()> {
    let _lock = lock(out, "completion.lock", deadline)?;
    let mut state = completed(out)?;
    update(&mut state);
    write_json(out, "completed-resources.json", &state)
}

pub(super) fn writer_completed(out: &Path, writer: &Writer) -> Result<bool> {
    Ok(completed(out)?.writers.contains(writer))
}

pub(super) fn complete_writer(out: &Path, writer: Writer, deadline: Instant) -> Result<()> {
    let entries = entries(out)?;
    update_completed(out, deadline, |state| {
        state.writer_stopped(writer, &entries);
    })
}

pub(super) fn remaining(out: &Path) -> Result<usize> {
    let state = completed(out)?;
    let controllers: Vec<Writer> = super::read_json(&out.join("writers.json"))?;
    Ok(state.pending(entries(out)?).len()
        + controllers
            .iter()
            .filter(|writer| writer.pid != std::process::id() && !state.writers.contains(writer))
            .count())
}

fn writers_quiescent(out: &Path) -> Result<bool> {
    let state = completed(out)?;
    let mut writers: Vec<Writer> = super::read_json(&out.join("writers.json"))?;
    writers.extend(
        entries(out)?
            .into_iter()
            .filter(|e| matches!(e.kind.as_str(), "probe" | "child" | "pf-acquire"))
            .map(|e| Writer {
                pid: e.pid,
                start: e.start,
            }),
    );
    Ok(writers
        .iter()
        .all(|writer| writer.pid == std::process::id() || state.writers.contains(writer)))
}

pub(super) fn quiescent(out: &Path, deadline: Instant) -> Result<bool> {
    Ok(super::tool::jobs_absent(out, deadline)?
        && super::pf::groups_gone(out)?
        && writers_quiescent(out)?)
}

pub(super) fn entries(out: &Path) -> Result<Vec<Entry>> {
    let path = out.join("resources.jsonl");
    if !path.exists() {
        return Ok(Vec::new());
    }
    protected_path(&path, false)?;
    Ok(journal::committed(&fs::read_to_string(path)?)?)
}

pub(super) fn journaled_keys(out: &Path) -> Result<Vec<String>> {
    Ok(entries(out)?
        .into_iter()
        .filter(|e| e.kind == "key")
        .map(|e| e.path)
        .collect())
}

pub(super) fn writers(out: &Path, probes_only: bool) -> Result<Vec<Writer>> {
    Ok(completed(out)?
        .pending(entries(out)?)
        .into_iter()
        .map(|(_, e)| e)
        .filter(|e| {
            if probes_only {
                e.kind == "probe"
            } else {
                matches!(e.kind.as_str(), "probe" | "child" | "pf-acquire")
            }
        })
        .map(|e| Writer {
            pid: e.pid,
            start: e.start,
        })
        .collect())
}

pub(super) fn restore_lock(out: &Path, deadline: Instant) -> Result<fs::File> {
    lock(out, "restore.lock", deadline)
}

fn lock(out: &Path, name: &str, deadline: Instant) -> Result<fs::File> {
    let lock = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .open(out.join(name))?;
    loop {
        match rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => return Ok(lock),
            Err(error) if error == rustix::io::Errno::WOULDBLOCK && Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(20));
            }
            Err(error) => return Err(error.into()),
        }
    }
}

fn action(
    out: &Path,
    program: &str,
    args: &[&str],
    deadline: Instant,
    actions: &mut Vec<String>,
    failures: &mut Vec<String>,
) {
    let evidence = invoke_before(program, args, deadline);
    let label = std::iter::once(program)
        .chain(args.iter().copied())
        .collect::<Vec<_>>()
        .join(" ");
    actions.push(label.clone());
    if !evidence.complete() {
        failures.push(format!("restore action failed: {label}"));
    }
    if let Err(error) = write_json(out, &format!("{}.json", unique("undo")), &evidence) {
        failures.push(format!("restore evidence failed: {label}: {error}"));
    }
}

fn ioctl_inventory(out: &Path, deadline: Instant) -> Result<Vec<journal::Token>> {
    let bin = std::env::current_exe()?.with_file_name("probe-pf-starters");
    protected_path(&bin, false)?;
    let evidence = invoke_before(
        bin.to_str().ok_or("invalid inventory path")?,
        &[out.to_str().ok_or("invalid out")?, "--inventory"],
        deadline,
    );
    write_json(
        out,
        &format!("{}.json", unique("token-inventory")),
        &evidence,
    )?;
    if !evidence.complete() {
        return Err("cannot execute ioctl token inventory".into());
    }
    let value: Value = serde_json::from_str(&evidence.stdout)?;
    Ok(journal::ioctl_tokens(&value)?)
}

fn live_tokens(out: &Path, deadline: Instant) -> Result<Vec<journal::Token>> {
    let ioctl_error = match ioctl_inventory(out, deadline) {
        Ok(tokens) => return Ok(tokens),
        Err(error) => error.to_string(),
    };
    let evidence = invoke_before("/sbin/pfctl", &["-s", "References"], deadline);
    write_json(
        out,
        &format!("{}.json", unique("token-inventory-fallback")),
        &json!({"ioctl_problem": ioctl_error, "pfctl": evidence}),
    )?;
    if !evidence.complete() {
        return Err(format!("ioctl: {ioctl_error}; pfctl References unavailable").into());
    }
    let build = crate::decode::pftext::Build::system()
        .map_err(|e| super::environment_issue(format!("OS build unavailable: {e:?}")))?;
    super::super::journal::live_text_tokens(&build, &evidence, unix_seconds())
        .map_err(|error| format!("ioctl: {ioctl_error}; pfctl References: {error}").into())
}

fn attached_devices(out: &Path, paths: &[&str], deadline: Instant) -> Result<Vec<String>> {
    if paths.is_empty() {
        return Ok(Vec::new());
    }
    let info = invoke_before("/usr/bin/hdiutil", &["info", "-plist"], deadline);
    write_json(out, &format!("{}.json", unique("image-inventory")), &info)?;
    if !info.complete() {
        return Err("cannot inventory attached images".into());
    }
    let parsed = command(
        "/usr/bin/plutil",
        &["-convert", "json", "-o", "-", "-"],
        Some(&info.stdout),
        TOOL_BUDGET.min(deadline.saturating_duration_since(Instant::now())),
    );
    write_json(out, &format!("{}.json", unique("image-plist")), &parsed)?;
    if !parsed.complete() {
        return Err("cannot parse image inventory".into());
    }
    let json: Value = serde_json::from_str(&parsed.stdout)?;
    let mut devices = Vec::new();
    for image in json["images"].as_array().ok_or("missing images array")? {
        let path = image["image-path"]
            .as_str()
            .ok_or("attached image has no path")?;
        if !paths.contains(&path) {
            continue;
        }
        let device = image["system-entities"]
            .as_array()
            .and_then(|entities| {
                entities
                    .iter()
                    .find_map(|entity| entity["dev-entry"].as_str())
            })
            .ok_or("attached fixture image has no device")?;
        if !device.starts_with("/dev/disk")
            || !device[9..].bytes().all(|b| b.is_ascii_digit() || b == b's')
        {
            return Err("invalid fixture image device".into());
        }
        devices.push(device.into());
    }
    Ok(devices)
}

/// Restore the journaled disabled baseline using live build-qualified status.
fn undo_pf_state(
    out: &Path,
    deadline: Instant,
    actions: &mut Vec<String>,
    failures: &mut Vec<String>,
) {
    let info = invoke_before("/sbin/pfctl", &["-s", "info"], deadline);
    let osversion = invoke_before("/usr/sbin/sysctl", &["-n", "kern.osversion"], deadline);
    let current = BTreeMap::from([("pf-info".into(), info), ("osversion".into(), osversion)]);
    if let Err(error) = write_json(
        out,
        &format!("{}.json", unique("restore-pf-status")),
        &current,
    ) {
        failures.push(format!("restore pf status capture failed: {error}"));
    }
    match restore_check::restore_disable(&current) {
        Ok(true) => {
            action(out, "/sbin/pfctl", &["-d"], deadline, actions, failures);
        }
        Ok(false) => {}
        Err(reason) => {
            failures.push(reason.into());
            // Unknown still permits deliberate restoration toward the disabled baseline.
            // Only the later complete state check can prove Disabled.
            action(out, "/sbin/pfctl", &["-d"], deadline, actions, failures);
        }
    }
}

#[allow(clippy::too_many_lines)] // Restore follows the dependency order: stop writers, release, anchors, images, interfaces.
pub(super) fn undo(
    out: &Path,
    before: &Snapshot,
    deadline: Instant,
    restore_pf_state: bool,
    mut campaign_quiescent: impl FnMut() -> Result<bool>,
) -> Result<(Vec<String>, Vec<String>)> {
    repair_tail(out)?;
    let pending = completed(out)?.pending(entries(out)?);
    if pending.is_empty() && !restore_pf_state {
        return Ok((Vec::new(), Vec::new()));
    }
    let mut actions = Vec::new();
    let mut failures = Vec::new();
    // Validate the protected native journal before the portable boundary reads it.
    entries(out)?;
    let step_failures = super::super::resources::undo(
        out,
        &mut campaign_quiescent,
        || super::tool::jobs_absent(out, deadline),
        || Ok(super::pf::groups_gone(out)? && writers_quiescent(out)?),
        |step, pending| -> Result<()> {
            let entries: Vec<_> = pending.iter().map(|(_, e)| e.clone()).collect();
            // Stop failures are recorded by the caller; a fresh census still
            // controls destructive work. Independent steps are always visited.
            if !super::pf::groups_gone(out)? || !writers_quiescent(out)? {
                return Err(format!("{step}: writers not quiescent; cleanup withheld").into());
            }
            match step {
                "tools" => {
                    super::tool::restore(out, &entries, deadline, &mut actions, &mut failures);
                }
                "tokens" => undo_tokens(out, &entries, deadline, &mut actions, &mut failures),
                "anchors" => {
                    // Journaled configuration only; a scoped flush creates a missing name.
                    let mut seen = std::collections::BTreeSet::new();
                    for e in entries.iter().filter(|e| e.kind == "anchor") {
                        if !seen.insert(e.path.clone()) {
                            continue;
                        }
                        if !matches!(
                            e.path.as_str(),
                            "scupper-qual/scupper"
                                | "com.apple/scupper"
                                | "com.apple/scupper-qual"
                                | "scupper-qual/children"
                        ) && !e.path.starts_with("scupper-qual/children/")
                        {
                            failures.push("unrecognized fixture anchor".into());
                            continue;
                        }
                        let path = crate::decode::pfanchor::AnchorPath::new(&e.path)?;
                        if let Err(error) = recheck_foreign_tokens(out, deadline) {
                            failures.push(format!("anchor restore withheld: {error}"));
                            continue;
                        }
                        let mut io = AnchorInventory::new(out, deadline, &e.path);
                        if crate::decode::pfanchor::read(&mut io, &path)
                            .is_ok_and(|text| text.is_none())
                        {
                            continue;
                        }
                        let mut targets = if e.path == "scupper-qual/children"
                            || e.path.starts_with("scupper-qual/children/")
                        {
                            match measurement_paths(&mut io, &e.path) {
                                Ok(paths) => paths,
                                Err(error) => {
                                    failures.push(format!(
                                        "measurement subtree restore withheld: {error}"
                                    ));
                                    continue;
                                }
                            }
                        } else {
                            vec![e.path.clone()]
                        };
                        if e.path == super::super::desc_inventory::ROOT {
                            targets.extend(
                                entries
                                    .iter()
                                    .filter(|e| {
                                        e.kind == "anchor-target"
                                            && super::super::desc_inventory::target_path(&e.path)
                                    })
                                    .map(|e| e.path.clone()),
                            );
                            targets.sort();
                            targets.dedup();
                        }
                        for target in targets.iter().rev() {
                            if e.path == super::super::desc_inventory::ROOT {
                                match scupper_darwin::qual_pf_rulesets(target) {
                                    Ok(None) => continue,
                                    Ok(Some(_)) => (),
                                    Err(error) => {
                                        failures.push(format!(
                                            "anchor restore census: {target}: {error}"
                                        ));
                                        continue;
                                    }
                                }
                            }
                            // Recovery tries every class even when a previous flush failed.
                            for (op, class) in [
                                (Operation::Rules, "rules"),
                                (Operation::Nat, "nat"),
                                (Operation::Tables, "Tables"),
                                (Operation::Dummynet, "dummynet"),
                            ] {
                                actions.push(format!("/sbin/pfctl -a {target} -F {class}"));
                                if let Err(error) = io.call(op, &["-a", target, "-F", class], &[]) {
                                    failures.push(format!(
                                        "anchor restore {class}: {target} {error:?}"
                                    ));
                                }
                            }
                        }
                        if !crate::decode::pfanchor::read(&mut io, &path)
                            .is_ok_and(|text| text.is_none())
                        {
                            failures.push(format!(
                                "anchor configuration absence not established: {}",
                                e.path
                            ));
                        }
                    }
                }
                "pf state" => {
                    if restore_pf_state
                        && restore_check::pf_status(&before.observations) == Some(false)
                    {
                        if let Err(error) = recheck_foreign_tokens(out, deadline) {
                            failures.push(format!("pf disable withheld: {error}"));
                        } else {
                            undo_pf_state(out, deadline, &mut actions, &mut failures);
                        }
                    }
                }
                "keys" => undo_keys(out, &entries, deadline, &mut actions, &mut failures)?,
                "resolver" => undo_resolver_clone(
                    out,
                    before,
                    &entries,
                    deadline,
                    &mut actions,
                    &mut failures,
                )?,
                "images" => {
                    // Holder processes were killed by exact pid/start before any cleanup.
                    // Images are matched by their recorded path, never a guessed disk number.
                    let paths: Vec<_> = entries
                        .iter()
                        .filter(|e| e.kind == "image")
                        .map(|e| e.path.as_str())
                        .collect();
                    match attached_devices(out, &paths, deadline) {
                        Ok(devices) => {
                            for device in devices {
                                detach_device(out, &device, deadline, &mut actions, &mut failures);
                            }
                        }
                        Err(error) => failures.push(error.to_string()),
                    }
                }
                "store tree" => {
                    let paths: Vec<_> = entries
                        .iter()
                        .filter(|e| e.kind == "image")
                        .map(|e| e.path.as_str())
                        .collect();
                    if entries.iter().any(|e| e.kind == "r5-tree") && writers_quiescent(out)? {
                        match attached_devices(out, &paths, deadline) {
                            Ok(devices) if devices.is_empty() => {
                                super::store::restore_tree(
                                    out,
                                    &entries,
                                    &mut actions,
                                    &mut failures,
                                );
                            }
                            _ => failures.push(
                                "R5 images not proven detached; fixture tree retained".into(),
                            ),
                        }
                    }
                }
                "loopback" => {
                    if entries.iter().any(|e| e.kind == "loopback-alias") {
                        let interfaces = invoke_before("/sbin/ifconfig", &["lo0"], deadline);
                        if interfaces.complete()
                            && interfaces.stdout.lines().any(|line| {
                                line.split_whitespace().take(2).eq(["inet", "127.0.0.53"])
                            })
                        {
                            action(
                                out,
                                "/sbin/ifconfig",
                                &["lo0", "-alias", "127.0.0.53"],
                                deadline,
                                &mut actions,
                                &mut failures,
                            );
                        }
                    }
                }
                "child staging" => restore_child(out)?,
                "sockets" => {
                    for e in entries.iter().filter(|e| e.kind == "socket") {
                        if e.path.starts_with("/var/run/wireguard/utun")
                            && Path::new(&e.path)
                                .extension()
                                .is_some_and(|ext| ext == "sock")
                            && !e.path.contains("..")
                            && Path::new(&e.path).exists()
                        {
                            match fs::remove_file(&e.path) {
                                Ok(()) => actions.push(format!("unlink {}", e.path)),
                                Err(error) => {
                                    failures.push(format!("socket restore {}: {error}", e.path));
                                }
                            }
                        }
                    }
                }
                "feth" => {
                    for e in entries.iter().filter(|e| e.kind == "feth") {
                        if !matches!(e.path.as_str(), "feth0" | "feth1") {
                            failures.push("invalid feth journal entry".into());
                            continue;
                        }
                        if let Err(error) = recheck_foreign_tokens(out, deadline) {
                            failures.push(format!("feth restore withheld: {error}"));
                            continue;
                        }
                        let inventory = invoke_before("/sbin/ifconfig", &["-l"], deadline);
                        if !inventory.complete() {
                            failures.push("feth inventory incomplete".into());
                            continue;
                        }
                        if inventory
                            .stdout
                            .split_whitespace()
                            .any(|name| name == e.path)
                        {
                            action(
                                out,
                                "/sbin/ifconfig",
                                &[&e.path, "destroy"],
                                deadline,
                                &mut actions,
                                &mut failures,
                            );
                        }
                    }
                }
                _ => complete_from_inventory(out, pending, deadline, &mut failures)?,
            }
            Ok(())
        },
    )?;
    failures.extend(step_failures);
    Ok((actions, failures))
}

fn complete_from_inventory(
    out: &Path,
    pending: &[(usize, Entry)],
    deadline: Instant,
    failures: &mut Vec<String>,
) -> Result<()> {
    // Only complete entries after a complete inventory verifies absence. An
    // action's success alone cannot prove that no fixture resource remains.
    if !writers_quiescent(out)? {
        return Ok(());
    }
    let entries: Vec<_> = pending.iter().map(|(_, e)| e.clone()).collect();
    let paths: Vec<_> = entries
        .iter()
        .filter(|e| e.kind == "image")
        .map(|e| e.path.as_str())
        .collect();
    let mut verified = Vec::new();
    if entries
        .iter()
        .any(|e| matches!(e.kind.as_str(), "token" | "pf-acquire"))
    {
        match live_tokens(out, deadline) {
            Ok(tokens) => {
                for (index, entry) in pending {
                    if matches!(entry.kind.as_str(), "token" | "pf-acquire")
                        && !tokens.iter().any(|token| {
                            journal::owns_token(
                                std::slice::from_ref(entry),
                                token.value,
                                token.pid,
                                token.timestamp,
                                unix_seconds(),
                            )
                        })
                        && (entry.kind != "pf-acquire"
                            || writer_completed(
                                out,
                                &Writer {
                                    pid: entry.pid,
                                    start: entry.start.clone(),
                                },
                            )?)
                    {
                        verified.push(*index);
                    }
                }
            }
            Err(error) => failures.push(format!("token completion inventory: {error}")),
        }
    }
    if !paths.is_empty() {
        match attached_devices(out, &paths, deadline) {
            Ok(devices) if devices.is_empty() => verified.extend(
                pending
                    .iter()
                    // The mount intent belongs to this fixture image too;
                    // detachment proves that it cannot remain mounted.
                    .filter(|(_, e)| matches!(e.kind.as_str(), "image" | "mount"))
                    .map(|(index, _)| *index),
            ),
            Ok(_) => failures.push("fixture image remains attached".into()),
            Err(error) => failures.push(format!("image completion inventory: {error}")),
        }
    }
    update_completed(out, deadline, |state| state.entries.extend(verified))?;
    Ok(())
}

pub(super) fn complete_from_snapshot(
    out: &Path,
    post: &Snapshot,
    deadline: Instant,
    snapshot_quiescent: bool,
    empty_anchor_names: &[String],
) -> Result<()> {
    if !writers_quiescent(out)? {
        return Ok(());
    }
    let pending = completed(out)?.pending(entries(out)?);
    let mut verified = Vec::new();
    for (index, entry) in pending {
        let absent = match entry.kind.as_str() {
            "anchor" => snapshot_quiescent && empty_anchor_names.contains(&entry.path),
            "anchor-target" => {
                snapshot_quiescent
                    && super::super::desc_inventory::target_path(&entry.path)
                    && empty_anchor_names
                        .iter()
                        .any(|name| name == super::super::desc_inventory::ROOT)
            }
            "feth" => {
                let list = invoke_before("/sbin/ifconfig", &["-l"], deadline);
                list.complete()
                    && !list
                        .stdout
                        .split_whitespace()
                        .any(|name| name == entry.path)
            }
            "r6-group" => snapshot_quiescent && super::pf::groups_gone(out)?,
            "r6-pf" => {
                snapshot_quiescent
                    && super::pf::groups_gone(out)?
                    && super::super::restore_check::pf_status(&post.observations) == Some(false)
                    && post.observations.get("pf-references").is_some_and(|e| {
                        e.complete()
                            && super::super::guard::pf_build(&post.observations).is_some_and(
                                |build| {
                                    super::super::guard::no_foreign_references(
                                        &build, &e.stdout, &e.stderr,
                                    )
                                },
                            )
                    })
            }
            "key" => post.observations.get("scutil-keys").is_some_and(|keys| {
                restore_check::valid_key_list(keys)
                    && !restore_check::key_list(&keys.stdout).contains(&entry.path)
            }),
            "cloned-route" if entry.path == "127.0.0.53" => {
                post.observations.get("routes").is_some_and(|routes| {
                    routes.complete() && !restore_check::resolver_clone(&routes.stdout)
                })
            }
            "loopback-alias" if entry.path == "127.0.0.53" => {
                post.observations
                    .get("interfaces")
                    .is_some_and(|interfaces| {
                        interfaces.complete()
                            && !interfaces.stdout.lines().any(|line| {
                                line.split_whitespace().take(2).eq(["inet", "127.0.0.53"])
                            })
                    })
            }
            "r7-child-intent"
            | "r7-child-created"
            | "r7-child-dir-intent"
            | "r7-child-dir-created" => super::super::child_stage::absent(Path::new(&entry.path))?,
            "r4-wireguard-created" => fs::symlink_metadata(&entry.path)
                .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
            "r4-wireguard-sockets" => {
                fs::read_dir(&entry.path).is_ok_and(|mut entries| entries.next().is_none())
            }
            "r4-tree" | "r5-tree" => fs::symlink_metadata(&entry.path)
                .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
            "r4-job" => {
                let status = invoke_before("/bin/launchctl", &["print", &entry.path], deadline);
                super::super::jobs::absent(&status)
            }
            "socket" => fs::symlink_metadata(&entry.path)
                .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound),
            _ => false,
        };
        if absent {
            verified.push(index);
        }
    }
    if !verified.is_empty() {
        update_completed(out, deadline, |state| state.entries.extend(verified))?;
    }
    Ok(())
}

fn detach_device(
    out: &Path,
    device: &str,
    deadline: Instant,
    actions: &mut Vec<String>,
    failures: &mut Vec<String>,
) {
    struct Detach<'a> {
        out: &'a Path,
        device: &'a str,
        start: Instant,
        actions: &'a mut Vec<String>,
        problem: Option<String>,
    }
    impl super::super::detach::Io for Detach<'_> {
        fn elapsed(&self) -> Duration {
            self.start.elapsed()
        }
        fn pause(&mut self, delay: Duration) {
            thread::sleep(delay);
        }
        fn attempt(&mut self, force: bool, budget: Duration) -> super::super::detach::Outcome {
            let args = if force {
                vec!["detach", "-force", self.device]
            } else {
                vec!["detach", self.device]
            };
            let journal = |phase: &str, evidence: Option<&super::Evidence>| -> Result<()> {
                let mut file = fs::OpenOptions::new()
                    .append(true)
                    .create(true)
                    .mode(0o600)
                    .open(self.out.join("resources.jsonl"))?;
                writeln!(
                    file,
                    "{}",
                    json!({"kind":"detach-attempt","path":self.device,"force":force,"phase":phase,"elapsed_ms":self.start.elapsed().as_millis(),"evidence":evidence})
                )?;
                file.sync_all()?;
                Ok(())
            };
            if let Err(error) = journal("before", None) {
                self.problem = Some(error.to_string());
                return super::super::detach::Outcome {
                    success: false,
                    busy: false,
                };
            }
            let evidence = command("/usr/bin/hdiutil", &args, None, budget.min(TOOL_BUDGET));
            if let Err(error) = journal("after", Some(&evidence)) {
                self.problem = Some(error.to_string());
            }
            self.actions
                .push(format!("/usr/bin/hdiutil {}", args.join(" ")));
            let saved = write_json(
                self.out,
                &format!("{}.json", unique("undo-image")),
                &evidence,
            );
            if let Err(error) = saved {
                self.problem = Some(error.to_string());
            }
            super::super::detach::Outcome {
                success: evidence.complete() && self.problem.is_none(),
                busy: evidence.exit_code == Some(16) || evidence.stderr.contains("Resource busy"),
            }
        }
    }
    let mut io = Detach {
        out,
        device,
        start: Instant::now(),
        actions,
        problem: None,
    };
    let success =
        super::super::detach::run(&mut io, deadline.saturating_duration_since(Instant::now()));
    if let Some(error) = io.problem {
        failures.push(format!("detach journal failed: {error}"));
    }
    if !success {
        failures.push(format!(
            "fixture image detach exhausted 30s plain and 5s forced retries: {device}"
        ));
    }
}

/// Measurement/restore raw command session. Candidate parsing here grants no
/// native qualification; captures and final case verdict retain that distinction.
struct AnchorInventory<'a> {
    out: &'a Path,
    deadline: Instant,
    measurement_descendants: bool,
    descendant_paths: std::collections::BTreeSet<String>,
    last_read: String,
}
impl<'a> AnchorInventory<'a> {
    fn new(out: &'a Path, deadline: Instant, path: &str) -> Self {
        Self {
            out,
            deadline,
            measurement_descendants: path == "scupper-qual/children"
                || path.starts_with("scupper-qual/children/"),
            descendant_paths: std::collections::BTreeSet::default(),
            last_read: String::new(),
        }
    }
}
impl crate::decode::pfanchor::Commands for AnchorInventory<'_> {
    fn build(
        &self,
    ) -> std::result::Result<crate::decode::pftext::Build, crate::platform::SysError> {
        crate::decode::pftext::Build::system()
    }
    fn descendants_reviewed(&self) -> std::result::Result<bool, crate::platform::SysError> {
        // Harness-only absence/restore measurement; never native qualification.
        Ok(self.measurement_descendants
            || crate::decode::pfanchor::descendants_reviewed(&self.build()?))
    }
    fn call(
        &mut self,
        op: crate::decode::pfanchor::Operation,
        args: &[&str],
        _: &[u8],
    ) -> std::result::Result<crate::decode::pfanchor::Text, crate::platform::SysError> {
        if op == Operation::Inventory
            && args.len() == 3
            && args[1].starts_with("scupper-qual/children/")
        {
            self.descendant_paths.insert(args[1].to_owned());
        }
        self.last_read = format!("pfctl {}", args.join(" "));
        let evidence = invoke_before("/sbin/pfctl", args, self.deadline);
        write_json(
            self.out,
            &format!("{}.json", unique("anchor-inventory")),
            &evidence,
        )
        .map_err(|_| crate::platform::SysError::Unknown)?;
        if evidence.timed_out || evidence.truncated {
            return Err(crate::platform::SysError::Unknown);
        }
        let build = crate::decode::pftext::Build::system()?;
        let text = crate::decode::pfanchor::proposed(
            &build,
            if op == crate::decode::pfanchor::Operation::Filter {
                crate::decode::pfanchor::Operation::HarnessFilter
            } else {
                op
            },
            evidence
                .exit_code
                .ok_or(crate::platform::SysError::Unknown)?,
            evidence.stdout.as_bytes(),
            evidence.stderr.as_bytes(),
        )?;
        if self.measurement_descendants && op == Operation::Inventory {
            let parent = if args.len() == 3 { args[1] } else { "" };
            write!(
                &mut self.last_read,
                "; DIOCGETRULESETS/DIOCGETRULESET {parent}"
            )
            .map_err(|_| crate::platform::SysError::Unknown)?;
            let kernel = scupper_darwin::qual_pf_rulesets(parent);
            write_json(self.out, &format!("{}.json", unique("anchor-kernel-inventory")),
                &json!({"path":parent,"kernel":format!("{kernel:?}"),"text":format!("{text:?}"),"qualification_absence_only":true}))
                .map_err(|_| crate::platform::SysError::Unknown)?;
            return super::super::desc_inventory::merge(
                text,
                kernel.map_err(|_| crate::platform::SysError::Unknown)?,
                parent,
            );
        }
        Ok(text)
    }
}
// Cleanup authority is confined to the independently journaled disposable root.
fn measurement_paths(io: &mut AnchorInventory<'_>, root: &str) -> Result<Vec<String>> {
    let mut paths = Vec::new();
    let mut pending = vec![(root.to_owned(), 0)];
    let mut count = 1;
    while let Some((path, depth)) = pending.pop() {
        if scupper_darwin::qual_pf_rulesets(&path)?.is_none() {
            continue;
        }
        let Text::Present(text) = io.call(Operation::Inventory, &["-a", &path, "-sA"], &[])? else {
            return Err("incomplete measurement subtree inventory".into());
        };
        let children = crate::decode::pfanchor::inventory_at(&text, &path)?
            .into_iter()
            .map(str::to_owned)
            .collect::<std::collections::BTreeSet<_>>();
        for child in children {
            count += 1;
            if depth >= 8 || count > 64 {
                return Err("measurement subtree bound exceeded".into());
            }
            pending.push((format!("{path}/{child}"), depth + 1));
        }
        paths.push(path);
    }
    Ok(paths)
}
// Independent cleanup budget, even after the measurement case has expired.
pub(super) fn cleanup_measurement(out: &Path, root: &str) -> Result<()> {
    if root != super::super::desc_inventory::ROOT
        && !super::super::desc_inventory::target_path(root)
    {
        return Err("invalid measurement cleanup root".into());
    }
    let deadline = Instant::now() + Duration::from_secs(30);
    recheck_foreign_tokens(out, deadline)?;
    let mut io = AnchorInventory::new(out, deadline, root);
    let mut failures = Vec::new();
    let mut paths = match measurement_paths(&mut io, root) {
        Ok(paths) => paths,
        Err(error) => {
            failures.push(format!("cleanup enumeration incomplete: {error}"));
            vec![root.to_owned()]
        }
    };
    paths.extend(
        entries(out)?
            .into_iter()
            .filter(|e| {
                e.kind == "anchor-target"
                    && super::super::desc_inventory::target_path(&e.path)
                    && (e.path == root || e.path.starts_with(&format!("{root}/")))
            })
            .map(|e| e.path),
    );
    paths.sort();
    paths.dedup();
    for path in paths.iter().rev() {
        match scupper_darwin::qual_pf_rulesets(path) {
            Ok(None) => continue,
            Ok(Some(_)) => (),
            Err(error) => {
                failures.push(format!("{path}: cleanup kernel census: {error}"));
                continue;
            }
        }
        for (op, class) in [
            (Operation::Rules, "rules"),
            (Operation::Nat, "nat"),
            (Operation::Tables, "Tables"),
            (Operation::Dummynet, "dummynet"),
        ] {
            if let Err(error) = io.call(op, &["-a", path, "-F", class], &[]) {
                failures.push(format!("{path} {class}: {error}"));
            }
        }
    }
    let after = crate::decode::pfanchor::read(
        &mut io,
        &crate::decode::pfanchor::AnchorPath::new(super::super::desc_inventory::ROOT)?,
    );
    if after != Ok(None) {
        failures.push(format!("measurement absence: {after:?}"));
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; ").into())
    }
}
pub(super) fn anchor_read(
    out: &Path,
    path: &str,
    deadline: Instant,
) -> std::result::Result<Option<String>, crate::platform::SysError> {
    let path = crate::decode::pfanchor::AnchorPath::new(path)?;
    crate::decode::pfanchor::read(
        &mut AnchorInventory::new(out, deadline, path.as_str()),
        &path,
    )
}
/// Names allowed to persist in post-state inventories, only after complete
/// configuration reads. Parent namespaces created by a journaled child need
/// empty classes too; new siblings are still detected by the full inventory.
pub(super) fn restored_anchor_names(
    out: &Path,
    before: &Snapshot,
    deadline: Instant,
) -> Result<super::recovery::AnchorReads> {
    let paths = entries(out)?
        .into_iter()
        .filter(|e| e.kind == "anchor")
        .map(|e| e.path)
        .collect::<std::collections::BTreeSet<_>>();
    let mut reads = super::recovery::read_anchors(paths, |name| -> Result<Option<Vec<String>>> {
        let mut io = AnchorInventory::new(out, deadline, name);
        let path = crate::decode::pfanchor::AnchorPath::new(name)?;
        if crate::decode::pfanchor::read(&mut io, &path)
            .map_err(|e| format!("{}: {e:?}", io.last_read))?
            .is_some()
        {
            return Ok(None);
        }
        let mut names = vec![name.to_owned()];
        names.extend(io.descendant_paths);
        Ok(Some(names))
    });
    // Read each created top-level namespace once, independently of its children.
    if entries(out)?
        .iter()
        .any(|e| e.kind == "anchor" && e.path.starts_with("scupper-qual/"))
        && !before.observations.get("pf-anchors").is_some_and(|e| {
            e.complete() && e.stdout.lines().any(|line| line.trim() == "scupper-qual")
        })
    {
        let parent = "scupper-qual";
        let result = (|| -> Result<bool> {
            let mut io = AnchorInventory::new(out, deadline, parent);
            for (op, flag) in [
                (Operation::Filter, "-sr"),
                (Operation::Extra, "-sn"),
                (Operation::Extra, "-sT"),
                (Operation::Extra, "-sd"),
            ] {
                match io
                    .call(op, &["-a", parent, flag], &[])
                    .map_err(|e| format!("pfctl -a {parent} {flag}: {e:?}"))?
                {
                    Text::Missing => return Ok(true),
                    Text::MissingParent(_) => {
                        return Err(format!("pfctl -a {parent} {flag}: missing parent").into());
                    }
                    Text::Present(text) if text.is_empty() => (),
                    Text::Present(_) => return Ok(false),
                }
            }
            Ok(true)
        })();
        match result {
            Ok(true) => reads.empty_names.push(parent.into()),
            Ok(false) => reads
                .violations
                .push(format!("anchor parent has foreign content: {parent}")),
            Err(error) => {
                reads.incomplete_names.push(parent.into());
                reads
                    .inconclusive
                    .push(format!("anchor parent read incomplete: {parent}: {error}"));
            }
        }
    }
    write_json(
        out,
        &format!("{}.json", unique("restored-anchor-reads")),
        &reads,
    )?;
    Ok(reads)
}
pub(super) fn journal_anchor(out: &Path, path: &str, deadline: Instant) -> Result<()> {
    let absent = anchor_read(out, path, deadline);
    super::super::journal::anchor_after_absence(&absent, || {
        let entry = json!({"kind":"anchor","path":path});
        let mut file = fs::OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .open(out.join("resources.jsonl"))?;
        writeln!(file, "{entry}")?;
        file.sync_all()?;
        Ok(())
    })
}
/// Deep targets inherit only the original, completely absent disposable root's
/// authority. They are never passed to the two-component adapter path parser.
pub(super) fn journal_measurement_target(out: &Path, path: &str) -> Result<()> {
    if !super::super::desc_inventory::target_path(path)
        || !entries(out)?
            .iter()
            .any(|e| e.kind == "anchor" && e.path == super::super::desc_inventory::ROOT)
    {
        return Err("measurement target lacks original root absence authority".into());
    }
    let mut file = fs::OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .open(out.join("resources.jsonl"))?;
    writeln!(file, "{}", json!({"kind":"anchor-target","path":path}))?;
    file.sync_all()?;
    Ok(())
}
pub(super) fn recheck_foreign_tokens(out: &Path, deadline: Instant) -> Result<()> {
    let mut entries = entries(out)?;
    // Native -E attempts persist complete byte captures before interpretation.
    // Recognize their acquiring PID/time only for this baseline restore check;
    // this never authorizes numeric -X. A crash/capture failure before persistence
    // withholds restore rather than treating an unidentified token as ours.
    for file in fs::read_dir(out)? {
        let file = file?;
        let name = file.file_name();
        if !name
            .to_string_lossy()
            .starts_with("pf-text-native-acquire-")
            || file.path().extension().is_none_or(|e| e != "json")
        {
            continue;
        }
        protected_path(&file.path(), false)?;
        let capture: Value = super::read_json(&file.path())?;
        if capture["command"] != json!(["/sbin/pfctl", "-E"]) {
            continue;
        }
        let pid = u32::try_from(
            capture["pid"]
                .as_u64()
                .ok_or("native acquisition capture PID missing")?,
        )?;
        let at = capture["started_unix_ms"]
            .as_u64()
            .ok_or("native acquisition capture time missing")?
            / 1000;
        entries.push(Entry {
            kind: "pf-acquire".into(),
            pid,
            at,
            start: String::new(),
            token: 0,
            path: String::new(),
            dev: 0,
            ino: 0,
        });
    }
    let tokens = live_tokens(out, deadline)?;
    if tokens
        .iter()
        .any(|t| !journal::owns_token(&entries, t.value, t.pid, t.timestamp, unix_seconds()))
    {
        return Err("foreign tokens present before destructive restore".into());
    }
    Ok(())
}

fn undo_resolver_clone(
    out: &Path,
    before: &Snapshot,
    entries: &[Entry],
    deadline: Instant,
    actions: &mut Vec<String>,
    failures: &mut Vec<String>,
) -> Result<()> {
    if entries
        .iter()
        .any(|e| e.kind == "cloned-route" && e.path == "127.0.0.53")
        && !before
            .observations
            .get("routes")
            .is_some_and(|e| restore_check::resolver_clone(&e.stdout))
    {
        let routes = invoke_before("/usr/sbin/netstat", &["-rn", "-f", "inet"], deadline);
        write_json(
            out,
            &format!("{}.json", unique("resolver-clone-inventory")),
            &routes,
        )?;
        if !routes.complete() {
            failures.push("cannot inventory journaled resolver clone".into());
        } else if restore_check::resolver_clone(&routes.stdout) {
            action(
                out,
                "/sbin/route",
                &[
                    "-n",
                    "delete",
                    "-host",
                    "127.0.0.53",
                    "127.0.0.1",
                    "-ifscope",
                    "lo0",
                ],
                deadline,
                actions,
                failures,
            );
        }
    }
    Ok(())
}

fn undo_tokens(
    out: &Path,
    entries: &[Entry],
    deadline: Instant,
    actions: &mut Vec<String>,
    failures: &mut Vec<String>,
) {
    if entries
        .iter()
        .any(|e| matches!(e.kind.as_str(), "pf-acquire" | "token"))
    {
        let inventory = live_tokens(out, deadline).map_err(|error| error.to_string());
        let (tokens, problems) = journal::recovery_tokens(entries, inventory, unix_seconds());
        failures.extend(problems);
        for value in tokens {
            if let Err(error) = recheck_foreign_tokens(out, deadline) {
                failures.push(format!("token restore withheld: {error}"));
                break;
            }
            action(
                out,
                "/sbin/pfctl",
                &["-X", &value.to_string()],
                deadline,
                actions,
                failures,
            );
        }
    }
}

fn undo_keys(
    out: &Path,
    entries: &[Entry],
    deadline: Instant,
    actions: &mut Vec<String>,
    failures: &mut Vec<String>,
) -> Result<()> {
    if !entries.iter().any(|e| e.kind == "key") {
        return Ok(());
    }
    let keys = command(
        "/usr/sbin/scutil",
        &[],
        Some("list\nquit\n"),
        TOOL_BUDGET.min(deadline.saturating_duration_since(Instant::now())),
    );
    let listed = restore_check::key_list(&keys.stdout);
    if !restore_check::valid_key_list(&keys) {
        failures.push("cannot inventory SystemConfiguration keys".into());
    }
    for key in entries
        .iter()
        .filter(|e| e.kind == "key")
        .map(|e| e.path.as_str())
        .collect::<std::collections::BTreeSet<_>>()
    {
        if !key.starts_with("State:/Network/Service/scupper-qual-") || key.contains(['\n', '\r']) {
            failures.push("invalid harness key".into());
            continue;
        }
        if !listed.iter().any(|old| old == key) {
            continue;
        }
        let evidence = command(
            "/usr/sbin/scutil",
            &[],
            Some(&format!("remove {key}\nquit\n")),
            TOOL_BUDGET.min(deadline.saturating_duration_since(Instant::now())),
        );
        actions.push(format!("remove {key}"));
        if !evidence.complete()
            || evidence.stdout.contains("failed")
            || evidence.stdout.contains("error")
        {
            failures.push(format!("remove failed: {key}"));
        }
        write_json(out, &format!("{}.json", unique("undo-key")), &evidence)?;
    }
    Ok(())
}

fn repair_tail(out: &Path) -> Result<()> {
    let path = out.join("resources.jsonl");
    if !path.exists() {
        return Ok(());
    }
    let bytes = fs::read(&path)?;
    if bytes.last().is_some_and(|byte| *byte != b'\n') {
        let complete = bytes
            .iter()
            .rposition(|byte| *byte == b'\n')
            .map_or(0, |index| index + 1);
        write_json(
            out,
            &format!("{}.json", unique("journal-uncommitted-tail")),
            &json!({"discarded_uncommitted_tail": String::from_utf8_lossy(&bytes[complete..])}),
        )?;
        let file = fs::OpenOptions::new().write(true).open(path)?;
        file.set_len(u64::try_from(complete)?)?;
        file.sync_all()?;
    }
    Ok(())
}

pub(super) fn restore_child(out: &Path) -> Result<()> {
    let records = entries(out)?
        .into_iter()
        .filter(|e| e.kind.starts_with("r7-child-"))
        .map(|e| super::super::child_stage::Record {
            kind: e.kind,
            path: e.path,
            dev: e.dev,
            ino: e.ino,
        })
        .collect::<Vec<_>>();
    super::super::child_stage::restore(&records)?;
    Ok(())
}
