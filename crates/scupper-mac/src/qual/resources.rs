//! Write-ahead fixture recovery, used by both the dead-man and always-step.
use super::{
    Result, Snapshot, TOOL_BUDGET, Writer, command, invoke_before, protected_path, restore_check,
    unique, unix_seconds, write_json,
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::OpenOptionsExt,
    path::Path,
    thread,
    time::{Duration, Instant},
};

use super::super::journal::{self, Entry};
use super::super::recovery::Completed;

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
) -> Result<()> {
    let evidence = invoke_before(program, args, deadline);
    let label = std::iter::once(program)
        .chain(args.iter().copied())
        .collect::<Vec<_>>()
        .join(" ");
    actions.push(label.clone());
    if !evidence.complete() {
        failures.push(format!("restore action failed: {label}"));
    }
    write_json(out, &format!("{}.json", unique("undo")), &evidence)
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
            if let Err(error) = action(out, "/sbin/pfctl", &["-d"], deadline, actions, failures) {
                failures.push(format!("restore disable evidence failed: {error}"));
            }
        }
        Ok(false) => {}
        Err(reason) => {
            failures.push(reason.into());
            // Unknown still permits deliberate restoration toward the disabled baseline.
            // Only the later complete state check can prove Disabled.
            if let Err(error) = action(out, "/sbin/pfctl", &["-d"], deadline, actions, failures) {
                failures.push(format!("restore disable evidence failed: {error}"));
            }
        }
    }
}

pub(super) fn undo(
    out: &Path,
    before: &Snapshot,
    deadline: Instant,
    restore_pf_state: bool,
) -> Result<(Vec<String>, Vec<String>)> {
    repair_tail(out)?;
    let pending = completed(out)?.pending(entries(out)?);
    if pending.is_empty() && !restore_pf_state {
        return Ok((Vec::new(), Vec::new()));
    }
    let entries: Vec<_> = pending.iter().map(|(_, e)| e.clone()).collect();
    let mut actions = Vec::new();
    let mut failures = Vec::new();
    super::tool::restore(out, &entries, deadline, &mut actions, &mut failures)?;
    undo_tokens(out, &entries, deadline, &mut actions, &mut failures)?;
    // No R2 probe loads rules. Flush only explicitly journaled fixture anchors,
    // and never flush a hooked parent or a foreign anchor discovered by name.
    for e in entries.iter().filter(|e| e.kind == "anchor") {
        if !matches!(
            e.path.as_str(),
            "scupper-qual/scupper" | "com.apple/scupper"
        ) {
            failures.push("unrecognized fixture anchor".into());
            continue;
        }
        let rules = invoke_before("/sbin/pfctl", &["-a", &e.path, "-sr"], deadline);
        if rules.complete() && !rules.stdout.trim().is_empty() {
            action(
                out,
                "/sbin/pfctl",
                &["-a", &e.path, "-F", "all"],
                deadline,
                &mut actions,
                &mut failures,
            )?;
        }
    }
    if restore_pf_state && restore_check::pf_status(&before.observations) == Some(false) {
        undo_pf_state(out, deadline, &mut actions, &mut failures);
    }
    undo_keys(out, &entries, deadline, &mut actions, &mut failures)?;
    undo_resolver_clone(out, before, &entries, deadline, &mut actions, &mut failures)?;
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
                detach_device(out, &device, deadline, &mut actions, &mut failures)?;
            }
        }
        Err(error) => failures.push(error.to_string()),
    }
    if entries.iter().any(|e| e.kind == "r5-tree") && writers_quiescent(out)? {
        match attached_devices(out, &paths, deadline) {
            Ok(devices) if devices.is_empty() => {
                super::store::restore_tree(out, &entries, &mut actions, &mut failures);
            }
            _ => failures.push("R5 images not proven detached; fixture tree retained".into()),
        }
    }
    if entries.iter().any(|e| e.kind == "loopback-alias") {
        let interfaces = invoke_before("/sbin/ifconfig", &["lo0"], deadline);
        if interfaces.complete()
            && interfaces
                .stdout
                .lines()
                .any(|line| line.split_whitespace().take(2).eq(["inet", "127.0.0.53"]))
        {
            action(
                out,
                "/sbin/ifconfig",
                &["lo0", "-alias", "127.0.0.53"],
                deadline,
                &mut actions,
                &mut failures,
            )?;
        }
    }
    for e in entries.iter().filter(|e| e.kind == "socket") {
        if e.path.starts_with("/var/run/wireguard/utun")
            && Path::new(&e.path)
                .extension()
                .is_some_and(|ext| ext == "sock")
            && !e.path.contains("..")
            && Path::new(&e.path).exists()
        {
            fs::remove_file(&e.path)?;
            actions.push(format!("unlink {}", e.path));
        }
    }
    complete_from_inventory(out, &pending, deadline, &mut failures)?;
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
) -> Result<()> {
    if !writers_quiescent(out)? {
        return Ok(());
    }
    let pending = completed(out)?.pending(entries(out)?);
    let mut verified = Vec::new();
    for (index, entry) in pending {
        let absent = match entry.kind.as_str() {
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
            "r4-wireguard-created" => fs::symlink_metadata(&entry.path)
                .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
            "r4-wireguard-sockets" => {
                fs::read_dir(&entry.path).is_ok_and(|mut entries| entries.next().is_none())
            }
            "r4-tree" | "r5-tree" => fs::symlink_metadata(&entry.path)
                .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
            "r4-job" => {
                let status = invoke_before("/bin/launchctl", &["print", &entry.path], deadline);
                status.exit_code == Some(113) && !status.timed_out && !status.truncated
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
) -> Result<()> {
    for force in [false, true] {
        let args = if force {
            vec!["detach", "-force", device]
        } else {
            vec!["detach", device]
        };
        let evidence = command(
            "/usr/bin/hdiutil",
            &args,
            None,
            Duration::from_secs(30).min(deadline.saturating_duration_since(Instant::now())),
        );
        actions.push(format!("/usr/bin/hdiutil {}", args.join(" ")));
        write_json(out, &format!("{}.json", unique("undo-image")), &evidence)?;
        if evidence.complete() {
            return Ok(());
        }
    }
    failures.push(format!(
        "fixture image detach and forced retry failed: {device}"
    ));
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
            )?;
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
) -> Result<()> {
    if entries
        .iter()
        .any(|e| matches!(e.kind.as_str(), "pf-acquire" | "token"))
    {
        let inventory = live_tokens(out, deadline).map_err(|error| error.to_string());
        let (tokens, problems) = journal::recovery_tokens(entries, inventory, unix_seconds());
        failures.extend(problems);
        for value in tokens {
            action(
                out,
                "/sbin/pfctl",
                &["-X", &value.to_string()],
                deadline,
                actions,
                failures,
            )?;
        }
    }
    Ok(())
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
