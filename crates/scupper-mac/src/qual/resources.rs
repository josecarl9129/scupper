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

fn entries(out: &Path) -> Result<Vec<Entry>> {
    let path = out.join("resources.jsonl");
    if !path.exists() {
        return Ok(Vec::new());
    }
    protected_path(&path, false)?;
    Ok(journal::committed(&fs::read_to_string(path)?)?)
}

pub(super) fn writers(out: &Path, probes_only: bool) -> Result<Vec<Writer>> {
    Ok(entries(out)?
        .into_iter()
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
    let lock = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .open(out.join("restore.lock"))?;
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
    if super::super::guard::no_foreign_references(&evidence.stdout, &evidence.stderr) {
        return Ok(Vec::new());
    }
    journal::text_tokens(&evidence.stdout, unix_seconds())
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
        if !image["image-path"]
            .as_str()
            .is_some_and(|path| paths.contains(&path))
        {
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

pub(super) fn undo(
    out: &Path,
    before: &Snapshot,
    deadline: Instant,
    restore_pf_state: bool,
) -> Result<(Vec<String>, Vec<String>)> {
    repair_tail(out)?;
    let entries = entries(out)?;
    let mut actions = Vec::new();
    let mut failures = Vec::new();
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
        let info = invoke_before("/sbin/pfctl", &["-s", "info"], deadline);
        let current = BTreeMap::from([("pf-info".into(), info)]);
        if restore_check::pf_status(&current) == Some(true) {
            action(
                out,
                "/sbin/pfctl",
                &["-d"],
                deadline,
                &mut actions,
                &mut failures,
            )?;
        }
    }
    undo_keys(out, &entries, deadline, &mut actions, &mut failures)?;
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
                action(
                    out,
                    "/usr/bin/hdiutil",
                    &["detach", &device],
                    deadline,
                    &mut actions,
                    &mut failures,
                )?;
            }
        }
        Err(error) => failures.push(error.to_string()),
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
    Ok((actions, failures))
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
