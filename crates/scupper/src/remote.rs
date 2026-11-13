//! Gateway dispatch for strictly validated bounded SSH requests.
use scupper_core::{
    install::{self as model, Change},
    release,
};
use scupper_proto::deploy::{
    DeployOp, DeployPlan, DeployRequest, ReleaseHash, SwitchOutcome, read_deploy,
};
use scupper_sys::{
    fs::{Fs, RealFs},
    install::{self, Options, Paths},
    store::VersionStore,
    system::{Program, RealSystem, System},
};
use std::{
    fs,
    io::{self, Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    process::Command,
    time::Duration,
};

fn safe_directory(path: &Path, paths: &Paths) -> Result<(), String> {
    for p in path.ancestors() {
        let m = fs::symlink_metadata(p).map_err(|e| e.to_string())?;
        if !m.is_dir()
            || m.is_symlink()
            || m.uid() != rustix::process::geteuid().as_raw()
            || m.mode() & 0o022 != 0
        {
            return Err("unsafe deploy directory".into());
        }
        if p == paths.at("/") {
            break;
        }
    }
    Ok(())
}
fn write_new(path: &Path, bytes: &[u8], mode: u32) -> Result<(), String> {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .map_err(|e| e.to_string())?;
    f.write_all(bytes)
        .and_then(|()| f.sync_all())
        .map_err(|e| e.to_string())
}
fn read_archive(stage: &Path) -> Result<Vec<u8>, String> {
    let fd = rustix::fs::open(
        stage.join("archive.tar.gz"),
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::NONBLOCK
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|e| e.to_string())?;
    let file = fs::File::from(fd);
    let m = file.metadata().map_err(|e| e.to_string())?;
    if !m.is_file()
        || m.uid() != rustix::process::geteuid().as_raw()
        || m.mode() & 0o022 != 0
        || m.len() > (release::MAX_RELEASE + 65536) as u64
    {
        return Err("unsafe release archive".into());
    }
    let mut bytes = Vec::new();
    file.take((release::MAX_RELEASE + 65537) as u64)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    Ok(bytes)
}
fn extract(stage: &Path, bytes: &[u8], expected: &str) -> Result<(), String> {
    if release::hash(bytes) != expected {
        return Err("release checksum mismatch; extraction refused".into());
    }
    let members = release::decode(bytes, true).map_err(|e| e.to_string())?;
    // The release checksum and complete MANIFEST are verified before any file write.
    write_new(
        &stage.join("SHA256SUMS"),
        format!("{expected}  archive.tar.gz\n").as_bytes(),
        0o644,
    )?;
    for (name, data) in members {
        let mode = if matches!(name.as_str(), "scupper" | "scupperd") {
            0o755
        } else {
            0o644
        };
        write_new(&stage.join(name), &data, mode)?;
    }
    Ok(())
}
fn verified(stage: &Path) -> Result<(), String> {
    let bytes = read_archive(stage)?;
    let expected = format!("{}  archive.tar.gz\n", release::hash(&bytes));
    if fs::read(stage.join("SHA256SUMS")).map_err(|e| e.to_string())? != expected.as_bytes() {
        return Err("staged checksum mismatch".into());
    }
    let members = release::decode(&bytes, true).map_err(|e| e.to_string())?;
    for (name, data) in members {
        let path = stage.join(name);
        let m = fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
        if !m.is_file()
            || m.is_symlink()
            || m.uid() != rustix::process::geteuid().as_raw()
            || m.mode() & 0o022 != 0
            || fs::read(path).map_err(|e| e.to_string())? != data
        {
            return Err("staged member mismatch".into());
        }
    }
    Ok(())
}
fn service(system: &dyn System, args: &[&str]) -> Result<(), String> {
    // Unit TimeoutStartSec=90; allow systemd time to finish reporting failure.
    let timeout = if args.first() == Some(&"restart") {
        Duration::from_secs(120)
    } else {
        Duration::from_secs(30)
    };
    let mut args = args.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
    args.push("--job-mode=replace".into());
    let result = system
        .run(Program::Systemctl, &args, timeout)
        .map_err(|e| format!("systemctl {}: {e}", args.join(" ")))?;
    if result.status != Some(0) {
        return Err(format!("systemctl {} failed", args.join(" ")));
    }
    Ok(())
}
fn installed(paths: &Paths) -> Result<bool, String> {
    let head = VersionStore::read_only(&paths.at(model::STATE_ROOT), &paths.at(model::CONFIG_ROOT))
        .head()
        .map_err(|e| e.to_string())?;
    Ok(head.is_some()
        && model::UNITS.iter().all(|unit| {
            paths
                .at(&format!("{}/{unit}.service", model::UNIT_ROOT))
                .is_file()
        }))
}
fn prepare_install(
    system: &dyn System,
    paths: &Paths,
    stage: &Path,
) -> Result<install::Prepared, String> {
    install::prepare(
        system,
        paths,
        &Options {
            binaries: stage.into(),
            ..Options::default()
        },
    )
    .map_err(|e| e.to_string())
}
/// Decode before executing any remote operation. Root is mandatory.
/// # Errors
/// Refuses malformed input, unsafe staging, unverified payloads or failed installation.
pub fn run(input: impl Read, out: &mut dyn Write) -> Result<u8, String> {
    run_mode(input, out, false)
}
/// Internal re-exec entry; the marker prevents staged executable path alias loops.
/// # Errors
/// Returns bounded execution or installation failures.
pub fn run_mode(input: impl Read, out: &mut dyn Write, staged: bool) -> Result<u8, String> {
    let request = read_deploy(input).map_err(|e| e.to_string())?;
    let switching = matches!(request.operation, DeployOp::Switch { .. });
    let result = run_request(request, out, staged);
    finish_refusal(result, switching, out)
}
fn run_request(request: DeployRequest, out: &mut dyn Write, staged: bool) -> Result<u8, String> {
    if !rustix::process::geteuid().is_root() {
        return Err("remote requires root".into());
    }
    let system = RealSystem::default();
    let paths = Paths::new("/");
    if !staged
        && matches!(
            request.operation,
            DeployOp::Plan { .. } | DeployOp::Switch { .. }
        )
    {
        let stage = paths.at(&format!(
            "/usr/local/lib/scupper/deploy/{}/new",
            request.operation.id()
        ));
        safe_directory(&stage, &paths)?;
        verified(&stage)?;
        let switching = matches!(request.operation, DeployOp::Switch { .. });
        let timeout = Duration::from_secs(if switching { 360 } else { 150 });
        let mut command = Command::new(stage.join("scupper"));
        command.args(["remote", "--staged"]);
        let result = crate::deploy_process::execute(
            command,
            &serde_json::to_vec(&request).map_err(|e| e.to_string())?,
            timeout,
        );
        return forward_child(result, switching, out);
    }
    dispatch(request, out, &system, &paths, &RealFs)
}
/// Execute gateway operations with isolated paths and an injected command/filesystem boundary.
/// Production enters through `run_mode`, which re-executes the verified staged installer.
/// # Errors
/// Refuses malformed requests, non-root systems, tampered staging and changed plans.
pub fn run_staged(
    input: impl Read,
    out: &mut dyn Write,
    system: &dyn System,
    paths: &Paths,
    filesystem: &dyn Fs,
) -> Result<u8, String> {
    let request = read_deploy(input).map_err(|e| e.to_string())?;
    let switching = matches!(request.operation, DeployOp::Switch { .. });
    let result = dispatch(request, out, system, paths, filesystem);
    finish_refusal(result, switching, out)
}
fn report_switch(outcome: SwitchOutcome, reason: &str, out: &mut dyn Write) -> u8 {
    // A failed output pipe must not replace the actual switch outcome with a refusal.
    let _ = writeln!(out, "{}", crate::deploy::switch_message(outcome, reason));
    outcome.exit_code()
}
fn finish_refusal(
    result: Result<u8, String>,
    switching: bool,
    out: &mut dyn Write,
) -> Result<u8, String> {
    match result {
        Err(reason) if switching => Ok(report_switch(SwitchOutcome::RefusedNoChange, &reason, out)),
        result => result,
    }
}
// This is the production outer gateway boundary: preserve typed child failures,
// classify missing status/timeouts conservatively, and print only one gateway copy.
fn forward_child(
    result: Result<crate::deploy::TransportOutput, crate::deploy_process::ProcessError>,
    switching: bool,
    out: &mut dyn Write,
) -> Result<u8, String> {
    match result {
        Ok(result) if switching && result.code != 0 => {
            let outcome = SwitchOutcome::from_exit_code(result.code);
            let reason = format!("{}{}", result.stdout, result.stderr);
            Ok(report_switch(outcome, &reason, out))
        }
        Ok(result) => {
            let text = result.success()?;
            if let Err(error) = out.write_all(text.as_bytes()) {
                if switching {
                    return Ok(report_switch(
                        SwitchOutcome::Unknown,
                        &error.to_string(),
                        out,
                    ));
                }
                return Err(error.to_string());
            }
            Ok(0)
        }
        Err(error) if switching => Ok(report_switch(
            if error.started {
                SwitchOutcome::Unknown
            } else {
                SwitchOutcome::RefusedNoChange
            },
            &error.reason,
            out,
        )),
        Err(error) => Err(format!(
            "Plan child failed: {error}. Live binaries were not switched."
        )),
    }
}
#[allow(clippy::too_many_lines)]
fn dispatch(
    request: DeployRequest,
    out: &mut dyn Write,
    system: &dyn System,
    paths: &Paths,
    filesystem: &dyn Fs,
) -> Result<u8, String> {
    if system.install_uid() != 0 {
        return Err("remote requires root".into());
    }
    let base = paths.at("/usr/local/lib/scupper/deploy");
    let deployment = base.join(request.operation.id());
    let stage = deployment.join("new");
    if matches!(request.operation, DeployOp::Prepare { .. }) {
        for p in [paths.at("/usr/local/lib/scupper"), base] {
            safe_directory(p.parent().ok_or("missing deploy parent")?, paths)?;
            match fs::DirBuilder::new().mode(0o700).create(&p) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.to_string()),
            }
            safe_directory(&p, paths)?;
        }
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&deployment)
            .map_err(|e| e.to_string())?;
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&stage)
            .map_err(|e| e.to_string())?;
        writeln!(
            out,
            "{}",
            if installed(paths)? {
                "installed"
            } else {
                "fresh"
            }
        )
        .map_err(|e| e.to_string())?;
        return Ok(0);
    }
    safe_directory(&stage, paths)?;
    match request.operation {
        DeployOp::Stage { sha256, .. } => {
            let bytes = read_archive(&stage)?;
            extract(&stage, &bytes, sha256.as_str())?;
            writeln!(out, "Archive and MANIFEST verified.").map_err(|e| e.to_string())?;
            Ok(0)
        }
        DeployOp::Plan { .. } => {
            verified(&stage)?;
            let prepared = prepare_install(system, paths, &stage)?;
            let plan = DeployPlan {
                plan: prepared.plan.text(),
                plan_sha256: ReleaseHash::try_from(prepared.confirmation_digest())?,
            };
            serde_json::to_writer(out, &plan).map_err(|e| e.to_string())?;
            Ok(0)
        }
        DeployOp::Switch { plan_sha256, .. } => {
            let mut replaced = false;
            let mut mutations = install::Mutations::default();
            let result: Result<u8, String> = (|| {
                verified(&stage)?;
                let prepared = prepare_install(system, paths, &stage)?;
                if prepared.confirmation_digest() != plan_sha256.as_str() {
                    return Err("deployment plan changed since confirmation; no change made; request and confirm a new plan".into());
                }
                if model::BINARIES
                    .iter()
                    .any(|name| !paths.at(&format!("{}/{name}", model::BIN_ROOT)).is_file())
                {
                    return Err("Switch requires both installed binaries for manual recovery; copy and install the release manually".into());
                }
                let net_changed = prepared.plan.steps.iter().any(|s| matches!(&s.change, Change::File(path, _) if path == &format!("{}/scupper-net.service", model::UNIT_ROOT)));
                let binary_changed = prepared
                    .plan
                    .steps
                    .iter()
                    .any(|s| matches!(s.change, Change::Binary(..)));
                let (_, changes) = install::apply_with_fs_tracked(
                    system, paths, prepared, filesystem,
                )
                .map_err(|error| {
                    replaced = error.replaced;
                    mutations = error.mutations;
                    error.reason
                })?;
                mutations = changes;
                replaced = binary_changed;
                tracked_service(system, &["daemon-reload"], &mut mutations)?;
                if net_changed {
                    tracked_service(system, &["restart", "scupper-net"], &mut mutations)?;
                    writeln!(out, "scupper-net: an attached supervisor makes boot idempotent; newly installed boot logic runs on the next rebuild or reboot.").map_err(|e| e.to_string())?;
                }
                tracked_service(system, &["restart", "scupperd"], &mut mutations)?;
                write!(out, "{}", mutations.text()).map_err(|e| e.to_string())?;
                Ok(0)
            })();
            match result {
                Ok(code) => Ok(code),
                Err(reason) => Ok(report_switch(
                    if replaced {
                        SwitchOutcome::FailedAfterRename
                    } else if !mutations.possibly_changed.is_empty() {
                        SwitchOutcome::PossiblyChanged
                    } else if !mutations.changed.is_empty() {
                        SwitchOutcome::FailedAfterChange
                    } else {
                        SwitchOutcome::RefusedNoChange
                    },
                    &format!("{reason}\n{}", mutations.text()),
                    out,
                )),
            }
        }
        DeployOp::Check { .. } => {
            let result = system
                .run(
                    Program::Scupper,
                    &["check".into()],
                    Duration::from_secs(120),
                )
                .map_err(|e| {
                    format!("Check failed: {e}. Switch completed; gateway health is unconfirmed.")
                })?;
            out.write_all(result.stdout.as_bytes())
                .map_err(|e| e.to_string())?;
            Ok(result
                .status
                .and_then(|c| u8::try_from(c).ok())
                .unwrap_or(1))
        }
        DeployOp::Prepare { .. } => Err("invalid deploy state".into()),
    }
}
fn tracked_service(
    system: &dyn System,
    args: &[&str],
    mutations: &mut install::Mutations,
) -> Result<(), String> {
    let label = format!("systemctl {}", args.join(" "));
    mutations.begin(&label);
    service(system, args)?;
    mutations.complete(&label);
    Ok(())
}
use std::os::unix::fs::DirBuilderExt;

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    #[test]
    fn outer_gateway_preserves_typed_outcomes_without_duplicate_recovery() {
        for outcome in [
            SwitchOutcome::RefusedNoChange,
            SwitchOutcome::FailedAfterRename,
            SwitchOutcome::Unknown,
            SwitchOutcome::FailedAfterChange,
            SwitchOutcome::PossiblyChanged,
        ] {
            let message = crate::deploy::switch_message(outcome, "injected failure");
            let mut command = Command::new("sh");
            command.args([
                "-c",
                "cat; exit \"$1\"",
                "switch-child",
                &outcome.exit_code().to_string(),
            ]);
            let result =
                crate::deploy_process::execute(command, message.as_bytes(), Duration::from_secs(2));
            let mut out = Vec::new();
            let code = forward_child(result, true, &mut out).unwrap();
            assert_eq!(code, outcome.exit_code());
            let text = String::from_utf8(out).unwrap();
            assert_eq!(text, format!("{message}\n"));
            assert_eq!(
                text.matches(model::RESTORE_COMMANDS).count(),
                usize::from(matches!(
                    outcome,
                    SwitchOutcome::FailedAfterRename | SwitchOutcome::Unknown
                ))
            );
        }
    }
    #[test]
    fn outer_gateway_timeout_signal_or_unrecognized_exit_is_unknown() {
        for script in ["sleep 10", "exit 255", "kill -KILL $$"] {
            let mut command = Command::new("sh");
            command.args(["-c", script]);
            let result = crate::deploy_process::execute(command, b"", Duration::from_millis(50));
            let mut out = Vec::new();
            assert_eq!(
                forward_child(result, true, &mut out).unwrap(),
                SwitchOutcome::Unknown.exit_code()
            );
            let text = String::from_utf8(out).unwrap();
            assert!(text.contains("outcome unknown"));
            assert_eq!(text.matches(model::RESTORE_COMMANDS).count(), 1);
        }
    }
    #[test]
    fn outer_gateway_pre_exec_refusal_and_spawn_failure_have_no_recovery() {
        let mut out = Vec::new();
        let code = finish_refusal(Err("staged member mismatch".into()), true, &mut out).unwrap();
        assert_eq!(code, SwitchOutcome::RefusedNoChange.exit_code());
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("refused, nothing changed: staged member mismatch"));
        assert!(!text.contains(model::RESTORE_COMMANDS));
        let result = crate::deploy_process::execute(
            Command::new(Path::new(env!("CARGO_MANIFEST_DIR")).join("no-such-switch-child")),
            b"",
            Duration::from_secs(1),
        );
        let mut out = Vec::new();
        assert_eq!(
            forward_child(result, true, &mut out).unwrap(),
            SwitchOutcome::RefusedNoChange.exit_code()
        );
        assert!(
            !String::from_utf8(out)
                .unwrap()
                .contains(model::RESTORE_COMMANDS)
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod empty_diagnostic_tests {
    use super::*;
    #[test]
    fn outer_gateway_uses_typed_status_even_without_child_diagnostics() {
        for outcome in [
            SwitchOutcome::RefusedNoChange,
            SwitchOutcome::FailedAfterRename,
            SwitchOutcome::Unknown,
            SwitchOutcome::FailedAfterChange,
            SwitchOutcome::PossiblyChanged,
        ] {
            let result = crate::deploy::TransportOutput {
                code: outcome.exit_code(),
                stdout: String::new(),
                stderr: String::new(),
            };
            let mut out = Vec::new();
            assert_eq!(
                forward_child(Ok(result), true, &mut out).unwrap(),
                outcome.exit_code()
            );
            let text = String::from_utf8(out).unwrap();
            assert_eq!(
                text.matches(model::RESTORE_COMMANDS).count(),
                usize::from(matches!(
                    outcome,
                    SwitchOutcome::FailedAfterRename | SwitchOutcome::Unknown
                ))
            );
            if outcome == SwitchOutcome::RefusedNoChange {
                assert!(text.contains("refused, nothing changed"));
            }
        }
    }
}
