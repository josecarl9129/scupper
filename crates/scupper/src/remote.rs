//! Gateway dispatch for strictly validated bounded SSH requests.
use scupper_core::{
    install::{self as model, Change},
    release,
};
use scupper_proto::deploy::{DeployOp, DeployPlan, DeployRequest, ReleaseHash, read_deploy};
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
        match result {
            Ok((code, text)) => {
                out.write_all(text.as_bytes()).map_err(|e| e.to_string())?;
                return Ok(code);
            }
            Err(error) => {
                let error = if switching {
                    format!(
                        "Switch child failed: {error}. Gateway binaries may be mixed or services stopped. Restore manually:\n{}",
                        model::RESTORE_COMMANDS
                    )
                } else {
                    format!("Plan child failed: {error}. Live binaries were not switched.")
                };
                let _ = writeln!(out, "{error}");
                return Err(error);
            }
        }
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
    dispatch(request, out, system, paths, filesystem)
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
            let result: Result<u8, String> = (|| {
                install::apply_with_fs(system, paths, prepared, filesystem)?;
                service(system, &["daemon-reload"])?;
                if net_changed {
                    service(system, &["restart", "scupper-net"])?;
                }
                service(system, &["restart", "scupperd"])?;
                Ok(0)
            })();
            result.map_err(|e| {
                let message = format!("Switch failed: {e}. Gateway binaries may be mixed or services stopped. Restore manually:\n{}", model::RESTORE_COMMANDS);
                let _ = writeln!(out, "{message}");
                message
            })
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
use std::os::unix::fs::DirBuilderExt;
