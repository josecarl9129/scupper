//! Gateway dispatch for strictly validated bounded SSH requests.
use scupper_core::{install::Change, release};
use scupper_proto::deploy::{DeployOp, read_deploy};
use scupper_sys::{
    install::{self, Options, Paths},
    system::RealSystem,
};
use std::{
    fs,
    io::{self, Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    process::Command,
};

fn safe_directory(path: &Path) -> Result<(), String> {
    for p in path.ancestors() {
        let m = fs::symlink_metadata(p).map_err(|e| e.to_string())?;
        if !m.is_dir() || m.is_symlink() || m.uid() != 0 || m.mode() & 0o022 != 0 {
            return Err("unsafe deploy directory".into());
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
        || m.uid() != 0
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
            || m.uid() != 0
            || m.mode() & 0o022 != 0
            || fs::read(path).map_err(|e| e.to_string())? != data
        {
            return Err("staged member mismatch".into());
        }
    }
    Ok(())
}
fn command(program: &Path, args: &[&str], out: &mut dyn Write) -> Result<u8, String> {
    let result = Command::new(program)
        .args(args)
        .output()
        .map_err(|e| e.to_string())?;
    out.write_all(&result.stdout).map_err(|e| e.to_string())?;
    io::stderr()
        .write_all(&result.stderr)
        .map_err(|e| e.to_string())?;
    Ok(result
        .status
        .code()
        .and_then(|c| u8::try_from(c).ok())
        .unwrap_or(1))
}
/// Services to restart, ordered to let boot adopt the namespace before scupperd.
#[must_use]
pub fn restart_units(net_changed: bool) -> Vec<&'static str> {
    if net_changed {
        vec!["scupper-net", "scupperd"]
    } else {
        vec!["scupperd"]
    }
}
/// Decode before executing any remote operation. Root is mandatory.
/// # Errors
/// Refuses malformed input, unsafe staging, unverified payloads or failed installation.
pub fn run(input: impl Read, out: &mut dyn Write) -> Result<u8, String> {
    let request = read_deploy(input).map_err(|e| e.to_string())?;
    if !rustix::process::geteuid().is_root() {
        return Err("remote requires root".into());
    }
    let id = request.operation.id();
    let base = Path::new("/usr/local/lib/scupper/deploy");
    let deployment = base.join(id);
    let stage = deployment.join("new");
    if matches!(request.operation, DeployOp::Prepare { .. }) {
        for p in [Path::new("/usr/local/lib/scupper"), base] {
            safe_directory(p.parent().ok_or("missing deploy parent")?)?;
            match fs::DirBuilder::new().mode(0o700).create(p) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.to_string()),
            }
            safe_directory(p)?;
        }
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&deployment)
            .map_err(|e| e.to_string())?;
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&stage)
            .map_err(|e| e.to_string())?;
        writeln!(out, "installed").map_err(|e| e.to_string())?;
        return Ok(0);
    }
    safe_directory(&stage)?;
    match request.operation {
        DeployOp::Stage { sha256, .. } => {
            let bytes = read_archive(&stage)?;
            extract(&stage, &bytes, sha256.as_str())?;
            writeln!(out, "Archive and MANIFEST verified.").map_err(|e| e.to_string())?;
            Ok(0)
        }
        DeployOp::Plan { .. } => {
            verified(&stage)?;
            command(&stage.join("scupper"), &["install", "--plan"], out)
        }
        DeployOp::Switch { .. } => {
            verified(&stage)?;
            // Execute the new installer, not the old version handling this SSH call.
            if std::env::current_exe().map_err(|e| e.to_string())? != stage.join("scupper") {
                let request = scupper_proto::deploy::DeployRequest {
                    request_id: request.request_id,
                    operation: DeployOp::Switch {
                        id: scupper_proto::Identifier::try_from(request.operation.id())?,
                    },
                };
                let mut child = Command::new(stage.join("scupper"))
                    .arg("remote")
                    .stdin(std::process::Stdio::piped())
                    .spawn()
                    .map_err(|e| e.to_string())?;
                let sent = child
                    .stdin
                    .take()
                    .ok_or("missing staged stdin")?
                    .write_all(&serde_json::to_vec(&request).map_err(|e| e.to_string())?);
                let status = child.wait().map_err(|e| e.to_string())?;
                sent.map_err(|e| e.to_string())?;
                return Ok(status
                    .code()
                    .and_then(|c| u8::try_from(c).ok())
                    .unwrap_or(1));
            }
            let system = RealSystem::default();
            let paths = Paths::new("/");
            let prepared = install::prepare(
                &system,
                &paths,
                &Options {
                    binaries: stage,
                    ..Options::default()
                },
            )
            .map_err(|e| e.to_string())?;
            let net_changed = prepared.plan.steps.iter().any(|s| matches!(&s.change, Change::File(path, _) if path == "/etc/systemd/system/scupper-net.service"));
            install::apply(&system, &paths, prepared)?;
            if command(Path::new("/usr/bin/systemctl"), &["daemon-reload"], out)? != 0 {
                return Err("daemon-reload failed".into());
            }
            for unit in restart_units(net_changed) {
                if command(Path::new("/usr/bin/systemctl"), &["restart", unit], out)? != 0 {
                    return Err(format!("restart {unit} failed"));
                }
            }
            Ok(0)
        }
        DeployOp::Check { .. } => command(Path::new("/usr/local/bin/scupper"), &["check"], out),
        DeployOp::Prepare { .. } => Err("invalid deploy state".into()),
    }
}
use std::os::unix::fs::DirBuilderExt;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn checksum_mismatch_never_reaches_extraction() {
        // A nonexistent path makes accidental extraction observable without host writes.
        let error = extract(
            Path::new("nonexistent-scupper-deploy-test"),
            b"corrupt",
            &"0".repeat(64),
        )
        .err();
        assert_eq!(
            error.as_deref(),
            Some("release checksum mismatch; extraction refused")
        );
    }
}
