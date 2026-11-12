//! Release assembly shared by Linux and macOS builders.
use scupper_core::{
    release::{self, Members},
    render::units,
};
use std::{fs, path::PathBuf, process::Command};

/// Builds and packages the requested supported target in `dist/`.
/// # Errors
/// Returns build, filesystem or archive validation errors.
pub fn run(target: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let gateway = match target {
        "x86_64-unknown-linux-musl" | "aarch64-unknown-linux-musl" => true,
        "aarch64-apple-darwin" => false,
        _ => return Err("unsupported release target".into()),
    };
    let mut command = Command::new("cargo");
    command.args([
        "build",
        "--release",
        "--locked",
        "--target",
        target,
        "-p",
        "scupper",
    ]);
    if gateway {
        command.args(["-p", "scupperd"]);
    }
    if !command.status()?.success() {
        return Err("release build failed".into());
    }
    let root =
        PathBuf::from(std::env::var_os("CARGO_TARGET_DIR").unwrap_or_else(|| "target".into()))
            .join(target)
            .join("release");
    let mut members = Members::new();
    members.insert("scupper".into(), fs::read(root.join("scupper"))?);
    if gateway {
        members.insert("scupperd".into(), fs::read(root.join("scupperd"))?);
        members.insert(
            "scupper-net.service".into(),
            units::scupper_net().as_bytes().to_vec(),
        );
        members.insert(
            "scupperd.service".into(),
            units::scupperd().as_bytes().to_vec(),
        );
    }
    let archive = release::encode(members)?;
    release::decode(&archive, gateway)?;
    let name = format!("scupper-{}-{target}.tar.gz", env!("CARGO_PKG_VERSION"));
    fs::create_dir_all("dist")?;
    fs::write(PathBuf::from("dist").join(&name), &archive)?;
    let sums = PathBuf::from("dist/SHA256SUMS");
    let mut lines: Vec<String> = match fs::read_to_string(&sums) {
        Ok(text) => text
            .lines()
            .filter(|l| !l.ends_with(&format!("  {name}")))
            .map(str::to_owned)
            .collect(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(e.into()),
    };
    lines.push(format!("{}  {name}", release::hash(&archive)));
    lines.sort();
    fs::write(sums, format!("{}\n", lines.join("\n")))?;
    println!("dist/{name}");
    Ok(())
}
