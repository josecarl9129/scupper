//! Read-only v1 markers used by installation preflight.
use crate::{
    canon::command,
    rules::V1Config,
    system::{EXEC_TIMEOUT, ExecError, Program, System},
    verdict::{Probe, ProbeError},
};
use std::collections::BTreeSet;

/// Evidence of the retired host layout; never removed by detection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum V1Marker {
    /// An installed binary without the M2 version-store CLI.
    Binary,
    /// An enabled wg-quick instance, including instances outside the v1 defaults.
    EnabledWgQuick(String),
    /// The host namespace contains `table inet scupper`.
    HostTable,
    /// A host link has a v1 tunnel name.
    HostLink(String),
}

/// Finds enabled wg-quick instances, the host table, and v1 tunnel link names.
/// Does not inspect binaries, configuration secrets or namespace contents.
///
/// # Errors
/// Returns execution or parse failures; a failed observation is never absence.
pub fn detect_v1_layout(sys: &dyn System) -> Probe<Vec<V1Marker>> {
    detect_v1_layout_for(sys, &[])
}

/// Also refuses host links named by the requested configuration.
/// # Errors
/// An observation or parse failure is never treated as absence.
pub fn detect_v1_layout_for(sys: &dyn System, names: &[&str]) -> Probe<Vec<V1Marker>> {
    detect_layout(sys, names, None)
}

/// Install detection ignores only host links that boot can safely remove.
/// Missing optional utilities cannot hide other v1 evidence.
/// # Errors
/// Missing installed tools remain observation errors; uninspectable links are evidence.
pub fn detect_install_layout(
    sys: &dyn System,
    names: &[&str],
    packages: &BTreeSet<String>,
) -> Probe<Vec<V1Marker>> {
    detect_layout(sys, names, Some(packages))
}

fn detect_layout(
    sys: &dyn System,
    names: &[&str],
    packages: Option<&BTreeSet<String>>,
) -> Probe<Vec<V1Marker>> {
    let mut markers = enabled_units(sys)?;
    if packages.is_some() && !markers.is_empty() {
        return Ok(markers);
    }
    if packages.is_none_or(|p| p.contains("nftables")) {
        let tables = command(
            sys,
            Program::Nft,
            &["-j".into(), "list".into(), "tables".into()],
            EXEC_TIMEOUT,
        )?;
        let tables = crate::canon::canonicalize(&tables)?;
        for entry in tables["nftables"]
            .as_array()
            .ok_or_else(|| ProbeError::setup("missing nftables table list"))?
        {
            let table = entry
                .get("table")
                .ok_or_else(|| ProbeError::setup("malformed nftables table listing"))?;
            let family = table
                .get("family")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| ProbeError::setup("missing table family"))?;
            let name = table
                .get("name")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| ProbeError::setup("missing table name"))?;
            if family == "inet" && name == "scupper" {
                markers.push(V1Marker::HostTable);
            }
        }
    }
    if packages.is_some_and(|p| !p.contains("iproute2"))
        || (packages.is_some() && !markers.is_empty())
    {
        return Ok(markers);
    }
    let links = command(
        sys,
        Program::Ip,
        &["-d".into(), "-j".into(), "link".into(), "show".into()],
        EXEC_TIMEOUT,
    )?;
    let config = V1Config::default();
    if packages.is_none() {
        for link in crate::parse::links(&links)? {
            if link.name == config.client_iface.as_str()
                || link.name == config.exit_iface.as_str()
                || names.contains(&link.name.as_str())
            {
                markers.push(V1Marker::HostLink(link.name));
            }
        }
        return Ok(markers);
    }
    for link in scupper_core::parse::parse_ip_link(&links)? {
        if link.ifname == config.client_iface.as_str()
            || link.ifname == config.exit_iface.as_str()
            || names.contains(&link.ifname.as_str())
        {
            if names.contains(&link.ifname.as_str())
                && packages.is_some_and(|p| p.contains("wireguard-tools"))
            {
                match crate::boot::links::host_link_removable(sys, &link) {
                    Ok(true) => continue,
                    Ok(false)
                    | Err(crate::boot::links::HostLinkError::Exec(ExecError::NotFound {
                        program: Program::Wg,
                    })) => {}
                    Err(error) => return Err(ProbeError::setup(&error.to_string())),
                }
            }
            markers.push(V1Marker::HostLink(link.ifname));
        }
    }
    Ok(markers)
}

fn enabled_units(sys: &dyn System) -> Probe<Vec<V1Marker>> {
    sys.wg_quick_units()
        .map(|units| units.into_iter().map(V1Marker::EnabledWgQuick).collect())
        .map_err(|_| ProbeError::setup("cannot inspect wg-quick unit files"))
}

/// Inspect public systemd unit templates and enablement symlinks under a host root.
/// Missing files establish absence; unreadable inventories are errors.
/// # Errors
/// Returns metadata, open, directory enumeration or symlink-read failures.
pub fn wg_quick_units_at(root: &std::path::Path) -> std::io::Result<Vec<String>> {
    use std::{fs, io, os::unix::fs::FileTypeExt};
    for directory in [
        "lib/systemd/system",
        "usr/lib/systemd/system",
        "etc/systemd/system",
        "run/systemd/system",
    ] {
        let template = root.join(directory).join("wg-quick@.service");
        if fs::symlink_metadata(&template).is_ok_and(|m| m.file_type().is_symlink())
            && fs::read_link(&template)? == std::path::Path::new("/dev/null")
        {
            continue; // A masked template is present, but cannot start a service.
        }
        match fs::File::open(&template) {
            Ok(file) if file.metadata()?.is_file() => {}
            Ok(file) if file.metadata()?.file_type().is_char_device() => {}
            Ok(_) => return Err(io::Error::other("wg-quick template is not a regular file")),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    let mut units = BTreeSet::new();
    for directory in ["etc/systemd/system", "run/systemd/system"] {
        let entries = match fs::read_dir(root.join(directory)) {
            Ok(entries) => entries,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        };
        for entry in entries {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if !name.ends_with(".wants") && !name.ends_with(".requires") {
                continue;
            }
            for unit in fs::read_dir(entry.path())? {
                let unit = unit?;
                let name = unit.file_name().to_string_lossy().into_owned();
                if name.starts_with("wg-quick@")
                    && name.ends_with(".service")
                    && name != "wg-quick@.service"
                {
                    if !unit.file_type()?.is_symlink() {
                        return Err(io::Error::other("wg-quick enablement is not a symlink"));
                    }
                    fs::read_link(unit.path())?;
                    units.insert(name);
                }
            }
        }
    }
    Ok(units.into_iter().collect())
}

/// Identifies retired/unknown binaries by the version-store CLI, not semver:
/// v1 and M2 development binaries can share the same package version.
/// The caller first checks that the fixed installed path exists.
/// # Errors
/// Failed execution is an observation error, never evidence of absence.
pub fn detect_installed_binary(sys: &dyn System) -> Probe<Option<V1Marker>> {
    let output = sys
        .run(
            Program::Scupper,
            &["config".into(), "--help".into()],
            EXEC_TIMEOUT,
        )
        .map_err(|_| ProbeError::setup("cannot inspect installed binary"))?;
    let words: BTreeSet<_> = output.stdout.split_whitespace().collect();
    Ok(
        (output.status != Some(0) || !words.contains("bundle") || !words.contains("validate"))
            .then_some(V1Marker::Binary),
    )
}
