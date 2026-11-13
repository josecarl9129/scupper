//! Read-only v1 markers used by installation preflight.
use crate::{
    canon::{command, command_result},
    rules::V1Config,
    system::{EXEC_TIMEOUT, ExecError, Program, SYSTEMCTL_TIMEOUT, System},
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
    let mut markers = Vec::new();
    let output = sys.run(
        Program::Systemctl,
        &[
            "list-unit-files".into(),
            "--type=service".into(),
            "--no-legend".into(),
            "--no-pager".into(),
            "wg-quick@*.service".into(),
        ],
        SYSTEMCTL_TIMEOUT,
    );
    // systemctl returns a nonzero status when this glob matches no unit files.
    // Keep failures with diagnostics or any listed units as observation errors.
    let units = match output {
        Ok(output)
            if output.status.is_some_and(|status| status != 0)
                && matches!(output.stdout.trim(), "" | "0 unit files listed.")
                && output.stderr.lines().all(no_units_diagnostic) =>
        {
            String::new()
        }
        other => command_result(other)?,
    };
    let mut instances = BTreeSet::new();
    for line in units.lines().filter(|line| !line.trim().is_empty()) {
        let name = line.split_whitespace().next().unwrap_or_default();
        // The installed template is present even on a clean M2 host.
        if name == "wg-quick@.service" {
            continue;
        }
        if !name.starts_with("wg-quick@")
            || !name.ends_with(".service")
            || name.len() <= "wg-quick@.service".len()
        {
            return Err(ProbeError::setup("malformed wg-quick unit listing"));
        }
        instances.insert(name.to_owned());
    }
    for unit in instances {
        let output = sys.run(
            Program::Systemctl,
            &["is-enabled".into(), unit.clone()],
            SYSTEMCTL_TIMEOUT,
        );
        match output {
            Ok(output)
                if output.status == Some(0)
                    && matches!(output.stdout.trim(), "enabled" | "enabled-runtime") =>
            {
                markers.push(V1Marker::EnabledWgQuick(unit));
            }
            Ok(output)
                if matches!(output.status, Some(0 | 1 | 3 | 4))
                    && matches!(
                        output.stdout.trim(),
                        "disabled"
                            | "masked"
                            | "masked-runtime"
                            | "static"
                            | "indirect"
                            | "not-found"
                            | "linked"
                            | "linked-runtime"
                            | "alias"
                            | "generated"
                            | "transient"
                    ) => {}
            other => {
                command_result(other)?;
                return Err(ProbeError::setup("unexpected is-enabled response"));
            }
        }
    }
    Ok(markers)
}

fn no_units_diagnostic(line: &str) -> bool {
    matches!(
        line.trim()
            .trim_end_matches('.')
            .to_ascii_lowercase()
            .as_str(),
        "" | "no units found"
            | "no unit files found"
            | "no matching unit files found"
            | "0 unit files listed"
    )
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
