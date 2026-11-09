//! Read-only v1 markers reserved for the future install preflight.
use crate::{
    canon::{command, command_result},
    parse,
    rules::V1Config,
    system::{EXEC_TIMEOUT, Program, SYSTEMCTL_TIMEOUT, System},
    verdict::{Probe, ProbeError},
};
use std::collections::BTreeSet;

/// Evidence of the retired host layout; never removed by detection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum V1Marker {
    /// An enabled wg-quick instance, including instances outside the v1 defaults.
    EnabledWgQuick(String),
    /// The host namespace contains `table inet scupper`.
    HostTable,
    /// A host link has a v1 tunnel name.
    HostLink(String),
}

/// Finds enabled wg-quick instances, the host table, and v1 tunnel link names.
/// Does not inspect binaries, configuration secrets or namespace contents.
/// Nothing invokes this helper until the install preflight is implemented.
///
/// # Errors
/// Returns execution or parse failures; a failed observation is never absence.
pub fn detect_v1_layout(sys: &dyn System) -> Probe<Vec<V1Marker>> {
    let mut markers = enabled_units(sys)?;
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
    let links = command(
        sys,
        Program::Ip,
        &["-d".into(), "-j".into(), "link".into(), "show".into()],
        EXEC_TIMEOUT,
    )?;
    let config = V1Config::default();
    for link in parse::links(&links)? {
        if link.name == config.client_iface.as_str() || link.name == config.exit_iface.as_str() {
            markers.push(V1Marker::HostLink(link.name));
        }
    }
    Ok(markers)
}

fn enabled_units(sys: &dyn System) -> Probe<Vec<V1Marker>> {
    let mut markers = Vec::new();
    let units = command(
        sys,
        Program::Systemctl,
        &[
            "list-unit-files".into(),
            "--type=service".into(),
            "--no-legend".into(),
            "--no-pager".into(),
            "wg-quick@*.service".into(),
        ],
        SYSTEMCTL_TIMEOUT,
    )?;
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
