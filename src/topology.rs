//! M1 containment collectors, with known violations taking priority over errors.
//!
//! The allowed-IPs check accepts any peer on the client interface: `V1Config` has
//! no client key. The default-route check is IPv4 only; IPv6 forwarding is
//! dropped by the inet forward policy.

use std::{io, path::Path};

use crate::{
    canon::{combined_error, command, observe_ruleset},
    check::TopologySource,
    parse,
    rules::{IfName, V1Config},
    system::{EXEC_TIMEOUT, Program, System},
    verdict::{self, ConfigMismatch, M1Topology, Probe, ProbeError, RulesetObs},
};

/// Injectable reader for the legacy firewall table lists in procfs.
pub trait LegacyTablesReader {
    /// Reads one table list; a missing file means the module is not loaded.
    ///
    /// # Errors
    /// Returns the file read error, including `NotFound` for unloaded modules.
    fn read(&self, path: &Path) -> io::Result<String>;
}

struct ProcLegacyTables;

impl LegacyTablesReader for ProcLegacyTables {
    fn read(&self, path: &Path) -> io::Result<String> {
        std::fs::read_to_string(path)
    }
}

/// Inspects host rules, traffic control and configuration/kernel agreement.
#[derive(Debug, Default)]
pub struct HostTopology;

impl HostTopology {
    /// Uses an injected legacy table reader instead of reading host procfs.
    pub fn with_legacy_reader(reader: &dyn LegacyTablesReader) -> impl TopologySource + '_ {
        TopologyWithReader(reader)
    }
}

struct TopologyWithReader<'a>(&'a dyn LegacyTablesReader);

impl TopologySource for HostTopology {
    fn observe(&self, sys: &dyn System, cfg: &V1Config) -> Probe<M1Topology> {
        TopologyWithReader(&ProcLegacyTables).observe(sys, cfg)
    }
}

fn collect<T>(errors: &mut Vec<ProbeError>, result: Probe<T>) -> Option<T> {
    match result {
        Ok(value) => Some(value),
        Err(error) => {
            errors.push(error);
            None
        }
    }
}

fn query<T>(
    sys: &dyn System,
    program: Program,
    args: &[&str],
    parse: impl FnOnce(&str) -> Result<T, parse::ParseError>,
) -> Probe<T> {
    let args: Vec<_> = args.iter().map(|arg| (*arg).to_owned()).collect();
    Ok(parse(&command(sys, program, &args, EXEC_TIMEOUT)?)?)
}

fn tc_hook(sys: &dyn System, iface: &IfName, errors: &mut Vec<ProbeError>) -> bool {
    let qdisc = collect(
        errors,
        query(
            sys,
            Program::Tc,
            &["-j", "qdisc", "show", "dev", iface.as_str()],
            parse::qdisc_has_hooks,
        ),
    );
    let filter = collect(
        errors,
        query(
            sys,
            Program::Tc,
            &["-j", "filter", "show", "dev", iface.as_str()],
            parse::filter_has_hooks,
        ),
    );
    qdisc == Some(true) || filter == Some(true)
}

fn exit_checks(
    sys: &dyn System,
    cfg: &V1Config,
    link: Option<&parse::Link>,
    topology: &mut M1Topology,
    errors: &mut Vec<ProbeError>,
) {
    let mut exit_errors = Vec::new();
    let mut rechecked = false;
    let mut address_missing = false;
    let mut hook = link.is_some_and(|link| link.xdp);
    for (program, kind) in [
        (Program::Ip, "addr"),
        (Program::Tc, "qdisc"),
        (Program::Tc, "filter"),
    ] {
        // A down exit need not have its address yet.
        if kind == "addr" && link.is_some_and(|link| !link.up) {
            continue;
        }
        let result = query(
            sys,
            program,
            &["-j", kind, "show", "dev", cfg.exit_iface.as_str()],
            |out| match kind {
                "addr" => Ok(!parse::local_addresses(out)?.contains(&cfg.exit_addr.into())),
                "qdisc" => parse::qdisc_has_hooks(out),
                _ => parse::filter_has_hooks(out),
            },
        );
        match result {
            Ok(found) if kind == "addr" => address_missing = found,
            Ok(found) => hook |= found,
            Err(error) => {
                exit_errors.push(error);
                if !rechecked {
                    rechecked = true;
                    // Re-read immediately on the first failed exit query. If
                    // gone, discard its errors and skip its remaining checks.
                    if collect(
                        &mut exit_errors,
                        query(sys, Program::Ip, &["-j", "link", "show"], parse::links),
                    )
                    .is_some_and(|links| {
                        !links
                            .iter()
                            .any(|link| link.name == cfg.exit_iface.as_str())
                    }) {
                        return;
                    }
                }
            }
        }
    }
    errors.extend(exit_errors);
    if address_missing {
        topology
            .config_mismatches
            .push(ConfigMismatch::ExitAddrNotOnExitIface);
    }
    if hook {
        topology.tc_hooks.push(cfg.exit_iface.clone());
    }
}

fn legacy_tables(reader: &dyn LegacyTablesReader, errors: &mut Vec<ProbeError>) -> Vec<String> {
    let mut names = Vec::new();
    for path in [
        "/proc/net/ip_tables_names",
        "/proc/net/ip6_tables_names",
        "/proc/net/arp_tables_names",
    ] {
        match reader.read(Path::new(path)) {
            Ok(text) => names.extend(
                text.split_whitespace()
                    .take(8 - names.len())
                    .map(|name| name.chars().take(32).collect()),
            ),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => errors.push(if error.kind() == io::ErrorKind::PermissionDenied {
                ProbeError::setup(&format!("read {path}: {error}"))
            } else {
                ProbeError::io(&format!("read {path}: {error}"))
            }),
        }
    }
    names
}

impl TopologySource for TopologyWithReader<'_> {
    fn observe(&self, sys: &dyn System, cfg: &V1Config) -> Probe<M1Topology> {
        let mut errors = Vec::new();
        let mut topology = M1Topology {
            // A failed ruleset collector is never returned as Exact unless a
            // separate known violation already determines the safety verdict.
            ruleset: RulesetObs::Exact,
            tc_hooks: Vec::new(),
            legacy_tables: Vec::new(),
            config_mismatches: Vec::new(),
            uplink_addrs: Vec::new(),
        };
        let links = collect(
            &mut errors,
            query(sys, Program::Ip, &["-j", "link", "show"], parse::links),
        );
        if let Some(links) = &links {
            for iface in [&cfg.client_iface, &cfg.uplink_iface] {
                if !links.iter().any(|link| link.name == iface.as_str()) {
                    topology
                        .config_mismatches
                        .push(ConfigMismatch::InterfaceMissing(iface.clone()));
                }
            }
        }
        // Unknown existence still permits independent observations. An absent
        // exit is normal fail-closed state, as is a present link without UP.
        let link = |iface: &IfName| {
            links
                .as_ref()
                .and_then(|links| links.iter().find(|link| link.name == iface.as_str()))
        };
        let exists = |iface: &IfName| links.is_none() || link(iface).is_some();
        if collect(
            &mut errors,
            query(
                sys,
                Program::Ip,
                &["-j", "route", "show", "default"],
                |out| parse::default_routes_use(out, &cfg.uplink_iface),
            ),
        ) == Some(false)
        {
            topology
                .config_mismatches
                .push(ConfigMismatch::UplinkNotDefaultRouteDev);
        }
        if collect(
            &mut errors,
            query(
                sys,
                Program::Wg,
                &["show", cfg.client_iface.as_str(), "allowed-ips"],
                |out| parse::allowed_ips_contain(out, cfg.client_addr),
            ),
        ) == Some(false)
        {
            topology
                .config_mismatches
                .push(ConfigMismatch::ClientAddrNotInPeerAllowedIps);
        }
        if let Some(addrs) = collect(
            &mut errors,
            query(
                sys,
                Program::Ip,
                &["-j", "addr", "show", "dev", cfg.uplink_iface.as_str()],
                parse::local_addresses,
            ),
        ) {
            topology.uplink_addrs = addrs;
        }
        if exists(&cfg.client_iface) {
            let tc = tc_hook(sys, &cfg.client_iface, &mut errors);
            if tc || link(&cfg.client_iface).is_some_and(|link| link.xdp) {
                topology.tc_hooks.push(cfg.client_iface.clone());
            }
        }
        if exists(&cfg.exit_iface) {
            exit_checks(sys, cfg, link(&cfg.exit_iface), &mut topology, &mut errors);
        }
        topology.legacy_tables = legacy_tables(self.0, &mut errors);
        // The namespace canonicalization is last because it is the costly part.
        if let Some(ruleset) = collect(&mut errors, observe_ruleset(sys, cfg)) {
            topology.ruleset = ruleset;
        }
        if verdict::topology_violations(&topology).is_some() || errors.is_empty() {
            Ok(topology)
        } else {
            Err(combined_error(errors.remove(0), &errors))
        }
    }
}
