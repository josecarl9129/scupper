//! Complete repair inventories. The health summaries deliberately discard identities.
use super::{key_bytes, peer_field, topology::peers, wg};
use crate::{
    canon::{canonicalize, command_result, fingerprint},
    cmd::{IpCmd, KernelCmd, NftCmd, RouteTable, SysctlCmd, TcCmd, TcParent, run_cmd},
    netns::NetnsHandle,
    reconcile::Observation,
    system::{EXEC_TIMEOUT, ExecError, ExecOutput, ExecTarget, Program, System},
};
use scupper_core::{
    failover::ExitLinkState,
    parse::{
        Handshake, WgField, WgOutput, parse_ip_addr, parse_ip_link, parse_ip_route, parse_ip_rule,
        parse_sysctl, parse_tc_filter, parse_tc_qdisc,
    },
    planner::{
        Desired, KernelLink, KernelModel, Known, LinkSettings, NamespaceState, RouteKey, Ruleset,
    },
    render::{Family, Scope, SysctlFamily, SysctlKey},
    rules::IfName,
    verdict::v2::{DefaultRouteObs, HealthConfigV2, Probe, ProbeError},
};
use scupper_proto::ReadFailureKind;
use std::{
    cell::{Cell, RefCell},
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

/// Applies a shared safety deadline in addition to the per-exec bound.
pub(crate) struct SafetySystem<'a> {
    pub(crate) system: &'a dyn System,
    pub(crate) read_purpose: crate::system::HelperPurpose,
    pub(crate) deadline: Instant,
    pub(crate) failed: Cell<bool>,
    pub(crate) failures: RefCell<Vec<scupper_proto::ReadFailure>>,
    pub(crate) unsafe_tc: RefCell<BTreeSet<String>>,
}
impl SafetySystem<'_> {
    fn purpose(&self, purpose: crate::system::HelperPurpose) -> crate::system::HelperPurpose {
        use crate::system::HelperPurpose;
        match purpose {
            HelperPurpose::Observation | HelperPurpose::Probe => self.read_purpose,
            HelperPurpose::Mutation | HelperPurpose::Storage | HelperPurpose::Notification => {
                purpose
            }
        }
    }
}
impl System for SafetySystem<'_> {
    fn record_unsafe_tc(&self, link: &str) {
        self.unsafe_tc.borrow_mut().insert(link.to_owned());
    }

    fn record_read_failure(&self, failure: scupper_proto::ReadFailure) {
        self.failed.set(true);
        let mut failures = self.failures.borrow_mut();
        if failures.len() < 64 && !failures.contains(&failure) {
            failures.push(failure);
        }
    }

    fn client_session_io(
        &self,
        purpose: crate::system::HelperPurpose,
        held: &NetnsHandle,
        request: &crate::client_sessions::Request,
    ) -> std::io::Result<crate::client_sessions::Response> {
        if Instant::now() >= self.deadline {
            return Err(std::io::ErrorKind::TimedOut.into());
        }
        let result = self
            .system
            .client_session_io(self.purpose(purpose), held, request)?;
        if Instant::now() >= self.deadline {
            return Err(std::io::ErrorKind::TimedOut.into());
        }
        Ok(result)
    }
    fn canon_safety_deadline(&self) -> Option<Instant> {
        Some(self.deadline)
    }
    fn canon_worker(&self) -> Option<Box<dyn System + Send>> {
        self.system.canon_worker()
    }
    fn canon_executable(&self) -> &Path {
        self.system.canon_executable()
    }
    fn canon_run_root(&self) -> &Path {
        self.system.canon_run_root()
    }
    fn canon_cache(&self) -> Option<(&std::cell::RefCell<crate::canon::CanonCache>, &Path)> {
        self.system.canon_cache()
    }

    fn run(
        &self,
        purpose: crate::system::HelperPurpose,
        p: Program,
        args: &[String],
        timeout: Duration,
    ) -> Result<ExecOutput, ExecError> {
        self.run_in(purpose, ExecTarget::Host, p, args, timeout)
    }
    fn run_in(
        &self,
        purpose: crate::system::HelperPurpose,
        target: ExecTarget<'_>,
        p: Program,
        args: &[String],
        timeout: Duration,
    ) -> Result<ExecOutput, ExecError> {
        // Reserve executor cleanup/reaping time within this shared deadline.
        let remaining = self
            .deadline
            .saturating_duration_since(Instant::now())
            .saturating_sub(Duration::from_millis(900));
        let purpose = self.purpose(purpose);
        let result = if remaining.is_zero() {
            Err(ExecError::Timeout {
                after: Duration::from_secs(6),
            })
        } else {
            self.system.run_in(
                purpose,
                target,
                p,
                args,
                timeout.min(EXEC_TIMEOUT).min(remaining),
            )
        };
        if !result.as_ref().is_ok_and(|out| out.status == Some(0)) {
            self.failed.set(true);
            let failure = match &result {
                Ok(out) if out.status.is_none() => ReadFailureKind::Signal,
                Ok(_) => ReadFailureKind::ExitStatus,
                Err(ExecError::Timeout { .. }) => ReadFailureKind::Timeout,
                Err(ExecError::OutputTooLarge { .. }) => ReadFailureKind::OutputTooLarge,
                Err(ExecError::NonUtf8) => ReadFailureKind::NonUtf8,
                Err(ExecError::NamespaceIdentity | ExecError::NamespaceEnter { .. }) => {
                    ReadFailureKind::NamespaceIdentity
                }
                Err(_) => ReadFailureKind::Spawn,
            };
            if let Some(context) = read_context(target, p, args, failure) {
                self.record_read_failure(context);
            }
        }
        result
    }
    fn now_unix_secs(&self) -> u64 {
        self.system.now_unix_secs()
    }
    fn wireguard_socket_dirs(&self) -> Vec<PathBuf> {
        self.system.wireguard_socket_dirs()
    }
    fn read_host_udp(&self, ipv6: bool) -> std::io::Result<String> {
        self.system.read_host_udp(ipv6)
    }
}
fn read_context(
    target: ExecTarget<'_>,
    program: Program,
    args: &[String],
    failure: scupper_proto::ReadFailureKind,
) -> Option<scupper_proto::ReadFailure> {
    use scupper_proto::{ReadNamespace as N, ReadStage as S};
    let has = |arg: &str| args.iter().any(|value| value == arg);
    let stage = match program {
        Program::Ip if has("link") => S::LinkList,
        Program::Nft => S::Ruleset,
        Program::Sysctl => S::Sysctl,
        Program::Tc if has("qdisc") => S::TcQdisc,
        Program::Tc if has("ingress") => S::TcFilterIngress,
        Program::Tc if has("egress") => S::TcFilterEgress,
        Program::Tc => S::TcFilterRoot,
        _ => return None,
    };
    let link = args
        .windows(2)
        .find(|pair| pair[0] == "dev")
        .map(|pair| pair[1].clone())
        .or_else(|| {
            if program == Program::Sysctl {
                args.iter().find_map(|arg| {
                    arg.split(".conf.")
                        .nth(1)
                        .and_then(|tail| tail.split('.').next())
                        .filter(|name| !matches!(*name, "all" | "default"))
                        .map(str::to_owned)
                })
            } else {
                None
            }
        });
    Some(scupper_proto::ReadFailure {
        namespace: match target {
            ExecTarget::Host => N::Host,
            ExecTarget::Netns(_) => N::Held,
        },
        link,
        stage,
        failure,
    })
}
fn read_parsed<T>(
    sys: &dyn System,
    target: ExecTarget<'_>,
    cmd: &KernelCmd,
    parse: impl FnOnce(&str) -> Result<T, scupper_core::parse::ParseError>,
) -> Probe<T> {
    let text = read_in(sys, target, cmd)?;
    parse(&text).map_err(|error| {
        let (program, args) = cmd.render();
        if let Some(context) = read_context(
            target,
            program,
            &args,
            scupper_proto::ReadFailureKind::Parse,
        ) {
            sys.record_read_failure(context);
        }
        error.into()
    })
}
fn read(sys: &dyn System, held: &NetnsHandle, cmd: &KernelCmd) -> Probe<String> {
    command_result(run_cmd(sys, ExecTarget::Netns(held), cmd, EXEC_TIMEOUT))
}
fn known<T>(value: Probe<T>) -> Known<T> {
    value.map_or(Known::Unknown, Known::Value)
}
fn gate(
    sys: &dyn System,
    held: &NetnsHandle,
    family: SysctlFamily,
    scope: Scope,
    name: &'static str,
) -> Known<i64> {
    known(read_parsed(
        sys,
        ExecTarget::Netns(held),
        &KernelCmd::Sysctl(SysctlCmd::Read(SysctlKey {
            family,
            scope,
            name,
        })),
        parse_sysctl,
    ))
}

pub(crate) fn hooks(
    sys: &dyn System,
    held: &NetnsHandle,
    name: &str,
    xdp: bool,
) -> Probe<Vec<String>> {
    hooks_in(sys, ExecTarget::Netns(held), name, xdp)
}
fn read_in(sys: &dyn System, target: ExecTarget<'_>, cmd: &KernelCmd) -> Probe<String> {
    command_result(run_cmd(sys, target, cmd, EXEC_TIMEOUT))
}
fn hooks_in(sys: &dyn System, target: ExecTarget<'_>, name: &str, xdp: bool) -> Probe<Vec<String>> {
    let dev = IfName::new(name).map_err(|_| ProbeError::io("unrepresentable tc link"))?;
    let mut hooks = if xdp { vec!["xdp".into()] } else { Vec::new() };
    let qdiscs = match read_parsed(
        sys,
        target,
        &KernelCmd::Tc(TcCmd::QdiscShowJson { dev: dev.clone() }),
        parse_tc_qdisc,
    ) {
        Ok(value) => value,
        Err(error) => {
            if !hooks.is_empty() {
                sys.record_unsafe_tc(name);
            }
            return Err(error);
        }
    };
    for q in qdiscs {
        if q.kind == "noqueue"
            && q.root
            && q.handle.as_deref() == Some("0:")
            && q.parent.is_none()
            && q.dev.as_deref().is_none_or(|d| d == name)
            && q.options
                .as_ref()
                .is_none_or(|o| o.as_object().is_some_and(serde_json::Map::is_empty))
        {
            continue;
        }
        hooks.push(if matches!(q.kind.as_str(), "ingress" | "clsact") {
            q.kind
        } else {
            "root".into()
        });
    }
    for parent in [TcParent::Root, TcParent::Ingress, TcParent::Egress] {
        let filters = match read_parsed(
            sys,
            target,
            &KernelCmd::Tc(TcCmd::FilterShowJson {
                dev: dev.clone(),
                parent,
            }),
            parse_tc_filter,
        ) {
            Ok(value) => value,
            Err(error) => {
                if !hooks.is_empty() {
                    sys.record_unsafe_tc(name);
                }
                return Err(error);
            }
        };
        if !filters.is_empty() {
            hooks.push(
                match parent {
                    TcParent::Root => "root",
                    TcParent::Ingress => "ingress-filters",
                    TcParent::Egress => "egress-filters",
                }
                .into(),
            );
        }
    }
    hooks.sort();
    hooks.dedup();
    Ok(hooks)
}

fn settings(
    sys: &dyn System,
    held: &NetnsHandle,
    name: &str,
    mtu: u32,
    client: bool,
) -> Probe<LinkSettings> {
    let public_key = if client {
        match wg(sys, held, name, WgField::PublicKey)? {
            WgOutput::PublicKey(key) => key.as_ref().map(key_bytes).transpose()?,
            _ => return Err(ProbeError::io("invalid public key field")),
        }
    } else {
        None
    };
    let WgOutput::ListenPort(port) = wg(sys, held, name, WgField::ListenPort)? else {
        return Err(ProbeError::io("invalid listen port field"));
    };
    let keepalives = if client {
        BTreeMap::new()
    } else {
        peer_field(sys, held, name, WgField::PersistentKeepalive)?
            .into_iter()
            .map(|p| {
                Ok((
                    key_bytes(&p.public_key)?,
                    Duration::from_secs(u64::from(
                        p.keepalive
                            .ok_or_else(|| ProbeError::io("missing keepalive"))?,
                    )),
                ))
            })
            .collect::<Probe<_>>()?
    };
    Ok(LinkSettings {
        mtu,
        public_key,
        listen_port: if client { u32::from(port) } else { 0 },
        keepalives,
    })
}

pub(crate) fn rules(sys: &dyn System, held: &NetnsHandle) -> Probe<Vec<String>> {
    let mut extra = Vec::new();
    for family in [Family::V4, Family::V6] {
        let raw = read(sys, held, &KernelCmd::Ip(IpCmd::RuleShowJson { family }))?;
        let mut parsed = parse_ip_rule(&raw)?;
        let json: serde_json::Value =
            serde_json::from_str(&raw).map_err(|_| ProbeError::io("invalid rules"))?;
        let baseline = if family == Family::V4 {
            r#"[{"priority":0,"src":"all","table":"local"},{"priority":32766,"src":"all","table":"main"},{"priority":32767,"src":"all","table":"default"}]"#
        } else {
            r#"[{"priority":0,"src":"all","table":"local"},{"priority":32766,"src":"all","table":"main"}]"#
        };
        let want = parse_ip_rule(baseline)?;
        for rule in &mut parsed {
            if matches!(rule.protocol.as_deref(), Some("kernel" | "2")) {
                rule.protocol = None;
            }
        }
        if !want.iter().all(|r| parsed.contains(r)) {
            return Err(ProbeError::io("baseline policy rule missing"));
        }
        for (index, rule) in parsed.iter().enumerate().filter(|(_, r)| !want.contains(r)) {
            if parsed
                .iter()
                .filter(|r| r.priority == rule.priority)
                .count()
                != 1
            {
                return Err(ProbeError::io("ambiguous rule priority"));
            }
            extra.push(
                serde_json::json!({"v6": family == Family::V6, "rule": json[index]}).to_string(),
            );
        }
    }
    Ok(extra)
}

fn routes(sys: &dyn System, held: &NetnsHandle, cfg: &HealthConfigV2, model: &mut KernelModel) {
    let mut extra = Vec::new();
    let mut complete = true;
    for family in [Family::V4, Family::V6] {
        let result = read(
            sys,
            held,
            &KernelCmd::Ip(IpCmd::RouteShowJson {
                family,
                table: RouteTable::All,
            }),
        )
        .and_then(|s| Ok(parse_ip_route(&s)?));
        let target = if family == Family::V4 {
            &mut model.default_v4
        } else {
            &mut model.default_v6
        };
        *target = Known::Unknown;
        match result {
            Ok(routes) => {
                let mut default_seen = false;
                *target = Known::Value(DefaultRouteObs::Missing);
                for route in routes {
                    use scupper_core::parse::{RouteDestination, RoutingTable};
                    if route.table == RoutingTable::Main
                        && route.dst == RouteDestination::Default
                        && !default_seen
                    {
                        *target = Known::Value(super::routes::answer(&route));
                        default_seen = true;
                    } else if !(route.table == RoutingTable::Main
                        && super::routes::kernel_route(&route, cfg)
                        || route.table == RoutingTable::Local
                            && super::routes::kernel_local(&route, cfg, family))
                    {
                        extra.push(RouteKey {
                            family,
                            entry: route,
                        });
                    }
                }
            }
            Err(_) => complete = false,
        }
    }
    model.extra_routes = if complete {
        Known::Value(extra)
    } else {
        Known::Unknown
    };
}

// Safety first: inode, links, ruleset, all forwarding gates and hooks. Only then
// collect public configuration, routes, host leftovers, hardening and handshakes.
#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
pub(crate) fn observe(
    sys: &dyn System,
    held: &NetnsHandle,
    desired: &Desired,
    cfg: &HealthConfigV2,
    namespace: &Path,
    edge: Option<&Path>,
    owned: &BTreeMap<String, u32>,
) -> Observation {
    observe_until(
        sys,
        held,
        desired,
        cfg,
        namespace,
        edge,
        owned,
        Instant::now() + Duration::from_secs(6),
    )
}

#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
pub(crate) fn observe_until(
    sys: &dyn System,
    held: &NetnsHandle,
    desired: &Desired,
    cfg: &HealthConfigV2,
    namespace: &Path,
    edge: Option<&Path>,
    owned: &BTreeMap<String, u32>,
    deadline: Instant,
) -> Observation {
    observe_safety(sys, held, desired, cfg, namespace, edge, owned, deadline)
}
#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
fn observe_safety(
    sys: &dyn System,
    held: &NetnsHandle,
    desired: &Desired,
    cfg: &HealthConfigV2,
    namespace: &Path,
    edge: Option<&Path>,
    owned: &BTreeMap<String, u32>,
    deadline: Instant,
) -> Observation {
    let start = Instant::now();
    let safety = SafetySystem {
        read_purpose: crate::system::HelperPurpose::Observation,
        system: sys,
        deadline,
        failed: Cell::new(false),
        failures: RefCell::new(Vec::new()),
        unsafe_tc: RefCell::new(BTreeSet::new()),
    };
    let mut model = KernelModel::desired(desired);
    model.conntrack_flushed = false;
    model.latch = None;
    model.namespace = match sys.namespace_identity(namespace) {
        Ok(identity) if identity == held.identity() => NamespaceState::Ready,
        Ok(_) => NamespaceState::NameGone,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => NamespaceState::NameGone,
        Err(_) => {
            safety.record_read_failure(scupper_proto::ReadFailure {
                namespace: scupper_proto::ReadNamespace::Held,
                link: None,
                stage: scupper_proto::ReadStage::NamespaceIdentity,
                failure: scupper_proto::ReadFailureKind::Io,
            });
            NamespaceState::Unknown
        }
    };
    if let Some(path) = edge {
        match sys.namespace_identity(path) {
            Ok(identity) if identity != held.identity() => {
                if model.namespace == NamespaceState::Ready {
                    model.namespace = NamespaceState::EdgeElsewhere;
                }
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => model.edge_dead = true,
            Err(_) => safety.record_read_failure(scupper_proto::ReadFailure {
                namespace: scupper_proto::ReadNamespace::Edge,
                link: None,
                stage: scupper_proto::ReadStage::NamespaceIdentity,
                failure: scupper_proto::ReadFailureKind::Io,
            }),
        }
    }
    let raw = read_parsed(
        &safety,
        ExecTarget::Netns(held),
        &KernelCmd::Ip(IpCmd::LinkShowJson),
        parse_ip_link,
    );
    model.links_complete = raw.is_ok();
    let raw = raw.unwrap_or_else(|_| {
        safety.failed.set(true);
        vec![]
    });
    model.links.clear();
    let ruleset = if safety.canon_cache().is_some() {
        crate::canon::netns_rulesets_safety(&safety, held, desired.rendered()).and_then(
            |(want, live)| {
                Ok(if live == want {
                    Ruleset::Verified(desired.fingerprint())
                } else if live
                    .get("nftables")
                    .and_then(serde_json::Value::as_array)
                    .is_some_and(Vec::is_empty)
                {
                    Ruleset::Absent
                } else {
                    Ruleset::Unverified(fingerprint(&live)?)
                })
            },
        )
    } else {
        read(&safety, held, &KernelCmd::Nft(NftCmd::ListRulesetJson)).and_then(|text| {
            let canon = canonicalize(&text)?;
            let live = fingerprint(&canon)?;
            Ok(if live == desired.fingerprint() {
                Ruleset::Verified(live)
            } else if canon
                .get("nftables")
                .and_then(serde_json::Value::as_array)
                .is_some_and(Vec::is_empty)
            {
                Ruleset::Absent
            } else {
                Ruleset::Unverified(live)
            })
        })
    };
    if let Err(error) = &ruleset
        && !safety
            .failures
            .borrow()
            .iter()
            .any(|context| context.stage == scupper_proto::ReadStage::Ruleset)
    {
        let failure = match error {
            ProbeError::Timeout => ReadFailureKind::Timeout,
            ProbeError::ExitStatus { code: None, .. } => ReadFailureKind::Signal,
            ProbeError::ExitStatus { .. } => ReadFailureKind::ExitStatus,
            ProbeError::Parse(_) => ReadFailureKind::Parse,
            _ => ReadFailureKind::Io,
        };
        safety.record_read_failure(scupper_proto::ReadFailure {
            namespace: scupper_proto::ReadNamespace::Held,
            link: None,
            stage: scupper_proto::ReadStage::Ruleset,
            failure,
        });
    }
    model.ruleset = known(ruleset);
    model.forwarding_v4 = gate(
        &safety,
        held,
        SysctlFamily::Ipv4,
        Scope::Global,
        "ip_forward",
    );
    model.forwarding_v6 = gate(&safety, held, SysctlFamily::Ipv6, Scope::All, "forwarding");
    model.default_forwarding_v4 = gate(
        &safety,
        held,
        SysctlFamily::Ipv4,
        Scope::Default,
        "forwarding",
    );
    model.default_forwarding_v6 = gate(
        &safety,
        held,
        SysctlFamily::Ipv6,
        Scope::Default,
        "forwarding",
    );
    let mut failed_links = Vec::new();
    for link in &raw {
        // Per-link failures can mean deletion after the dump. Keep their failure
        // accounting separate until one bounded re-dump can prove absence.
        let per_link = SafetySystem {
            read_purpose: crate::system::HelperPurpose::Observation,
            system: sys,
            deadline: safety.deadline,
            failed: Cell::new(false),
            failures: RefCell::new(Vec::new()),
            unsafe_tc: RefCell::new(BTreeSet::new()),
        };
        let name = &link.ifname;
        let ifname = IfName::new(name);
        let (gates, tc) = match ifname {
            Ok(dev) => (
                [
                    gate(
                        &per_link,
                        held,
                        SysctlFamily::Ipv4,
                        Scope::Link(dev.clone()),
                        "forwarding",
                    ),
                    gate(
                        &per_link,
                        held,
                        SysctlFamily::Ipv6,
                        Scope::Link(dev),
                        "forwarding",
                    ),
                ],
                known(hooks(&per_link, held, name, link.xdp)),
            ),
            Err(_) => ([Known::Unknown, Known::Unknown], Known::Unknown),
        };
        if per_link.failed.get() || gates.contains(&Known::Unknown) || tc == Known::Unknown {
            failed_links.push((name.clone(), link.ifindex));
        }
        safety
            .failures
            .borrow_mut()
            .extend(per_link.failures.into_inner());
        safety
            .unsafe_tc
            .borrow_mut()
            .extend(per_link.unsafe_tc.into_inner());
        model.links.insert(
            name.clone(),
            KernelLink {
                kind: Known::Value(if name == "lo" {
                    "loopback".into()
                } else {
                    link.kind.clone().unwrap_or_default()
                }),
                ours: Known::Value(
                    owned.get(name) == Some(&link.ifindex)
                        && link.kind.as_deref() == Some("wireguard"),
                ),
                up: Known::Value(link.flags.iter().any(|f| f == "UP")),
                addresses: Known::Unknown,
                peers: if link.kind.as_deref() == Some("wireguard") {
                    Known::Unknown
                } else {
                    Known::Value(vec![])
                },
                settings: Known::Unknown,
                tc_hooks: tc,
                forwarding_v4: gates[0].clone(),
                forwarding_v6: gates[1].clone(),
            },
        );
    }
    if !failed_links.is_empty() {
        // A complete second dump proves only absence of the same identity, never
        // safety of a replacement with the same name or a newly introduced link.
        // One re-dump for the entire failed batch uses the original safety deadline.
        let again = read_parsed(
            &safety,
            ExecTarget::Netns(held),
            &KernelCmd::Ip(IpCmd::LinkShowJson),
            parse_ip_link,
        );
        match again {
            Ok(again) => {
                if again.iter().any(|link| {
                    !raw.iter()
                        .any(|old| old.ifname == link.ifname && old.ifindex == link.ifindex)
                }) {
                    model.links_complete = false;
                }
                for (name, ifindex) in failed_links {
                    if again
                        .iter()
                        .all(|link| link.ifname != name && link.ifindex != ifindex)
                    {
                        model.links.remove(&name);
                        safety.unsafe_tc.borrow_mut().remove(&name);
                        safety
                            .failures
                            .borrow_mut()
                            .retain(|failure| failure.link.as_ref() != Some(&name));
                    } else {
                        safety.failed.set(true);
                    }
                }
            }
            Err(_) => safety.failed.set(true),
        }
    }
    model.client_forwarding_v4 = model.links.get(&model.client_link).map_or_else(
        || {
            if model.links_complete {
                Known::Value(0)
            } else {
                Known::Unknown
            }
        },
        |link| link.forwarding_v4.clone(),
    );
    // Routing evidence is part of the stop classification even with closed
    // ingress/forwarding; an unrelated closed gate is not a global safety proof.
    model.extra_rules = known(rules(&safety, held));
    routes(&safety, held, cfg, &mut model);
    let safety_complete = model.links_complete
        && !safety.failed.get()
        && Instant::now() < deadline
        && model.ruleset != Known::Unknown
        && [
            &model.forwarding_v4,
            &model.forwarding_v6,
            &model.default_forwarding_v4,
            &model.default_forwarding_v6,
        ]
        .iter()
        .all(|v| **v != Known::Unknown)
        && model.links.values().all(|l| {
            l.tc_hooks != Known::Unknown
                && l.forwarding_v4 != Known::Unknown
                && l.forwarding_v6 != Known::Unknown
        });
    let safety_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
    super::super::reconcile::unknown_nonsafety(&mut model);
    Observation {
        failures: safety.failures.into_inner(),
        known_unsafe_tc: !safety.unsafe_tc.into_inner().is_empty(),
        model,
        safety_complete,
        safety_ms,
        complete: safety_complete,
        handshakes: BTreeMap::new(),
        exit_links: BTreeMap::new(),
    }
}

/// Complete availability observations only after the emergency prefix.
#[allow(clippy::too_many_lines)]
pub(crate) fn observe_rest(
    system: &dyn System,
    held: &NetnsHandle,
    desired: &Desired,
    cfg: &HealthConfigV2,
    observed: Observation,
    deadline: Instant,
) -> Observation {
    observe_availability(system, held, desired, cfg, observed, deadline)
}
#[allow(clippy::too_many_lines)]
fn observe_availability(
    system: &dyn System,
    held: &NetnsHandle,
    desired: &Desired,
    cfg: &HealthConfigV2,
    observed: Observation,
    deadline: Instant,
) -> Observation {
    let bounded = SafetySystem {
        read_purpose: crate::system::HelperPurpose::Observation,
        system,
        deadline,
        failed: Cell::new(false),
        failures: RefCell::new(Vec::new()),
        unsafe_tc: RefCell::new(BTreeSet::new()),
    };
    let sys: &dyn System = &bounded;
    let Observation {
        mut model,
        mut failures,
        known_unsafe_tc,
        safety_complete,
        safety_ms,
        ..
    } = observed;
    let raw = read(sys, held, &KernelCmd::Ip(IpCmd::LinkShowJson))
        .and_then(|s| Ok(parse_ip_link(&s)?))
        .unwrap_or_default();
    let addresses = read(sys, held, &KernelCmd::Ip(IpCmd::AddrShowJson))
        .and_then(|s| Ok(parse_ip_addr(&s)?))
        .ok();
    for link in &raw {
        let Some(actual) = model.links.get_mut(&link.ifname) else {
            continue;
        };
        actual.addresses = addresses
            .as_ref()
            .and_then(|a| {
                a.iter()
                    .find(|a| a.ifindex == link.ifindex && a.ifname == link.ifname)
            })
            .map_or(Known::Unknown, |a| {
                known(
                    a.addresses
                        .iter()
                        .map(|a| {
                            ipnet::IpNet::new(a.local, a.prefixlen)
                                .map_err(|_| ProbeError::io("invalid prefix"))
                        })
                        .collect(),
                )
            });
        if link.kind.as_deref() == Some("wireguard") && desired.links().contains_key(&link.ifname) {
            actual.peers = known(peers(sys, held, &link.ifname));
            actual.settings = known(settings(
                sys,
                held,
                &link.ifname,
                link.mtu,
                link.ifname == model.client_link,
            ));
        }
    }
    for setting in desired.hardening() {
        model.hardening.insert(
            setting.key.to_string(),
            known(
                read(
                    sys,
                    held,
                    &KernelCmd::Sysctl(SysctlCmd::Read(setting.key.clone())),
                )
                .and_then(|s| Ok(parse_sysctl(&s)?.to_string())),
            ),
        );
    }
    model.extra_rules = known(rules(sys, held));
    routes(sys, held, cfg, &mut model);
    // A failed host inventory must not look like an empty, positively owned host.
    model.host_links.clear();
    let host = command_result(run_cmd(
        sys,
        ExecTarget::Host,
        &KernelCmd::Ip(IpCmd::LinkShowJson),
        EXEC_TIMEOUT,
    ))
    .and_then(|s| Ok(parse_ip_link(&s)?));
    let host_addresses = command_result(run_cmd(
        sys,
        ExecTarget::Host,
        &KernelCmd::Ip(IpCmd::AddrShowJson),
        EXEC_TIMEOUT,
    ))
    .and_then(|s| Ok(parse_ip_addr(&s)?))
    .ok();
    model.host_links_complete = host.is_ok();
    if let Ok(host) = host {
        for link in host
            .into_iter()
            .filter(|l| desired.links().contains_key(&l.ifname))
        {
            let peers = command_result(run_cmd(
                sys,
                ExecTarget::Host,
                &KernelCmd::Wg(crate::cmd::WgCmd::Show {
                    ifname: match IfName::new(&link.ifname) {
                        Ok(n) => n,
                        Err(_) => continue,
                    },
                    field: WgField::Peers,
                }),
                EXEC_TIMEOUT,
            ));
            let Some(mut record) = KernelModel::desired(desired).links.remove(&link.ifname) else {
                continue;
            };
            record.kind = Known::Value(link.kind.unwrap_or_default());
            record.up = Known::Value(link.flags.iter().any(|f| f == "UP"));
            record.peers = if peers.is_ok_and(|p| p.trim().is_empty()) {
                Known::Value(vec![])
            } else {
                Known::Unknown
            };
            record.addresses = host_addresses
                .as_ref()
                .and_then(|a| {
                    a.iter()
                        .find(|a| a.ifname == link.ifname && a.ifindex == link.ifindex)
                })
                .map_or(Known::Unknown, |a| {
                    known(
                        a.addresses
                            .iter()
                            .map(|a| {
                                ipnet::IpNet::new(a.local, a.prefixlen)
                                    .map_err(|_| ProbeError::io("invalid host prefix"))
                            })
                            .collect(),
                    )
                });
            record.tc_hooks = known(hooks_in(sys, ExecTarget::Host, &link.ifname, link.xdp));
            record.ours = Known::Value(false); // Replaced below only on positive leftover verification.
            if record.kind == Known::Value("wireguard".into())
                && record.up == Known::Value(false)
                && record.peers == Known::Value(vec![])
                && record.addresses == Known::Value(vec![])
                && record.tc_hooks == Known::Value(vec![])
            {
                record.ours = Known::Value(true);
            }
            model.host_links.insert(link.ifname, record);
        }
    }
    let mut handshakes = BTreeMap::new();
    let mut exit_links = BTreeMap::new();
    for (id, name) in desired.exits() {
        if let Ok(map) = super::handshake_map(sys, held, name)
            && let Some(peer) = desired.links().get(name).and_then(|l| l.peers.first())
            && let Some(h) = map.get(&peer.public_key)
        {
            let age = match h {
                Handshake::At { unix_secs: at } if *at <= sys.now_unix_secs() => {
                    Some(Duration::from_secs(sys.now_unix_secs() - *at))
                }
                Handshake::Never | Handshake::At { .. } => None,
            };
            if age.is_none_or(|a| a > cfg.max_handshake_age) {
                model.stale_exits.insert(id.clone());
            }
            handshakes.insert(id.clone(), age);
        }
        let link = model.links.get(name);
        exit_links.insert(
            id.clone(),
            ExitLinkState {
                link_up: link.is_some_and(|l| l.up == Known::Value(true)),
                peer_present: link.is_some_and(|l| l.peers.value().is_some_and(|p| !p.is_empty())),
                key_present: true,
            },
        );
    }
    failures.extend(bounded.failures.into_inner());
    Observation {
        failures,
        known_unsafe_tc,
        model,
        safety_complete,
        safety_ms,
        complete: Instant::now() < deadline,
        handshakes,
        exit_links,
    }
}
