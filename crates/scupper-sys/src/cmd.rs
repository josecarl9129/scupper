//! Typed literal kernel commands. Secret input is supplied separately on stdin.

use crate::netns::NetnsHandle;
use crate::system::{ExecError, ExecOutput, ExecTarget, Program, System};
use ipnet::IpNet;
pub use scupper_core::parse::WgField;
use scupper_core::{
    parse::PeerKey,
    render::{Family, RouteTarget, SysctlKey, route_argv},
    rules::IfName,
};
use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};

/// Tables accepted by a route inventory command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteTable {
    /// Main routing table.
    Main,
    /// Kernel local routing table.
    Local,
    /// All routing tables, including local routes.
    All,
}

/// Allowed iproute2 observations and mutations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpCmd {
    /// All links as JSON.
    LinkShowJson,
    /// All interface addresses as JSON.
    AddrShowJson,
    /// Routes for one family and table selection.
    RouteShowJson {
        /// Address family.
        family: Family,
        /// Tables to inspect.
        table: RouteTable,
    },
    /// Default routes for one family.
    DefaultShowJson(Family),
    /// Policy rules for one family.
    RuleShowJson {
        /// Address family.
        family: Family,
    },
    /// The kernel's textual route answer for a packet.
    RouteGet {
        /// Destination address.
        dst: IpAddr,
        /// Optional source address.
        from: Option<IpAddr>,
        /// Optional ingress interface for forwarded traffic.
        iif: Option<IfName>,
    },
    /// Replace a default route with a validated exit or unreachable route.
    RouteReplace(Family, RouteTarget),
    /// Delete one fully observed route.
    RouteDelete(scupper_core::planner::RouteKey),
    /// Administratively disable a link.
    LinkSetDown(IfName),
    /// Delete a link.
    LinkDelete(IfName),
}

/// The complete `WireGuard` allow-list; no private-key observation is expressible.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WgCmd {
    /// Observe one safe field.
    Show {
        /// Validated interface.
        ifname: IfName,
        /// Public output field.
        field: WgField,
    },
    /// Set a private key exclusively through `/dev/stdin`.
    SetPrivateKeyFromStdin {
        /// Validated interface.
        ifname: IfName,
    },
    /// Set an exit preshared key exclusively through stdin.
    SetPresharedKeyFromStdin {
        /// Validated interface.
        ifname: IfName,
        /// Public peer key.
        public_key: PeerKey,
    },
    /// Configure the UDP listen port.
    SetListenPort {
        /// Validated interface.
        ifname: IfName,
        /// UDP port (zero requests an automatic port).
        port: u16,
    },
    /// Configure a public peer, clearing any previous preshared key.
    SetPeer {
        /// Validated interface.
        ifname: IfName,
        /// Validated public peer key.
        public_key: PeerKey,
        /// Complete allowed prefix set; empty clears it.
        allowed_ips: Vec<IpNet>,
        /// Optional numeric endpoint; DNS resolution happens outside this command.
        endpoint: Option<SocketAddr>,
        /// Optional keepalive interval in seconds; zero disables it.
        keepalive: Option<u16>,
    },
    /// Remove a public peer.
    RemovePeer {
        /// Validated interface.
        ifname: IfName,
        /// Validated public peer key.
        public_key: PeerKey,
    },
    /// Derive a public key from a private key supplied on stdin.
    Pubkey,
}

/// Transactional nftables commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NftCmd {
    /// The complete JSON ruleset.
    ListRulesetJson,
    /// Load a transaction supplied on stdin.
    LoadStdin,
    /// Validate a transaction supplied on stdin.
    CheckStdin,
}

/// Traffic-control attachment being inspected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcParent {
    /// Ingress attachment.
    Ingress,
    /// Egress attachment.
    Egress,
    /// Root attachment.
    Root,
}

/// Traffic-control inventory commands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TcCmd {
    /// Queueing disciplines on an interface.
    QdiscShowJson {
        /// Validated interface.
        dev: IfName,
    },
    /// Filters on a particular attachment.
    FilterShowJson {
        /// Validated interface.
        dev: IfName,
        /// Attachment to inspect.
        parent: TcParent,
    },
}

/// Sysctl operations executed in the selected namespace, never via parent procfs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SysctlCmd {
    /// Read a numeric setting without its key name.
    Read(SysctlKey),
    /// Write a numeric setting. Callers must read it back to verify the value;
    /// procps versions differ in their write exit status. Prefer [`write_sysctl_verified`].
    Write(SysctlKey, i64),
}

/// Connection tracking maintenance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConntrackCmd {
    /// Flush both families (`-F` must not be combined with `-f`).
    Flush,
}

/// Commands permitted by the M2 kernel adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KernelCmd {
    /// Read the selected public UDP socket table in the execution namespace.
    ReadUdp(bool),
    /// Links, addresses, routes and rules.
    Ip(IpCmd),
    /// `WireGuard` public observations and constrained configuration.
    Wg(WgCmd),
    /// Firewall rulesets.
    Nft(NftCmd),
    /// Traffic-control inventory.
    Tc(TcCmd),
    /// Namespace sysctls.
    Sysctl(SysctlCmd),
    /// Connection tracking.
    Conntrack(ConntrackCmd),
}

fn strings(args: &[&str]) -> Vec<String> {
    args.iter().map(|arg| (*arg).to_owned()).collect()
}
fn family_flag(family: Family) -> &'static str {
    match family {
        Family::V4 => "-4",
        Family::V6 => "-6",
    }
}

impl IpCmd {
    fn argv(&self) -> Vec<String> {
        match self {
            Self::LinkShowJson => strings(&["-d", "-j", "link", "show"]),
            Self::AddrShowJson => strings(&["-j", "addr", "show"]),
            Self::RouteShowJson { family, table } => strings(&[
                "-j",
                family_flag(*family),
                "route",
                "show",
                "table",
                match table {
                    RouteTable::Main => "main",
                    RouteTable::Local => "local",
                    RouteTable::All => "all",
                },
            ]),
            Self::DefaultShowJson(family) => {
                strings(&["-j", family_flag(*family), "route", "show", "default"])
            }
            Self::RuleShowJson { family } => strings(&["-j", family_flag(*family), "rule", "show"]),
            Self::RouteGet { dst, from, iif } => {
                let mut args = strings(&["route", "get", &dst.to_string()]);
                if dst.is_ipv6() {
                    args.insert(0, "-6".into());
                }
                if let Some(from) = from {
                    args.extend(["from".into(), from.to_string()]);
                }
                if let Some(iif) = iif {
                    args.extend(["iif".into(), iif.to_string()]);
                }
                args
            }
            Self::RouteReplace(family, target) => route_argv(*family, target),
            Self::RouteDelete(route) => route_delete_argv(route),
            Self::LinkSetDown(dev) => strings(&["link", "set", "dev", dev.as_str(), "down"]),
            Self::LinkDelete(dev) => strings(&["link", "delete", "dev", dev.as_str()]),
        }
    }
}

impl WgCmd {
    fn argv(&self) -> Vec<String> {
        match self {
            Self::Show { ifname, field } => strings(&["show", ifname.as_str(), field.as_str()]),
            Self::SetPrivateKeyFromStdin { ifname } => {
                strings(&["set", ifname.as_str(), "private-key", "/dev/stdin"])
            }
            Self::SetPresharedKeyFromStdin { ifname, public_key } => strings(&[
                "set",
                ifname.as_str(),
                "peer",
                public_key.as_str(),
                "preshared-key",
                "/dev/stdin",
            ]),
            Self::SetListenPort { ifname, port } => {
                strings(&["set", ifname.as_str(), "listen-port", &port.to_string()])
            }
            Self::SetPeer {
                ifname,
                public_key,
                allowed_ips,
                endpoint,
                keepalive,
            } => {
                let mut args = strings(&[
                    "set",
                    ifname.as_str(),
                    "peer",
                    public_key.as_str(),
                    "preshared-key",
                    "/dev/null",
                    "allowed-ips",
                    &allowed_ips
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(","),
                ]);
                if let Some(endpoint) = endpoint {
                    args.extend(["endpoint".into(), endpoint.to_string()]);
                }
                if let Some(seconds) = keepalive {
                    args.extend(["persistent-keepalive".into(), seconds.to_string()]);
                }
                args
            }
            Self::RemovePeer { ifname, public_key } => strings(&[
                "set",
                ifname.as_str(),
                "peer",
                public_key.as_str(),
                "remove",
            ]),
            Self::Pubkey => strings(&["pubkey"]),
        }
    }
}

impl KernelCmd {
    /// Renders the selected executable and literal arguments without I/O.
    #[must_use]
    pub fn render(&self) -> (Program, Vec<String>) {
        match self {
            Self::ReadUdp(ipv6) => (
                Program::Cat,
                strings(&[if *ipv6 {
                    "/proc/net/udp6"
                } else {
                    "/proc/net/udp"
                }]),
            ),
            Self::Ip(cmd) => (Program::Ip, cmd.argv()),
            Self::Wg(cmd) => (Program::Wg, cmd.argv()),
            Self::Nft(cmd) => (
                Program::Nft,
                strings(match cmd {
                    NftCmd::ListRulesetJson => &["-j", "list", "ruleset"],
                    NftCmd::LoadStdin => &["-f", "-"],
                    NftCmd::CheckStdin => &["-c", "-f", "-"],
                }),
            ),
            Self::Tc(cmd) => (
                Program::Tc,
                match cmd {
                    TcCmd::QdiscShowJson { dev } => {
                        strings(&["-j", "qdisc", "show", "dev", dev.as_str()])
                    }
                    TcCmd::FilterShowJson { dev, parent } => strings(&[
                        "-j",
                        "filter",
                        "show",
                        "dev",
                        dev.as_str(),
                        match parent {
                            TcParent::Ingress => "ingress",
                            TcParent::Egress => "egress",
                            TcParent::Root => "root",
                        },
                    ]),
                },
            ),
            Self::Sysctl(cmd) => (
                Program::Sysctl,
                match cmd {
                    SysctlCmd::Read(key) => strings(&["-n", &key.to_string()]),
                    SysctlCmd::Write(key, value) => strings(&["-w", &format!("{key}={value}")]),
                },
            ),
            Self::Conntrack(ConntrackCmd::Flush) => (Program::Conntrack, strings(&["-F"])),
        }
    }

    /// Whether dispatch requires a pinned namespace, never an `ExecTarget`.
    #[must_use]
    pub const fn mutates(&self) -> bool {
        matches!(
            self,
            Self::Ip(
                IpCmd::RouteReplace(..)
                    | IpCmd::RouteDelete(_)
                    | IpCmd::LinkSetDown(_)
                    | IpCmd::LinkDelete(_)
            ) | Self::Wg(
                WgCmd::SetPrivateKeyFromStdin { .. }
                    | WgCmd::SetPresharedKeyFromStdin { .. }
                    | WgCmd::SetListenPort { .. }
                    | WgCmd::SetPeer { .. }
                    | WgCmd::RemovePeer { .. }
            ) | Self::Nft(NftCmd::LoadStdin)
                | Self::Sysctl(SysctlCmd::Write(..))
                | Self::Conntrack(_)
        )
    }

    /// Whether this command requires an explicitly supplied stdin stream.
    #[must_use]
    pub const fn needs_stdin(&self) -> bool {
        matches!(
            self,
            Self::Wg(
                WgCmd::SetPrivateKeyFromStdin { .. }
                    | WgCmd::SetPresharedKeyFromStdin { .. }
                    | WgCmd::Pubkey
            ) | Self::Nft(NftCmd::LoadStdin | NftCmd::CheckStdin)
        )
    }
}

/// Executes a read-only command without stdin, preserving nonzero exit status.
///
/// # Errors
/// Returns execution errors; commands requiring stdin are rejected before spawn.
pub fn run_cmd(
    sys: &(impl System + ?Sized),
    target: ExecTarget<'_>,
    cmd: &KernelCmd,
    timeout: Duration,
) -> Result<ExecOutput, ExecError> {
    if cmd.mutates() {
        return Err(ExecError::spawn(
            "mutation requires namespace-only dispatch",
        ));
    }
    if cmd.needs_stdin() {
        return Err(ExecError::spawn("command requires explicit stdin"));
    }
    dispatch(sys, target, cmd, None, timeout)
}

/// Executes a read-only stdin command; input is never part of the command value.
/// The caller owns and must zeroize secret input bytes.
///
/// # Errors
/// Returns execution errors or rejects commands that do not accept stdin.
pub fn run_cmd_with_stdin(
    sys: &(impl System + ?Sized),
    target: ExecTarget<'_>,
    cmd: &KernelCmd,
    stdin: &[u8],
    timeout: Duration,
) -> Result<ExecOutput, ExecError> {
    if cmd.mutates() {
        return Err(ExecError::spawn(
            "mutation requires namespace-only dispatch",
        ));
    }
    if !cmd.needs_stdin() {
        return Err(ExecError::spawn("command does not accept stdin"));
    }
    dispatch(sys, target, cmd, Some(stdin), timeout)
}

/// Executes a namespace command, including mutations, using a held handle.
///
/// # Errors
/// Rejects commands requiring stdin and unsafe shared `WireGuard` sockets.
pub fn run_netns_cmd(
    sys: &(impl System + ?Sized),
    handle: &NetnsHandle,
    cmd: &KernelCmd,
    timeout: Duration,
) -> Result<ExecOutput, ExecError> {
    if cmd.needs_stdin() {
        return Err(ExecError::spawn("command requires explicit stdin"));
    }
    dispatch(sys, ExecTarget::Netns(handle), cmd, None, timeout)
}

/// Executes a namespace stdin transaction. Callers must zeroize secret input.
///
/// # Errors
/// Rejects commands without stdin and unsafe shared `WireGuard` sockets.
pub fn run_netns_cmd_with_stdin(
    sys: &(impl System + ?Sized),
    handle: &NetnsHandle,
    cmd: &KernelCmd,
    stdin: &[u8],
    timeout: Duration,
) -> Result<ExecOutput, ExecError> {
    if !cmd.needs_stdin() {
        return Err(ExecError::spawn("command does not accept stdin"));
    }
    dispatch(sys, ExecTarget::Netns(handle), cmd, Some(stdin), timeout)
}

fn dispatch(
    sys: &(impl System + ?Sized),
    target: ExecTarget<'_>,
    cmd: &KernelCmd,
    input: Option<&[u8]>,
    timeout: Duration,
) -> Result<ExecOutput, ExecError> {
    let (program, args) = cmd.render();
    if program == Program::Wg && matches!(target, ExecTarget::Netns(_)) {
        crate::system::check_wg_args(sys, &args)?;
    }
    match input {
        Some(bytes) => sys.run_with_stdin(target, program, &args, bytes, timeout),
        None => sys.run_in(target, program, &args, timeout),
    }
}

/// Writes a sysctl and verifies its numeric value in the same held namespace.
/// procps write statuses differ between releases; the readback decides success.
/// Each command has the supplied deadline.
///
/// # Errors
/// Returns execution errors or an unsuccessful, malformed or mismatched readback.
pub fn write_sysctl_verified(
    sys: &(impl System + ?Sized),
    handle: &NetnsHandle,
    key: &SysctlKey,
    value: i64,
    timeout: Duration,
) -> Result<(), ExecError> {
    run_netns_cmd(
        sys,
        handle,
        &KernelCmd::Sysctl(SysctlCmd::Write(key.clone(), value)),
        timeout,
    )?;
    let read = run_netns_cmd(
        sys,
        handle,
        &KernelCmd::Sysctl(SysctlCmd::Read(key.clone())),
        timeout,
    )?;
    if read.status != Some(0) || scupper_core::parse::parse_sysctl(&read.stdout).ok() != Some(value)
    {
        return Err(ExecError::spawn(
            "sysctl readback did not match requested value",
        ));
    }
    Ok(())
}

fn route_delete_argv(route: &scupper_core::planner::RouteKey) -> Vec<String> {
    use scupper_core::parse::{RouteDestination, RouteKind, RoutingTable};
    let r = &route.entry;
    let mut args = strings(&[family_flag(route.family), "route", "del"]);
    args.push(
        match r.kind {
            RouteKind::Unicast => "unicast",
            RouteKind::Unreachable => "unreachable",
            RouteKind::Blackhole => "blackhole",
            RouteKind::Local => "local",
            RouteKind::Broadcast => "broadcast",
            RouteKind::Multicast => "multicast",
            RouteKind::Anycast => "anycast",
            RouteKind::Prohibit => "prohibit",
            RouteKind::Throw => "throw",
            RouteKind::Nat => "nat",
            RouteKind::Xresolve => "xresolve",
        }
        .into(),
    );
    args.push(match &r.dst {
        RouteDestination::Default => "default".into(),
        RouteDestination::Prefix(p) => p.to_string(),
    });
    let table = match &r.table {
        RoutingTable::Main => "main".into(),
        RoutingTable::Local => "local".into(),
        RoutingTable::Default => "default".into(),
        RoutingTable::Number(n) => n.to_string(),
        RoutingTable::Named(s) => s.clone(),
    };
    args.extend(["table".into(), table]);
    if let Some(from) = r.from {
        args.extend(["from".into(), from.to_string()]);
    }
    if let Some(gateway) = r.gateway {
        args.extend(["via".into(), gateway.to_string()]);
    }
    if let Some(dev) = &r.dev {
        args.extend(["dev".into(), dev.clone()]);
    }
    if let Some(metric) = r.metric {
        args.extend(["metric".into(), metric.to_string()]);
    }
    if let Some(src) = r.prefsrc {
        args.extend(["src".into(), src.to_string()]);
    }
    if let Some(protocol) = &r.protocol {
        args.extend(["proto".into(), protocol.clone()]);
    }
    if let Some(scope) = &r.scope {
        args.extend(["scope".into(), scope.clone()]);
    }
    args
}

/// Delete an observed unique-priority rule only after rechecking its full identity.
/// The encoded identity is supplied by the collector, never by a control request.
///
/// # Errors
/// Refuses ambiguous, stale, malformed identities and execution failures.
pub(crate) fn delete_observed_rule(
    sys: &dyn System,
    held: &NetnsHandle,
    identity: &str,
) -> Result<(), ExecError> {
    let value: serde_json::Value =
        serde_json::from_str(identity).map_err(|_| ExecError::spawn("invalid rule identity"))?;
    let family = match value["v6"].as_bool() {
        Some(true) => Family::V6,
        Some(false) => Family::V4,
        None => return Err(ExecError::spawn("invalid rule family")),
    };
    let rule = &value["rule"];
    let priority = rule["priority"]
        .as_u64()
        .and_then(|p| u32::try_from(p).ok())
        .ok_or_else(|| ExecError::spawn("invalid rule priority"))?;
    let output = run_cmd(
        sys,
        ExecTarget::Netns(held),
        &KernelCmd::Ip(IpCmd::RuleShowJson { family }),
        crate::system::EXEC_TIMEOUT,
    )?;
    if output.status != Some(0) {
        return Err(ExecError::spawn("rule inventory failed"));
    }
    scupper_core::parse::parse_ip_rule(&output.stdout)
        .map_err(|_| ExecError::spawn("invalid rule inventory"))?;
    let live: serde_json::Value = serde_json::from_str(&output.stdout)
        .map_err(|_| ExecError::spawn("invalid rule inventory"))?;
    let entries = live
        .as_array()
        .ok_or_else(|| ExecError::spawn("invalid rule inventory"))?;
    let matches: Vec<_> = entries
        .iter()
        .filter(|r| r["priority"].as_u64() == Some(u64::from(priority)))
        .collect();
    if matches.is_empty() {
        return Ok(());
    }
    if matches.len() != 1 || matches[0] != rule {
        return Err(ExecError::spawn("rule changed before deletion"));
    }
    let output = sys.run_in(
        ExecTarget::Netns(held),
        Program::Ip,
        &strings(&[
            family_flag(family),
            "rule",
            "del",
            "priority",
            &priority.to_string(),
        ]),
        crate::system::EXEC_TIMEOUT,
    )?;
    if output.status != Some(0) {
        return Err(ExecError::spawn("rule deletion failed"));
    }
    Ok(())
}

/// Delete an observed route, accepting a concurrent disappearance only after inventory.
/// # Errors
/// Returns command, inventory or parsing errors while the route remains unproved absent.
pub fn delete_observed_route(
    system: &dyn crate::system::System,
    held: &crate::netns::NetnsHandle,
    route: &scupper_core::planner::RouteKey,
) -> Result<(), crate::verdict::ProbeError> {
    if let Err(error) = crate::canon::command_result(run_netns_cmd(
        system,
        held,
        &KernelCmd::Ip(IpCmd::RouteDelete(route.clone())),
        crate::system::EXEC_TIMEOUT,
    )) {
        let text = crate::canon::command_result(run_netns_cmd(
            system,
            held,
            &KernelCmd::Ip(IpCmd::RouteShowJson {
                family: route.family,
                table: RouteTable::All,
            }),
            crate::system::EXEC_TIMEOUT,
        ))?;
        if scupper_core::parse::parse_ip_route(&text)?
            .iter()
            .any(|entry| {
                let old = &route.entry;
                entry.table == old.table
                    && entry.dst == old.dst
                    && entry.kind == old.kind
                    && entry.from == old.from
                    && entry.dev == old.dev
                    && entry.gateway == old.gateway
                    && entry.metric == old.metric
            })
        {
            return Err(error);
        }
    }
    Ok(())
}
