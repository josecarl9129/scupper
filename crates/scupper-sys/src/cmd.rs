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
    /// Configure the UDP listen port.
    SetListenPort {
        /// Validated interface.
        ifname: IfName,
        /// UDP port (zero requests an automatic port).
        port: u16,
    },
    /// Configure a public peer, without preshared-key support.
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
                    RouteTable::All => "all",
                },
            ]),
            Self::RuleShowJson { family } => strings(&["-j", family_flag(*family), "rule", "show"]),
            Self::RouteGet { dst, from, iif } => {
                let mut args = strings(&["route", "get", &dst.to_string()]);
                if let Some(from) = from {
                    args.extend(["from".into(), from.to_string()]);
                }
                if let Some(iif) = iif {
                    args.extend(["iif".into(), iif.to_string()]);
                }
                args
            }
            Self::RouteReplace(family, target) => route_argv(*family, target),
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
            Self::Ip(IpCmd::RouteReplace(..) | IpCmd::LinkSetDown(_) | IpCmd::LinkDelete(_))
                | Self::Wg(
                    WgCmd::SetPrivateKeyFromStdin { .. }
                        | WgCmd::SetListenPort { .. }
                        | WgCmd::SetPeer { .. }
                        | WgCmd::RemovePeer { .. }
                )
                | Self::Nft(NftCmd::LoadStdin)
                | Self::Sysctl(SysctlCmd::Write(..))
                | Self::Conntrack(_)
        )
    }

    /// Whether this command requires an explicitly supplied stdin stream.
    #[must_use]
    pub const fn needs_stdin(&self) -> bool {
        matches!(
            self,
            Self::Wg(WgCmd::SetPrivateKeyFromStdin { .. } | WgCmd::Pubkey)
                | Self::Nft(NftCmd::LoadStdin | NftCmd::CheckStdin)
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
