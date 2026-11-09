//! Typed JSON observations. Rules use a strict key allow-list; unsupported routing
//! selectors are rejected rather than mistaken for an unconditional lookup.

use super::{ParseError, json_array};
use ipnet::IpNet;
use serde_json::Value;
use std::net::IpAddr;

fn invalid() -> ParseError {
    ParseError::Topology("invalid kernel field or unsupported shape")
}
fn string<'a>(value: &'a Value, key: &str) -> Result<&'a str, ParseError> {
    value.get(key).and_then(Value::as_str).ok_or_else(invalid)
}
fn optional_string(value: &Value, key: &str) -> Result<Option<String>, ParseError> {
    value
        .get(key)
        .map(|value| value.as_str().map(str::to_owned).ok_or_else(invalid))
        .transpose()
}
fn number(value: &Value, key: &str) -> Result<u32, ParseError> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .and_then(|n| u32::try_from(n).ok())
        .ok_or_else(invalid)
}
fn optional_number(value: &Value, key: &str) -> Result<Option<u32>, ParseError> {
    value.get(key).map(|_| number(value, key)).transpose()
}
fn boolean(value: &Value, key: &str) -> Result<bool, ParseError> {
    value
        .get(key)
        .map_or(Ok(false), |value| value.as_bool().ok_or_else(invalid))
}
fn text_array(value: &Value, key: &str) -> Result<Vec<String>, ParseError> {
    value.get(key).map_or_else(
        || Ok(Vec::new()),
        |value| {
            value
                .as_array()
                .ok_or_else(invalid)?
                .iter()
                .map(|value| value.as_str().map(str::to_owned).ok_or_else(invalid))
                .collect()
        },
    )
}
fn optional_ip(value: &Value, key: &str) -> Result<Option<IpAddr>, ParseError> {
    optional_string(value, key)?
        .map(|text| text.parse().map_err(|_| invalid()))
        .transpose()
}
fn prefix(text: &str) -> Result<IpNet, ParseError> {
    text.parse()
        .or_else(|_| text.parse::<IpAddr>().map(IpNet::from))
        .map_err(|_| invalid())
}
// iprule.c emits separate lengths only for non-host prefixes. Slash-bearing
// strings are not its rule format and must not hide a contradictory length.
fn rule_prefix(value: &Value, key: &str, length_key: &str) -> Result<Option<IpNet>, ParseError> {
    let length = optional_number(value, length_key)?;
    match optional_string(value, key)?.as_deref() {
        None | Some("all") if length.is_none() => Ok(None),
        Some(text) => {
            let address: IpAddr = text.parse().map_err(|_| invalid())?;
            let max = if address.is_ipv4() { 32 } else { 128 };
            let length = length.unwrap_or(max);
            let net = IpNet::new(address, u8::try_from(length).map_err(|_| invalid())?)
                .map_err(|_| invalid())?;
            Ok(Some(net))
        }
        _ => Err(invalid()),
    }
}
fn route_source(value: &Value) -> Result<Option<IpNet>, ParseError> {
    if value.get("src").is_some() || value.get("srclen").is_some() {
        if value.get("from").is_some() {
            return Err(invalid());
        }
        rule_prefix(value, "src", "srclen")
    } else {
        optional_string(value, "from")?
            .map(|text| prefix(&text))
            .transpose()
    }
}
fn scalar(value: &Value, key: &str) -> Result<Option<String>, ParseError> {
    value
        .get(key)
        .map(|value| match value {
            Value::String(text) => Ok(text.clone()),
            Value::Number(n) if n.is_u64() => Ok(n.to_string()),
            _ => Err(invalid()),
        })
        .transpose()
}
fn reject(value: &Value, keys: &[&str]) -> Result<(), ParseError> {
    if keys.iter().any(|key| value.get(key).is_some()) {
        Err(invalid())
    } else {
        Ok(())
    }
}

/// One link from `ip -j link show`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpLink {
    /// Kernel interface index.
    pub ifindex: u32,
    /// Kernel name, including foreign names outside configuration syntax.
    pub ifname: String,
    /// Administrative and operational flags.
    pub flags: Vec<String>,
    /// Link MTU.
    pub mtu: u32,
    /// Link kind when detailed information is available.
    pub kind: Option<String>,
    /// Presence of XDP information, including a null value.
    pub xdp: bool,
}

/// Parses a link inventory, retaining kernel names and flags.
///
/// # Errors
/// Rejects malformed JSON and invalid required or recognized fields.
pub fn parse_ip_link(out: &str) -> Result<Vec<IpLink>, ParseError> {
    json_array(out)?
        .iter()
        .map(|entry| {
            let kind = entry
                .get("linkinfo")
                .map(|info| {
                    if !info.is_object() {
                        return Err(invalid());
                    }
                    optional_string(info, "info_kind")
                })
                .transpose()?
                .flatten();
            Ok(IpLink {
                ifindex: number(entry, "ifindex")?,
                ifname: string(entry, "ifname")?.to_owned(),
                flags: text_array(entry, "flags")?,
                mtu: number(entry, "mtu")?,
                kind,
                xdp: entry.get("xdp").is_some(),
            })
        })
        .collect()
}

/// A local interface address and its prefix length.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressEntry {
    /// Local IPv4 or IPv6 address.
    pub local: IpAddr,
    /// Prefix length validated against the address family.
    pub prefixlen: u8,
    /// Address scope such as host, link or global.
    pub scope: String,
}

/// Address inventory for one interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceAddrs {
    /// Kernel interface index.
    pub ifindex: u32,
    /// Kernel interface name.
    pub ifname: String,
    /// Local addresses, preserving kernel order.
    pub addresses: Vec<AddressEntry>,
}

/// Parses `ip -j addr show`, including empty interfaces and both families.
///
/// # Errors
/// Rejects malformed address shapes, unknown families and invalid prefix lengths.
pub fn parse_ip_addr(out: &str) -> Result<Vec<InterfaceAddrs>, ParseError> {
    json_array(out)?
        .iter()
        .map(|entry| {
            let addresses = entry.get("addr_info").map_or_else(
                || Ok(Vec::new()),
                |info| {
                    info.as_array()
                        .ok_or_else(invalid)?
                        .iter()
                        .map(|addr| {
                            let local: IpAddr =
                                string(addr, "local")?.parse().map_err(|_| invalid())?;
                            let max = match (string(addr, "family")?, local) {
                                ("inet", IpAddr::V4(_)) => 32,
                                ("inet6", IpAddr::V6(_)) => 128,
                                _ => return Err(invalid()),
                            };
                            let prefixlen = number(addr, "prefixlen")?;
                            if prefixlen > max {
                                return Err(invalid());
                            }
                            Ok(AddressEntry {
                                local,
                                prefixlen: u8::try_from(prefixlen).map_err(|_| invalid())?,
                                scope: string(addr, "scope")?.to_owned(),
                            })
                        })
                        .collect::<Result<Vec<_>, ParseError>>()
                },
            )?;
            Ok(InterfaceAddrs {
                ifindex: number(entry, "ifindex")?,
                ifname: string(entry, "ifname")?.to_owned(),
                addresses,
            })
        })
        .collect()
}

/// A normalized routing table identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoutingTable {
    /// Table 254.
    Main,
    /// Table 255.
    Local,
    /// Table 253.
    Default,
    /// Another numeric table.
    Number(u32),
    /// A name supplied by the system's `rt_tables` configuration.
    Named(String),
}
fn table(value: &Value) -> Result<RoutingTable, ParseError> {
    let number = if let Some(text) = value.as_str() {
        match text {
            "main" => return Ok(RoutingTable::Main),
            "local" => return Ok(RoutingTable::Local),
            "default" => return Ok(RoutingTable::Default),
            "" => return Err(invalid()),
            other => match other.parse::<u32>() {
                Ok(n) => n,
                Err(_) if other.bytes().all(|b| b.is_ascii_digit()) => return Err(invalid()),
                Err(_) => return Ok(RoutingTable::Named(other.to_owned())),
            },
        }
    } else {
        value
            .as_u64()
            .and_then(|n| u32::try_from(n).ok())
            .ok_or_else(invalid)?
    };
    Ok(match number {
        254 => RoutingTable::Main,
        255 => RoutingTable::Local,
        253 => RoutingTable::Default,
        n => RoutingTable::Number(n),
    })
}

/// A route destination, with a family-independent default marker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteDestination {
    /// Default for the family selected by the observation command.
    Default,
    /// A network or host prefix.
    Prefix(IpNet),
}

/// Recognized Linux route types; unknown types cannot be assumed unicast.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteKind {
    /// Ordinary forwarding route.
    Unicast,
    /// Immediate unreachable error.
    Unreachable,
    /// Silent discard.
    Blackhole,
    /// Local delivery.
    Local,
    /// Broadcast delivery.
    Broadcast,
    /// Multicast delivery.
    Multicast,
    /// Anycast delivery.
    Anycast,
    /// Administrative rejection.
    Prohibit,
    /// Continue policy lookup.
    Throw,
    /// Legacy NAT route.
    Nat,
    /// External route resolution.
    Xresolve,
}
fn route_kind(text: &str) -> Result<RouteKind, ParseError> {
    Ok(match text {
        "unicast" => RouteKind::Unicast,
        "unreachable" => RouteKind::Unreachable,
        "blackhole" => RouteKind::Blackhole,
        "local" => RouteKind::Local,
        "broadcast" => RouteKind::Broadcast,
        "multicast" => RouteKind::Multicast,
        "anycast" => RouteKind::Anycast,
        "prohibit" => RouteKind::Prohibit,
        "throw" => RouteKind::Throw,
        "nat" => RouteKind::Nat,
        "xresolve" => RouteKind::Xresolve,
        _ => return Err(invalid()),
    })
}

/// A simple route; multipath and encapsulated routes are rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteEntry {
    /// Destination prefix or default.
    pub dst: RouteDestination,
    /// Output interface, absent for some rejecting routes.
    pub dev: Option<String>,
    /// Main if the kernel omits the table.
    pub table: RoutingTable,
    /// Kernel route action.
    pub kind: RouteKind,
    /// Optional preference metric.
    pub metric: Option<u32>,
    /// Optional next-hop address.
    pub gateway: Option<IpAddr>,
    /// Preferred source address.
    pub prefsrc: Option<IpAddr>,
    /// Route origin, including numeric protocol identifiers.
    pub protocol: Option<String>,
    /// Route scope.
    pub scope: Option<String>,
    /// Kernel flags, including link-down state.
    pub flags: Vec<String>,
    /// Optional source prefix for source-specific IPv6 routes.
    pub from: Option<IpNet>,
}

/// Parses `ip -j [-4|-6] route show table main|all`.
///
/// # Errors
/// Rejects malformed fields, unknown route actions and unsupported next-hop shapes.
pub fn parse_ip_route(out: &str) -> Result<Vec<RouteEntry>, ParseError> {
    json_array(out)?
        .iter()
        .map(|entry| {
            reject(
                entry,
                &["nexthops", "nhid", "encap", "via", "newdst", "tos"],
            )?;
            let dst = match string(entry, "dst")? {
                "default" => RouteDestination::Default,
                text => RouteDestination::Prefix(prefix(text)?),
            };
            Ok(RouteEntry {
                dst,
                dev: optional_string(entry, "dev")?,
                table: entry.get("table").map_or(Ok(RoutingTable::Main), table)?,
                kind: route_kind(
                    optional_string(entry, "type")?
                        .as_deref()
                        .unwrap_or("unicast"),
                )?,
                metric: optional_number(entry, "metric")?,
                gateway: optional_ip(entry, "gateway")?,
                prefsrc: optional_ip(entry, "prefsrc")?,
                protocol: scalar(entry, "protocol")?,
                scope: scalar(entry, "scope")?,
                flags: text_array(entry, "flags")?,
                from: route_source(entry)?,
            })
        })
        .collect()
}

/// Policy-rule action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleAction {
    /// Jump to another rule priority.
    Goto,
    /// Continue to the next rule.
    Nop,
    /// Look up a routing table.
    Lookup,
    /// Discard silently.
    Blackhole,
    /// Return unreachable.
    Unreachable,
    /// Return administratively prohibited.
    Prohibit,
}

/// One policy rule with supported selectors retained explicitly.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)] // Independent flags in the kernel rule ABI.
pub struct IpRule {
    /// Rule ordering priority.
    pub priority: u32,
    /// Lookup table, absent for rejecting actions.
    pub table: Option<RoutingTable>,
    /// Source prefix; None represents all sources.
    pub src: Option<IpNet>,
    /// Destination prefix; None represents all destinations.
    pub dst: Option<IpNet>,
    /// Input interface selector.
    pub iif: Option<String>,
    /// Output interface selector.
    pub oif: Option<String>,
    /// Firewall mark selector.
    pub fwmark: Option<u32>,
    /// Firewall mark mask.
    pub fwmask: Option<u32>,
    /// Whether selectors are inverted.
    pub invert: bool,
    /// Whether the input interface selector is detached.
    pub iif_detached: bool,
    /// Whether the output interface selector is detached.
    pub oif_detached: bool,
    /// Lookups use the layer-3 master device table.
    pub l3mdev: bool,
    /// Reject routes at or below this prefix length during lookup.
    pub suppress_prefixlen: Option<u32>,
    /// Inclusive user ID selector.
    pub uid: Option<(u32, u32)>,
    /// Inclusive source port selector (single ports are equal endpoints).
    pub sport: Option<(u16, u16)>,
    /// Inclusive destination port selector.
    pub dport: Option<(u16, u16)>,
    /// IP protocol name or number as printed by iproute2.
    pub ipproto: Option<String>,
    /// TOS selector, including system-defined names.
    pub tos: Option<String>,
    /// DS field selector if emitted under this key.
    pub dsfield: Option<String>,
    /// Jump priority, or the explicit unresolved destination `none`.
    pub goto: Option<String>,
    /// Whether a jump destination is unresolved.
    pub unresolved: bool,
    /// Flow identifier when emitted under this key.
    pub flowid: Option<String>,
    /// Realms when emitted under this key.
    pub realms: Option<String>,
    /// Source realm printed by iprule.c.
    pub flow_from: Option<String>,
    /// Destination realm printed by iprule.c.
    pub flow_to: Option<String>,
    /// Rule origin protocol, distinct from the packet IP protocol selector.
    pub protocol: Option<String>,
    /// Rule action.
    pub action: RuleAction,
}
fn mark(value: &Value, key: &str) -> Result<Option<u32>, ParseError> {
    value
        .get(key)
        .map(|v| {
            if let Some(n) = v.as_u64() {
                return u32::try_from(n).map_err(|_| invalid());
            }
            let text = v.as_str().ok_or_else(invalid)?;
            if let Some(hex) = text.strip_prefix("0x") {
                u32::from_str_radix(hex, 16).map_err(|_| invalid())
            } else {
                text.parse().map_err(|_| invalid())
            }
        })
        .transpose()
}

fn marker(value: &Value, key: &str) -> Result<bool, ParseError> {
    match value.get(key) {
        None => Ok(false),
        Some(Value::Null) => Ok(true),
        _ => Err(invalid()),
    }
}
fn range(value: &Value, start: &str, end: &str) -> Result<Option<(u32, u32)>, ParseError> {
    match (optional_number(value, start)?, optional_number(value, end)?) {
        (None, None) => Ok(None),
        (Some(a), Some(b)) if a <= b => Ok(Some((a, b))),
        _ => Err(invalid()),
    }
}
fn ports(value: &Value, key: &str) -> Result<Option<(u16, u16)>, ParseError> {
    let endpoints = range(value, &format!("{key}_start"), &format!("{key}_end"))?;
    let single = optional_number(value, key)?;
    let endpoints = match (endpoints, single) {
        (Some(_), Some(_)) => return Err(invalid()),
        (Some(pair), None) => Some(pair),
        (None, Some(n)) => Some((n, n)),
        (None, None) => None,
    };
    endpoints
        .map(|(a, b)| {
            Ok((
                u16::try_from(a).map_err(|_| invalid())?,
                u16::try_from(b).map_err(|_| invalid())?,
            ))
        })
        .transpose()
}

const RULE_KEYS: &[&str] = &[
    "priority",
    "src",
    "srclen",
    "dst",
    "dstlen",
    "iif",
    "oif",
    "iif_detached",
    "oif_detached",
    "fwmark",
    "fwmask",
    "not",
    "table",
    "action",
    "protocol",
    "l3mdev",
    "goto",
    "nop",
    "unresolved",
    "suppress_prefixlen",
    "uid_start",
    "uid_end",
    "sport",
    "sport_start",
    "sport_end",
    "dport",
    "dport_start",
    "dport_end",
    "ipproto",
    "tos",
    "dsfield",
    "flowid",
    "realms",
    "flow_from",
    "flow_to",
];

/// Parses iproute2's JSON policy rules, including its null presence markers.
/// Every allowed selector is retained; new keys fail closed until modelled.
///
/// # Errors
/// Rejects malformed fields, unknown keys and unsupported or inconsistent actions.
pub fn parse_ip_rule(out: &str) -> Result<Vec<IpRule>, ParseError> {
    json_array(out)?
        .iter()
        .map(|entry| {
            if entry
                .as_object()
                .ok_or_else(invalid)?
                .keys()
                .any(|key| !RULE_KEYS.contains(&key.as_str()))
            {
                return Err(invalid());
            }
            let goto = scalar(entry, "goto")?;
            if let Some(text) = &goto
                && text != "none"
                && text.parse::<u32>().is_err()
            {
                return Err(invalid());
            }
            let nop = marker(entry, "nop")?;
            if goto.is_some() && nop {
                return Err(invalid());
            }
            let action = match optional_string(entry, "action")?.as_deref() {
                None | Some("goto") if goto.is_some() => RuleAction::Goto,
                None if nop => RuleAction::Nop,
                None | Some("lookup" | "to_tbl" | "unicast") => RuleAction::Lookup,
                Some("blackhole") => RuleAction::Blackhole,
                Some("unreachable") => RuleAction::Unreachable,
                Some("prohibit") => RuleAction::Prohibit,
                Some("nop") => RuleAction::Nop,
                _ => return Err(invalid()),
            };
            if (goto.is_some() && action != RuleAction::Goto) || (nop && action != RuleAction::Nop)
            {
                return Err(invalid());
            }
            let table = entry.get("table").map(table).transpose()?;
            let l3mdev = marker(entry, "l3mdev")?;
            if action == RuleAction::Lookup && table.is_none() && !l3mdev {
                return Err(invalid());
            }
            let iif = optional_string(entry, "iif")?;
            let oif = optional_string(entry, "oif")?;
            let iif_detached = marker(entry, "iif_detached")?;
            let oif_detached = marker(entry, "oif_detached")?;
            let unresolved = marker(entry, "unresolved")?;
            if (iif_detached && iif.is_none())
                || (oif_detached && oif.is_none())
                || (unresolved && action != RuleAction::Goto)
            {
                return Err(invalid());
            }
            let suppress_prefixlen = optional_number(entry, "suppress_prefixlen")?;
            if suppress_prefixlen.is_some_and(|n| n > 128) {
                return Err(invalid());
            }
            Ok(IpRule {
                priority: number(entry, "priority")?,
                table,
                src: rule_prefix(entry, "src", "srclen")?,
                dst: rule_prefix(entry, "dst", "dstlen")?,
                iif,
                oif,
                iif_detached,
                oif_detached,
                fwmark: mark(entry, "fwmark")?,
                fwmask: mark(entry, "fwmask")?,
                invert: entry.get("not").is_some(),
                action,
                l3mdev,
                suppress_prefixlen,
                uid: range(entry, "uid_start", "uid_end")?,
                sport: ports(entry, "sport")?,
                dport: ports(entry, "dport")?,
                ipproto: scalar(entry, "ipproto")?,
                tos: scalar(entry, "tos")?,
                dsfield: scalar(entry, "dsfield")?,
                goto,
                unresolved,
                flowid: scalar(entry, "flowid")?,
                realms: scalar(entry, "realms")?,
                flow_from: scalar(entry, "flow_from")?,
                flow_to: scalar(entry, "flow_to")?,
                protocol: scalar(entry, "protocol")?,
            })
        })
        .collect()
}

/// One queueing discipline or filter, retaining options for drift inspection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcEntry {
    /// Queueing discipline or classifier kind.
    pub kind: String,
    /// Device, if printed by tc.
    pub dev: Option<String>,
    /// Handle, if present.
    pub handle: Option<String>,
    /// Parent attachment, if present.
    pub parent: Option<String>,
    /// Root attachment flag.
    pub root: bool,
    /// Classifier protocol, if present.
    pub protocol: Option<String>,
    /// Classifier priority.
    pub pref: Option<u32>,
    /// Kind-specific options retained without assuming a classifier schema.
    pub options: Option<Value>,
}
fn tc(out: &str) -> Result<Vec<TcEntry>, ParseError> {
    json_array(out)?
        .iter()
        .map(|entry| {
            let options = entry
                .get("options")
                .map(|v| {
                    if v.is_object() {
                        Ok(v.clone())
                    } else {
                        Err(invalid())
                    }
                })
                .transpose()?;
            Ok(TcEntry {
                kind: string(entry, "kind")?.to_owned(),
                dev: optional_string(entry, "dev")?,
                handle: scalar(entry, "handle")?,
                parent: optional_string(entry, "parent")?,
                root: boolean(entry, "root")?,
                protocol: optional_string(entry, "protocol")?,
                pref: optional_number(entry, "pref")?,
                options,
            })
        })
        .collect()
}

/// Parses a JSON queueing-discipline inventory.
///
/// # Errors
/// Rejects malformed or missing recognized fields; extra fields are ignored.
pub fn parse_tc_qdisc(out: &str) -> Result<Vec<TcEntry>, ParseError> {
    tc(out)
}

/// Parses JSON filters, preserving classifier options and actions.
///
/// # Errors
/// Rejects malformed or missing recognized fields; extra fields are ignored.
pub fn parse_tc_filter(out: &str) -> Result<Vec<TcEntry>, ParseError> {
    tc(out)
}

/// Parses a single numeric `sysctl -n` value, allowing surrounding whitespace.
///
/// # Errors
/// Rejects empty, multiple, nondecimal or overflowing values.
pub fn parse_sysctl(out: &str) -> Result<i64, ParseError> {
    let text = out.trim();
    let digits = text.strip_prefix('-').unwrap_or(text);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid());
    }
    text.parse().map_err(|_| invalid())
}

/// Parses an nft JSON ruleset using the existing runtime canonicalization.
///
/// # Errors
/// Rejects malformed JSON and invalid nftables envelopes.
pub fn parse_nft_ruleset(out: &str) -> Result<Value, ParseError> {
    crate::canon::canonicalize(out)
}
