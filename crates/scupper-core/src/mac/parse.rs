//! Bounded parsers for captured tool text. Fixtures are synthetic until qualification.

use super::{
    Error, Interface,
    policy::{Direction, Pass, State},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
};

const MAX_CAPTURE: usize = 1024 * 1024;
fn bounded(text: &str) -> Result<(), Error> {
    if text.len() > MAX_CAPTURE
        || text
            .bytes()
            .any(|b| b == 0 || (b.is_ascii_control() && !matches!(b, b'\n' | b'\r' | b'\t')))
    {
        return Err(Error("capture size/control characters"));
    }
    Ok(())
}
/// pf enabled status. References are a separate command, never an ownership claim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PfInfo {
    /// Explicit enabled status.
    pub enabled: bool,
}
/// Parse `pfctl -s info`; require exactly one recognized status line.
///
/// # Errors
/// Rejects invalid, incomplete, out-of-order or unsupported supplied evidence.
pub fn pf_info(text: &str) -> Result<PfInfo, Error> {
    bounded(text)?;
    let mut enabled = None;
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
        if let Some(status) = line.strip_prefix("Status: ") {
            let mut status_fields = status.split_whitespace();
            let value = match status_fields.next() {
                Some("Enabled") => true,
                Some("Disabled") => false,
                _ => return Err(Error("pf status")),
            };
            let suffix: Vec<_> = status_fields.collect();
            if !suffix.is_empty() && !valid_status_suffix(&suffix) {
                return Err(Error("pf status suffix"));
            }
            if enabled.replace(value).is_some() {
                return Err(Error("duplicate pf status"));
            }
        } else if !info_counter(line) {
            return Err(Error("unknown pf info field"));
        }
    }
    Ok(PfInfo {
        enabled: enabled.ok_or(Error("missing pf status"))?,
    })
}
fn valid_status_suffix(fields: &[&str]) -> bool {
    let ["for", days, "days", clock, "Debug:", level] = fields else {
        return false;
    };
    let time: Vec<_> = clock.split(':').collect();
    decimal(days).is_ok()
        && time.len() == 3
        && time.iter().all(|n| n.len() == 2 && decimal(n).is_ok())
        && matches!(*level, "None" | "Urgent" | "Misc" | "Loud")
}
fn info_counter(line: &str) -> bool {
    // Qualified non-policy counters; their values cannot supply enabled evidence.
    let headers = [
        "Debug:",
        "Hostid:",
        "Checksum:",
        "State Table",
        "Source Tracking Table",
        "Counters",
    ];
    if headers.iter().any(|h| line.starts_with(h)) {
        return true;
    }
    let keys = [
        "current entries",
        "searches",
        "inserts",
        "removals",
        "match",
        "bad-offset",
        "fragment",
        "short",
        "normalize",
        "memory",
        "bad-timestamp",
        "congestion",
        "ip-option",
        "proto-cksum",
        "state-mismatch",
        "state-insert",
        "state-limit",
        "src-limit",
        "synproxy",
        "map-failed",
    ];
    keys.iter().any(|key| {
        line.strip_prefix(key).is_some_and(|tail| {
            let parts: Vec<_> = tail.split_whitespace().collect();
            !parts.is_empty()
                && parts
                    .iter()
                    .all(|v| v.trim_end_matches("/s").parse::<f64>().is_ok())
        })
    })
}
fn decimal(s: &str) -> Result<u64, Error> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error("decimal integer"));
    }
    s.parse().map_err(|_| Error("decimal overflow"))
}
/// Parsed pf statement; unsupported constructs are retained for a reasoned refusal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Rule {
    /// Filter pass in the supported grammar.
    Pass(Pass),
    /// Default block, with explicit quick behavior.
    Block {
        /// Whether it stops evaluation.
        quick: bool,
    },
    /// Filter anchor call, in evaluation order.
    Anchor {
        /// Full or relative anchor name.
        name: String,
        /// Quick anchor call.
        quick: bool,
    },
    /// Recognized but unqualified pf construct.
    Unsupported(String),
}
/// Ordered rules and normalized pfctl read-back text, not renderer source text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rules {
    /// Ordered statements.
    statements: Vec<Rule>,
    normalized: String,
    /// Whether the read-back uses named `ICMPv6` types.
    named_icmp: bool,
}
impl Rules {
    /// Ordered parsed statements; immutable so they cannot diverge from read-back text.
    #[must_use]
    pub fn rules(&self) -> &[Rule] {
        &self.statements
    }
    /// Whether the captured text used symbolic ICMP types.
    #[must_use]
    pub fn uses_named_icmp(&self) -> bool {
        self.named_icmp
    }
    /// Whitespace-normalized text, retaining spelling, order, flags and expansion.
    #[must_use]
    pub fn normalized(&self) -> &str {
        &self.normalized
    }
}
/// Parse the small pf grammar, rejecting malformed known constructs. Empty output
/// is a valid empty ruleset, which is never an exact protected anchor.
///
/// # Errors
/// Rejects invalid, incomplete, out-of-order or unsupported supplied evidence.
pub fn pf_rules(text: &str) -> Result<Rules, Error> {
    bounded(text)?;
    let mut rules = Vec::new();
    let mut normalized = String::new();
    let mut named_icmp = false;
    for line in text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        let spaced = line
            .replace('{', " { ")
            .replace('}', " } ")
            .replace(',', " , ");
        let tokens: Vec<_> = spaced.split_whitespace().collect();
        if tokens.is_empty() {
            return Err(Error("empty rule"));
        }
        let rule = match tokens[0] {
            "pass" => {
                named_icmp |= tokens
                    .iter()
                    .any(|t| matches!(*t, "routersol" | "routeradv" | "neighbrsol" | "neighbradv"));
                if tokens.iter().any(|t| {
                    matches!(
                        *t,
                        "route-to"
                            | "reply-to"
                            | "dup-to"
                            | "tag"
                            | "tagged"
                            | "user"
                            | "group"
                            | "probability"
                            | "rtable"
                    )
                }) || line.contains('<')
                {
                    Rule::Unsupported("qualified filter grammar".into())
                } else {
                    Rule::Pass(parse_pass(&tokens)?)
                }
            }
            "block" => {
                if matches!(
                    tokens.as_slice(),
                    ["block", "drop", "quick", "all"]
                        | ["block", "drop" | "quick", "all"]
                        | ["block", "all"]
                ) {
                    Rule::Block {
                        quick: tokens.contains(&"quick"),
                    }
                } else {
                    Rule::Unsupported("qualified block grammar".into())
                }
            }
            "anchor" => {
                if tokens.len() < 2 {
                    return Err(Error("anchor name"));
                }
                let quoted = tokens[1];
                let name = quoted
                    .strip_prefix('"')
                    .and_then(|s| s.strip_suffix('"'))
                    .ok_or(Error("quoted anchor name"))?;
                if name.is_empty()
                    || !name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._-/*".contains(&b))
                {
                    return Err(Error("anchor name"));
                }
                if tokens.len() > 3 || (tokens.len() == 3 && !matches!(tokens[2], "quick" | "all"))
                {
                    Rule::Unsupported("conditional anchor".into())
                } else {
                    Rule::Anchor {
                        name: name.into(),
                        quick: tokens.get(2) == Some(&"quick"),
                    }
                }
            }
            "table" | "nat" | "rdr" | "binat" | "nat-anchor" | "rdr-anchor" | "scrub"
            | "scrub-anchor" | "dummynet-anchor" | "match" | "set" | "load" => {
                Rule::Unsupported(tokens[0].into())
            }
            _ => return Err(Error("unknown pf statement")),
        };
        normalized.push_str(&tokens.join(" "));
        normalized.push('\n');
        rules.push(rule);
    }
    Ok(Rules {
        statements: rules,
        normalized,
        named_icmp,
    })
}
struct Cursor<'a> {
    tokens: &'a [&'a str],
    index: usize,
}
impl<'a> Cursor<'a> {
    fn peek(&self) -> Option<&'a str> {
        self.tokens.get(self.index).copied()
    }
    fn take(&mut self) -> Result<&'a str, Error> {
        let token = self.peek().ok_or(Error("truncated pf rule"))?;
        self.index += 1;
        Ok(token)
    }
    fn eat(&mut self, token: &str) -> bool {
        if self.peek() == Some(token) {
            self.index += 1;
            true
        } else {
            false
        }
    }
    fn require(&mut self, token: &str) -> Result<(), Error> {
        if self.eat(token) {
            Ok(())
        } else {
            Err(Error("unexpected pf token"))
        }
    }
    fn addresses(&mut self) -> Result<Vec<String>, Error> {
        let mut values = Vec::new();
        if self.eat("{") {
            loop {
                values.push(address(self.take()?)?);
                if self.eat("}") {
                    break;
                }
                self.require(",")?;
                if values.len() > 64 {
                    return Err(Error("pf address list size"));
                }
            }
        } else {
            values.push(address(self.take()?)?);
        }
        Ok(values)
    }
    fn port(&mut self) -> Result<Option<u16>, Error> {
        if !self.eat("port") {
            return Ok(None);
        }
        self.eat("=");
        let port = decimal(self.take()?)?;
        Ok(Some(u16::try_from(port).map_err(|_| Error("pf port"))?))
    }
}
fn address(token: &str) -> Result<String, Error> {
    if token == "any" {
        return Ok(token.into());
    }
    if token.contains('/') {
        token
            .parse::<ipnet::IpNet>()
            .map_err(|_| Error("pf network"))?;
    } else {
        token.parse::<IpAddr>().map_err(|_| Error("pf address"))?;
    }
    Ok(token.into())
}
fn parse_pass(tokens: &[&str]) -> Result<Pass, Error> {
    let mut c = Cursor { tokens, index: 1 };
    let mut row = Pass::all(None);
    row.direction = if c.eat("out") {
        Direction::Out
    } else if c.eat("in") {
        Direction::In
    } else {
        Direction::Both
    };
    row.quick = c.eat("quick");
    if c.eat("on") {
        let name: Interface = c.take()?.parse()?;
        row.interface = Some(name.to_string());
    }
    if matches!(c.peek(), Some("inet" | "inet6")) {
        row.family = Some(c.take()?.into());
    }
    if c.eat("proto") {
        let protocol = c.take()?;
        if !matches!(protocol, "udp" | "tcp" | "ipv6-icmp") {
            return Err(Error("pf protocol"));
        }
        row.protocol = Some(protocol.into());
    }
    if !c.eat("all") {
        c.require("from")?;
        row.sources = c.addresses()?;
        row.source_port = c.port()?;
        c.require("to")?;
        row.destinations = c.addresses()?;
        row.destination_port = c.port()?;
    }
    if c.eat("flags") {
        c.require("S/SA")?;
        row.tcp_flags = true;
    }
    if c.eat("icmp6-type") {
        row.icmp6_type = Some(match c.take()? {
            "133" | "routersol" => 133,
            "134" | "routeradv" => 134,
            "135" | "neighbrsol" => 135,
            "136" | "neighbradv" => 136,
            _ => return Err(Error("ICMPv6 type")),
        });
    }
    if c.eat("no") {
        c.require("state")?;
        row.state = State::None;
    } else if c.eat("keep") {
        c.require("state")?;
        c.require("(if-bound)")?;
        row.state = State::IfBound;
    }
    if c.peek().is_some() {
        return Err(Error("unconsumed pf tokens"));
    }
    if row.tcp_flags
        && row
            .protocol
            .as_deref()
            .is_some_and(|protocol| protocol != "tcp")
    {
        return Err(Error("TCP flags on non-TCP rule"));
    }
    Ok(row)
}
/// Parse every enumerated interface, including bridge/vmnet/awdl and utun names.
///
/// # Errors
/// Rejects invalid, incomplete, out-of-order or unsupported supplied evidence.
pub fn ifconfig_list(text: &str) -> Result<BTreeSet<Interface>, Error> {
    bounded(text)?;
    let mut result = BTreeSet::new();
    for name in text.split_whitespace() {
        if !result.insert(name.parse()?) {
            return Err(Error("duplicate interface"));
        }
    }
    if result.is_empty() {
        return Err(Error("empty interface enumeration"));
    }
    Ok(result)
}
/// pf skip flags by interface. Absence is not interpreted as `false`.
pub type SkipFlags = BTreeMap<Interface, bool>;
/// Parse the name and optional `(skip)` printed by `pfctl -s Interfaces -v`.
///
/// # Errors
/// Rejects unknown suffixes, duplicates and empty output.
pub fn pf_interfaces(text: &str) -> Result<SkipFlags, Error> {
    bounded(text)?;
    let mut result = BTreeMap::new();
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
        let (name, skip) = line
            .strip_suffix(" (skip)")
            .map_or((line, false), |n| (n, true));
        if result.insert(name.parse()?, skip).is_some() {
            return Err(Error("duplicate pf interface"));
        }
    }
    if result.is_empty() {
        return Err(Error("empty pf interfaces"));
    }
    Ok(result)
}
/// Recursive `-s Anchors` inventory. Names are full storage paths, not execution paths.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnchorInventory(BTreeSet<String>);
impl AnchorInventory {
    /// Enumerated full paths in strcmp order.
    #[must_use]
    pub fn names(&self) -> &BTreeSet<String> {
        &self.0
    }
}
/// Parse recursive `pfctl -vv -s Anchors` output (full paths with two-space indentation).
/// This command/output shape, recursion and `_`-hidden roots require OS qualification.
///
/// # Errors
/// Rejects duplicate, invalid, overdeep and excessive names. Empty is an empty tree.
pub fn anchor_list(text: &str) -> Result<AnchorInventory, Error> {
    bounded(text)?;
    let mut names = BTreeSet::new();
    for name in text.lines().map(str::trim).filter(|n| !n.is_empty()) {
        if name.len() > 1024
            || name.split('/').count() > 16
            || name.split('/').any(|part| {
                part.is_empty()
                    || part == "."
                    || part == ".."
                    || !part
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            })
            || !names.insert(name.to_owned())
            || names.len() > 4096
        {
            return Err(Error("anchor inventory name/size/duplicate"));
        }
    }
    Ok(AnchorInventory(names))
}
/// Separate `-s nat` output; unknown syntax is retained for conservative refusal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Translation(String);
impl Translation {
    /// Whitespace-normalized translation text, preserving line order.
    #[must_use]
    pub fn normalized(&self) -> &str {
        &self.0
    }
}
/// Parse bounded translation output without interpreting unknown rules as empty.
///
/// # Errors
/// Rejects oversized output and control characters.
pub fn translation(text: &str) -> Result<Translation, Error> {
    bounded(text)?;
    Ok(Translation(
        text.lines()
            .map(|l| l.split_whitespace().collect::<Vec<_>>().join(" "))
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(|l| l + "\n")
            .collect(),
    ))
}
/// A DNS resolver in the order printed by scutil, retaining scope and order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Resolver {
    /// Resolver number within its section.
    pub number: u32,
    /// Section title; scoped/supplemental output is not merged with default DNS.
    pub section: String,
    /// Nameserver addresses in printed order.
    pub servers: Vec<IpAddr>,
    /// Explicit search order, if printed.
    pub order: Option<u32>,
    /// Validated scoped interface, if printed.
    pub interface: Option<Interface>,
    /// Other recognized resolver properties, preserved for qualification.
    pub properties: Vec<(String, String)>,
}
/// Parse `scutil --dns`; resolver order is never sorted or guessed.
///
/// # Errors
/// Rejects invalid, incomplete, out-of-order or unsupported supplied evidence.
pub fn dns(text: &str) -> Result<Vec<Resolver>, Error> {
    bounded(text)?;
    let mut section = None;
    let mut result: Vec<Resolver> = Vec::new();
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
        if matches!(
            line,
            "DNS configuration"
                | "DNS configuration (for scoped queries)"
                | "DNS configuration (for service specific queries)"
        ) {
            section = Some(line.to_owned());
        } else if let Some(number) = line.strip_prefix("resolver #") {
            let number = u32::try_from(decimal(number)?).map_err(|_| Error("resolver number"))?;
            let section = section.clone().ok_or(Error("DNS section missing"))?;
            if result
                .iter()
                .any(|r| r.section == section && r.number == number)
            {
                return Err(Error("duplicate resolver"));
            }
            result.push(Resolver {
                number,
                section,
                servers: Vec::new(),
                order: None,
                interface: None,
                properties: Vec::new(),
            });
        } else {
            let resolver = result.last_mut().ok_or(Error("DNS resolver missing"))?;
            if section.as_ref() != Some(&resolver.section) {
                return Err(Error("DNS field before resolver"));
            }
            let (key, value) = line.split_once(':').ok_or(Error("DNS property"))?;
            let key = key.trim();
            let value = value.trim();
            if indexed(key, "nameserver") {
                resolver
                    .servers
                    .push(value.parse().map_err(|_| Error("DNS server"))?);
            } else if key == "order" {
                if resolver
                    .order
                    .replace(u32::try_from(decimal(value)?).map_err(|_| Error("DNS order"))?)
                    .is_some()
                {
                    return Err(Error("duplicate DNS order"));
                }
            } else if key == "if_index" {
                let (index, name) = value.split_once(" (").ok_or(Error("DNS interface"))?;
                decimal(index)?;
                let name = name
                    .strip_suffix(')')
                    .ok_or(Error("DNS interface"))?
                    .parse()?;
                if resolver.interface.replace(name).is_some() {
                    return Err(Error("duplicate DNS interface"));
                }
            } else if matches!(
                key,
                "domain" | "flags" | "reach" | "timeout" | "options" | "configuration id"
            ) || indexed(key, "search domain")
            {
                if value.is_empty() {
                    return Err(Error("empty DNS property"));
                }
                resolver.properties.push((key.into(), value.into()));
            } else {
                return Err(Error("unknown DNS property"));
            }
        }
    }
    if result.is_empty() {
        return Err(Error("no DNS resolvers"));
    }
    Ok(result)
}
fn indexed(key: &str, prefix: &str) -> bool {
    key.strip_prefix(prefix)
        .and_then(|s| s.strip_prefix('['))
        .and_then(|s| s.strip_suffix(']'))
        .is_some_and(|s| decimal(s).is_ok())
}
/// Route lookup preserves missing/link-layer gateway explicitly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Route {
    /// Numeric query target, distinct from the matched route destination.
    pub route_to: IpAddr,
    /// Selected interface.
    pub interface: Interface,
    /// IP gateway, if this is an IP next-hop route.
    pub gateway: Option<IpAddr>,
    /// Non-IP link gateway, when printed.
    pub link_gateway: Option<String>,
}
/// Parse `route -n get`; no gateway is never replaced by a tunnel/default route.
///
/// # Errors
/// Rejects invalid, incomplete, out-of-order or unsupported supplied evidence.
pub fn route(text: &str) -> Result<Route, Error> {
    bounded(text)?;
    let mut interface = None;
    let mut gateway = None;
    let mut link_gateway = None;
    let mut fields = BTreeSet::new();
    let mut route_header = false;
    let mut route_to = None;
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
        if line.starts_with("recvpipe")
            || (route_header && line.split_whitespace().all(|s| decimal(s).is_ok()))
        {
            continue;
        }
        let (key, value) = line.split_once(':').ok_or(Error("route property"))?;
        let key = key.trim();
        let value = value.trim();
        if !fields.insert(key) {
            return Err(Error("duplicate route property"));
        }
        match key {
            "route to" => {
                route_to = Some(value.parse().map_err(|_| Error("numeric route target"))?);
                route_header = true;
            }
            "destination" | "mask" if value == "default" => {
                route_header = true;
            }
            "destination" | "mask" => {
                value
                    .parse::<IpAddr>()
                    .map_err(|_| Error("numeric route address"))?;
                route_header = true;
            }
            "gateway" => {
                if let Ok(ip) = value.parse() {
                    gateway = Some(ip);
                } else if value
                    .strip_prefix("link#")
                    .is_some_and(|n| decimal(n).is_ok())
                {
                    link_gateway = Some(value.into());
                } else {
                    return Err(Error("numeric route gateway"));
                }
            }
            "interface" => {
                interface = Some(value.parse()?);
            }
            "flags" | "mtu" | "expire" | "hopcount" => {
                if value.is_empty() {
                    return Err(Error("route field"));
                }
            }
            _ => return Err(Error("unknown route property")),
        }
    }
    if !route_header {
        return Err(Error("missing route header"));
    }
    Ok(Route {
        route_to: route_to.ok_or(Error("missing route target"))?,
        interface: interface.ok_or(Error("missing route interface"))?,
        gateway,
        link_gateway,
    })
}
