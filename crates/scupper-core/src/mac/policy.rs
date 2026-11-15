//! The §14 allow table as data, and its deterministic pf source rendering.

use super::{DhcpPhase, Inputs};
use std::fmt::Write;

/// Direction relative to the named interface.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Direction {
    /// Both directions.
    Both,
    /// Outbound.
    Out,
    /// Inbound.
    In,
}
/// State behavior must be explicit for every rendered pass.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum State {
    /// Stateless DHCP, ND and loopback.
    None,
    /// Interface-bound endpoint/tunnel state.
    IfBound,
    /// Only for observations; never emitted.
    Implicit,
}
/// A single allow-table row. Address lists are expanded for semantic comparison.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Pass {
    /// Direction.
    pub direction: Direction,
    /// Explicit interface; absent only in parsed surrounding rules.
    pub interface: Option<String>,
    /// `inet`, `inet6`, or no family restriction.
    pub family: Option<String>,
    /// Protocol, or any protocol.
    pub protocol: Option<String>,
    /// Source address alternatives (`any` for no restriction).
    pub sources: Vec<String>,
    /// Source port.
    pub source_port: Option<u16>,
    /// Destination address alternatives.
    pub destinations: Vec<String>,
    /// Destination port.
    pub destination_port: Option<u16>,
    /// `ICMPv6` numeric type.
    pub icmp6_type: Option<u8>,
    /// Explicit state semantics.
    pub state: State,
    /// Whether evaluation terminates here.
    pub quick: bool,
    /// Observed implicit TCP flags, retained for qualification checks.
    pub tcp_flags: bool,
}
impl Pass {
    pub(super) fn all(interface: Option<String>) -> Self {
        Self {
            direction: Direction::Both,
            interface,
            family: None,
            protocol: None,
            sources: vec!["any".into()],
            source_port: None,
            destinations: vec!["any".into()],
            destination_port: None,
            icmp6_type: None,
            state: State::Implicit,
            quick: false,
            tcp_flags: false,
        }
    }
    /// Expand address alternatives without changing rule order or widening a row.
    #[must_use]
    pub fn expanded(&self) -> Vec<Self> {
        let mut rows = Vec::new();
        for source in &self.sources {
            for destination in &self.destinations {
                let mut row = self.clone();
                row.sources = vec![source.clone()];
                row.destinations = vec![destination.clone()];
                row.tcp_flags = false;
                rows.push(row);
            }
        }
        rows
    }
    fn render(&self) -> String {
        let direction = match self.direction {
            Direction::Both => "",
            Direction::Out => " out",
            Direction::In => " in",
        };
        let mut s = format!(
            "pass{direction} quick on {}",
            self.interface.as_deref().unwrap_or("")
        );
        if let Some(family) = &self.family {
            let _ = write!(s, " {family}");
        }
        if let Some(protocol) = &self.protocol {
            let _ = write!(s, " proto {protocol}");
        }
        if self.family.is_none() && self.protocol.is_none() {
            s.push_str(" all");
        } else {
            let _ = write!(s, " from {}", addresses(&self.sources));
            if let Some(port) = self.source_port {
                let _ = write!(s, " port {port}");
            }
            let _ = write!(s, " to {}", addresses(&self.destinations));
            if let Some(port) = self.destination_port {
                let _ = write!(s, " port {port}");
            }
            if let Some(kind) = self.icmp6_type {
                let _ = write!(s, " icmp6-type {kind}");
            }
        }
        s.push_str(match self.state {
            State::None => " no state",
            State::IfBound => " keep state (if-bound)",
            State::Implicit => "",
        });
        s
    }
}
fn addresses(items: &[String]) -> String {
    if items.len() == 1 {
        items[0].clone()
    } else {
        format!("{{ {} }}", items.join(", "))
    }
}
/// Policy form, independent of tunnel health.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Form {
    /// No tunnel interface passes.
    PreTunnel,
    /// Current-generation tunnel passes.
    Joined,
}
/// pf source text, including a trailing newline and final default block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnchorText(String);
impl AnchorText {
    /// Borrow source text. A normalized read-back baseline is a different type.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
/// Build the entire allow table. No LAN access or IPv6 underlay data rows exist.
#[must_use]
pub fn policy_table(inputs: &Inputs, form: Form) -> Vec<Pass> {
    let mut loopback = Pass::all(Some("lo0".into()));
    loopback.quick = true;
    loopback.state = State::None;
    let mut rows = vec![loopback];
    if form == Form::Joined {
        for direction in [Direction::Out, Direction::In] {
            let mut row = Pass::all(Some(inputs.tunnel().name.to_string()));
            row.direction = direction;
            row.state = State::IfBound;
            row.quick = true;
            rows.push(row);
        }
    }
    for (proto, port) in [("udp", inputs.endpoint().port()), ("tcp", 22)] {
        let mut row = Pass::all(Some(inputs.selected().to_string()));
        row.direction = Direction::Out;
        row.family = Some("inet".into());
        row.protocol = Some(proto.into());
        row.destinations = vec![inputs.endpoint().address().to_string()];
        row.destination_port = Some(port);
        row.state = State::IfBound;
        row.quick = true;
        rows.push(row);
    }
    for (interface, phase) in inputs.physical() {
        let (destination, source) = match phase {
            DhcpPhase::AcquiringRebinding => ("255.255.255.255".into(), "any".into()),
            DhcpPhase::Bound { server } => (server.to_string(), server.to_string()),
        };
        for direction in [Direction::Out, Direction::In] {
            let mut row = Pass::all(Some(interface.to_string()));
            row.direction = direction;
            row.family = Some("inet".into());
            row.protocol = Some("udp".into());
            row.sources = vec![if direction == Direction::Out {
                "any".into()
            } else {
                source.clone()
            }];
            row.destinations = vec![if direction == Direction::Out {
                destination.clone()
            } else {
                "any".into()
            }];
            row.source_port = Some(if direction == Direction::Out { 68 } else { 67 });
            row.destination_port = Some(if direction == Direction::Out { 67 } else { 68 });
            row.quick = true;
            row.state = State::None;
            rows.push(row);
        }
    }
    // The ND matrix is deliberately data, including the distinct DAD source.
    let nd = [
        (133, Direction::Out, "fe80::/10", vec!["ff02::2"]),
        (
            134,
            Direction::In,
            "fe80::/10",
            vec!["fe80::/10", "ff02::1"],
        ),
        (
            135,
            Direction::Out,
            "fe80::/10",
            vec!["fe80::/10", "ff02::1:ff00:0/104"],
        ),
        (
            135,
            Direction::In,
            "fe80::/10",
            vec!["fe80::/10", "ff02::1:ff00:0/104"],
        ),
        (
            136,
            Direction::Out,
            "fe80::/10",
            vec!["fe80::/10", "ff02::1"],
        ),
        (
            136,
            Direction::In,
            "fe80::/10",
            vec!["fe80::/10", "ff02::1"],
        ),
        (135, Direction::Out, "::", vec!["ff02::1:ff00:0/104"]),
        (135, Direction::In, "::", vec!["ff02::1:ff00:0/104"]),
    ];
    for (kind, direction, source, destinations) in nd {
        let mut row = Pass::all(Some(inputs.selected().to_string()));
        row.direction = direction;
        row.family = Some("inet6".into());
        row.protocol = Some("ipv6-icmp".into());
        row.sources = vec![source.into()];
        row.destinations = destinations.into_iter().map(str::to_owned).collect();
        row.icmp6_type = Some(kind);
        row.state = State::None;
        row.quick = true;
        rows.push(row);
    }
    rows
}
fn render(inputs: &Inputs, form: Form) -> AnchorText {
    let mut text = policy_table(inputs, form)
        .iter()
        .map(Pass::render)
        .collect::<Vec<_>>()
        .join("\n");
    text.push_str("\nblock drop quick all\n");
    AnchorText(text)
}
/// Render the verified-enforcement prerequisite to any child mutation.
#[must_use]
pub fn render_pre_tunnel(inputs: &Inputs) -> AnchorText {
    render(inputs, Form::PreTunnel)
}
/// Render passes for the expected tunnel; identity must be verified separately.
#[must_use]
pub fn render_joined(inputs: &Inputs) -> AnchorText {
    render(inputs, Form::Joined)
}
