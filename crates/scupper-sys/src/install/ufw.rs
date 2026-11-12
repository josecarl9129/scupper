//! M2 availability heuristic using ufw's stable, C-locale status fields.
use super::{Refusal, firewall::Packet, input};
use crate::system::{EXEC_TIMEOUT, ExecError, Program, System};

#[derive(Debug, PartialEq, Eq)]
enum Policy {
    Allow,
    Block,
}
impl Policy {
    fn parse(text: &str) -> Option<Self> {
        match text {
            "allow" => Some(Self::Allow),
            "deny" | "reject" => Some(Self::Block),
            _ => None,
        }
    }
}

pub(super) struct Status {
    incoming: Policy,
    outgoing: Policy,
    rules: Vec<String>,
}

fn active(text: &str) -> bool {
    text.lines().any(|line| line.trim() == "Status: active")
}

pub(super) fn parse(text: &str) -> Option<Status> {
    if !active(text) {
        return None;
    }
    let defaults = text
        .lines()
        .find_map(|line| line.strip_prefix("Default: "))?;
    let policy = |direction| {
        defaults.split(',').find_map(|part| {
            let mut fields = part.split_whitespace();
            let value = fields.next()?;
            (fields.next()? == direction).then(|| Policy::parse(value))?
        })
    };
    let rules = text
        .lines()
        .skip_while(|line| line.split_whitespace().collect::<Vec<_>>() != ["To", "Action", "From"])
        .skip(1)
        .map(str::to_owned)
        .collect();
    Some(Status {
        incoming: policy("(incoming)")?,
        outgoing: policy("(outgoing)")?,
        rules,
    })
}

/// Missing or inactive ufw falls back to nft. Failed active observations refuse
/// rather than treating a failed query as an inactive firewall.
pub(super) fn observe(system: &dyn System) -> Result<Option<Status>, Refusal> {
    let run = |args: &[&str]| {
        system.run(
            Program::Ufw,
            &args.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>(),
            EXEC_TIMEOUT,
        )
    };
    let status = match run(&["status"]) {
        Err(ExecError::Spawn(_)) => return Ok(None), // Optional executable absent.
        result => result.map_err(|_| Refusal::CommandFailed("ufw status failed".into()))?,
    };
    if status.status != Some(0) {
        return Err(Refusal::CommandFailed("ufw status failed".into()));
    }
    if status
        .stdout
        .lines()
        .any(|line| line.trim() == "Status: inactive")
    {
        return Ok(None);
    }
    if !active(&status.stdout) {
        return Err(input("invalid ufw status observation"));
    }
    let verbose = run(&["status", "verbose"])
        .map_err(|_| Refusal::CommandFailed("ufw status verbose failed".into()))?;
    if verbose.status != Some(0) {
        return Err(Refusal::CommandFailed("ufw status verbose failed".into()));
    }
    parse(&verbose.stdout)
        .map(Some)
        .ok_or_else(|| input("invalid active ufw status observation"))
}

impl Status {
    pub(super) fn may_block(&self, packet: Packet<'_>) -> bool {
        let policy = if packet.hook == "input" {
            &self.incoming
        } else {
            &self.outgoing
        };
        *policy != Policy::Allow && !self.rules.iter().any(|line| allows(line, packet))
    }
}

fn anywhere(fields: &[&str], ipv6: bool) -> bool {
    fields == ["Anywhere"] || fields == [if ipv6 { "::/0" } else { "0.0.0.0/0" }]
}

fn on_uplink<'a>(fields: &'a [&'a str], uplink: &str) -> Option<&'a [&'a str]> {
    if let Some(on) = fields.iter().position(|field| *field == "on") {
        if fields.get(on + 1) != Some(&uplink) || on + 2 != fields.len() {
            return None;
        }
        Some(&fields[..on])
    } else {
        Some(fields)
    }
}

fn allows(line: &str, packet: Packet<'_>) -> bool {
    let line = line.split('#').next().unwrap_or("");
    let ipv6 = line.split_whitespace().any(|field| field == "(v6)");
    if ipv6 != packet.destination.is_ipv6() {
        return false;
    }
    let fields: Vec<_> = line
        .split_whitespace()
        .filter(|field| *field != "(v6)")
        .collect();
    let Some(action) = fields.iter().position(|field| *field == "ALLOW") else {
        return false;
    };
    let direction = if packet.hook == "input" { "IN" } else { "OUT" };
    if fields.get(action + 1) != Some(&direction) {
        return false;
    }
    // ufw prints an input interface in To, and an output interface in From.
    let (mut to, mut from) = (&fields[..action], &fields[action + 2..]);
    if packet.hook == "input" {
        let Some(local) = on_uplink(to, packet.uplink) else {
            return false;
        };
        to = local;
    } else {
        let Some(local) = on_uplink(from, packet.uplink) else {
            return false;
        };
        from = local;
    }
    if !anywhere(from, ipv6) {
        return false;
    }
    // An output rule may name the literal endpoint. Input exceptions must be
    // reachable from any source, to any local address on this interface.
    if packet.hook == "output" && to.len() == 2 {
        if to[0].parse::<std::net::IpAddr>().ok() != Some(packet.destination) {
            return false;
        }
        to = &to[1..];
    }
    anywhere(to, ipv6) || to == [packet.port.to_string()] || to == [format!("{}/udp", packet.port)]
}

#[cfg(test)]
#[path = "ufw/tests.rs"]
mod tests;
