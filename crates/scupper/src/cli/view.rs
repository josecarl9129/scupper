//! Human health views and the schema-1 status observation projection.
use super::{AppliedConfig, output_error};
use scupper_core::{
    parse::{Handshake, HandshakeAge},
    verdict::v2::{CheckError, Observations, Probe, Report, Supervisor},
};
use serde_json::{Value, json};
use std::io::Write;

// Render the Report wire value so socket and local checks use the same view.
pub(super) fn check(out: &mut dyn Write, report: &Value) -> Result<(), String> {
    let verdict = &report["verdict"];
    let summary = if let Some(protected) = verdict.get("Protected") {
        format!(
            "protected via {} (exit IP {})",
            text(&protected["exit"]),
            text(&protected["exit_ip"])
        )
    } else if let Some(unsupervised) = verdict.get("Unsupervised") {
        format!(
            "unsupervised via {} (exit IP {}): {}",
            text(&unsupervised["exit"]),
            text(&unsupervised["exit_ip"]),
            human(&unsupervised["why"])
        )
    } else {
        human(verdict)
    };
    let warnings = report["warnings"]
        .as_array()
        .ok_or("invalid health report warnings")?;
    let noun = if warnings.len() == 1 {
        "warning"
    } else {
        "warnings"
    };
    writeln!(
        out,
        "{summary}, config v{}, {} {noun}",
        report["config_version"],
        warnings.len()
    )
    .map_err(output_error)?;
    for warning in warnings {
        writeln!(out, "warning: {}", human(warning)).map_err(output_error)?;
    }
    Ok(())
}

fn text(value: &Value) -> &str {
    value.as_str().unwrap_or("unknown")
}

// Enum names and fields become readable phrases; no Rust Debug representation
// is part of the human interface, including uncommon failures and warnings.
fn words(name: &str) -> String {
    let mut result = String::new();
    for (i, c) in name.chars().enumerate() {
        if c == '_' {
            result.push(' ');
        } else {
            if i > 0 && c.is_uppercase() {
                result.push(' ');
            }
            result.extend(c.to_lowercase());
        }
    }
    result
}
fn human(value: &Value) -> String {
    match value {
        Value::String(s) => words(s),
        Value::Object(fields) if fields.len() == 1 && fields.contains_key("RulesetDiffers") => {
            "ruleset differs".into()
        }
        Value::Object(fields) if fields.len() == 1 && fields.contains_key("Ok") => {
            human(&fields["Ok"])
        }
        Value::Object(fields) if fields.len() == 1 && fields.contains_key("Dev") => {
            format!("via {}", text(&fields["Dev"]))
        }
        Value::Object(fields) => fields
            .iter()
            .map(|(key, value)| format!("{}: {}", words(key), human(value)))
            .collect::<Vec<_>>()
            .join(", "),
        Value::Array(values) => values.iter().map(human).collect::<Vec<_>>().join("; "),
        other => other.to_string(),
    }
}

fn stage<T>(value: Option<&Probe<T>>, project: impl FnOnce(&T) -> Value) -> Value {
    match value {
        None => Value::Null,
        Some(Ok(value)) => json!({"ok": project(value)}),
        Some(Err(error)) => json!({"error": error.to_string()}),
    }
}
fn handshake(value: &Handshake) -> Value {
    match value {
        Handshake::Never => json!("never"),
        Handshake::At { unix_secs } => json!({"at": unix_secs}),
    }
}
fn age(value: Option<&Handshake>, now: u64) -> String {
    match value.map(|h| h.age_at(now)) {
        None => "not observed".into(),
        Some(HandshakeAge::Never) => "never".into(),
        Some(HandshakeAge::Age(age)) => format!("{}s ago", age.as_secs()),
        Some(HandshakeAge::InFuture(age)) => format!("{}s in future", age.as_secs()),
    }
}

// Fixed-size public keys only. Private material never enters this projection.
fn public_key(bytes: &[u8; 32]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::with_capacity(44);
    for chunk in bytes.chunks(3) {
        let a = chunk[0];
        let b = chunk.get(1).copied().unwrap_or(0);
        let c = chunk.get(2).copied().unwrap_or(0);
        result.push(char::from(ALPHABET[usize::from(a >> 2)]));
        result.push(char::from(ALPHABET[usize::from(((a & 3) << 4) | (b >> 4))]));
        result.push(if chunk.len() > 1 {
            char::from(ALPHABET[usize::from(((b & 15) << 2) | (c >> 6))])
        } else {
            '='
        });
        result.push(if chunk.len() > 2 {
            char::from(ALPHABET[usize::from(c & 63)])
        } else {
            '='
        });
    }
    result
}

#[allow(clippy::too_many_lines)] // Keep the documented observation fields together.
pub(super) fn status_value(
    config: &AppliedConfig,
    result: &Result<Report, CheckError>,
    obs: &Observations,
    now: u64,
) -> Result<Value, String> {
    let gateway = config
        .site
        .gateway(&config.gateway)
        .ok_or("unknown gateway")?;
    let exits: Vec<_> = gateway.exits().iter().map(|exit| {
        let h = obs.handshakes.as_ref().and_then(|r| r.as_ref().ok()).and_then(|h| h.get(exit.id()));
        let endpoint = obs.topology.as_ref().and_then(|r| r.as_ref().ok()).and_then(|t| t.peers.get(exit.ifname().as_str())).and_then(|peers| peers.iter().find(|p| p.public_key == exit.peer_public_key())).and_then(|p| p.endpoint);
        json!({"id": exit.id(), "interface": exit.ifname().as_str(), "public_key": exit.peer_public_key_text().as_str(), "handshake_age": age(h, now), "endpoint": endpoint})
    }).collect();
    let clients: Vec<_> = config.site.devices().iter().filter(|(_, device)| device.gateways().contains(&config.gateway)).map(|(name, device)| {
        let h = obs.forwarding.as_ref().and_then(|r| r.as_ref().ok()).and_then(|f| f.client_handshakes.get(&device.public_key()));
        json!({"name": name, "public_key": device.public_key_text().as_str(), "handshake_age": age(h, now)})
    }).collect();
    let topology = stage(obs.topology.as_ref(), |t| {
        let peers: serde_json::Map<_, _> = t.peers.iter().map(|(interface, peers)| {
            let peers: Vec<_> = peers.iter().map(|p| json!({"public_key": public_key(&p.public_key), "allowed_ips": p.allowed_ips.iter().map(ToString::to_string).collect::<Vec<_>>(), "endpoint": if interface == gateway.client_tunnel().ifname().as_str() { None } else { p.endpoint }})).collect();
            (interface.clone(), json!(peers))
        }).collect();
        let links: Vec<_> = t.links.iter().map(|l| json!({"name": l.name, "kind": l.kind, "up": l.up, "addresses": l.addresses.iter().map(ToString::to_string).collect::<Vec<_>>()})).collect();
        let netns = match t.netns {
            scupper_core::verdict::v2::NetnsObs::Present { device, inode } => {
                json!({"present": {"device": device, "inode": inode}})
            }
            scupper_core::verdict::v2::NetnsObs::Missing => json!("missing"),
            scupper_core::verdict::v2::NetnsObs::WrongInode => json!("wrong_inode"),
        };
        let ruleset = match &t.ruleset {
            scupper_core::verdict::v2::RulesetObs::Exact => json!("exact"),
            scupper_core::verdict::v2::RulesetObs::Missing => json!("missing"),
            scupper_core::verdict::v2::RulesetObs::Differs { live, want } => {
                json!({"differs": {"live": live, "want": want}})
            }
        };
        json!({"netns": netns, "links": links, "peers": peers, "ruleset": ruleset, "errors": t.errors, "links_complete": t.links_complete, "addresses_complete": t.addresses_complete, "host_wireguard_on_client_port": t.host_wireguard_on_client_port, "extra_rules": t.extra_rules, "tc_hooks": t.tc_hooks})
    });
    let defaults = stage(
        obs.defaults.as_ref(),
        |d| json!({"v4": d.v4, "v6": d.v6, "extra": d.extra, "violations": d.violations}),
    );
    let handshakes = stage(obs.handshakes.as_ref(), |h| {
        Value::Object(
            h.iter()
                .map(|(id, h)| (id.as_str().to_owned(), handshake(h)))
                .collect(),
        )
    });
    let forwarding = stage(obs.forwarding.as_ref(), |f| {
        let clients: serde_json::Map<_, _> = f
            .client_handshakes
            .iter()
            .map(|(key, h)| (public_key(key), handshake(h)))
            .collect();
        let sockets = |sockets: &[scupper_core::parse::UdpSocket]| {
            sockets
                .iter()
                .map(|s| json!({"local": s.local, "inode": s.inode}))
                .collect::<Vec<_>>()
        };
        json!({"v4": f.v4, "v6": f.v6, "client_v4": f.client_v4, "hardening": f.hardening, "quarantine": f.quarantine, "client_public_key": f.client_public_key.as_ref().map(public_key), "listen_port": f.listen_port, "client_handshakes": clients, "host_sockets": sockets(&f.host_sockets), "netns_sockets": sockets(&f.netns_sockets)})
    });
    let routes = obs.routes.as_ref().map(|routes| {
        routes
            .iter()
            .map(|(client, r)| json!({"client": client, "v4": r.v4, "v6": r.v6}))
            .collect::<Vec<_>>()
    });
    let supervisor = obs.supervisor.map(|s| match s {
        Supervisor::Alive { iteration_age, netns } => json!({"state": "alive", "iteration_age_seconds": iteration_age.as_secs(), "netns": netns}),
        Supervisor::Dead => json!({"state": "dead"}),
        Supervisor::NotRequired => json!({"state": "not_required"}),
    });
    Ok(
        json!({"schema": 1, "report": result.as_ref().ok(), "error": result.as_ref().err().map(|e| super::json_error(Some(e.stage), &e.source.to_string())), "observations": {"topology": topology, "selection": obs.selection, "active": obs.active, "defaults": defaults, "handshakes": handshakes, "forwarding": forwarding, "routes": routes, "exit_probe": stage(obs.exit_probe.as_ref(), |ip| json!(ip)), "standby_probe": stage(obs.standby_probe.as_ref(), |()| Value::Null), "dns": stage(obs.dns.as_ref(), |()| Value::Null), "supervisor": supervisor}, "exits": exits, "clients": clients}),
    )
}

pub(super) fn status(out: &mut dyn Write, value: &Value) -> Result<(), String> {
    writeln!(out, "Verdict").map_err(output_error)?;
    if value["report"].is_null() {
        writeln!(
            out,
            "observation failed: {}",
            text(&value["error"]["message"])
        )
        .map_err(output_error)?;
    } else {
        check(out, &value["report"])?;
    }
    for (section, field, name) in [("Exits", "exits", "id"), ("Clients", "clients", "name")] {
        writeln!(out, "\n{section}").map_err(output_error)?;
        if let Some(rows) = value[field].as_array() {
            for row in rows {
                write!(out, "  {}", text(&row[name])).map_err(output_error)?;
                if field == "exits" {
                    write!(out, " ({})", text(&row["interface"])).map_err(output_error)?;
                }
                write!(out, ": handshake {}", text(&row["handshake_age"])).map_err(output_error)?;
                if field == "exits" {
                    write!(
                        out,
                        ", endpoint {}",
                        row["endpoint"].as_str().unwrap_or("not observed")
                    )
                    .map_err(output_error)?;
                }
                writeln!(out, "\n    public key {}", text(&row["public_key"]))
                    .map_err(output_error)?;
            }
        }
    }
    let obs = &value["observations"];
    writeln!(out, "\nClient route").map_err(output_error)?;
    if let Some(routes) = obs["routes"].as_array() {
        if routes.is_empty() {
            writeln!(out, "  no clients").map_err(output_error)?;
        }
        for route in routes {
            writeln!(
                out,
                "  {}: IPv4 {}; IPv6 {}",
                text(&route["client"]),
                human(&route["v4"]),
                human(&route["v6"])
            )
            .map_err(output_error)?;
        }
    } else {
        writeln!(out, "  not observed").map_err(output_error)?;
    }
    writeln!(out, "\nForwarding").map_err(output_error)?;
    let forwarding = &obs["forwarding"];
    if let Some(f) = forwarding.get("ok") {
        writeln!(
            out,
            "  IPv4 {}; IPv6 {}; client ingress IPv4 {}",
            f["v4"], f["v6"], f["client_v4"]
        )
        .map_err(output_error)?;
    } else {
        writeln!(
            out,
            "  {}",
            forwarding.get("error").map_or("not observed", text)
        )
        .map_err(output_error)?;
    }
    writeln!(out, "\nSupervisor / daemon").map_err(output_error)?;
    let supervisor = &obs["supervisor"];
    match supervisor["state"].as_str() {
        Some("alive") => writeln!(
            out,
            "  scupperd alive, last complete iteration {}s ago",
            supervisor["iteration_age_seconds"]
        ),
        Some("dead") => writeln!(out, "  scupperd unavailable"),
        Some("not_required") => writeln!(out, "  supervision not required; daemon not observed"),
        _ => writeln!(out, "  not observed"),
    }
    .map_err(output_error)
}
