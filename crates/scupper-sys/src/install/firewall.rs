//! Availability heuristic for fresh client and exit `WireGuard` UDP.
use serde_json::Value;
use std::net::IpAddr;

#[derive(Clone, Copy)]
pub(super) struct Packet<'a> {
    pub hook: &'a str,
    pub uplink: &'a str,
    pub port: u16,
    pub destination: IpAddr,
}
// Unknown predicates can match, but cannot prove an unconditional accept.
fn predicate(expr: &Value, packet: Packet<'_>) -> Option<bool> {
    let m = expr.get("match")?;
    let left = &m["left"];
    let right = &m["right"];
    if left["payload"]["protocol"]
        .as_str()
        .is_some_and(|p| matches!(p, "tcp" | "icmp" | "icmpv6"))
    {
        return Some(false);
    }
    let wanted = if left["ct"]["key"] == "state" {
        Value::from("new")
    } else if left["fib"]["result"] == "type"
        && left["fib"]["flags"]
            .as_array()
            .is_some_and(|flags| flags == &[Value::from("daddr")])
        && packet.hook == "input"
    {
        // The input hook is reached only after routing to a local address.
        // Do not apply this inference to an output packet's remote destination.
        Value::from("local")
    } else if left["meta"]["key"] == "nfproto" {
        Value::from(if packet.destination.is_ipv4() {
            "ipv4"
        } else {
            "ipv6"
        })
    } else if left["meta"]["key"]
        == if packet.hook == "input" {
            "iifname"
        } else {
            "oifname"
        }
    {
        Value::from(packet.uplink)
    } else if left["meta"]["key"] == "l4proto"
        || matches!(
            left["payload"]["field"].as_str(),
            Some("protocol" | "nexthdr")
        )
    {
        if right.is_number()
            || right.get("range").is_some()
            || right["set"]
                .as_array()
                .is_some_and(|values| values.iter().all(Value::is_number))
        {
            Value::from(17)
        } else {
            Value::from("udp")
        }
    } else if left["payload"]["field"] == "dport" {
        // A TCP dport expression cannot match this UDP packet.
        if left["payload"]["protocol"]
            .as_str()
            .is_some_and(|p| p != "udp" && p != "th")
        {
            return Some(false);
        }
        Value::from(packet.port)
    } else if left["payload"]["field"] == "daddr" {
        let protocol = left["payload"]["protocol"].as_str()?;
        if (protocol == "ip" && packet.destination.is_ipv6())
            || (protocol == "ip6" && packet.destination.is_ipv4())
        {
            return Some(false);
        }
        Value::from(packet.destination.to_string())
    } else {
        return None;
    };
    let equal = matches_value(right, &wanted, packet.destination)?;
    match m["op"].as_str()? {
        "==" | "in" => Some(equal),
        "!=" => Some(!equal),
        _ => None,
    }
}

fn matches_value(right: &Value, wanted: &Value, destination: IpAddr) -> Option<bool> {
    let equal = if let Some(prefix) = right.get("prefix") {
        let network: ipnet::IpNet =
            format!("{}/{}", prefix["addr"].as_str()?, prefix["len"].as_u64()?)
                .parse()
                .ok()?;
        network.contains(&destination)
    } else if let Some(set) = right.get("set").and_then(Value::as_array) {
        let matches = set
            .iter()
            .map(|item| matches_value(item, wanted, destination))
            .collect::<Option<Vec<_>>>()?;
        matches.contains(&true)
    } else if let Some(range) = right.get("range").and_then(Value::as_array) {
        wanted
            .as_u64()
            .zip(range.first()?.as_u64())
            .zip(range.get(1)?.as_u64())
            .is_some_and(|((n, low), high)| low <= n && n <= high)
    } else if let (Some(pattern), Some(value)) = (right.as_str(), wanted.as_str()) {
        pattern
            .strip_suffix('*')
            .map_or(pattern == value, |prefix| value.starts_with(prefix))
    } else if right.is_number() || right.is_string() {
        right == wanted
    } else {
        return None;
    };
    Some(equal)
}

// Outcomes are possible drop and possible return to the caller. An accept
// terminates only this base chain; every other applicable base chain is checked.
// A possible return must survive a later accept when its predicate is unknown.
#[derive(Clone, Copy)]
struct Outcome {
    drop: bool,
    returns: bool,
}

fn condition(expr: &Value, packet: Packet<'_>) -> Option<bool> {
    if expr.get("match").is_some() {
        predicate(expr, packet)
    } else if [
        "counter", "log", "accept", "drop", "reject", "return", "jump", "goto",
    ]
    .iter()
    .any(|key| expr.get(key).is_some())
    {
        Some(true)
    } else {
        // This includes opaque xt matches and unsupported predicates such as
        // limits. They may apply but cannot establish a definite accept/return.
        None
    }
}

fn chain<'a>(
    rows: &'a [Value],
    family: &Value,
    table: &Value,
    name: &'a Value,
    packet: Packet<'_>,
    path: &mut Vec<&'a Value>,
) -> Outcome {
    // Only the active call path is a cycle: separate calls to a shared chain
    // are legal. Bound acyclic nesting as well, independent of ruleset size.
    if path.len() >= 16 || path.contains(&name) {
        return Outcome {
            drop: true,
            returns: true,
        };
    }
    path.push(name);
    let outcome = chain_rules(rows, family, table, name, packet, path);
    path.pop();
    outcome
}

fn chain_rules<'a>(
    rows: &'a [Value],
    family: &Value,
    table: &Value,
    name: &Value,
    packet: Packet<'_>,
    path: &mut Vec<&'a Value>,
) -> Outcome {
    let mut returns = false;
    for rule in rows
        .iter()
        .filter_map(|r| r.get("rule"))
        .filter(|r| &r["family"] == family && &r["table"] == table && &r["chain"] == name)
    {
        let Some(exprs) = rule["expr"].as_array() else {
            continue;
        };
        let tests: Vec<_> = exprs.iter().map(|e| condition(e, packet)).collect();
        if tests.contains(&Some(false)) {
            continue;
        }
        let certain = tests.iter().all(|v| *v == Some(true));
        for expr in exprs {
            if expr.get("drop").is_some() || expr.get("reject").is_some() {
                return Outcome {
                    drop: true,
                    returns,
                };
            }
            for verdict in ["jump", "goto"] {
                if let Some(target) = expr.get(verdict).and_then(|v| v.get("target")) {
                    let outcome = chain(rows, family, table, target, packet, path);
                    if outcome.drop {
                        return outcome;
                    }
                    if verdict == "goto" {
                        returns |= outcome.returns;
                    }
                    if certain && (!outcome.returns || verdict == "goto") {
                        return Outcome {
                            drop: false,
                            returns,
                        };
                    }
                }
            }
            if certain && expr.get("accept").is_some() {
                return Outcome {
                    drop: false,
                    returns,
                };
            }
            if expr.get("return").is_some() {
                returns = true;
                if certain {
                    return Outcome {
                        drop: false,
                        returns,
                    };
                }
            }
        }
    }
    Outcome {
        drop: false,
        returns: true,
    }
}

pub(super) fn may_block(json: &Value, packet: Packet<'_>) -> bool {
    let Some(rows) = json["nftables"].as_array() else {
        return false;
    };
    rows.iter()
        .filter_map(|row| row.get("chain"))
        .filter(|c| {
            c["hook"] == packet.hook
                && (c["family"] == "inet"
                    || c["family"]
                        == if packet.destination.is_ipv4() {
                            "ip"
                        } else {
                            "ip6"
                        })
        })
        .any(|c| {
            let outcome = chain(
                rows,
                &c["family"],
                &c["table"],
                &c["name"],
                packet,
                &mut Vec::new(),
            );
            outcome.drop || (outcome.returns && c["policy"] == "drop")
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn may_block(json: &Value, uplink: &str) -> bool {
        super::may_block(
            json,
            Packet {
                hook: "input",
                uplink,
                port: 51820,
                destination: "192.0.2.1".parse().unwrap(),
            },
        )
    }
    fn rules(hook: &str, policy: &str, expr: &Value) -> Value {
        json!({"nftables":[
            {"chain":{"family":"ip","table":"filter","name":"INPUT","hook":hook,"policy":policy}},
            {"rule":{"family":"ip","table":"filter","chain":"INPUT","expr":expr}}
        ]})
    }
    fn port(n: u16) -> Value {
        json!({"match":{"op":"==","left":{"payload":{"protocol":"udp","field":"dport"}},"right":n}})
    }
    #[test]
    fn docker_forward_drops_comments_and_names_do_not_warn() {
        assert!(!may_block(
            &rules("forward", "drop", &json!([{"drop":null}])),
            "up0"
        ));
        let r = json!({"nftables":[{"chain":{"family":"inet","table":"drop","name":"reject","hook":"input","policy":"accept"}},{"rule":{"family":"inet","table":"drop","chain":"reject","expr":[{"counter":{"packets":0,"bytes":0}}],"comment":"drop UDP"}}]});
        assert!(!may_block(&r, "up0"));
        assert!(!may_block(
            &rules("input", "accept", &json!([port(53),{"drop":null}])),
            "up0"
        ));
        assert!(!may_block(
            &rules(
                "input",
                "accept",
                &json!([{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":51820}},{"reject":null}])
            ),
            "up0"
        ));
        assert!(!may_block(
            &rules("input", "drop", &json!([{"accept":null}])),
            "up0"
        ));
    }
    #[test]
    fn ufw_uplink_deny_is_reachable_from_input_jump() {
        let mut r = rules(
            "input",
            "accept",
            &json!([{"jump":{"target":"ufw-user-input"}}]),
        );
        r["nftables"].as_array_mut().unwrap().push(json!({"rule":{"family":"ip","table":"filter","chain":"ufw-user-input","expr":[{"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"up0"}},port(51820),{"drop":null}]}}));
        assert!(may_block(&r, "up0"));
        assert!(!may_block(&r, "eth0"));
    }
    #[test]
    fn input_policy_drop_requires_applicable_accept() {
        assert!(may_block(&rules("input", "drop", &json!([])), "up0"));
        assert!(!may_block(
            &rules("input", "drop", &json!([port(51820),{"accept":null}])),
            "up0"
        ));
        assert!(may_block(
            &rules("input", "drop", &json!([port(53),{"accept":null}])),
            "up0"
        ));
        assert!(may_block(
            &rules(
                "input",
                "accept",
                &json!([port(51820),{"reject":{"type":"icmp"}}])
            ),
            "up0"
        ));
    }
    #[test]
    fn exit_output_policy_rules_and_configured_port_are_checked() {
        let packet = Packet {
            hook: "output",
            uplink: "up0",
            port: 443,
            destination: "203.0.113.2".parse().unwrap(),
        };
        assert!(super::may_block(
            &rules("output", "drop", &json!([])),
            packet
        ));
        assert!(!super::may_block(
            &rules("input", "drop", &json!([])),
            packet
        ));
        assert!(!super::may_block(
            &rules("output", "accept", &json!([port(51820), {"drop":null}])),
            packet
        ));
        assert!(super::may_block(
            &rules("output", "accept", &json!([port(443), {"reject":null}])),
            packet
        ));
        assert!(!super::may_block(
            &rules("output", "drop", &json!([port(443), {"accept":null}])),
            packet
        ));
        for (interface, blocked) in [("up0", true), ("other0", false)] {
            let r = rules(
                "output",
                "accept",
                &json!([
                    {"match":{"op":"==","left":{"meta":{"key":"oifname"}},"right":interface}},
                    port(443), {"drop":null}
                ]),
            );
            assert_eq!(super::may_block(&r, packet), blocked);
        }
        let scoped = rules(
            "output",
            "accept",
            &json!([
                {"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"daddr"}},"right":"203.0.113.3"}},
                port(443), {"drop":null}
            ]),
        );
        assert!(!super::may_block(&scoped, packet));
        let mut prefixes = scoped.clone();
        prefixes["nftables"][1]["rule"]["expr"][0]["match"]["right"] =
            json!({"set":[{"prefix":{"addr":"203.0.113.0","len":24}}]});
        assert!(super::may_block(&prefixes, packet));
        assert!(super::may_block(
            &scoped,
            Packet {
                destination: "203.0.113.3".parse().unwrap(),
                ..packet
            }
        ));
    }
    #[test]
    fn fresh_udp_ignores_unrelated_protocols_ports_and_states_in_both_directions() {
        for hook in ["input", "output"] {
            let packet = Packet {
                hook,
                uplink: "up0",
                port: 51820,
                destination: "198.51.100.2".parse().unwrap(),
            };
            for state in [
                json!("invalid"),
                json!({"set":["related", "established"]}),
                json!("untracked"),
            ] {
                let r = rules(
                    hook,
                    "accept",
                    &json!([
                        {"match":{"op":"in","left":{"ct":{"key":"state"}},"right":state}}, {"drop":null}
                    ]),
                );
                assert!(!super::may_block(&r, packet));
            }
            for protocol in [
                json!(17),
                json!("udp"),
                json!({"set":[6, 17]}),
                json!({"set":["tcp", "udp"]}),
            ] {
                let r = rules(
                    hook,
                    "accept",
                    &json!([
                        {"match":{"op":"in","left":{"meta":{"key":"l4proto"}},"right":protocol}}, {"drop":null}
                    ]),
                );
                assert!(super::may_block(&r, packet));
            }
            for state in [json!("new"), json!({"set":["invalid", "new"]})] {
                let r = rules(
                    hook,
                    "accept",
                    &json!([
                        {"match":{"op":"in","left":{"ct":{"key":"state"}},"right":state}}, {"drop":null}
                    ]),
                );
                assert!(super::may_block(&r, packet));
            }
            for expr in [
                json!([port(53), {"drop":null}]),
                json!([{"match":{"op":"==","left":{"meta":{"key":"l4proto"}},"right":"tcp"}}, {"drop":null}]),
                json!([{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":51820}}, {"reject":null}]),
            ] {
                assert!(!super::may_block(&rules(hook, "accept", &expr), packet));
            }
        }
    }
    #[test]
    fn ufw_local_return_precedes_not_local_drop_but_unknown_return_is_uncertain() {
        let mut r = rules(
            "input",
            "drop",
            &json!([{"jump":{"target":"ufw-not-local"}}]),
        );
        let rows = r["nftables"].as_array_mut().unwrap();
        rows.push(json!({"rule":{"family":"ip","table":"filter","chain":"ufw-not-local","expr":[
            {"match":{"op":"==","left":{"fib":{"result":"type","flags":["daddr"]}},"right":"local"}}, {"return":null}
        ]}}));
        rows.push(json!({"rule":{"family":"ip","table":"filter","chain":"ufw-not-local","expr":[{"drop":null}]}}));
        rows.push(json!({"rule":{"family":"ip","table":"filter","chain":"INPUT","expr":[port(51820), {"accept":null}]}}));
        assert!(!may_block(&r, "up0"));
        r["nftables"][2]["rule"]["expr"][0]["match"]["left"] = json!({"unknown":{}});
        assert!(may_block(&r, "up0"));
    }
    #[test]
    fn output_goto_and_address_family_limit_the_warning() {
        let packet = Packet {
            hook: "output",
            uplink: "up0",
            port: 443,
            destination: "203.0.113.2".parse().unwrap(),
        };
        let mut r = rules(
            "output",
            "accept",
            &json!([{"goto":{"target":"exit-deny"}}]),
        );
        r["nftables"].as_array_mut().unwrap().push(json!({"rule":{"family":"ip","table":"filter","chain":"exit-deny","expr":[port(443),{"reject":null}]}}));
        assert!(super::may_block(&r, packet));
        let packet6 = Packet {
            destination: "2001:db8::2".parse().unwrap(),
            ..packet
        };
        assert!(!super::may_block(&r, packet6));
        let mut r = rules("output", "drop", &json!([]));
        r["nftables"][0]["chain"]["family"] = json!("ip6");
        assert!(!super::may_block(&r, packet));
        assert!(super::may_block(&r, packet6));
    }
    // V-13 writes these with nft -j list ruleset after actual ufw enable and
    // successive default, allow, default-outgoing deny and bidirectional deny rules.
    // Opaque xt predicates still warn on inbound allow dumps without ufw status.
    #[test]
    #[ignore = "requires real V-13 ufw ruleset dumps; run by the systemd CI matrix"]
    fn real_ufw_enable_ruleset_dumps() {
        let root = std::env::var_os("SCUPPER_TEST_UFW_DUMPS").expect("V-13 artifacts directory");
        for (label, inbound, outbound) in [
            ("V-13-default", true, false),
            ("V-13-allow", true, false),
            ("V-13-exit", true, true),
            ("V-13", true, true),
        ] {
            let path = std::path::Path::new(&root).join(format!("{label}-ruleset.json"));
            let rules: Value =
                serde_json::from_slice(&std::fs::read(&path).expect("real ufw ruleset dump"))
                    .unwrap();
            let status_path = std::path::Path::new(&root).join(format!("{label}-ufw-status.txt"));
            let status = crate::install::ufw::parse(
                &std::fs::read_to_string(&status_path).expect("real ufw status verbose output"),
            )
            .expect("active ufw status");
            for (hook, destination, expected) in [
                ("input", "198.51.100.2", inbound),
                ("output", "203.0.113.2", outbound),
            ] {
                let packet = Packet {
                    hook,
                    uplink: "up0",
                    port: 51820,
                    destination: destination.parse().unwrap(),
                };
                let status_blocked = if hook == "input" {
                    matches!(label, "V-13-default" | "V-13")
                } else {
                    outbound
                };
                assert_eq!(
                    status.may_block(packet),
                    status_blocked,
                    "{} {hook}",
                    status_path.display()
                );
                assert_eq!(
                    super::may_block(
                        &rules,
                        Packet {
                            hook,
                            uplink: "up0",
                            port: 51820,
                            destination: destination.parse().unwrap()
                        }
                    ),
                    expected,
                    "{} {hook}",
                    path.display()
                );
            }
        }
    }
}

#[cfg(test)]
#[path = "firewall/flow_tests.rs"]
mod flow_tests;
