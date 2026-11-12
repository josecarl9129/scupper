//! Availability heuristic for inbound UDP 51820, following input-chain jumps.
use serde_json::Value;

// Unknown predicates can match, but cannot prove an unconditional accept.
fn predicate(expr: &Value, uplink: &str) -> Option<bool> {
    let m = expr.get("match")?;
    let left = &m["left"];
    let right = &m["right"];
    if left["payload"]["protocol"]
        .as_str()
        .is_some_and(|p| matches!(p, "tcp" | "icmp" | "icmpv6"))
    {
        return Some(false);
    }
    let wanted = if left["meta"]["key"] == "iifname" {
        Value::from(uplink)
    } else if left["meta"]["key"] == "l4proto" || left["payload"]["field"] == "protocol" {
        if right.is_number() {
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
        Value::from(51820)
    } else {
        return None;
    };
    let equal = if let Some(set) = right.get("set").and_then(Value::as_array) {
        set.contains(&wanted)
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
        *right == wanted
    } else {
        return None;
    };
    match m["op"].as_str()? {
        "==" | "in" => Some(equal),
        "!=" => Some(!equal),
        _ => None,
    }
}

// Outcomes are possible drop and possible fall-through. An accept terminates
// only this base chain; callers still inspect every other input base chain.
fn chain(
    rows: &[Value],
    family: &Value,
    table: &Value,
    name: &Value,
    uplink: &str,
    depth: usize,
) -> (bool, bool) {
    if depth > rows.len() {
        return (true, true);
    }
    for rule in rows
        .iter()
        .filter_map(|r| r.get("rule"))
        .filter(|r| &r["family"] == family && &r["table"] == table && &r["chain"] == name)
    {
        let Some(exprs) = rule["expr"].as_array() else {
            continue;
        };
        let tests: Vec<_> = exprs
            .iter()
            .filter(|e| e.get("match").is_some())
            .map(|e| predicate(e, uplink))
            .collect();
        if tests.contains(&Some(false)) {
            continue;
        }
        let certain =
            tests.iter().all(|v| *v == Some(true)) && !exprs.iter().any(|e| e.get("xt").is_some());
        for expr in exprs {
            if expr.get("drop").is_some() || expr.get("reject").is_some() {
                return (true, true);
            }
            for verdict in ["jump", "goto"] {
                if let Some(target) = expr.get(verdict).and_then(|v| v.get("target")) {
                    let (drop, returns) = chain(rows, family, table, target, uplink, depth + 1);
                    if drop {
                        return (true, true);
                    }
                    if certain && (!returns || verdict == "goto") {
                        return (false, verdict == "goto" && returns);
                    }
                }
            }
            if certain && expr.get("accept").is_some() {
                return (false, false);
            }
            if certain && expr.get("return").is_some() {
                return (false, true);
            }
        }
    }
    (false, true)
}

pub(super) fn may_block(json: &Value, uplink: &str) -> bool {
    let Some(rows) = json["nftables"].as_array() else {
        return false;
    };
    rows.iter()
        .filter_map(|row| row.get("chain"))
        .filter(|c| {
            c["hook"] == "input" && matches!(c["family"].as_str(), Some("inet" | "ip" | "ip6"))
        })
        .any(|c| {
            let (drop, fallthrough) = chain(rows, &c["family"], &c["table"], &c["name"], uplink, 0);
            drop || (fallthrough && c["policy"] == "drop")
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
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
}
