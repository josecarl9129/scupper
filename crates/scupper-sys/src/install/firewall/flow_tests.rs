use super::{Packet, may_block};
use serde_json::{Value, json};

fn packet(hook: &str) -> Packet<'_> {
    Packet {
        hook,
        uplink: "up0",
        port: if hook == "input" { 51820 } else { 443 },
        destination: "198.51.100.2".parse().unwrap(),
    }
}

fn rules(hook: &str, policy: &str) -> Value {
    json!({"nftables":[{"chain":{
        "family":"ip", "table":"filter", "name":"base", "hook":hook, "policy":policy
    }}]})
}

fn add(rules: &mut Value, chain: &str, expr: Value) {
    let mut row = json!({"rule":{
        "family":"ip", "table":"filter", "chain":chain, "expr":[]
    }});
    row["rule"]["expr"] = expr;
    rules["nftables"].as_array_mut().unwrap().push(row);
}

#[test]
fn jump_returns_on_explicit_return_and_end_then_resumes_in_rule_order() {
    for explicit_return in [false, true] {
        let mut r = rules("input", "drop");
        add(&mut r, "base", json!([{"jump":{"target":"leaf"}}]));
        add(&mut r, "base", json!([{"accept":null}]));
        add(&mut r, "base", json!([{"drop":null}]));
        // An explicit return bypasses this drop; end-of-chain is also a return.
        if explicit_return {
            add(&mut r, "leaf", json!([{"return":null}]));
            add(&mut r, "leaf", json!([{"drop":null}]));
        }
        assert!(!may_block(&r, packet("input")));
    }
}

#[test]
fn goto_returns_to_jump_caller_and_skips_local_rules() {
    for (transfer, blocked) in [("jump", false), ("goto", true)] {
        for leaf in [json!([]), json!([{"return":null}])] {
            let mut r = rules("input", "accept");
            add(&mut r, "base", json!([{"jump":{"target":"first"}}]));
            add(&mut r, "base", json!([{"drop":null}]));
            add(&mut r, "first", json!([{transfer:{"target":"leaf"}}]));
            add(&mut r, "first", json!([{"accept":null}]));
            add(&mut r, "leaf", leaf);
            assert_eq!(may_block(&r, packet("input")), blocked, "{transfer}");
        }
    }
    let mut r = rules("input", "drop");
    add(&mut r, "base", json!([{"goto":{"target":"leaf"}}]));
    add(&mut r, "base", json!([{"accept":null}]));
    assert!(may_block(&r, packet("input")));
}

#[test]
fn definite_nested_accept_ends_base_chain_but_other_base_chains_still_apply() {
    let mut r = rules("input", "drop");
    add(&mut r, "base", json!([{"jump":{"target":"first"}}]));
    add(&mut r, "base", json!([{"drop":null}]));
    add(&mut r, "first", json!([{"jump":{"target":"leaf"}}]));
    add(&mut r, "first", json!([{"reject":null}]));
    add(&mut r, "leaf", json!([{"accept":null}]));
    assert!(!may_block(&r, packet("input")));
    r["nftables"].as_array_mut().unwrap().push(json!({"chain":{
        "family":"inet", "table":"other", "name":"base", "hook":"input", "policy":"drop"
    }}));
    assert!(may_block(&r, packet("input")));
}

#[test]
fn cycles_and_excessive_depth_warn_but_repeated_calls_are_not_cycles() {
    let mut cycle = rules("input", "accept");
    add(&mut cycle, "base", json!([{"jump":{"target":"leaf"}}]));
    add(&mut cycle, "leaf", json!([{"jump":{"target":"base"}}]));
    assert!(may_block(&cycle, packet("input")));

    let mut repeated = rules("input", "drop");
    add(&mut repeated, "base", json!([{"jump":{"target":"leaf"}}]));
    add(&mut repeated, "base", json!([{"jump":{"target":"leaf"}}]));
    add(&mut repeated, "base", json!([{"accept":null}]));
    add(&mut repeated, "leaf", json!([{"return":null}]));
    assert!(!may_block(&repeated, packet("input")));

    for (depth, blocked) in [(14, false), (15, true)] {
        let mut r = rules("input", "accept");
        add(&mut r, "base", json!([{"jump":{"target":"0"}}]));
        for n in 0..depth {
            add(
                &mut r,
                &n.to_string(),
                json!([{"jump":{"target":(n+1).to_string()}}]),
            );
        }
        assert_eq!(may_block(&r, packet("input")), blocked);
    }
}

#[test]
fn unknown_predicates_cannot_hide_drops_or_caller_policy() {
    for unknown in [
        json!({"limit":{"rate":1,"per":"second"}}),
        json!({"xt":null}),
    ] {
        let mut r = rules("input", "drop");
        add(&mut r, "base", json!([{"jump":{"target":"leaf"}}]));
        add(&mut r, "leaf", json!([unknown, {"return":null}]));
        add(&mut r, "leaf", json!([{"accept":null}]));
        assert!(may_block(&r, packet("input")));

        r["nftables"][2]["rule"]["expr"][1] = json!({"accept":null});
        assert!(!may_block(&r, packet("input")));
        r["nftables"][2]["rule"]["expr"][1] = json!({"drop":null});
        assert!(may_block(&r, packet("input")));
    }
}

#[test]
fn unknown_goto_return_preserves_the_possible_caller_drop() {
    let mut r = rules("input", "drop");
    add(&mut r, "base", json!([{"jump":{"target":"first"}}]));
    add(
        &mut r,
        "first",
        json!([{"limit":{"rate":1,"per":"second"}}, {"goto":{"target":"leaf"}}]),
    );
    add(&mut r, "first", json!([{"accept":null}]));
    assert!(may_block(&r, packet("input")));
}

#[test]
fn exit_udp_drop_in_jump_target_checks_endpoint_port_interface_and_new_state() {
    let mut r = rules("output", "accept");
    add(&mut r, "base", json!([{"jump":{"target":"exit-deny"}}]));
    add(
        &mut r,
        "exit-deny",
        json!([
            {"match":{"op":"==","left":{"meta":{"key":"oifname"}},"right":"up0"}},
            {"match":{"op":"==","left":{"ct":{"key":"state"}},"right":"new"}},
            {"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"daddr"}},"right":"198.51.100.2"}},
            {"match":{"op":"==","left":{"payload":{"protocol":"udp","field":"dport"}},"right":443}},
            {"drop":null}
        ]),
    );
    let p = packet("output");
    assert!(may_block(&r, p));
    assert!(!may_block(&r, Packet { port: 51820, ..p }));
    assert!(!may_block(
        &r,
        Packet {
            uplink: "other0",
            ..p
        }
    ));
    assert!(!may_block(
        &r,
        Packet {
            destination: "203.0.113.1".parse().unwrap(),
            ..p
        }
    ));
    r["nftables"][2]["rule"]["expr"][1]["match"]["right"] = json!("invalid");
    assert!(!may_block(&r, p));
}

fn fixture(dump: &str, inbound: bool) {
    let r: Value = serde_json::from_str(dump).unwrap();
    for destination in ["198.51.100.2", "2001:db8::2"] {
        let p = Packet {
            destination: destination.parse().unwrap(),
            ..packet("input")
        };
        assert_eq!(may_block(&r, p), inbound, "input {destination}");
    }
}

#[test]
fn ubuntu_22_04_ufw_default_dump() {
    fixture(
        include_str!("../../../tests/fixtures/firewall/ubuntu-22.04-ufw-default.json"),
        true,
    );
}

#[test]
fn ubuntu_24_04_ufw_default_dump() {
    fixture(
        include_str!("../../../tests/fixtures/firewall/ubuntu-24.04-ufw-default.json"),
        true,
    );
}

// These raw dumps omit xt match arguments. Without ufw status, the walker
// must warn: it cannot evaluate xt to prove the allow rules are reachable.
#[test]
fn ubuntu_22_04_ufw_allow_dump() {
    fixture(
        include_str!("../../../tests/fixtures/firewall/ubuntu-22.04-ufw-allow.json"),
        true,
    );
}

#[test]
fn ubuntu_24_04_ufw_allow_dump() {
    fixture(
        include_str!("../../../tests/fixtures/firewall/ubuntu-24.04-ufw-allow.json"),
        true,
    );
}
