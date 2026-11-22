//! Synthetic until qualification: pure §14 policy, capture and transition evidence.

#![allow(clippy::unwrap_used, clippy::panic)] // Fixture construction must fail loudly.

use proptest::prelude::*;
use scupper_core::mac::{
    lifecycle::{
        ClosingRetry, ConnectionStatus, Durable, Event, Machine, ReferenceEntry, ReferenceIntent,
        ReferenceSettlement, Step, TunnelHealth,
    },
    parse::{self, Rule},
    policy::{self, Direction, Form, State},
    verify::{
        self, Action, AnchorObservation, Baseline, Context, Expected, IdentityEvidence, LiveTree,
        Normalization, Observations, Qualification, Reason, SelectedPath, SleepCountingClock,
        StateEvidence, StepOutcome, ToolIntegrity, Transport, Verdict,
    },
    *,
};
use std::collections::{BTreeMap, BTreeSet};
#[derive(Clone, Copy)]
struct Clock(u64);
impl SleepCountingClock for Clock {
    fn now(&self) -> u64 {
        self.0
    }
}
// Legacy fixtures execute effects at 99 and publish full rounds at their proof time.
// Time-advancing regressions below call the clock-taking API directly.
trait FixtureTransition {
    fn fixture_transition(&self, event: Event) -> Result<Machine, Error>;
}
impl FixtureTransition for Machine {
    fn fixture_transition(&self, event: Event) -> Result<Machine, Error> {
        let now = match &event {
            Event::Observed {
                verdict: Verdict::Protected(p),
                ..
            } => p.completed_at(),
            Event::StatesClean { completed_at, .. }
            | Event::InterfaceStatesRemoved { completed_at, .. } => *completed_at,
            _ => 99,
        };
        self.transition(event, &Clock(now))
    }
}
const PRE: &str = include_str!("../../../tests/golden/mac/pre-bound.pf");
const JOINED: &str = include_str!("../../../tests/golden/mac/joined-bound.pf");
const MAIN: &str = include_str!("fixtures/mac/main.pf");
fn tunnel(generation: u64) -> Tunnel {
    Tunnel {
        name: "utun6".parse().unwrap(),
        generation: TunnelGeneration::new(generation).unwrap(),
    }
}
fn inputs(acquiring: bool, additional: bool) -> Inputs {
    let phase = if acquiring {
        DhcpPhase::AcquiringRebinding
    } else {
        DhcpPhase::Bound {
            server: "192.0.2.1".parse().unwrap(),
        }
    };
    let mut physical = BTreeMap::from([("en0".parse().unwrap(), phase)]);
    if additional {
        physical.insert("en7".parse().unwrap(), DhcpPhase::AcquiringRebinding);
    }
    Inputs::new(
        "en0".parse().unwrap(),
        "198.51.100.7:51820".parse().unwrap(),
        physical,
        tunnel(1),
        HopLimitPolicy::QualifiedLimitation,
    )
    .unwrap()
}
fn normalization() -> Normalization {
    Normalization {
        expanded_lists: true,
        named_icmp: true,
        implicit_tcp_flags: true,
    }
}
fn setup(form: Form) -> (Observations, Expected) {
    let inputs = inputs(false, false);
    let text = if form == Form::Joined { JOINED } else { PRE };
    let main = parse::pf_rules(MAIN).unwrap();
    let qualification = Qualification {
        os_build: "synthetic-until-qualification".into(),
        main: main.clone(),
        main_translation: parse::translation(include_str!("fixtures/mac/main-nat.txt")).unwrap(),
        siblings: BTreeMap::from([
            ("com.apple".into(), parse::pf_rules("").unwrap()),
            (
                "com.apple/100.synthetic".into(),
                parse::pf_rules("").unwrap(),
            ),
        ]),
        anchor_translation: ["com.apple", "com.apple/100.synthetic"]
            .into_iter()
            .map(|n| (n.into(), parse::translation("").unwrap()))
            .collect(),
        physical: inputs.physical().keys().cloned().collect(),
        normalization: normalization(),
        hop_limit: HopLimitPolicy::QualifiedLimitation,
    };
    let tree = LiveTree {
        before: parse::anchor_list(include_str!("fixtures/mac/anchors.txt")).unwrap(),
        after: parse::anchor_list(include_str!("fixtures/mac/anchors.txt")).unwrap(),
        complete: true,
        anchors: ["com.apple", "com.apple/100.synthetic", "com.apple/scupper"]
            .into_iter()
            .map(|name| {
                (
                    name.into(),
                    AnchorObservation {
                        rules: parse::pf_rules(if name == "com.apple/scupper" {
                            text
                        } else {
                            ""
                        }),
                        translation: parse::translation(""),
                    },
                )
            })
            .collect(),
    };
    let observations = Observations {
        started_at: verify::required_reads(&tree)
            .into_iter()
            .map(|k| (k, 100))
            .collect(),
        states: StateEvidence::Clean {
            epoch: 0,
            completed_at: 99,
        },
        os_build: qualification.os_build.clone(),
        pf: parse::pf_info(include_str!("fixtures/mac/pf-info.txt")),
        anchor: Ok(Some(parse::pf_rules(text).unwrap())),
        main: Ok(main),
        translation: Ok(qualification.main_translation.clone()),
        live_tree: Ok(tree),
        interfaces: parse::ifconfig_list(include_str!("fixtures/mac/ifconfig-list.txt")),
        skips: parse::pf_interfaces(include_str!("fixtures/mac/interfaces.txt")),
        dns: parse::dns(include_str!("fixtures/mac/dns.txt")),
        local_address: Ok("192.0.2.2".parse().unwrap()),
        route: parse::route(include_str!("fixtures/mac/route.txt")),
        policy_inputs: Ok(inputs.clone()),
        identity: IdentityEvidence::CurrentGeneration(tunnel(1)),
        selected_path: SelectedPath::Selected,
        tool_integrity: ToolIntegrity::Match,
        external_hop_limit_verified: false,
        step: StepOutcome::Complete,
    };
    let expected = Expected {
        context: Context::default(),
        baseline: verify::capture_baseline(text, &inputs, form, &normalization()).unwrap(),
        inputs,
        transport: Transport {
            local_address: "192.0.2.2".parse().unwrap(),
            endpoint_route: observations.route.clone().unwrap(),
        },
        form,
        qualification,
        max_age: 5,
        join_intended: true,
    };
    (observations, expected)
}
#[test]
fn validated_tokens_reject_pf_injection_and_invalid_values() {
    for bad in [
        "",
        "en0\npass",
        "en 0",
        "en0\t",
        "en0{",
        "en0}",
        "en0\"",
        "en0'",
        "en0;",
        "en0\\",
        "en0#",
        "en0\r",
        "en0\0",
        "en123456789012345",
        "é0",
    ] {
        assert!(bad.parse::<Interface>().is_err(), "{bad:?}");
        assert!(bad.parse::<PhysicalInterface>().is_err());
        assert!(bad.parse::<Utun>().is_err());
    }
    for bad in ["awdl0", "llw0", "ap1", "bridge100", "anpi0", "utun6", "lo0"] {
        assert!(bad.parse::<PhysicalInterface>().is_err());
    }
    assert!("utun6".parse::<Utun>().is_ok());
    for bad in ["utun", "en0", "utun-1", "utun1x"] {
        assert!(bad.parse::<Utun>().is_err());
    }
    for bad in [
        "host:51820",
        "[::1]:51820",
        "198.51.100.7:0",
        "198.51.100.7:65536",
        "198.51.100.7:+1",
        "198.51.100.7:22\n",
        "198.51.100.7: 22",
        "0.0.0.0:5",
        "255.255.255.255:5",
        "224.0.0.1:5",
    ] {
        assert!(bad.parse::<Endpoint>().is_err(), "{bad}");
    }
    for bad in [
        "192.0.2.1\n",
        "192.0.2.1 ",
        "{192.0.2.1}",
        "0.0.0.0",
        "255.255.255.255",
        "::1",
    ] {
        assert!(bad.parse::<LeaseServer>().is_err());
    }
    assert!(TunnelGeneration::new(0).is_err());
    assert!(
        Inputs::new(
            "en1".parse().unwrap(),
            "198.51.100.7:1".parse().unwrap(),
            BTreeMap::new(),
            tunnel(1),
            HopLimitPolicy::External255
        )
        .is_err()
    );
}
#[test]
fn section14_goldens_all_forms_and_dhcp_phases() {
    for (acquiring, pre, joined) in [
        (false, PRE, JOINED),
        (
            true,
            include_str!("../../../tests/golden/mac/pre-acquiring.pf"),
            include_str!("../../../tests/golden/mac/joined-acquiring.pf"),
        ),
    ] {
        let inputs = inputs(acquiring, false);
        assert_eq!(policy::render_pre_tunnel(&inputs).as_str(), pre);
        assert_eq!(policy::render_joined(&inputs).as_str(), joined);
    }
    let mixed = policy::render_joined(&inputs(false, true));
    assert!(
        mixed
            .as_str()
            .contains("on en7 inet proto udp from any port 68 to 255.255.255.255 port 67 no state")
    );
    assert!(
        mixed
            .as_str()
            .contains("on en0 inet proto udp from any port 68 to 192.0.2.1 port 67 no state")
    );
    assert_eq!(
        mixed
            .as_str()
            .lines()
            .filter(|line| line.contains("on en7"))
            .count(),
        2
    );
}
#[test]
fn policy_table_is_exact_nd_and_bounded_underlay() {
    let inputs = inputs(false, true);
    let table = policy::policy_table(policy::Policy::Installed(&inputs, Form::Joined));
    assert_eq!(table.len(), 17); // lo + 2 utun + 2 endpoint + 4 DHCP + 8 ND
    let nd: Vec<_> = table.iter().filter(|r| r.icmp6_type.is_some()).collect();
    assert_eq!(nd.len(), 8);
    assert_eq!(nd.iter().filter(|r| r.sources == ["::"]).count(), 2);
    for row in &nd {
        assert_eq!(row.interface.as_deref(), Some("en0"));
        assert_eq!(row.state, State::None);
        if row.sources == ["::"] {
            assert_eq!(row.destinations, ["ff02::1:ff00:0/104"]);
            assert_eq!(row.icmp6_type, Some(135));
        }
    }
    let endpoint: Vec<_> = table
        .iter()
        .filter(|r| r.state == State::IfBound && r.interface.as_deref() == Some("en0"))
        .collect();
    assert_eq!(endpoint.len(), 2);
    for row in endpoint {
        assert_eq!(row.direction, Direction::Out);
        assert_eq!(row.destinations, ["198.51.100.7"]);
        assert_eq!(row.family.as_deref(), Some("inet"));
        assert!(matches!(row.destination_port, Some(22 | 51820)));
    }
}
#[test]
fn realistic_synthetic_captures_preserve_order_and_absence() {
    let (o, _) = setup(Form::Joined);
    assert_eq!(o.pf.unwrap(), parse::PfInfo { enabled: true });
    let dns = o.dns.unwrap();
    assert_eq!(dns.len(), 3);
    assert_eq!(dns[0].order, Some(100_000));
    assert_eq!(dns[1].order, Some(300_000));
    assert_eq!(dns[2].order, Some(200_000));
    assert!(dns[2].section.contains("scoped"));
    assert_eq!(o.route.unwrap().interface.to_string(), "en0");
    let route = parse::route("route to: 198.51.100.7\ninterface: en0\n").unwrap();
    assert_eq!(route.gateway, None);
    let route = parse::route("route to: 198.51.100.7\ngateway: link#6\ninterface: en0\n").unwrap();
    assert_eq!(route.link_gateway.as_deref(), Some("link#6"));
    let rules = parse::pf_rules(
        "anchor \"com.apple/100.first\" all\nanchor \"com.apple/200.second\" all\n",
    )
    .unwrap();
    assert!(matches!(&rules.rules()[0], Rule::Anchor {name, ..} if name.ends_with("first")));
    assert!(matches!(&rules.rules()[1], Rule::Anchor {name, ..} if name.ends_with("second")));
    assert!(!parse::pf_info("Status: Disabled\n").unwrap().enabled);
    assert!(parse::pf_info("Status: Enabled\n").unwrap().enabled);
}
#[test]
fn runner_disabled_info_counters_cannot_supply_status_evidence() {
    for text in [
        include_str!("fixtures/mac/pf-info-disabled-24H232.txt"),
        include_str!("fixtures/mac/pf-info-disabled-25G332.txt"),
    ] {
        assert!(!parse::pf_info(text).unwrap().enabled);
        assert!(parse::pf_info(&text.replace("Status: Disabled", "Status: Enabled")).is_err());
        assert!(parse::pf_info(&text.replace("dummynet", "unknown-counter")).is_err());
        assert!(parse::pf_info(text.split_once('\n').unwrap().1).is_err());
    }
}
#[test]
fn source_derived_disabled_info_accepts_only_documented_debug_suffix() {
    assert!(
        !parse::pf_info(include_str!("fixtures/mac/pf-info-disabled-source.txt"))
            .unwrap()
            .enabled
    );
    for level in ["None", "Urgent", "Misc", "Loud"] {
        assert!(
            !parse::pf_info(&format!("Status: Disabled        Debug: {level}\n"))
                .unwrap()
                .enabled
        );
    }
    for text in [
        "Status: Disabled Debug:",
        "Status: Disabled Debug: unknown",
        "Status: Disabled Debug: Urgent extra",
        "Status: Disabled unknown Debug: Urgent",
        "Status: Enabled Debug: Urgent",
    ] {
        assert!(
            parse::pf_info(text).is_err(),
            "assertion: accepted invalid pf info: {text}"
        );
    }
}
#[test]
fn unparseable_is_never_a_default() {
    for text in [
        "",
        "garbage",
        "Status: Maybe",
        "Status: Enabled garbage",
        "Status: Enabled\nStatus: Disabled",
        "Token: 1",
        "Status: Enabled\nToken: -1",
        "Status: Enabled\nnew unknown field",
    ] {
        assert!(parse::pf_info(text).is_err(), "{text}");
    }
    for text in [
        "pass",
        "pass quick all keep state",
        "anchor unquoted",
        "mystery all",
        "pass on en0 from any to",
        "pass on en0 from { any, } to any",
        "pass on en0 from any to any port 65536",
    ] {
        assert!(parse::pf_rules(text).is_err(), "{text}");
    }
    for text in ["", "en0 en0", "lo0 en0;pass", "lo0 { en0 }"] {
        assert!(parse::ifconfig_list(text).is_err());
    }
    for text in ["", "en0 ()", "en0 (mystery)", "en0 (skip", "en0\nen0"] {
        assert!(parse::pf_interfaces(text).is_err());
    }
    for text in [
        "",
        "resolver #1",
        "DNS configuration\nresolver #1\nunknown: 2",
        "DNS configuration\nresolver #1\nnameserver[0]: host",
        "DNS configuration\nresolver #1\norder: -1",
        "DNS configuration\nresolver #1\norder: 1\norder: 2",
    ] {
        assert!(parse::dns(text).is_err());
    }
    for text in [
        "",
        "interface: en0",
        "route to: host\ninterface: en0",
        "route to: 198.51.100.7\ngateway: host\ninterface: en0",
        "route to: 198.51.100.7\ninterface: en0\ninterface: utun6",
        "route to: 198.51.100.7\ninterface: en0\nnew_field: safe",
    ] {
        assert!(parse::route(text).is_err());
    }
    assert!(parse::ifconfig_list(&"a".repeat(1_048_577)).is_err());
}
#[test]
fn normalized_baseline_uses_reviewed_readback_and_cannot_bless_drift() {
    let (mut o, mut e) = setup(Form::Joined);
    let transformed = JOINED
        .replace("icmp6-type 133", "icmp6-type routersol")
        .replace("icmp6-type 134", "icmp6-type routeradv")
        .replace("icmp6-type 135", "icmp6-type neighbrsol")
        .replace("icmp6-type 136", "icmp6-type neighbradv")
        .replace("port 22 keep", "port = 22 flags S/SA keep")
        .replace("all keep state", "all flags S/SA keep state");
    let parsed = parse::pf_rules(&transformed).unwrap();
    e.baseline = Baseline::capture(&parsed, &e.inputs, e.form, &normalization()).unwrap();
    assert_ne!(e.baseline.text(), JOINED);
    o.live_tree
        .as_mut()
        .unwrap()
        .anchors
        .get_mut("com.apple/scupper")
        .unwrap()
        .rules = Ok(parsed.clone());
    o.anchor = Ok(Some(parsed));
    assert_protected(&o, &e, 102);
    // Semantically equal but unexplained spelling changes do not refresh the baseline.
    o.anchor = Ok(Some(parse::pf_rules(JOINED).unwrap()));
    assert_eq!(
        verify::verify(&o, &e, &Clock(102)),
        Verdict::Repair(Action::Rejoin)
    );
    let strict = Normalization {
        expanded_lists: false,
        named_icmp: false,
        implicit_tcp_flags: false,
    };
    assert!(verify::capture_baseline(&transformed, &e.inputs, e.form, &strict).is_err());
    for drift in [
        JOINED.replace("port 22", "port 23"),
        JOINED.replace("if-bound", "floating"),
        JOINED.replace("198.51.100.7", "0.0.0.0/0"),
    ] {
        assert!(verify::capture_baseline(&drift, &e.inputs, e.form, &normalization()).is_err());
    }
    let expanded = JOINED.replace("to { fe80::/10, ff02::1 } icmp6-type 134", "to fe80::/10 icmp6-type 134 no state\npass in quick on en0 inet6 proto ipv6-icmp from fe80::/10 to ff02::1 icmp6-type 134");
    assert!(verify::capture_baseline(&expanded, &e.inputs, e.form, &normalization()).is_ok());
    assert!(verify::capture_baseline(&expanded, &e.inputs, e.form, &strict).is_err());
}
#[test]
#[allow(clippy::too_many_lines)] // Keep the complete DESIGN verdict table together.
fn verifier_section14_table_and_failure_mutations() {
    type Mutation = fn(&mut Observations);
    let cases: Vec<(&str, Mutation, Verdict)> = vec![
        (
            "fresh complete",
            |_| {},
            verify::verify(&setup(Form::Joined).0, &setup(Form::Joined).1, &Clock(102)),
        ),
        (
            "anchor missing",
            |o| o.anchor = Ok(None),
            Verdict::Repair(Action::Rejoin),
        ),
        (
            "anchor changed",
            |o| o.anchor = Ok(Some(parse::pf_rules(PRE).unwrap())),
            Verdict::Repair(Action::Rejoin),
        ),
        (
            "pf disabled",
            |o| o.pf.as_mut().unwrap().enabled = false,
            Verdict::Repair(Action::EnableAndRejoin),
        ),
        (
            "hook missing",
            |o| o.main = parse::pf_rules(""),
            Verdict::NotProtected(Reason::HookMissing),
        ),
        (
            "earlier quick",
            |o| o.main = parse::pf_rules(&format!("pass quick all\n{MAIN}")),
            Verdict::NotProtected(Reason::QuickPass),
        ),
        (
            "sibling quick",
            |o| {
                o.live_tree
                    .as_mut()
                    .unwrap()
                    .anchors
                    .get_mut("com.apple/100.synthetic")
                    .unwrap()
                    .rules = parse::pf_rules("pass quick all");
            },
            Verdict::NotProtected(Reason::QuickPass),
        ),
        (
            "skip bridge",
            |o| {
                o.skips
                    .as_mut()
                    .unwrap()
                    .insert("bridge100".parse().unwrap(), true);
            },
            Verdict::NotProtected(Reason::Skip("bridge100".parse().unwrap())),
        ),
        (
            "OS unknown",
            |o| o.os_build = "unknown".into(),
            Verdict::NotProtected(Reason::Unsupported("unqualified OS build")),
        ),
        (
            "unsupported",
            |o| o.main = parse::pf_rules(&format!("table <x> persist\n{MAIN}")),
            Verdict::NotProtected(Reason::Unsupported("construct before required hook")),
        ),
        (
            "parse failure",
            |o| o.anchor = Err(Error("read-back parse failed")),
            Verdict::NotProtected(Reason::Observation("read-back parse failed")),
        ),
        (
            "failed step",
            |o| o.step = StepOutcome::Failed("step failed"),
            Verdict::NotProtected(Reason::Observation("step failed")),
        ),
        (
            "hung step",
            |o| o.step = StepOutcome::Failed("deadline exceeded"),
            Verdict::NotProtected(Reason::Observation("deadline exceeded")),
        ),
        (
            "child death/restart",
            |o| o.identity = IdentityEvidence::LostOrStale,
            Verdict::Repair(Action::RecreateChild),
        ),
        (
            "wrong generation",
            |o| o.identity = IdentityEvidence::CurrentGeneration(tunnel(2)),
            Verdict::Repair(Action::RecreateChild),
        ),
        (
            "wrong utun",
            |o| {
                let mut t = tunnel(1);
                t.name = "utun7".parse().unwrap();
                o.identity = IdentityEvidence::CurrentGeneration(t);
            },
            Verdict::Repair(Action::RecreateChild),
        ),
        (
            "5a2 unresolved",
            |o| o.identity = IdentityEvidence::Unresolved5a2,
            Verdict::NotProtected(Reason::Unsupported("5a2 tunnel identity proof unresolved")),
        ),
        (
            "route recursion",
            |o| o.route.as_mut().unwrap().interface = "utun6".parse().unwrap(),
            Verdict::NotProtected(Reason::RouteRecursion),
        ),
        (
            "missing gateway",
            |o| o.route.as_mut().unwrap().gateway = None,
            Verdict::NotProtected(Reason::MissingGateway),
        ),
        (
            "ambiguous path",
            |o| o.selected_path = SelectedPath::Ambiguous,
            Verdict::NotProtected(Reason::AmbiguousPath),
        ),
        (
            "tool mismatch",
            |o| o.tool_integrity = ToolIntegrity::Mismatch,
            Verdict::NotProtected(Reason::ToolIntegrity),
        ),
        (
            "stale",
            |o| o.started_at.values_mut().for_each(|t| *t = 90),
            Verdict::Unknown { since: 95 },
        ),
        (
            "helper unavailable",
            |o| {
                o.started_at.values_mut().for_each(|t| *t = 90);
                o.step = StepOutcome::Unavailable;
            },
            Verdict::Unknown { since: 90 },
        ),
    ];
    let (base, expected) = setup(Form::Joined);
    for (name, mutation, verdict) in cases {
        let mut changed = base.clone();
        mutation(&mut changed);
        assert_eq!(
            verify::verify(&changed, &expected, &Clock(102)),
            verdict,
            "{name}"
        );
        if name != "fresh complete" {
            assert_ne!(
                verify::verify(&changed, &expected, &Clock(102)),
                verify::verify(&base, &expected, &Clock(102)),
                "inactive verifier guard: {name}"
            );
        }
    }
    assert!(matches!(
        verify::verify(&base, &expected, &Clock(105)),
        Verdict::Protected(_)
    ));
    assert_eq!(
        verify::verify(&base, &expected, &Clock(106)),
        Verdict::Unknown { since: 105 }
    );
}
#[test]
fn each_anchor_row_removed_or_widened_changes_verdict_and_fails_capture() {
    let (mut o, e) = setup(Form::Joined);
    let lines: Vec<_> = JOINED.lines().collect();
    for index in 0..lines.len() {
        let removed = lines
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != index)
            .map(|(_, l)| *l)
            .collect::<Vec<_>>()
            .join("\n");
        o.anchor = Ok(Some(parse::pf_rules(&removed).unwrap()));
        assert_eq!(
            verify::verify(&o, &e, &Clock(102)),
            Verdict::Repair(Action::Rejoin),
            "removed {index}"
        );
        assert!(verify::capture_baseline(&removed, &e.inputs, e.form, &normalization()).is_err());
        let mut flipped = lines.clone();
        let wider = if lines[index].starts_with("pass") {
            lines[index].replace("quick on", "on")
        } else {
            "block drop all".into()
        };
        flipped[index] = &wider;
        let flipped = flipped.join("\n");
        o.anchor = Ok(Some(parse::pf_rules(&flipped).unwrap()));
        assert_eq!(
            verify::verify(&o, &e, &Clock(102)),
            Verdict::Repair(Action::Rejoin),
            "flipped {index}"
        );
        assert!(verify::capture_baseline(&flipped, &e.inputs, e.form, &normalization()).is_err());
    }
}
#[test]
fn walker_refuses_unsupported_constructs_unknown_anchors_and_inventory_gaps() {
    let (o, e) = setup(Form::Joined);
    for prefix in [
        "table <x> persist",
        "pass out quick on en0 route-to (en0 192.0.2.1) all",
        "anchor \"other/unknown\" all",
        "scrub-anchor \"com.apple/*\" all",
    ] {
        let rules = parse::pf_rules(&format!("{prefix}\n{MAIN}")).unwrap();
        assert!(
            verify::walk_path(
                &rules,
                o.translation.as_ref().unwrap(),
                o.live_tree.as_ref().unwrap(),
                o.interfaces.as_ref().unwrap(),
                o.skips.as_ref().unwrap(),
                &e.qualification
            )
            .is_err(),
            "{prefix}"
        );
    }
    let mut gaps = o.clone();
    gaps.skips
        .as_mut()
        .unwrap()
        .remove(&"vmnet1".parse().unwrap());
    assert!(matches!(
        verify::verify(&gaps, &e, &Clock(102)),
        Verdict::Unknown { .. }
    ));
    gaps = o.clone();
    gaps.live_tree
        .as_mut()
        .unwrap()
        .anchors
        .remove("com.apple/100.synthetic");
    assert!(matches!(
        verify::verify(&gaps, &e, &Clock(102)),
        Verdict::NotProtected(_)
    ));
    gaps = o.clone();
    gaps.live_tree.as_mut().unwrap().complete = false;
    assert!(matches!(
        verify::verify(&gaps, &e, &Clock(102)),
        Verdict::NotProtected(_)
    ));
    // Stock-name trust and even an explicitly recorded matching sibling are refused.
    gaps = o;
    gaps.live_tree
        .as_mut()
        .unwrap()
        .anchors
        .get_mut("com.apple/100.synthetic")
        .unwrap()
        .rules = parse::pf_rules("pass all");
    let mut e = e;
    e.qualification.siblings.insert(
        "com.apple/100.synthetic".into(),
        parse::pf_rules("pass all").unwrap(),
    );
    assert!(matches!(
        verify::verify(&gaps, &e, &Clock(102)),
        Verdict::NotProtected(_)
    ));
}
#[test]
fn multiple_leases_are_valid_pre_tunnel_and_health_is_not_an_input() {
    let (mut o, mut e) = setup(Form::PreTunnel);
    let mut physical = e.inputs.physical().clone();
    physical.insert(
        "en7".parse().unwrap(),
        DhcpPhase::Bound {
            server: "192.0.2.2".parse().unwrap(),
        },
    );
    e.inputs = Inputs::new(
        "en0".parse().unwrap(),
        e.inputs.endpoint().clone(),
        physical,
        tunnel(1),
        HopLimitPolicy::QualifiedLimitation,
    )
    .unwrap();
    e.qualification.physical = e.inputs.physical().keys().cloned().collect();
    let text = policy::render_pre_tunnel(&e.inputs);
    e.baseline =
        verify::capture_baseline(text.as_str(), &e.inputs, e.form, &normalization()).unwrap();
    o.policy_inputs = Ok(e.inputs.clone());
    o.anchor = Ok(Some(parse::pf_rules(text.as_str()).unwrap()));
    o.live_tree
        .as_mut()
        .unwrap()
        .anchors
        .get_mut("com.apple/scupper")
        .unwrap()
        .rules = parse::pf_rules(text.as_str());
    o.identity = IdentityEvidence::LostOrStale;
    assert_protected(&o, &e, 102);
}
proptest! {
    #[test]
    fn rendering_never_exceeds_the_allow_table(n in 0u16..999, acquiring in any::<bool>(), joined in any::<bool>(), extra in any::<bool>(), port in 1u16..=65535) {
        let selected:PhysicalInterface=format!("en{n}").parse().unwrap();
        let phase=if acquiring {DhcpPhase::AcquiringRebinding} else {DhcpPhase::Bound {server:"192.0.2.1".parse().unwrap()}};
        let mut physical=BTreeMap::from([(selected.clone(),phase)]);
        if extra {physical.insert("en1000".parse().unwrap(),DhcpPhase::AcquiringRebinding);}
        let i=Inputs::new(selected,format!("198.51.100.7:{port}").parse().unwrap(),physical,tunnel(1),HopLimitPolicy::QualifiedLimitation).unwrap();
        let form=if joined {Form::Joined} else {Form::PreTunnel};
        let text=if joined {policy::render_joined(&i)} else {policy::render_pre_tunnel(&i)};
        let parsed=parse::pf_rules(text.as_str()).unwrap();
        let independent = independent_policy(&i, form);
        let literal = parse::pf_rules(&independent).unwrap();
        let table: Vec<_> = literal.rules().iter().filter_map(|r| if let Rule::Pass(p) = r {Some(p.clone())} else {None}).collect();
        let expected:Vec<_>=table.iter().flat_map(policy::Pass::expanded).collect();
        let mut actual=Vec::new();
        for rule in parsed.rules() {
            if let Rule::Pass(row)=rule {
                let name=row.interface.as_deref().unwrap();
                prop_assert!(name=="lo0" || (joined && name=="utun6") || i.physical().keys().any(|p| p.to_string()==name));
                prop_assert!(row.quick && row.state!=State::Implicit);
                for expanded in row.expanded() {prop_assert!(expected.contains(&expanded));actual.push(expanded);}
            }
        }
        prop_assert_eq!(actual,expected);
        prop_assert_eq!(parsed.rules().last(),Some(&Rule::Block {quick:true}));
    }
}

#[test]
fn every_capture_failure_precludes_protection_even_when_stale() {
    type Mutation = fn(&mut Observations);
    let mutations: Vec<Mutation> = vec![
        |o| o.pf = Err(Error("pf info")),
        |o| o.anchor = Err(Error("anchor")),
        |o| o.main = Err(Error("main")),
        |o| o.live_tree = Err(Error("tree")),
        |o| o.translation = Err(Error("nat")),
        |o| o.interfaces = Err(Error("interfaces")),
        |o| o.skips = Err(Error("skips")),
        |o| o.dns = Err(Error("dns")),
        |o| o.route = Err(Error("route")),
        |o| o.local_address = Err(Error("selected local address")),
        |o| o.policy_inputs = Err(Error("lease/server/T1/T2")),
    ];
    let (base, e) = setup(Form::Joined);
    for mutation in mutations {
        let mut o = base.clone();
        mutation(&mut o);
        assert!(matches!(
            verify::verify(&o, &e, &Clock(102)),
            Verdict::NotProtected(_)
        ));
        assert!(matches!(
            verify::verify(&o, &e, &Clock(200)),
            Verdict::NotProtected(_)
        ));
    }
    let mut bypass_and_disabled = base;
    bypass_and_disabled.pf.as_mut().unwrap().enabled = false;
    bypass_and_disabled.main = parse::pf_rules("");
    assert_eq!(
        verify::verify(&bypass_and_disabled, &e, &Clock(200)),
        Verdict::NotProtected(Reason::HookMissing)
    );
    assert_eq!(
        Reason::HookMissing.to_string(),
        "Required pf hook missing; responsible process unknown"
    );
}

#[test]
fn qualification_and_generation_inputs_cannot_be_silently_defaulted() {
    let (mut o, mut e) = setup(Form::Joined);
    o.tool_integrity = ToolIntegrity::PendingAfterEnforcement;
    assert_eq!(
        verify::verify(&o, &e, &Clock(102)),
        Verdict::NotProtected(Reason::Observation("tool integrity unverified"))
    );
    let (mut pre, pre_expected) = setup(Form::PreTunnel);
    pre.tool_integrity = ToolIntegrity::PendingAfterEnforcement;
    assert_protected(&pre, &pre_expected, 102);
    o.tool_integrity = ToolIntegrity::Match;
    e.qualification.normalization.named_icmp = false;
    assert!(matches!(
        verify::verify(&o, &e, &Clock(102)),
        Verdict::NotProtected(_)
    ));
    e.qualification.normalization = normalization();
    e.qualification.physical.clear();
    assert_eq!(
        verify::verify(&o, &e, &Clock(102)),
        Verdict::NotProtected(Reason::Unsupported("unqualified physical service"))
    );
    for invalid in ["0", "-1", " 1", "1\n", "1{", "1\"", "18446744073709551616"] {
        assert!(invalid.parse::<TunnelGeneration>().is_err());
    }
    let (mut o, mut e) = setup(Form::PreTunnel);
    e.inputs = Inputs::new(
        e.inputs.selected().clone(),
        e.inputs.endpoint().clone(),
        e.inputs.physical().clone(),
        tunnel(1),
        HopLimitPolicy::External255,
    )
    .unwrap();
    e.qualification.hop_limit = HopLimitPolicy::External255;
    e.baseline = verify::capture_baseline(PRE, &e.inputs, e.form, &normalization()).unwrap();
    o.policy_inputs = Ok(e.inputs.clone());
    assert_eq!(
        verify::verify(&o, &e, &Clock(102)),
        Verdict::NotProtected(Reason::Observation("ND hop-limit enforcement unverified"))
    );
    o.external_hop_limit_verified = true;
    assert_protected(&o, &e, 102);
    o.started_at.insert("main".into(), 103);
    assert!(matches!(
        verify::verify(&o, &e, &Clock(102)),
        Verdict::NotProtected(_)
    ));
}

#[test]
fn synthetic_pfctl_normalization_fixture_is_semantically_checked_before_storage() {
    let (mut o, mut e) = setup(Form::Joined);
    let captured = include_str!("fixtures/mac/joined-readback.pf");
    let parsed = parse::pf_rules(captured).unwrap();
    e.baseline = Baseline::capture(&parsed, &e.inputs, e.form, &normalization()).unwrap();
    assert_ne!(e.baseline.text(), JOINED);
    o.live_tree
        .as_mut()
        .unwrap()
        .anchors
        .get_mut("com.apple/scupper")
        .unwrap()
        .rules = Ok(parsed.clone());
    o.anchor = Ok(Some(parsed));
    assert_protected(&o, &e, 102);
    let strict = Normalization {
        expanded_lists: false,
        named_icmp: false,
        implicit_tcp_flags: false,
    };
    assert!(verify::capture_baseline(captured, &e.inputs, e.form, &strict).is_err());
}

fn assert_protected(o: &Observations, e: &Expected, now: u64) {
    let Verdict::Protected(proof) = verify::verify(o, e, &Clock(now)) else {
        panic!(
            "expected protection: {:?}",
            verify::verify(o, e, &Clock(now))
        );
    };
    assert_eq!(proof.verified_at(), *o.started_at.values().min().unwrap());
    assert_eq!(proof.completed_at(), now);
    assert_eq!(proof.context(), e.context);
    assert_eq!(proof.form(), e.form);
    assert_eq!(proof.tunnel(), Some(e.inputs.tunnel()));
    assert_eq!(proof.baseline_hash(), e.baseline.hash());
}

// Independent transcription of §14. This never calls policy_table or a renderer.
fn independent_policy(i: &Inputs, form: Form) -> String {
    let mut rows = vec!["pass quick on lo0 all no state".to_owned()];
    if form == Form::Joined {
        rows.extend([
            format!(
                "pass out quick on {} all keep state (if-bound)",
                i.tunnel().name
            ),
            format!(
                "pass in quick on {} all keep state (if-bound)",
                i.tunnel().name
            ),
        ]);
    }
    rows.push(format!(
        "pass out quick on {} inet proto udp from any to {} port {} keep state (if-bound)",
        i.selected(),
        i.endpoint().address(),
        i.endpoint().port()
    ));
    rows.push(format!(
        "pass out quick on {} inet proto tcp from any to {} port 22 keep state (if-bound)",
        i.selected(),
        i.endpoint().address()
    ));
    for (name, phase) in i.physical() {
        let (src, dst) = match phase {
            DhcpPhase::Bound { server } => (server.to_string(), server.to_string()),
            DhcpPhase::AcquiringRebinding => ("any".into(), "255.255.255.255".into()),
        };
        rows.push(format!(
            "pass out quick on {name} inet proto udp from any port 68 to {dst} port 67 no state"
        ));
        rows.push(format!(
            "pass in quick on {name} inet proto udp from {src} port 67 to any port 68 no state"
        ));
    }
    for literal in [
        "pass out quick on {if} inet6 proto ipv6-icmp from fe80::/10 to ff02::2 icmp6-type 133 no state",
        "pass in quick on {if} inet6 proto ipv6-icmp from fe80::/10 to { fe80::/10, ff02::1 } icmp6-type 134 no state",
        "pass out quick on {if} inet6 proto ipv6-icmp from fe80::/10 to { fe80::/10, ff02::1:ff00:0/104 } icmp6-type 135 no state",
        "pass in quick on {if} inet6 proto ipv6-icmp from fe80::/10 to { fe80::/10, ff02::1:ff00:0/104 } icmp6-type 135 no state",
        "pass out quick on {if} inet6 proto ipv6-icmp from fe80::/10 to { fe80::/10, ff02::1 } icmp6-type 136 no state",
        "pass in quick on {if} inet6 proto ipv6-icmp from fe80::/10 to { fe80::/10, ff02::1 } icmp6-type 136 no state",
        "pass out quick on {if} inet6 proto ipv6-icmp from :: to ff02::1:ff00:0/104 icmp6-type 135 no state",
        "pass in quick on {if} inet6 proto ipv6-icmp from :: to ff02::1:ff00:0/104 icmp6-type 135 no state",
    ] {
        rows.push(literal.replace("{if}", &i.selected().to_string()));
    }
    rows.push("block drop quick all".into());
    rows.join("\n") + "\n"
}

#[test]
fn widening_every_applicable_dimension_of_every_pass_fails_capture() {
    for form in [Form::PreTunnel, Form::Joined] {
        for acquiring in [true, false] {
            let i = inputs(acquiring, true);
            let source = independent_policy(&i, form);
            let lines: Vec<_> = source.lines().collect();
            for (index, line) in lines
                .iter()
                .enumerate()
                .filter(|(_, l)| l.starts_with("pass"))
            {
                let mut variants = vec![line.replace("quick ", "")];
                let words: Vec<_> = line.split_whitespace().collect();
                for (key, count) in [("on", 2), ("proto", 2), ("port", 2), ("icmp6-type", 2)] {
                    for pos in words
                        .iter()
                        .enumerate()
                        .filter_map(|(p, w)| (*w == key).then_some(p))
                    {
                        variants.push(
                            words
                                .iter()
                                .enumerate()
                                .filter_map(|(p, w)| {
                                    (!(pos..pos + count).contains(&p)).then_some(*w)
                                })
                                .collect::<Vec<_>>()
                                .join(" "),
                        );
                    }
                }
                for token in ["inet", "inet6", "in", "out"] {
                    if words.contains(&token) {
                        variants.push(
                            words
                                .iter()
                                .copied()
                                .filter(|w| *w != token)
                                .collect::<Vec<_>>()
                                .join(" "),
                        );
                    }
                }
                if line.contains("keep state (if-bound)") {
                    variants.push(line.replace("keep state (if-bound)", "keep state"));
                    variants.push(line.replace("keep state (if-bound)", ""));
                } else {
                    variants.push(line.replace("no state", ""));
                }
                // Replace each constrained address or address list independently.
                let parsed = parse::pf_rules(line).unwrap();
                if let Rule::Pass(pass) = &parsed.rules()[0] {
                    for (keyword, addresses) in
                        [("from", &pass.sources), ("to", &pass.destinations)]
                    {
                        if addresses != &["any"] {
                            let literal = if addresses.len() == 1 {
                                addresses[0].clone()
                            } else {
                                format!("{{ {} }}", addresses.join(", "))
                            };
                            variants.push(line.replacen(
                                &format!("{keyword} {literal}"),
                                &format!("{keyword} any"),
                                1,
                            ));
                        }
                    }
                }
                if line.contains("from :: ") {
                    variants.push(line.replace("from :: ", "from fe80::/10 "));
                }
                for variant in variants {
                    assert_ne!(variant, *line);
                    let mut changed = lines.clone();
                    changed[index] = &variant;
                    assert!(
                        verify::capture_baseline(&changed.join("\n"), &i, form, &normalization())
                            .is_err(),
                        "accepted widening: {variant}"
                    );
                }
            }
        }
    }
}

fn retime(o: &mut Observations, at: u64) {
    let tree = o.live_tree.as_ref().unwrap();
    o.started_at = verify::required_reads(tree)
        .into_iter()
        .map(|k| (k, at))
        .collect();
}
fn add_anchor(o: &mut Observations, name: &str, filter: &str, nat: &str) {
    let tree = o.live_tree.as_mut().unwrap();
    tree.anchors.insert(
        name.into(),
        AnchorObservation {
            rules: parse::pf_rules(filter),
            translation: parse::translation(nat),
        },
    );
    let text = tree.anchors.keys().cloned().collect::<Vec<_>>().join("\n");
    tree.before = parse::anchor_list(&text).unwrap();
    tree.after = tree.before.clone();
    retime(o, 100);
}
#[test]
fn translation_is_observed_separately_at_root_and_every_anchor_including_later_ones() {
    let translations = [
        "nat pass on en0 inet from any to any -> (en0)",
        "nat on en0 inet from any to any -> 192.0.2.2",
        "rdr pass on en0 inet proto tcp from any to any port = 80 -> 127.0.0.1 port 8080",
        "rdr on bridge100 inet from any to any -> 192.0.2.2",
        "binat pass on en0 inet from 192.0.2.0/24 to any -> 198.51.100.0/24",
        "binat on vmnet1 inet from 192.0.2.0/24 to any -> 198.51.100.0/24",
        "unknown-translation with future syntax",
    ];
    for nat in translations {
        for path in [
            "",
            "com.apple/100.synthetic",
            "com.apple/scupper",
            "com.apple/zz.later",
        ] {
            let (mut o, mut e) = setup(Form::Joined);
            add_anchor(&mut o, "com.apple/zz.later", "pass quick all", "");
            e.qualification.siblings.insert(
                "com.apple/zz.later".into(),
                parse::pf_rules("pass quick all").unwrap(),
            );
            e.qualification
                .anchor_translation
                .insert("com.apple/zz.later".into(), parse::translation("").unwrap());
            assert_protected(&o, &e, 102); // later filter rules cannot override our quick decision
            if path.is_empty() {
                o.translation = parse::translation(nat);
            } else {
                o.live_tree
                    .as_mut()
                    .unwrap()
                    .anchors
                    .get_mut(path)
                    .unwrap()
                    .translation = parse::translation(nat);
            }
            assert_eq!(
                verify::verify(&o, &e, &Clock(102)),
                Verdict::NotProtected(Reason::TranslationPresent),
                "{path}: {nat}"
            );
        }
    }
}
#[test]
fn live_inventory_contents_hooks_and_completeness_are_all_required() {
    for name in [
        "com.apple/000.evil",
        "com.apple/zz.evil",
        "other",
        "com.apple/scupper/nested",
    ] {
        let (mut o, e) = setup(Form::Joined);
        add_anchor(&mut o, name, "", "");
        assert!(
            matches!(
                verify::verify(&o, &e, &Clock(102)),
                Verdict::NotProtected(_)
            ),
            "{name}"
        );
    }
    for change in 0..7 {
        let (mut o, e) = setup(Form::Joined);
        let tree = o.live_tree.as_mut().unwrap();
        match change {
            0 => tree.complete = false,
            1 => tree.after = parse::anchor_list("com.apple\ncom.apple/scupper").unwrap(),
            2 => {
                tree.anchors.remove("com.apple/100.synthetic");
            }
            3 => {
                tree.anchors.remove("com.apple/scupper");
                tree.before = parse::anchor_list("com.apple\ncom.apple/100.synthetic").unwrap();
                tree.after = tree.before.clone();
            }
            4 => {
                tree.anchors
                    .get_mut("com.apple/100.synthetic")
                    .unwrap()
                    .rules = parse::pf_rules("block all");
            }
            5 => tree.anchors.get_mut("com.apple/scupper").unwrap().rules = parse::pf_rules(PRE),
            _ => {
                tree.anchors
                    .get_mut("com.apple/100.synthetic")
                    .unwrap()
                    .translation = Err(Error("failed nat read"));
            }
        }
        retime(&mut o, 100);
        assert!(
            !matches!(verify::verify(&o, &e, &Clock(102)), Verdict::Protected(_)),
            "change {change}"
        );
    }
    for hook in [
        "anchor \"com.apple/*\" on en0",
        "anchor \"com.apple/*\" quick",
        "anchor \"/com.apple/*\" all",
        "anchor \"../com.apple/*\" all",
        "anchor \"missing/*\" all",
    ] {
        let (mut o, mut e) = setup(Form::Joined);
        o.main = parse::pf_rules(hook);
        e.qualification.main = o.main.clone().unwrap();
        assert!(
            !matches!(verify::verify(&o, &e, &Clock(102)), Verdict::Protected(_)),
            "{hook}"
        );
    }
    // Nested relative hooks are resolved by invocation, not storage order alone.
    let (mut o, mut e) = setup(Form::Joined);
    o.main = parse::pf_rules("anchor \"com.apple\" all");
    e.qualification.main = o.main.clone().unwrap();
    o.live_tree
        .as_mut()
        .unwrap()
        .anchors
        .get_mut("com.apple")
        .unwrap()
        .rules = parse::pf_rules("anchor \"*\" all");
    e.qualification.siblings.insert(
        "com.apple".into(),
        parse::pf_rules("anchor \"*\" all").unwrap(),
    );
    assert_protected(&o, &e, 102);
}
#[test]
fn real_command_shapes_are_accepted_and_query_identity_is_checked() {
    assert!(
        !parse::pf_interfaces("all\nlo0 (skip)\nen0\nutun6\n").unwrap()[&"en0".parse().unwrap()]
    );
    for text in ["en0 (attached)", "en0 (skip, attached)", "en0 (unknown)"] {
        assert!(parse::pf_interfaces(text).is_err());
    }
    for name in ["all", "lo", "en", "egress", "En0", "en0x", "e0n1"] {
        assert!(name.parse::<PhysicalInterface>().is_err());
    }
    let (mut o, e) = setup(Form::PreTunnel);
    o.route = parse::route(include_str!("fixtures/mac/route-default.txt"));
    assert_protected(&o, &e, 102);
    o.route.as_mut().unwrap().route_to = "198.51.100.8".parse().unwrap();
    assert_eq!(
        verify::verify(&o, &e, &Clock(102)),
        Verdict::NotProtected(Reason::Observation("route lookup target mismatch"))
    );
    let (mut o, mut e) = setup(Form::Joined);
    let main = parse::pf_rules(&format!(
        "scrub-anchor \"com.apple/*\" all fragment reassemble\n{MAIN}"
    ))
    .unwrap();
    o.main = Ok(main.clone());
    e.qualification.main = main;
    assert_protected(&o, &e, 102);
}
#[test]
fn freshness_uses_oldest_start_separates_completion_and_precedes_disruptive_repairs() {
    let (mut o, e) = setup(Form::Joined);
    o.started_at
        .insert("com.apple/100.synthetic:nat".into(), 90);
    o.started_at.insert("inventory-before".into(), 90);
    o.pf.as_mut().unwrap().enabled = false;
    assert_eq!(
        verify::verify(&o, &e, &Clock(102)),
        Verdict::Unknown { since: 95 }
    );
    o.pf.as_mut().unwrap().enabled = true;
    o.started_at.remove("main");
    assert!(matches!(
        verify::verify(&o, &e, &Clock(102)),
        Verdict::NotProtected(_)
    ));
    retime(&mut o, 100);
    let verdict = verify::verify(&o, &e, &Clock(104));
    let Verdict::Protected(ref p) = verdict else {
        panic!("missing proof")
    };
    assert_eq!((p.verified_at(), p.completed_at()), (100, 104));
    assert_eq!(verdict.at(&Clock(106)), Verdict::Unknown { since: 105 });
    o.states = StateEvidence::Unproven;
    assert!(matches!(
        verify::verify(&o, &e, &Clock(104)),
        Verdict::Unknown { .. }
    ));
    // A vanished bypass does not establish clean states.
    o.translation = parse::translation("nat pass on en0 from any to any -> (en0)");
    assert!(matches!(
        verify::verify(&o, &e, &Clock(104)),
        Verdict::NotProtected(_)
    ));
    o.translation = Ok(e.qualification.main_translation.clone());
    assert!(matches!(
        verify::verify(&o, &e, &Clock(104)),
        Verdict::Unknown { .. }
    ));
}

fn machine_fixture(m: &Machine, form: Form, generation: u64, at: u64) -> (Observations, Expected) {
    let (mut o, mut e) = setup(form);
    e.context = m.context();
    e.inputs = Inputs::new(
        e.inputs.selected().clone(),
        e.inputs.endpoint().clone(),
        e.inputs.physical().clone(),
        tunnel(generation),
        e.inputs.hop_limit().clone(),
    )
    .unwrap();
    let text = independent_policy(&e.inputs, form);
    e.baseline = verify::capture_baseline(&text, &e.inputs, form, &normalization()).unwrap();
    o.anchor = parse::pf_rules(&text).map(Some);
    o.live_tree
        .as_mut()
        .unwrap()
        .anchors
        .get_mut("com.apple/scupper")
        .unwrap()
        .rules = parse::pf_rules(&text);
    o.policy_inputs = Ok(e.inputs.clone());
    o.identity = IdentityEvidence::CurrentGeneration(tunnel(generation));
    o.states = StateEvidence::Clean {
        epoch: m.context().state_epoch,
        completed_at: m.states_clean_at().unwrap_or(at - 1),
    };
    retime(&mut o, at);
    (o, e)
}
fn complete_event(m: &Machine, generation: u64) -> Event {
    match m.pending().unwrap() {
        Step::AcquireReference => {
            Event::ReferenceAcquired(m.durable().pf_reference.unwrap_or(100) + 1)
        }
        Step::ReconcileReference if !m.durable().uncertain_acquires.is_empty() => {
            Event::Failed(Reason::Observation("unresolved acquisition debt"))
        }
        Step::ReconcileReference => Event::ReferenceReconciled {
            context: m.context(),
            current: m
                .durable()
                .pf_reference
                .or_else(|| m.durable().older_references.first().copied()),
            predecessor: m
                .durable()
                .pf_reference
                .and_then(|_| m.durable().older_references.first().copied()),
        },
        Step::ReserveGeneration => Event::GenerationReserved(tunnel(generation).generation),
        Step::StartChild => Event::ChildStarted(tunnel(generation)),
        Step::VerifyIdentity => Event::IdentityVerified(tunnel(generation)),
        Step::VerifyPreTunnelLoad | Step::VerifyJoinedLoad | Step::VerifyReplacement(_) => {
            let form = match m.pending().unwrap() {
                Step::VerifyPreTunnelLoad => Form::PreTunnel,
                Step::VerifyJoinedLoad => Form::Joined,
                Step::VerifyReplacement(f) => f,
                _ => unreachable!(),
            };
            Event::ReadbackValidated(machine_fixture(m, form, generation, 100).1.baseline)
        }
        Step::VerifyPreTunnel | Step::VerifyJoined => {
            let form = if m.pending() == Some(Step::VerifyJoined) {
                Form::Joined
            } else {
                Form::PreTunnel
            };
            let (mut o, e) = machine_fixture(m, form, generation, 100);
            if m.states_clean_at().is_none() {
                o.states = StateEvidence::Unproven;
            }
            Event::Observed {
                context: m.context(),
                form,
                verdict: verify::verify(&o, &e, &Clock(102)),
            }
        }
        Step::FlushStates => Event::StatesClean {
            epoch: m.context().state_epoch,
            completed_at: 99,
        },
        Step::RemoveVanishedInterfaceStates => Event::InterfaceStatesRemoved {
            interfaces: m.vanished_interfaces().clone(),
            completed_at: 99,
        },
        step => Event::Completed(step),
    }
}
fn finish(mut m: Machine, generation: u64) -> Machine {
    for _ in 0..60 {
        if m.pending().is_none() || m.connectivity_restored() {
            return m;
        }
        m = settle_modeled_predecessors(m, 99);
        m = m
            .fixture_transition(complete_event(&m, generation))
            .unwrap();
    }
    panic!("plan did not settle: {:?}", m.pending());
}
fn joined() -> Machine {
    finish(
        Machine::restart(Durable::default())
            .fixture_transition(Event::Join)
            .unwrap(),
        1,
    )
}
#[test]
fn lifecycle_join_order_requires_readback_flush_reservation_and_current_proof() {
    let m = Machine::restart(Durable::default());
    assert_eq!(m.status_at(&Clock(99)), ConnectionStatus::Idle);
    let mut m = m.fixture_transition(Event::Join).unwrap();
    assert_eq!(m.status_at(&Clock(99)), ConnectionStatus::JoiningRecovering);
    let mut steps = Vec::new();
    while let Some(step) = m.pending() {
        steps.push(step);
        assert!(
            m.fixture_transition(Event::Completed(Step::VerifyJoined))
                .is_err()
        );
        m = m.fixture_transition(complete_event(&m, 1)).unwrap();
    }
    assert_eq!(
        &steps[..6],
        &[
            Step::PersistIntent,
            Step::AcquireReference,
            Step::LoadPreTunnel,
            Step::VerifyPreTunnelLoad,
            Step::FlushStates,
            Step::VerifyPreTunnel
        ]
    );
    let pos = |s| steps.iter().position(|x| *x == s).unwrap();
    assert!(pos(Step::CheckTools) > pos(Step::VerifyPreTunnel));
    assert!(pos(Step::ReserveGeneration) < pos(Step::StartChild));
    assert!(pos(Step::VerifyIdentity) < pos(Step::LoadJoined));
    assert!(matches!(
        m.enforcement_at(&Clock(102)),
        Verdict::Protected(_)
    ));
    assert_eq!(
        m.enforcement_at(&Clock(106)),
        Verdict::Unknown { since: 105 }
    );
    assert_eq!(m.last_verified(), Some(100));
    assert_eq!(m.tunnel_health(), &TunnelHealth::AwaitingHandshake);
    let after = m
        .fixture_transition(Event::Handshake {
            generation: tunnel(1).generation,
            fresh: true,
        })
        .unwrap();
    assert_eq!(
        after.enforcement_at(&Clock(106)),
        Verdict::Unknown { since: 105 }
    );
    assert_eq!(after.tunnel_health(), &TunnelHealth::Healthy);
    let (o, e) = machine_fixture(&m, Form::Joined, 1, 100);
    let old = verify::verify(&o, &e, &Clock(102));
    let invalidated = m
        .fixture_transition(Event::InvalidateObservations { since: 103 })
        .unwrap();
    assert!(
        invalidated
            .fixture_transition(Event::Observed {
                context: invalidated.context(),
                form: Form::Joined,
                verdict: old
            })
            .is_err()
    );
    let restarted = Machine::restart(m.durable().clone());
    assert_ne!(restarted.context(), m.context());
    assert!(!matches!(
        restarted.enforcement_at(&Clock(102)),
        Verdict::Protected(_)
    ));
}
#[test]
fn returning_from_gap_or_failure_requires_new_state_cleanliness_even_if_bypass_disappears() {
    let m = joined();
    let (o, e) = machine_fixture(&m, Form::Joined, 1, 110);
    let stale = m
        .transition(
            observed(&m, Form::Joined, verify::verify(&o, &e, &Clock(112))),
            &Clock(112),
        )
        .unwrap();
    assert_eq!(stale.pending(), Some(Step::FlushStates));
    assert!(!matches!(
        stale.enforcement_at(&Clock(112)),
        Verdict::Protected(_)
    ));

    for verdict in [
        Verdict::Unknown { since: 105 },
        Verdict::NotProtected(Reason::HookMissing),
    ] {
        let mut m = joined()
            .transition(Event::InvalidateObservations { since: 105 }, &Clock(110))
            .unwrap();
        // A monitor result can arrive while the machine's own flush is in flight.
        m = m
            .transition(observed(&m, Form::Joined, verdict), &Clock(110))
            .unwrap();
        m = m
            .transition(
                Event::StatesClean {
                    epoch: m.context().state_epoch,
                    completed_at: 110,
                },
                &Clock(110),
            )
            .unwrap();
        // The cancelled in-flight flush settles before the new epoch's flush.
        assert_eq!(m.pending(), Some(Step::FlushStates));
        assert!(
            m.transition(Event::Completed(Step::FlushStates), &Clock(111))
                .is_err()
        );
        m = m
            .transition(
                Event::StatesClean {
                    epoch: m.context().state_epoch,
                    completed_at: 111,
                },
                &Clock(111),
            )
            .unwrap();
        assert_eq!(m.pending(), Some(Step::VerifyJoined));
        let (o, e) = machine_fixture(&m, Form::Joined, 1, 112);
        m = m
            .transition(
                observed(&m, Form::Joined, verify::verify(&o, &e, &Clock(114))),
                &Clock(114),
            )
            .unwrap();
        assert!(matches!(
            m.enforcement_at(&Clock(114)),
            Verdict::Protected(_)
        ));
        assert_eq!(m.pending(), None);
    }
}
fn observed(m: &Machine, form: Form, verdict: Verdict) -> Event {
    Event::Observed {
        context: m.context(),
        form,
        verdict,
    }
}
#[test]
fn leave_during_every_repair_boundary_suppresses_rejoin_and_ignores_verification_failures() {
    let start = joined()
        .fixture_transition(Event::Repair(Action::EnableAndRejoin))
        .unwrap();
    let mut m = start;
    while m.pending().is_some() {
        let step = m.pending().unwrap();
        let settling = complete_event(&m, 2);
        let mut leaving = m.fixture_transition(Event::Leave).unwrap();
        assert_eq!(leaving.pending(), Some(step));
        assert!(!matches!(
            leaving.enforcement_at(&Clock(102)),
            Verdict::Protected(_)
        ));
        leaving = leaving.fixture_transition(Event::ChildDied).unwrap();
        leaving = leaving.fixture_transition(settling).unwrap();
        assert_eq!(
            leaving.pending(),
            Some(Step::PersistLeaving),
            "boundary {step:?}"
        );
        leaving = leaving
            .fixture_transition(Event::Completed(Step::PersistLeaving))
            .unwrap();
        assert!(leaving.durable().leaving && !leaving.durable().join_intended);
        assert!(leaving.fixture_transition(Event::Join).is_err());
        let pending = leaving.pending();
        leaving = leaving
            .fixture_transition(Event::Observed {
                context: leaving.context(),
                form: Form::PreTunnel,
                verdict: Verdict::NotProtected(Reason::Unsupported("unqualified OS build")),
            })
            .unwrap();
        assert_eq!(leaving.pending(), pending);
        leaving = finish(Machine::restart(leaving.durable().clone()), 3);
        assert!(leaving.connectivity_restored());
        m = m.fixture_transition(complete_event(&m, 2)).unwrap();
    }
}
#[test]
fn cleanup_attempts_every_owned_step_after_failures_and_remains_resumable() {
    let mut m = joined().fixture_transition(Event::Leave).unwrap();
    m = m
        .fixture_transition(Event::Completed(Step::PersistLeaving))
        .unwrap();
    let mut attempted = Vec::new();
    while let Some(step) = m.pending() {
        if matches!(step, Step::Backoff { .. }) {
            break;
        }
        assert!(attempted.len() < 10, "unpaced cleanup retry");
        attempted.push(step);
        m = m
            .fixture_transition(Event::Failed(Reason::Observation(
                "injected cleanup failure",
            )))
            .unwrap();
    }
    assert_eq!(
        attempted,
        vec![
            Step::StopChild,
            Step::CleanupRoutes,
            Step::CleanupDns,
            Step::CleanupArtifacts,
            Step::RemoveAnchor
        ]
    );
    assert_eq!(m.durable().pending_cleanup, attempted);
    assert_eq!(m.durable().cleanup_errors.len(), attempted.len());
    assert!(m.durable().pf_reference.is_some());
    assert!(m.durable().leaving && !m.connectivity_restored());
    assert!(
        m.fixture_transition(Event::Completed(Step::ClearIntent))
            .is_err()
    );
    // Wake/Unknown during an ownership-debt timer cannot resurrect recovery.
    m = m
        .fixture_transition(Event::InvalidateObservations { since: 102 })
        .unwrap();
    m = m
        .fixture_transition(observed(
            &m,
            Form::PreTunnel,
            Verdict::Unknown { since: 102 },
        ))
        .unwrap();
    assert!(!m.plan().contains(&Step::LoadPreTunnel));
    assert!(m.durable().leaving);
    m = Machine::restart(m.durable().clone());
    m = finish(m, 2);
    assert!(m.connectivity_restored());
    assert!(m.durable().pending_cleanup.is_empty() && m.durable().cleanup_errors.is_empty());
    let idle = Machine::restart(Durable::default())
        .fixture_transition(Event::Leave)
        .unwrap();
    let idle = idle
        .fixture_transition(Event::Completed(Step::PersistLeaving))
        .unwrap();
    assert_eq!(idle.pending(), Some(Step::ClearIntent));
    assert!(finish(idle, 1).connectivity_restored());
}
#[test]
fn failed_leaving_persistence_retries_without_conflicting_cleanup() {
    let m = joined().fixture_transition(Event::Leave).unwrap();
    let m = m
        .fixture_transition(Event::Failed(Reason::Observation("journal unavailable")))
        .unwrap();
    assert!(!m.durable().leaving);
    assert!(!m.connectivity_restored());
    let m = m.fixture_transition(Event::Leave).unwrap();
    assert_eq!(m.pending(), Some(Step::PersistLeaving));
    assert!(finish(m, 2).connectivity_restored());
}
#[test]
fn negative_observations_during_configuration_invalidate_status_and_cancel_at_boundary() {
    for unknown in [false, true] {
        let mut m = Machine::restart(Durable::default())
            .fixture_transition(Event::Join)
            .unwrap();
        while m.pending() != Some(Step::ConfigureUapi) {
            m = m.fixture_transition(complete_event(&m, 1)).unwrap();
        }
        let verdict = if unknown {
            Verdict::Unknown { since: 103 }
        } else {
            Verdict::NotProtected(Reason::HookMissing)
        };
        let m = m
            .fixture_transition(Event::Observed {
                context: m.context(),
                form: Form::PreTunnel,
                verdict: verdict.clone(),
            })
            .unwrap();
        assert_eq!(m.enforcement_at(&Clock(104)), verdict);
        assert_eq!(m.pending(), Some(Step::ConfigureUapi));
        assert!(
            m.fixture_transition(Event::Observed {
                context: m.context(),
                form: Form::PreTunnel,
                verdict: fixture_verdict(machine_fixture(&m, Form::PreTunnel, 1, 100))
            })
            .is_err()
        );
        let m = m
            .fixture_transition(Event::Completed(Step::ConfigureUapi))
            .unwrap();
        assert_eq!(
            m.pending(),
            Some(if unknown {
                Step::ConfigureAddresses
            } else {
                Step::LoadPreTunnel
            })
        );
        assert!(!matches!(
            m.enforcement_at(&Clock(104)),
            Verdict::Protected(_)
        ));
    }
}
// All lifecycle success fixtures go through the real verifier.
fn fixture_verdict((o, e): (Observations, Expected)) -> Verdict {
    verify::verify(&o, &e, &Clock(102))
}
#[test]
fn dhcp_replacement_preserves_child_and_states_and_requires_readback() {
    let m = joined();
    let (mut o, e) = machine_fixture(&m, Form::Joined, 1, 100);
    o.policy_inputs = Ok(inputs(true, true));
    let mut e = e;
    e.qualification.physical = inputs(true, true).physical().keys().cloned().collect();
    assert_eq!(
        verify::verify(&o, &e, &Clock(102)),
        Verdict::Repair(Action::Rerender { form: Form::Joined })
    );
    let mut m = m
        .fixture_transition(Event::Repair(Action::Rerender { form: Form::Joined }))
        .unwrap();
    let child = m.tunnel().cloned();
    let epoch = m.context().state_epoch;
    let old_hash = fixture_verdict(machine_fixture(&joined(), Form::Joined, 1, 100));
    let mut steps = vec![m.pending().unwrap()];
    m = m
        .fixture_transition(Event::Completed(Step::ReplaceAnchor(Form::Joined)))
        .unwrap();
    let (mut o, mut e) = machine_fixture(&m, Form::Joined, 1, 100);
    e.inputs = inputs(true, true);
    e.qualification.physical = e.inputs.physical().keys().cloned().collect();
    let text = independent_policy(&e.inputs, Form::Joined);
    e.baseline = verify::capture_baseline(&text, &e.inputs, e.form, &normalization()).unwrap();
    o.policy_inputs = Ok(e.inputs.clone());
    o.anchor = parse::pf_rules(&text).map(Some);
    o.live_tree
        .as_mut()
        .unwrap()
        .anchors
        .get_mut("com.apple/scupper")
        .unwrap()
        .rules = parse::pf_rules(&text);
    steps.push(m.pending().unwrap());
    m = m
        .fixture_transition(Event::ReadbackValidated(e.baseline.clone()))
        .unwrap();
    steps.push(m.pending().unwrap());
    let proof = verify::verify(&o, &e, &Clock(102));
    if let (Verdict::Protected(old), Verdict::Protected(new)) = (old_hash, &proof) {
        assert_ne!(old.baseline_hash(), new.baseline_hash());
    } else {
        panic!("expected old and replacement proofs");
    }
    m = m
        .fixture_transition(Event::Observed {
            context: m.context(),
            form: Form::Joined,
            verdict: proof,
        })
        .unwrap();
    assert_eq!(
        steps,
        vec![
            Step::ReplaceAnchor(Form::Joined),
            Step::VerifyReplacement(Form::Joined),
            Step::VerifyJoined
        ]
    );
    assert_eq!(m.tunnel(), child.as_ref());
    assert_eq!(m.context().state_epoch, epoch);
    assert!(matches!(
        m.enforcement_at(&Clock(102)),
        Verdict::Protected(_)
    ));
    let mut failed = m
        .fixture_transition(Event::Repair(Action::Rerender { form: Form::Joined }))
        .unwrap();
    failed = failed
        .fixture_transition(Event::Completed(Step::ReplaceAnchor(Form::Joined)))
        .unwrap();
    failed = failed
        .fixture_transition(Event::Failed(Reason::Observation("readback failed")))
        .unwrap();
    assert!(matches!(
        failed.enforcement_at(&Clock(102)),
        Verdict::NotProtected(_)
    ));
    assert_eq!(failed.tunnel(), child.as_ref());
}
#[test]
fn references_are_retained_and_generation_is_reserved_before_child_start() {
    let joined = joined();
    let old = joined.durable().pf_reference.unwrap();
    let m = joined
        .fixture_transition(Event::Repair(Action::Rejoin))
        .unwrap();
    assert_eq!(m.pending(), Some(Step::LoadPreTunnel));
    assert_eq!(m.durable().pf_reference, Some(old));
    let reuse = joined
        .fixture_transition(Event::Repair(Action::EnableAndRejoin))
        .unwrap();
    assert_eq!(reuse.durable().pf_reference, Some(old));
    assert_eq!(reuse.pending(), Some(Step::LoadPreTunnel));
    let m = joined
        .fixture_transition(observed(
            &joined,
            Form::Joined,
            Verdict::Repair(Action::EnableAndRejoin),
        ))
        .unwrap();
    assert_eq!(m.durable().pf_reference, Some(old)); // observations cannot release a token
    let m = m
        .fixture_transition(Event::ReferenceAcquired(old + 1))
        .unwrap();
    assert_eq!(m.durable().older_references, vec![old]);
    let mut m = m;
    while m.pending() != Some(Step::ReserveGeneration) {
        m = m.fixture_transition(complete_event(&m, 2)).unwrap();
    }
    assert!(
        m.fixture_transition(Event::ChildStarted(tunnel(2)))
            .is_err()
    );
    m = m
        .fixture_transition(Event::GenerationReserved(tunnel(2).generation))
        .unwrap();
    let restarted = Machine::restart(m.durable().clone());
    assert_eq!(
        restarted.durable().previous_generation,
        Some(tunnel(2).generation)
    );
    assert!(
        m.fixture_transition(Event::ChildStarted(tunnel(1)))
            .is_err()
    );
}
proptest! {
    #[test]
    fn adversarial_lifecycle_orders_preserve_proof_identity_and_state_flush_after_gaps(
        start_joined in any::<bool>(),
        events in prop::collection::vec((0u8..25, 0u64..12, 0u64..9), 0..300)
    ) {
        let mut m = if start_joined { joined() } else { Machine::restart(Durable::default()) };
        let mut now = 102u64;
        let mut accepted = match m.enforcement_at(&Clock(now)) { Verdict::Protected(p) => Some(p), _ => None };
        let mut expiry = accepted.as_ref().map(verify::Proof::expires_at);
        let mut last_gap = 0;
        let mut checked_flush = start_joined.then_some((m.context().state_epoch, 99));
        for (code, elapsed, round_age) in events {
            // This clock includes simulated sleep, with no wake notification required.
            now += elapsed;
            if let Some(at) = expiry && now > at { last_gap = last_gap.max(at); }
            let generation = if matches!(m.pending(), Some(Step::StartChild | Step::VerifyIdentity | Step::VerifyJoinedLoad | Step::VerifyJoined)) {
                m.durable().previous_generation.map_or(1, TunnelGeneration::value)
            } else { m.durable().previous_generation.map_or(1, |g| g.value()+1) };
            let form = m.installed_form().unwrap_or(Form::Joined);
            let round = |m: &Machine, old_states: bool, changed_dhcp: bool| {
                let (mut o, mut e) = machine_fixture(m, form, generation, now - round_age);
                if old_states { o.states = StateEvidence::Clean { epoch: m.context().state_epoch, completed_at: 99 }; }
                if changed_dhcp {
                    o.policy_inputs = Ok(inputs(true, true));
                    e.qualification.physical = inputs(true, true).physical().keys().cloned().collect();
                }
                observed(m, form, verify::verify(&o, &e, &Clock(now)))
            };
            let event = match code {
                0 => Event::Join, 1 | 2 => Event::Leave, 3 => Event::ChildDied,
                4 => Event::Repair(Action::EnableAndRejoin),
                5 => Event::Repair(Action::Rerender { form }),
                6 => Event::InvalidateObservations { since: now },
                7 => observed(&m, form, Verdict::NotProtected(Reason::HookMissing)),
                8 => Event::Failed(Reason::Observation("adversarial failure")),
                9 => {
                    m = Machine::restart(m.durable().clone()); accepted = None;
                    checked_flush = None; expiry = None; last_gap = now; continue;
                },
                10 => Event::Completed(Step::RemoveAnchor),
                11 => Event::Handshake { generation: tunnel(1).generation, fresh: true },
                12 => Event::StatesClean { epoch: m.context().state_epoch, completed_at: now },
                13 => round(&m, false, false),
                14 => round(&m, true, true), // expired cleanliness + DHCP can request Rerender
                15 => round(&m, true, false),
                16 => observed(&m, form, Verdict::Unknown { since: now - round_age }),
                _ => match m.pending() {
                    Some(Step::FlushStates) => Event::StatesClean { epoch: m.context().state_epoch, completed_at: now },
                    Some(Step::RemoveVanishedInterfaceStates) => Event::InterfaceStatesRemoved { interfaces: m.vanished_interfaces().clone(), completed_at: now },
                    Some(Step::VerifyPreTunnel | Step::VerifyJoined) => round(&m, false, false),
                    Some(_) => complete_event(&m, generation),
                    None => Event::Join,
                },
            };
            let proof = match &event { Event::Observed { verdict: Verdict::Protected(p), .. } => Some(p.clone()), _ => None };
            let gap = match &event {
                // Ownership-only reconciliation failure does not change enforcement.
                Event::Failed(_) if m.pending() == Some(Step::ReconcileReference) => None,
                Event::Failed(_) | Event::Observed { verdict: Verdict::NotProtected(_), .. } => Some(now),
                Event::InvalidateObservations { since } | Event::Observed { verdict: Verdict::Unknown { since }, .. } => Some(*since),
                _ => None,
            };
            let flush = match &event {
                Event::StatesClean { epoch, completed_at } if m.pending() == Some(Step::FlushStates) && *epoch == m.context().state_epoch => Some((*epoch, *completed_at)),
                _ => None,
            };
            if let Ok(next) = m.transition(event, &Clock(now)) {
                if next.context().state_epoch != m.context().state_epoch { checked_flush = None; }
                if let Some(gap) = gap { last_gap = last_gap.max(gap); }
                if let Some(flush) = flush { checked_flush = Some(flush); }
                if let Some(p) = proof && matches!(next.enforcement_at(&Clock(now)), Verdict::Protected(_)) {
                    expiry = Some(p.expires_at()); accepted = Some(p);
                }
                m = next;
            }
            if let Verdict::Protected(p) = m.enforcement_at(&Clock(now)) {
                prop_assert_eq!(accepted.as_ref(), Some(&p));
                prop_assert_eq!(p.context(), m.context());
                prop_assert_eq!(m.installed_form(), Some(p.form()));
                prop_assert_eq!(checked_flush, Some((p.context().state_epoch, p.states_clean_at())));
                prop_assert!(p.states_clean_at() >= last_gap, "flush {} predates gap {} at {}", p.states_clean_at(), last_gap, now);
                if p.form() == Form::Joined { prop_assert_eq!(m.tunnel(), p.tunnel()); }
                prop_assert!(!m.durable().leaving);
            }
            if m.durable().leaving {
                prop_assert!(!m.durable().join_intended);
                prop_assert!(!matches!(m.enforcement_at(&Clock(now)), Verdict::Protected(_)));
                prop_assert!(!matches!(m.pending(),Some(Step::StartChild | Step::AcquireReference | Step::LoadPreTunnel | Step::LoadJoined)), "code {code}, pending {:?}, journal {:?}", m.pending(), m.durable());
            }
            if m.durable().join_intended && !m.durable().leave_requested {
                prop_assert!(m.pending().is_some()
                    || (m.installed_form() == Some(Form::Joined) && m.tunnel().is_some()));
            }
        }
    }
}

#[test]
fn verification_completion_uses_injected_sleep_counting_clock() {
    struct AdvancingClock(std::cell::Cell<u64>);
    impl SleepCountingClock for AdvancingClock {
        fn now(&self) -> u64 {
            let t = self.0.get();
            self.0.set(t + 6);
            t
        }
    }
    let (o, e) = setup(Form::Joined);
    // Simulate suspension during the walk: evidence expires before completion.
    assert_eq!(
        verify::verify(&o, &e, &AdvancingClock(std::cell::Cell::new(100))),
        Verdict::Unknown { since: 105 }
    );
    let mut o = o;
    o.pf.as_mut().unwrap().enabled = false;
    assert_eq!(
        verify::verify(&o, &e, &AdvancingClock(std::cell::Cell::new(100))),
        Verdict::Unknown { since: 105 }
    );
}
#[test]
fn interface_churn_and_stale_kifs_are_retryable_or_repaired() {
    let (mut o, e) = setup(Form::Joined);
    o.interfaces
        .as_mut()
        .unwrap()
        .remove(&"utun6".parse().unwrap());
    assert_eq!(
        verify::verify(&o, &e, &Clock(102)),
        Verdict::Repair(Action::RecreateChild)
    );
    let (mut o, e) = setup(Form::PreTunnel);
    o.interfaces
        .as_mut()
        .unwrap()
        .remove(&"en0".parse().unwrap());
    assert!(matches!(
        verify::verify(&o, &e, &Clock(102)),
        Verdict::Unknown { .. }
    ));
    let (mut o, e) = setup(Form::PreTunnel);
    o.skips
        .as_mut()
        .unwrap()
        .insert("utun99".parse().unwrap(), false);
    assert_protected(&o, &e, 102);
    o.skips
        .as_mut()
        .unwrap()
        .insert("utun99".parse().unwrap(), true);
    assert_eq!(
        verify::verify(&o, &e, &Clock(102)),
        Verdict::NotProtected(Reason::Skip("utun99".parse().unwrap()))
    );
    let (mut o, e) = setup(Form::PreTunnel);
    o.route.as_mut().unwrap().interface = "utun99".parse().unwrap();
    assert_eq!(
        verify::verify(&o, &e, &Clock(102)),
        Verdict::NotProtected(Reason::RouteRecursion)
    );
}
#[test]
fn anchor_names_and_traversal_bounds_fail_closed() {
    for text in [
        "com.apple\ncom.apple",
        "/absolute",
        "../parent",
        "com.apple/*",
        "a//b",
        "a/./b",
        "name with spaces",
        "a/../../b",
    ] {
        assert!(parse::anchor_list(text).is_err(), "{text}");
    }
    assert!(parse::anchor_list(&vec!["a"; 17].join("/")).is_err());
    let (mut o, mut e) = setup(Form::Joined);
    let repeated = "anchor \"com.apple/100.synthetic\" all\n".repeat(8193) + MAIN;
    o.main = parse::pf_rules(&repeated);
    e.qualification.main = o.main.clone().unwrap();
    assert_eq!(
        verify::verify(&o, &e, &Clock(102)),
        Verdict::NotProtected(Reason::Unsupported("anchor traversal budget"))
    );
    let (mut o, e) = setup(Form::Joined);
    o.live_tree
        .as_mut()
        .unwrap()
        .anchors
        .get_mut("com.apple")
        .unwrap()
        .translation = parse::translation("nat-anchor \"*\" all");
    assert_eq!(
        verify::verify(&o, &e, &Clock(102)),
        Verdict::NotProtected(Reason::Unsupported("changed stock translation hooks"))
    );
}
#[test]
fn proofs_for_other_policy_child_and_lifecycle_identities_are_discarded() {
    let m = joined();
    for mutation in 0..4 {
        let (mut o, mut e) =
            machine_fixture(&m, Form::Joined, if mutation == 2 { 2 } else { 1 }, 100);
        match mutation {
            0 => e.context.policy_generation += 1,
            1 => e.context.lifecycle_revision += 1,
            2 => {}
            _ => {
                e.inputs = inputs(true, false);
                let text = independent_policy(&e.inputs, e.form);
                e.baseline =
                    verify::capture_baseline(&text, &e.inputs, e.form, &normalization()).unwrap();
                o.anchor = parse::pf_rules(&text).map(Some);
                o.live_tree
                    .as_mut()
                    .unwrap()
                    .anchors
                    .get_mut("com.apple/scupper")
                    .unwrap()
                    .rules = parse::pf_rules(&text);
                o.policy_inputs = Ok(e.inputs.clone());
            }
        }
        let proof = verify::verify(&o, &e, &Clock(102));
        assert!(matches!(proof, Verdict::Protected(_)));
        assert!(
            m.fixture_transition(Event::Observed {
                context: m.context(),
                form: Form::Joined,
                verdict: proof
            })
            .is_err()
        );
    }
}
#[test]
fn repair_and_child_loss_wait_for_active_mutation_before_recovery() {
    for child_loss in [false, true] {
        let mut m = Machine::restart(Durable::default())
            .fixture_transition(Event::Join)
            .unwrap();
        while m.pending() != Some(Step::ConfigureUapi) {
            m = m.fixture_transition(complete_event(&m, 1)).unwrap();
        }
        let event = if child_loss {
            Event::ChildDied
        } else {
            Event::Observed {
                context: m.context(),
                form: Form::PreTunnel,
                verdict: Verdict::Repair(Action::EnableAndRejoin),
            }
        };
        m = m.fixture_transition(event).unwrap();
        assert_eq!(m.pending(), Some(Step::ConfigureUapi));
        assert!(!matches!(
            m.enforcement_at(&Clock(102)),
            Verdict::Protected(_)
        ));
        m = m
            .fixture_transition(Event::Completed(Step::ConfigureUapi))
            .unwrap();
        assert_eq!(
            m.pending(),
            Some(if child_loss {
                Step::LoadPreTunnel
            } else {
                Step::AcquireReference
            })
        );
    }
}
#[test]
fn cleanup_final_journal_failure_is_incomplete_and_does_not_spin() {
    let mut m = joined().fixture_transition(Event::Leave).unwrap();
    while m.pending() != Some(Step::ClearIntent) {
        m = m.fixture_transition(complete_event(&m, 1)).unwrap();
    }
    m = m
        .fixture_transition(Event::Failed(Reason::Observation("clear journal failed")))
        .unwrap();
    assert_eq!(m.pending(), None);
    assert!(m.durable().leaving && !m.connectivity_restored());
    assert!(finish(Machine::restart(m.durable().clone()), 2).connectivity_restored());
}

#[test]
fn a_full_check_finishing_after_consumer_expiry_cannot_bridge_the_gap_with_old_states() {
    let m = joined(); // old proof expires at 105
    let (o, e) = machine_fixture(&m, Form::Joined, 1, 104);
    // Sampling began in time, but publication missed the consumer's deadline.
    let late = verify::verify(&o, &e, &Clock(106));
    assert!(matches!(late, Verdict::Protected(_)));
    let m = m
        .transition(observed(&m, Form::Joined, late), &Clock(106))
        .unwrap();
    assert_eq!(m.pending(), Some(Step::FlushStates));
    assert!(!matches!(
        m.enforcement_at(&Clock(106)),
        Verdict::Protected(_)
    ));
    let m = m
        .transition(
            Event::StatesClean {
                epoch: m.context().state_epoch,
                completed_at: 106,
            },
            &Clock(106),
        )
        .unwrap();
    let (o, e) = machine_fixture(&m, Form::Joined, 1, 107);
    let m = m
        .transition(
            observed(&m, Form::Joined, verify::verify(&o, &e, &Clock(108))),
            &Clock(108),
        )
        .unwrap();
    assert!(matches!(
        m.enforcement_at(&Clock(108)),
        Verdict::Protected(_)
    ));
}

#[test]
fn a_leave_request_survives_restart_while_repair_is_still_settling() {
    let m = joined();
    let m = m
        .fixture_transition(observed(
            &m,
            Form::Joined,
            Verdict::Repair(Action::EnableAndRejoin),
        ))
        .unwrap();
    let m = m.fixture_transition(Event::Leave).unwrap();
    assert!(m.durable().leave_requested);
    assert_eq!(m.status_at(&Clock(102)), ConnectionStatus::Leaving);
    let restarted = Machine::restart(m.durable().clone());
    assert_eq!(restarted.pending(), Some(Step::PersistLeaving));
    assert!(finish(restarted, 2).connectivity_restored());
    assert_eq!(
        Reason::TranslationPresent.to_string(),
        "pf translation present"
    );
}

#[test]
fn stale_negative_and_repair_results_cannot_act_on_a_newer_lifecycle() {
    let m = joined();
    let context = m.context();
    let current = m
        .fixture_transition(Event::InvalidateObservations { since: 103 })
        .unwrap();
    for verdict in [
        Verdict::NotProtected(Reason::HookMissing),
        Verdict::Unknown { since: 103 },
        Verdict::Repair(Action::EnableAndRejoin),
    ] {
        assert!(
            current
                .fixture_transition(Event::Observed {
                    context,
                    form: Form::Joined,
                    verdict
                })
                .is_err()
        );
        assert_eq!(current.pending(), Some(Step::FlushStates));
        assert_eq!(
            current.enforcement_at(&Clock(104)),
            Verdict::Unknown { since: 103 }
        );
    }
}

fn replacement_fixture(m: &Machine, new_inputs: &Inputs, at: u64) -> (Observations, Expected) {
    let (mut o, mut e) = machine_fixture(m, Form::Joined, 1, at);
    e.inputs = new_inputs.clone();
    e.qualification
        .physical
        .extend(e.inputs.physical().keys().cloned());
    let text = independent_policy(&e.inputs, e.form);
    e.baseline = verify::capture_baseline(&text, &e.inputs, e.form, &normalization()).unwrap();
    o.policy_inputs = Ok(e.inputs.clone());
    o.anchor = parse::pf_rules(&text).map(Some);
    o.live_tree
        .as_mut()
        .unwrap()
        .anchors
        .get_mut("com.apple/scupper")
        .unwrap()
        .rules = parse::pf_rules(&text);
    (o, e)
}

#[test]
fn expired_rerender_requires_flush_after_prior_expiry_even_when_status_was_invalidated() {
    for start in [104, 200] {
        let mut m = joined(); // clean at 99, proof expires at 105
        let (mut o, mut e) = machine_fixture(&m, Form::Joined, 1, start);
        let new_inputs = inputs(true, true);
        e.qualification
            .physical
            .extend(new_inputs.physical().keys().cloned());
        o.policy_inputs = Ok(new_inputs.clone());
        let repair = verify::verify(&o, &e, &Clock(start));
        assert_eq!(
            repair,
            Verdict::Repair(Action::Rerender { form: Form::Joined })
        );
        m = m
            .transition(observed(&m, Form::Joined, repair), &Clock(start))
            .unwrap();
        let child = m.tunnel().cloned();
        assert_eq!(m.pending(), Some(Step::ReplaceAnchor(Form::Joined)));
        m = m
            .transition(
                Event::Completed(Step::ReplaceAnchor(Form::Joined)),
                &Clock(start),
            )
            .unwrap();
        let (_, e) = replacement_fixture(&m, &new_inputs, start);
        m = m
            .transition(Event::ReadbackValidated(e.baseline), &Clock(start))
            .unwrap();
        if start == 104 {
            // Replacement invalidated status before the machine missed the window.
            assert_eq!(m.pending(), Some(Step::VerifyJoined));
            let (o, e) = replacement_fixture(&m, &new_inputs, 200);
            let proof = verify::verify(&o, &e, &Clock(202));
            assert!(matches!(proof, Verdict::Protected(_)));
            m = m
                .transition(observed(&m, Form::Joined, proof), &Clock(202))
                .unwrap();
        }
        assert_eq!(m.pending(), Some(Step::FlushStates));
        assert!(!matches!(
            m.enforcement_at(&Clock(202)),
            Verdict::Protected(_)
        ));
        assert!(
            m.transition(
                Event::StatesClean {
                    epoch: m.context().state_epoch,
                    completed_at: 99
                },
                &Clock(202)
            )
            .is_err()
        );
        assert!(
            m.transition(
                Event::StatesClean {
                    epoch: m.context().state_epoch - 1,
                    completed_at: 202
                },
                &Clock(202)
            )
            .is_err()
        );
        m = m
            .transition(
                Event::StatesClean {
                    epoch: m.context().state_epoch,
                    completed_at: 202,
                },
                &Clock(202),
            )
            .unwrap();
        assert_eq!(m.pending(), Some(Step::VerifyJoined));
        let (o, e) = replacement_fixture(&m, &new_inputs, 203);
        m = m
            .transition(
                observed(&m, Form::Joined, verify::verify(&o, &e, &Clock(204))),
                &Clock(204),
            )
            .unwrap();
        let Verdict::Protected(proof) = m.enforcement_at(&Clock(204)) else {
            panic!("replacement failed to recover")
        };
        assert_eq!(proof.states_clean_at(), 202);
        assert!(proof.states_clean_at() >= 105);
        assert_eq!(m.tunnel(), child.as_ref());
        assert_eq!(m.pending(), None);
    }
}

#[test]
fn drifted_own_anchor_plus_changed_dhcp_inputs_requires_full_rejoin() {
    for tree_drift in [false, true] {
        let m = joined();
        let (mut o, e) = machine_fixture(&m, Form::Joined, 1, 100);
        o.policy_inputs = Ok(inputs(true, false));
        let widened = JOINED.replace("198.51.100.7", "any");
        if tree_drift {
            o.live_tree
                .as_mut()
                .unwrap()
                .anchors
                .get_mut("com.apple/scupper")
                .unwrap()
                .rules = parse::pf_rules(&widened);
        } else {
            o.anchor = parse::pf_rules(&widened).map(Some);
        }
        let verdict = verify::verify(&o, &e, &Clock(102));
        assert_eq!(verdict, Verdict::Repair(Action::Rejoin));
        let mut m = m
            .transition(observed(&m, Form::Joined, verdict), &Clock(102))
            .unwrap();
        let mut steps = Vec::new();
        while m.pending() != Some(Step::VerifyPreTunnel) {
            steps.push(m.pending().unwrap());
            m = m
                .transition(checked_completion_at(&m, 102), &Clock(102))
                .unwrap();
        }
        assert_eq!(
            steps,
            [
                Step::LoadPreTunnel,
                Step::VerifyPreTunnelLoad,
                Step::FlushStates
            ]
        );
    }
}

#[test]
fn qualified_filter_only_stock_child_is_allowed_behind_scrub_hook() {
    let (mut o, mut e) = setup(Form::Joined);
    let main = parse::pf_rules(&format!(
        "scrub-anchor \"com.apple/*\" all fragment reassemble\n{MAIN}"
    ))
    .unwrap();
    o.main = Ok(main.clone());
    e.qualification.main = main;
    // A later stock filter decision cannot override our quick all-traffic decision.
    let name = "com.apple/zz.stock";
    add_anchor(&mut o, name, "pass all", "");
    assert_eq!(
        verify::verify(&o, &e, &Clock(102)),
        Verdict::NotProtected(Reason::Unsupported(
            "unqualified or changed scrub-hook child"
        ))
    );
    e.qualification
        .siblings
        .insert(name.into(), parse::pf_rules("pass all").unwrap());
    e.qualification
        .anchor_translation
        .insert(name.into(), parse::translation("").unwrap());
    assert_protected(&o, &e, 102);
    // Qualification never authorizes actual scrub statements through filter output.
    add_anchor(&mut o, name, "scrub in all fragment reassemble", "");
    e.qualification.siblings.insert(
        name.into(),
        parse::pf_rules("scrub in all fragment reassemble").unwrap(),
    );
    assert!(matches!(
        verify::verify(&o, &e, &Clock(102)),
        Verdict::NotProtected(_)
    ));
}

#[test]
fn dhcp_replacement_requires_unchanged_transport_and_current_child_identity() {
    for change in 0..7 {
        let (mut o, mut e) = setup(Form::Joined);
        o.policy_inputs = Ok(inputs(true, false));
        match change {
            0 => o.local_address = Ok("192.0.2.3".parse().unwrap()),
            1 => o.route.as_mut().unwrap().gateway = Some("192.0.2.9".parse().unwrap()),
            2 => {
                o.policy_inputs = Ok(Inputs::new(
                    "en0".parse().unwrap(),
                    "198.51.100.8:51820".parse().unwrap(),
                    inputs(true, false).physical().clone(),
                    tunnel(1),
                    HopLimitPolicy::QualifiedLimitation,
                )
                .unwrap());
            }
            3 => {
                o.policy_inputs = Ok(Inputs::new(
                    "en0".parse().unwrap(),
                    e.inputs.endpoint().clone(),
                    inputs(true, false).physical().clone(),
                    tunnel(2),
                    HopLimitPolicy::QualifiedLimitation,
                )
                .unwrap());
            }
            4 => o.identity = IdentityEvidence::LostOrStale,
            5 => {
                o.route.as_mut().unwrap().interface = "en7".parse().unwrap();
                o.policy_inputs = Ok(Inputs::new(
                    "en7".parse().unwrap(),
                    e.inputs.endpoint().clone(),
                    inputs(true, true).physical().clone(),
                    tunnel(1),
                    HopLimitPolicy::QualifiedLimitation,
                )
                .unwrap());
                e.qualification.physical = inputs(true, true).physical().keys().cloned().collect();
            }
            _ => o.route.as_mut().unwrap().link_gateway = Some("link#4".into()),
        }
        assert_eq!(
            verify::verify(&o, &e, &Clock(102)),
            Verdict::Repair(if change == 4 {
                Action::RecreateChild
            } else {
                Action::Rejoin
            }),
            "change {change}"
        );
    }
    let (mut o, e) = setup(Form::Joined);
    let mut physical = e.inputs.physical().clone();
    physical.insert(
        "en0".parse().unwrap(),
        DhcpPhase::Bound {
            server: "192.0.2.8".parse().unwrap(),
        },
    );
    o.policy_inputs = Ok(Inputs::new(
        e.inputs.selected().clone(),
        e.inputs.endpoint().clone(),
        physical,
        tunnel(1),
        e.inputs.hop_limit().clone(),
    )
    .unwrap());
    assert_eq!(
        verify::verify(&o, &e, &Clock(102)),
        Verdict::Repair(Action::Rerender { form: Form::Joined })
    );
}

fn replacement_after_vanished_interface_cleanup() -> (Machine, Observations, Expected) {
    let new_inputs = inputs(true, true);
    let mut m = joined()
        .transition(
            Event::Repair(Action::Rerender { form: Form::Joined }),
            &Clock(102),
        )
        .unwrap();
    m = m
        .transition(
            Event::Completed(Step::ReplaceAnchor(Form::Joined)),
            &Clock(102),
        )
        .unwrap();
    let (o, e) = replacement_fixture(&m, &new_inputs, 102);
    m = m
        .transition(Event::ReadbackValidated(e.baseline.clone()), &Clock(102))
        .unwrap();
    m = m
        .transition(
            observed(&m, Form::Joined, verify::verify(&o, &e, &Clock(102))),
            &Clock(102),
        )
        .unwrap();
    assert!(matches!(
        m.enforcement_at(&Clock(102)),
        Verdict::Protected(_)
    ));
    assert_eq!(m.tunnel(), Some(&tunnel(1)));

    m = m
        .transition(
            Event::Repair(Action::Rerender { form: Form::Joined }),
            &Clock(102),
        )
        .unwrap();
    m = m
        .transition(
            Event::Completed(Step::ReplaceAnchor(Form::Joined)),
            &Clock(102),
        )
        .unwrap();
    let reduced = inputs(true, false);
    let (_, e) = replacement_fixture(&m, &reduced, 102);
    m = m
        .transition(Event::ReadbackValidated(e.baseline), &Clock(102))
        .unwrap();
    assert_eq!(m.pending(), Some(Step::RemoveVanishedInterfaceStates));
    assert_eq!(
        m.vanished_interfaces(),
        &BTreeSet::from(["en7".parse().unwrap()])
    );
    assert!(
        m.transition(
            Event::Completed(Step::RemoveVanishedInterfaceStates),
            &Clock(102)
        )
        .is_err()
    );
    assert!(
        m.transition(
            Event::InterfaceStatesRemoved {
                interfaces: BTreeSet::default(),
                completed_at: 102
            },
            &Clock(102)
        )
        .is_err()
    );
    let (mut o, e) = replacement_fixture(&m, &reduced, 102);
    o.interfaces
        .as_mut()
        .unwrap()
        .remove(&"en7".parse().unwrap());
    assert!(
        m.transition(
            observed(&m, Form::Joined, verify::verify(&o, &e, &Clock(102))),
            &Clock(102)
        )
        .is_err()
    );
    m = m
        .transition(
            Event::InterfaceStatesRemoved {
                interfaces: m.vanished_interfaces().clone(),
                completed_at: 102,
            },
            &Clock(102),
        )
        .unwrap();
    (m, o, e)
}

#[test]
fn replacement_removes_and_verifies_vanished_interface_states_before_full_verification() {
    let (m, o, e) = replacement_after_vanished_interface_cleanup();
    let stable = m
        .transition(
            observed(&m, Form::Joined, verify::verify(&o, &e, &Clock(102))),
            &Clock(102),
        )
        .unwrap();
    assert!(matches!(
        stable.enforcement_at(&Clock(102)),
        Verdict::Protected(_)
    ));
    assert_eq!(stable.tunnel(), Some(&tunnel(1)));
}

#[test]
fn replacement_rechecks_transport_after_readback_even_if_expected_changes() {
    let (m, original_o, original_e) = replacement_after_vanished_interface_cleanup();
    // Even if a caller changes Expected along with live transport, the serialized
    // replacement must rejoin instead of accepting the new path without teardown.
    for change_gateway in [false, true] {
        let (mut o, mut e) = (original_o.clone(), original_e.clone());
        if change_gateway {
            o.route.as_mut().unwrap().gateway = Some("192.0.2.9".parse().unwrap());
            e.transport.endpoint_route = o.route.clone().unwrap();
        } else {
            o.local_address = Ok("192.0.2.3".parse().unwrap());
            e.transport.local_address = o.local_address.clone().unwrap();
        }
        let verdict = verify::verify(&o, &e, &Clock(102));
        assert!(matches!(verdict, Verdict::Protected(_)));
        let recovering = m
            .transition(observed(&m, Form::Joined, verdict), &Clock(102))
            .unwrap();
        assert_eq!(recovering.pending(), Some(Step::LoadPreTunnel));
    }
}

#[test]
fn recursive_inventory_includes_hidden_roots_and_incomplete_collection_fails_closed() {
    let inventory = parse::anchor_list(include_str!("fixtures/mac/anchors-hidden.txt")).unwrap();
    assert!(inventory.names().contains("_hidden"));
    assert!(inventory.names().contains("_hidden/nested"));
    let (mut o, e) = setup(Form::Joined);
    let tree = o.live_tree.as_mut().unwrap();
    // A collector that only saw top-level names cannot claim recursive completion.
    tree.before = parse::anchor_list("com.apple").unwrap();
    tree.after = tree.before.clone();
    tree.anchors.retain(|name, _| name == "com.apple");
    tree.complete = false;
    retime(&mut o, 100);
    assert_eq!(
        verify::verify(&o, &e, &Clock(102)),
        Verdict::NotProtected(Reason::Observation("incomplete live anchor traversal"))
    );
}

#[test]
fn delayed_proof_delivery_and_wake_during_verification_schedule_checked_flush() {
    for explicit_wake in [false, true] {
        let m = joined();
        let (o, e) = machine_fixture(&m, Form::Joined, 1, 100);
        let proof = verify::verify(&o, &e, &Clock(102));
        let mut m = if explicit_wake {
            let m = m
                .transition(
                    Event::Repair(Action::Rerender { form: Form::Joined }),
                    &Clock(102),
                )
                .unwrap();
            let m = m
                .transition(
                    Event::Completed(Step::ReplaceAnchor(Form::Joined)),
                    &Clock(102),
                )
                .unwrap();
            let (_, e) = machine_fixture(&m, Form::Joined, 1, 102);
            let m = m
                .transition(Event::ReadbackValidated(e.baseline), &Clock(102))
                .unwrap();
            let (o, e) = machine_fixture(&m, Form::Joined, 1, 102);
            let in_flight = observed(&m, Form::Joined, verify::verify(&o, &e, &Clock(102)));
            let m = m
                .transition(Event::InvalidateObservations { since: 105 }, &Clock(200))
                .unwrap();
            // The stale context settles the cancelled verification without publishing.
            m.transition(in_flight, &Clock(200)).unwrap()
        } else {
            m.transition(observed(&m, Form::Joined, proof), &Clock(200))
                .unwrap()
        };
        assert_eq!(m.pending(), Some(Step::FlushStates));
        assert!(
            m.transition(
                Event::StatesClean {
                    epoch: m.context().state_epoch,
                    completed_at: 199
                },
                &Clock(200)
            )
            .is_err()
        );
        m = m
            .transition(
                Event::StatesClean {
                    epoch: m.context().state_epoch,
                    completed_at: 200,
                },
                &Clock(200),
            )
            .unwrap();
        let (o, e) = machine_fixture(&m, Form::Joined, 1, 201);
        m = m
            .transition(
                observed(&m, Form::Joined, verify::verify(&o, &e, &Clock(202))),
                &Clock(202),
            )
            .unwrap();
        assert!(matches!(
            m.enforcement_at(&Clock(202)),
            Verdict::Protected(_)
        ));
    }
}

#[test]
fn replacement_readback_that_changes_stateful_permissions_requires_full_rejoin() {
    for change_endpoint in [false, true] {
        let m = joined()
            .transition(
                Event::Repair(Action::Rerender { form: Form::Joined }),
                &Clock(102),
            )
            .unwrap();
        let m = m
            .transition(
                Event::Completed(Step::ReplaceAnchor(Form::Joined)),
                &Clock(102),
            )
            .unwrap();
        let old = inputs(false, false);
        let changed = Inputs::new(
            old.selected().clone(),
            if change_endpoint {
                "198.51.100.7:51821".parse().unwrap()
            } else {
                old.endpoint().clone()
            },
            old.physical().clone(),
            if change_endpoint {
                tunnel(1)
            } else {
                tunnel(2)
            },
            old.hop_limit().clone(),
        )
        .unwrap();
        let (_, e) = replacement_fixture(&m, &changed, 102);
        let m = m
            .transition(Event::ReadbackValidated(e.baseline), &Clock(102))
            .unwrap();
        assert_eq!(m.pending(), Some(Step::LoadPreTunnel));
        assert!(!matches!(
            m.enforcement_at(&Clock(102)),
            Verdict::Protected(_)
        ));
    }
}

// Fair executor: waits for deadlines, advances generations and collects fresh proofs.
fn executor_time(m: &Machine, now: u64) -> u64 {
    match m.pending() {
        Some(Step::Backoff { until }) => now.max(until),
        _ => now,
    }
}
fn checked_completion_at(m: &Machine, now: u64) -> Event {
    let generation = m.durable().previous_generation.map_or(1, |g| {
        g.value() + u64::from(m.pending() == Some(Step::ReserveGeneration))
    });
    match m.pending().unwrap() {
        Step::VerifyPreTunnel | Step::VerifyJoined => {
            let form = m.installed_form().unwrap();
            let (mut o, e) = machine_fixture(m, form, generation, now);
            if m.states_clean_at().is_none() {
                o.states = StateEvidence::Unproven;
            }
            observed(m, form, verify::verify(&o, &e, &Clock(now)))
        }
        Step::FlushStates => Event::StatesClean {
            epoch: m.context().state_epoch,
            completed_at: now,
        },
        Step::RemoveVanishedInterfaceStates => Event::InterfaceStatesRemoved {
            interfaces: m.vanished_interfaces().clone(),
            completed_at: now,
        },
        _ => complete_event(m, generation),
    }
}

// Fair fixture executors have same-boot evidence for these modeled tokens.
// Production summaries alone cannot discard them: send exact settlements first.
fn settle_modeled_predecessors(mut m: Machine, now: u64) -> Machine {
    if m.pending() == Some(Step::ReconcileReference)
        && m.durable().pf_reference.is_some()
        && m.durable().join_intended
        && !m.durable().leave_requested
        && !m.durable().leaving
    {
        for token in m.durable().older_references.clone() {
            m = settled(
                &m,
                ReferenceEntry::Token(token),
                ReferenceSettlement::Released,
                now,
            );
        }
    }
    m
}

#[test]
#[allow(clippy::too_many_lines)] // Exercise both recovery modes at every interrupted boundary.
fn aborted_join_and_recover_resume_automatically_until_joined() {
    for recovering in [false, true] {
        for interrupted in [
            Step::StartChild,
            Step::ConfigureDns,
            Step::VerifyPreTunnel,
            Step::LoadJoined,
        ] {
            let mut m = if recovering {
                joined()
                    .transition(Event::Repair(Action::RecreateChild), &Clock(102))
                    .unwrap()
            } else {
                Machine::restart(Durable::default())
                    .transition(Event::Join, &Clock(102))
                    .unwrap()
            };
            let mut now = 102;
            while m.pending() != Some(interrupted) {
                now = executor_time(&m, now + 1);
                m = m
                    .transition(checked_completion_at(&m, now), &Clock(now))
                    .unwrap();
            }
            let cause = Reason::Observation("DNS configuration failed");
            match interrupted {
                Step::StartChild | Step::LoadJoined => {
                    m = m
                        .transition(Event::InvalidateObservations { since: now }, &Clock(now))
                        .unwrap();
                    assert_eq!(m.pending(), Some(interrupted));
                    m = m
                        .transition(checked_completion_at(&m, now), &Clock(now))
                        .unwrap();
                }
                Step::ConfigureDns => {
                    m = m
                        .transition(Event::Failed(cause.clone()), &Clock(now))
                        .unwrap();
                    assert_eq!(m.failure(), Some(&cause));
                }
                Step::VerifyPreTunnel => {
                    let proof = checked_completion_at(&m, now);
                    now += 6; // Refuse an otherwise valid proof delivered after its expiry.
                    m = m.transition(proof, &Clock(now)).unwrap();
                }
                _ => unreachable!(),
            }
            assert_eq!(m.pending(), Some(Step::LoadPreTunnel));
            assert_eq!(
                m.status_at(&Clock(now)),
                ConnectionStatus::JoiningRecovering
            );
            let mut steps = Vec::new();
            for _ in 0..60 {
                let Some(step) = m.pending() else { break };
                steps.push(step);
                now = executor_time(&m, now + 1);
                m = m
                    .transition(checked_completion_at(&m, now), &Clock(now))
                    .unwrap();
                if let Verdict::Protected(p) = m.enforcement_at(&Clock(now)) {
                    if p.form() == Form::PreTunnel {
                        assert!(matches!(
                            m.status_at(&Clock(now)),
                            ConnectionStatus::JoiningRecovering
                                | ConnectionStatus::Recovering { .. }
                        ));
                        assert!(m.pending().is_some());
                    }
                    if p.form() == Form::Joined {
                        assert_eq!(m.failure(), None);
                        continue;
                    }
                }
                if interrupted == Step::ConfigureDns {
                    assert_eq!(m.failure(), Some(&cause));
                }
            }
            let closing: Vec<_> = steps
                .iter()
                .copied()
                .filter(|s| !matches!(s, Step::Backoff { .. }))
                .collect();
            assert_eq!(
                &closing[..5],
                &[
                    Step::LoadPreTunnel,
                    Step::VerifyPreTunnelLoad,
                    Step::FlushStates,
                    Step::VerifyPreTunnel,
                    Step::StopChild,
                ]
            );
            assert_eq!(m.pending(), None);
            assert!(
                matches!(m.enforcement_at(&Clock(now)), Verdict::Protected(p) if p.form() == Form::Joined)
            );
            assert_eq!(m.status_at(&Clock(now)), ConnectionStatus::Joined);
            assert_eq!(
                m.status_at(&Clock(now + 6)),
                ConnectionStatus::JoiningRecovering
            );
        }
    }
}

#[test]
fn recovered_reference_reconciliation_clears_its_error_after_joined() {
    let mut m = Machine::restart(joined().durable().clone());
    let mut now = 102;
    if m.pending() == Some(Step::PersistIntent) {
        m = property_transition(&m, Event::Completed(Step::PersistIntent), now);
    }
    for _ in 0..24 {
        if m.pending().is_none() {
            break;
        }
        now = executor_time(&m, now + 1);
        m = settle_modeled_predecessors(m, now);
        m = property_transition(&m, checked_completion_at(&m, now), now);
    }
    now = executor_time(&m, now + 1);
    assert_eq!(m.pending(), Some(Step::ReconcileReference));
    assert!(
        matches!(m.enforcement_at(&Clock(now)), Verdict::Protected(p) if p.form() == Form::Joined)
    );
    m = property_transition(&m, Event::Failed(Reason::Observation("effect failed")), now);
    assert_eq!(m.failure(), Some(&Reason::Observation("effect failed")));
    assert!(m.durable().reference_error.is_some());
    assert!(
        matches!(m.enforcement_at(&Clock(now)), Verdict::Protected(p) if p.form() == Form::Joined)
    );
    for _ in 0..160 {
        if m.pending().is_none() {
            break;
        }
        now = executor_time(&m, now + 1);
        m = settle_modeled_predecessors(m, now);
        m = property_transition(&m, checked_completion_at(&m, now), now);
    }
    assert_eq!(m.pending(), None);
    assert!(
        matches!(m.enforcement_at(&Clock(now)), Verdict::Protected(p) if p.form() == Form::Joined)
    );
    assert_eq!(m.failure(), None);
    assert!(m.durable().reference_error.is_none());
    assert_eq!(m.durable().older_references, [] as [u64; 0]);
}

proptest! {
    #[test]
    fn join_intent_never_parks_pre_tunnel_and_fair_completion_reaches_joined(
        recovering in any::<bool>(),
        initial_completions in 0usize..35,
        persistent_failure in any::<bool>(),
        fault_index in 0usize..8,
        disturbances in prop::collection::vec(0u8..9, 0..80),
    ) {
        let mut m = if recovering {
            Machine::restart(joined().durable().clone())
        } else {
            Machine::restart(Durable::default()).transition(Event::Join, &Clock(102)).unwrap()
        };
        let mut now = 102;
        if m.pending() == Some(Step::PersistIntent) {
            m = property_transition(&m, Event::Completed(Step::PersistIntent), now);
        }
        for _ in 0..initial_completions {
            if m.pending().is_none() { break; }
            now = executor_time(&m, now + 1);
            m = settle_modeled_predecessors(m, now);
            m = property_transition(&m, checked_completion_at(&m, now), now);
        }
        for disturbance in disturbances {
            now = executor_time(&m, now + 1);
            let event = match disturbance {
                0 => Event::InvalidateObservations { since: now },
                1 => Event::Failed(Reason::Observation("effect failed")),
                2 => Event::ChildDied,
                3 => observed(&m, m.installed_form().unwrap_or(Form::PreTunnel), Verdict::Unknown { since: now }),
                4 => observed(&m, m.installed_form().unwrap_or(Form::PreTunnel), Verdict::Repair(Action::EnableAndRejoin)),
                5 => observed(&m, m.installed_form().unwrap_or(Form::PreTunnel), Verdict::Repair(Action::Rejoin)),
                7 => observed(&m, m.installed_form().unwrap_or(Form::PreTunnel), Verdict::NotProtected(Reason::HookMissing)),
                8 => observed(&m, m.installed_form().unwrap_or(Form::PreTunnel), Verdict::Repair(Action::Rerender { form: m.installed_form().unwrap_or(Form::PreTunnel) })),
                _ if m.pending().is_some() => checked_completion_at(&m, now),
                _ => Event::InvalidateObservations { since: now },
            };
            m = property_transition(&m, event, now);
            if m.durable().join_intended {
                prop_assert!(m.pending().is_some()
                    || (m.installed_form() == Some(Form::Joined) && m.tunnel().is_some()));
            }
            if m.status_at(&Clock(now)) == ConnectionStatus::Joined {
                prop_assert!(matches!(m.enforcement_at(&Clock(now)), Verdict::Protected(p) if p.form() == Form::Joined));
            }
        }
        // Exercise persistent failures in the safety prefix, cleanup and rejoin suffix.
        let fault = [Step::AcquireReference, Step::LoadPreTunnel, Step::FlushStates,
            Step::VerifyPreTunnel, Step::CleanupDns, Step::CheckTools,
            Step::StartChild, Step::ConfigureDns][fault_index];
        for _ in 0..100 {
            if m.pending().is_none() { break; }
            now = executor_time(&m, now + 1);
            m = settle_modeled_predecessors(m, now);
            let event = if persistent_failure && m.pending() == Some(fault) {
                Event::Failed(Reason::Observation("persistent executor failure"))
            } else {
                checked_completion_at(&m, now)
            };
            m = property_transition(&m, event, now);
            prop_assert!(m.pending().is_some()
                || (m.installed_form() == Some(Form::Joined) && m.tunnel().is_some()));
        }
        let joined = matches!(m.enforcement_at(&Clock(now)), Verdict::Protected(p) if p.form() == Form::Joined);
        prop_assert!(joined || m.failure().is_some());
        // Fault clears: fair completion alone must reach fresh Protected(Joined),
        // even after persistent failure, without any user Join/Repair event.
        for _ in 0..60 {
            if m.pending().is_none() { break; }
            now = executor_time(&m, now + 1);
            if m.pending() == Some(Step::ReconcileReference) {
                // This fault model proves the synthetic lost acquire had no effect.
                for sequence in m.durable().uncertain_acquires.clone() {
                    m = settled(&m, ReferenceEntry::Acquire(sequence), ReferenceSettlement::Void, now);
                }
                m = settle_modeled_predecessors(m, now);
            }
            m = property_transition(&m, checked_completion_at(&m, now), now);
        }
        prop_assert_eq!(m.pending(), None);
        prop_assert!(matches!(m.enforcement_at(&Clock(now)), Verdict::Protected(p) if p.form() == Form::Joined));
        prop_assert_eq!(m.failure(), None);
    }
}

// Zero-duration checked effects exercise the worst possible retry rate.
fn drive_to(mut m: Machine, target: Option<Step>, now: &mut u64) -> Machine {
    for _ in 0..100 {
        if m.pending() == target || target.is_none() && m.connectivity_restored() {
            return m;
        }
        *now = executor_time(&m, *now);
        m = settle_modeled_predecessors(m, *now);
        m = m
            .transition(checked_completion_at(&m, *now), &Clock(*now))
            .unwrap();
    }
    panic!("executor did not reach {target:?}: {:?}", m.pending());
}

#[test]
fn persistent_faults_bound_attempts_in_a_five_minute_window() {
    for fault in [Step::CheckTools, Step::StartChild, Step::ConfigureDns] {
        let mut now = 102;
        let mut m = Machine::restart(Durable::default())
            .transition(Event::Join, &Clock(now))
            .unwrap();
        let reason = Reason::Observation("persistent fault");
        let mut failures = Vec::new();
        loop {
            m = drive_to(m, Some(fault), &mut now);
            failures.push(now - 102);
            m = m
                .transition(Event::Failed(reason.clone()), &Clock(now))
                .unwrap();
            assert_eq!(m.pending(), Some(Step::LoadPreTunnel));
            m = drive_to_backoff(m, &mut now);
            let Some(step @ Step::Backoff { until }) = m.pending() else {
                panic!("missing retry backoff after {fault:?}");
            };
            let waiting = m.clone();
            assert!(
                m.transition(Event::Completed(step), &Clock(until - 1))
                    .is_err()
            );
            assert_eq!(m, waiting); // Early completion cannot mutate the plan or journal.
            assert_eq!(m.failure(), Some(&reason));
            assert_eq!(
                m.status_at(&Clock(now)).to_string(),
                format!("recovering (retry in {}s)", until - now)
            );
            assert_eq!(
                m.status_at(&Clock(until + 100)),
                ConnectionStatus::Recovering { retry_in: 0 }
            );
            assert!(m.tunnel().is_none());
            assert_eq!(m.installed_form(), Some(Form::PreTunnel));
            assert!(m.states_clean_at().is_some());
            if until > 402 {
                break;
            }
            now = until;
            m = m.transition(Event::Completed(step), &Clock(now)).unwrap();
        }
        // One initial attempt, then 1, 2, 4, 8, 16, 32, 60, 60, ... seconds.
        assert_eq!(failures, [0, 1, 3, 7, 15, 31, 63, 123, 183, 243]);
        // After the fault clears, timers and checked completions alone reach Joined.
        m = drive_to(m, None, &mut now);
        assert!(
            matches!(m.enforcement_at(&Clock(now)), Verdict::Protected(p) if p.form() == Form::Joined)
        );
        assert_eq!(m.failure(), None);
    }
}

fn capped_backoff() -> (Machine, u64) {
    let mut now = 102;
    let mut m = Machine::restart(Durable::default())
        .transition(Event::Join, &Clock(now))
        .unwrap();
    for _ in 0..8 {
        m = drive_to(m, Some(Step::ConfigureDns), &mut now);
        m = m
            .transition(
                Event::Failed(Reason::Observation("DNS refused")),
                &Clock(now),
            )
            .unwrap();
    }
    m = drive_to_backoff(m, &mut now);
    assert_eq!(m.pending(), Some(Step::Backoff { until: now + 60 }));
    assert!(m.tunnel().is_none());
    assert_eq!(m.installed_form(), Some(Form::PreTunnel));
    assert_eq!(m.states_clean_at(), Some(now));
    (m, now)
}

#[test]
fn leave_cancels_backoff_immediately_and_completed_leave_resets_retries() {
    let (mut m, mut now) = capped_backoff();
    let timer = m.pending().unwrap();
    assert!(m.tunnel().is_none());
    m = m.transition(Event::Leave, &Clock(now)).unwrap();
    assert_eq!(m.pending(), Some(Step::PersistLeaving));
    assert_eq!(m.status_at(&Clock(now)), ConnectionStatus::Leaving);
    assert!(m.durable().leave_requested);
    assert!(
        m.transition(Event::Completed(timer), &Clock(now + 60))
            .is_err()
    );
    assert_eq!(
        Machine::restart(m.durable().clone()).pending(),
        Some(Step::PersistLeaving)
    );
    m = drive_to(m, None, &mut now);
    assert!(m.connectivity_restored());
    assert_eq!(m.failure(), None);
    m = m.transition(Event::Join, &Clock(now)).unwrap();
    m = drive_to(m, Some(Step::CheckTools), &mut now);
    m = m
        .transition(
            Event::Failed(Reason::Observation("tools missing")),
            &Clock(now),
        )
        .unwrap();
    assert_eq!(m.pending(), Some(Step::LoadPreTunnel));
    m = drive_to_backoff(m, &mut now);
    assert_eq!(m.pending(), Some(Step::Backoff { until: now + 1 }));
}

#[test]
fn protected_joined_resets_retries_but_pre_tunnel_success_does_not() {
    let (mut m, mut now) = capped_backoff();
    // Pre-tunnel successes in capped_backoff did not reset the increasing delay.
    m = drive_to(m, None, &mut now);
    assert!(
        matches!(m.enforcement_at(&Clock(now)), Verdict::Protected(p) if p.form() == Form::Joined)
    );
    m = m.transition(Event::ChildDied, &Clock(now)).unwrap();
    assert_eq!(m.pending(), Some(Step::LoadPreTunnel));
    m = drive_to(m, Some(Step::CheckTools), &mut now);
    m = m
        .transition(
            Event::Failed(Reason::Observation("tools missing")),
            &Clock(now),
        )
        .unwrap();
    assert_eq!(m.pending(), Some(Step::LoadPreTunnel));
    m = drive_to_backoff(m, &mut now);
    assert_eq!(m.pending(), Some(Step::Backoff { until: now + 1 }));
}

// Complete safety effects at the same clock instant; never complete a timer here.
fn drive_to_backoff(mut m: Machine, now: &mut u64) -> Machine {
    for _ in 0..30 {
        if matches!(m.pending(), Some(Step::Backoff { .. })) {
            return m;
        }
        m = m
            .transition(checked_completion_at(&m, *now), &Clock(*now))
            .unwrap();
    }
    panic!("safety prefix did not reach backoff");
}

#[test]
fn sleep_counts_toward_rejoin_deadline_and_leave_still_interrupts() {
    let (mut m, mut now) = capped_backoff();
    let timer = m.pending().unwrap();
    now += 3_600;
    m = m.transition(Event::Completed(timer), &Clock(now)).unwrap();
    // Sleep expired the proof as well as the delay. Reclose now, with the
    // elapsed rejoin delay already satisfied after fresh prefix success.
    assert_eq!(m.pending(), Some(Step::LoadPreTunnel));
    let woke_at = now;
    m = drive_to(m, Some(Step::CheckTools), &mut now);
    assert_eq!(now, woke_at);
    m = drive_to(m, None, &mut now);
    assert_eq!(m.status_at(&Clock(now)), ConnectionStatus::Joined);
    assert_eq!(m.failure(), None);
}

#[test]
fn negative_observations_during_capped_backoff_close_immediately() {
    for verdict in [
        Verdict::Repair(Action::EnableAndRejoin), // pf disabled
        Verdict::Repair(Action::Rejoin),          // owned anchor flushed
        Verdict::Repair(Action::RecreateChild),
        Verdict::Repair(Action::Rerender {
            form: Form::PreTunnel,
        }),
        Verdict::NotProtected(Reason::HookMissing),
        Verdict::Unknown { since: 100 },
    ] {
        let (mut m, mut now) = capped_backoff();
        let context = m.context();
        let reason = match &verdict {
            Verdict::Repair(action) => Reason::Repair(*action),
            Verdict::NotProtected(reason) => reason.clone(),
            Verdict::Unknown { since } => Reason::Unknown { since: *since },
            _ => unreachable!(),
        };
        let enable = verdict == Verdict::Repair(Action::EnableAndRejoin);
        m = m
            .transition(observed(&m, Form::PreTunnel, verdict), &Clock(now))
            .unwrap();
        assert_eq!(
            m.pending(),
            Some(if enable {
                Step::AcquireReference
            } else if matches!(reason, Reason::Unknown { .. }) {
                Step::FlushStates
            } else {
                Step::LoadPreTunnel
            })
        );
        assert_eq!(m.durable().retry_attempts, 7);
        if matches!(reason, Reason::Unknown { .. }) {
            assert_eq!(m.failure(), Some(&Reason::Observation("DNS refused")));
            assert_eq!(m.durable().enforcement_error, Some(reason.clone()));
        } else {
            assert_eq!(m.failure(), Some(&reason));
        }
        assert_ne!(m.context(), context);
        assert_eq!(m.states_clean_at(), None);
        assert!(!matches!(
            m.enforcement_at(&Clock(now)),
            Verdict::Protected(_)
        ));
        // All closing effects, including load and flush, finish without advancing time.
        m = drive_to_backoff(m, &mut now);
        assert_eq!(m.installed_form(), Some(Form::PreTunnel));
        assert_eq!(m.states_clean_at(), Some(now));
        assert!(m.tunnel().is_none());
        assert_eq!(m.pending(), Some(Step::Backoff { until: now + 1 }));
        assert_eq!(m.durable().enforcement_error, Some(reason.clone()));
        m = m.transition(Event::Leave, &Clock(now)).unwrap();
        assert_eq!(m.pending(), Some(Step::PersistLeaving));
    }
}

#[test]
fn failed_joined_recheck_flush_closes_now_and_retries_flush_within_one_second() {
    let mut now = 102;
    let mut m = joined()
        .transition(Event::InvalidateObservations { since: now }, &Clock(now))
        .unwrap();
    assert_eq!(m.pending(), Some(Step::FlushStates));
    let reason = Reason::Observation("flush failed");
    m = m
        .transition(Event::Failed(reason.clone()), &Clock(now))
        .unwrap();
    assert_eq!(m.pending(), Some(Step::LoadPreTunnel));
    m = drive_to(m, Some(Step::FlushStates), &mut now);
    assert_eq!(now, 102);
    // Subsequent failure of this closing flush may delay only that same step, <=1s.
    for _ in 0..10 {
        let failed_at = now;
        m = m
            .transition(Event::Failed(reason.clone()), &Clock(now))
            .unwrap();
        assert_eq!(m.pending(), Some(Step::LoadPreTunnel));
        m = drive_to_backoff(m, &mut now);
        assert_eq!(
            m.pending(),
            Some(Step::Backoff {
                until: failed_at + 1
            })
        );
        m = drive_to(m, Some(Step::FlushStates), &mut now);
        assert!(now <= failed_at + 1);
    }
    m = drive_to(m, None, &mut now);
    assert_eq!(m.status_at(&Clock(now)), ConnectionStatus::Joined);
}

#[test]
fn restart_preserves_retry_counter_and_waits_after_fresh_safety_prefix() {
    let (mut m, mut now) = capped_backoff();
    for _ in 0..3 {
        now += 1_000; // Restart is not clock zero and may occur after the old deadline.
        let mut durable = m.durable().clone();
        durable.pf_reference = None;
        durable.older_references.clear();
        m = Machine::restart(durable);
        assert_eq!(m.pending(), Some(Step::AcquireReference));
        assert_eq!(m.durable().retry_attempts, 7);
        m = drive_to_backoff(m, &mut now);
        assert_eq!(m.pending(), Some(Step::Backoff { until: now + 60 }));
    }
}

#[test]
fn bare_unknown_survives_replanning_and_records_its_reason() {
    let mut now = 102;
    let mut m = Machine::restart(Durable::default())
        .transition(Event::Join, &Clock(now))
        .unwrap();
    m = drive_to(m, Some(Step::VerifyPreTunnel), &mut now);
    m = m
        .transition(
            observed(&m, Form::PreTunnel, Verdict::Unknown { since: now }),
            &Clock(now),
        )
        .unwrap();
    assert_eq!(m.pending(), Some(Step::LoadPreTunnel));
    assert_eq!(
        m.enforcement_at(&Clock(now)),
        Verdict::Unknown { since: now }
    );
    assert_eq!(m.failure(), Some(&Reason::Unknown { since: now }));
    // The failed closing verification retries within one second and stays Unknown.
    m = drive_to_backoff(m, &mut now);
    assert_eq!(m.pending(), Some(Step::Backoff { until: now + 1 }));
    assert_eq!(
        m.enforcement_at(&Clock(now)),
        Verdict::Unknown { since: now }
    );
    assert_eq!(m.failure(), Some(&Reason::Unknown { since: now }));
    // Unknown at the wait queues fresh cleanup without moving the verification deadline.
    m = m
        .transition(
            observed(&m, Form::PreTunnel, Verdict::Unknown { since: now }),
            &Clock(now),
        )
        .unwrap();
    assert_eq!(m.pending(), Some(Step::FlushStates));
    m = drive_to_backoff(m, &mut now);
    assert_eq!(m.pending(), Some(Step::Backoff { until: now + 1 }));
    assert_eq!(
        m.enforcement_at(&Clock(now)),
        Verdict::Unknown { since: now }
    );
    m = drive_to(m, None, &mut now);
    assert_eq!(m.failure(), None);
}

#[test]
fn closing_failures_delay_only_the_same_action_and_never_more_than_one_second() {
    for fault in [
        Step::LoadPreTunnel,
        Step::VerifyPreTunnelLoad,
        Step::FlushStates,
        Step::VerifyPreTunnel,
        Step::StopChild,
        Step::CleanupRoutes,
        Step::CleanupDns,
        Step::CleanupArtifacts,
    ] {
        let (mut m, mut now) = capped_backoff();
        m = m
            .transition(
                observed(
                    &m,
                    Form::PreTunnel,
                    Verdict::Repair(Action::EnableAndRejoin),
                ),
                &Clock(now),
            )
            .unwrap();
        m = drive_to(m, Some(fault), &mut now);
        let failed_at = now;
        m = m
            .transition(
                Event::Failed(Reason::Observation("closing failed")),
                &Clock(now),
            )
            .unwrap();
        // Earlier closing steps execute at the same instant. Only the failed action waits.
        m = drive_to_backoff(m, &mut now);
        assert_eq!(now, failed_at);
        let timer = m.pending().unwrap();
        assert_eq!(
            timer,
            Step::Backoff {
                until: failed_at + 1
            }
        );
        now += 1;
        m = m.transition(Event::Completed(timer), &Clock(now)).unwrap();
        assert_eq!(m.pending(), Some(fault));
        m = drive_to(m, None, &mut now);
        assert_eq!(m.status_at(&Clock(now)), ConnectionStatus::Joined);
    }
}

#[test]
fn wake_and_child_loss_during_backoff_reestablish_state_cleanliness_before_rejoin() {
    for child_loss in [false, true] {
        let (mut m, mut now) = capped_backoff();
        let event = if child_loss {
            Event::ChildDied
        } else {
            Event::InvalidateObservations { since: now }
        };
        let before = m.clone();
        m = m.transition(event, &Clock(now)).unwrap();
        if child_loss {
            assert_eq!(m, before);
            continue;
        }
        assert_eq!(m.pending(), Some(Step::LoadPreTunnel));
        assert_eq!(m.states_clean_at(), None);
        m = drive_to_backoff(m, &mut now);
        assert_eq!(m.states_clean_at(), Some(now));
        m = drive_to(m, None, &mut now);
        assert_eq!(m.status_at(&Clock(now)), ConnectionStatus::Joined);
    }
}

#[test]
fn pf_disable_or_anchor_flush_during_sixty_second_backoff_closes_without_waiting() {
    for disabled in [false, true] {
        for during_backoff in [false, true] {
            let (mut m, mut now) = capped_backoff();
            if !during_backoff {
                m = m
                    .transition(
                        observed(&m, Form::PreTunnel, Verdict::Repair(Action::Rejoin)),
                        &Clock(now),
                    )
                    .unwrap();
                m = drive_to(m, Some(Step::VerifyPreTunnel), &mut now);
            }
            let generation = m.durable().previous_generation.unwrap().value();
            let (mut o, e) = machine_fixture(&m, Form::PreTunnel, generation, now);
            if disabled {
                o.pf.as_mut().unwrap().enabled = false;
            } else {
                o.anchor = Ok(None);
                o.live_tree
                    .as_mut()
                    .unwrap()
                    .anchors
                    .get_mut("com.apple/scupper")
                    .unwrap()
                    .rules = parse::pf_rules("");
            }
            let action = if disabled {
                Action::EnableAndRejoin
            } else {
                Action::Rejoin
            };
            let verdict = verify::verify(&o, &e, &Clock(now));
            assert_eq!(verdict, Verdict::Repair(action));
            m = m
                .transition(observed(&m, Form::PreTunnel, verdict), &Clock(now))
                .unwrap();
            assert_eq!(
                m.pending(),
                Some(if disabled {
                    Step::AcquireReference
                } else {
                    Step::LoadPreTunnel
                })
            );
            assert_eq!(m.failure(), Some(&Reason::Repair(action)));
            let repaired_at = now;
            m = drive_to_backoff(m, &mut now);
            assert_eq!(now, repaired_at);
            assert_eq!(m.states_clean_at(), Some(repaired_at));
            assert_eq!(m.installed_form(), Some(Form::PreTunnel));
            assert!(m.tunnel().is_none());
            assert_eq!(m.pending(), Some(Step::Backoff { until: now + 1 }));
            assert_eq!(m.plan()[1], Step::VerifyPreTunnel);
            assert_eq!(
                m.enforcement_at(&Clock(now)),
                Verdict::Unknown { since: repaired_at }
            );
        }
    }
}

fn property_transition(m: &Machine, event: Event, now: u64) -> Machine {
    let verification_result = matches!(event, Event::Observed { .. })
        && matches!(
            m.pending(),
            Some(Step::VerifyPreTunnel | Step::VerifyJoined)
        );
    let completion = verification_result
        || matches!(
            event,
            Event::Completed(_)
                | Event::ReferenceAcquired(_)
                | Event::ReadbackValidated(_)
                | Event::StatesClean { .. }
                | Event::InterfaceStatesRemoved { .. }
        );
    if completion
        && let Some(retry) = m.closing_retry()
        && m.pending() == Some(retry.target)
    {
        assert!(
            now >= retry.until,
            "retry executed early: {retry:?} at {now}"
        );
    }
    let noise = matches!(
        event,
        Event::InvalidateObservations { .. }
            | Event::ChildDied
            | Event::Observed {
                verdict: Verdict::Repair(_) | Verdict::Unknown { .. },
                ..
            }
    );
    let next = m.transition(event, &Clock(now)).unwrap();
    if noise
        && !verification_result
        && let Some(old) = m.closing_retry()
    {
        assert_eq!(
            next.closing_retry().unwrap().until,
            old.until,
            "replanning moved a deadline"
        );
    }
    assert_backoff_invariant(&next, now);
    next
}

fn assert_backoff_invariant(m: &Machine, now: u64) {
    assert!(m.durable().older_references.len() <= 1);
    if let Some(Step::Backoff { until }) = m.pending() {
        let target = m.plan()[1];
        if target == Step::ReconcileReference {
            assert!(until <= now + 1);
            return;
        }
        if target == Step::CheckTools {
            assert_eq!(m.installed_form(), Some(Form::PreTunnel));
            assert!(m.tunnel().is_none());
            let clean = m.states_clean_at().unwrap();
            assert!(m.gap_after().is_none_or(|gap| clean >= gap));
        } else {
            let retry = m.closing_retry().unwrap_or_else(|| {
                panic!(
                    "no closing_retry: target={target:?} plan={:?} pending={:?}",
                    m.plan(),
                    m.pending()
                )
            });
            assert_eq!(retry.until, retry.failed_at + 1);
            assert_eq!(retry.until, until);
            assert_eq!(retry.target, target);
            assert!(until <= now + 1);
            assert!(
                m.transition(
                    Event::Completed(Step::Backoff { until }),
                    &Clock(retry.failed_at)
                )
                .is_err()
            );
        }
    }
}

#[test]
fn persistent_repair_verdicts_bound_closing_completions_for_five_minutes() {
    for action in [
        Action::EnableAndRejoin,
        Action::Rejoin,
        Action::Rerender {
            form: Form::PreTunnel,
        },
    ] {
        let mut now = 102;
        let m = joined();
        let mut m = m
            .transition(
                observed(
                    &m,
                    Form::Joined,
                    Verdict::Repair(if action == Action::EnableAndRejoin {
                        action
                    } else {
                        Action::Rejoin
                    }),
                ),
                &Clock(now),
            )
            .unwrap();
        assert_eq!(
            m.pending(),
            Some(if action == Action::EnableAndRejoin {
                Step::AcquireReference
            } else {
                Step::LoadPreTunnel
            })
        );
        let mut loads = 0;
        let mut acquires = 0;
        let mut verifications = Vec::new();
        let mut transitions = 0;
        while now <= 402 {
            transitions += 1;
            assert!(transitions < 20_000, "same-instant closing loop");
            let step = m.pending().unwrap();
            if let Step::Backoff { until } = step {
                assert_backoff_invariant(&m, now);
                if until > 402 {
                    break;
                }
                now = until;
            }
            let event = if step == Step::VerifyPreTunnel {
                verifications.push(now);
                observed(&m, Form::PreTunnel, Verdict::Repair(action))
            } else {
                checked_completion_at(&m, now)
            };
            loads += usize::from(step == Step::LoadPreTunnel);
            acquires += usize::from(step == Step::AcquireReference);
            m = m.transition(event, &Clock(now)).unwrap();
            assert_backoff_invariant(&m, now);
            assert!(!matches!(
                m.enforcement_at(&Clock(now)),
                Verdict::Protected(_)
            ));
        }
        assert!((300..=302).contains(&loads), "{action:?}: {loads}");
        assert!(acquires <= 302);
        assert_eq!(verifications[0], 102); // immediate first prefix, then paced verification
        assert!(verifications.windows(2).all(|v| v[1] > v[0]));
        assert_eq!(m.durable().retry_attempts, 0); // no rejoin attempt was made
    }
}

#[test]
fn repair_at_verify_joined_recovers_to_pre_tunnel_with_exact_retry_target() {
    for action in [
        Action::EnableAndRejoin,
        Action::Rejoin,
        Action::Rerender { form: Form::Joined },
    ] {
        let mut now = 102;
        let mut m = Machine::restart(Durable::default())
            .transition(Event::Join, &Clock(now))
            .unwrap();
        m = drive_to(m, Some(Step::VerifyJoined), &mut now);
        m = m
            .transition(
                observed(&m, Form::Joined, Verdict::Repair(action)),
                &Clock(now),
            )
            .unwrap();
        assert_eq!(
            m.closing_retry(),
            Some(ClosingRetry {
                failed_at: now,
                target: Step::VerifyPreTunnel,
                until: now + 1
            })
        );
        assert_eq!(
            m.pending(),
            Some(if action == Action::EnableAndRejoin {
                Step::AcquireReference
            } else {
                Step::LoadPreTunnel
            })
        );
        assert_eq!(m.durable().retry_attempts, 1);
        assert_eq!(m.failure(), Some(&Reason::Repair(action)));
        m = drive_to_backoff(m, &mut now);
        assert_eq!(m.plan()[1], Step::VerifyPreTunnel);
        assert_eq!(
            m.enforcement_at(&Clock(now)),
            Verdict::Unknown { since: now }
        );
        assert_backoff_invariant(&m, now);
    }
}

#[test]
fn replan_below_saturation_preserves_counter_and_original_deadline() {
    for failures in [1, 2, 3] {
        for action in [None, Some(Action::Rejoin), Some(Action::EnableAndRejoin)] {
            let mut now = 102;
            let mut m = Machine::restart(Durable::default())
                .transition(Event::Join, &Clock(now))
                .unwrap();
            for _ in 0..failures {
                m = drive_to(m, Some(Step::ConfigureDns), &mut now);
                m = m
                    .transition(
                        Event::Failed(Reason::Observation("DNS refused")),
                        &Clock(now),
                    )
                    .unwrap();
            }
            m = drive_to_backoff(m, &mut now);
            let original = m.pending().unwrap();
            let Step::Backoff { until } = original else {
                unreachable!()
            };
            let event = observed(
                &m,
                Form::PreTunnel,
                action.map_or(Verdict::Unknown { since: now }, Verdict::Repair),
            );
            m = m.transition(event, &Clock(now)).unwrap();
            assert_eq!(m.durable().retry_attempts, failures);
            let mut early_now = now;
            let early = drive_to(m.clone(), Some(Step::CheckTools), &mut early_now);
            assert_eq!(early_now, until); // no deadline restart, including 1 s backoff
            assert_eq!(early.durable().retry_attempts, failures);
            // Finish prefix after the original delay: it is already satisfied.
            now = until + 2;
            m = drive_to(m, Some(Step::CheckTools), &mut now);
            assert_eq!(now, until + 2);
            assert_eq!(m.durable().retry_attempts, failures);
            m = m
                .transition(Event::Failed(Reason::ToolIntegrity), &Clock(now))
                .unwrap();
            assert_eq!(m.durable().retry_attempts, failures + 1);
        }
    }
}

#[test]
fn refresh_during_rejoin_wait_preserves_plan_connection_error_and_gap_history() {
    let (mut m, now) = capped_backoff();
    let plan = m.plan().to_vec();
    let failure = m.failure().cloned();
    let generation = m.durable().previous_generation.unwrap().value();
    for elapsed in (4..=32).step_by(4) {
        let at = now + elapsed;
        let (o, e) = machine_fixture(&m, Form::PreTunnel, generation, at);
        let event = observed(&m, Form::PreTunnel, verify::verify(&o, &e, &Clock(at)));
        m = m.transition(event, &Clock(at)).unwrap();
        assert_eq!(m.plan(), plan);
        assert_eq!(m.failure(), failure.as_ref());
        assert_eq!(m.durable().retry_attempts, 7);
        assert_eq!(m.last_verified(), Some(at));
        assert_eq!(
            m.status_text_at(&Clock(at)),
            "traffic blocked; tunnel recovering"
        );
        assert!(
            matches!(m.enforcement_at(&Clock(at)), Verdict::Protected(p) if p.form() == Form::PreTunnel)
        );
    }
    // A rejected refresh retains its detected gap and immediately recloses.
    let (o, e) = machine_fixture(&m, Form::PreTunnel, generation, now + 40);
    let gap = m
        .transition(
            observed(
                &m,
                Form::PreTunnel,
                verify::verify(&o, &e, &Clock(now + 40)),
            ),
            &Clock(now + 40),
        )
        .unwrap();
    assert_eq!(gap.pending(), Some(Step::LoadPreTunnel));
    assert!(gap.gap_after().is_some());
    // Context/generation, baseline, expiration and observation ordering still apply.
    let (o, mut e) = machine_fixture(&m, Form::PreTunnel, generation, now + 33);
    e.context.lifecycle_revision += 1;
    assert!(
        m.transition(
            observed(
                &m,
                Form::PreTunnel,
                verify::verify(&o, &e, &Clock(now + 33))
            ),
            &Clock(now + 33)
        )
        .is_err()
    );
    // A fresh proof cannot silently switch the selected transport configuration.
    let at = now + 33;
    let (mut o, mut e) = machine_fixture(&m, Form::PreTunnel, generation, at);
    let changed = "192.0.2.8".parse().unwrap();
    o.local_address = Ok(changed);
    e.transport.local_address = changed;
    let verdict = verify::verify(&o, &e, &Clock(at));
    assert!(matches!(verdict, Verdict::Protected(_)));
    let replanned = m
        .transition(observed(&m, Form::PreTunnel, verdict), &Clock(at))
        .unwrap();
    assert_eq!(replanned.pending(), Some(Step::LoadPreTunnel));
    assert_eq!(replanned.durable().retry_attempts, 7);
    assert_eq!(replanned.failure(), failure.as_ref());
}

#[test]
fn unknown_enforcement_does_not_replace_a_connection_failure_and_restart_drops_clock_evidence() {
    let mut now = 102;
    let mut m = Machine::restart(Durable::default())
        .transition(Event::Join, &Clock(now))
        .unwrap();
    m = drive_to(m, Some(Step::ConfigureDns), &mut now);
    let connection = Reason::Observation("DNS refused");
    m = m
        .transition(Event::Failed(connection.clone()), &Clock(now))
        .unwrap();
    m = drive_to(m, Some(Step::VerifyPreTunnel), &mut now);
    m = m
        .transition(
            observed(&m, Form::PreTunnel, Verdict::Unknown { since: now }),
            &Clock(now),
        )
        .unwrap();
    assert_eq!(
        m.enforcement_at(&Clock(now)),
        Verdict::Unknown { since: now }
    );
    assert_eq!(m.failure(), Some(&connection));
    let restarted = Machine::restart(m.durable().clone());
    assert_eq!(
        restarted.enforcement_at(&Clock(0)),
        Verdict::Unknown { since: 0 }
    );
    assert!(restarted.states_clean_at().is_none());
    assert!(restarted.last_verified().is_none());
    assert_ne!(restarted.context(), m.context());
}

#[test]
fn unresolved_reference_operations_reconcile_before_another_acquisition_and_leave_retains_all() {
    let mut now = 102;
    let m = Machine::restart(Durable::default())
        .transition(Event::Join, &Clock(now))
        .unwrap();
    let m = m
        .transition(Event::Completed(Step::PersistIntent), &Clock(now))
        .unwrap();
    assert_eq!(
        m.durable().reference_intent,
        Some(ReferenceIntent::Acquire(1))
    );
    // A crash occupies one uncertain slot. One replacement can still enable pf,
    // while failed reconciliation cannot delay the safety prefix.
    let mut r = Machine::restart(m.durable().clone());
    assert_eq!(r.pending(), Some(Step::ReconcileReference));
    r = r
        .transition(
            Event::Failed(Reason::Observation("acquire outcome unresolved")),
            &Clock(now),
        )
        .unwrap();
    assert_eq!(r.pending(), Some(Step::AcquireReference));
    assert_eq!(r.durable().uncertain_acquires, vec![1]);
    r = r
        .transition(Event::ReferenceAcquired(501), &Clock(now))
        .unwrap();
    r = drive_to(r, Some(Step::VerifyPreTunnel), &mut now);
    assert_eq!(r.states_clean_at(), Some(now));
    assert_eq!(r.durable().uncertain_acquires, vec![1]);
    assert!(
        r.status_text_at(&Clock(now))
            .contains("ownership cleanup debt")
    );
    // Two potentially live tokens are retained; replans never take a third.
    let mut durable = joined().durable().clone();
    durable.pf_reference = Some(501);
    durable.older_references = vec![500];
    durable.reference_intent = Some(ReferenceIntent::Release);
    let r = Machine::restart(durable);
    let mut r = r
        .transition(
            Event::ReferenceReconciled {
                context: r.context(),
                current: Some(501),
                predecessor: Some(500),
            },
            &Clock(now),
        )
        .unwrap();
    assert_eq!(r.pending(), Some(Step::LoadPreTunnel));
    assert_eq!(r.durable().older_references.len(), 1);
    r = drive_to(r, None, &mut now);
    assert_eq!(r.durable().older_references, [] as [u64; 0]);
    r = r.transition(Event::Leave, &Clock(now)).unwrap();
    r = drive_to(r, Some(Step::ClearIntent), &mut now);
    assert_eq!(r.durable().pf_reference, Some(501));
    assert_eq!(r.durable().older_references, [] as [u64; 0]);
    assert_eq!(r.durable().reference_intent, None);
    r = drive_to(r, None, &mut now);
    assert!(r.connectivity_restored());
}

#[test]
fn millisecond_disturbances_coalesce_during_both_backoffs_and_in_flight_replacement() {
    // Clock units are seconds; deliver one event every simulated millisecond,
    // including 1,000 distinct observations in each one-second wait.
    const SECONDS: u64 = 10;
    for start in 0..3 {
        let (mut m, base) = if start == 0 {
            capped_backoff()
        } else {
            let m = joined();
            let event = if start == 1 {
                observed(&m, Form::Joined, Verdict::Repair(Action::Rejoin))
            } else {
                Event::Repair(Action::Rerender { form: Form::Joined })
            };
            (m.transition(event, &Clock(102)).unwrap(), 102)
        };
        let mut loads = 0;
        let mut journal_writes = 0;
        let mut waits = 0;
        let mut mutations = 0;
        for ms in 0..SECONDS * 1_000 {
            let now = base + ms / 1_000;
            let at_verification = matches!(
                m.pending(),
                Some(Step::VerifyPreTunnel | Step::VerifyJoined)
            );
            let old_retry = m.closing_retry();
            let old_journal = m.durable().clone();
            let form = m.installed_form().unwrap_or(Form::PreTunnel);
            let verdict = match ms % 5 {
                0 => Verdict::Repair(Action::EnableAndRejoin),
                1 => Verdict::Repair(Action::Rejoin),
                2 => Verdict::Unknown { since: now },
                _ => Verdict::Repair(Action::Rerender { form }),
            };
            let event = if ms % 5 == 4 {
                Event::InvalidateObservations { since: now }
            } else {
                observed(&m, form, verdict)
            };
            m = m.transition(event, &Clock(now)).unwrap();
            journal_writes += usize::from(m.durable() != &old_journal);
            if !at_verification && let Some(old) = old_retry {
                assert_eq!(
                    m.closing_retry().unwrap().until,
                    old.until,
                    "event moved deadline at {ms}ms"
                );
            }
            let Some(step) = m.pending() else {
                continue;
            };
            if let Step::Backoff { until } = step {
                waits += 1;
                assert_backoff_invariant(&m, now);
                if now < until {
                    continue;
                }
            } else {
                mutations += 1;
            }
            let old_journal = m.durable().clone();
            loads += usize::from(matches!(step, Step::LoadPreTunnel | Step::ReplaceAnchor(_)));
            // Every new accepted loss can restart at the next effect boundary;
            // one effect settles before exposing the next serialized repair.
            assert!(loads <= mutations);
            m = m
                .transition(checked_completion_at(&m, now), &Clock(now))
                .unwrap();
            journal_writes += usize::from(m.durable() != &old_journal);
            assert_backoff_invariant(&m, now);
        }
        // Fresh rounds after a completed prefix may repair again within this second.
        assert!(loads > 0 && mutations > 0);
        assert!(journal_writes <= 4 * usize::try_from(SECONDS * 1_000).unwrap());
        let _ = waits;
    }
}

#[test]
fn rerender_is_benign_only_for_planned_replacement_with_a_valid_proof() {
    let m = joined();
    let action = Action::Rerender { form: Form::Joined };
    let planned = m
        .transition(
            observed(&m, Form::Joined, Verdict::Repair(action)),
            &Clock(102),
        )
        .unwrap();
    assert_eq!(planned.failure(), None);
    assert!(matches!(
        planned.enforcement_at(&Clock(102)),
        Verdict::Unknown { .. }
    ));
    assert_eq!(planned.pending(), Some(Step::ReplaceAnchor(Form::Joined)));
    let mut now = 102;
    let m = drive_to(planned, Some(Step::VerifyJoined), &mut now);
    let mismatch = m
        .transition(
            observed(&m, Form::Joined, Verdict::Repair(action)),
            &Clock(now),
        )
        .unwrap();
    assert_eq!(mismatch.failure(), Some(&Reason::Repair(action)));
    assert_eq!(mismatch.pending(), Some(Step::LoadPreTunnel));
    assert_eq!(
        mismatch.closing_retry().unwrap().target,
        Step::VerifyPreTunnel
    );
}

#[test]
fn repeated_child_loss_counts_one_failed_rejoin_attempt() {
    let mut now = 102;
    let m = Machine::restart(Durable::default())
        .transition(Event::Join, &Clock(now))
        .unwrap();
    let mut m = drive_to(m, Some(Step::ConfigureDns), &mut now);
    for _ in 0..10 {
        m = m.transition(Event::ChildDied, &Clock(now)).unwrap();
        assert_eq!(m.durable().retry_attempts, 1);
    }
    m = m
        .transition(Event::Completed(Step::ConfigureDns), &Clock(now))
        .unwrap();
    assert_eq!(m.durable().retry_attempts, 1);
    m = drive_to(m, Some(Step::CheckTools), &mut now);
    m = m
        .transition(Event::Failed(Reason::ToolIntegrity), &Clock(now))
        .unwrap();
    assert_eq!(m.durable().retry_attempts, 2);
}

#[test]
fn disable_during_in_flight_acquire_reconciles_ordering_before_reusing_the_token() {
    let now = 102;
    let m = Machine::restart(Durable::default())
        .transition(Event::Join, &Clock(now))
        .unwrap();
    let mut m = m
        .transition(Event::Completed(Step::PersistIntent), &Clock(now))
        .unwrap();
    m = m
        .transition(
            observed(
                &m,
                Form::PreTunnel,
                Verdict::Repair(Action::EnableAndRejoin),
            ),
            &Clock(now),
        )
        .unwrap();
    assert_eq!(m.pending(), Some(Step::AcquireReference));
    m = m
        .transition(Event::ReferenceAcquired(501), &Clock(now))
        .unwrap();
    assert_eq!(m.pending(), Some(Step::LoadPreTunnel));
    assert_eq!(m.durable().pf_reference, Some(501)); // possibly live: never discard on guessed ordering
    assert_eq!(m.durable().reference_intent, None);
    assert!(m.durable().reference_needs_reconcile);
    let restarted = Machine::restart(m.durable().clone());
    assert_eq!(restarted.pending(), Some(Step::ReconcileReference));
    // Executor proves the acquisition preceded the stop, making this token void.
    let restarted = restarted
        .transition(
            Event::ReferenceSettled {
                entry: ReferenceEntry::Token(501),
                how: ReferenceSettlement::Void,
            },
            &Clock(now),
        )
        .unwrap();
    let m = restarted
        .transition(
            Event::ReferenceReconciled {
                context: restarted.context(),
                current: None,
                predecessor: None,
            },
            &Clock(now),
        )
        .unwrap();
    assert_eq!(m.pending(), Some(Step::AcquireReference));
    assert_eq!(
        m.durable().reference_intent,
        Some(ReferenceIntent::Acquire(2))
    );
}

#[test]
fn disable_during_leave_retains_tokens_and_records_evidence_without_starting_repair() {
    let now = 102;
    let m = joined();
    let m = m.transition(Event::Leave, &Clock(now)).unwrap();
    assert!(m.durable().pf_reference.is_some());
    let next = m
        .transition(
            observed(&m, Form::Joined, Verdict::Repair(Action::EnableAndRejoin)),
            &Clock(now),
        )
        .unwrap();
    assert_eq!(next.pending(), m.pending());
    assert_eq!(next.durable().pf_reference, m.durable().pf_reference);
    assert_eq!(
        next.durable().enforcement_error,
        Some(Reason::Repair(Action::EnableAndRejoin))
    );
    assert_eq!(next.durable().older_references, [] as [u64; 0]);
    let mut now = now;
    assert!(drive_to(next, None, &mut now).connectivity_restored());
}

#[test]
fn same_second_invalidation_rejects_a_delayed_proof_and_pre_gap_flush() {
    let mut now = 102;
    let m = joined();
    let mut m = m
        .transition(
            observed(&m, Form::Joined, Verdict::Repair(Action::Rejoin)),
            &Clock(now),
        )
        .unwrap();
    m = drive_to(m, Some(Step::VerifyPreTunnel), &mut now);
    m = m
        .transition(
            observed(&m, Form::PreTunnel, Verdict::Repair(Action::Rejoin)),
            &Clock(now),
        )
        .unwrap();
    m = drive_to_backoff(m, &mut now);
    let generation = m.durable().previous_generation.unwrap().value();
    let (o, e) = machine_fixture(&m, Form::PreTunnel, generation, now);
    let delayed = observed(&m, Form::PreTunnel, verify::verify(&o, &e, &Clock(now)));
    let deadline = m.pending().unwrap();
    m = m
        .transition(
            observed(&m, Form::PreTunnel, Verdict::Unknown { since: now }),
            &Clock(now),
        )
        .unwrap();
    assert_eq!(m.pending(), Some(Step::FlushStates));
    assert!(m.states_clean_at().is_none());
    m = drive_to_backoff(m, &mut now);
    assert_eq!(m.pending(), Some(deadline));
    now += 1;
    m = m
        .transition(Event::Completed(deadline), &Clock(now))
        .unwrap();
    assert!(m.transition(delayed, &Clock(now)).is_err());
    m = drive_to(m, None, &mut now);
    assert!(matches!(
        m.enforcement_at(&Clock(now)),
        Verdict::Protected(_)
    ));
}

#[test]
fn every_fresh_uncovered_loss_runs_an_immediate_prefix_without_moving_verification_deadline() {
    let mut now = 102;
    let m = joined();
    let m = m
        .transition(
            observed(&m, Form::Joined, Verdict::Repair(Action::Rejoin)),
            &Clock(now),
        )
        .unwrap();
    let m = drive_to(m, Some(Step::VerifyPreTunnel), &mut now);
    let mut m = m
        .transition(
            observed(&m, Form::PreTunnel, Verdict::Repair(Action::Rejoin)),
            &Clock(now),
        )
        .unwrap();
    m = drive_to_backoff(m, &mut now);
    let deadline = m.pending();
    for _ in 0..10 {
        let loss = observed(&m, Form::PreTunnel, Verdict::Repair(Action::Rejoin));
        m = m.transition(loss.clone(), &Clock(now)).unwrap();
        assert_eq!(m.pending(), Some(Step::LoadPreTunnel));
        // A round captured before completion is covered, and cannot queue another prefix.
        let covered = observed(&m, Form::PreTunnel, Verdict::Repair(Action::Rejoin));
        for _ in 0..10 {
            if let Ok(next) = m.transition(covered.clone(), &Clock(now)) {
                m = next;
            }
        }
        m = drive_to_backoff(m, &mut now);
        assert_eq!(m.pending(), deadline);
        assert!(m.transition(covered, &Clock(now)).is_err());
    }
}

#[test]
fn restart_migrates_a_legacy_unknown_without_reusing_its_clock_domain() {
    let m = Machine::restart(Durable {
        last_error: Some(Reason::Unknown { since: 9_000_000 }),
        ..Durable::default()
    });
    assert_eq!(m.enforcement_at(&Clock(0)), Verdict::Unknown { since: 0 });
    assert_eq!(m.failure(), Some(&Reason::Unknown { since: 0 }));
    assert!(m.states_clean_at().is_none());
    assert!(m.last_verified().is_none());
}

#[test]
fn a_harmless_event_noticing_expiry_recloses_before_remaining_rejoin_wait() {
    let (m, now) = capped_backoff();
    let original = m.pending().unwrap();
    let generation = m.durable().previous_generation.unwrap();
    let m = m
        .transition(
            Event::Handshake {
                generation,
                fresh: true,
            },
            &Clock(now + 6),
        )
        .unwrap();
    assert_eq!(m.pending(), Some(Step::LoadPreTunnel));
    assert!(m.states_clean_at().is_none());
    assert_eq!(m.durable().retry_attempts, 7);
    let mut now = now + 6;
    let m = drive_to_backoff(m, &mut now);
    assert_eq!(m.pending(), Some(original));
    assert_backoff_invariant(&m, now);
}

#[path = "mac_effect_oracle/mod.rs"]
mod effect_oracle;

#[test]
fn late_predecessor_during_disabled_replacement_keeps_both_acquisitions_and_the_plan_head() {
    let mut now = 102;
    let m = Machine::restart(Durable::default())
        .transition(Event::Join, &Clock(now))
        .unwrap();
    let mut m = drive_to(m, Some(Step::AcquireReference), &mut now);
    let Some(ReferenceIntent::Acquire(first)) = m.durable().reference_intent else {
        panic!("missing first intent")
    };
    m = m
        .transition(
            Event::Failed(Reason::Observation("lost result")),
            &Clock(now),
        )
        .unwrap();
    m = m
        .transition(
            Event::Failed(Reason::Observation("unresolved")),
            &Clock(now),
        )
        .unwrap();
    let Some(ReferenceIntent::Acquire(second)) = m.durable().reference_intent else {
        panic!("missing replacement intent")
    };
    assert_ne!(first, second);
    m = m
        .transition(
            observed(
                &m,
                Form::PreTunnel,
                Verdict::Repair(Action::EnableAndRejoin),
            ),
            &Clock(now),
        )
        .unwrap();
    m = m
        .transition(
            Event::ReferenceAcquiredFor {
                sequence: first,
                token: 701,
            },
            &Clock(now),
        )
        .unwrap();
    assert_eq!(m.pending(), Some(Step::AcquireReference));
    assert_eq!(
        m.durable().reference_intent,
        Some(ReferenceIntent::Acquire(second))
    );
    m = m
        .transition(
            Event::ReferenceAcquiredFor {
                sequence: second,
                token: 702,
            },
            &Clock(now),
        )
        .unwrap();
    assert_eq!(m.durable().pf_reference, Some(702));
    assert_eq!(m.durable().older_references, [701]);
    assert!(m.durable().reference_needs_reconcile);
    m = m.transition(Event::Leave, &Clock(now)).unwrap();
    m = drive_to(m, Some(Step::ClearIntent), &mut now);
    assert_eq!(m.durable().pf_reference, Some(702));
    assert_eq!(m.durable().older_references, [701]);
    assert!(drive_to(m, None, &mut now).connectivity_restored());
}

#[test]
fn failed_reconcile_then_another_disable_never_exposes_an_unjournaled_acquire() {
    let mut now = 102;
    let m = Machine::restart(Durable::default())
        .transition(Event::Join, &Clock(now))
        .unwrap();
    let mut m = drive_to(m, Some(Step::AcquireReference), &mut now);
    m = m
        .transition(
            observed(
                &m,
                Form::PreTunnel,
                Verdict::Repair(Action::EnableAndRejoin),
            ),
            &Clock(now),
        )
        .unwrap();
    m = m
        .transition(Event::ReferenceAcquired(701), &Clock(now))
        .unwrap();
    assert_eq!(m.pending(), Some(Step::LoadPreTunnel));
    m = drive_to(m, Some(Step::ReconcileReference), &mut now);
    assert_eq!(m.durable().reference_intent, None);
    m = m
        .transition(
            Event::Failed(Reason::Observation("unresolved")),
            &Clock(now),
        )
        .unwrap();
    assert_eq!(m.pending(), Some(Step::VerifyPreTunnel));
    m = m
        .transition(
            observed(
                &m,
                Form::PreTunnel,
                Verdict::Repair(Action::EnableAndRejoin),
            ),
            &Clock(now),
        )
        .unwrap();
    assert_eq!(m.pending(), Some(Step::AcquireReference));
    assert_eq!(
        m.durable().reference_intent,
        Some(ReferenceIntent::Acquire(2))
    );
    m = m
        .transition(Event::ReferenceAcquired(702), &Clock(now))
        .unwrap();
    assert_eq!(m.durable().pf_reference, Some(702));
    assert_eq!(m.durable().older_references, [701]);
    m = m.transition(Event::Leave, &Clock(now)).unwrap();
    assert!(drive_to(m, None, &mut now).connectivity_restored());
}

#[test]
fn reconcile_started_before_acquisition_completion_cannot_void_that_identity() {
    let mut now = 102;
    let m = Machine::restart(Durable::default())
        .transition(Event::Join, &Clock(now))
        .unwrap();
    let mut m = drive_to(m, Some(Step::AcquireReference), &mut now);
    m = m
        .transition(
            observed(
                &m,
                Form::PreTunnel,
                Verdict::Repair(Action::EnableAndRejoin),
            ),
            &Clock(now),
        )
        .unwrap();
    let before_acquire = m.context();
    m = m
        .transition(Event::ReferenceAcquired(701), &Clock(now))
        .unwrap();
    assert_eq!(m.pending(), Some(Step::LoadPreTunnel));
    m = drive_to(m, Some(Step::ReconcileReference), &mut now);
    assert!(
        m.transition(
            Event::ReferenceReconciled {
                context: before_acquire,
                current: None,
                predecessor: None
            },
            &Clock(now)
        )
        .is_err()
    );
    assert_eq!(m.durable().pf_reference, Some(701));
    let m = m
        .transition(
            Event::ReferenceSettled {
                entry: ReferenceEntry::Token(701),
                how: ReferenceSettlement::Void,
            },
            &Clock(now),
        )
        .unwrap();
    let m = m
        .transition(
            Event::ReferenceReconciled {
                context: m.context(),
                current: None,
                predecessor: None,
            },
            &Clock(now),
        )
        .unwrap();
    assert_eq!(m.pending(), Some(Step::AcquireReference));
}

#[test]
fn first_prefix_and_replacement_disable_repair_at_the_very_next_effect_boundary() {
    for mode in 0..3 {
        let mut now = 102;
        let (m, target) = match mode {
            0 => (
                Machine::restart(Durable::default())
                    .transition(Event::Join, &Clock(now))
                    .unwrap(),
                Step::VerifyPreTunnelLoad,
            ),
            1 => (
                Machine::restart(joined().durable().clone()),
                Step::VerifyPreTunnelLoad,
            ),
            _ => (
                joined()
                    .transition(
                        Event::Repair(Action::Rerender { form: Form::Joined }),
                        &Clock(now),
                    )
                    .unwrap(),
                Step::VerifyReplacement(Form::Joined),
            ),
        };
        let mut m = drive_to(m, Some(target), &mut now);
        let completion = checked_completion_at(&m, now);
        m = m
            .transition(
                observed(
                    &m,
                    m.installed_form().unwrap(),
                    Verdict::Repair(Action::EnableAndRejoin),
                ),
                &Clock(now),
            )
            .unwrap();
        assert_eq!(m.pending(), Some(target));
        m = m.transition(completion, &Clock(now)).unwrap();
        if m.pending() == Some(Step::ReconcileReference) {
            for token in m
                .durable()
                .pf_reference
                .into_iter()
                .chain(m.durable().older_references.clone())
            {
                m = m
                    .transition(
                        Event::ReferenceSettled {
                            entry: ReferenceEntry::Token(token),
                            how: ReferenceSettlement::Void,
                        },
                        &Clock(now),
                    )
                    .unwrap();
            }
            m = m
                .transition(
                    Event::ReferenceReconciled {
                        context: m.context(),
                        current: None,
                        predecessor: None,
                    },
                    &Clock(now),
                )
                .unwrap();
        }
        assert_eq!(m.pending(), Some(Step::AcquireReference), "mode {mode}");
        assert_eq!(
            drive_to(m, None, &mut now).status_at(&Clock(now)),
            ConnectionStatus::Joined
        );
    }
}

#[test]
fn child_loss_then_rerender_still_completes_recovery() {
    let mut now = 102;
    let mut m = Machine::restart(Durable::default())
        .transition(Event::Join, &Clock(now))
        .unwrap();
    m = property_transition(&m, Event::Completed(Step::PersistIntent), now);
    for _ in 0..18 {
        now = executor_time(&m, now + 1);
        m = property_transition(&m, checked_completion_at(&m, now), now);
    }
    for disturbance in [2, 2, 8] {
        now = executor_time(&m, now + 1);
        let event = if disturbance == 2 {
            Event::ChildDied
        } else {
            observed(
                &m,
                m.installed_form().unwrap(),
                Verdict::Repair(Action::Rerender {
                    form: m.installed_form().unwrap(),
                }),
            )
        };
        m = property_transition(&m, event, now);
    }
    assert!(m.tunnel().is_none());
    assert_eq!(m.pending(), Some(Step::FlushStates));
    now += 1;
    m = property_transition(&m, checked_completion_at(&m, now), now);
    assert_eq!(m.pending(), Some(Step::LoadPreTunnel));
    for _ in 0..60 {
        if m.pending().is_none() {
            break;
        }
        now = executor_time(&m, now + 1);
        m = property_transition(&m, checked_completion_at(&m, now), now);
    }
    assert_eq!(m.pending(), None);
    assert_eq!(m.status_at(&Clock(now)), ConnectionStatus::Joined);
}

#[test]
fn joined_unknown_twice_after_seventeen_completions_records_flush_retry() {
    let mut now = 102;
    let mut m = Machine::restart(Durable::default())
        .transition(Event::Join, &Clock(now))
        .unwrap();
    m = property_transition(&m, Event::Completed(Step::PersistIntent), now);
    for _ in 0..17 {
        now = executor_time(&m, now + 1);
        m = property_transition(&m, checked_completion_at(&m, now), now);
    }
    assert_eq!(m.pending(), Some(Step::VerifyJoined));
    let generation = m.durable().previous_generation;
    now += 1;
    m = property_transition(
        &m,
        observed(&m, Form::Joined, Verdict::Unknown { since: now }),
        now,
    );
    let failed_at = now;
    let until = now + 1;
    assert_eq!(
        m.closing_retry(),
        Some(ClosingRetry {
            failed_at,
            until,
            target: Step::VerifyJoined,
        })
    );
    assert_eq!(
        m.plan(),
        &[
            Step::FlushStates,
            Step::Backoff { until },
            Step::VerifyJoined
        ]
    );
    now = executor_time(&m, now + 1);
    m = property_transition(
        &m,
        observed(&m, Form::Joined, Verdict::Unknown { since: now }),
        now,
    );
    assert_eq!(m.closing_retry().unwrap().until, until);
    m = property_transition(&m, checked_completion_at(&m, now), now);
    assert_eq!(
        m.plan(),
        &[
            Step::Backoff { until },
            Step::FlushStates,
            Step::VerifyJoined
        ]
    );
    assert_eq!(
        m.closing_retry(),
        Some(ClosingRetry {
            failed_at,
            until,
            target: Step::FlushStates,
        })
    );
    for _ in 0..3 {
        m = property_transition(
            &m,
            observed(&m, Form::Joined, Verdict::Unknown { since: now }),
            now,
        );
        assert_eq!(m.closing_retry().unwrap().until, until);
        assert_eq!(m.durable().retry_attempts, 0);
    }
    m = property_transition(&m, checked_completion_at(&m, now), now);
    assert_eq!(m.pending(), Some(Step::FlushStates));
    assert!(m.closing_retry().is_some());
    m = property_transition(&m, checked_completion_at(&m, now), now);
    assert_eq!(m.pending(), Some(Step::VerifyJoined));
    assert_eq!(m.closing_retry(), None);
    m = property_transition(&m, checked_completion_at(&m, now), now);
    assert_eq!(m.pending(), None);
    assert_eq!(m.status_at(&Clock(now)), ConnectionStatus::Joined);
    assert_eq!(m.durable().previous_generation, generation);
    assert_eq!(m.durable().retry_attempts, 0);
}

#[test]
fn joined_verification_retry_keeps_its_deadline_when_recovery_replaces_the_target() {
    let mut now = 102;
    let m = Machine::restart(Durable::default())
        .transition(Event::Join, &Clock(now))
        .unwrap();
    let mut m = drive_to(m, Some(Step::VerifyJoined), &mut now);
    m = property_transition(
        &m,
        observed(&m, Form::Joined, Verdict::Unknown { since: now }),
        now,
    );
    m = property_transition(&m, checked_completion_at(&m, now), now);
    let retry = m.closing_retry().unwrap();
    for flush_queued in [false, true] {
        let mut waiting = m.clone();
        if flush_queued {
            waiting = property_transition(
                &waiting,
                observed(&waiting, Form::Joined, Verdict::Unknown { since: now }),
                now,
            );
            assert_eq!(waiting.closing_retry().unwrap().target, Step::FlushStates);
        }
        for event in [
            Event::InvalidateObservations { since: now },
            observed(&waiting, Form::Joined, Verdict::Repair(Action::Rejoin)),
            Event::ChildDied,
        ] {
            let recovering = property_transition(&waiting, event, now);
            assert_eq!(recovering.pending(), Some(Step::LoadPreTunnel));
            assert_eq!(
                recovering.closing_retry(),
                Some(ClosingRetry {
                    target: Step::VerifyPreTunnel,
                    ..retry
                })
            );
            let mut finish_at = now;
            let recovering = drive_to_backoff(recovering, &mut finish_at);
            assert_backoff_invariant(&recovering, finish_at);
            assert_eq!(
                recovering.pending(),
                Some(Step::Backoff { until: retry.until })
            );
            assert_eq!(
                drive_to(recovering, None, &mut finish_at).status_at(&Clock(finish_at)),
                ConnectionStatus::Joined
            );
        }
    }
}

#[test]
fn setup_unknown_flushes_and_joined_unknown_retries_within_the_same_attempt() {
    let mut now = 102;
    let m = Machine::restart(Durable::default())
        .transition(Event::Join, &Clock(now))
        .unwrap();
    let mut m = drive_to(m, Some(Step::ConfigureAddresses), &mut now);
    m = m
        .transition(
            observed(&m, Form::PreTunnel, Verdict::Unknown { since: now }),
            &Clock(now),
        )
        .unwrap();
    assert_eq!(m.durable().retry_attempts, 0);
    let flush = m
        .plan()
        .iter()
        .position(|s| *s == Step::FlushStates)
        .unwrap();
    let load = m
        .plan()
        .iter()
        .position(|s| *s == Step::LoadJoined)
        .unwrap();
    assert!(flush < load);
    m = drive_to(m, Some(Step::VerifyJoined), &mut now);
    let generation = m.durable().previous_generation.unwrap();
    let started = now;
    for _ in 0..3 {
        m = m
            .transition(
                observed(&m, Form::Joined, Verdict::Unknown { since: now }),
                &Clock(now),
            )
            .unwrap();
        assert_eq!(m.pending(), Some(Step::FlushStates));
        assert_eq!(m.durable().retry_attempts, 0);
        m = m
            .transition(checked_completion_at(&m, now), &Clock(now))
            .unwrap();
        let deadline = m.pending();
        assert!(matches!(deadline, Some(Step::Backoff { .. })));
        m = m
            .transition(
                observed(&m, Form::Joined, Verdict::Unknown { since: now }),
                &Clock(now),
            )
            .unwrap();
        assert_eq!(m.pending(), deadline);
        m = drive_to(m, Some(Step::VerifyJoined), &mut now);
        assert_eq!(m.durable().previous_generation, Some(generation));
    }
    assert_eq!(now, started + 3);
    let success = drive_to(m.clone(), None, &mut now);
    assert_eq!(success.status_at(&Clock(now)), ConnectionStatus::Joined);
    assert_eq!(success.durable().retry_attempts, 0);
    m = m
        .transition(
            observed(&m, Form::Joined, Verdict::Unknown { since: now }),
            &Clock(now),
        )
        .unwrap();
    assert_eq!(m.durable().retry_attempts, 1); // fourth Unknown exhausts three retries
    assert_eq!(m.pending(), Some(Step::LoadPreTunnel));
}

#[test]
fn setup_wake_and_rerender_do_not_increment_the_rejoin_failure_counter() {
    for wake in [false, true] {
        let mut now = 102;
        let m = Machine::restart(Durable::default())
            .transition(Event::Join, &Clock(now))
            .unwrap();
        let mut m = drive_to(m, Some(Step::ConfigureAddresses), &mut now);
        let event = if wake {
            Event::InvalidateObservations { since: now }
        } else {
            observed(
                &m,
                Form::PreTunnel,
                Verdict::Repair(Action::Rerender {
                    form: Form::PreTunnel,
                }),
            )
        };
        m = m.transition(event, &Clock(now)).unwrap();
        m = m
            .transition(Event::Completed(Step::ConfigureAddresses), &Clock(now))
            .unwrap();
        assert_eq!(m.pending(), Some(Step::LoadPreTunnel));
        assert_eq!(m.durable().retry_attempts, 0);
        assert_eq!(
            drive_to(m, None, &mut now).status_at(&Clock(now)),
            ConnectionStatus::Joined
        );
    }
}

#[test]
fn late_acquire_keeps_reference_error_until_the_predecessor_is_settled() {
    let mut now = 102;
    let m = Machine::restart(Durable::default())
        .transition(Event::Join, &Clock(now))
        .unwrap();
    let mut m = drive_to(m, Some(Step::AcquireReference), &mut now);
    m = m
        .transition(
            Event::Failed(Reason::Observation("lost result")),
            &Clock(now),
        )
        .unwrap();
    m = m
        .transition(
            Event::Failed(Reason::Observation("unresolved")),
            &Clock(now),
        )
        .unwrap();
    m = m
        .transition(Event::ReferenceAcquired(702), &Clock(now))
        .unwrap();
    assert!(m.durable().reference_error.is_some());
    m = m
        .transition(
            Event::ReferenceAcquiredFor {
                sequence: 1,
                token: 701,
            },
            &Clock(now),
        )
        .unwrap();
    assert_eq!(m.durable().older_references, [702]);
    assert!(m.durable().reference_error.is_some());
    m = m
        .transition(Event::InvalidateObservations { since: now }, &Clock(now))
        .unwrap();
    assert!(m.durable().reference_error.is_some());
    assert!(
        m.status_text_at(&Clock(now))
            .contains("ownership cleanup debt")
    );
    m = settled(
        &m,
        ReferenceEntry::Token(702),
        ReferenceSettlement::Released,
        now,
    );
    assert!(m.durable().reference_error.is_none());
    assert!(
        !m.status_text_at(&Clock(now))
            .contains("ownership cleanup debt")
    );
}

#[test]
fn leave_persists_and_removes_the_anchor_before_reconciling_ownership_debt() {
    let mut now = 102;
    let m = Machine::restart(Durable::default())
        .transition(Event::Join, &Clock(now))
        .unwrap();
    let mut m = drive_to(m, Some(Step::AcquireReference), &mut now);
    m = m
        .transition(
            Event::Failed(Reason::Observation("lost result")),
            &Clock(now),
        )
        .unwrap();
    m = m
        .transition(
            Event::Failed(Reason::Observation("unresolved")),
            &Clock(now),
        )
        .unwrap();
    m = m
        .transition(Event::ReferenceAcquired(702), &Clock(now))
        .unwrap();
    m = m.transition(Event::Leave, &Clock(now)).unwrap();
    assert_eq!(m.pending(), Some(Step::LoadPreTunnel)); // settle the active effect
    m = m
        .transition(Event::Completed(Step::LoadPreTunnel), &Clock(now))
        .unwrap();
    assert_eq!(m.pending(), Some(Step::PersistLeaving));
    m = m
        .transition(Event::Completed(Step::PersistLeaving), &Clock(now))
        .unwrap();
    assert_eq!(m.pending(), Some(Step::StopChild));
    // The same ordering applies after restart with durable Leaving.
    m = Machine::restart(m.durable().clone());
    assert_eq!(m.pending(), Some(Step::StopChild));
    m = drive_to(m, Some(Step::RemoveAnchor), &mut now);
    m = m
        .transition(Event::Completed(Step::RemoveAnchor), &Clock(now))
        .unwrap();
    assert_eq!(m.pending(), Some(Step::ClearIntent));
    m = m
        .transition(Event::Completed(Step::ClearIntent), &Clock(now))
        .unwrap();
    assert!(m.connectivity_restored());
    assert_eq!(m.pending(), Some(Step::ReconcileReference));
}

#[test]
fn leave_restart_after_anchor_removal_clears_intent_before_reconciliation() {
    let m = Machine::restart(Durable {
        leaving: true,
        pf_reference: Some(701),
        reference_needs_reconcile: true,
        pending_cleanup: vec![],
        ..Durable::default()
    });
    assert_eq!(m.pending(), Some(Step::ClearIntent));
    assert_eq!(m.plan(), &[Step::ClearIntent]);
}

#[test]
fn reconciliation_accepts_monitor_revision_but_retains_disable_debt() {
    let mut now = 102;
    let mut durable = joined().durable().clone();
    durable.older_references = vec![77];
    durable.reference_needs_reconcile = true;
    let mut m = Machine::restart(durable);
    assert_eq!(m.pending(), Some(Step::ReconcileReference));
    let captured = m.context();
    m = m
        .transition(
            observed(
                &m,
                Form::PreTunnel,
                Verdict::Repair(Action::EnableAndRejoin),
            ),
            &Clock(now),
        )
        .unwrap();
    assert_ne!(m.context().lifecycle_revision, captured.lifecycle_revision);
    let token = m.durable().pf_reference.unwrap();
    m = m
        .transition(
            Event::ReferenceSettled {
                entry: ReferenceEntry::Token(token),
                how: ReferenceSettlement::Void,
            },
            &Clock(now),
        )
        .unwrap();
    let captured = Context {
        acquisition_revision: m.context().acquisition_revision,
        ..captured
    };
    m = m
        .transition(
            Event::ReferenceReconciled {
                context: captured,
                current: Some(77),
                predecessor: None,
            },
            &Clock(now),
        )
        .unwrap();
    // The disable observed during reconciliation is still owed: a live token
    // is not evidence that pf was re-enabled after the observed stop.
    assert_eq!(m.pending(), Some(Step::AcquireReference));
    assert!(matches!(
        m.durable().reference_intent,
        Some(ReferenceIntent::Acquire(_))
    ));
    m = m
        .transition(checked_completion_at(&m, now), &Clock(now))
        .unwrap();
    assert_eq!(m.pending(), Some(Step::LoadPreTunnel));
    assert_eq!(
        drive_to(m, None, &mut now).status_at(&Clock(now)),
        ConnectionStatus::Joined
    );
}
#[test]
fn fresh_disabled_acquire_runs_safety_before_reconciliation() {
    let mut now = 102;
    let mut m = Machine::restart(Durable::default())
        .transition(Event::Join, &Clock(now))
        .unwrap();
    m = drive_to(m, Some(Step::AcquireReference), &mut now);
    let mut order = vec![Step::AcquireReference];
    m = m
        .transition(
            observed(
                &m,
                Form::PreTunnel,
                Verdict::Repair(Action::EnableAndRejoin),
            ),
            &Clock(now),
        )
        .unwrap();
    m = m
        .transition(Event::ReferenceAcquired(700), &Clock(now))
        .unwrap();
    for _ in 0..10 {
        let step = m.pending().unwrap();
        order.push(step);
        if step == Step::ReconcileReference {
            break;
        }
        m = m
            .transition(checked_completion_at(&m, now), &Clock(now))
            .unwrap();
    }
    assert_eq!(
        order,
        vec![
            Step::AcquireReference,
            Step::LoadPreTunnel,
            Step::VerifyPreTunnelLoad,
            Step::FlushStates,
            Step::ReconcileReference
        ]
    );
}

#[test]
fn idle_states_clean_maintenance_acceptance_is_bounded_by_epoch_time_and_mode() {
    let m = joined();
    assert!(m.pending().is_none());
    let epoch = m.context().state_epoch;
    let refreshed = m
        .transition(
            Event::StatesClean {
                epoch,
                completed_at: 103,
            },
            &Clock(103),
        )
        .unwrap();
    assert_eq!(refreshed.states_clean_at(), Some(103));
    assert_eq!(refreshed.durable(), m.durable());
    assert!(refreshed.pending().is_none());
    for (epoch, completed_at, now) in [(epoch + 1, 103, 103), (epoch, 104, 103), (epoch, 0, 103)] {
        assert!(
            m.transition(
                Event::StatesClean {
                    epoch,
                    completed_at
                },
                &Clock(now)
            )
            .is_err()
        );
    }
    for event in [
        Event::Leave,
        Event::Repair(Action::Rejoin),
        Event::InvalidateObservations { since: 103 },
    ] {
        let changed = m.transition(event, &Clock(103)).unwrap();
        assert!(
            changed
                .transition(
                    Event::StatesClean {
                        epoch,
                        completed_at: 103
                    },
                    &Clock(103)
                )
                .is_err()
        );
    }
    let left = Machine::restart(Durable::default());
    assert!(
        left.transition(
            Event::StatesClean {
                epoch: left.context().state_epoch,
                completed_at: 103
            },
            &Clock(103)
        )
        .is_err()
    );
}

fn settled(m: &Machine, entry: ReferenceEntry, how: ReferenceSettlement, now: u64) -> Machine {
    m.transition(Event::ReferenceSettled { entry, how }, &Clock(now))
        .unwrap()
}

#[test]
fn leave_preserves_every_reference_field_and_finishes_before_idle_accounting() {
    let mut m = Machine::restart(Durable {
        leaving: true,
        leave_requested: true,
        pf_reference: Some(71),
        uncertain_acquires: vec![8],
        reference_sequence: 8,
        reference_needs_reconcile: true,
        reference_error: Some(Reason::Observation("retained debt")),
        pending_cleanup: vec![
            Step::StopChild,
            Step::CleanupRoutes,
            Step::CleanupDns,
            Step::CleanupArtifacts,
            Step::RemoveAnchor,
        ],
        ..Durable::default()
    });
    let entries = m.durable().clone();
    for step in [
        Step::StopChild,
        Step::CleanupRoutes,
        Step::CleanupDns,
        Step::CleanupArtifacts,
        Step::RemoveAnchor,
        Step::ClearIntent,
    ] {
        assert_eq!(m.pending(), Some(step));
        assert!(!m.plan().contains(&Step::ReleaseReference));
        assert!(!m.plan().contains(&Step::ReconcileReference));
        m = m.transition(Event::Completed(step), &Clock(100)).unwrap();
    }
    assert!(m.connectivity_restored());
    assert!(!m.cleanup_confirmed());
    assert_eq!(m.status_at(&Clock(100)), ConnectionStatus::Idle);
    assert_eq!(m.durable().pf_reference, entries.pf_reference);
    assert_eq!(m.durable().uncertain_acquires, entries.uncertain_acquires);
    assert_eq!(m.durable().reference_sequence, entries.reference_sequence);
    assert_eq!(m.durable().reference_error, entries.reference_error);
    assert_eq!(
        m.durable().reference_needs_reconcile,
        entries.reference_needs_reconcile
    );
    assert_eq!(m.pending(), Some(Step::ReconcileReference));
    m = settled(
        &m,
        ReferenceEntry::Token(71),
        ReferenceSettlement::Released,
        100,
    );
    m = settled(
        &m,
        ReferenceEntry::Acquire(8),
        ReferenceSettlement::Void,
        100,
    );
    m = m.transition(complete_event(&m, 1), &Clock(100)).unwrap();
    assert!(m.cleanup_confirmed());
}

#[test]
fn idle_reference_reconciliation_retries_double_to_sixty_and_never_acquire() {
    for durable in [
        Durable {
            pf_reference: Some(71),
            ..Durable::default()
        },
        Durable {
            older_references: vec![72],
            ..Durable::default()
        },
        Durable {
            uncertain_acquires: vec![8],
            reference_sequence: 8,
            ..Durable::default()
        },
    ] {
        let mut m = Machine::restart(durable);
        let mut now = 0;
        for delay in [1, 2, 4, 8, 16, 32, 60, 60] {
            assert_eq!(m.pending(), Some(Step::ReconcileReference));
            assert!(!m.plan().contains(&Step::AcquireReference));
            m = m
                .transition(
                    Event::Failed(Reason::Observation("not decidable")),
                    &Clock(now),
                )
                .unwrap();
            assert!(m.connectivity_restored());
            assert_eq!(m.status_at(&Clock(now)), ConnectionStatus::Idle);
            assert_eq!(m.pending(), Some(Step::Backoff { until: now + delay }));
            assert!(
                m.transition(Event::Completed(m.pending().unwrap()), &Clock(now))
                    .is_err()
            );
            now += delay;
            m = m
                .transition(Event::Completed(m.pending().unwrap()), &Clock(now))
                .unwrap();
        }
    }
}

#[test]
fn joined_reference_reconciliation_retries_stay_at_one_second() {
    let mut durable = joined().durable().clone();
    durable.reference_needs_reconcile = true;
    let mut m = Machine::restart(durable);
    let mut now = 102;
    for _ in 0..8 {
        m = drive_to(m, Some(Step::ReconcileReference), &mut now);
        m = m
            .transition(
                Event::Failed(Reason::Observation("not decidable")),
                &Clock(now),
            )
            .unwrap();
        let failed_at = now;
        m = drive_to(m, Some(Step::ReconcileReference), &mut now);
        assert_eq!(now, failed_at + 1);
        assert_eq!(m.pending(), Some(Step::ReconcileReference));
    }
}

#[test]
fn settlement_removes_exactly_the_named_entry_for_every_disposition_and_mode() {
    for how in [
        ReferenceSettlement::Released,
        ReferenceSettlement::Absent,
        ReferenceSettlement::Void,
    ] {
        for leaving in [false, true] {
            let base = Machine::restart(Durable {
                pf_reference: Some(71),
                older_references: vec![72],
                leaving,
                ..Durable::default()
            });
            for token in [71, 72] {
                let before = base.context().acquisition_revision;
                let m = settled(&base, ReferenceEntry::Token(token), how, 100);
                assert_eq!(
                    m.durable().pf_reference,
                    if token == 71 { None } else { Some(71) }
                );
                assert_eq!(
                    m.durable().older_references,
                    if token == 72 { vec![] } else { vec![72] }
                );
                assert_eq!(m.context().acquisition_revision, before + 1);
                assert_eq!(
                    m.durable().verification_context.acquisition_revision,
                    before + 1
                );
                assert!(
                    m.transition(
                        Event::ReferenceSettled {
                            entry: ReferenceEntry::Token(token),
                            how
                        },
                        &Clock(100)
                    )
                    .is_err()
                );
            }
            let base = Machine::restart(Durable {
                uncertain_acquires: vec![7, 8],
                reference_sequence: 8,
                leaving,
                ..Durable::default()
            });
            for sequence in [7, 8] {
                let m = settled(&base, ReferenceEntry::Acquire(sequence), how, 100);
                assert_eq!(
                    m.durable().uncertain_acquires,
                    if sequence == 7 { vec![8] } else { vec![7] }
                );
                assert_eq!(
                    m.context().acquisition_revision,
                    base.context().acquisition_revision + 1
                );
            }
        }
    }
}

#[test]
fn settlement_rejects_active_acquisition_and_does_not_confuse_token_and_sequence() {
    let m = Machine::restart(Durable::default())
        .transition(Event::Join, &Clock(100))
        .unwrap();
    let m = m
        .transition(Event::Completed(Step::PersistIntent), &Clock(100))
        .unwrap();
    let Some(ReferenceIntent::Acquire(sequence)) = m.durable().reference_intent else {
        panic!("missing reservation")
    };
    assert!(
        m.transition(
            Event::ReferenceSettled {
                entry: ReferenceEntry::Token(sequence),
                how: ReferenceSettlement::Absent,
            },
            &Clock(100)
        )
        .is_err()
    );
    assert!(
        m.transition(
            Event::ReferenceSettled {
                entry: ReferenceEntry::Acquire(sequence),
                how: ReferenceSettlement::Void,
            },
            &Clock(100)
        )
        .is_err()
    );
    let m = m
        .transition(
            Event::Failed(Reason::Observation("unknown acquire")),
            &Clock(100),
        )
        .unwrap();
    let m = settled(
        &m,
        ReferenceEntry::Acquire(sequence),
        ReferenceSettlement::Void,
        100,
    );
    assert_ne!(
        m.durable().reference_intent,
        Some(ReferenceIntent::Acquire(sequence))
    );
    assert!(m.plan().contains(&Step::AcquireReference));
    assert_eq!(m.durable().uncertain_acquires, [] as [u64; 0]);
}

#[test]
fn reference_error_clearing_preserves_other_errors_and_resurfaces_enforcement() {
    let reference = Reason::Observation("reference failure");
    let other = Reason::Observation("different failure");
    let enforcement = Reason::Observation("enforcement failure");
    for last in [reference.clone(), other.clone()] {
        let mut m = Machine::restart(Durable {
            reference_needs_reconcile: true,
            reference_error: Some(reference.clone()),
            last_error: Some(last.clone()),
            enforcement_error: Some(enforcement.clone()),
            ..Durable::default()
        });
        assert_eq!(m.pending(), Some(Step::ReconcileReference));
        m = m
            .transition(
                Event::ReferenceReconciled {
                    context: m.context(),
                    current: None,
                    predecessor: None,
                },
                &Clock(10),
            )
            .unwrap();
        assert!(m.durable().reference_error.is_none());
        assert_eq!(
            m.failure(),
            Some(if last == reference {
                &enforcement
            } else {
                &other
            })
        );
        assert_eq!(m.durable().enforcement_error, Some(enforcement.clone()));
    }
}

#[test]
fn settlement_invalidates_reconciliation_and_clears_only_the_last_debt_error() {
    let mut m = Machine::restart(Durable {
        pf_reference: Some(71),
        uncertain_acquires: vec![8],
        reference_sequence: 8,
        reference_error: Some(Reason::Observation("debt")),
        ..Durable::default()
    });
    let captured = m.context();
    m = settled(
        &m,
        ReferenceEntry::Acquire(8),
        ReferenceSettlement::Void,
        10,
    );
    assert!(m.durable().reference_error.is_some());
    assert!(
        m.transition(
            Event::ReferenceReconciled {
                context: captured,
                current: Some(71),
                predecessor: None,
            },
            &Clock(10)
        )
        .is_err()
    );
    m = settled(
        &m,
        ReferenceEntry::Token(71),
        ReferenceSettlement::Absent,
        10,
    );
    assert!(m.durable().reference_error.is_none());
    assert!(!m.durable().reference_needs_reconcile);
    m = m.transition(complete_event(&m, 1), &Clock(10)).unwrap();
    assert!(m.cleanup_confirmed());
}

#[test]
fn reconciliation_requires_settlement_of_uncertainty_and_cannot_drop_or_invent_tokens() {
    let m = Machine::restart(Durable {
        pf_reference: Some(71),
        uncertain_acquires: vec![8],
        reference_sequence: 8,
        ..Durable::default()
    });
    let reconcile = |m: &Machine, current| Event::ReferenceReconciled {
        context: m.context(),
        current,
        predecessor: None,
    };
    assert!(m.transition(reconcile(&m, Some(71)), &Clock(10)).is_err());
    let m = settled(
        &m,
        ReferenceEntry::Acquire(8),
        ReferenceSettlement::Void,
        10,
    );
    assert!(m.transition(reconcile(&m, None), &Clock(10)).is_err());
    assert!(m.transition(reconcile(&m, Some(72)), &Clock(10)).is_err());
    let m = m.transition(reconcile(&m, Some(71)), &Clock(10)).unwrap();
    assert_eq!(m.pending(), Some(Step::Backoff { until: 11 }));
}

#[test]
fn settling_last_joined_reference_requires_a_new_acquisition_and_resets_idle_delay() {
    let mut durable = joined().durable().clone();
    durable.reference_needs_reconcile = true;
    let m = Machine::restart(durable);
    let token = m.durable().pf_reference.unwrap();
    let m = settled(
        &m,
        ReferenceEntry::Token(token),
        ReferenceSettlement::Absent,
        100,
    );
    let m = m.transition(complete_event(&m, 1), &Clock(100)).unwrap();
    assert_eq!(m.pending(), Some(Step::AcquireReference));
    let mut m = Machine::restart(Durable {
        pf_reference: Some(71),
        older_references: vec![72],
        ..Durable::default()
    });
    m = m
        .transition(Event::Failed(Reason::Observation("debt")), &Clock(0))
        .unwrap();
    m = m
        .transition(Event::Completed(m.pending().unwrap()), &Clock(1))
        .unwrap();
    m = m
        .transition(Event::Failed(Reason::Observation("debt")), &Clock(1))
        .unwrap();
    assert_eq!(m.pending(), Some(Step::Backoff { until: 3 }));
    m = settled(
        &m,
        ReferenceEntry::Token(72),
        ReferenceSettlement::Absent,
        1,
    );
    assert_eq!(m.pending(), Some(Step::ReconcileReference));
    m = m
        .transition(Event::Failed(Reason::Observation("debt")), &Clock(3))
        .unwrap();
    assert_eq!(m.pending(), Some(Step::Backoff { until: 4 }));
}

proptest! {
    #[test]
    fn leave_completion_never_waits_on_reference_entries(
        tokens in prop::collection::btree_set(1u64..1000, 0..=2),
        uncertain in 0usize..=2,
        leaving in any::<bool>(),
    ) {
        let tokens: Vec<_> = tokens.into_iter().collect();
        let uncertain = uncertain.min(2 - tokens.len());
        let mut m = Machine::restart(Durable {
            join_intended: !leaving, leaving,
            pf_reference: tokens.first().copied(), older_references: tokens.iter().skip(1).copied().collect(),
            uncertain_acquires: (1..=u64::try_from(uncertain).unwrap()).collect(), reference_sequence: 2,
            pending_cleanup: if leaving { vec![Step::StopChild, Step::CleanupRoutes, Step::CleanupDns, Step::CleanupArtifacts, Step::RemoveAnchor] } else { vec![] },
            ..Durable::default()
        });
        if !leaving {
            m = m.transition(Event::Leave, &Clock(100)).unwrap();
            if m.pending() != Some(Step::PersistLeaving) {
                m = m.transition(Event::Failed(Reason::Observation("cancel active boundary")), &Clock(100)).unwrap();
            }
            m = m.transition(Event::Completed(Step::PersistLeaving), &Clock(100)).unwrap();
        }
        let entries = (m.durable().pf_reference, m.durable().older_references.clone(), m.durable().uncertain_acquires.clone(), m.durable().reference_intent);
        for _ in 0..6 {
            let step = m.pending().unwrap();
            prop_assert!(matches!(step, Step::StopChild | Step::CleanupRoutes | Step::CleanupDns | Step::CleanupArtifacts | Step::RemoveAnchor | Step::ClearIntent));
            m = m.transition(Event::Completed(step), &Clock(100)).unwrap();
            if m.connectivity_restored() { break; }
        }
        prop_assert!(m.connectivity_restored());
        prop_assert_eq!(entries, (m.durable().pf_reference, m.durable().older_references.clone(), m.durable().uncertain_acquires.clone(), m.durable().reference_intent));
    }

    #[test]
    fn lifecycle_events_preserve_reference_bound_and_require_a_held_token_for_protection(
        tokens in prop::collection::btree_set(1u64..1000, 0..=2),
        uncertain in 0usize..=2,
        events in prop::collection::vec(0u8..13, 1..100),
    ) {
        let tokens: Vec<_> = tokens.into_iter().collect();
        let uncertain = uncertain.min(2 - tokens.len());
        let mut m = Machine::restart(Durable {
            pf_reference: tokens.first().copied(), older_references: tokens.iter().skip(1).copied().collect(),
            uncertain_acquires: (1..=u64::try_from(uncertain).unwrap()).collect(), reference_sequence: 2,
            ..Durable::default()
        });
        let mut now = 0;
        for kind in events {
            now += 1;
            assert_reference_invariants(&m, now);

            let event = match (kind, m.pending()) {
                (0, Some(Step::ReconcileReference)) => Event::Failed(Reason::Observation("undecidable")),
                (1, Some(Step::Backoff { until })) => { now = now.max(until); Event::Completed(Step::Backoff { until }) },
                (2, _) if m.durable().pf_reference.is_some() => Event::ReferenceSettled { entry: ReferenceEntry::Token(m.durable().pf_reference.unwrap()), how: ReferenceSettlement::Absent },
                (3, _) if !m.durable().uncertain_acquires.is_empty() => Event::ReferenceSettled { entry: ReferenceEntry::Acquire(m.durable().uncertain_acquires[0]), how: ReferenceSettlement::Void },
                (4, _) => observed(&m, Form::PreTunnel, Verdict::Repair(Action::EnableAndRejoin)),
                (5, _) => observed(&m, Form::PreTunnel, Verdict::Unknown { since: now }),
                (6, Some(Step::ReconcileReference)) => complete_event(&m, 1),
                (7, _) => Event::Join,
                (8, _) => Event::Leave,
                (9, _) => Event::ChildDied,
                (10, _) => observed(&m, Form::PreTunnel, Verdict::NotProtected(Reason::Observation("lost protection"))),
                (11, Some(_)) => { now = executor_time(&m, now); checked_completion_at(&m, now) },
                _ => Event::InvalidateObservations { since: now },
            };
            match m.transition(event, &Clock(now)) {
                Ok(next) => m = next,
                Err(_) if kind == 7 => {}, // Join is refused during another mutation.
                Err(error) => panic!("unexpected event {kind} rejection: {error:?}; {m:?}"),
            }
        }
        assert_reference_invariants(&m, now);
    }
}

#[test]
fn idle_empty_reconciliation_never_acquires() {
    let m = Machine::restart(Durable {
        pf_reference: Some(71),
        ..Durable::default()
    });
    let m = settled(
        &m,
        ReferenceEntry::Token(71),
        ReferenceSettlement::Released,
        100,
    );
    let m = m.transition(complete_event(&m, 1), &Clock(100)).unwrap();
    assert_eq!(m.pending(), None);
    assert!(m.connectivity_restored());
    assert!(m.cleanup_confirmed());
    assert_eq!(m.durable().reference_intent, None);
}

#[test]
fn idle_reference_retry_resets_on_disabled_transition_and_mode_changes() {
    let mut m = Machine::restart(Durable {
        pf_reference: Some(71),
        ..Durable::default()
    });
    for now in [0, 1, 3] {
        if matches!(m.pending(), Some(Step::Backoff { .. })) {
            m = m
                .transition(Event::Completed(m.pending().unwrap()), &Clock(now))
                .unwrap();
        }
        m = m
            .transition(
                Event::Failed(Reason::Observation("undecidable")),
                &Clock(now),
            )
            .unwrap();
    }
    assert_eq!(m.pending(), Some(Step::Backoff { until: 7 }));
    let m = m
        .transition(
            observed(
                &m,
                Form::PreTunnel,
                Verdict::Repair(Action::EnableAndRejoin),
            ),
            &Clock(3),
        )
        .unwrap();
    assert_eq!(m.pending(), Some(Step::ReconcileReference));
    assert!(!m.plan().contains(&Step::AcquireReference));
    let m = m
        .transition(Event::Failed(Reason::Observation("undecidable")), &Clock(3))
        .unwrap();
    assert_eq!(m.pending(), Some(Step::Backoff { until: 4 }));
    let m = m.transition(Event::Join, &Clock(3)).unwrap();
    assert_eq!(m.pending(), Some(Step::PersistIntent));
    let m = m
        .transition(Event::Completed(Step::PersistIntent), &Clock(3))
        .unwrap();
    let m = m.transition(Event::Leave, &Clock(3)).unwrap();
    let m = m
        .transition(
            Event::Failed(Reason::Observation("cancel active boundary")),
            &Clock(3),
        )
        .unwrap();
    let mut now = 3;
    let m = drive_to(m, None, &mut now);
    assert!(m.connectivity_restored());
    assert_eq!(m.pending(), Some(Step::ReconcileReference));
    let m = m
        .transition(
            Event::Failed(Reason::Observation("undecidable")),
            &Clock(now),
        )
        .unwrap();
    assert_eq!(m.pending(), Some(Step::Backoff { until: now + 1 }));
}

#[test]
fn left_retains_release_intent_and_both_tokens_until_exact_settlements() {
    let m = Machine::restart(Durable {
        leaving: true,
        pf_reference: Some(71),
        older_references: vec![72],
        reference_intent: Some(ReferenceIntent::Release),
        reference_sequence: 9,
        reference_error: Some(Reason::Observation("release debt")),
        ..Durable::default()
    });
    assert_eq!(m.pending(), Some(Step::ClearIntent));
    let m = m
        .transition(Event::Completed(Step::ClearIntent), &Clock(100))
        .unwrap();
    assert!(m.connectivity_restored());
    assert!(!m.cleanup_confirmed());
    assert_eq!(m.durable().pf_reference, Some(71));
    assert_eq!(m.durable().older_references, vec![72]);
    assert_eq!(m.durable().reference_intent, Some(ReferenceIntent::Release));
    assert_eq!(m.durable().reference_sequence, 9);
    assert_eq!(m.pending(), Some(Step::ReconcileReference));
    assert!(!m.plan().contains(&Step::AcquireReference));
    let m = settled(
        &m,
        ReferenceEntry::Token(71),
        ReferenceSettlement::Released,
        100,
    );
    assert!(m.durable().reference_error.is_some());
    let m = settled(
        &m,
        ReferenceEntry::Token(72),
        ReferenceSettlement::Absent,
        100,
    );
    assert_eq!(m.durable().reference_intent, None);
    assert!(m.durable().reference_error.is_none());
    let m = m.transition(complete_event(&m, 1), &Clock(100)).unwrap();
    assert!(m.cleanup_confirmed());
}

fn assert_reference_invariants(m: &Machine, now: u64) {
    let slots = usize::from(m.durable().pf_reference.is_some())
        + m.durable().older_references.len()
        + m.durable().uncertain_acquires.len()
        + usize::from(matches!(
            m.durable().reference_intent,
            Some(ReferenceIntent::Acquire(_))
        ));
    assert!(slots <= 2, "reference slots exceeded: {m:?}");
    assert!(
        !m.plan().contains(&Step::AcquireReference)
            || m.durable().join_intended
            || m.pending() == Some(Step::PersistIntent)
    );
    if m.durable().join_intended && m.durable().pf_reference.is_none() {
        assert!(!matches!(
            m.enforcement_at(&Clock(now)),
            Verdict::Protected(_)
        ));
    }
}

#[test]
fn join_during_idle_reconcile_waits_for_its_completion_even_on_failure() {
    for outcome in 0..3 {
        let mut m = Machine::restart(Durable {
            pf_reference: Some(71),
            ..Durable::default()
        });
        m = m.transition(Event::Join, &Clock(100)).unwrap();
        assert_eq!(m.pending(), Some(Step::ReconcileReference));
        assert!(!m.durable().join_intended);
        assert_eq!(
            m.status_at(&Clock(100)),
            ConnectionStatus::JoiningRecovering
        );
        assert!(!m.connectivity_restored());
        assert!(m.transition(Event::Join, &Clock(100)).is_err());
        if outcome == 2 {
            m = settled(
                &m,
                ReferenceEntry::Token(71),
                ReferenceSettlement::Absent,
                100,
            );
            assert_eq!(m.pending(), Some(Step::ReconcileReference));
        }
        let event = if outcome == 1 {
            Event::Failed(Reason::Observation("idle reconcile failed"))
        } else {
            complete_event(&m, 1)
        };
        m = m.transition(event, &Clock(100)).unwrap();
        assert_eq!(m.pending(), Some(Step::PersistIntent));
        let m = finish(m, 1);
        assert!(m.durable().join_intended);
        assert!(matches!(
            m.enforcement_at(&Clock(102)),
            Verdict::Protected(_)
        ));
    }
}

#[test]
fn joined_last_reference_settlement_invalidates_proof_even_if_summary_fails() {
    for uncertain in [false, true] {
        let mut now = 1000;
        let mut m = Machine::restart(Durable::default())
            .transition(Event::Join, &Clock(now))
            .unwrap();
        m = m
            .transition(Event::Completed(Step::PersistIntent), &Clock(now))
            .unwrap();
        // Lose the first acquire, then hold a replacement while the debt retries.
        m = m
            .transition(
                Event::Failed(Reason::Observation("lost acquire")),
                &Clock(now),
            )
            .unwrap();
        m = m
            .transition(
                Event::Failed(Reason::Observation("undecidable")),
                &Clock(now),
            )
            .unwrap();
        assert_eq!(m.pending(), Some(Step::AcquireReference));
        m = m
            .transition(Event::ReferenceAcquired(71), &Clock(now))
            .unwrap();
        for _ in 0..100 {
            if matches!(m.enforcement_at(&Clock(now)), Verdict::Protected(p) if p.form() == Form::Joined)
            {
                break;
            }
            now = executor_time(&m, now);
            let event = if m.pending() == Some(Step::ReconcileReference) {
                Event::Failed(Reason::Observation("undecidable"))
            } else {
                checked_completion_at(&m, now)
            };
            m = m.transition(event, &Clock(now)).unwrap();
        }
        assert!(matches!(
            m.enforcement_at(&Clock(now)),
            Verdict::Protected(_)
        ));
        if let Some(Step::Backoff { until }) = m.pending() {
            now = until;
            m = m
                .transition(Event::Completed(Step::Backoff { until }), &Clock(now))
                .unwrap();
        }
        assert_eq!(m.pending(), Some(Step::ReconcileReference));
        if !uncertain {
            // This case has only the current held entry when settlement arrives.
            m = settled(
                &m,
                ReferenceEntry::Acquire(1),
                ReferenceSettlement::Void,
                now,
            );
        }
        assert!(matches!(
            m.enforcement_at(&Clock(now)),
            Verdict::Protected(_)
        ));
        m = settled(
            &m,
            ReferenceEntry::Token(71),
            ReferenceSettlement::Absent,
            now,
        );
        assert!(!matches!(
            m.enforcement_at(&Clock(now)),
            Verdict::Protected(_)
        ));
        assert_eq!(m.pending(), Some(Step::ReconcileReference));
        m = m
            .transition(
                Event::Failed(Reason::Observation("summary failed")),
                &Clock(now),
            )
            .unwrap();
        assert!(!matches!(
            m.enforcement_at(&Clock(now)),
            Verdict::Protected(_)
        ));
        assert!(m.plan().contains(&Step::AcquireReference));
        assert_reference_invariants(&m, now);
    }
}

#[test]
fn left_observations_preserve_reconcile_and_do_not_record_errors() {
    // A failed PersistIntent leaves no join intent, even though closing had begun.
    let left = Machine::restart(Durable::default())
        .transition(Event::Join, &Clock(0))
        .unwrap()
        .transition(
            Event::Failed(Reason::Observation("persist intent failed")),
            &Clock(0),
        )
        .unwrap();
    for verdict in [
        Verdict::NotProtected(Reason::HookMissing),
        Verdict::Unknown { since: 0 },
        Verdict::Repair(Action::Rejoin),
    ] {
        let next = left
            .transition(observed(&left, Form::PreTunnel, verdict), &Clock(0))
            .unwrap();
        assert_eq!(next.durable().last_error, left.durable().last_error);
        assert_eq!(next.plan(), left.plan());
    }
    for backoff in [false, true] {
        for verdict in [
            Verdict::NotProtected(Reason::Observation("monitor")),
            Verdict::Unknown { since: 1 },
            Verdict::Repair(Action::Rejoin),
        ] {
            let mut m = Machine::restart(Durable {
                pf_reference: Some(71),
                ..Durable::default()
            });
            if backoff {
                m = m
                    .transition(
                        Event::Failed(Reason::Observation("reference failure")),
                        &Clock(0),
                    )
                    .unwrap();
            }
            let before = m.clone();
            m = m
                .transition(observed(&m, Form::PreTunnel, verdict), &Clock(0))
                .unwrap();
            assert_eq!(m.plan(), before.plan());
            assert_eq!(m.durable().last_error, before.durable().last_error);
            // A later completion must not be discarded by abort_requested.
            let event = complete_event(&m, 1);
            let m = m.transition(event, &Clock(1)).unwrap();
            assert!(!m.plan().contains(&Step::AcquireReference));
        }
    }
}

#[test]
fn repeated_disabled_observations_preserve_idle_exponential_delay() {
    let mut m = Machine::restart(Durable {
        pf_reference: Some(71),
        ..Durable::default()
    });
    for now in [0, 1, 3, 7, 15, 31, 63] {
        if let Some(Step::Backoff { until }) = m.pending() {
            m = m
                .transition(Event::Completed(Step::Backoff { until }), &Clock(now))
                .unwrap();
        }
        let event = observed(
            &m,
            Form::PreTunnel,
            Verdict::Repair(Action::EnableAndRejoin),
        );
        m = m.transition(event, &Clock(now)).unwrap();
        m = m
            .transition(
                Event::Failed(Reason::Observation("undecidable")),
                &Clock(now),
            )
            .unwrap();
        let before = m.pending();
        m = m
            .transition(
                observed(
                    &m,
                    Form::PreTunnel,
                    Verdict::Repair(Action::EnableAndRejoin),
                ),
                &Clock(now),
            )
            .unwrap();
        assert_eq!(m.pending(), before);
    }
    assert_eq!(m.pending(), Some(Step::Backoff { until: 123 }));
}

#[test]
fn idle_reference_events_never_start_recovery() {
    let left = Machine::restart(Durable::default())
        .transition(
            Event::Failed(Reason::Observation("idle failure")),
            &Clock(0),
        )
        .unwrap();
    assert_eq!(left.pending(), None);
    assert_reference_invariants(&left, 0);
    let joining = Machine::restart(Durable::default())
        .transition(Event::Join, &Clock(0))
        .unwrap();
    let invalidated = joining
        .transition(Event::InvalidateObservations { since: 0 }, &Clock(0))
        .unwrap();
    assert_eq!(
        invalidated.plan(),
        joining.plan(),
        "not-yet-persisted Join must retain its plan"
    );
    for backoff in [false, true] {
        for kind in 0..4 {
            let mut m = Machine::restart(Durable {
                pf_reference: Some(71),
                ..Durable::default()
            });
            if backoff {
                m = m
                    .transition(Event::Failed(Reason::Observation("undecidable")), &Clock(0))
                    .unwrap();
            }
            let plan = m.plan().to_vec();
            if kind == 0 && !backoff {
                // Wake and an Unknown monitor describe the same idle evidence gap.
                // Neither may arm an abort of the reference effect in flight.
                let unknown = m
                    .transition(
                        observed(&m, Form::PreTunnel, Verdict::Unknown { since: 0 }),
                        &Clock(0),
                    )
                    .unwrap();
                let wake = m
                    .transition(Event::InvalidateObservations { since: 0 }, &Clock(0))
                    .unwrap();
                assert_eq!(wake, unknown);
            }
            let event = match kind {
                0 => Event::InvalidateObservations { since: 0 },
                1 => observed(&m, Form::PreTunnel, Verdict::Unknown { since: 0 }),
                2 => observed(&m, Form::PreTunnel, Verdict::Repair(Action::Rejoin)),
                _ => Event::Failed(Reason::Observation("reference failure")),
            };
            m = m.transition(event, &Clock(0)).unwrap();
            assert_reference_invariants(&m, 0);
            if kind < 3 {
                assert_eq!(m.plan(), plan, "event {kind}, backoff {backoff}");
            }
            if kind == 0 && !backoff {
                // Removing the in-flight invalidation guard must be observable at
                // the completion too: abort_requested would discard this retry.
                m = m
                    .transition(Event::Failed(Reason::Observation("undecidable")), &Clock(0))
                    .unwrap();
                assert!(matches!(m.pending(), Some(Step::Backoff { .. })));
            }
        }
    }
}

#[test]
fn fresh_leave_cleanup_never_plans_reference_release() {
    let mut m = joined().transition(Event::Leave, &Clock(102)).unwrap();
    assert_eq!(m.pending(), Some(Step::PersistLeaving));
    m = m
        .transition(Event::Completed(Step::PersistLeaving), &Clock(102))
        .unwrap();
    assert_eq!(
        m.plan(),
        &[
            Step::StopChild,
            Step::CleanupRoutes,
            Step::CleanupDns,
            Step::CleanupArtifacts,
            Step::RemoveAnchor
        ]
    );
    assert!(
        !m.durable()
            .pending_cleanup
            .contains(&Step::ReleaseReference)
    );
}

#[test]
fn join_from_left_with_two_entries_never_reserves_a_third_reference() {
    for uncertain in [false, true] {
        let mut m = Machine::restart(Durable {
            pf_reference: Some(71),
            older_references: if uncertain { vec![] } else { vec![72] },
            uncertain_acquires: if uncertain { vec![8] } else { vec![] },
            reference_sequence: 8,
            ..Durable::default()
        });
        m = m.transition(Event::Join, &Clock(100)).unwrap();
        assert_eq!(m.pending(), Some(Step::ReconcileReference));
        m = m
            .transition(
                Event::Failed(Reason::Observation("undecidable")),
                &Clock(100),
            )
            .unwrap();
        assert_eq!(m.pending(), Some(Step::PersistIntent));
        assert_reference_invariants(&m, 100);
        m = m
            .transition(Event::Completed(Step::PersistIntent), &Clock(100))
            .unwrap();
        assert_reference_invariants(&m, 100);
        assert!(!m.plan().contains(&Step::AcquireReference));
    }
}

#[test]
fn settlement_during_leave_never_restarts_a_join_after_clear_intent() {
    let mut m = joined()
        .transition(Event::Repair(Action::Rejoin), &Clock(102))
        .unwrap();
    m = m.transition(Event::Leave, &Clock(102)).unwrap();
    m = settled(
        &m,
        ReferenceEntry::Token(m.durable().pf_reference.unwrap()),
        ReferenceSettlement::Absent,
        102,
    );
    m = m
        .transition(Event::Completed(Step::LoadPreTunnel), &Clock(102))
        .unwrap();
    m = m
        .transition(Event::Completed(Step::PersistLeaving), &Clock(102))
        .unwrap();
    for step in [
        Step::StopChild,
        Step::CleanupRoutes,
        Step::CleanupDns,
        Step::CleanupArtifacts,
        Step::RemoveAnchor,
        Step::ClearIntent,
    ] {
        assert_eq!(m.pending(), Some(step));
        m = m.transition(Event::Completed(step), &Clock(102)).unwrap();
        assert_reference_invariants(&m, 102);
    }
    assert!(m.connectivity_restored());
}

#[test]
fn leave_cancels_a_join_deferred_behind_idle_reconciliation() {
    let mut m = Machine::restart(Durable {
        pf_reference: Some(71),
        ..Durable::default()
    });
    m = m.transition(Event::Join, &Clock(100)).unwrap();
    m = m.transition(Event::Leave, &Clock(100)).unwrap();
    assert_eq!(m.pending(), Some(Step::ReconcileReference));
    m = m
        .transition(
            Event::Failed(Reason::Observation("undecidable")),
            &Clock(100),
        )
        .unwrap();
    assert_eq!(m.pending(), Some(Step::PersistLeaving));
    let m = finish(m, 1);
    assert!(m.connectivity_restored());
    assert!(!m.durable().join_intended);
    assert!(!m.plan().contains(&Step::PersistIntent));
}

// Follow-up A1: start Join at the maximum Left accounting delay. Inspect every
// boundary instead of jumping across Backoff in finish().
#[test]
fn join_from_sixty_second_left_backoff_resets_reconciliation_delay() {
    for needs_reconcile in [false, true] {
        let mut m = Machine::restart(Durable {
            pf_reference: needs_reconcile.then_some(71),
            uncertain_acquires: if needs_reconcile { vec![] } else { vec![8] },
            reference_sequence: 8,
            reference_needs_reconcile: needs_reconcile,
            ..Durable::default()
        });
        let mut now = 0;
        for delay in [1, 2, 4, 8, 16, 32, 60] {
            m = m
                .transition(
                    Event::Failed(Reason::Observation("undecidable")),
                    &Clock(now),
                )
                .unwrap();
            assert_eq!(m.pending(), Some(Step::Backoff { until: now + delay }));
            if delay < 60 {
                now += delay;
                m = m
                    .transition(Event::Completed(m.pending().unwrap()), &Clock(now))
                    .unwrap();
            }
        }
        m = m.transition(Event::Join, &Clock(now)).unwrap();
        // Resetting a timer must not reinterpret a not-yet-dispatched reconcile
        // as in flight; either accepted boundary remains serialized.
        if m.pending() == Some(Step::ReconcileReference) {
            m = m
                .transition(
                    Event::Failed(Reason::Observation("deferred reconcile")),
                    &Clock(now),
                )
                .unwrap();
        }
        assert_eq!(m.pending(), Some(Step::PersistIntent));
        for _ in 0..80 {
            assert!(
                m.plan()
                    .iter()
                    .all(|s| !matches!(s, Step::Backoff { until } if *until > now + 1)),
                "{m:?}"
            );
            if matches!(m.enforcement_at(&Clock(now)), Verdict::Protected(p) if p.form() == Form::Joined)
            {
                assert_ne!(
                    m.status_at(&Clock(now)),
                    ConnectionStatus::Recovering { retry_in: 60 }
                );
                assert_eq!(m.status_at(&Clock(now)), ConnectionStatus::Joined);
                break;
            }
            now = executor_time(&m, now);
            m = m
                .transition(checked_completion_at(&m, now), &Clock(now))
                .unwrap();
        }
        assert!(
            matches!(m.enforcement_at(&Clock(now)), Verdict::Protected(p) if p.form() == Form::Joined)
        );
    }
}

#[test]
fn join_from_left_retained_reference_acquires_before_loading_policy() {
    for durable in [
        Durable {
            pf_reference: Some(71),
            ..Durable::default()
        },
        Durable {
            older_references: vec![71],
            ..Durable::default()
        },
        Durable {
            uncertain_acquires: vec![8],
            reference_sequence: 8,
            ..Durable::default()
        },
    ] {
        let mut m = Machine::restart(durable);
        m = m.transition(Event::Join, &Clock(100)).unwrap();
        m = m
            .transition(
                Event::Failed(Reason::Observation("retained entry unverified")),
                &Clock(100),
            )
            .unwrap();
        m = m
            .transition(Event::Completed(Step::PersistIntent), &Clock(100))
            .unwrap();
        assert!(m.plan().contains(&Step::AcquireReference));
        if m.pending() == Some(Step::ReconcileReference) {
            m = m
                .transition(
                    Event::Failed(Reason::Observation("undecidable")),
                    &Clock(100),
                )
                .unwrap();
        }
        assert_eq!(m.pending(), Some(Step::AcquireReference));
        assert_reference_invariants(&m, 100);
        m = m
            .transition(Event::ReferenceAcquired(72), &Clock(100))
            .unwrap();
        assert_eq!(m.durable().pf_reference, Some(72));
        assert_eq!(m.pending(), Some(Step::LoadPreTunnel));
        assert_reference_invariants(&m, 100);
    }
}

#[test]
fn restart_strips_legacy_release_cleanup_and_records_the_error() {
    let m = Machine::restart(Durable {
        leaving: true,
        pending_cleanup: vec![Step::StopChild, Step::ReleaseReference],
        pf_reference: Some(71),
        ..Durable::default()
    });
    assert!(
        !m.durable()
            .pending_cleanup
            .contains(&Step::ReleaseReference)
    );
    assert!(
        m.durable()
            .cleanup_errors
            .iter()
            .any(|(s, _)| *s == Step::ReleaseReference)
    );
    let m = m
        .transition(Event::Completed(Step::StopChild), &Clock(100))
        .unwrap();
    let m = m
        .transition(Event::Completed(Step::ClearIntent), &Clock(100))
        .unwrap();
    assert!(m.connectivity_restored());
    assert_eq!(m.durable().pf_reference, Some(71));
}

#[test]
fn protected_observation_with_two_uncertain_entries_cannot_publish_protected() {
    let mut m = Machine::restart(Durable {
        join_intended: true,
        uncertain_acquires: vec![7, 8],
        reference_sequence: 8,
        ..Durable::default()
    });
    let mut now = 100;
    m = drive_to(m, Some(Step::VerifyPreTunnel), &mut now);
    let event = checked_completion_at(&m, now);
    assert!(matches!(
        &event,
        Event::Observed {
            verdict: Verdict::Protected(_),
            ..
        }
    ));
    let m = m.transition(event, &Clock(now)).unwrap();
    assert!(!matches!(
        m.enforcement_at(&Clock(now)),
        Verdict::Protected(_)
    ));
    assert_reference_invariants(&m, now);
}

proptest! {
    #[test]
    fn join_replaces_a_retained_entry_without_exceeding_two_slots(token in 1u64..1000, kind in 0u8..3) {
        let m = Machine::restart(Durable {
            pf_reference: (kind == 0).then_some(token),
            older_references: if kind == 1 { vec![token] } else { vec![] },
            uncertain_acquires: if kind == 2 { vec![1] } else { vec![] },
            reference_sequence: 1,
            ..Durable::default()
        });
        let m = m.transition(Event::Join, &Clock(100)).unwrap();
        let m = m.transition(Event::Failed(Reason::Observation("unverified")), &Clock(100)).unwrap();
        let m = m.transition(Event::Completed(Step::PersistIntent), &Clock(100)).unwrap();
        prop_assert!(m.plan().contains(&Step::AcquireReference));
        let m = if m.pending() == Some(Step::ReconcileReference) {
            m.transition(Event::Failed(Reason::Observation("undecidable")), &Clock(100)).unwrap()
        } else { m };
        prop_assert_eq!(m.pending(), Some(Step::AcquireReference));
        assert_reference_invariants(&m, 100);
        let m = m.transition(Event::ReferenceAcquired(token + 1), &Clock(100)).unwrap();
        assert_reference_invariants(&m, 100);
    }
}

#[test]
fn enabled_pf_read_rearms_disabled_transition_in_every_mode_even_with_unknown_verdict() {
    for mode in 0..4 {
        let mut m = Machine::restart(Durable {
            join_intended: mode == 1 || mode == 3,
            hold: mode == 3,
            leaving: mode == 2,
            pf_reference: Some(71),
            ..Durable::default()
        });
        let read = |m: &Machine, enabled| {
            if enabled {
                Event::PfEnabledObserved {
                    context: m.context(),
                }
            } else {
                observed(m, Form::PreTunnel, Verdict::Repair(Action::EnableAndRejoin))
            }
        };
        m = m.transition(read(&m, false), &Clock(0)).unwrap();
        if mode == 0 {
            m = m
                .transition(Event::Failed(Reason::Observation("debt")), &Clock(0))
                .unwrap();
            assert_eq!(m.pending(), Some(Step::Backoff { until: 1 }));
        }
        m = m.transition(read(&m, true), &Clock(0)).unwrap();
        m = m
            .transition(
                observed(&m, Form::PreTunnel, Verdict::Unknown { since: 0 }),
                &Clock(0),
            )
            .unwrap();
        m = m.transition(read(&m, false), &Clock(0)).unwrap();
        if mode == 0 {
            assert_eq!(m.pending(), Some(Step::ReconcileReference));
            m = m
                .transition(Event::Failed(Reason::Observation("debt")), &Clock(0))
                .unwrap();
            assert_eq!(m.pending(), Some(Step::Backoff { until: 1 }));
        }
        let before = m.clone();
        assert!(
            m.transition(
                Event::PfEnabledObserved {
                    context: Context::default(),
                },
                &Clock(0)
            )
            .is_err()
        );
        assert_eq!(m, before);
    }
}

fn held() -> Machine {
    let mut m = Machine::restart(Durable {
        join_intended: true,
        hold: true,
        ..Durable::default()
    });
    let mut now = 100;
    for _ in 0..30 {
        if m.pending().is_none() {
            assert!(m.blocking_verified_at(&Clock(now)));
            return m;
        }
        now = executor_time(&m, now);
        m = m
            .transition(checked_completion_at(&m, now), &Clock(now))
            .unwrap();
    }
    panic!("hold did not become idle: {m:?}");
}

// Canonical Recovery: another product holds pf enabled, so neither uncertain
// acquisition can be decided. Accounting waits while blocking remains verified.
fn recovery_held() -> Machine {
    let mut m = Machine::restart(Durable {
        join_intended: true,
        hold: true,
        uncertain_acquires: vec![1, 2],
        reference_sequence: 2,
        ..Durable::default()
    });
    m = m
        .transition(
            Event::Failed(Reason::Observation("other product owns pf")),
            &Clock(100),
        )
        .unwrap();
    for _ in 0..12 {
        if matches!(m.pending(), Some(Step::Backoff { .. })) {
            assert_eq!(
                m.plan(),
                [Step::Backoff { until: 101 }, Step::ReconcileReference]
            );
            assert!(m.blocking_verified_at(&Clock(100)));
            return m;
        }
        m = m
            .transition(checked_completion_at(&m, 100), &Clock(100))
            .unwrap();
    }
    panic!("Recovery did not become idle-held: {m:?}");
}

#[test]
fn held_disabled_pf_reconciles_full_slots_before_acquiring_and_verifying() {
    let mut m = recovery_held();
    // The other product releases its last reference while accounting is parked.
    m = m
        .transition(
            observed(
                &m,
                Form::PreTunnel,
                Verdict::Repair(Action::EnableAndRejoin),
            ),
            &Clock(100),
        )
        .unwrap();
    assert_eq!(m.pending(), Some(Step::ReconcileReference));
    assert!(!m.plan().contains(&Step::AcquireReference));
    // The pf-disabled rule voids both uncertain acquisitions in this call.
    for sequence in [1, 2] {
        m = m
            .transition(
                Event::ReferenceSettled {
                    entry: ReferenceEntry::Acquire(sequence),
                    how: ReferenceSettlement::Void,
                },
                &Clock(100),
            )
            .unwrap();
        assert_eq!(m.pending(), Some(Step::ReconcileReference));
    }
    m = m
        .transition(
            Event::ReferenceReconciled {
                context: m.context(),
                current: None,
                predecessor: None,
            },
            &Clock(100),
        )
        .unwrap();
    assert_eq!(m.pending(), Some(Step::AcquireReference));
    assert_eq!(m.plan().get(1), Some(&Step::LoadPreTunnel));
    let mut pf_enabled = false;
    for _ in 0..12 {
        let Some(step) = m.pending() else {
            break;
        };
        assert!(!matches!(step, Step::Backoff { .. }));
        if step == Step::AcquireReference {
            pf_enabled = true;
        }
        if step == Step::VerifyPreTunnel {
            assert!(pf_enabled);
        }
        m = m
            .transition(checked_completion_at(&m, 100), &Clock(100))
            .unwrap();
    }
    assert!(pf_enabled);
    assert!(m.blocking_verified_at(&Clock(100)));
    assert_eq!(m.durable().uncertain_acquires, [] as [u64; 0]);
}

#[test]
fn held_fresh_prefix_loads_before_accounting_when_pf_does_not_need_enabling() {
    let mut m = Machine::restart(Durable {
        join_intended: true,
        hold: true,
        pf_reference: Some(702),
        older_references: vec![701],
        ..Durable::default()
    });
    m = m.transition(complete_event(&m, 1), &Clock(100)).unwrap();
    for _ in 0..12 {
        if matches!(m.pending(), Some(Step::Backoff { .. })) {
            break;
        }
        m = m
            .transition(checked_completion_at(&m, 100), &Clock(100))
            .unwrap();
    }
    assert_eq!(
        m.plan(),
        [Step::Backoff { until: 101 }, Step::ReconcileReference]
    );
    // No acquisition is needed: these are held tokens, not uncertain acquires.
    // Full slots still get an attempt in this prefix, after blocking is restored.
    let mut m = m
        .transition(Event::Repair(Action::Rejoin), &Clock(100))
        .unwrap();
    assert_eq!(
        m.plan(),
        [
            Step::LoadPreTunnel,
            Step::VerifyPreTunnelLoad,
            Step::FlushStates,
            Step::VerifyPreTunnel,
            Step::ReconcileReference,
        ]
    );
    for _ in 0..4 {
        m = m
            .transition(checked_completion_at(&m, 100), &Clock(100))
            .unwrap();
    }
    assert_eq!(m.pending(), Some(Step::ReconcileReference));
}

#[test]
fn held_lost_anchor_loads_before_failed_accounting_with_both_slots_uncertain() {
    let mut m = recovery_held()
        .transition(
            Event::Repair(Action::Rerender {
                form: Form::PreTunnel,
            }),
            &Clock(100),
        )
        .unwrap();
    assert_eq!(m.pending(), Some(Step::LoadPreTunnel));
    for _ in 0..4 {
        m = m
            .transition(checked_completion_at(&m, 100), &Clock(100))
            .unwrap();
    }
    assert!(m.blocking_verified_at(&Clock(100)));
    assert_eq!(m.pending(), Some(Step::ReconcileReference));
    m = m
        .transition(
            Event::Failed(Reason::Observation("still undecidable")),
            &Clock(100),
        )
        .unwrap();
    assert!(m.blocking_verified_at(&Clock(100)));
}

proptest! {
    #[test]
    fn under_hold_disabled_pf_reconciles_before_the_next_closing_prefix_completes(
        direct in any::<bool>(), elapsed in 0u64..=1,
        reference_state in 0u8..3, cleanup in 0u8..3, mid_prefix in any::<bool>(),
        reconcile_failures in 0usize..=2,
    ) {
        let initially_free_slot = reference_state != 0;
        let mut m = if cleanup > 0 {
            held_route_cleanup_retry(initially_free_slot)
        } else if reference_state == 2 {
            Machine::restart(Durable {
                join_intended: true,
                hold: true,
                uncertain_acquires: vec![1],
                pf_reference: None,
                reference_sequence: 1,
                ..Durable::default()
            })
        } else if initially_free_slot {
            held()
        } else {
            recovery_held()
        };
        let mut now = 100;
        if cleanup == 2 {
            now = executor_time(&m, now);
            m = m.transition(checked_completion_at(&m, now), &Clock(now)).unwrap();
            prop_assert_eq!(m.pending(), Some(Step::CleanupRoutes));
        }
        if mid_prefix {
            m = m.transition(Event::Repair(Action::Rejoin), &Clock(now)).unwrap();
            for _ in 0..12 {
                if m.pending() == Some(Step::LoadPreTunnel) { break; }
                now = executor_time(&m, now);
                m = m.transition(checked_completion_at(&m, now), &Clock(now)).unwrap();
            }
            prop_assert_eq!(m.pending(), Some(Step::LoadPreTunnel));
            m = m.transition(checked_completion_at(&m, now), &Clock(now)).unwrap();
            prop_assert_eq!(m.pending(), Some(Step::VerifyPreTunnelLoad));
        }
        let free_slot = usize::from(m.durable().pf_reference.is_some())
            + m.durable().older_references.len() + m.durable().uncertain_acquires.len() < 2;
        let event = if direct { Event::Repair(Action::EnableAndRejoin) }
            else { observed(&m, Form::PreTunnel, Verdict::Repair(Action::EnableAndRejoin)) };
        m = m.transition(event, &Clock(now)).unwrap();
        let mut failures = 0;
        let mut reconciled = false;
        let mut pf_enabled = false;
        let mut acquisition_verified = false;
        let mut reconcile_dispatched = false;
        let mut prefix_attempts = 0;
        let mut plans_since_progress = vec![];
        let mut dispatched = vec![];
        while !(reconciled && pf_enabled && m.blocking_verified_at(&Clock(now))) {
            now = executor_time(&m, now + elapsed);
            prop_assert!(m.pending().is_some(), "closing prefix became idle before convergence");
            let step = m.pending().unwrap();
            dispatched.push(step);
            // Each attempt must advance, verify, or consume an injected failure.
            // This rejects a stuck queue without a loose boundary/time budget.
            prop_assert!(!plans_since_progress.iter().any(|(context, plan)|
                *context == m.context() && plan == m.plan()),
                "no progress at {:?}", m.plan());
            plans_since_progress.push((m.context(), m.plan().to_vec()));
            assert_no_held_accounting_wait(&m);
            if step == Step::VerifyPreTunnel {
                prop_assert!(free_slot || reconcile_dispatched,
                    "full references must reconcile before the first post-disable verification");
                prefix_attempts += 1;
                prop_assert!(prefix_attempts <= reconcile_failures + 1,
                    "convergence exceeded failures + 1 prefix attempts: {dispatched:?}");
                plans_since_progress.clear();
            }
            let event = if step == Step::ReconcileReference {
                reconcile_dispatched = true;
                if failures < reconcile_failures {
                    failures += 1;
                    plans_since_progress.clear();
                    Event::Failed(Reason::Observation("injected undecidable reconcile"))
                } else {
                    // After the injected failures, obtain checked evidence. With
                    // disabled pf, void uncertain entries and recorded tokens;
                    // once enabled and verified, release retained predecessors.
                    for sequence in m.durable().uncertain_acquires.clone() {
                        m = settled(&m, ReferenceEntry::Acquire(sequence), ReferenceSettlement::Void, now);
                    }
                    if pf_enabled {
                        for token in m.durable().older_references.clone() {
                            prop_assert!(acquisition_verified);
                            m = settled(&m, ReferenceEntry::Token(token), ReferenceSettlement::Released, now);
                        }
                    } else {
                        let tokens: Vec<_> = m.durable().pf_reference.into_iter()
                            .chain(m.durable().older_references.iter().copied()).collect();
                        for token in tokens {
                            m = settled(&m, ReferenceEntry::Token(token), ReferenceSettlement::Void, now);
                        }
                    }
                    reconciled = true;
                    Event::ReferenceReconciled { context: m.context(), current: m.durable().pf_reference, predecessor: None }
                }
            } else if step == Step::VerifyPreTunnel && !pf_enabled {
                observed(&m, Form::PreTunnel, Verdict::Repair(Action::EnableAndRejoin))
            } else {
                if step == Step::AcquireReference {
                    pf_enabled = true;
                    acquisition_verified = false;
                }
                checked_completion_at(&m, now)
            };
            m = m.transition(event, &Clock(now)).unwrap();
            acquisition_verified |= step == Step::VerifyPreTunnel && m.blocking_verified_at(&Clock(now));
            assert_reference_invariants(&m, now);
        }
        prop_assert_eq!(failures, reconcile_failures);
        prop_assert!(prefix_attempts > 0 && prefix_attempts <= failures + 1);
        prop_assert!(reconciled, "accounting starved across held prefix attempts");
        prop_assert!(m.blocking_verified_at(&Clock(now)));
    }
}

#[test]
fn hold_restart_plans_accounting_prefix_and_cleanup_without_a_rejoin_suffix() {
    for uncertain in 0..=2 {
        let m = Machine::restart(Durable {
            join_intended: true,
            hold: true,
            uncertain_acquires: (1..=uncertain).collect(),
            reference_sequence: 2,
            retry_attempts: 7,
            ..Durable::default()
        });
        let mut expected = vec![];
        if uncertain == 2 {
            expected.push(Step::ReconcileReference);
        }
        if uncertain < 2 {
            expected.push(Step::AcquireReference);
        }
        expected.extend([
            Step::LoadPreTunnel,
            Step::VerifyPreTunnelLoad,
            Step::FlushStates,
            Step::VerifyPreTunnel,
        ]);
        if uncertain == 1 {
            expected.push(Step::ReconcileReference);
        }
        expected.extend([
            Step::StopChild,
            Step::CleanupRoutes,
            Step::CleanupDns,
            Step::CleanupArtifacts,
        ]);
        assert_eq!(m.plan(), expected);
        assert!(m.durable().hold);
        assert!(!m.blocking_verified_at(&Clock(100)));
    }
    let m = held();
    assert_eq!(m.pending(), None);
    assert_eq!(m.tunnel(), None);
    assert_eq!(
        m.enforcement_at(&Clock(100)),
        Verdict::NotProtected(Reason::Observation("state untrusted: run leave"))
    );
    assert!(m.status_text_at(&Clock(100)).contains("blocking verified"));
    let restarted = Machine::restart(m.durable().clone());
    assert!(restarted.durable().hold);
    assert!(!restarted.blocking_verified_at(&Clock(100)));
}

#[test]
fn idle_hold_refreshes_pre_tunnel_proof_without_planning_an_effect() {
    let m = held();
    let (o, e) = machine_fixture(&m, Form::PreTunnel, 1, 101);
    let verdict = verify::verify(&o, &e, &Clock(101));
    assert!(matches!(verdict, Verdict::Protected(_)));
    let m = m
        .transition(observed(&m, Form::PreTunnel, verdict), &Clock(101))
        .unwrap();
    assert_eq!(m.plan(), []);
    assert!(m.blocking_verified_at(&Clock(101)));
    assert!(!matches!(
        m.enforcement_at(&Clock(101)),
        Verdict::Protected(_)
    ));
    assert!(!m.blocking_verified_at(&Clock(1000)));
    assert!(!m.status_text_at(&Clock(1000)).contains("blocking verified"));
}

#[test]
fn idle_hold_repairs_losses_and_disabled_pf_with_only_the_closing_prefix() {
    let base = held();
    for event in [
        Event::Repair(Action::Rejoin),
        Event::Repair(Action::RecreateChild),
        Event::Repair(Action::Rerender {
            form: Form::PreTunnel,
        }),
        observed(
            &base,
            Form::PreTunnel,
            Verdict::NotProtected(Reason::HookMissing),
        ),
        observed(
            &base,
            Form::PreTunnel,
            Verdict::Repair(Action::EnableAndRejoin),
        ),
    ] {
        let mut m = base.transition(event, &Clock(101)).unwrap();
        let mut expected = vec![];
        if m.plan().contains(&Step::AcquireReference) {
            expected.push(Step::AcquireReference);
        }
        expected.extend([
            Step::LoadPreTunnel,
            Step::VerifyPreTunnelLoad,
            Step::FlushStates,
            Step::VerifyPreTunnel,
        ]);
        assert_eq!(m.plan(), expected);
        // Failed closing work retries after exactly one second.
        if m.pending() == Some(Step::AcquireReference) {
            m = m
                .transition(checked_completion_at(&m, 101), &Clock(101))
                .unwrap();
        }
        m = m
            .transition(
                Event::Failed(Reason::Observation("load failed")),
                &Clock(101),
            )
            .unwrap();
        // The failed load keeps its own deadline; accounting follows the
        // verification because no acquisition is needed to restore blocking.
        assert_eq!(m.pending(), Some(Step::Backoff { until: 102 }));
        assert_eq!(m.plan().get(1), Some(&Step::LoadPreTunnel));
        assert!(!m.plan().contains(&Step::StopChild));
    }
}

#[test]
fn idle_hold_gap_expiry_and_wake_flush_then_verify_and_reload_only_on_drift() {
    let base = held();
    for event in [
        Event::InvalidateObservations { since: 101 },
        observed(&base, Form::PreTunnel, Verdict::Unknown { since: 101 }),
        Event::ChildDied, // at a later time, expiry is noticed even on an ignored event
    ] {
        let now = if matches!(event, Event::ChildDied) {
            1000
        } else {
            101
        };
        let mut m = base.transition(event, &Clock(now)).unwrap();
        assert_eq!(m.plan(), [Step::FlushStates, Step::VerifyPreTunnel]);
        m = m
            .transition(checked_completion_at(&m, now), &Clock(now))
            .unwrap();
        let clean = m
            .transition(checked_completion_at(&m, now), &Clock(now))
            .unwrap();
        assert_eq!(clean.plan(), []);
        assert!(clean.blocking_verified_at(&Clock(now)));
        m = m
            .transition(
                observed(&m, Form::PreTunnel, Verdict::Repair(Action::Rejoin)),
                &Clock(now),
            )
            .unwrap();
        assert_eq!(m.pending(), Some(Step::LoadPreTunnel));
        assert!(m.plan().contains(&Step::VerifyPreTunnelLoad));
        assert!(!m.plan().contains(&Step::StopChild));
    }
}

#[test]
fn hold_ignores_child_died_without_changing_the_idle_machine() {
    let m = held();
    assert_eq!(m.transition(Event::ChildDied, &Clock(100)).unwrap(), m);
}

#[test]
fn join_is_refused_under_hold_at_restart_idle_and_during_leave() {
    let idle = held();
    for m in [
        Machine::restart(idle.durable().clone()),
        idle.clone(),
        idle.transition(Event::Leave, &Clock(100)).unwrap(),
    ] {
        let before = m.clone();
        assert!(m.transition(Event::Join, &Clock(100)).is_err());
        assert_eq!(m, before);
    }
}

#[test]
fn leave_under_hold_finishes_without_accounting_and_clear_intent_clears_both_flags() {
    for initial in [
        held(),
        Machine::restart(Durable {
            join_intended: true,
            hold: true,
            uncertain_acquires: vec![1, 2],
            reference_sequence: 2,
            ..Durable::default()
        }),
    ] {
        let mut m = initial.transition(Event::Leave, &Clock(100)).unwrap();
        if m.pending() != Some(Step::PersistLeaving) {
            m = m
                .transition(
                    Event::Failed(Reason::Observation("settle cancelled head")),
                    &Clock(100),
                )
                .unwrap();
        }
        m = m
            .transition(Event::Completed(Step::PersistLeaving), &Clock(100))
            .unwrap();
        assert!(m.durable().hold);
        for step in [
            Step::StopChild,
            Step::CleanupRoutes,
            Step::CleanupDns,
            Step::CleanupArtifacts,
            Step::RemoveAnchor,
            Step::ClearIntent,
        ] {
            assert_eq!(m.pending(), Some(step));
            m = m.transition(Event::Completed(step), &Clock(100)).unwrap();
        }
        assert!(!m.durable().hold);
        assert!(!m.durable().join_intended);
        assert!(m.connectivity_restored());
        assert!(m.transition(Event::Join, &Clock(100)).is_ok());
    }
}

#[test]
fn hold_reconcile_failure_never_parks_the_closing_prefix() {
    for uncertain in 0..=2 {
        let mut m = Machine::restart(Durable {
            join_intended: true,
            hold: true,
            pf_reference: (uncertain == 0).then_some(71),
            uncertain_acquires: (1..=uncertain).collect(),
            reference_sequence: 2,
            reference_needs_reconcile: true,
            ..Durable::default()
        });
        let mut failed = false;
        for _ in 0..16 {
            let step = m.pending().unwrap();
            if matches!(step, Step::Backoff { .. }) {
                break;
            }
            let event = if step == Step::ReconcileReference {
                assert!(!failed);
                failed = true;
                Event::Failed(Reason::Observation("undecidable"))
            } else {
                checked_completion_at(&m, 100)
            };
            m = m.transition(event, &Clock(100)).unwrap();
        }
        assert!(failed);
        assert!(m.blocking_verified_at(&Clock(100)));
        assert_eq!(
            m.plan(),
            [Step::Backoff { until: 101 }, Step::ReconcileReference]
        );
        // Fresh proofs also refresh while idle accounting is waiting.
        let (o, e) = machine_fixture(&m, Form::PreTunnel, 1, 100);
        let refreshed = m
            .transition(
                observed(&m, Form::PreTunnel, verify::verify(&o, &e, &Clock(100))),
                &Clock(100),
            )
            .unwrap();
        assert_eq!(refreshed.plan(), m.plan());
        // A wake cancels the accounting timer and runs only flush/verify.
        m = m
            .transition(Event::InvalidateObservations { since: 100 }, &Clock(100))
            .unwrap();
        assert_eq!(m.plan(), [Step::FlushStates, Step::VerifyPreTunnel]);
    }
}

proptest! {
    #[test]
    fn hold_never_plans_check_tools_reserve_generation_or_start_child(
        tokens in prop::collection::btree_set(1u64..1000, 0..=2),
        uncertain in 0usize..=2,
        events in prop::collection::vec((0u8..15, 0u64..4), 1..100),
    ) {
        let tokens: Vec<_> = tokens.into_iter().collect();
        let uncertain = uncertain.min(2 - tokens.len());
        let mut m = Machine::restart(Durable {
            join_intended: true, hold: true,
            pf_reference: tokens.first().copied(), older_references: tokens.iter().skip(1).copied().collect(),
            uncertain_acquires: (1..=u64::try_from(uncertain).unwrap()).collect(), reference_sequence: 2,
            ..Durable::default()
        });
        let mut now = 100;
        for (kind, elapsed) in events {
            now += elapsed;
            if m.durable().hold {
                prop_assert!(!m.plan().iter().any(|s| matches!(s, Step::CheckTools | Step::ReserveGeneration | Step::StartChild)));
                prop_assert!(!matches!(m.enforcement_at(&Clock(now)), Verdict::Protected(_)));
            }
            assert_reference_invariants(&m, now);
            let event = match kind {
                0 => Event::Join,
                1 => Event::Leave,
                2 => Event::ChildDied,
                3 => Event::Repair(Action::EnableAndRejoin),
                4 => Event::Repair(Action::Rerender { form: Form::PreTunnel }),
                5 => Event::InvalidateObservations { since: now },
                6 => observed(&m, Form::PreTunnel, Verdict::NotProtected(Reason::HookMissing)),
                7 => observed(&m, Form::PreTunnel, Verdict::Unknown { since: now }),
                8 => Event::Failed(Reason::Observation("injected hold failure")),
                9 => { m = Machine::restart(m.durable().clone()); continue; },
                10 => Event::PfEnabledObserved { context: m.context() },
                11 if m.durable().pf_reference.is_some() => Event::ReferenceSettled { entry: ReferenceEntry::Token(m.durable().pf_reference.unwrap()), how: ReferenceSettlement::Absent },
                _ if m.pending().is_some() => { now = executor_time(&m, now); checked_completion_at(&m, now) },
                _ => {
                    let (o, e) = machine_fixture(&m, Form::PreTunnel, 1, now);
                    observed(&m, Form::PreTunnel, verify::verify(&o, &e, &Clock(now)))
                },
            };
            if let Ok(next) = m.transition(event, &Clock(now)) { m = next; }
        }
        if m.durable().hold {
            prop_assert!(!m.plan().iter().any(|s| matches!(s, Step::CheckTools | Step::ReserveGeneration | Step::StartChild)));
        }
        assert_reference_invariants(&m, now);
    }
}

#[test]
fn held_maintenance_refreshes_cleanliness_without_changing_durable_state() {
    let m = held();
    let durable = m.durable().clone();
    let m = m
        .transition(
            Event::StatesClean {
                epoch: m.context().state_epoch,
                completed_at: 101,
            },
            &Clock(101),
        )
        .unwrap();
    assert_eq!(m.durable(), &durable);
    assert_eq!(m.states_clean_at(), Some(101));
    assert!(m.blocking_verified_at(&Clock(101)));
    assert_eq!(m.plan(), []);
}

#[test]
fn held_expiry_during_background_reconciliation_queues_flush_after_its_boundary() {
    let mut m = Machine::restart(Durable {
        join_intended: true,
        hold: true,
        uncertain_acquires: vec![1, 2],
        reference_sequence: 2,
        ..Durable::default()
    });
    m = m
        .transition(
            Event::Failed(Reason::Observation("undecidable")),
            &Clock(100),
        )
        .unwrap();
    for _ in 0..8 {
        if matches!(m.pending(), Some(Step::Backoff { .. })) {
            break;
        }
        m = m
            .transition(checked_completion_at(&m, 100), &Clock(100))
            .unwrap();
    }
    assert_eq!(
        m.plan(),
        [Step::Backoff { until: 101 }, Step::ReconcileReference]
    );
    let expired = m.transition(Event::ChildDied, &Clock(1000)).unwrap();
    assert_eq!(expired.plan(), [Step::FlushStates, Step::VerifyPreTunnel]);
    m = m
        .transition(Event::Completed(Step::Backoff { until: 101 }), &Clock(101))
        .unwrap();
    assert_eq!(m.pending(), Some(Step::ReconcileReference));
    // Its result is in flight when the old proof expires.
    m = m.transition(Event::ChildDied, &Clock(1000)).unwrap();
    assert_eq!(
        m.plan(),
        [
            Step::ReconcileReference,
            Step::FlushStates,
            Step::VerifyPreTunnel
        ]
    );
    m = m
        .transition(
            Event::Failed(Reason::Observation("still undecidable")),
            &Clock(1000),
        )
        .unwrap();
    assert_eq!(m.plan(), [Step::FlushStates, Step::VerifyPreTunnel]);
}

#[test]
fn recovery_hold_accepts_every_repair_with_accounting_waiting_or_in_flight() {
    for in_flight in [false, true] {
        let mut base = recovery_held();
        if in_flight {
            base = base
                .transition(Event::Completed(Step::Backoff { until: 101 }), &Clock(101))
                .unwrap();
        }
        for action in [
            Action::Rejoin,
            Action::EnableAndRejoin,
            Action::RecreateChild,
            Action::Rerender {
                form: Form::PreTunnel,
            },
            Action::Rerender { form: Form::Joined },
        ] {
            let mut m = base.transition(Event::Repair(action), &Clock(101)).unwrap();
            if in_flight {
                assert_eq!(m.plan(), [Step::ReconcileReference]);
                m = m
                    .transition(
                        Event::Failed(Reason::Observation("in-flight accounting")),
                        &Clock(101),
                    )
                    .unwrap();
            }
            if action == Action::EnableAndRejoin {
                assert_eq!(m.pending(), Some(Step::ReconcileReference));
                m = m
                    .transition(
                        Event::Failed(Reason::Observation("undecidable")),
                        &Clock(101),
                    )
                    .unwrap();
            } else {
                assert_eq!(m.pending(), Some(Step::LoadPreTunnel));
                assert_eq!(m.plan().last(), Some(&Step::ReconcileReference));
            }
            for _ in 0..4 {
                m = m
                    .transition(checked_completion_at(&m, 101), &Clock(101))
                    .unwrap();
            }
            if m.pending() == Some(Step::ReconcileReference) {
                m = m
                    .transition(
                        Event::Failed(Reason::Observation("undecidable")),
                        &Clock(101),
                    )
                    .unwrap();
            }
            assert!(m.blocking_verified_at(&Clock(101)));
            assert_eq!(
                m.plan(),
                [Step::Backoff { until: 102 }, Step::ReconcileReference]
            );
        }
    }
}

#[test]
#[allow(clippy::too_many_lines)] // Repeat every table row at both accounting boundaries.
fn recovery_hold_table_refresh_maintenance_losses_gaps_child_join_and_leave() {
    for in_flight in [false, true] {
        let mut base = recovery_held();
        if in_flight {
            base = base
                .transition(Event::Completed(Step::Backoff { until: 101 }), &Clock(101))
                .unwrap();
        }
        // Refresh and the ten-second maintenance receipt preserve queued debt.
        let durable = base.durable().clone();
        let clean = base
            .transition(
                Event::StatesClean {
                    epoch: base.context().state_epoch,
                    completed_at: 101,
                },
                &Clock(101),
            )
            .unwrap();
        assert_eq!(clean.durable(), &durable);
        assert_eq!(clean.plan(), base.plan());
        assert_eq!(clean.states_clean_at(), Some(101));
        let (o, e) = machine_fixture(&clean, Form::PreTunnel, 1, 101);
        let refreshed = clean
            .transition(
                observed(&clean, Form::PreTunnel, verify::verify(&o, &e, &Clock(101))),
                &Clock(101),
            )
            .unwrap();
        assert!(refreshed.blocking_verified_at(&Clock(101)));
        assert_eq!(refreshed.plan(), base.plan());
        assert_eq!(
            base.transition(Event::ChildDied, &Clock(100)).unwrap(),
            base
        );
        assert!(base.transition(Event::Join, &Clock(101)).is_err());

        for verdict in [
            Verdict::NotProtected(Reason::HookMissing),
            Verdict::Repair(Action::EnableAndRejoin),
        ] {
            let mut m = base
                .transition(observed(&base, Form::PreTunnel, verdict), &Clock(101))
                .unwrap();
            // Only a dispatched call or debt blocking enable runs first.
            for _ in 0..2 {
                if m.pending() != Some(Step::ReconcileReference) {
                    break;
                }
                m = m
                    .transition(
                        Event::Failed(Reason::Observation("undecidable")),
                        &Clock(101),
                    )
                    .unwrap();
            }
            assert_eq!(m.pending(), Some(Step::LoadPreTunnel));
            assert!(!m.plan().contains(&Step::StopChild));
        }
        for event in [
            Event::InvalidateObservations { since: 101 },
            observed(&base, Form::PreTunnel, Verdict::Unknown { since: 101 }),
            Event::ChildDied,
        ] {
            let now = if matches!(event, Event::ChildDied) {
                1000
            } else {
                101
            };
            let mut m = base.transition(event, &Clock(now)).unwrap();
            if in_flight {
                assert_eq!(m.pending(), Some(Step::ReconcileReference));
                m = m
                    .transition(
                        Event::Failed(Reason::Observation("undecidable")),
                        &Clock(now),
                    )
                    .unwrap();
            }
            assert_eq!(m.plan(), [Step::FlushStates, Step::VerifyPreTunnel]);
            for _ in 0..2 {
                m = m
                    .transition(checked_completion_at(&m, now), &Clock(now))
                    .unwrap();
            }
            assert!(m.blocking_verified_at(&Clock(now)));
            assert!(m.plan().contains(&Step::ReconcileReference));
        }
        let mut m = base.transition(Event::Leave, &Clock(101)).unwrap();
        if in_flight {
            m = m
                .transition(
                    Event::Failed(Reason::Observation("cancelled accounting")),
                    &Clock(101),
                )
                .unwrap();
        }
        assert_eq!(m.pending(), Some(Step::PersistLeaving));
        m = m
            .transition(Event::Completed(Step::PersistLeaving), &Clock(101))
            .unwrap();
        assert!(m.transition(Event::Join, &Clock(101)).is_err());
        for step in [
            Step::StopChild,
            Step::CleanupRoutes,
            Step::CleanupDns,
            Step::CleanupArtifacts,
            Step::RemoveAnchor,
            Step::ClearIntent,
        ] {
            assert_eq!(m.pending(), Some(step));
            m = m.transition(Event::Completed(step), &Clock(101)).unwrap();
        }
        assert!(!m.durable().hold);
        assert!(!m.durable().join_intended);
        assert_eq!(m.durable().uncertain_acquires, [1, 2]);
        assert!(m.connectivity_restored());
    }
}

#[test]
fn held_cleanup_failure_retries_only_that_step_and_does_not_starve_accounting() {
    for failed_step in [
        Step::StopChild,
        Step::CleanupRoutes,
        Step::CleanupDns,
        Step::CleanupArtifacts,
    ] {
        let mut m = Machine::restart(Durable {
            join_intended: true,
            hold: true,
            uncertain_acquires: vec![1, 2],
            reference_sequence: 2,
            ..Durable::default()
        });
        let mut loads = 0;
        let mut flushes = 0;
        let mut accounting = 0;
        let mut failures = Vec::new();
        for now in 100..=340 {
            if now > 100 {
                // Normal monitoring keeps the proof fresh; lifecycle cleanup
                // must not cause additional anchor loads or all-state flushes.
                let (o, e) = machine_fixture(&m, Form::PreTunnel, 1, now);
                m = m
                    .transition(
                        observed(&m, Form::PreTunnel, verify::verify(&o, &e, &Clock(now))),
                        &Clock(now),
                    )
                    .unwrap();
            }
            for _ in 0..20 {
                let Some(step) = m.pending() else {
                    break;
                };
                if matches!(step, Step::Backoff { until } if until > now) {
                    break;
                }
                let event = if step == failed_step {
                    failures.push(now);
                    Event::Failed(Reason::Observation("endpoint unknown"))
                } else if step == Step::ReconcileReference {
                    accounting += 1;
                    Event::Failed(Reason::Observation("other product owns pf"))
                } else {
                    loads += usize::from(step == Step::LoadPreTunnel);
                    flushes += usize::from(step == Step::FlushStates);
                    checked_completion_at(&m, now)
                };
                m = m.transition(event, &Clock(now)).unwrap();
            }
            assert!(m.blocking_verified_at(&Clock(now)));
            assert!(
                m.durable()
                    .cleanup_errors
                    .contains(&(failed_step, Reason::Observation("endpoint unknown")))
            );
            assert_eq!(
                m.status_at(&Clock(now)),
                ConnectionStatus::NotProtected {
                    reason: "state untrusted: run leave",
                    blocking_verified: true,
                }
            );
        }
        assert_eq!((loads, flushes), (1, 1));
        assert_eq!(failures, [100, 101, 103, 107, 115, 131, 163, 223, 283]);
        assert!(accounting >= 230, "accounting was starved: {accounting}");
        // A successful independent retry clears only this error.
        let now = 343;
        let (o, e) = machine_fixture(&m, Form::PreTunnel, 1, now);
        m = m
            .transition(
                observed(&m, Form::PreTunnel, verify::verify(&o, &e, &Clock(now))),
                &Clock(now),
            )
            .unwrap();
        for _ in 0..8 {
            if m.pending() == Some(failed_step) {
                break;
            }
            let event = if m.pending() == Some(Step::ReconcileReference) {
                Event::Failed(Reason::Observation("still undecidable"))
            } else {
                checked_completion_at(&m, now)
            };
            m = m.transition(event, &Clock(now)).unwrap();
        }
        assert_eq!(m.pending(), Some(failed_step));
        m = m
            .transition(Event::Completed(failed_step), &Clock(now))
            .unwrap();
        assert!(
            !m.durable()
                .cleanup_errors
                .iter()
                .any(|(step, _)| *step == failed_step)
        );
    }
}

#[test]
fn held_status_never_promises_rejoining_and_reports_only_fresh_blocking() {
    for m in [
        held(),
        recovery_held(),
        Machine::restart(recovery_held().durable().clone()),
    ] {
        for now in [100, 1000] {
            assert_eq!(
                m.status_at(&Clock(now)),
                ConnectionStatus::NotProtected {
                    reason: "state untrusted: run leave",
                    blocking_verified: m.blocking_verified_at(&Clock(now)),
                }
            );
            assert_eq!(
                m.enforcement_at(&Clock(now)),
                Verdict::NotProtected(Reason::Observation("state untrusted: run leave"))
            );
        }
    }
    // Even an invalid directly constructed core snapshot never flushes Left.
    let m = Machine::restart(Durable {
        hold: true,
        ..Durable::default()
    });
    assert_eq!(
        m.transition(Event::ChildDied, &Clock(100)).unwrap().plan(),
        []
    );
}

#[test]
#[allow(clippy::too_many_lines)] // Cover predecessor scheduling, refresh, timed recheck and exact settlement.
fn fresh_join_verification_schedules_retained_predecessor_for_exact_settlement() {
    let mut m = Machine::restart(Durable {
        pf_reference: Some(701),
        ..Durable::default()
    });
    m = m.transition(Event::Join, &Clock(100)).unwrap();
    // Settle the idle accounting call first; retain its token as current.
    m = m
        .transition(checked_completion_at(&m, 100), &Clock(100))
        .unwrap();
    while m.pending() != Some(Step::VerifyJoined) {
        // Releasing the retained token is permitted only after the fresh
        // acquisition has a full Joined proof, never during its setup prefix.
        assert!(!m.plan().contains(&Step::ReconcileReference));
        m = m
            .transition(checked_completion_at(&m, 100), &Clock(100))
            .unwrap();
    }
    assert_eq!(m.durable().pf_reference, Some(702));
    assert_eq!(m.durable().older_references, [701]);
    assert!(!m.plan().contains(&Step::ReconcileReference));
    m = m
        .transition(checked_completion_at(&m, 100), &Clock(100))
        .unwrap();
    assert_eq!(m.pending(), Some(Step::ReconcileReference));
    for in_flight in [false, true] {
        let background = if in_flight {
            m.clone()
        } else {
            m.transition(
                Event::Failed(Reason::Observation("predecessor undecidable")),
                &Clock(100),
            )
            .unwrap()
        };
        let (o, e) = machine_fixture(&background, Form::Joined, 1, 101);
        let refreshed = background
            .transition(
                observed(
                    &background,
                    Form::Joined,
                    verify::verify(&o, &e, &Clock(101)),
                ),
                &Clock(101),
            )
            .unwrap();
        assert_eq!(refreshed.plan(), background.plan());
        assert_eq!(refreshed.durable().older_references, [701]);
        assert_eq!(
            refreshed.durable().reference_error,
            background.durable().reference_error
        );
        assert_eq!(refreshed.status_at(&Clock(101)), ConnectionStatus::Joined);
    }
    // A summary is never authority to release an identity. The executor must
    // obtain same-boot release evidence and send its exact settlement first.
    let mut recheck = m
        .transition(
            Event::Failed(Reason::Observation("late predecessor result")),
            &Clock(106),
        )
        .unwrap();
    assert_eq!(recheck.plan(), [Step::FlushStates, Step::VerifyJoined]);
    recheck = recheck
        .transition(checked_completion_at(&recheck, 107), &Clock(107))
        .unwrap();
    assert_eq!(recheck.plan(), [Step::VerifyJoined]);
    recheck = recheck
        .transition(checked_completion_at(&recheck, 108), &Clock(108))
        .unwrap();
    assert_eq!(recheck.pending(), Some(Step::ReconcileReference));
    assert_eq!(recheck.status_at(&Clock(108)), ConnectionStatus::Joined);
    assert!(
        m.transition(
            Event::ReferenceReconciled {
                context: m.context(),
                current: Some(702),
                predecessor: None
            },
            &Clock(100)
        )
        .is_err()
    );
    m = m
        .transition(
            Event::ReferenceSettled {
                entry: ReferenceEntry::Token(701),
                how: ReferenceSettlement::Released,
            },
            &Clock(100),
        )
        .unwrap();
    m = m
        .transition(
            Event::ReferenceReconciled {
                context: m.context(),
                current: Some(702),
                predecessor: None,
            },
            &Clock(100),
        )
        .unwrap();
    assert_eq!(m.durable().older_references, [] as [u64; 0]);
    assert_eq!(m.durable().pf_reference, Some(702));
    assert!(!m.plan().contains(&Step::ReconcileReference));
    assert_eq!(m.pending(), None);
}

// K2 fixture: a verified held prefix whose route cleanup failed independently.
// Both uncertain acquisitions remain undecidable, so accounting must coexist
// with the cleanup retry instead of being dropped from its queue.
fn held_route_cleanup_retry(free_slot: bool) -> Machine {
    let mut m = Machine::restart(Durable {
        join_intended: true,
        hold: true,
        uncertain_acquires: if free_slot { vec![] } else { vec![1, 2] },
        reference_sequence: 2,
        ..Durable::default()
    });
    for _ in 0..20 {
        if matches!(m.pending(), Some(Step::Backoff { .. })) {
            assert!(m.blocking_verified_at(&Clock(100)));
            assert!(m.plan().contains(&Step::CleanupRoutes));
            return m;
        }
        let event = match m.pending().unwrap() {
            Step::CleanupRoutes => Event::Failed(Reason::Observation("route cleanup failed")),
            Step::ReconcileReference => {
                Event::Failed(Reason::Observation("accounting undecidable"))
            }
            _ => checked_completion_at(&m, 100),
        };
        m = m.transition(event, &Clock(100)).unwrap();
    }
    panic!("cleanup retry did not become background: {m:?}");
}

#[test]
fn held_cleanup_retry_results_keep_their_head_across_every_invalidation() {
    let base = held_route_cleanup_retry(false);
    assert!(base.plan().contains(&Step::ReconcileReference));
    let base = base
        .transition(checked_completion_at(&base, 101), &Clock(101))
        .unwrap();
    assert_eq!(base.pending(), Some(Step::CleanupRoutes));
    for event in [
        Event::InvalidateObservations { since: 101 },
        observed(&base, Form::PreTunnel, Verdict::Unknown { since: 101 }),
    ] {
        for failed in [false, true] {
            let mut m = base.transition(event.clone(), &Clock(101)).unwrap();
            assert_eq!(m.pending(), Some(Step::CleanupRoutes));
            let result = if failed {
                Event::Failed(Reason::Observation("retry failed"))
            } else {
                Event::Completed(Step::CleanupRoutes)
            };
            m = m.transition(result, &Clock(101)).unwrap();
            assert_eq!(m.plan(), [Step::FlushStates, Step::VerifyPreTunnel]);
            assert!(!m.plan().contains(&Step::LoadPreTunnel));
            let errors = &m.durable().cleanup_errors;
            if failed {
                assert!(
                    errors.contains(&(Step::CleanupRoutes, Reason::Observation("retry failed")))
                );
                assert!(!errors.iter().any(|(step, _)| *step == Step::FlushStates));
            } else {
                assert!(!errors.iter().any(|(step, _)| *step == Step::CleanupRoutes));
            }
        }
    }
}

#[test]
fn held_cleanup_retry_results_preserve_separately_requested_repairs() {
    let base = held_route_cleanup_retry(false);
    let base = base
        .transition(checked_completion_at(&base, 101), &Clock(101))
        .unwrap();
    assert_eq!(base.pending(), Some(Step::CleanupRoutes));
    for verdict in [
        Verdict::Repair(Action::Rerender {
            form: Form::PreTunnel,
        }),
        Verdict::NotProtected(Reason::HookMissing),
        Verdict::Repair(Action::EnableAndRejoin),
    ] {
        for failed in [false, true] {
            let event = observed(&base, Form::PreTunnel, verdict.clone());
            let mut m = base.transition(event, &Clock(101)).unwrap();
            assert_eq!(m.pending(), Some(Step::CleanupRoutes));
            let result = if failed {
                Event::Failed(Reason::Observation("retry failed"))
            } else {
                Event::Completed(Step::CleanupRoutes)
            };
            m = m.transition(result, &Clock(101)).unwrap();
            let expected = if verdict == Verdict::Repair(Action::EnableAndRejoin) {
                Step::ReconcileReference
            } else {
                Step::LoadPreTunnel
            };
            assert_eq!(m.pending(), Some(expected), "{verdict:?}, failed={failed}");
            let errors = &m.durable().cleanup_errors;
            if failed {
                assert!(
                    errors.contains(&(Step::CleanupRoutes, Reason::Observation("retry failed")))
                );
                assert!(!errors.iter().any(|(step, _)| *step == Step::FlushStates || *step == Step::LoadPreTunnel));
            } else {
                assert!(!errors.iter().any(|(step, _)| *step == Step::CleanupRoutes));
            }
        }
    }
}

#[test]
fn held_one_free_slot_acquires_before_accounting_and_reconciles_in_the_same_prefix() {
    let mut m = Machine::restart(Durable {
        join_intended: true,
        hold: true,
        uncertain_acquires: vec![1],
        reference_sequence: 1,
        ..Durable::default()
    });
    // A disabled observation arriving with acquisition in flight must not put
    // ownership accounting ahead of that dispatched enabling operation.
    m = m
        .transition(Event::Repair(Action::EnableAndRejoin), &Clock(100))
        .unwrap();
    assert_eq!(m.pending(), Some(Step::AcquireReference));
    let mut acquired = false;
    let mut verified = false;
    for _ in 0..20 {
        let step = m.pending().unwrap();
        assert!(!matches!(step, Step::Backoff { .. }));
        if step == Step::ReconcileReference {
            assert!(acquired && verified);
            return;
        }
        acquired |= step == Step::AcquireReference;
        verified |= step == Step::VerifyPreTunnel;
        m = m
            .transition(checked_completion_at(&m, 100), &Clock(100))
            .unwrap();
    }
    panic!("accounting did not follow verification in the held prefix");
}

#[test]
fn joined_retained_predecessor_accepts_maintenance_and_handshake_for_over_sixty_seconds() {
    let mut m = Machine::restart(Durable {
        pf_reference: Some(701),
        ..Durable::default()
    });
    let mut now = 100;
    m = m.transition(Event::Join, &Clock(now)).unwrap();
    // The Left reconciliation was already dispatched. It and every subsequent
    // accounting call fail; no fixture settles the predecessor behind our back.
    m = m
        .transition(
            Event::Failed(Reason::Observation("retained predecessor")),
            &Clock(now + 1),
        )
        .unwrap();
    now += 1;
    for _ in 0..80 {
        if m.status_at(&Clock(now)) == ConnectionStatus::Joined {
            break;
        }
        now = executor_time(&m, now + 1);
        let event = if m.pending() == Some(Step::ReconcileReference) {
            Event::Failed(Reason::Observation("retained predecessor"))
        } else {
            checked_completion_at(&m, now)
        };
        m = m.transition(event, &Clock(now)).unwrap();
    }
    assert_eq!(m.status_at(&Clock(now)), ConnectionStatus::Joined);
    assert_eq!(m.durable().older_references, [701]);
    let start = now;
    for cycle in 0..20 {
        now += 1;
        m = m
            .transition(
                Event::StatesClean {
                    epoch: m.context().state_epoch,
                    completed_at: now,
                },
                &Clock(now),
            )
            .unwrap();
        assert_eq!(m.status_at(&Clock(now)), ConnectionStatus::Joined);
        now += 1;
        let generation = m.tunnel().unwrap().generation;
        let (o, e) = machine_fixture(&m, Form::Joined, generation.value(), now);
        m = m
            .transition(
                observed(&m, Form::Joined, verify::verify(&o, &e, &Clock(now))),
                &Clock(now),
            )
            .unwrap();
        assert_eq!(m.status_at(&Clock(now)), ConnectionStatus::Joined);
        now += 1;
        let fresh = cycle % 2 == 0;
        m = m
            .transition(Event::Handshake { generation, fresh }, &Clock(now))
            .unwrap();
        assert_eq!(
            m.tunnel_health(),
            &if fresh {
                TunnelHealth::Healthy
            } else {
                TunnelHealth::AwaitingHandshake
            }
        );
        assert_eq!(m.status_at(&Clock(now)), ConnectionStatus::Joined);
        now = executor_time(&m, now + 1);
        let event = if m.pending() == Some(Step::ReconcileReference) {
            Event::Failed(Reason::Observation("retained predecessor"))
        } else {
            assert!(matches!(m.pending(), Some(Step::Backoff { .. })));
            checked_completion_at(&m, now)
        };
        m = m.transition(event, &Clock(now)).unwrap();
        assert_eq!(m.status_at(&Clock(now)), ConnectionStatus::Joined);
        assert_eq!(m.durable().older_references, [701]);
    }
    assert!(now - start >= 60);
}

#[test]
fn held_cleanup_retry_preserves_queued_accounting_and_clears_its_last_error_on_success() {
    let mut m = held_route_cleanup_retry(false);
    assert!(m.plan().contains(&Step::ReconcileReference));
    m = m
        .transition(checked_completion_at(&m, 101), &Clock(101))
        .unwrap();
    assert_eq!(m.pending(), Some(Step::CleanupRoutes));
    assert!(m.plan().contains(&Step::ReconcileReference));
    assert_eq!(
        m.durable().last_error,
        Some(Reason::Observation("route cleanup failed"))
    );
    m = m
        .transition(Event::Completed(Step::CleanupRoutes), &Clock(101))
        .unwrap();
    assert_eq!(m.durable().last_error, None);
    assert!(m.plan().contains(&Step::ReconcileReference));
    assert!(
        !m.durable()
            .cleanup_errors
            .iter()
            .any(|(step, _)| *step == Step::CleanupRoutes)
    );
}

#[test]
fn invalidation_preserves_predecessor_reference_and_cleanup_errors() {
    let error = Reason::Observation("predecessor release unknown");
    let mut m = Machine::restart(Durable {
        join_intended: true,
        hold: true,
        pf_reference: Some(702),
        older_references: vec![701],
        reference_error: Some(error.clone()),
        cleanup_errors: vec![(Step::ReconcileReference, error.clone())],
        ..Durable::default()
    });
    for _ in 0..16 {
        if matches!(m.pending(), Some(Step::Backoff { .. })) {
            break;
        }
        m = m
            .transition(checked_completion_at(&m, 100), &Clock(100))
            .unwrap();
    }
    assert!(m.blocking_verified_at(&Clock(100)));
    assert_eq!(m.pending(), Some(Step::Backoff { until: 101 }));
    m = m
        .transition(Event::InvalidateObservations { since: 100 }, &Clock(100))
        .unwrap();
    assert_eq!(m.durable().older_references, [701]);
    assert_eq!(m.durable().reference_error, Some(error.clone()));
    assert!(
        m.durable()
            .cleanup_errors
            .contains(&(Step::ReconcileReference, error))
    );
    assert!(
        m.status_text_at(&Clock(100))
            .contains("ownership cleanup debt")
    );
}

#[test]
fn held_accounting_backoff_never_precedes_safety_steps_except_a_closing_wait() {
    let mut m = recovery_held()
        .transition(Event::Repair(Action::EnableAndRejoin), &Clock(100))
        .unwrap();
    for sequence in [1, 2] {
        m = settled(
            &m,
            ReferenceEntry::Acquire(sequence),
            ReferenceSettlement::Void,
            100,
        );
    }
    // A failed reconciliation with newly free slots queues a fresh acquisition,
    // while its accounting deadline is still in the future.
    m = m
        .transition(
            Event::Failed(Reason::Observation("summary timed out")),
            &Clock(100),
        )
        .unwrap();
    assert_eq!(m.pending(), Some(Step::AcquireReference));
    m = m
        .transition(Event::Repair(Action::EnableAndRejoin), &Clock(100))
        .unwrap();
    for _ in 0..20 {
        let Some(step) = m.pending() else {
            break;
        };
        if matches!(step, Step::Backoff { .. }) && !m.plan().contains(&Step::VerifyPreTunnel) {
            break;
        }
        assert_no_held_accounting_wait(&m);
        let now = executor_time(&m, 100);
        let event = if step == Step::ReconcileReference {
            Event::Failed(Reason::Observation("accounting still pending"))
        } else {
            checked_completion_at(&m, now)
        };
        m = m.transition(event, &Clock(now)).unwrap();
    }
    // The separate closing-action timer remains valid and retains its target.
    let m = held()
        .transition(Event::Repair(Action::Rejoin), &Clock(100))
        .unwrap();
    let m = m
        .transition(
            Event::Failed(Reason::Observation("load failed")),
            &Clock(100),
        )
        .unwrap();
    assert_eq!(m.pending(), Some(Step::Backoff { until: 101 }));
    assert_no_held_accounting_wait(&m);
}

fn assert_no_held_accounting_wait(m: &Machine) {
    for (index, step) in m.plan().iter().enumerate() {
        if let Step::Backoff { until } = step {
            for target in &m.plan()[index + 1..] {
                if matches!(
                    target,
                    Step::LoadPreTunnel
                        | Step::VerifyPreTunnelLoad
                        | Step::FlushStates
                        | Step::VerifyPreTunnel
                ) {
                    let retry = m.closing_retry().unwrap_or_else(|| {
                        panic!("accounting wait ahead of {target:?}: {:?}", m.plan())
                    });
                    assert_eq!(*until, retry.until);
                    assert_eq!(m.plan()[index + 1], retry.target);
                }
            }
        }
    }
}

fn lockdown_fixture(m: Option<&Machine>, now: u64) -> (Observations, verify::LockdownExpected) {
    let (mut o, e) = setup(Form::PreTunnel);
    let text = policy::render_lockdown();
    let rules = parse::pf_rules(text.as_str()).unwrap();
    o.anchor = Ok(Some(rules.clone()));
    o.live_tree
        .as_mut()
        .unwrap()
        .anchors
        .get_mut("com.apple/scupper")
        .unwrap()
        .rules = Ok(rules);
    let context = m.map_or(Context::default(), Machine::context);
    o.started_at.retain(|key, _| {
        verify::required_lockdown_reads(o.live_tree.as_ref().unwrap()).contains(key)
    });
    for t in o.started_at.values_mut() {
        *t = now;
    }
    o.states = StateEvidence::Clean {
        epoch: context.state_epoch,
        completed_at: m.and_then(Machine::states_clean_at).unwrap_or(now),
    };
    // These are deliberately absent: lockdown proves no endpoint or tunnel facts.
    o.policy_inputs = Err(Error("no install"));
    o.route = Err(Error("no endpoint"));
    o.local_address = Err(Error("no local address"));
    o.dns = Err(Error("no DNS expectation"));
    (
        o,
        verify::LockdownExpected {
            context,
            baseline: verify::capture_lockdown_baseline(
                text.as_str(),
                &e.qualification.normalization,
            )
            .unwrap(),
            qualification: e.qualification,
            max_age: 5,
        },
    )
}

#[test]
fn lockdown_golden_and_global_verification() {
    assert_eq!(
        policy::render_lockdown().as_str(),
        "pass quick on lo0 all no state\nblock drop quick all\n"
    );
    assert_eq!(policy::policy_table(policy::Policy::Lockdown).len(), 1);
    let (o, e) = lockdown_fixture(None, 100);
    assert!(
        matches!(verify::verify_lockdown(&o, &e, &Clock(100)), Verdict::Protected(ref p)
        if p.kind() == policy::Kind::Lockdown && p.tunnel().is_none() && p.transport().is_none())
    );
    for attack in 0..7 {
        let mut changed = o.clone();
        match attack {
            0 => changed.main = parse::pf_rules("pass quick all\nanchor \"com.apple/*\"\n"),
            1 => {
                changed
                    .skips
                    .as_mut()
                    .unwrap()
                    .insert("en0".parse().unwrap(), true);
            }
            2 => changed.states = StateEvidence::Unproven,
            3 => changed.pf = Ok(parse::PfInfo { enabled: false }),
            4 => {
                changed.anchor = Ok(Some(
                    parse::pf_rules("pass quick on lo0 all no state\n").unwrap(),
                ));
            }
            5 => {
                changed.translation =
                    parse::translation("nat on en0 from any to any -> 192.0.2.1\n");
            }
            _ => {
                changed.started_at.remove("skips");
            }
        }
        assert!(
            !matches!(
                verify::verify_lockdown(&changed, &e, &Clock(100)),
                Verdict::Protected(_)
            ),
            "attack {attack}"
        );
    }
    assert!(matches!(
        verify::verify_lockdown(&o, &e, &Clock(106)),
        Verdict::Unknown { .. }
    ));
    assert!(verify::capture_lockdown_baseline("block drop quick all\n", &normalization()).is_err());
    assert!(verify::capture_lockdown_baseline(PRE, &normalization()).is_err());
}

#[test]
fn capture_named_icmp_is_typed_unqualified() {
    let mut n = normalization();
    n.named_icmp = false;
    assert_eq!(
        verify::capture_lockdown_baseline("pass out quick inet6 proto ipv6-icmp all icmp6-type routersol no state\nblock drop quick all\n", &n).unwrap_err(),
        verify::CaptureError::Unqualified(verify::UnqualifiedKind::Icmp)
    );
}

#[test]
fn capture_list_expansion_is_typed_unqualified() {
    let mut n = normalization();
    n.expanded_lists = false;
    assert_eq!(
        verify::capture_lockdown_baseline(
            "pass out quick all keep state (if-bound)\nblock drop quick all\n",
            &n
        )
        .unwrap_err(),
        verify::CaptureError::Unqualified(verify::UnqualifiedKind::ListExpansion)
    );
}

#[test]
fn hold_rejects_both_policy_mismatches_and_lockdown_never_joins() {
    for lockdown in [false, true] {
        let durable = Durable {
            join_intended: true,
            hold: true,
            uncertain_acquires: vec![1, 2],
            reference_sequence: 2,
            ..Durable::default()
        };
        let mut m = if lockdown {
            Machine::restart_lockdown(durable)
        } else {
            Machine::restart(durable)
        };
        for _ in 0..12 {
            if m.pending() == Some(Step::VerifyPreTunnelLoad) {
                break;
            }
            let event = if m.pending() == Some(Step::ReconcileReference) {
                Event::Failed(Reason::Observation("ownership unresolved"))
            } else {
                checked_completion_at(&m, 100)
            };
            m = m.transition(event, &Clock(100)).unwrap();
        }
        assert_eq!(m.pending(), Some(Step::VerifyPreTunnelLoad));
        let (_, lockdown_expected) = lockdown_fixture(Some(&m), 100);
        let (_, installed) = machine_fixture(&m, Form::PreTunnel, 1, 100);
        let wrong = if lockdown {
            installed.baseline.clone()
        } else {
            lockdown_expected.baseline.clone()
        };
        assert!(
            m.transition(Event::ReadbackValidated(wrong), &Clock(100))
                .is_err()
        );
        let right = if lockdown {
            lockdown_expected.baseline.clone()
        } else {
            installed.baseline.clone()
        };
        m = m
            .transition(Event::ReadbackValidated(right), &Clock(100))
            .unwrap();
        m = m
            .transition(
                Event::StatesClean {
                    epoch: m.context().state_epoch,
                    completed_at: 100,
                },
                &Clock(100),
            )
            .unwrap();
        assert_eq!(m.pending(), Some(Step::VerifyPreTunnel));
        let (o, e) = lockdown_fixture(Some(&m), 100);
        let lockdown_proof = verify::verify_lockdown(&o, &e, &Clock(100));
        let (o, e) = machine_fixture(&m, Form::PreTunnel, 1, 100);
        let pre_proof = verify::verify(&o, &e, &Clock(100));
        let wrong = if lockdown {
            pre_proof.clone()
        } else {
            lockdown_proof.clone()
        };
        assert!(
            m.transition(observed(&m, Form::PreTunnel, wrong), &Clock(100))
                .is_err()
        );
        assert!(
            m.transition(
                observed(&m, Form::Joined, lockdown_proof.clone()),
                &Clock(100)
            )
            .is_err()
        );
        let right = if lockdown { lockdown_proof } else { pre_proof };
        m = m
            .transition(observed(&m, Form::PreTunnel, right), &Clock(100))
            .unwrap();
        assert!(!matches!(
            m.enforcement_at(&Clock(100)),
            Verdict::Protected(_)
        ));
        assert!(m.blocking_verified_at(&Clock(100)));
        assert!(!m.blocking_verified_at(&Clock(106)));
        assert!(!m.plan().contains(&Step::CheckTools));
    }
}

#[test]
fn lockdown_rejects_preceding_and_nested_anchor_pass_even_if_qualified() {
    for nested in [false, true] {
        let (mut o, mut e) = lockdown_fixture(None, 100);
        let path = "com.apple/100.synthetic";
        let quick = parse::pf_rules("pass quick all\n").unwrap();
        if nested {
            let inner = format!("{path}/inner");
            let tree = o.live_tree.as_mut().unwrap();
            tree.anchors.get_mut(path).unwrap().rules = parse::pf_rules("anchor \"inner\"\n");
            tree.anchors.insert(
                inner.clone(),
                AnchorObservation {
                    rules: Ok(quick.clone()),
                    translation: parse::translation(""),
                },
            );
            let inventory = tree.anchors.keys().cloned().collect::<Vec<_>>().join("\n");
            tree.before = parse::anchor_list(&inventory).unwrap();
            tree.after = tree.before.clone();
            e.qualification
                .siblings
                .insert(path.into(), parse::pf_rules("anchor \"inner\"\n").unwrap());
            e.qualification.siblings.insert(inner.clone(), quick);
            e.qualification
                .anchor_translation
                .insert(inner, parse::translation("").unwrap());
        } else {
            o.live_tree
                .as_mut()
                .unwrap()
                .anchors
                .get_mut(path)
                .unwrap()
                .rules = Ok(quick.clone());
            e.qualification.siblings.insert(path.into(), quick);
        }
        o.started_at = verify::required_lockdown_reads(o.live_tree.as_ref().unwrap())
            .into_iter()
            .map(|read| (read, 100))
            .collect();
        assert_eq!(
            verify::verify_lockdown(&o, &e, &Clock(100)),
            Verdict::NotProtected(Reason::QuickPass)
        );
    }
}

#[test]
fn lockdown_proof_cannot_satisfy_joined_or_a_new_observation_context() {
    let mut machine = Machine::restart(Durable::default())
        .transition(Event::Join, &Clock(100))
        .unwrap();
    for _ in 0..40 {
        if machine.pending() == Some(Step::VerifyJoined) {
            break;
        }
        machine = machine
            .transition(checked_completion_at(&machine, 100), &Clock(100))
            .unwrap();
    }
    assert_eq!(machine.pending(), Some(Step::VerifyJoined));
    let (observations, expected) = lockdown_fixture(Some(&machine), 100);
    let proof = verify::verify_lockdown(&observations, &expected, &Clock(100));
    assert!(matches!(proof, Verdict::Protected(_)));
    assert!(
        machine
            .transition(observed(&machine, Form::Joined, proof.clone()), &Clock(100))
            .is_err()
    );
    let changed = machine
        .transition(Event::InvalidateObservations { since: 100 }, &Clock(100))
        .unwrap();
    assert_ne!(changed.context(), machine.context());
    // The outstanding verifier completion is consumed as a cancellation
    // boundary; it must not refresh enforcement in the newer context.
    let changed = changed
        .transition(observed(&changed, Form::PreTunnel, proof), &Clock(100))
        .unwrap();
    assert!(!matches!(
        changed.enforcement_at(&Clock(100)),
        Verdict::Protected(_)
    ));
    assert!(!changed.blocking_verified_at(&Clock(100)));
}
