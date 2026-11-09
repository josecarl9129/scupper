//! Captured Linux inventories exercise the entire M2 collection and driver path.
#![cfg(feature = "testing")]
#![allow(clippy::unwrap_used)]
#[path = "support/v2.rs"]
mod support;
use scupper_core::{
    config::GatewayId,
    verdict::v2::{Next, ProbeError, RulesetObs, Supervisor},
};
use scupper_sys::{
    check_v2::{self, Dependencies},
    collect,
    netns::testing,
    state::State,
};
use std::{fs, path::Path};
use support::{Root, Script, cfg, fixture, fresh, health, site};

#[test]
fn scripted_driver_exit_contract_on_both_runners() {
    for runner in ["ubuntu-22.04", "ubuntu-24.04"] {
        let handle = testing::handle().unwrap();
        let root = Root::new(runner, &handle);
        let site = site(runner);
        let gateway = GatewayId("gw1".into());
        let cfg = cfg(&site, &gateway, root.stamp);
        let sys = Script::new(runner);
        fresh(&sys);
        let deps = Dependencies {
            system: &sys,
            probe_exec: &sys,
            handle: Some(&handle),
            state_root: &root.path,
        };
        let check = || check_v2::run_check_v2(&deps, &cfg);
        let healthy = check().unwrap();
        assert_eq!(healthy.verdict.exit_code(), 0, "{healthy:?}");
        assert_eq!(serde_json::to_value(healthy).unwrap()["schema"], 1);
        // Whole-ruleset differences must be repeated before becoming violations.
        let mut live: serde_json::Value =
            serde_json::from_str(&fixture(runner, "scupper-nft-ruleset.json")).unwrap();
        live["nftables"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({"table": {"family": "inet", "name": "foreign"}}));
        sys.replace("scupper-nft-ruleset.json", &live.to_string());
        let before = sys.calls.borrow().len();
        assert_eq!(check().unwrap().verdict.exit_code(), 2);
        assert_eq!(
            sys.calls.borrow()[before..]
                .iter()
                .filter(|(_, p, _)| *p == scupper_sys::system::Program::Unshare)
                .count(),
            2
        );
        sys.replacements
            .borrow_mut()
            .remove("scupper-nft-ruleset.json");
        sys.replace("scupper--4-route.json", "[]");
        assert_eq!(check().unwrap().verdict.exit_code(), 3);
        sys.replacements
            .borrow_mut()
            .remove("scupper--4-route.json");
        let key = fixture(runner, "scupper-wg-ex-ch1-peers.txt");
        sys.replace(
            "scupper-wg-ex-ch1-latest-handshakes.txt",
            &format!("{}\t1\n", key.trim()),
        );
        assert_eq!(check().unwrap().verdict.exit_code(), 4);
        fresh(&sys);
        *sys.probe.borrow_mut() = serde_json::json!({"result": {"class": "setup", "message": "injected setup error"}, "credentials": null, "threads_before_setns": null}).to_string();
        assert_eq!(check().unwrap_err().exit_code(), 1);
        fs::remove_file(root.path.join("boot.json")).unwrap();
        assert_eq!(check().unwrap_err().exit_code(), 1);
    }
}

#[test]
fn every_command_failure_is_an_error_observation_and_targets_are_pinned() {
    let runner = "ubuntu-24.04";
    let handle = testing::handle().unwrap();
    let site = site(runner);
    let health = health(&site, &handle);
    let root = Root::new(runner, &handle);
    let gateway = GatewayId("gw1".into());
    let sys = Script::new(runner);
    fresh(&sys);
    let topology = || collect::topology(&sys, &handle, &site, &gateway, &root.stamp);
    assert!(topology().is_ok());
    let count = sys.calls.borrow().len();
    assert!(sys.calls.borrow().iter().all(|(ns, p, _)| *ns
        || matches!(
            p,
            scupper_sys::system::Program::Unshare | scupper_sys::system::Program::Wg
        )));
    for index in 0..count {
        sys.calls.borrow_mut().clear();
        *sys.fail.borrow_mut() = Some(index);
        assert!(
            !topology().unwrap().errors.is_empty(),
            "topology command {index}"
        );
    }
    *sys.fail.borrow_mut() = None;
    for collector in [
        Next::Defaults,
        Next::Handshakes,
        Next::Forwarding,
        Next::Routes,
    ] {
        let run = || match collector {
            Next::Defaults => collect::defaults(&sys, &handle, &health).map(|_| ()),
            Next::Handshakes => collect::handshakes(&sys, &handle, &health).map(|_| ()),
            Next::Forwarding => {
                collect::forwarding(&sys, &handle, &health, &State::default()).map(|_| ())
            }
            Next::Routes => collect::routes(&sys, &handle, &health).and_then(|routes| {
                for (_, route) in routes {
                    route.v4?;
                    route.v6?;
                }
                Ok(())
            }),
            _ => unreachable!(),
        };
        sys.calls.borrow_mut().clear();
        assert!(run().is_ok(), "{collector:?}");
        let count = sys.calls.borrow().len();
        for index in 0..count {
            sys.calls.borrow_mut().clear();
            *sys.fail.borrow_mut() = Some(index);
            assert!(run().is_err(), "{collector:?} command {index}");
        }
        *sys.fail.borrow_mut() = None;
    }
    *sys.file_error.borrow_mut() = true;
    assert!(collect::forwarding(&sys, &handle, &health, &State::default()).is_err());
    assert_eq!(
        collect::supervisor(&sys, &handle, &health),
        Supervisor::NotRequired
    );
    let mut required = health.clone();
    required.require_daemon = true;
    assert_eq!(
        collect::supervisor(&sys, &handle, &required),
        Supervisor::Dead
    );
    assert!(collect::standby_probe(&sys, &handle, &health).is_err());
    assert!(collect::dns(&sys, &handle, &health).is_err());
    assert!(collect::selection(&root.path.join("missing")).is_err());
    assert!(collect::boot_identity(&root.path.join("missing")).is_err());
}

#[test]
fn malformed_and_incomplete_answers_never_pass() {
    let runner = "ubuntu-22.04";
    let handle = testing::handle().unwrap();
    let root = Root::new(runner, &handle);
    let site = site(runner);
    let health = health(&site, &handle);
    let gateway = GatewayId("gw1".into());
    for filename in [
        "scupper--4-link.json",
        "scupper--4-addr.json",
        "scupper-wg-ex-ch1-peers.txt",
        "scupper-wg-ex-ch1-allowed-ips.txt",
        "scupper-wg-ex-ch1-endpoints.txt",
        "scupper--6-rule.json",
        "scupper-tc-qdisc.json",
        "scupper-tc-lo-ingress.json",
        "scupper-nft-ruleset.json",
        "want.json",
    ] {
        let sys = Script::new(runner);
        // The qdisc fake parses its fixture to select the requested device.
        let bad = if filename == "scupper-tc-qdisc.json" {
            r#"[{"dev":"lo"}]"#
        } else {
            "malformed"
        };
        sys.replace(filename, bad);
        assert!(
            !collect::topology(&sys, &handle, &site, &gateway, &root.stamp)
                .unwrap()
                .errors
                .is_empty(),
            "{filename}"
        );
    }
    let sys = Script::new(runner);
    sys.replace("scupper-wg-ex-ch1-endpoints.txt", "");
    assert_ne!(
        collect::topology(&sys, &handle, &site, &gateway, &root.stamp)
            .unwrap()
            .errors,
        [] as [ProbeError; 0]
    );
    sys.replace("scupper-wg-ex-ch1-latest-handshakes.txt", "");
    assert!(collect::handshakes(&sys, &handle, &health).is_err());
}

#[test]
fn namespace_guard_refuses_gateway_before_any_nft_and_ruleset_missing_is_a_violation() {
    let sys = Script::new("ubuntu-24.04");
    let read = |_: &Path| Ok("net:[222]".into());
    let result = scupper_sys::canon::isolated_netns_ruleset(
        &sys,
        Path::new("unused"),
        Path::new("net:[111]"),
        Path::new("net:[222]"),
        read,
    );
    assert!(matches!(result, Err(ProbeError::Setup(_))));
    assert!(sys.calls.borrow().is_empty());
    let handle = testing::handle().unwrap();
    sys.replace("scupper-nft-ruleset.json", r#"{"nftables":[]}"#);
    assert_eq!(
        scupper_sys::canon::observe_netns_ruleset(&sys, &handle, "flush ruleset").unwrap(),
        RulesetObs::Missing
    );
}

#[test]
fn inventory_drift_state_loss_and_hardening_are_distinguished() {
    let runner = "ubuntu-24.04";
    let handle = testing::handle().unwrap();
    let root = Root::new(runner, &handle);
    let site = site(runner);
    let gateway = GatewayId("gw1".into());
    let cfg = cfg(&site, &gateway, root.stamp);
    let sys = Script::new(runner);
    fresh(&sys);
    let deps = Dependencies {
        system: &sys,
        probe_exec: &sys,
        handle: Some(&handle),
        state_root: &root.path,
    };
    let check = || check_v2::run_check_v2(&deps, &cfg);
    // Kernel type must come from detailed linkinfo. The old non-detailed
    // capture cannot be assumed to prove WireGuard merely from its names.
    let detailed = sys.text("scupper--4-link.json");
    sys.replace(
        "scupper--4-link.json",
        &fixture(runner, "scupper--4-link.json"),
    );
    assert_eq!(check().unwrap().verdict.exit_code(), 2);
    sys.replace("scupper--4-link.json", &detailed);
    for (file, value, expected) in [
        ("scupper--6-rule.json", "[]", 2),
        ("scupper-tc-lo-ingress.json", r#"[{"kind":"bpf"}]"#, 2),
        ("scupper-sysctl-net.ipv4.ip_forward.txt", "0\n", 3),
        ("scupper-wg-wg0-listen-port.txt", "42\n", 3),
        ("scupper-wg-wg0-public-key.txt", "(none)\n", 3),
        ("scupper-sysctl-net.ipv4.ip_forward.txt", "unreadable", 1),
        ("gwhost-proc-net-udp.txt", "unreadable", 1),
    ] {
        sys.replace(file, value);
        let result = check();
        let code = result
            .as_ref()
            .map_or_else(scupper_core::verdict::v2::CheckError::exit_code, |r| {
                r.verdict.exit_code()
            });
        assert_eq!(code, expected, "{file}: {result:?}");
        sys.replacements.borrow_mut().remove(file);
    }
    let hardening_key = "net.ipv4.conf.wg0.accept_redirects";
    sys.replace(&format!("scupper-sysctl-{hardening_key}.txt"), "1\n");
    let report = check().unwrap();
    assert_eq!(report.verdict.exit_code(), 0);
    assert!(
        report
            .warnings
            .contains(&scupper_core::verdict::v2::Warning::HardeningSysctl(
                hardening_key.into()
            ))
    );
    fs::write(
        root.path.join("boot.json"),
        r#"{"netns":{"dev":1,"ino":2}}"#,
    )
    .unwrap();
    assert_eq!(check().unwrap().verdict.exit_code(), 2);
    fs::write(
        root.path.join("boot.json"),
        r#"{"netns":{"dev":1,"ino":0}}"#,
    )
    .unwrap();
    assert_eq!(check().unwrap_err().exit_code(), 1);
    fs::remove_file(root.path.join("state.json")).unwrap();
    assert!(collect::selection(&root.path).is_err());
    fs::write(root.path.join("state.json"), "{}").unwrap();
    assert!(collect::selection(&root.path).is_err());
}

#[test]
fn no_device_routes_use_the_probe_source_and_explicit_ipv6_family() {
    let sys = Script::new("ubuntu-24.04");
    let mut raw = scupper_core::config::parse_site(&support::site_text(&sys.runner)).unwrap();
    raw.devices.clear();
    let site = scupper_core::config::validate(raw).unwrap();
    let handle = testing::handle().unwrap();
    let cfg = health(&site, &handle);
    assert_eq!(cfg.clients, [] as [std::net::IpAddr; 0]);
    assert_eq!(cfg.route_sources.len(), 1);
    let routes = collect::routes(&sys, &handle, &cfg).unwrap();
    assert_eq!(routes.len(), 1);
    assert_eq!(
        routes[0].1.v6,
        Ok(scupper_core::verdict::v2::RouteAnswer::Unreachable)
    );
    let calls = sys.calls.borrow();
    assert_eq!(
        calls[0].2,
        ["route", "get", "1.1.1.1", "from", "10.99.0.2", "iif", "wg0"]
    );
    assert_eq!(
        calls[1].2,
        ["-6", "route", "get", "2606:4700:4700::1111", "iif", "wg0"]
    );
}

#[test]
fn client_socket_birth_namespace_and_host_wireguard_ownership() {
    use scupper_core::verdict::v2::{ClientFault, Degraded, Verdict, Violation};
    for runner in ["ubuntu-22.04", "ubuntu-24.04"] {
        let handle = testing::handle().unwrap();
        let root = Root::new(runner, &handle);
        let site = site(runner);
        let gateway = GatewayId("gw1".into());
        let cfg = cfg(&site, &gateway, root.stamp);
        let sys = Script::new(runner);
        fresh(&sys);
        let deps = Dependencies {
            system: &sys,
            probe_exec: &sys,
            handle: Some(&handle),
            state_root: &root.path,
        };
        let check = || check_v2::run_check_v2(&deps, &cfg).unwrap().verdict;
        for (file, host_file) in [
            ("scupper-proc-net-udp.txt", "gwhost-proc-net-udp.txt"),
            ("scupper-proc-net-udp6.txt", "gwhost-proc-net-udp6.txt"),
        ] {
            sys.replace(file, &fixture(runner, host_file));
            assert_eq!(
                check(),
                Verdict::Degraded(Degraded::ClientSideBroken(ClientFault::HostSocket))
            );
            sys.replacements.borrow_mut().remove(file);
        }
        sys.replace("host-wg-interfaces", "wg-legacy\n");
        sys.replace("host-wg-wg-legacy-listen-port", "51821\n");
        assert!(matches!(check(), Verdict::Protected { .. }));
        sys.replace("host-wg-wg-legacy-listen-port", "51820\n");
        let Verdict::Unprotected(found) = check() else {
            panic!("parallel host path was accepted");
        };
        assert!(
            found
                .as_slice()
                .contains(&Violation::HostWireguardOnClientPort("wg-legacy".into()))
        );
        // A later client observation failure must not hide the parallel path.
        sys.replace("scupper-wg-wg0-latest-handshakes.txt", "malformed");
        assert_eq!(check().exit_code(), 2);
        sys.replace("scupper--4-route.json", "[]");
        assert_eq!(check().exit_code(), 2);
        sys.replace("host-wg-interfaces", "wg-legacy wg-unreadable");
        sys.replace("host-wg-wg-unreadable-listen-port", "malformed");
        assert_eq!(check().exit_code(), 2);
    }
}

#[test]
fn local_and_other_table_routes_are_containment_violations() {
    use scupper_core::verdict::v2::{Verdict, Violation};
    for runner in ["ubuntu-22.04", "ubuntu-24.04"] {
        let handle = testing::handle().unwrap();
        let root = Root::new(runner, &handle);
        let site = site(runner);
        let gateway = GatewayId("gw1".into());
        let cfg = cfg(&site, &gateway, root.stamp);
        let sys = Script::new(runner);
        fresh(&sys);
        let deps = Dependencies {
            system: &sys,
            probe_exec: &sys,
            handle: Some(&handle),
            state_root: &root.path,
        };
        for (family, dst, table) in [
            ("-4", "128.0.0.0/1", serde_json::json!("local")),
            ("-6", "8000::/1", serde_json::json!("local")),
            ("-4", "128.0.0.0/1", serde_json::json!(253)),
            ("-6", "8000::/1", serde_json::json!(123)),
        ] {
            let file = format!("scupper-{family}-routes-all.json");
            let mut routes: serde_json::Value =
                serde_json::from_str(&fixture(runner, &file)).unwrap();
            routes
                .as_array_mut()
                .unwrap()
                .push(serde_json::json!({"dst": dst, "dev": "wg0", "table": table}));
            sys.replace(&file, &routes.to_string());
            let verdict = check_v2::run_check_v2(&deps, &cfg).unwrap().verdict;
            let Verdict::Unprotected(found) = verdict else {
                panic!("{verdict:?}");
            };
            assert!(found.as_slice().iter().any(|v| matches!(v, Violation::ExtraRoute { dst: got, dev: Some(dev), .. } if got == dst && dev == "wg0")));
            sys.replacements.borrow_mut().remove(&file);
            assert_eq!(
                check_v2::run_check_v2(&deps, &cfg)
                    .unwrap()
                    .verdict
                    .exit_code(),
                0
            );
        }
        // A plausible kernel protocol/type cannot authorize another local address.
        let file = "scupper--4-routes-all.json";
        let mut routes: serde_json::Value = serde_json::from_str(&fixture(runner, file)).unwrap();
        routes.as_array_mut().unwrap().push(serde_json::json!({"type":"local", "protocol":"kernel", "dst":"203.0.113.2", "dev":"lo", "table":"local"}));
        sys.replace(file, &routes.to_string());
        assert_eq!(
            check_v2::run_check_v2(&deps, &cfg)
                .unwrap()
                .verdict
                .exit_code(),
            2
        );
    }
}

#[test]
fn topology_retains_violations_across_item_and_precondition_errors() {
    use scupper_core::verdict::v2::{Verdict, Violation};
    let runner = "ubuntu-24.04";
    let handle = testing::handle().unwrap();
    let root = Root::new(runner, &handle);
    let site = site(runner);
    let gateway = GatewayId("gw1".into());
    let cfg = cfg(&site, &gateway, root.stamp);
    let sys = Script::new(runner);
    fresh(&sys);
    let deps = Dependencies {
        system: &sys,
        probe_exec: &sys,
        handle: Some(&handle),
        state_root: &root.path,
    };
    let check = || check_v2::run_check_v2(&deps, &cfg);
    let detailed = sys.text("scupper--4-link.json");
    for name in ["é", "-foreign", "foreignwg"] {
        let mut links: serde_json::Value =
            serde_json::from_str(&sys.text("scupper--4-link.json")).unwrap();
        links
            .as_array_mut()
            .unwrap()
            .retain(|link| link["ifindex"] != 99);
        links.as_array_mut().unwrap().push(serde_json::json!({"ifindex":99,"ifname":name,"mtu":1420,"flags":["UP"],"linkinfo":{"info_kind":"wireguard"}}));
        sys.replace("scupper--4-link.json", &links.to_string());
        // Address inventory is now inconsistent, yet the raw foreign link wins.
        let Verdict::Unprotected(found) = check().unwrap().verdict else {
            panic!("foreign link lost");
        };
        assert!(
            found
                .as_slice()
                .contains(&Violation::ForeignLink(name.into()))
        );
        assert!(
            !sys.calls
                .borrow()
                .iter()
                .any(|(_, _, args)| args.iter().any(|arg| arg == name))
        );
    }
    let boot = fs::read_to_string(root.path.join("boot.json")).unwrap();
    let state = fs::read_to_string(root.path.join("state.json")).unwrap();
    for file in ["boot.json", "state.json"] {
        fs::remove_file(root.path.join(file)).unwrap();
        assert_eq!(check().unwrap().verdict.exit_code(), 2, "{file}");
        fs::write(
            root.path.join(file),
            if file == "boot.json" { &boot } else { &state },
        )
        .unwrap();
    }
    sys.replace("gwhost--4-addr.json", "malformed");
    assert_eq!(check().unwrap().verdict.exit_code(), 2);
    sys.replacements.borrow_mut().remove("gwhost--4-addr.json");
    sys.replace("scupper--4-link.json", &detailed);
    // A tc violation survives a peer failure on a later configured link.
    sys.replace("scupper-tc-lo-ingress.json", r#"[{"kind":"bpf"}]"#);
    sys.replace("scupper-wg-ex-ch1-peers.txt", "malformed");
    let Verdict::Unprotected(found) = check().unwrap().verdict else {
        panic!("tc violation lost");
    };
    assert!(
        found
            .as_slice()
            .contains(&Violation::TrafficControlHook("lo".into()))
    );
    sys.replacements
        .borrow_mut()
        .remove("scupper-wg-ex-ch1-peers.txt");
    sys.replacements
        .borrow_mut()
        .remove("scupper-tc-lo-ingress.json");
    *sys.oversized_nft.borrow_mut() = true;
    let Verdict::Unprotected(found) = check().unwrap().verdict else {
        panic!("oversized ruleset lost");
    };
    assert!(
        found
            .as_slice()
            .iter()
            .any(|v| matches!(v, Violation::RulesetDiffers { .. }))
    );
    *sys.oversized_nft.borrow_mut() = false;
    fs::remove_file(root.path.join("boot.json")).unwrap();
    assert_eq!(check().unwrap_err().exit_code(), 1);
    let missing = Dependencies {
        handle: None,
        ..deps
    };
    let Verdict::Unprotected(found) = check_v2::run_check_v2(&missing, &cfg).unwrap().verdict
    else {
        panic!("missing namespace hidden by boot error");
    };
    assert!(found.as_slice().contains(&Violation::NetnsMissing));
}

#[test]
fn ingress_forwarding_and_strict_unreachable_diagnostics() {
    use scupper_core::verdict::v2::{DefaultRouteObs, Degraded, RouteAnswer, Verdict};
    let sys = Script::new("ubuntu-24.04");
    fresh(&sys);
    let handle = testing::handle().unwrap();
    let root = Root::new(&sys.runner, &handle);
    let site = site(&sys.runner);
    let gateway = GatewayId("gw1".into());
    let cfg = cfg(&site, &gateway, root.stamp);
    let deps = Dependencies {
        system: &sys,
        probe_exec: &sys,
        handle: Some(&handle),
        state_root: &root.path,
    };
    *sys.route_failure.borrow_mut() = Some((2, "RTNETLINK answers: No route to host\n".into()));
    assert!(matches!(
        check_v2::run_check_v2(&deps, &cfg).unwrap().verdict,
        Verdict::Degraded(Degraded::RouteWrong {
            got: DefaultRouteObs::Unreachable,
            ..
        })
    ));
    sys.replace("scupper-sysctl-net.ipv4.conf.wg0.forwarding.txt", "0\n");
    assert_eq!(
        check_v2::run_check_v2(&deps, &cfg).unwrap().verdict,
        Verdict::Degraded(Degraded::ForwardingDisabled)
    );
    sys.replacements
        .borrow_mut()
        .remove("scupper-sysctl-net.ipv4.conf.wg0.forwarding.txt");
    let health = health(&site, &handle);
    for (status, message) in [
        (2, "Permission denied"),
        (2, "Invalid argument"),
        (1, "No route to host"),
    ] {
        *sys.route_failure.borrow_mut() = Some((status, format!("RTNETLINK answers: {message}\n")));
        let routes = collect::routes(&sys, &handle, &health).unwrap();
        assert!(routes.iter().all(|(_, r)| r.v4.is_err() && r.v6.is_err()));
        assert_eq!(
            check_v2::run_check_v2(&deps, &cfg).unwrap_err().exit_code(),
            1
        );
    }
    *sys.route_failure.borrow_mut() = Some((2, "RTNETLINK answers: No route to host\n".into()));
    assert_eq!(
        collect::routes(&sys, &handle, &health).unwrap()[0].1.v4,
        Ok(RouteAnswer::Unreachable)
    );
}
