//! Boot command traces and FS-9 prefixes use a stateful fake kernel.
//! Fresh namespaces may inherit forwarding=1 while containing only loopback;
//! live namespaces remain untouched during read-only adoption checks. After the
//! gate closes, only verification in the current run permits forwarding=1.
#![cfg(feature = "testing")]
#![allow(clippy::unwrap_used, clippy::panic)]
#[path = "support/v2.rs"]
mod support;
use scupper_core::render::{Scope, desired_sysctls};
use scupper_sys::{
    boot::{BootDeps, BootNamespace, BootPoint, BootReport, BootStep, boot},
    lock::WriterLock,
    netns::testing,
    state::{Quarantine, Selection, StateFile},
    system::Program,
};
use std::{cell::Cell, collections::BTreeMap, fs, os::unix::fs::PermissionsExt, time::Duration};
use support::Root;

#[path = "support/boot_kernel.rs"]
mod boot_kernel;
use boot_kernel::{Kernel, Link};

struct Fixture {
    root: Root,
    kernel: Kernel,
}
impl Fixture {
    fn new() -> Self {
        let root = Root::new("ubuntu-24.04", &testing::handle().unwrap());
        let writer = WriterLock::acquire(root.path.join("lock")).unwrap();
        StateFile::open(&root.path, Some(&writer))
            .unwrap()
            .update(&writer, |s| s.applied_version = Some(1))
            .unwrap();
        let site = support::site("ubuntu-24.04");
        let gw = site.gateways().values().next().unwrap();
        for dir in ["secrets", "secrets/wg"] {
            fs::create_dir(root.path.join(dir)).unwrap();
            fs::set_permissions(root.path.join(dir), fs::Permissions::from_mode(0o700)).unwrap();
        }
        for reference in [
            &gw.client_tunnel().identity().private_key_ref,
            gw.exits()[0].private_key_ref(),
        ] {
            let path = root.path.join("secrets/wg").join(reference.name());
            fs::write(&path, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n").unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        fs::remove_file(root.path.join("boot.json")).unwrap();
        Self {
            root,
            kernel: Kernel::new(),
        }
    }
    fn run(&self, hook: Option<&dyn Fn(BootPoint) -> Result<(), String>>) -> BootReport {
        self.kernel.verified_this_run.set(false);
        self.kernel.gates_closed.set(false);
        self.kernel.began_live.set(
            ["net.ipv4.ip_forward", "net.ipv6.conf.all.forwarding"]
                .iter()
                .any(|key| {
                    self.kernel
                        .values
                        .borrow()
                        .get(*key)
                        .is_some_and(|v| v == "1")
                }),
        );
        boot(&BootDeps {
            system: &self.kernel,
            namespace: &self.kernel,
            state_root: &self.root.path,
            config_root: &self.root.path,
            run_root: &self.root.path.join("run"),
            hook,
            secret_owner: rustix::process::geteuid().as_raw(),
        })
    }
    fn check(&self) -> scupper_core::verdict::v2::Report {
        let held = testing::handle().unwrap();
        let site = support::site("ubuntu-24.04");
        scupper_sys::check_v2::run_check_v2(
            &scupper_sys::check_v2::Dependencies {
                system: &self.kernel,
                probe_exec: &self.kernel.script,
                handle: Some(&held),
                state_root: &self.root.path,
                run_root: &self.root.path.join("run"),
            },
            &scupper_sys::check_v2::Config {
                site: &site,
                gateway: &scupper_core::config::GatewayId("gw1".into()),
                stamp: self.root.stamp,
            },
        )
        .unwrap()
    }
    fn state(&self, change: impl FnOnce(&mut scupper_sys::state::State)) {
        let guard = WriterLock::acquire(self.root.path.join("lock")).unwrap();
        StateFile::open(&self.root.path, Some(&guard))
            .unwrap()
            .update(&guard, change)
            .unwrap();
    }
}

fn assert_only_module_calls(f: &Fixture) {
    assert!(
        f.kernel
            .calls
            .borrow()
            .iter()
            .all(|call| call.starts_with("host Modprobe "))
    );
}

#[test]
fn fresh_and_adopt_call_goldens() {
    let fixture = Fixture::new();
    let report = fixture.run(None);
    assert!(report.succeeded(), "{report:?}");
    assert!(!report.adopted);
    let fresh = fixture.kernel.calls.borrow().join("\n") + "\n";
    // Golden updates are explicit and stay inside the repository.
    if std::env::var_os("SCUPPER_UPDATE_GOLDENS").is_some() {
        fs::write(
            concat!(env!("CARGO_MANIFEST_DIR"), "/tests/golden/boot-fresh.txt"),
            &fresh,
        )
        .unwrap();
    }
    if std::env::var_os("SCUPPER_UPDATE_GOLDENS").is_none() {
        assert_eq!(fresh, include_str!("golden/boot-fresh.txt"));
    }
    let path = fixture.root.path.join("run/boot.json");
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o644
    );
    let persisted: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
    assert_eq!(persisted["steps"].as_array().unwrap().len(), 9);
    assert_eq!(persisted["applied_version"], 1);
    let identities =
        scupper_core::parse::parse_ip_link(&Kernel::json_links(&fixture.kernel.ns.borrow()))
            .unwrap()
            .into_iter()
            .filter(|l| l.kind.as_deref() == Some("wireguard"))
            .map(|l| (l.ifname, l.ifindex))
            .collect::<BTreeMap<_, _>>();
    assert_eq!(report.owned_links, identities);
    assert_eq!(
        persisted["owned_links"],
        serde_json::to_value(&identities).unwrap()
    );
    let roundtrip: BootReport = serde_json::from_value(persisted).unwrap();
    assert!(roundtrip.succeeded());
    assert_eq!(roundtrip.owned_links, identities);
    fixture.kernel.calls.borrow_mut().clear();
    let report = fixture.run(None);
    assert!(report.succeeded() && report.adopted, "{report:?}");
    let adopt = fixture.kernel.calls.borrow().join("\n") + "\n";
    if std::env::var_os("SCUPPER_UPDATE_GOLDENS").is_some() {
        fs::write(
            concat!(env!("CARGO_MANIFEST_DIR"), "/tests/golden/boot-adopt.txt"),
            &adopt,
        )
        .unwrap();
    }
    if std::env::var_os("SCUPPER_UPDATE_GOLDENS").is_none() {
        assert_eq!(adopt, include_str!("golden/boot-adopt.txt"));
    }
    assert_eq!(
        adopt
            .lines()
            .filter(|line| line.contains("replace"))
            .count(),
        2
    );
    // Match the lab's adoption oracle: only reads and two default replacements.
    for call in adopt.lines() {
        assert!(
            call.starts_with("netns Ip ") && (call.contains("show") || call.contains("replace"))
                || call.starts_with("netns Wg show ")
                || call.starts_with("netns Wg pubkey ")
                || call.starts_with("netns Sysctl -n ")
                || call == "netns Nft -j list ruleset"
                || call.starts_with("netns Tc ") && call.contains("show")
                || call.starts_with("host Wg show ")
                || call.starts_with("host Unshare "),
            "adoption unexpectedly mutated the gateway: {call}"
        );
    }
}
#[test]
fn fs9_every_command_and_checkpoint_prefix_is_closed_and_retry_completes() {
    let full = Fixture::new();
    assert!(full.run(None).succeeded());
    let count = full.kernel.calls.borrow().len();
    for stop in 1..=count {
        let f = Fixture::new();
        f.kernel.fail_after.set(Some(stop));
        let report = f.run(None);
        assert!(!report.succeeded(), "command {stop}");
        f.kernel.closed();
        assert!(
            f.kernel
                .host
                .borrow()
                .values()
                .all(|link| !link.up && link.peers.is_empty() && link.addresses.is_empty())
        );
        f.kernel.fail_after.set(None);
        let retry = f.run(None);
        assert!(retry.succeeded(), "retry command {stop}: {retry:?}");
    }
    for point in [
        BootStep::Lock,
        BootStep::Modules,
        BootStep::Inputs,
        BootStep::Close,
        BootStep::Ruleset,
        BootStep::Links,
        BootStep::Routes,
        BootStep::Forwarding,
        BootStep::Record,
    ]
    .map(BootPoint::After)
    .into_iter()
    .chain([
        BootPoint::LinkAdded(scupper_core::rules::IfName::new("wg0").unwrap()),
        BootPoint::LinkAdded(scupper_core::rules::IfName::new("ex-ch1").unwrap()),
    ]) {
        let f = Fixture::new();
        let report = f.run(Some(&|got| {
            if got == point {
                Err("injected checkpoint kill".into())
            } else {
                Ok(())
            }
        }));
        assert!(!report.succeeded(), "{point:?}");
        f.kernel.closed();
        assert!(
            f.kernel
                .host
                .borrow()
                .values()
                .all(|link| !link.up && link.peers.is_empty() && link.addresses.is_empty())
        );
        assert!(f.run(None).succeeded(), "retry {point:?}");
    }
}
#[test]
fn leftovers_secrets_latch_and_absent_state_fail_closed() {
    let f = Fixture::new();
    f.kernel
        .host
        .borrow_mut()
        .insert("wg0".into(), Link::new("wireguard"));
    let report = f.run(None);
    assert!(report.succeeded(), "{report:?}");
    assert!(
        f.kernel
            .calls
            .borrow()
            .iter()
            .any(|c| c == "host Ip link delete dev wg0")
    );
    for kind in [
        "dummy",
        "wireguard-up",
        "wireguard-peer",
        "wireguard-address",
    ] {
        let f = Fixture::new();
        let mut link = Link::new("wireguard");
        match kind {
            "dummy" => link.kind = "dummy".into(),
            "wireguard-up" => link.up = true,
            "wireguard-peer" => {
                link.peers.insert(
                    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
                    ("0.0.0.0/0".into(), "(none)".into()),
                );
            }
            _ => link.addresses.push("192.0.2.1/32".into()),
        }
        f.kernel.host.borrow_mut().insert("wg0".into(), link);
        let report = f.run(None);
        assert!(!report.succeeded(), "{kind}: {report:?}");
        assert_eq!(report.steps.last().unwrap().step, BootStep::Links);
        assert!(
            !f.kernel
                .calls
                .borrow()
                .iter()
                .any(|c| c.contains("link delete"))
        );
        assert_eq!(f.kernel.values.borrow()["net.ipv4.ip_forward"], "0");
    }
    let f = Fixture::new();
    fs::remove_dir_all(f.root.path.join("secrets")).unwrap();
    let report = f.run(None);
    assert!(!report.succeeded());
    assert_eq!(report.steps.last().unwrap().step, BootStep::Inputs);
    assert_only_module_calls(&f);
    let f = Fixture::new();
    f.state(|s| {
        s.quarantine = Some(Quarantine {
            reason: "budget".into(),
            object: "rules".into(),
            since_unix: 1,
            uncertain: false,
        });
    });
    let report = f.run(None);
    assert!(report.succeeded(), "{report:?}");
    assert_eq!(f.kernel.values.borrow()["net.ipv4.ip_forward"], "0");
    assert!(!report.adopted);
    let f = Fixture::new();
    fs::remove_file(f.root.path.join("state.json")).unwrap();
    let report = f.run(None);
    assert!(report.succeeded(), "{report:?}");
    assert_eq!(report.warnings.len(), 1);
    assert_eq!(f.kernel.values.borrow()["net.ipv4.ip_forward"], "0");
    assert_eq!(
        f.kernel.values.borrow()["net.ipv6.conf.all.forwarding"],
        "0"
    );
    assert!(
        f.kernel
            .defaults
            .borrow()
            .values()
            .all(|v| v.contains("unreachable"))
    );
    assert!(!f.root.path.join("state.json").exists());
    let f = Fixture::new();
    fs::remove_file(f.root.path.join("config/head")).unwrap();
    let report = f.run(None);
    assert_eq!(
        report.steps.last().unwrap().error.as_deref(),
        Some("no configuration")
    );
    assert_only_module_calls(&f);
}
#[test]
fn sysctl_mismatch_and_canonical_mismatch_stop_before_links() {
    let f = Fixture::new();
    f.kernel.wrong_readback.set(true);
    assert!(!f.run(None).succeeded());
    assert!(!f.kernel.rules.get());
    let f = Fixture::new();
    f.kernel.bad_canon.set(true);
    let r = f.run(None);
    assert_eq!(r.steps.last().unwrap().step, BootStep::Ruleset);
    assert!(f.kernel.host.borrow().is_empty());
    f.kernel.closed();
}
#[test]
fn sysctl_order_has_gate_first_and_readback_after_hardening() {
    let f = Fixture::new();
    assert!(f.run(None).succeeded());
    let calls = f.kernel.calls.borrow();
    let index = calls
        .iter()
        .position(|c| c == "netns Sysctl -w net.ipv4.ip_forward=1")
        .unwrap();
    let after = &calls[index..];
    assert_eq!(after[1], "netns Sysctl -w net.ipv6.conf.all.forwarding=1");
    let first_read = after.iter().position(|c| c.contains("Sysctl -n")).unwrap();
    assert!(after[..first_read].iter().all(|c| c.contains("Sysctl -w")));
    assert!(
        desired_sysctls(&[], true)
            .iter()
            .filter(|v| v.key.scope != Scope::Global)
            .all(|v| after
                .iter()
                .any(|c| c == &format!("netns Sysctl -w {}={}", v.key, v.value)))
    );
}
#[test]
fn disconnected_routes_are_both_unreachable() {
    let f = Fixture::new();
    f.state(|s| s.selection = Selection::Disconnected);
    assert!(f.run(None).succeeded());
    assert!(
        f.kernel
            .defaults
            .borrow()
            .values()
            .all(|v| v.contains("unreachable"))
    );
    for sysctl in desired_sysctls(
        &[
            scupper_core::rules::IfName::new("wg0").unwrap(),
            scupper_core::rules::IfName::new("ex-ch1").unwrap(),
            scupper_core::rules::IfName::new("lo").unwrap(),
        ],
        false,
    )
    .into_iter()
    .filter(|s| {
        s.key.to_string().ends_with("forwarding") || s.key.to_string() == "net.ipv4.ip_forward"
    }) {
        assert_eq!(f.kernel.values.borrow()[&sysctl.key.to_string()], "0");
    }
    assert!(
        !f.kernel
            .calls
            .borrow()
            .iter()
            .any(|call| call.ends_with("forwarding=1") || call.ends_with("ip_forward=1"))
    );
}

#[test]
fn disconnected_adoption_rejects_open_forwarding_gates() {
    let f = Fixture::new();
    f.state(|s| s.selection = Selection::Disconnected);
    assert!(f.run(None).succeeded());
    for value in f
        .kernel
        .values
        .borrow_mut()
        .iter_mut()
        .filter(|(key, _)| key.ends_with("forwarding") || key.as_str() == "net.ipv4.ip_forward")
    {
        *value.1 = "1".into();
    }
    f.kernel.calls.borrow_mut().clear();
    let report = f.run(None);
    assert!(report.succeeded() && !report.adopted, "{report:?}");
    assert_eq!(f.kernel.values.borrow()["net.ipv4.ip_forward"], "0");
    assert!(
        !f.kernel
            .calls
            .borrow()
            .iter()
            .any(|call| call.ends_with("forwarding=1") || call.ends_with("ip_forward=1"))
    );
}

#[test]
fn drift_reuses_the_namespace_and_foreign_links_stay_down() {
    let f = Fixture::new();
    assert!(f.run(None).succeeded());
    f.kernel
        .values
        .borrow_mut()
        .insert("net.ipv4.conf.all.rp_filter".into(), "2".into());
    f.kernel.calls.borrow_mut().clear();
    let report = f.run(None);
    assert!(report.succeeded() && !report.adopted, "{report:?}");
    assert!(
        !f.kernel
            .calls
            .borrow()
            .iter()
            .any(|c| c.contains("netns add") || c.contains("netns delete"))
    );
    f.kernel.check_links.set(false);
    let mut foreign = Link::new("veth");
    foreign.up = true;
    f.kernel.ns.borrow_mut().insert("uplink".into(), foreign);
    let report = f.run(None);
    assert!(!report.succeeded());
    assert_eq!(report.steps.last().unwrap().step, BootStep::Close);
    assert!(!f.kernel.ns.borrow()["uplink"].up);
    assert_eq!(f.kernel.values.borrow()["net.ipv4.ip_forward"], "0");
}

#[test]
fn boot_uses_applied_version_even_when_head_is_newer() {
    use scupper_sys::store::{MetaInput, VersionStore};
    let f = Fixture::new();
    let writer = WriterLock::acquire(f.root.path.join("lock")).unwrap();
    let store = VersionStore::open(&f.root.path, Some(&writer)).unwrap();
    let candidate = support::site_text("ubuntu-24.04").replace("1420", "1380");
    assert_eq!(
        store
            .commit(
                &writer,
                Some(1),
                &candidate,
                MetaInput {
                    actor: "test".into(),
                    at: 2,
                    reason: "pending candidate".into()
                }
            )
            .unwrap(),
        2
    );
    drop(writer);
    let report = f.run(None);
    assert!(report.succeeded(), "{report:?}");
    assert_eq!(report.applied_version, Some(1));
    assert!(
        f.kernel
            .calls
            .borrow()
            .iter()
            .any(|c| c.contains("mtu 1420 up"))
    );
    assert!(!f.kernel.calls.borrow().iter().any(|c| c.contains("1380")));
}

#[test]
fn invalid_secret_and_corrupt_render_fail_before_kernel_changes() {
    let f = Fixture::new();
    let secret = fs::read_dir(f.root.path.join("secrets/wg"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    fs::write(secret, "invalid key\n").unwrap();
    assert!(!f.run(None).succeeded());
    assert_only_module_calls(&f);
    let f = Fixture::new();
    fs::write(f.root.path.join("rendered/000001.nft"), "flush ruleset\n").unwrap();
    assert!(!f.run(None).succeeded());
    assert_only_module_calls(&f);
}

#[test]
fn lock_contention_is_bounded_and_record_failure_is_reported() {
    let f = Fixture::new();
    let guard = WriterLock::acquire(f.root.path.join("run")).unwrap();
    let start = std::time::Instant::now();
    let report = f.run(None);
    assert!(start.elapsed() < Duration::from_secs(7));
    assert_eq!(report.steps.len(), 1);
    assert_eq!(report.steps[0].step, BootStep::Lock);
    assert!(report.steps[0].error.as_ref().unwrap().contains("timeout"));
    assert!(f.kernel.calls.borrow().is_empty());
    drop(guard);
    std::os::unix::fs::symlink(
        f.root.path.join("state.json"),
        f.root.path.join("run/boot.json"),
    )
    .unwrap();
    let report = f.run(None);
    assert!(!report.succeeded());
    assert_eq!(report.steps.last().unwrap().step, BootStep::Record);
    assert!(
        report
            .steps
            .last()
            .unwrap()
            .error
            .as_ref()
            .unwrap()
            .contains("symlink")
    );
    f.kernel.closed();
}

#[test]
fn every_foreign_link_is_disabled_before_hooks_or_per_link_sysctls() {
    for names in [
        vec!["uplink", "uplink2"],
        vec!["eth0.100"],
        vec!["strange+@"],
        vec!["ex-ch1"],
        vec!["tiny"],
    ] {
        let f = Fixture::new();
        f.kernel.exists.set(true);
        f.kernel.conntrack_loaded.set(true);
        f.kernel.wireguard_loaded.set(true);
        f.kernel.check_links.set(false);
        for name in &names {
            let mut link = Link::new("veth");
            link.up = true;
            if *name == "tiny" {
                link.mtu = 40;
            }
            link.hooks = true;
            link.xdp = true;
            f.kernel.ns.borrow_mut().insert((*name).into(), link);
        }
        let report = f.run(None);
        assert!(!report.succeeded(), "{names:?}: {report:?}");
        assert_eq!(report.steps.last().unwrap().step, BootStep::Close);
        for name in &names {
            let links = f.kernel.ns.borrow();
            let link = &links[*name];
            assert!(!link.up && !link.hooks && !link.xdp, "{name}");
        }
        let calls = f.kernel.calls.borrow();
        let last_down = calls.iter().rposition(|c| c.ends_with(" down")).unwrap();
        let first_hook = calls
            .iter()
            .position(|c| c.contains("Tc qdisc del"))
            .unwrap();
        assert!(last_down < first_hook);
        assert!(
            !calls
                .iter()
                .any(|c| c.contains("Sysctl -w net.ipv4.conf.lo."))
        );
        assert_eq!(f.kernel.values.borrow()["net.ipv4.ip_forward"], "0");
    }
}

#[test]
fn unsafe_raw_names_fail_closed_but_other_foreign_links_are_still_disabled() {
    for name in ["bad/name", "bad name", "bad\0name", "sixteencharacters"] {
        let f = Fixture::new();
        f.kernel.exists.set(true);
        f.kernel.conntrack_loaded.set(true);
        f.kernel.wireguard_loaded.set(true);
        f.kernel.check_links.set(false);
        for name in [name, "uplink"] {
            let mut link = Link::new("veth");
            link.up = true;
            f.kernel.ns.borrow_mut().insert(name.into(), link);
        }
        let report = f.run(None);
        assert!(!report.succeeded());
        assert!(!f.kernel.ns.borrow()["uplink"].up);
        assert!(
            report
                .steps
                .last()
                .unwrap()
                .error
                .as_ref()
                .unwrap()
                .contains("raw kernel link name")
        );
        assert!(
            !f.kernel
                .calls
                .borrow()
                .iter()
                .any(|c| c.contains(name) && c.contains("link set"))
        );
    }
}

#[test]
fn rebuild_flushes_conntrack_after_verification_before_opening_and_records_failure() {
    let f = Fixture::new();
    assert!(f.run(None).succeeded());
    f.kernel
        .values
        .borrow_mut()
        .insert("net.ipv4.conf.all.rp_filter".into(), "2".into());
    f.kernel.calls.borrow_mut().clear();
    let report = f.run(None);
    assert!(report.succeeded() && !report.adopted, "{report:?}");
    let rebuild = f.kernel.calls.borrow().join("\n") + "\n";
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/golden/boot-rebuild.txt");
    if std::env::var_os("SCUPPER_UPDATE_GOLDENS").is_some() {
        fs::write(path, &rebuild).unwrap();
    } else {
        assert_eq!(rebuild, fs::read_to_string(path).unwrap());
    }
    let calls = f.kernel.calls.borrow();
    let flush = calls
        .iter()
        .position(|c| c == "netns Conntrack -F")
        .unwrap();
    let load = calls.iter().position(|c| c.contains("Nft -f")).unwrap();
    let verify = calls[load..]
        .iter()
        .position(|c| c.contains("Unshare"))
        .unwrap()
        + load;
    let open = calls
        .iter()
        .position(|c| c.ends_with("net.ipv4.ip_forward=1"))
        .unwrap();
    assert!(load < verify && verify < flush && flush < open);
    drop(calls);
    for diagnostic in ["command not found", "flush failed", "missing-binary"] {
        f.kernel
            .values
            .borrow_mut()
            .insert("net.ipv4.conf.all.rp_filter".into(), "2".into());
        *f.kernel.failure.borrow_mut() = Some((Program::Conntrack, "-F".into(), diagnostic.into()));
        let report = f.run(None);
        assert!(!report.succeeded());
        let error = report.steps.last().unwrap().error.as_ref().unwrap();
        assert!(error.contains("install conntrack"));
        assert!(error.contains(if diagnostic == "missing-binary" {
            "No such file or directory"
        } else {
            diagnostic
        }));
        assert_eq!(f.kernel.values.borrow()["net.ipv4.ip_forward"], "0");
        let saved: serde_json::Value =
            serde_json::from_slice(&fs::read(f.root.path.join("run/boot.json")).unwrap()).unwrap();
        assert_eq!(
            saved["steps"].as_array().unwrap().last().unwrap()["error"],
            *error
        );
    }
}

#[test]
fn adoption_refuses_every_stale_link_attribute() {
    for attribute in [
        "lo-down",
        "wg0-down",
        "exit-down",
        "wg0-key",
        "exit-key",
        "port",
        "endpoint",
        "keepalive",
        "wg0-mtu",
        "exit-mtu",
        "peer-key",
        "allowed-ips",
        "missing-wg0",
        "missing-exit",
        "rotated-secret",
    ] {
        let f = Fixture::new();
        assert!(f.run(None).succeeded());
        {
            let mut links = f.kernel.ns.borrow_mut();
            match attribute {
                "lo-down" => links.get_mut("lo").unwrap().up = false,
                "wg0-down" => links.get_mut("wg0").unwrap().up = false,
                "exit-down" => links.get_mut("ex-ch1").unwrap().up = false,
                "wg0-key" => links.get_mut("wg0").unwrap().public_key = "(none)".into(),
                "exit-key" => links.get_mut("ex-ch1").unwrap().public_key = "(none)".into(),
                "port" => links.get_mut("wg0").unwrap().port = 1,
                "endpoint" => {
                    links
                        .get_mut("ex-ch1")
                        .unwrap()
                        .peers
                        .values_mut()
                        .next()
                        .unwrap()
                        .1 = "192.0.2.1:1".into();
                }
                "keepalive" => links.get_mut("ex-ch1").unwrap().keepalive = 1,
                "wg0-mtu" => links.get_mut("wg0").unwrap().mtu = 1380,
                "exit-mtu" => links.get_mut("ex-ch1").unwrap().mtu = 1380,
                "peer-key" => {
                    let exit = links.get_mut("ex-ch1").unwrap();
                    let peer = exit.peers.values().next().unwrap().clone();
                    exit.peers.clear();
                    exit.peers
                        .insert("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=".into(), peer);
                }
                "allowed-ips" => {
                    links
                        .get_mut("ex-ch1")
                        .unwrap()
                        .peers
                        .values_mut()
                        .next()
                        .unwrap()
                        .0 = "192.0.2.1/32".into();
                }
                "missing-wg0" => {
                    links.remove("wg0");
                }
                "missing-exit" => {
                    links.remove("ex-ch1");
                }
                "rotated-secret" => {
                    let secret = fs::read_dir(f.root.path.join("secrets/wg"))
                        .unwrap()
                        .next()
                        .unwrap()
                        .unwrap()
                        .path();
                    fs::write(secret, "BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n").unwrap();
                }
                _ => unreachable!(),
            }
        }
        let report = f.run(None);
        assert!(
            report.succeeded() && !report.adopted,
            "{attribute}: {report:?}"
        );
        assert!(f.run(None).adopted, "{attribute} was not repaired");
    }
}

#[test]
fn selections_are_explicit_and_unconfigured_pin_and_prefer_fail_closed() {
    use scupper_core::config::ExitId;
    for selection in [
        Selection::Pin(ExitId("ch1".into())),
        Selection::Prefer(ExitId("ch1".into())),
        Selection::Pin(ExitId("missing".into())),
        Selection::Prefer(ExitId("missing".into())),
    ] {
        let f = Fixture::new();
        assert!(f.run(None).succeeded());
        f.state(|s| s.selection = selection.clone());
        let report = f.run(None);
        let configured =
            matches!(&selection, Selection::Pin(id) | Selection::Prefer(id) if id.0 == "ch1");
        assert_eq!(report.succeeded(), configured, "{selection:?}: {report:?}");
        if configured {
            assert!(f.kernel.defaults.borrow()[&false].contains("ex-ch1"));
            assert!(f.kernel.defaults.borrow()[&true].contains("unreachable"));
        } else {
            assert!(!report.adopted);
            assert_eq!(f.kernel.values.borrow()["net.ipv4.ip_forward"], "0");
            assert!(
                report
                    .steps
                    .last()
                    .unwrap()
                    .error
                    .as_ref()
                    .unwrap()
                    .contains("unconfigured exit")
            );
        }
    }
}

#[test]
fn failed_boot_replaces_prior_success_even_when_inputs_cannot_be_resolved() {
    let f = Fixture::new();
    assert!(f.run(None).succeeded());
    fs::remove_file(f.root.path.join("config/head")).unwrap();
    assert!(!f.run(None).succeeded());
    let saved: serde_json::Value =
        serde_json::from_slice(&fs::read(f.root.path.join("run/boot.json")).unwrap()).unwrap();
    assert_eq!(saved["steps"][2]["error"], "no configuration");
}

#[test]
fn writer_diagnostics_are_bounded_sanitized_and_secret_stdin_is_redacted() {
    for (program, needle, secret) in [
        (Program::Ip, "link add", false),
        (Program::Wg, "listen-port", false),
        (Program::Wg, "private-key", true),
    ] {
        let f = Fixture::new();
        *f.kernel.failure.borrow_mut() =
            Some((program, needle.into(), "diagnostic\n\u{1b}".repeat(500)));
        let report = f.run(None);
        let error = report.steps.last().unwrap().error.as_ref().unwrap();
        assert_eq!(error.contains("diagnostic"), !secret);
        assert!(!error.contains('\n') && !error.contains('\u{1b}'));
        assert!(error.len() < 2200);
    }
}

#[test]
fn fs9b_live_rebuild_checkpoint_prefixes_are_closed_and_retry_completes() {
    for point in [
        BootStep::Lock,
        BootStep::Modules,
        BootStep::Inputs,
        BootStep::Close,
        BootStep::Ruleset,
        BootStep::Links,
        BootStep::Routes,
        BootStep::Forwarding,
        BootStep::Record,
    ] {
        let f = Fixture::new();
        assert!(f.run(None).succeeded());
        f.kernel
            .values
            .borrow_mut()
            .insert("net.ipv4.conf.all.rp_filter".into(), "2".into());
        let report = f.run(Some(&|got| {
            if got == BootPoint::After(point) {
                Err("rebuild checkpoint kill".into())
            } else {
                Ok(())
            }
        }));
        assert!(!report.succeeded(), "{point:?}");
        f.kernel.closed();
        // Step 0 is before input resolution or any namespace mutation; the
        // previously verified live namespace is still intact at that point.
        if point != BootStep::Lock && (point as u8) < BootStep::Forwarding as u8 {
            assert_eq!(
                f.kernel.values.borrow()["net.ipv4.ip_forward"],
                "0",
                "{point:?}"
            );
            assert_eq!(
                f.kernel.values.borrow()["net.ipv6.conf.all.forwarding"],
                "0",
                "{point:?}"
            );
        }
        assert!(f.run(None).succeeded(), "retry {point:?}");
    }
}

#[test]
fn rebuild_removes_redirect_hooks_on_every_configured_link() {
    let f = Fixture::new();
    assert!(f.run(None).succeeded());
    for link in f.kernel.ns.borrow_mut().values_mut() {
        link.hooks = true;
        link.xdp = true;
    }
    let report = f.run(None);
    assert!(report.succeeded() && !report.adopted, "{report:?}");
    assert!(f.kernel.ns.borrow().values().all(|l| !l.hooks && !l.xdp));
}

#[test]
fn fake_closed_cannot_reuse_a_previous_runs_verification() {
    let f = Fixture::new();
    assert!(f.run(None).succeeded());
    f.kernel.verified_this_run.set(false);
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f.kernel.closed())).is_err());
}

#[test]
fn fs9b_live_rebuild_every_command_prefix_is_closed_and_retry_completes() {
    let full = Fixture::new();
    assert!(full.run(None).succeeded());
    full.kernel
        .values
        .borrow_mut()
        .insert("net.ipv4.conf.all.rp_filter".into(), "2".into());
    full.kernel.calls.borrow_mut().clear();
    assert!(full.run(None).succeeded());
    let count = full.kernel.calls.borrow().len();
    for stop in 1..=count {
        let f = Fixture::new();
        assert!(f.run(None).succeeded());
        f.kernel
            .values
            .borrow_mut()
            .insert("net.ipv4.conf.all.rp_filter".into(), "2".into());
        f.kernel.calls.borrow_mut().clear();
        f.kernel.fail_after.set(Some(stop));
        assert!(!f.run(None).succeeded(), "rebuild command {stop}");
        f.kernel.closed();
        f.kernel.fail_after.set(None);
        assert!(f.run(None).succeeded(), "retry rebuild command {stop}");
    }
}

#[test]
fn losing_state_on_a_live_gateway_excludes_adoption_and_keeps_both_gates_closed() {
    let f = Fixture::new();
    assert!(f.run(None).succeeded());
    fs::remove_file(f.root.path.join("state.json")).unwrap();
    let report = f.run(None);
    assert!(report.succeeded() && !report.adopted, "{report:?}");
    assert_eq!(report.warnings.len(), 1);
    for key in ["net.ipv4.ip_forward", "net.ipv6.conf.all.forwarding"] {
        assert_eq!(f.kernel.values.borrow()[key], "0");
    }
    assert!(
        f.kernel
            .defaults
            .borrow()
            .values()
            .all(|r| r.contains("unreachable"))
    );
    assert!(!f.kernel.ns.borrow()["ex-ch1"].up);
    assert!(!f.root.path.join("state.json").exists());
}

#[test]
fn adopting_a_disconnect_closes_routes_before_exits_and_reconnect_opens_exits_before_routes() {
    let f = Fixture::new();
    assert!(f.run(None).succeeded());
    f.state(|s| s.selection = Selection::Disconnected);
    // Disconnected adoption requires closed gates; step 5 still reasserts
    // route closure before lowering exits, preserving the client session.
    for (key, value) in f.kernel.values.borrow_mut().iter_mut() {
        if key.ends_with("forwarding") || key == "net.ipv4.ip_forward" {
            *value = "0".into();
        }
    }
    f.kernel.calls.borrow_mut().clear();
    let report = f.run(None);
    assert!(report.succeeded() && report.adopted, "{report:?}");
    let calls = f.kernel.calls.borrow();
    let route = calls
        .iter()
        .rposition(|c| c.contains("route replace unreachable"))
        .unwrap();
    let down = calls
        .iter()
        .position(|c| c == "netns Ip link set dev ex-ch1 down")
        .unwrap();
    assert!(route < down);
    drop(calls);
    f.state(|s| s.selection = Selection::Auto);
    f.kernel.calls.borrow_mut().clear();
    let reconnect = f.run(None);
    assert!(reconnect.succeeded() && !reconnect.adopted, "{reconnect:?}");
    let calls = f.kernel.calls.borrow();
    let up = calls
        .iter()
        .position(|c| c.contains("ex-ch1") && c.ends_with(" up"))
        .unwrap();
    let route = calls
        .iter()
        .position(|c| c.contains("route replace default dev ex-ch1"))
        .unwrap();
    assert!(up < route);
}

#[test]
fn failed_sysctl_write_keeps_stderr_when_readback_disagrees() {
    let f = Fixture::new();
    f.kernel
        .values
        .borrow_mut()
        .insert("net.ipv4.conf.all.rp_filter".into(), "2".into());
    *f.kernel.failure.borrow_mut() = Some((
        Program::Sysctl,
        "-w net.ipv4.conf.all.rp_filter=0".into(),
        "permission denied".into(),
    ));
    let report = f.run(None);
    assert!(!report.succeeded());
    assert!(
        report
            .steps
            .last()
            .unwrap()
            .error
            .as_ref()
            .unwrap()
            .contains("permission denied")
    );
}

#[test]
fn absent_qdisc_deletes_are_idempotent_and_failed_detaches_disable_all_affected_links() {
    let f = Fixture::new();
    *f.kernel.failure.borrow_mut() = Some((
        Program::Tc,
        "qdisc del".into(),
        "No such file or directory".into(),
    ));
    assert!(f.run(None).succeeded());
    for link in f.kernel.ns.borrow_mut().values_mut() {
        link.hooks = true;
        link.xdp = true;
    }
    let report = f.run(None);
    assert!(!report.succeeded());
    assert!(f.kernel.ns.borrow().values().all(|l| !l.up && !l.xdp));
    assert_eq!(f.kernel.values.borrow()["net.ipv4.ip_forward"], "0");
    assert!(
        report
            .steps
            .last()
            .unwrap()
            .error
            .as_ref()
            .unwrap()
            .contains("No such file or directory")
    );
}

#[test]
fn inputs_checkpoint_already_has_every_foreign_link_down_and_every_redirect_removed() {
    let f = Fixture::new();
    assert!(f.run(None).succeeded());
    f.kernel.check_links.set(false);
    for name in ["foreign+", "eth0.100", "uplink"] {
        let mut link = Link::new("veth");
        link.up = true;
        f.kernel.ns.borrow_mut().insert(name.into(), link);
    }
    for link in f.kernel.ns.borrow_mut().values_mut() {
        link.hooks = true;
        link.xdp = true;
    }
    let report = f.run(Some(&|point| {
        if point == BootPoint::After(BootStep::Inputs) {
            Err("kill before Close checkpoint".into())
        } else {
            Ok(())
        }
    }));
    assert!(!report.succeeded());
    let links = f.kernel.ns.borrow();
    for name in ["foreign+", "eth0.100", "uplink"] {
        assert!(!links[name].up);
    }
    assert!(links.values().all(|l| !l.hooks && !l.xdp));
    assert_eq!(f.kernel.values.borrow()["net.ipv4.ip_forward"], "0");
}

#[test]
fn reconciler_link_configuration_is_local_and_ignores_other_missing_keys() {
    use scupper_core::{
        config::GatewayId,
        planner::{Desired, Step},
        render::RouteTarget,
        verdict::v2::Selection,
    };
    use scupper_sys::reconcile::{Config, Kernel as _, RealKernel};
    use std::sync::Arc;
    let fixture = Fixture::new();
    assert!(fixture.run(None).succeeded());
    let site = support::site("ubuntu-24.04");
    let exit = &site.gateway(&GatewayId("gw1".into())).unwrap().exits()[0];
    fs::remove_file(
        fixture
            .root
            .path
            .join("secrets/wg")
            .join(exit.private_key_ref().name()),
    )
    .unwrap();
    let handle = Arc::new(testing::handle().unwrap());
    let config = Config {
        site: site.clone(),
        gateway: GatewayId("gw1".into()),
        stamp: fixture.root.stamp,
        fingerprint: [7; 32],
        run_root: fixture.root.path.join("run"),
        lock_wait: Duration::ZERO,
    };
    let desired = Desired::new(
        &site,
        &config.gateway,
        &config.stamp,
        config.fingerprint,
        &RouteTarget::Unreachable,
        &Selection::Auto,
    )
    .unwrap();
    let adapter = RealKernel::new(
        BootDeps {
            system: &fixture.kernel,
            namespace: &fixture.kernel,
            state_root: &fixture.root.path,
            config_root: &fixture.root.path,
            run_root: &config.run_root,
            hook: None,
            secret_owner: rustix::process::geteuid().as_raw(),
        },
        handle.clone(),
        &config,
        support::health(&site, &handle),
        handle.fd_path(),
        None,
    )
    .unwrap();
    fixture.kernel.calls.borrow_mut().clear();
    let gates = fixture.kernel.values.borrow().clone();
    adapter
        .execute(&Step::LinkReconfigure {
            link: desired.links()["wg0"].clone(),
        })
        .unwrap();
    assert_eq!(*fixture.kernel.values.borrow(), gates);
    assert!(
        !fixture
            .kernel
            .calls
            .borrow()
            .iter()
            .any(|call| call.contains("Sysctl"))
    );
}

#[test]
fn durable_boot_handoff_resumes_owned_links_and_guards_forwarding_intent() {
    use scupper_core::{
        config::GatewayId,
        failover::MonoTime,
        planner::{Known, Step},
        render::VersionStamp,
        verdict::v2::{HealthConfigV2, NetnsIdentity},
    };
    use scupper_sys::{
        events::EventLog,
        reconcile::{Config, Kernel as KernelAdapter, RealKernel, Reconciler},
        state::Selection,
    };
    use std::{sync::Arc, time::Instant};
    let fixture = Fixture::new();
    assert!(fixture.run(None).succeeded());
    let held = Arc::new(fixture.kernel.open().unwrap().unwrap());
    let config = Config {
        site: support::site("ubuntu-24.04"),
        gateway: GatewayId("gw1".into()),
        stamp: VersionStamp {
            version: 1,
            sha256: [0; 32],
        },
        fingerprint: scupper_sys::canon::fingerprint(
            &scupper_sys::canon::canonicalize(&support::fixture(
                "ubuntu-24.04",
                "scupper-nft-ruleset.json",
            ))
            .unwrap(),
        )
        .unwrap(),
        run_root: fixture.root.path.join("run"),
        lock_wait: Duration::ZERO,
    };
    let health = HealthConfigV2::new(
        &config.site,
        &config.gateway,
        NetnsIdentity {
            device: held.identity().0,
            inode: held.identity().1,
        },
        vec!["203.0.113.1".parse().unwrap()],
        1,
    )
    .unwrap();
    let run_root = config.run_root.clone();
    let kernel = RealKernel::from_boot_file(
        BootDeps {
            system: &fixture.kernel,
            namespace: &fixture.kernel,
            state_root: &fixture.root.path,
            config_root: &fixture.root.path,
            run_root: &run_root,
            hook: None,
            secret_owner: rustix::process::geteuid().as_raw(),
        },
        held.clone(),
        &config,
        health,
        held.fd_path(),
        None,
    )
    .unwrap();
    let safety = kernel.observe(&held);
    for name in ["wg0", "ex-ch1"] {
        assert_eq!(safety.model.links[name].ours, Known::Value(true));
    }
    // The pre-enable state read has a fresh timeout even after collection expired.
    kernel.observe_rest(&held, safety, Instant::now());
    kernel.execute(&Step::FlushConntrack).unwrap();
    let on = Step::ForwardingOn {
        requires: config.fingerprint,
    };
    kernel.execute(&on).unwrap();
    kernel.execute(&Step::ForwardingOff).unwrap();
    let guard = WriterLock::acquire(&config.run_root).unwrap();
    let store = StateFile::open(&fixture.root.path, None).unwrap();
    store
        .update(&guard, |state| state.selection = Selection::Disconnected)
        .unwrap();
    kernel.execute(&Step::FlushConntrack).unwrap();
    assert!(kernel.execute(&on).is_err());
    drop(guard);
    let log =
        EventLog::memory_only(config.gateway.clone(), || scupper_proto::UnixSeconds(1000)).unwrap();
    let mut reconciler = Reconciler::new(kernel, store, log.handle.clone(), config, held, || {
        (MonoTime(Duration::from_secs(1)), 1000)
    })
    .unwrap();
    let report = reconciler.tick();
    assert!(
        !report
            .escalations
            .contains(&scupper_sys::reconcile::Escalation::LinkCollision)
    );
    assert!(
        report
            .steps
            .iter()
            .all(|s| !matches!(s, Step::ForwardingOn { .. }))
    );
}

#[test]
fn control_commit_and_apply_use_one_writer_and_end_version_changes_in_full_boot() {
    use scupper_proto::{ApiErrorCode, OpResult, Reason};
    use scupper_sys::{daemon::admin, events::EventLog};
    let fixture = Fixture::new();
    assert!(fixture.run(None).succeeded());
    let run_root = fixture.root.path.join("run");
    let deps = BootDeps {
        system: &fixture.kernel,
        namespace: &fixture.kernel,
        state_root: &fixture.root.path,
        config_root: &fixture.root.path,
        run_root: &run_root,
        hook: None,
        secret_owner: rustix::process::geteuid().as_raw(),
    };
    let log = EventLog::memory_only(scupper_core::config::GatewayId("gw1".into()), || {
        scupper_proto::UnixSeconds(1000)
    })
    .unwrap();
    let before = fs::read(fixture.root.path.join("state.json")).unwrap();
    let calls = fixture.kernel.calls.borrow().len();
    assert!(matches!(
        admin::apply(&deps, &log.handle, None, true, 0).unwrap(),
        OpResult::Apply {
            dry_run: true,
            version: 1,
            ..
        }
    ));
    assert_eq!(fixture.kernel.calls.borrow().len(), calls);
    assert_eq!(
        fs::read(fixture.root.path.join("state.json")).unwrap(),
        before
    );
    assert_eq!(
        admin::apply(&deps, &log.handle, Some(999), true, 0)
            .unwrap_err()
            .code,
        ApiErrorCode::NotFound
    );
    assert_eq!(
        admin::apply(&deps, &log.handle, None, false, 1000)
            .unwrap_err()
            .code,
        ApiErrorCode::Unauthorized
    );
    let text = support::site_text("ubuntu-24.04");
    assert_eq!(
        admin::commit(&deps, &log.handle, Some(99), &text, Reason::Operator, 0)
            .unwrap_err()
            .code,
        ApiErrorCode::Conflict
    );
    assert!(matches!(
        admin::commit(&deps, &log.handle, Some(1), &text, Reason::Operator, 0).unwrap(),
        OpResult::Commit { version: 2 }
    ));
    let guard = WriterLock::acquire(&run_root).unwrap();
    assert!(admin::apply(&deps, &log.handle, None, false, 0).is_err());
    drop(guard);
    fixture.kernel.verified_this_run.set(false);
    fixture.kernel.gates_closed.set(false);
    fixture.kernel.began_live.set(true);
    assert!(matches!(
        admin::apply(&deps, &log.handle, None, false, 0).unwrap(),
        OpResult::Apply {
            version: 2,
            dry_run: false,
            ..
        }
    ));
    let report: BootReport =
        serde_json::from_slice(&fs::read(run_root.join("boot.json")).unwrap()).unwrap();
    assert_eq!(report.applied_version, Some(2));
    assert!(!report.adopted);
    assert!(fixture.kernel.verified_this_run.get());
}

#[test]
fn control_apply_keeps_quarantine_on_failure_and_clears_only_after_full_verification() {
    use scupper_sys::{daemon::admin, events::EventLog};
    let fixture = Fixture::new();
    fixture.state(|s| {
        s.quarantine = Some(Quarantine {
            reason: "repair-budget".into(),
            object: "safety:ruleset".into(),
            since_unix: 1000,
            uncertain: false,
        });
    });
    assert!(fixture.run(None).succeeded());
    let run_root = fixture.root.path.join("run");
    let observed_open = Cell::new(false);
    let verification = |point| {
        assert!(
            WriterLock::try_acquire(&run_root).is_err(),
            "apply released its writer capability"
        );
        if point == BootPoint::After(BootStep::Forwarding) {
            let file = StateFile::open(&fixture.root.path, None).unwrap();
            let scupper_sys::state::StateRead::Present(state) = file.read().unwrap() else {
                panic!("missing state");
            };
            assert!(
                state.quarantine.is_some(),
                "latch cleared before opening boot verified"
            );
            observed_open.set(true);
        }
        Ok(())
    };
    let deps = BootDeps {
        system: &fixture.kernel,
        namespace: &fixture.kernel,
        state_root: &fixture.root.path,
        config_root: &fixture.root.path,
        run_root: &run_root,
        hook: Some(&verification),
        secret_owner: rustix::process::geteuid().as_raw(),
    };
    let log = EventLog::memory_only(scupper_core::config::GatewayId("gw1".into()), || {
        scupper_proto::UnixSeconds(1000)
    })
    .unwrap();
    *fixture.kernel.failure.borrow_mut() = Some((Program::Nft, "-f".into(), "injected".into()));
    assert!(admin::apply(&deps, &log.handle, None, false, 0).is_err());
    let file = StateFile::open(&fixture.root.path, None).unwrap();
    let scupper_sys::state::StateRead::Present(state) = file.read().unwrap() else {
        panic!("missing state");
    };
    assert!(state.quarantine.is_some());
    assert_eq!(fixture.kernel.values.borrow()["net.ipv4.ip_forward"], "0");
    // A failure in the boot that enables forwarding must leave durable quarantine intact.
    *fixture.kernel.failure.borrow_mut() = Some((
        Program::Sysctl,
        "net.ipv6.conf.all.forwarding=1".into(),
        "opening failed".into(),
    ));
    assert!(admin::apply(&deps, &log.handle, None, false, 0).is_err());
    let scupper_sys::state::StateRead::Present(state) = file.read().unwrap() else {
        panic!("missing state");
    };
    assert!(state.quarantine.is_some());
    assert_eq!(fixture.kernel.values.borrow()["net.ipv4.ip_forward"], "0");
    *fixture.kernel.failure.borrow_mut() = None;
    fixture.kernel.calls.borrow_mut().clear();
    assert!(admin::apply(&deps, &log.handle, None, false, 0).is_ok());
    let scupper_sys::state::StateRead::Present(state) = file.read().unwrap() else {
        panic!("missing state");
    };
    assert!(state.quarantine.is_none());
    assert!(observed_open.get());
    assert!(
        !fixture
            .kernel
            .calls
            .borrow()
            .iter()
            .any(|call| call.contains("wg0 down")
                || (call.starts_with("netns Wg set wg0 peer") && call.ends_with("remove")))
    );
    assert_eq!(fixture.kernel.values.borrow()["net.ipv4.ip_forward"], "1");
}

#[test]
fn disconnected_reboot_preserves_client_sessions() {
    let f = Fixture::new();
    assert!(f.run(None).succeeded());
    f.state(|state| state.selection = Selection::Disconnected);
    assert!(f.run(None).succeeded());
    // Effective daemon disconnect closes the gates as well as exit links.
    for key in [
        "net.ipv4.ip_forward",
        "net.ipv6.conf.all.forwarding",
        "net.ipv4.conf.default.forwarding",
        "net.ipv6.conf.default.forwarding",
    ] {
        f.kernel.values.borrow_mut().insert(key.into(), "0".into());
    }
    f.kernel.calls.borrow_mut().clear();
    // A second boot sees exits already down, as after an effective disconnect.
    let reboot = f.run(None);
    assert!(reboot.succeeded() && reboot.adopted, "{reboot:?}");
    assert!(
        f.kernel
            .defaults
            .borrow()
            .values()
            .all(|route| route.contains("unreachable"))
    );
    assert_eq!(f.kernel.defaults.borrow().len(), 2);
    assert!(!f.kernel.ns.borrow()["ex-ch1"].up);
    assert_eq!(f.kernel.values.borrow()["net.ipv4.ip_forward"], "0");
    assert_eq!(
        f.kernel.values.borrow()["net.ipv6.conf.all.forwarding"],
        "0"
    );
    assert_eq!(
        f.check().verdict,
        scupper_core::verdict::v2::Verdict::FailClosed(
            scupper_core::verdict::v2::FailClosed::AdminDisconnected
        )
    );
    let calls = f.kernel.calls.borrow();
    assert!(
        !calls
            .iter()
            .any(|call| call.starts_with("netns Wg set wg0"))
    );
    assert!(!calls.iter().any(|call| call.contains("wg0 down")));
}

#[test]
fn explicit_apply_version_does_not_verify_unrelated_head() {
    use scupper_sys::{daemon::admin, events::EventLog};
    let f = Fixture::new();
    assert!(f.run(None).succeeded());
    // Head's committed version is now unavailable. The requested older version
    // is still below that committed head and its own metadata verifies.
    fs::write(f.root.path.join("config/head"), b"2\n").unwrap();
    let run_root = f.root.path.join("run");
    let deps = BootDeps {
        system: &f.kernel,
        namespace: &f.kernel,
        state_root: &f.root.path,
        config_root: &f.root.path,
        run_root: &run_root,
        hook: None,
        secret_owner: rustix::process::geteuid().as_raw(),
    };
    let log = EventLog::memory_only(scupper_core::config::GatewayId("gw1".into()), || {
        scupper_proto::UnixSeconds(1000)
    })
    .unwrap();
    assert!(admin::apply(&deps, &log.handle, Some(1), true, 0).is_ok());
    assert!(admin::apply(&deps, &log.handle, None, true, 0).is_err());
}

#[test]
fn full_boot_updates_client_peers_without_resetting_sessions() {
    let f = Fixture::new();
    assert!(f.run(None).succeeded());
    for peer in f
        .kernel
        .ns
        .borrow_mut()
        .get_mut("wg0")
        .unwrap()
        .peers
        .values_mut()
    {
        peer.1 = "198.51.100.44:65000".into();
    }
    let peers = f.kernel.ns.borrow()["wg0"].peers.clone();
    // Retained peers must lose an injected default AllowedIP in place.
    for peer in f
        .kernel
        .ns
        .borrow_mut()
        .get_mut("wg0")
        .unwrap()
        .peers
        .values_mut()
    {
        peer.0.push_str(",0.0.0.0/0");
    }
    f.kernel
        .ns
        .borrow_mut()
        .get_mut("wg0")
        .unwrap()
        .peers
        .insert(
            "CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk=".into(),
            ("10.99.0.99/32".into(), "(none)".into()),
        );
    // A changed MTU forces a full boot over the existing link.
    f.kernel.ns.borrow_mut().get_mut("wg0").unwrap().mtu = 1300;
    f.kernel.calls.borrow_mut().clear();
    let report = f.run(None);
    assert!(report.succeeded() && !report.adopted, "{report:?}");
    assert_eq!(f.kernel.ns.borrow()["wg0"].peers, peers);
    let calls = f.kernel.calls.borrow();
    assert!(!calls.iter().any(|call| {
        peers
            .keys()
            .any(|key| call == &format!("netns Wg set wg0 peer {key} remove"))
    }));
    assert!(!calls.iter().any(|call| call.contains("wg0 down")));
    assert!(
        calls
            .iter()
            .any(|call| call.starts_with("netns Wg set wg0 peer")
                && call.contains("allowed-ips")
                && call.contains("persistent-keepalive 0")
                && call.contains("preshared-key /dev/null"))
    );
}

#[test]
fn disconnected_boot_closes_an_up_exit_and_foreign_default() {
    let f = Fixture::new();
    assert!(f.run(None).succeeded());
    f.state(|state| state.selection = Selection::Disconnected);
    f.kernel
        .defaults
        .borrow_mut()
        .insert(false, "default dev foreign0".into());
    let report = f.run(None);
    assert!(report.succeeded(), "{report:?}");
    assert!(!f.kernel.ns.borrow()["ex-ch1"].up);
    assert!(
        f.kernel
            .defaults
            .borrow()
            .values()
            .all(|route| route.contains("unreachable"))
    );
    assert_eq!(f.check().verdict.exit_code(), 4);
}

#[test]
#[allow(clippy::too_many_lines)]
fn failed_apply_restores_version_without_drift_budget_or_latch_and_restart_boots_previous() {
    use scupper_proto::{EventKind, Op, OpResult};
    use scupper_sys::{
        daemon::admin,
        events::EventLog,
        store::{MetaInput, VersionStore},
    };
    let f = Fixture::new();
    assert!(f.run(None).succeeded());
    let run_root = f.root.path.join("run");
    let guard = WriterLock::acquire(&run_root).unwrap();
    VersionStore::open(&f.root.path, Some(&guard))
        .unwrap()
        .commit(
            &guard,
            Some(1),
            &support::site_text("ubuntu-24.04").replace("mtu = 1420", "mtu = 1400"),
            MetaInput {
                actor: "test".into(),
                at: 1000,
                reason: "exit change".into(),
            },
        )
        .unwrap();
    drop(guard);
    let fail_target = |point| {
        let scupper_sys::state::StateRead::Present(state) =
            StateFile::open(&f.root.path, None).unwrap().read().unwrap()
        else {
            unreachable!()
        };
        if point == BootPoint::After(BootStep::Ruleset) && state.applied_version == Some(2) {
            assert!(f.kernel.verified_this_run.get());
            return Err("target failed after loading ruleset".into());
        }
        Ok(())
    };
    let deps = || BootDeps {
        system: &f.kernel,
        namespace: &f.kernel,
        state_root: &f.root.path,
        config_root: &f.root.path,
        run_root: &run_root,
        hook: Some(&fail_target),
        secret_owner: rustix::process::geteuid().as_raw(),
    };
    let log = EventLog::memory_only(scupper_core::config::GatewayId("gw1".into()), || {
        scupper_proto::UnixSeconds(1000)
    })
    .unwrap();
    for _ in 0..4 {
        assert!(admin::apply(&deps(), &log.handle, Some(2), false, 0).is_err());
        let scupper_sys::state::StateRead::Present(state) =
            StateFile::open(&f.root.path, None).unwrap().read().unwrap()
        else {
            unreachable!()
        };
        assert_eq!(state.applied_version, Some(1));
        assert!(state.quarantine.is_none());
        let report: BootReport =
            serde_json::from_slice(&fs::read(run_root.join("boot.json")).unwrap()).unwrap();
        assert!(report.succeeded());
        assert_eq!(report.applied_version, Some(1));
        let site = support::site("ubuntu-24.04");
        let stamp = f.root.stamp;
        let held = std::sync::Arc::new(testing::handle().unwrap());
        let (device, inode) = held.identity();
        let health = scupper_core::verdict::v2::HealthConfigV2::new(
            &site,
            &scupper_core::config::GatewayId("gw1".into()),
            scupper_core::verdict::v2::NetnsIdentity { device, inode },
            vec!["203.0.113.1".parse().unwrap()],
            1,
        )
        .unwrap();
        let fingerprint = scupper_sys::canon::fingerprint(
            &scupper_sys::canon::canonicalize(&f.kernel.script.text("want.json")).unwrap(),
        )
        .unwrap();
        let config = scupper_sys::reconcile::Config {
            site,
            gateway: scupper_core::config::GatewayId("gw1".into()),
            stamp,
            fingerprint,
            run_root: run_root.clone(),
            lock_wait: Duration::from_millis(100),
        };
        let kernel = scupper_sys::reconcile::RealKernel::from_boot_file(
            deps(),
            held.clone(),
            &config,
            health,
            "/proc/self/ns/net".into(),
            None,
        )
        .unwrap();
        let mut machine = scupper_sys::reconcile::Reconciler::new(
            kernel,
            StateFile::open(&f.root.path, None).unwrap(),
            log.handle.clone(),
            config,
            held,
            || (scupper_core::failover::MonoTime(Duration::ZERO), 1000),
        )
        .unwrap();
        machine.resume_existing();
        assert!(matches!(
            admin::execute(&mut machine, Op::Ping {}, 0, Some(0), |_| unreachable!()).unwrap(),
            OpResult::Ping {
                version: 1,
                quarantined: false,
                ..
            }
        ));
        let tick = machine.tick();
        assert!(
            !tick
                .events
                .iter()
                .any(|event| matches!(event, EventKind::DriftDetected { .. }))
        );
        assert!(machine.latch().is_none());
        drop(machine);
        let restart = f.run(None);
        assert!(restart.succeeded());
        assert_eq!(restart.applied_version, Some(1));
    }
    assert!(!run_root.join("boot-attempts").exists());
    let disk = EventLog::open(
        &f.root.path,
        scupper_core::config::GatewayId("gw1".into()),
        || scupper_proto::UnixSeconds(1000),
    )
    .unwrap();
    log.handle.replay_into(&disk.handle).unwrap();
    disk.handle.flush_blocking(Duration::from_secs(2)).unwrap();
    let events: Vec<_> = scupper_sys::events::read_since(&f.root.path, 0, None)
        .map(Result::unwrap)
        .collect();
    assert_eq!(
        events
            .iter()
            .filter(|e| matches!(e.kind, EventKind::ApplyFailed { .. }))
            .count(),
        4
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(
                event.kind,
                EventKind::Boot {
                    result: scupper_proto::Outcome::Recovered,
                    ..
                }
            ))
            .count(),
        4
    );
    assert!(
        !events
            .iter()
            .any(|e| matches!(e.kind, EventKind::DriftDetected { .. }))
    );
}

#[test]
fn failed_apply_with_undurable_rollback_keeps_forwarding_closed() {
    use scupper_sys::{daemon::admin, events::EventLog};
    let f = Fixture::new();
    assert!(f.run(None).succeeded());
    let break_rollback = |point| {
        if point == BootPoint::After(BootStep::Ruleset) {
            fs::rename(
                f.root.path.join("state.json"),
                f.root.path.join("saved-state.json"),
            )
            .unwrap();
            fs::create_dir(f.root.path.join("state.json")).unwrap();
            return Err("boot failed and rollback publication unavailable".into());
        }
        Ok(())
    };
    let run_root = f.root.path.join("run");
    let deps = BootDeps {
        system: &f.kernel,
        namespace: &f.kernel,
        state_root: &f.root.path,
        config_root: &f.root.path,
        run_root: &run_root,
        hook: Some(&break_rollback),
        secret_owner: rustix::process::geteuid().as_raw(),
    };
    let log = EventLog::memory_only(scupper_core::config::GatewayId("gw1".into()), || {
        scupper_proto::UnixSeconds(1000)
    })
    .unwrap();
    let error = admin::apply(&deps, &log.handle, Some(1), false, 0).unwrap_err();
    assert_eq!(error.code, scupper_proto::ApiErrorCode::RollbackFailed);
    assert_eq!(f.kernel.values.borrow()["net.ipv4.ip_forward"], "0");
    assert_eq!(
        f.kernel.values.borrow()["net.ipv6.conf.all.forwarding"],
        "0"
    );
    let report: BootReport =
        serde_json::from_slice(&fs::read(run_root.join("boot.json")).unwrap()).unwrap();
    assert!(!report.succeeded());
}

#[test]
fn runtime_dispatcher_failed_apply_rolls_back_and_unknown_version_keeps_attachment() {
    use scupper_sys::{
        daemon::testing::dispatch_apply,
        store::{MetaInput, VersionStore},
    };
    let f = Fixture::new();
    assert!(f.run(None).succeeded());
    let run = f.root.path.join("run");
    let guard = WriterLock::acquire(&run).unwrap();
    VersionStore::open(&f.root.path, Some(&guard))
        .unwrap()
        .commit(
            &guard,
            Some(1),
            &support::site_text("ubuntu-24.04").replace("mtu = 1420", "mtu = 1400"),
            MetaInput {
                actor: "test".into(),
                at: 1000,
                reason: "failing target".into(),
            },
        )
        .unwrap();
    drop(guard);
    for version in [99, 2] {
        *f.kernel.failure.borrow_mut() =
            Some((Program::Ip, "mtu 1400".into(), "target failure".into()));
        let deps = BootDeps {
            system: &f.kernel,
            namespace: &f.kernel,
            state_root: &f.root.path,
            config_root: &f.root.path,
            run_root: &run,
            hook: None,
            secret_owner: rustix::process::geteuid().as_raw(),
        };
        let (response, before, after, retained_completion, tick) =
            dispatch_apply(deps, version).unwrap();
        assert_eq!(
            before, after,
            "published attachment changed for apply {version}"
        );
        assert_eq!(retained_completion, version == 99);
        let error = response.result.unwrap_err();
        if version == 99 {
            assert_eq!(error.code, scupper_proto::ApiErrorCode::NotFound);
        } else {
            assert_eq!(
                error.observation.as_ref().unwrap()["rollback"]["verified"],
                true
            );
            assert!(error.to_string().contains("rolled back to 1 (verified)"));
        }
        assert!(tick.complete, "apply {version}: {tick:?}");
        assert!(
            tick.events
                .iter()
                .all(|event| !matches!(event, scupper_proto::EventKind::DriftDetected { .. })),
            "{tick:?}"
        );
    }
}

#[test]
fn full_boot_rotates_keys_and_reconfiguration_removes_unassigned_clients() {
    use scupper_core::config::{GatewayId, parse_site, validate};
    use scupper_sys::store::{MetaInput, VersionStore};
    let f = Fixture::new();
    assert!(f.run(None).succeeded());
    let mut config = parse_site(&support::site_text("ubuntu-24.04")).unwrap();
    let mut other = config.devices["client"].clone();
    other.public_key =
        scupper_core::config::PublicKey("BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ=".into());
    other.address4 = "10.99.0.3/32".into();
    config.devices.insert("other".into(), other.clone());
    let run = f.root.path.join("run");
    let publish = |config: &scupper_core::config::SiteConfig| {
        let text = toml::to_string(config).unwrap();
        validate(config.clone()).unwrap();
        let guard = WriterLock::acquire(&run).unwrap();
        let store = VersionStore::open(&f.root.path, Some(&guard)).unwrap();
        let version = store
            .commit(
                &guard,
                store.head().unwrap(),
                &text,
                MetaInput {
                    actor: "test".into(),
                    at: 1000,
                    reason: "device update".into(),
                },
            )
            .unwrap();
        let file = StateFile::open(&f.root.path, None).unwrap();
        let scupper_sys::state::StateRead::Present(mut state) = file.read().unwrap() else {
            unreachable!()
        };
        state.applied_version = Some(version);
        file.write(&guard, &state).unwrap();
    };
    publish(&config);
    assert!(f.run(None).succeeded());
    let old = config.devices["client"].public_key.0.clone();
    let new = "BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU=";
    config.devices.get_mut("client").unwrap().public_key =
        scupper_core::config::PublicKey(new.into());
    f.kernel.calls.borrow_mut().clear();
    publish(&config);
    assert!(f.run(None).succeeded());
    assert!(!f.kernel.ns.borrow()["wg0"].peers.contains_key(&old));
    assert!(f.kernel.ns.borrow()["wg0"].peers.contains_key(new));
    assert!(
        f.kernel.ns.borrow()["wg0"]
            .peers
            .contains_key(&other.public_key.0)
    );
    assert!(
        !f.kernel
            .calls
            .borrow()
            .iter()
            .any(|call| call == &format!("netns Wg set wg0 peer {} remove", other.public_key.0))
    );
    let mut gateway = config.gateways[&GatewayId("gw1".into())].clone();
    gateway.endpoint = "198.51.100.3:51820".into();
    config.gateways.insert(GatewayId("gw2".into()), gateway);
    config.devices.get_mut("client").unwrap().gateways = vec![GatewayId("gw2".into())];
    // M2 release validation permits one gateway only; exercise the shared
    // production link configurator with an internal multi-gateway fixture.
    let site = scupper_core::config::testing_build(config).unwrap();
    scupper_sys::boot::testing::configure_clients(
        BootDeps {
            system: &f.kernel,
            namespace: &f.kernel,
            state_root: &f.root.path,
            config_root: &f.root.path,
            run_root: &run,
            hook: None,
            secret_owner: rustix::process::geteuid().as_raw(),
        },
        site,
    )
    .unwrap();
    assert!(!f.kernel.ns.borrow()["wg0"].peers.contains_key(new));
    assert!(
        f.kernel.ns.borrow()["wg0"]
            .peers
            .contains_key(&other.public_key.0)
    );
}

#[test]
fn broken_notify_still_records_daemon_started_once() {
    let f = Fixture::new();
    assert!(f.run(None).succeeded());
    let run = f.root.path.join("run");
    let count = scupper_sys::daemon::testing::started_with_broken_notify(BootDeps {
        system: &f.kernel,
        namespace: &f.kernel,
        state_root: &f.root.path,
        config_root: &f.root.path,
        run_root: &run,
        hook: None,
        secret_owner: rustix::process::geteuid().as_raw(),
    })
    .unwrap();
    assert_eq!(count, 1);
}

#[test]
fn failed_apply_reports_reclose_and_rollback_failures() {
    use scupper_sys::{daemon::admin, events::EventLog};
    for fail_reclose in [false, true] {
        let f = Fixture::new();
        assert!(f.run(None).succeeded());
        let inject = |point| {
            if point == BootPoint::After(BootStep::Record) {
                *f.kernel.failure.borrow_mut() = Some(if fail_reclose {
                    (
                        Program::Sysctl,
                        "net.ipv4.ip_forward=0".into(),
                        "stuck gate".into(),
                    )
                } else {
                    (
                        Program::Wg,
                        "pubkey".into(),
                        "rollback inputs failed".into(),
                    )
                });
                return Err("target record failed".into());
            }
            Ok(())
        };
        let run = f.root.path.join("run");
        let deps = BootDeps {
            system: &f.kernel,
            namespace: &f.kernel,
            state_root: &f.root.path,
            config_root: &f.root.path,
            run_root: &run,
            hook: Some(&inject),
            secret_owner: rustix::process::geteuid().as_raw(),
        };
        let log = EventLog::memory_only(scupper_core::config::GatewayId("gw1".into()), || {
            scupper_proto::UnixSeconds(1000)
        })
        .unwrap();
        let error = admin::apply(&deps, &log.handle, Some(1), false, 0).unwrap_err();
        assert_eq!(error.code, scupper_proto::ApiErrorCode::RollbackFailed);
        let rollback = &error.observation.as_ref().unwrap()["rollback"];
        assert_eq!(rollback["verified"], false);
        assert_eq!(rollback["reclosed"], !fail_reclose);
        assert_eq!(rollback["closed"], !fail_reclose);
        assert!(error.to_string().contains(if fail_reclose {
            "closure unverified"
        } else {
            "rollback failed: closed"
        }));
    }
}

#[test]
fn post_mutation_gate_and_state_failures_report_recovery_outcome() {
    use scupper_sys::{daemon::admin, events::EventLog};
    for state_write in [false, true] {
        let f = Fixture::new();
        assert!(f.run(None).succeeded());
        if state_write {
            *f.kernel.state_failure_on_close.borrow_mut() = Some(f.root.path.join("state.json"));
        } else {
            *f.kernel.failure.borrow_mut() = Some((
                Program::Sysctl,
                "net.ipv4.ip_forward=0".into(),
                "stuck gate".into(),
            ));
        }
        let run = f.root.path.join("run");
        let log = EventLog::memory_only(scupper_core::config::GatewayId("gw1".into()), || {
            scupper_proto::UnixSeconds(1000)
        })
        .unwrap();
        let error = admin::apply(
            &BootDeps {
                system: &f.kernel,
                namespace: &f.kernel,
                state_root: &f.root.path,
                config_root: &f.root.path,
                run_root: &run,
                hook: None,
                secret_owner: rustix::process::geteuid().as_raw(),
            },
            &log.handle,
            Some(1),
            false,
            0,
        )
        .unwrap_err();
        assert_eq!(error.code, scupper_proto::ApiErrorCode::RollbackFailed);
        let recovery = &error.observation.unwrap()["rollback"];
        assert_eq!(recovery["verified"], false);
        assert_eq!(recovery["closed"], state_write);
        assert_eq!(recovery["reclosed"], state_write);
        assert_eq!(recovery["durable"], !state_write);
        assert_eq!(
            f.kernel.values.borrow()["net.ipv6.conf.all.forwarding"],
            "0"
        );
    }
}

#[test]
fn hardening_write_failure_does_not_hide_verified_closed_gates() {
    use scupper_core::{config::GatewayId, planner::Step};
    use scupper_sys::reconcile::{Config, Kernel as _, RealKernel};
    let f = Fixture::new();
    assert!(f.run(None).succeeded());
    let site = support::site("ubuntu-24.04");
    let held = std::sync::Arc::new(testing::handle().unwrap());
    let config = Config {
        site: site.clone(),
        gateway: GatewayId("gw1".into()),
        stamp: f.root.stamp,
        fingerprint: [7; 32],
        run_root: f.root.path.join("run"),
        lock_wait: Duration::ZERO,
    };
    let adapter = RealKernel::new(
        BootDeps {
            system: &f.kernel,
            namespace: &f.kernel,
            state_root: &f.root.path,
            config_root: &f.root.path,
            run_root: &config.run_root,
            hook: None,
            secret_owner: rustix::process::geteuid().as_raw(),
        },
        held.clone(),
        &config,
        support::health(&site, &held),
        f.kernel.path().to_path_buf(),
        None,
    )
    .unwrap();
    *f.kernel.failure.borrow_mut() = Some((
        Program::Sysctl,
        "net.ipv4.conf.wg0.accept_redirects=0".into(),
        "link changed".into(),
    ));
    adapter.execute(&Step::ForwardingOff).unwrap();
    for key in [
        "net.ipv4.ip_forward",
        "net.ipv6.conf.all.forwarding",
        "net.ipv4.conf.default.forwarding",
        "net.ipv6.conf.default.forwarding",
    ] {
        assert_eq!(f.kernel.values.borrow()[key], "0");
    }
    let health = support::health(&site, &held);
    let forwarding = scupper_sys::collect::forwarding(
        &f.kernel,
        &held,
        &health,
        &scupper_sys::state::State::default(),
    )
    .unwrap();
    assert!(
        forwarding
            .hardening
            .iter()
            .any(|key| key == "net.ipv4.conf.wg0.accept_redirects")
    );
}

#[test]
fn corrupt_apply_target_preserves_attachment_and_error_kind() {
    use scupper_sys::{
        daemon::testing::dispatch_apply,
        store::{MetaInput, VersionStore},
    };
    for directory_instead in [false, true] {
        let f = Fixture::new();
        assert!(f.run(None).succeeded());
        let run = f.root.path.join("run");
        let guard = WriterLock::acquire(&run).unwrap();
        VersionStore::open(&f.root.path, Some(&guard))
            .unwrap()
            .commit(
                &guard,
                Some(1),
                &support::site_text("ubuntu-24.04"),
                MetaInput {
                    actor: "test".into(),
                    at: 1000,
                    reason: "target".into(),
                },
            )
            .unwrap();
        drop(guard);
        let target = f.root.path.join("config/versions/000002.toml");
        if directory_instead {
            fs::remove_file(&target).unwrap();
            fs::create_dir(&target).unwrap();
        } else {
            fs::write(&target, "corrupt target").unwrap();
        }
        let (response, before, after, retained, _) = dispatch_apply(
            BootDeps {
                system: &f.kernel,
                namespace: &f.kernel,
                state_root: &f.root.path,
                config_root: &f.root.path,
                run_root: &run,
                hook: None,
                secret_owner: rustix::process::geteuid().as_raw(),
            },
            2,
        )
        .unwrap();
        assert_eq!(
            response.result.unwrap_err().code,
            if directory_instead {
                scupper_proto::ApiErrorCode::PersistenceUnavailable
            } else {
                scupper_proto::ApiErrorCode::Internal
            }
        );
        assert_eq!(before, after);
        assert!(retained);
    }
}

#[test]
fn crash_checkpoints_persist_exact_numeric_and_host_link_evidence() {
    let root = Root::new("ubuntu-24.04", &testing::handle().unwrap());
    let path = root.path.join("boot-reached");
    for (point, expected) in [
        (BootPoint::After(BootStep::Lock), "reached 0\n"),
        (BootPoint::After(BootStep::Record), "reached 7\n"),
        (
            BootPoint::LinkAdded(scupper_core::rules::IfName::new("wg0").unwrap()),
            "reached link-add-wg0\n",
        ),
    ] {
        scupper_sys::boot::testing_checkpoint(&path, &point).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), expected);
    }
}

#[test]
fn boot_never_adds_source_policy_rules_or_nonbaseline_rules() {
    for disconnected in [false, true] {
        let f = Fixture::new();
        if disconnected {
            f.state(|s| s.selection = Selection::Disconnected);
        }
        assert!(f.run(None).succeeded());
        let mut families = [false; 2];
        for call in f.kernel.calls.borrow().iter() {
            let words: Vec<_> = call.split_whitespace().collect();
            if words.contains(&"Ip") && words.contains(&"rule") {
                match words.as_slice() {
                    ["netns", "Ip", "-j", "-4", "rule", "show"] => families[0] = true,
                    ["netns", "Ip", "-j", "-6", "rule", "show"] => families[1] = true,
                    _ => panic!("boot must only observe baseline rules: {call}"),
                }
            }
        }
        assert_eq!(families, [true, true], "both rule inventories must run");
    }
}

#[test]
#[allow(clippy::too_many_lines)] // Keep the complete live transaction and its safety assertions together.
fn missing_secret_commit_and_apply_refuse_before_kernel_or_state_changes() {
    use scupper_core::config::{GatewayId, SecretKind, SecretName, parse_site};
    use scupper_proto::{ApiErrorCode, Reason, UnixSeconds};
    use scupper_sys::{
        daemon::admin,
        events::EventLog,
        store::{MetaInput, VersionStore},
    };
    for field in ["private", "psk", "identity", "sink", "heartbeat"] {
        let f = Fixture::new();
        assert!(f.run(None).succeeded());
        let run_root = f.root.path.join("run");
        let deps = BootDeps {
            system: &f.kernel,
            namespace: &f.kernel,
            state_root: &f.root.path,
            config_root: &f.root.path,
            run_root: &run_root,
            hook: None,
            secret_owner: rustix::process::geteuid().as_raw(),
        };
        let log = EventLog::memory_only(GatewayId("gw1".into()), || UnixSeconds(1000)).unwrap();
        let mut site = parse_site(&support::site_text("ubuntu-24.04")).unwrap();
        let reference = SecretName::new(
            if ["sink", "heartbeat"].contains(&field) {
                SecretKind::Url
            } else {
                SecretKind::Wg
            },
            "missing-ref",
        )
        .unwrap();
        match field {
            "private" => {
                site.gateways
                    .get_mut(&GatewayId("gw1".into()))
                    .unwrap()
                    .exits[0]
                    .private_key_ref = reference;
            }
            "psk" => {
                site.gateways
                    .get_mut(&GatewayId("gw1".into()))
                    .unwrap()
                    .exits[0]
                    .preshared_key_ref = Some(reference);
            }
            "identity" => site.identities.values_mut().next().unwrap().private_key_ref = reference,
            "sink" => {
                site.alerts.sinks.insert(
                    "test".into(),
                    scupper_core::config::AlertSink::Ntfy {
                        url_ref: reference,
                        min_severity: scupper_core::config::Severity::Critical,
                    },
                );
            }
            "heartbeat" => {
                site.heartbeat = Some(scupper_core::config::HeartbeatSettings {
                    kind: scupper_core::config::HeartbeatKind::Healthchecks,
                    url_ref: reference,
                    interval: scupper_core::config::DurationStr("60s".into()),
                    report: scupper_core::config::HeartbeatReport::StatusCode,
                });
            }
            _ => unreachable!(),
        }
        let text = toml::to_string(&site).unwrap();
        let error =
            admin::commit(&deps, &log.handle, Some(1), &text, Reason::Operator, 0).unwrap_err();
        assert_eq!(error.code, ApiErrorCode::InvalidRequest);
        assert!(error.to_string().contains("missing-ref"), "{error}");
        let store = VersionStore::read_only(&f.root.path, &f.root.path);
        assert_eq!(store.head().unwrap(), Some(1));
        // A stored version can lose a file after publication, or come from older history.
        let writer = WriterLock::acquire(&run_root).unwrap();
        let store =
            VersionStore::open_with_mirror_root(&f.root.path, &f.root.path, Some(&writer)).unwrap();
        store
            .commit(
                &writer,
                Some(1),
                &text,
                MetaInput {
                    actor: "test".into(),
                    at: 1000,
                    reason: "missing key fixture".into(),
                },
            )
            .unwrap();
        drop(writer);
        let before = fs::read(f.root.path.join("state.json")).unwrap();
        let calls = f.kernel.calls.borrow().clone();
        for dry_run in [true, false] {
            if ["sink", "heartbeat"].contains(&field) {
                let result = admin::apply(&deps, &log.handle, None, dry_run, 0).unwrap();
                let scupper_proto::OpResult::Apply { warnings, .. } = result else {
                    panic!("expected apply")
                };
                assert!(
                    warnings
                        .iter()
                        .any(|warning| warning.contains("missing-ref"))
                );
            } else {
                let error = admin::apply(&deps, &log.handle, None, dry_run, 0).unwrap_err();
                assert_eq!(error.code, ApiErrorCode::InvalidRequest);
                assert!(error.to_string().contains("missing-ref"), "{error}");
            }
            if !dry_run && ["sink", "heartbeat"].contains(&field) {
                continue;
            }
            assert_eq!(fs::read(f.root.path.join("state.json")).unwrap(), before);
            assert_eq!(*f.kernel.calls.borrow(), calls);
        }
        if ["sink", "heartbeat"].contains(&field) {
            continue;
        }
        assert_eq!(fs::read(f.root.path.join("state.json")).unwrap(), before);
        assert_eq!(*f.kernel.calls.borrow(), calls);
        assert_eq!(f.kernel.values.borrow()["net.ipv4.ip_forward"], "1");
    }
}

#[test]
fn socket_reset_compares_current_intent_and_preserves_concurrent_disconnect() {
    use scupper_core::config::ExitId;
    use scupper_sys::daemon::testing::dispatch_reset_selection;
    for current in [
        Selection::Disconnected,
        Selection::Auto,
        Selection::Pin(ExitId("other".into())),
        Selection::Prefer(ExitId("other".into())),
        Selection::Pin(ExitId("ch1".into())),
        Selection::Prefer(ExitId("ch1".into())),
    ] {
        let f = Fixture::new();
        f.state(|s| s.selection = Selection::Pin(ExitId("ch1".into())));
        assert!(f.run(None).succeeded());
        let run = f.root.path.join("run");
        let expected = match &current {
            Selection::Pin(id) | Selection::Prefer(id) if id.as_str() == "ch1" => Selection::Auto,
            _ => current.clone(),
        };
        let before = std::cell::RefCell::new(Vec::new());
        let response = dispatch_reset_selection(
            BootDeps {
                system: &f.kernel,
                namespace: &f.kernel,
                state_root: &f.root.path,
                config_root: &f.root.path,
                run_root: &run,
                hook: None,
                secret_owner: rustix::process::geteuid().as_raw(),
            },
            (&ExitId("ch1".into())).into(),
            || {
                f.state(|s| s.selection = current.clone());
                *before.borrow_mut() = fs::read(f.root.path.join("state.json")).unwrap();
            },
        )
        .unwrap();
        assert!(matches!(
            response.result.unwrap(),
            scupper_proto::OpResult::ResetSelection {}
        ));
        let scupper_sys::state::StateRead::Present(saved) =
            StateFile::open(&f.root.path, None).unwrap().read().unwrap()
        else {
            panic!("missing state")
        };
        assert_eq!(saved.selection, expected);
        if expected == current {
            assert_eq!(
                fs::read(f.root.path.join("state.json")).unwrap(),
                *before.borrow()
            );
        }
    }
}

#[test]
fn apply_input_io_and_corruption_keep_their_error_kinds_in_both_modes() {
    use scupper_sys::{daemon::admin, events::EventLog};
    for failure in ["state", "render", "gateway", "render-mismatch"] {
        let f = Fixture::new();
        assert!(f.run(None).succeeded());
        fs::create_dir_all(f.root.path.join("rendered")).unwrap();
        match failure {
            "state" => {
                fs::remove_file(f.root.path.join("state.json")).unwrap();
                fs::create_dir(f.root.path.join("state.json")).unwrap();
            }
            "render" => {
                fs::create_dir(f.root.path.join("rendered/000001.nft")).unwrap();
            }
            "gateway" => {
                fs::remove_file(f.root.path.join("gateway-id")).unwrap();
            }
            "render-mismatch" => {
                fs::write(f.root.path.join("rendered/000001.nft"), "invalid render").unwrap();
            }
            _ => unreachable!(),
        }
        let run = f.root.path.join("run");
        let deps = BootDeps {
            system: &f.kernel,
            namespace: &f.kernel,
            state_root: &f.root.path,
            config_root: &f.root.path,
            run_root: &run,
            hook: None,
            secret_owner: rustix::process::geteuid().as_raw(),
        };
        let log = EventLog::memory_only(scupper_core::config::GatewayId("gw1".into()), || {
            scupper_proto::UnixSeconds(1000)
        })
        .unwrap();
        let calls = f.kernel.calls.borrow().clone();
        for dry_run in [true, false] {
            let error = admin::apply(&deps, &log.handle, None, dry_run, 0).unwrap_err();
            assert_eq!(
                error.code,
                if ["state", "render"].contains(&failure) {
                    scupper_proto::ApiErrorCode::PersistenceUnavailable
                } else {
                    scupper_proto::ApiErrorCode::Internal
                }
            );
            assert_eq!(*f.kernel.calls.borrow(), calls);
            assert_eq!(f.kernel.values.borrow()["net.ipv4.ip_forward"], "1");
        }
    }
}

#[test]
fn host_link_inspection_keeps_status_and_sanitized_bounded_stderr() {
    for (program, needle) in [
        (Program::Wg, "show wg0 peers"),
        (Program::Ip, "-j addr show"),
    ] {
        let f = Fixture::new();
        f.kernel
            .host
            .borrow_mut()
            .insert("wg0".into(), Link::new("wireguard"));
        *f.kernel.failure.borrow_mut() = Some((
            program,
            needle.into(),
            format!("inspection\nfailed\t{}", "x".repeat(3000)),
        ));
        let report = f.run(None);
        assert!(!report.succeeded(), "{report:?}");
        let error = report.steps.last().unwrap().error.as_ref().unwrap();
        assert!(error.starts_with("cannot inspect host link:"), "{error}");
        assert!(error.contains("status Some(2)"), "{error}");
        assert!(error.contains("inspection failed "), "{error}");
        assert!(!error.chars().any(char::is_control));
        assert!(error.len() < 2200);
    }
}

#[test]
fn modules_precede_sysctls_on_a_cold_host_and_failures_name_the_module() {
    let f = Fixture::new();
    assert!(!f.kernel.conntrack_loaded.get());
    let report = f.run(None);
    assert!(report.succeeded(), "{report:?}");
    let calls = f.kernel.calls.borrow();
    assert_eq!(
        calls
            .iter()
            .filter(|call| call.contains("Modprobe"))
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["host Modprobe nf_conntrack", "host Modprobe wireguard"]
    );
    let first_sysctl = calls.iter().position(|c| c.contains("Sysctl")).unwrap();
    for module in scupper_core::install::BOOT_MODULES {
        let position = calls
            .iter()
            .position(|c| c == &format!("host Modprobe {module}"))
            .unwrap();
        assert!(position < first_sysctl);
    }
    drop(calls);
    for module in scupper_core::install::BOOT_MODULES {
        for diagnostic in ["module unavailable", "missing-binary"] {
            let f = Fixture::new();
            *f.kernel.failure.borrow_mut() =
                Some((Program::Modprobe, (*module).into(), diagnostic.into()));
            let report = f.run(None);
            assert!(!report.succeeded());
            let last = report.steps.last().unwrap();
            assert_eq!(last.step, BootStep::Modules);
            assert!(last.error.as_ref().unwrap().contains(module));
            assert!(!f.kernel.exists.get());
            assert!(!f.kernel.calls.borrow().iter().any(|c| c.contains("Sysctl")));
            let saved: BootReport =
                serde_json::from_slice(&fs::read(f.root.path.join("run/boot.json")).unwrap())
                    .unwrap();
            assert_eq!(saved.steps, report.steps);
        }
    }
}

#[test]
fn fresh_boot_loads_only_missing_modules() {
    for missing in [None, Some("nf_conntrack"), Some("wireguard")] {
        let f = Fixture::new();
        f.kernel
            .conntrack_loaded
            .set(missing != Some("nf_conntrack"));
        f.kernel.wireguard_loaded.set(missing != Some("wireguard"));
        let report = f.run(None);
        assert!(report.succeeded() && !report.adopted, "{report:?}");
        assert_eq!(report.steps[1].step, BootStep::Modules);
        assert_eq!(report.steps.len(), 9);
        let calls = f.kernel.calls.borrow();
        let loads = calls
            .iter()
            .filter(|call| call.contains("Modprobe"))
            .collect::<Vec<_>>();
        let expected = missing
            .map(|module| format!("host Modprobe {module}"))
            .into_iter()
            .collect::<Vec<_>>();
        assert_eq!(loads, expected.iter().collect::<Vec<_>>());
        if let Some(load) = loads.first() {
            let load_index = calls.iter().position(|call| call == *load).unwrap();
            let sysctl_index = calls
                .iter()
                .position(|call| call.contains("Sysctl"))
                .unwrap();
            assert!(load_index < sysctl_index);
        }
    }
}

#[test]
fn adoption_with_a_missing_module_fails_without_any_commands() {
    for module in scupper_core::install::BOOT_MODULES {
        let f = Fixture::new();
        assert!(f.run(None).succeeded());
        if *module == "nf_conntrack" {
            f.kernel.conntrack_loaded.set(false);
        } else {
            f.kernel.wireguard_loaded.set(false);
        }
        f.kernel.calls.borrow_mut().clear();
        let report = f.run(None);
        assert!(!report.succeeded() && !report.adopted, "{report:?}");
        assert_eq!(report.steps.len(), 2);
        let last = report.steps.last().unwrap();
        assert_eq!(last.step, BootStep::Modules);
        let error = last.error.as_ref().unwrap();
        assert!(
            error.contains(module) && error.contains("existing namespace"),
            "{error}"
        );
        assert!(f.kernel.calls.borrow().is_empty());
        let saved: BootReport =
            serde_json::from_slice(&fs::read(f.root.path.join("run/boot.json")).unwrap()).unwrap();
        assert_eq!(saved.steps, report.steps);
    }
}

#[test]
fn unreadable_module_inventory_fails_without_commands() {
    for existing in [false, true] {
        let f = Fixture::new();
        if existing {
            assert!(f.run(None).succeeded());
            f.kernel.calls.borrow_mut().clear();
        }
        *f.kernel.script.file_error.borrow_mut() = true;
        let report = f.run(None);
        assert!(!report.succeeded(), "{report:?}");
        let last = report.steps.last().unwrap();
        assert_eq!(last.step, BootStep::Modules);
        assert!(last.error.as_ref().unwrap().contains("nf_conntrack"));
        assert!(f.kernel.calls.borrow().is_empty());
    }
}

#[test]
fn upgraded_daemon_restarts_adopt_legacy_boot_file_without_closing_or_rebuilding() {
    use scupper_core::planner::Step;
    use scupper_sys::reconcile::Escalation;

    let fixture = Fixture::new();
    let running = fixture.run(None);
    assert!(running.succeeded());
    // Exact pre-checkpoint schema used by 4442253, beside its real legacy boot report.
    fs::write(
        fixture.root.path.join("state.json"),
        r#"{"schema":1,"applied_version":1,"selection":"Auto","quarantine":null}"#,
    )
    .unwrap();
    fs::remove_file(fixture.root.path.join("repair-state.json")).unwrap();
    // Model the real kernel's propagation of all.forwarding=1 to per-link gates;
    // this fake stores each sysctl independently. Handshakes are already fresh.
    for name in fixture.kernel.ns.borrow().keys() {
        for family in ["ipv4", "ipv6"] {
            fixture
                .kernel
                .values
                .borrow_mut()
                .insert(format!("net.{family}.conf.{name}.forwarding"), "1".into());
        }
    }
    let mut legacy: BootReport =
        serde_json::from_str(include_str!("fixtures/boot-pre-modules.json")).unwrap();
    assert_eq!(legacy.owned_links, running.owned_links);
    // The only fixture substitution is the identity of this run's held namespace.
    legacy.netns = running.netns;
    let bytes = serde_json::to_vec(&legacy).unwrap();
    let run_root = fixture.root.path.join("run");
    fs::write(run_root.join("boot.json"), &bytes).unwrap();

    for _ in 0..2 {
        fixture.kernel.calls.borrow_mut().clear();
        let tick = scupper_sys::daemon::testing::restart_tick(BootDeps {
            system: &fixture.kernel,
            namespace: &fixture.kernel,
            state_root: &fixture.root.path,
            config_root: &fixture.root.path,
            run_root: &run_root,
            hook: None,
            secret_owner: rustix::process::geteuid().as_raw(),
        })
        .unwrap();
        assert!(tick.complete, "{tick:?}");
        assert!(!tick.steps.contains(&Step::ForwardingOff), "{tick:?}");
        assert!(!tick.escalations.contains(&Escalation::RebuildRequired));
        assert!(!tick.escalations.contains(&Escalation::ReinitializeRequired));
        let calls = fixture.kernel.calls.borrow();
        assert!(
            calls
                .iter()
                .all(|call| !["Modprobe", "Sysctl -w", "Ip netns add", "Nft -f"]
                    .iter()
                    .any(|write| call.contains(write))),
            "{calls:?}"
        );
        for key in ["net.ipv4.ip_forward", "net.ipv6.conf.all.forwarding"] {
            assert_eq!(fixture.kernel.values.borrow()[key], "1");
        }
        assert_eq!(fs::read(run_root.join("boot.json")).unwrap(), bytes);
        assert!(fixture.root.path.join("repair-state.json").is_file());
        assert!(
            StateFile::open(&fixture.root.path, None)
                .unwrap()
                .repair_state()
                .latch()
                .is_none()
        );
    }
}

#[test]
fn legacy_boot_migrates_once_without_changing_forwarding_or_quarantine() {
    for quarantined in [false, true] {
        let f = Fixture::new();
        assert!(f.run(None).succeeded());
        if quarantined {
            f.state(|s| {
                s.quarantine = Some(scupper_sys::state::Quarantine {
                    reason: "legacy safety budget".into(),
                    object: "safety:ruleset".into(),
                    since_unix: 1000,
                    uncertain: false,
                });
            });
        }
        let state = fs::read(f.root.path.join("state.json")).unwrap();
        fs::remove_file(f.root.path.join("repair-state.json")).unwrap();
        for _ in 0..2 {
            let report = f.run(None);
            assert!(report.succeeded(), "{report:?}");
            assert_eq!(
                f.kernel.values.borrow()["net.ipv4.ip_forward"],
                if quarantined { "0" } else { "1" }
            );
            assert_eq!(fs::read(f.root.path.join("state.json")).unwrap(), state);
            if quarantined {
                assert_eq!(f.check().verdict.exit_code(), 4);
            }
        }
        let events = scupper_sys::events::Tail::default()
            .read(&f.root.path, 0, u64::MAX)
            .unwrap();
        assert_eq!(events.iter().filter(|record| matches!(record,
            scupper_sys::events::TailRecord::Event(event) if matches!(event.kind, scupper_proto::EventKind::RepairCheckpointCreated {})
        )).count(), 1);
    }
}

#[test]
fn migration_audit_failure_does_not_abort_daemon_initialization() {
    use scupper_sys::events::EventLog;
    let f = Fixture::new();
    assert!(f.run(None).succeeded());
    fs::remove_file(f.root.path.join("repair-state.json")).unwrap();
    let log = EventLog::memory_only(scupper_core::config::GatewayId("gw1".into()), || {
        scupper_proto::UnixSeconds(1000)
    })
    .unwrap();
    drop(log.log);
    assert!(
        log.handle
            .emit(
                scupper_proto::EventKind::RepairCheckpointCreated {},
                scupper_proto::Actor::Daemon,
                None
            )
            .is_err()
    );
    let tick = scupper_sys::daemon::testing::restart_tick_with_log(
        BootDeps {
            system: &f.kernel,
            namespace: &f.kernel,
            state_root: &f.root.path,
            config_root: &f.root.path,
            run_root: &f.root.path.join("run"),
            hook: None,
            secret_owner: rustix::process::geteuid().as_raw(),
        },
        log.handle,
    )
    .unwrap();
    assert!(tick.complete, "{tick:?}");
    assert!(f.root.path.join("repair-state.json").is_file());
}

#[test]
fn daemon_rebuild_migration_reuses_its_locked_audit_writer() {
    for running in [false, true] {
        let f = Fixture::new();
        assert!(f.run(None).succeeded());
        let start = std::time::Instant::now();
        scupper_sys::daemon::testing::rebuild_legacy(
            BootDeps {
                system: &f.kernel,
                namespace: &f.kernel,
                state_root: &f.root.path,
                config_root: &f.root.path,
                run_root: &f.root.path.join("run"),
                hook: None,
                secret_owner: rustix::process::geteuid().as_raw(),
            },
            running,
        )
        .unwrap();
        // A second EventLog::open waits five seconds for this process's writer.
        assert!(
            start.elapsed() < Duration::from_secs(3),
            "{running}: {:?}",
            start.elapsed()
        );
        let events = scupper_sys::events::read_since(&f.root.path, 0, None)
            .collect::<std::io::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(
                    event.kind,
                    scupper_proto::EventKind::RepairCheckpointCreated {}
                ) && event.actor == scupper_proto::Actor::Daemon)
                .count(),
            1
        );
    }
}

#[path = "fixtures/previous_state.rs"]
mod previous_state;

#[test]
fn previous_release_reads_written_boot_report() {
    let f = Fixture::new();
    let report = f.run(None);
    assert!(report.succeeded());
    let bytes = fs::read(f.root.path.join("run/boot.json")).unwrap();
    let old: previous_state::BootReport = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(old.steps.len(), report.steps.len());
    assert_eq!(old.applied_version, report.applied_version);
    assert_eq!(old.owned_links, report.owned_links);
}
