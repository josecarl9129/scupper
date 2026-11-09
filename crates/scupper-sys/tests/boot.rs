//! Boot command traces and FS-9 prefixes use a stateful fake kernel.
#![cfg(feature = "testing")]
#![allow(clippy::unwrap_used, clippy::panic)]
#[path = "support/v2.rs"]
mod support;
use scupper_core::render::{Scope, desired_sysctls};
use scupper_sys::{
    boot::{BootDeps, BootNamespace, BootPoint, BootReport, BootStep, boot},
    lock::WriterLock,
    netns::{NetnsError, NetnsHandle, testing},
    state::{Quarantine, Selection, StateFile},
    system::{ExecError, ExecOutput, ExecTarget, Program, System},
};
use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
    fs,
    os::unix::fs::PermissionsExt,
    time::Duration,
};
use support::{Root, Script};

#[derive(Clone)]
struct Link {
    kind: String,
    up: bool,
    addresses: Vec<String>,
    peers: BTreeMap<String, (String, String)>,
}
impl Link {
    fn new(kind: &str) -> Self {
        Self {
            kind: kind.into(),
            up: false,
            addresses: vec![],
            peers: BTreeMap::new(),
        }
    }
}
struct Kernel {
    exists: Cell<bool>,
    host: RefCell<BTreeMap<String, Link>>,
    ns: RefCell<BTreeMap<String, Link>>,
    values: RefCell<BTreeMap<String, String>>,
    calls: RefCell<Vec<String>>,
    rules: Cell<bool>,
    verified: Cell<bool>,
    verified_this_run: Cell<bool>,
    fail_after: Cell<Option<usize>>,
    script: Script,
    defaults: RefCell<BTreeMap<bool, String>>,
    wrong_readback: Cell<bool>,
    bad_canon: Cell<bool>,
    check_links: Cell<bool>,
}
impl Kernel {
    fn new() -> Self {
        Self {
            exists: Cell::new(false),
            host: RefCell::default(),
            ns: RefCell::new(BTreeMap::from([("lo".into(), Link::new("loopback"))])),
            values: RefCell::default(),
            calls: RefCell::default(),
            rules: Cell::new(false),
            verified: Cell::new(false),
            verified_this_run: Cell::new(false),
            fail_after: Cell::new(None),
            script: Script::new("ubuntu-24.04"),
            defaults: RefCell::default(),
            wrong_readback: Cell::new(false),
            bad_canon: Cell::new(false),
            check_links: Cell::new(true),
        }
    }
    fn closed(&self) {
        if self.check_links.get() {
            assert!(self.ns.borrow().iter().all(|(name, link)| name == "lo"
                || ["wg0", "ex-ch1"].contains(&name.as_str()) && link.kind == "wireguard"));
        }
        let values = self.values.borrow();
        for key in ["net.ipv4.ip_forward", "net.ipv6.conf.all.forwarding"] {
            assert!(
                values.get(key).is_none_or(|v| v != "1") || self.verified.get(),
                "forwarding before same-run verification"
            );
        }
    }
    fn json_links(links: &BTreeMap<String, Link>) -> String {
        serde_json::Value::Array(links.iter().enumerate().map(|(i,(name,link))| serde_json::json!({"ifindex":i+1,"ifname":name,"mtu":1420,"flags":if link.up { vec!["UP"] } else {vec![]},"linkinfo":{"info_kind":link.kind}})).collect()).to_string()
    }
    fn json_addresses(links: &BTreeMap<String, Link>) -> String {
        serde_json::Value::Array(links.iter().enumerate().map(|(i,(name,link))| serde_json::json!({"ifindex":i+1,"ifname":name,"addr_info":link.addresses.iter().map(|a| { let (local,prefix)=a.split_once('/').unwrap(); serde_json::json!({"family":"inet","scope":"global","local":local,"prefixlen":prefix.parse::<u8>().unwrap()}) }).collect::<Vec<_>>() })).collect()).to_string()
    }
    #[allow(clippy::too_many_lines)]
    fn exec(
        &self,
        target: ExecTarget<'_>,
        p: Program,
        args: &[String],
        input: Option<&[u8]>,
    ) -> Result<ExecOutput, ExecError> {
        let ns = matches!(target, ExecTarget::Netns(_));
        let a = |i| args.get(i).map_or("", String::as_str);
        let words = args
            .iter()
            .map(|word| {
                if word.starts_with("/proc/") && word.contains("/fd/") {
                    "<netns-fd>"
                } else if word.contains("scupper-canon-") {
                    "<render>"
                } else if word.starts_with("net:[") {
                    "<identity>"
                } else if word.starts_with('/') && p == Program::Unshare {
                    "<executable>"
                } else {
                    word
                }
            })
            .collect::<Vec<_>>()
            .join(" ");
        self.calls.borrow_mut().push(format!(
            "{} {p:?} {words}{}",
            if ns { "netns" } else { "host" },
            input.map_or(String::new(), |bytes| format!(" stdin={}", bytes.len()))
        ));
        let count = self.calls.borrow().len();
        if self.fail_after.get().is_some_and(|stop| count > stop) {
            return Err(ExecError::spawn("injected kill"));
        }
        let mut stdout = String::new();
        let map = if ns { &self.ns } else { &self.host };
        match p {
            Program::Ip if a(0) == "netns" => {
                self.exists.set(true);
            }
            Program::Ip if args == ["-d", "-j", "link", "show"] => {
                stdout = Self::json_links(&map.borrow());
            }
            Program::Ip if args == ["-j", "addr", "show"] => {
                stdout = Self::json_addresses(&map.borrow());
            }
            Program::Ip if a(0) == "link" && a(1) == "add" => {
                assert!(!ns);
                map.borrow_mut().insert(a(2).into(), Link::new("wireguard"));
            }
            Program::Ip if a(0) == "link" && a(1) == "delete" => {
                assert!(!ns);
                map.borrow_mut().remove(a(3));
            }
            Program::Ip if a(0) == "link" && a(1) == "set" => {
                if a(3) == "netns" {
                    assert!(!ns);
                    assert!(a(4).starts_with("/proc/") && a(4).contains("/fd/"));
                    let link = self.host.borrow_mut().remove(a(2)).unwrap();
                    self.ns.borrow_mut().insert(a(2).into(), link);
                } else {
                    assert!(ns);
                    let mut links = map.borrow_mut();
                    let name = if a(2) == "dev" { a(3) } else { a(2) };
                    links.get_mut(name).unwrap().up = args.last().unwrap() == "up";
                }
            }
            Program::Ip if a(0) == "addr" => {
                assert!(ns);
                let mut links = map.borrow_mut();
                if a(1) == "flush" {
                    links.get_mut(a(3)).unwrap().addresses.clear();
                } else {
                    links.get_mut(a(4)).unwrap().addresses.push(a(2).into());
                }
            }
            Program::Ip if args.iter().any(|a| a == "replace") => {
                assert!(ns);
                self.defaults
                    .borrow_mut()
                    .insert(a(0) == "-6", args.join(" "));
            }
            Program::Sysctl => {
                assert!(ns);
                if a(0) == "-w" {
                    let (k, v) = a(1).split_once('=').unwrap();
                    if v == "1" {
                        assert!(self.verified_this_run.get());
                    }
                    self.values.borrow_mut().insert(k.into(), v.into());
                } else {
                    stdout = self
                        .values
                        .borrow()
                        .get(a(1))
                        .cloned()
                        .unwrap_or_else(|| "0".into());
                    if self.wrong_readback.get() {
                        stdout = "99".into();
                    }
                }
            }
            Program::Nft if input.is_some() => {
                assert!(ns);
                if a(0) == "-f" {
                    self.rules.set(true);
                }
            }
            Program::Nft => {
                assert!(ns);
                stdout = if self.rules.get() {
                    self.script.text("want.json")
                } else {
                    "{\"nftables\":[]}".into()
                };
            }
            Program::Unshare => {
                assert!(!ns);
                stdout = self.script.text("want.json");
                if self.bad_canon.get() {
                    stdout = "{\"nftables\":[]}".into();
                } else if self.rules.get() {
                    self.verified.set(true);
                    self.verified_this_run.set(true);
                }
            }
            Program::Wg if a(0) == "set" => {
                assert!(ns);
                let mut links = map.borrow_mut();
                let link = links.get_mut(a(1)).unwrap();
                match a(2) {
                    "private-key" => {
                        assert_eq!(a(3), "/dev/stdin");
                        assert!(input.is_some());
                    }
                    "listen-port" => {}
                    "peer" if a(4) == "remove" => {
                        link.peers.remove(a(3));
                    }
                    "peer" => {
                        let allowed = args.iter().position(|a| a == "allowed-ips").unwrap();
                        let endpoint = args
                            .iter()
                            .position(|a| a == "endpoint")
                            .map_or("(none)", |i| a(i + 1));
                        link.peers
                            .insert(a(3).into(), (a(allowed + 1).into(), endpoint.into()));
                    }
                    _ => panic!("unexpected wg writer"),
                }
            }
            Program::Wg if a(1) == "interfaces" => {}
            Program::Wg if a(0) == "show" => {
                let links = map.borrow();
                let link = links.get(a(1)).unwrap();
                stdout = link
                    .peers
                    .iter()
                    .map(|(key, (allowed, endpoint))| match a(2) {
                        "peers" => format!("{key}\n"),
                        "allowed-ips" => format!("{key}\t{allowed}\n"),
                        "endpoints" => format!("{key}\t{endpoint}\n"),
                        _ => panic!("unexpected wg read"),
                    })
                    .collect();
            }
            _ => return self.script.run_in(target, p, args, Duration::from_secs(3)),
        }
        self.closed();
        if self.fail_after.get() == Some(count) {
            return Err(ExecError::spawn("injected kill after command"));
        }
        Ok(ExecOutput {
            status: Some(0),
            stdout,
            stderr: String::new(),
        })
    }
}
impl System for Kernel {
    fn run(&self, p: Program, a: &[String], _: Duration) -> Result<ExecOutput, ExecError> {
        self.exec(ExecTarget::Host, p, a, None)
    }
    fn run_in(
        &self,
        t: ExecTarget<'_>,
        p: Program,
        a: &[String],
        _: Duration,
    ) -> Result<ExecOutput, ExecError> {
        self.exec(t, p, a, None)
    }
    fn run_with_stdin(
        &self,
        t: ExecTarget<'_>,
        p: Program,
        a: &[String],
        b: &[u8],
        _: Duration,
    ) -> Result<ExecOutput, ExecError> {
        self.exec(t, p, a, Some(b))
    }
    fn wireguard_socket_dirs(&self) -> Vec<std::path::PathBuf> {
        vec![]
    }
    fn now_unix_secs(&self) -> u64 {
        1000
    }
}
impl BootNamespace for Kernel {
    fn open(&self) -> Result<Option<NetnsHandle>, NetnsError> {
        if self.exists.get() {
            testing::handle().map(Some)
        } else {
            Ok(None)
        }
    }
}
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
    fn state(&self, change: impl FnOnce(&mut scupper_sys::state::State)) {
        let guard = WriterLock::acquire(self.root.path.join("lock")).unwrap();
        StateFile::open(&self.root.path, Some(&guard))
            .unwrap()
            .update(&guard, change)
            .unwrap();
    }
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
    assert_eq!(persisted["steps"].as_array().unwrap().len(), 8);
    assert_eq!(persisted["applied_version"], 1);
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
    assert!(!adopt.contains("Sysctl -w") && !adopt.contains("Nft -f") && !adopt.contains("Wg set"));
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
    assert!(f.kernel.calls.borrow().is_empty());
    let f = Fixture::new();
    f.state(|s| {
        s.quarantine = Some(Quarantine {
            reason: "budget".into(),
            object: "rules".into(),
            since_unix: 1,
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
    assert!(f.kernel.calls.borrow().is_empty());
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
    assert!(f.kernel.calls.borrow().is_empty());
    let f = Fixture::new();
    fs::write(f.root.path.join("rendered/000001.nft"), "flush ruleset\n").unwrap();
    assert!(!f.run(None).succeeded());
    assert!(f.kernel.calls.borrow().is_empty());
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
