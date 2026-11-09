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

fn derived_key(input: &[u8]) -> String {
    if input.starts_with(b"A") {
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into()
    } else {
        "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=".into()
    }
}

#[derive(Clone)]
struct Link {
    kind: String,
    up: bool,
    addresses: Vec<String>,
    peers: BTreeMap<String, (String, String)>,
    mtu: u32,
    public_key: String,
    port: u16,
    keepalive: u16,
    hooks: bool,
    xdp: bool,
}
impl Link {
    fn new(kind: &str) -> Self {
        Self {
            kind: kind.into(),
            up: false,
            addresses: vec![],
            peers: BTreeMap::new(),
            mtu: 1420,
            public_key: "(none)".into(),
            port: 0,
            keepalive: 0,
            hooks: false,
            xdp: false,
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
    gates_closed: Cell<bool>,
    began_live: Cell<bool>,
    failure: RefCell<Option<(Program, String, String)>>,
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
            gates_closed: Cell::new(false),
            began_live: Cell::new(false),
            failure: RefCell::default(),
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
        if ["net.ipv4.ip_forward", "net.ipv6.conf.all.forwarding"]
            .iter()
            .all(|k| values.get(*k).is_some_and(|v| v == "0"))
        {
            self.gates_closed.set(true);
        }
        // A live namespace remains untouched during read-only adoption checks.
        // A fresh lo-only namespace may inherit forwarding until its first write.
        if !self.gates_closed.get() && (self.began_live.get() || self.ns.borrow().len() == 1) {
            return;
        }
        for key in ["net.ipv4.ip_forward", "net.ipv6.conf.all.forwarding"] {
            assert!(
                values.get(key).is_none_or(|v| v != "1") || self.verified_this_run.get(),
                "forwarding before same-run verification"
            );
        }
    }
    fn json_links(links: &BTreeMap<String, Link>) -> String {
        serde_json::Value::Array(links.iter().enumerate().map(|(i, (name, link))| {
            let mut value = serde_json::json!({"ifindex":i+1,"ifname":name,"mtu":link.mtu,"flags":if link.up { vec!["UP"] } else {vec![]},"linkinfo":{"info_kind":link.kind}});
            if link.xdp { value["xdp"] = serde_json::json!({"attached": "generic"}); }
            value
        }).collect()).to_string()
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
        if let Some((program, needle, stderr)) = &*self.failure.borrow()
            && *program == p
            && args.join(" ").contains(needle)
        {
            if stderr == "missing-binary" {
                return Err(ExecError::spawn("No such file or directory"));
            }
            return Ok(ExecOutput {
                status: Some(2),
                stdout: String::new(),
                stderr: stderr.clone(),
            });
        }
        let mut stdout = String::new();
        let map = if ns { &self.ns } else { &self.host };
        match p {
            Program::Ip if a(0) == "netns" => {
                self.exists.set(true);
                self.values
                    .borrow_mut()
                    .insert("net.ipv4.ip_forward".into(), "1".into());
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
                    let link = links.get_mut(name).unwrap();
                    if let Some(i) = args.iter().position(|a| a == "mtu") {
                        link.mtu = a(i + 1).parse().unwrap();
                    }
                    if a(4) == "xdp" {
                        link.xdp = false;
                    } else if args.last().unwrap() == "up" {
                        link.up = true;
                    } else if args.last().unwrap() == "down" {
                        link.up = false;
                    }
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
                if let Some(i) = args.iter().position(|word| word == "dev") {
                    assert!(
                        self.ns.borrow().get(a(i + 1)).unwrap().up,
                        "route via a down link"
                    );
                }
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
                        link.public_key = derived_key(input.unwrap());
                    }
                    "listen-port" => link.port = a(3).parse().unwrap(),
                    "peer" if a(4) == "remove" => {
                        link.peers.remove(a(3));
                    }
                    "peer" => {
                        let allowed = args.iter().position(|a| a == "allowed-ips").unwrap();
                        let endpoint = args
                            .iter()
                            .position(|a| a == "endpoint")
                            .map_or("(none)", |i| a(i + 1));
                        link.keepalive = args
                            .iter()
                            .position(|a| a == "persistent-keepalive")
                            .map_or(0, |i| a(i + 1).parse().unwrap());
                        link.peers
                            .insert(a(3).into(), (a(allowed + 1).into(), endpoint.into()));
                    }
                    _ => panic!("unexpected wg writer"),
                }
            }
            Program::Conntrack => {
                assert!(ns && self.verified_this_run.get());
            }
            Program::Tc if a(0) == "-j" && a(1) == "qdisc" => {
                if map.borrow().get(a(4)).is_some_and(|l| l.hooks) {
                    stdout = r#"[{"kind":"clsact","handle":"ffff:","parent":"ffff:fff1"}]"#.into();
                } else {
                    return self.script.run_in(target, p, args, Duration::from_secs(3));
                }
            }
            Program::Tc if a(0) == "qdisc" => {
                map.borrow_mut().get_mut(a(3)).unwrap().hooks = false;
            }
            Program::Wg if a(0) == "pubkey" => {
                stdout = derived_key(input.unwrap());
            }
            Program::Wg if a(1) == "interfaces" => {}
            Program::Wg if a(0) == "show" => {
                let links = map.borrow();
                let link = links.get(a(1)).unwrap();
                stdout = match a(2) {
                    "public-key" => link.public_key.clone(),
                    "listen-port" => link.port.to_string(),
                    _ => link
                        .peers
                        .iter()
                        .map(|(key, (allowed, endpoint))| match a(2) {
                            "peers" => format!("{key}\n"),
                            "allowed-ips" => format!("{key}\t{allowed}\n"),
                            "endpoints" => format!("{key}\t{endpoint}\n"),
                            "persistent-keepalive" => format!("{key}\t{}\n", link.keepalive),
                            "latest-handshakes" => format!("{key}\t999\n"),
                            _ => panic!("unexpected wg read"),
                        })
                        .collect(),
                };
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
    assert_eq!(saved["steps"][1]["error"], "no configuration");
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
    assert!(f.run(None).succeeded());
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
