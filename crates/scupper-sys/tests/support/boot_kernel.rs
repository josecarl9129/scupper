#![allow(dead_code, clippy::unwrap_used, clippy::panic)]
use super::support::Script;
use scupper_sys::{
    boot::BootNamespace,
    netns::{NetnsError, NetnsHandle, testing},
    system::{ExecError, ExecOutput, ExecTarget, Program, System},
};
use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
    fs,
    time::Duration,
};

fn derived_key(input: &[u8]) -> String {
    if input.starts_with(b"CAgI") {
        "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=".into()
    } else if input.starts_with(b"A") {
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into()
    } else {
        "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=".into()
    }
}

#[derive(Clone)]
pub struct Link {
    pub kind: String,
    pub up: bool,
    pub addresses: Vec<String>,
    pub peers: BTreeMap<String, (String, String)>,
    pub mtu: u32,
    pub public_key: String,
    pub port: u16,
    pub keepalive: u16,
    pub hooks: bool,
    pub xdp: bool,
}
impl Link {
    pub fn new(kind: &str) -> Self {
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
pub struct Kernel {
    pub conntrack_loaded: Cell<bool>,
    pub wireguard_loaded: Cell<bool>,
    pub exists: Cell<bool>,
    pub host: RefCell<BTreeMap<String, Link>>,
    pub ns: RefCell<BTreeMap<String, Link>>,
    pub values: RefCell<BTreeMap<String, String>>,
    pub calls: RefCell<Vec<String>>,
    pub rules: Cell<bool>,
    pub gates_closed: Cell<bool>,
    pub began_live: Cell<bool>,
    pub failure: RefCell<Option<(Program, String, String)>>,
    pub verified_this_run: Cell<bool>,
    pub fail_after: Cell<Option<usize>>,
    pub script: Script,
    pub defaults: RefCell<BTreeMap<bool, String>>,
    pub wrong_readback: Cell<bool>,
    pub state_failure_on_close: RefCell<Option<std::path::PathBuf>>,
    pub bad_canon: Cell<bool>,
    pub check_links: Cell<bool>,
}
impl Kernel {
    pub fn new() -> Self {
        Self {
            conntrack_loaded: Cell::new(false),
            wireguard_loaded: Cell::new(false),
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
            state_failure_on_close: RefCell::new(None),
            bad_canon: Cell::new(false),
            check_links: Cell::new(true),
        }
    }
    pub fn closed(&self) {
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
    pub fn json_links(links: &BTreeMap<String, Link>) -> String {
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
                if !ns {
                    return Err(ExecError::NotFound { program: p });
                }
                return Ok(ExecOutput {
                    status: Some(127),
                    stdout: String::new(),
                    stderr: "No such file or directory".into(),
                });
            }
            return Ok(ExecOutput {
                status: Some(2),
                stdout: String::new(),
                stderr: stderr.clone(),
            });
        }
        let mut stdout = String::new();
        let map = if ns { &self.ns } else { &self.host };
        if p == Program::Sysctl && words.contains("net.netfilter.") && !self.conntrack_loaded.get()
        {
            return Ok(ExecOutput {
                status: Some(1),
                stdout: String::new(),
                stderr: "sysctl path absent before modprobe".into(),
            });
        }
        match p {
            Program::Modprobe => {
                assert!(!ns);
                if a(0) == "nf_conntrack" {
                    self.conntrack_loaded.set(true);
                } else if a(0) == "wireguard" {
                    self.wireguard_loaded.set(true);
                }
            }

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
                let mut addresses: Vec<serde_json::Value> =
                    serde_json::from_str(&Self::json_addresses(&map.borrow())).unwrap();
                if !ns {
                    let uplinks: Vec<serde_json::Value> =
                        serde_json::from_str(&self.script.text("gwhost--4-addr.json")).unwrap();
                    addresses.extend(uplinks.into_iter().filter(|link| link["ifname"] == "eth0"));
                }
                stdout = serde_json::to_string(&addresses).unwrap();
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
            Program::Ip if a(0) == "-j" && a(2) == "route" && a(3) == "show" => {
                let all = a(5) == "all" || a(5) == "local";
                let filename = format!(
                    "scupper-{}-{}.json",
                    a(1),
                    if all { "routes-all" } else { "route" }
                );
                let mut routes: Vec<serde_json::Value> =
                    serde_json::from_str(&self.script.text(&filename)).unwrap();
                // Replacing an exit address also replaces its kernel local route.
                for route in &mut routes {
                    if route["type"] != "local" || route["dev"] != "ex-ch1" {
                        continue;
                    }
                    let links = self.ns.borrow();
                    if let Some(address) = links.get("ex-ch1").and_then(|l| l.addresses.first()) {
                        let host = address.split('/').next().unwrap();
                        route["prefsrc"] = serde_json::json!(host);
                        route["dst"] = serde_json::json!(host);
                    }
                }
                if let Some(route) = self.defaults.borrow().get(&(a(1) == "-6")) {
                    routes.retain(|r| r["dst"] != "default");
                    routes.push(if route.contains("unreachable") {
                        serde_json::json!({"dst":"default", "type":"unreachable"})
                    } else {
                        serde_json::json!({"dst":"default", "dev":"ex-ch1"})
                    });
                }
                if a(4) == "default" {
                    routes.retain(|r| r["dst"] == "default");
                }
                if a(5) == "local" {
                    routes.retain(|r| r["table"] == "local");
                }
                stdout = serde_json::to_string(&routes).unwrap();
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
                    if k == "net.ipv4.ip_forward"
                        && v == "0"
                        && let Some(path) = self.state_failure_on_close.borrow_mut().take()
                    {
                        fs::rename(&path, path.with_extension("saved")).unwrap();
                        fs::create_dir(&path).unwrap();
                    }
                    if v == "1" {
                        assert!(self.verified_this_run.get());
                    }
                    if k == "net.ipv4.ip_forward"
                        && self.values.borrow().get(k).is_some_and(|old| old != v)
                    {
                        let mut values = self.values.borrow_mut();
                        for scope in ["all", "default", "lo", "wg0", "ex-ch1"] {
                            values.insert(
                                format!("net.ipv4.conf.{scope}.accept_redirects"),
                                "1".into(),
                            );
                        }
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
                        let endpoint = args.iter().position(|a| a == "endpoint").map_or_else(
                            || {
                                link.peers
                                    .get(a(3))
                                    .map_or_else(|| "(none)".into(), |peer| peer.1.clone())
                            },
                            |i| a(i + 1).to_owned(),
                        );
                        link.keepalive = args
                            .iter()
                            .position(|a| a == "persistent-keepalive")
                            .map_or(0, |i| a(i + 1).parse().unwrap());
                        link.peers
                            .insert(a(3).into(), (a(allowed + 1).into(), endpoint));
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
    fn client_session_io(
        &self,
        _: &NetnsHandle,
        request: &scupper_sys::client_sessions::Request,
    ) -> std::io::Result<scupper_sys::client_sessions::Response> {
        use scupper_sys::client_sessions::{Response, Sample};
        self.calls.borrow_mut().push(format!(
            "client-session {} {}",
            request.iface,
            if request.probe.is_some() {
                "probe"
            } else {
                "checkpoint-samples"
            }
        ));
        if let Some((_, destinations)) = &request.probe {
            return Ok(Response::Probes(vec![true; destinations.len()]));
        }
        let ns = self.ns.borrow();
        let link = ns
            .get(&request.iface)
            .ok_or_else(|| std::io::Error::other("missing client link"))?;
        let samples = link
            .peers
            .keys()
            .map(|key| Sample {
                key: scupper_core::config::PublicKey(key.clone())
                    .bytes()
                    .unwrap(),
                handshake: (0, 0),
                rx: 0,
                tx: 0,
            })
            .collect();
        Ok(Response::Samples(samples))
    }

    fn module_loaded(&self, module: &str) -> std::io::Result<bool> {
        if *self.script.file_error.borrow() {
            return Err(std::io::ErrorKind::PermissionDenied.into());
        }
        Ok(match module {
            "nf_conntrack" => self.conntrack_loaded.get(),
            "wireguard" => self.wireguard_loaded.get(),
            _ => panic!("unexpected module {module}"),
        })
    }

    fn namespace_identity(&self, _: &std::path::Path) -> std::io::Result<(u64, u64)> {
        testing::handle()
            .map(|held| held.identity())
            .map_err(std::io::Error::other)
    }

    fn canon_run_root(&self) -> &std::path::Path {
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
    }
    fn run(&self, p: Program, a: &[String], _: Duration) -> Result<ExecOutput, ExecError> {
        self.exec(ExecTarget::Host, p, a, None)
    }
    fn run_in(
        &self,
        t: ExecTarget<'_>,
        p: Program,
        a: &[String],
        timeout: Duration,
    ) -> Result<ExecOutput, ExecError> {
        if p == Program::Modprobe {
            assert_eq!(timeout, scupper_sys::system::EXEC_TIMEOUT);
            assert_eq!(a.len(), 1);
        }
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
    fn path(&self) -> &std::path::Path {
        static PATH: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();
        PATH.get_or_init(|| {
            std::env::var_os("CARGO_TARGET_TMPDIR")
                .map_or_else(
                    || {
                        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                            .join("../../target/tmp")
                    },
                    std::path::PathBuf::from,
                )
                .join("boot-test-namespace")
        })
    }
    fn open(&self) -> Result<Option<NetnsHandle>, NetnsError> {
        if self.exists.get() {
            testing::handle().map(Some)
        } else {
            Ok(None)
        }
    }
}
