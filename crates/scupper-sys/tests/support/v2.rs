#![allow(dead_code, clippy::unwrap_used)]
use scupper_core::{
    config::{GatewayId, ValidatedSite, parse_site, validate},
    render::VersionStamp,
};
use scupper_sys::{
    lock::WriterLock,
    netns::NetnsHandle,
    probe_child::ProbeExec,
    state::{State, StateFile},
    store::{MetaInput, VersionStore},
    system::{ExecError, ExecOutput, ExecTarget, Program, System},
};
use std::{
    cell::RefCell,
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

pub fn fixture(runner: &str, name: &str) -> String {
    // This support module is also compiled by the CLI integration tests.
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("scupper-sys/tests/fixtures/netns");
    fs::read_to_string(root.join(runner).join(name))
        .unwrap()
        .replace("PUBKEY1", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
        .replace("PUBKEY2", "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=")
        .replace("PUBKEY3", "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=")
        .replace("PUBKEY4", "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=")
}

pub struct Script {
    pub runner: String,
    pub calls: RefCell<Vec<(bool, Program, Vec<String>)>>,
    pub replacements: RefCell<BTreeMap<String, String>>,
    pub fail: RefCell<Option<usize>>,
    pub probe: RefCell<String>,
    pub file_error: RefCell<bool>,
}
impl Script {
    pub fn new(runner: &str) -> Self {
        // The checked-in captures predate `-d` and omit linkinfo. Supplement
        // that one field from the reference topology; production never infers
        // a kind from link_type or interface name. Keep the raw capture intact.
        let mut links: serde_json::Value =
            serde_json::from_str(&fixture(runner, "scupper--4-link.json")).unwrap();
        for link in links.as_array_mut().unwrap() {
            if link["ifname"] != "lo" {
                link["linkinfo"] = serde_json::json!({"info_kind": "wireguard"});
            }
        }
        Self { runner: runner.into(), calls: RefCell::default(), replacements: RefCell::new(BTreeMap::from([("scupper--4-link.json".into(), links.to_string())])),
            fail: RefCell::default(), file_error: RefCell::new(false),
            probe: RefCell::new(serde_json::json!({"result": {"class": "success", "ip": "8.8.4.4"},
                "credentials": {"uids": [99,99,99,99], "gids": [98,98,98,98], "no_new_privs": true, "cap_bnd": 0},
                "threads_before_setns": 1}).to_string()) }
    }
    pub fn replace(&self, name: &str, value: &str) {
        self.replacements
            .borrow_mut()
            .insert(name.into(), value.into());
    }
    pub fn text(&self, name: &str) -> String {
        self.replacements
            .borrow()
            .get(name)
            .cloned()
            .unwrap_or_else(|| fixture(&self.runner, name))
    }
    fn execute(
        &self,
        netns: bool,
        program: Program,
        args: &[String],
    ) -> Result<ExecOutput, ExecError> {
        self.calls
            .borrow_mut()
            .push((netns, program, args.to_vec()));
        if *self.fail.borrow() == Some(self.calls.borrow().len() - 1) {
            return Err(ExecError::spawn("injected collector error"));
        }
        let host = if netns { "scupper" } else { "gwhost" };
        let mut out = ExecOutput {
            status: Some(0),
            stdout: String::new(),
            stderr: String::new(),
        };
        let arg = |index: usize| args.get(index).map_or("", String::as_str);
        let name = match program {
            Program::Unshare => {
                assert!(!netns);
                assert_eq!(arg(0), "--net");
                assert!(args.iter().any(|arg| arg == "--gateway-netns"));
                "want.json".into()
            }
            Program::Nft => {
                assert!(netns);
                "scupper-nft-ruleset.json".into()
            }
            Program::Wg => {
                assert!(netns);
                format!("scupper-wg-{}-{}.txt", arg(1), arg(2))
            }
            Program::Sysctl => {
                assert!(netns);
                format!("scupper-sysctl-{}.txt", arg(1))
            }
            Program::Tc if arg(1) == "qdisc" => {
                let dev = arg(4);
                let entries: Vec<serde_json::Value> =
                    serde_json::from_str(&self.text("scupper-tc-qdisc.json")).unwrap();
                out.stdout = serde_json::to_string(
                    &entries
                        .into_iter()
                        .filter(|e| e["dev"] == dev)
                        .collect::<Vec<_>>(),
                )
                .unwrap();
                return Ok(out);
            }
            Program::Tc => {
                let parent = arg(5);
                if parent == "root" {
                    out.stdout = "[]".into();
                    return Ok(out);
                }
                format!("scupper-tc-{}-{parent}.json", arg(4))
            }
            Program::Ip if args.iter().any(|a| a == "get") => {
                assert!(netns);
                if arg(0) == "-6" {
                    out.status = Some(2);
                    out.stderr = "RTNETLINK answers: Network is unreachable\n".into();
                    return Ok(out);
                }
                "scupper-route-get-public.txt".into()
            }
            Program::Ip if arg(0) == "-d" => "scupper--4-link.json".into(),
            Program::Ip if arg(1) == "addr" => format!("{host}--4-addr.json"),
            Program::Ip if arg(2) == "rule" => format!("scupper-{}-rule.json", arg(1)),
            Program::Ip if arg(2) == "route" => {
                if arg(4) == "default" {
                    let text = self.text(&format!("scupper-{}-route.json", arg(1)));
                    let entries: Vec<serde_json::Value> = serde_json::from_str(&text).unwrap();
                    out.stdout = serde_json::to_string(
                        &entries
                            .into_iter()
                            .filter(|e| e["dst"] == "default")
                            .collect::<Vec<_>>(),
                    )
                    .unwrap();
                    return Ok(out);
                }
                format!("scupper-{}-route.json", arg(1))
            }
            _ => return Err(ExecError::spawn("unexpected scripted command")),
        };
        out.stdout = if name == "want.json" && !self.replacements.borrow().contains_key(&name) {
            fixture(&self.runner, "scupper-nft-ruleset.json")
        } else {
            self.text(&name)
        };
        Ok(out)
    }
}
impl System for Script {
    fn run(&self, p: Program, args: &[String], _: Duration) -> Result<ExecOutput, ExecError> {
        self.execute(false, p, args)
    }
    fn run_in(
        &self,
        target: ExecTarget<'_>,
        p: Program,
        args: &[String],
        _: Duration,
    ) -> Result<ExecOutput, ExecError> {
        self.execute(matches!(target, ExecTarget::Netns(_)), p, args)
    }
    fn now_unix_secs(&self) -> u64 {
        1000
    }
    fn wireguard_socket_dirs(&self) -> Vec<PathBuf> {
        vec![]
    }
    fn read_host_udp(&self, ipv6: bool) -> std::io::Result<String> {
        if *self.file_error.borrow() {
            return Err(std::io::ErrorKind::PermissionDenied.into());
        }
        Ok(self.text(if ipv6 {
            "gwhost-proc-net-udp6.txt"
        } else {
            "gwhost-proc-net-udp.txt"
        }))
    }
}
impl ProbeExec for Script {
    fn accepts_test_namespace(&self) -> bool {
        true
    }
    fn execute_probe(&self, json: &str, _: fs::File, _: Duration) -> Result<ExecOutput, ExecError> {
        let request: serde_json::Value = serde_json::from_str(json).unwrap();
        assert!(request["bind"].is_null());
        assert_eq!(request["kind"], "ExitIp");
        Ok(ExecOutput {
            status: Some(0),
            stdout: self.probe.borrow().clone(),
            stderr: String::new(),
        })
    }
}

pub fn site_text(runner: &str) -> String {
    let mut text = include_str!("../../../../xtask/lab/site-lab.toml")
        .replace("https://sink.lab.test/", "https://icanhazip.com/");
    for (old, name) in [
        (
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "scupper-wg-wg0-public-key.txt",
        ),
        (
            "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
            "scupper-wg-ex-ch1-peers.txt",
        ),
        (
            "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=",
            "scupper-wg-wg0-peers.txt",
        ),
    ] {
        text = text.replace(old, &format!("<{name}>"));
    }
    for name in [
        "scupper-wg-wg0-public-key.txt",
        "scupper-wg-ex-ch1-peers.txt",
        "scupper-wg-wg0-peers.txt",
    ] {
        text = text.replace(&format!("<{name}>"), fixture(runner, name).trim());
    }
    text.replace("[health]", "[health]\nrequire_daemon = false")
}
pub fn site(runner: &str) -> ValidatedSite {
    validate(parse_site(&site_text(runner)).unwrap()).unwrap()
}

pub struct Root {
    pub path: PathBuf,
    pub stamp: VersionStamp,
}
impl Root {
    pub fn new(runner: &str, handle: &NetnsHandle) -> Self {
        let path = std::env::temp_dir().join(format!(
            "scupper-v2-test-{}-{}",
            std::process::id(),
            unique()
        ));
        fs::create_dir_all(&path).unwrap();
        let writer = WriterLock::acquire(path.join("lock")).unwrap();
        let store = VersionStore::open(&path, Some(&writer)).unwrap();
        let text = site_text(runner);
        let version = store
            .commit(
                &writer,
                None,
                &text,
                MetaInput {
                    actor: "test".into(),
                    at: 1000,
                    reason: "test".into(),
                },
            )
            .unwrap();
        let (_, meta) = store.read(version).unwrap();
        let mut digest = [0; 32];
        for (i, byte) in digest.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&meta.sha256[i * 2..i * 2 + 2], 16).unwrap();
        }
        StateFile::open(&path, Some(&writer))
            .unwrap()
            .write(&writer, &State::default())
            .unwrap();
        fs::write(path.join("gateway-id"), "gw1\n").unwrap();
        fs::write(
            path.join("boot.json"),
            serde_json::json!({"netns": {"dev": handle.identity().0, "ino": handle.identity().1}})
                .to_string(),
        )
        .unwrap();
        Self {
            path,
            stamp: VersionStamp {
                version,
                sha256: digest,
            },
        }
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.path).unwrap();
    }
}
fn unique() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

pub fn fresh(sys: &Script) {
    for name in ["wg0", "ex-ch1"] {
        let peers = fixture(&sys.runner, &format!("scupper-wg-{name}-peers.txt"));
        sys.replace(
            &format!("scupper-wg-{name}-latest-handshakes.txt"),
            &peers.lines().fold(String::new(), |mut text, key| {
                use std::fmt::Write;
                writeln!(text, "{key}\t1000").unwrap();
                text
            }),
        );
    }
}

pub fn cfg<'a>(
    site: &'a ValidatedSite,
    gateway: &'a GatewayId,
    stamp: VersionStamp,
) -> scupper_sys::check_v2::Config<'a> {
    scupper_sys::check_v2::Config {
        site,
        gateway,
        stamp,
    }
}
pub fn health(
    site: &ValidatedSite,
    handle: &NetnsHandle,
) -> scupper_core::verdict::v2::HealthConfigV2 {
    scupper_core::verdict::v2::HealthConfigV2::new(
        site,
        &GatewayId("gw1".into()),
        scupper_core::verdict::v2::NetnsIdentity {
            device: handle.identity().0,
            inode: handle.identity().1,
        },
        vec!["198.51.100.2".parse().unwrap()],
        1,
    )
    .unwrap()
}
