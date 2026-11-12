//! Reusable fake installation host. Files live only under the integration-test root.
#![allow(dead_code)]
use scupper_core::install as model;
use scupper_sys::{
    install::{self, Options, Paths},
    system::{ExecError, ExecOutput, ExecTarget, Program, System},
};
use sha2::{Digest, Sha256};
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    fs,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};
pub const PRIVATE: &str = "BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ=";
pub const PUBLIC: &str = "BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU=";
pub const PEER: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
#[allow(clippy::struct_excessive_bools)] // Independent fault injection axes.
pub struct Fake {
    pub run_root: RefCell<Option<PathBuf>>,
    pub pubkey_inputs: RefCell<Vec<[u8; 32]>>,
    pub addresses: Vec<&'static str>,
    pub host_link: Option<&'static str>,
    pub leftover: bool,
    pub enable_failure: bool,
    pub calls: RefCell<Vec<(Program, Vec<String>)>>,
    pub users: RefCell<BTreeSet<String>>,
    pub group: RefCell<bool>,
    pub enabled: RefCell<bool>,
    pub os_kernel: String,
    pub arch: String,
    pub uid: u32,
    pub missing_packages: bool,
    pub marker: Option<&'static str>,
    pub firewall: bool,
    pub fail_pubkey: bool,
}
impl Default for Fake {
    fn default() -> Self {
        Self {
            run_root: RefCell::default(),
            pubkey_inputs: RefCell::default(),
            addresses: vec!["198.51.100.7"],
            host_link: None,
            leftover: false,
            enable_failure: false,
            calls: RefCell::default(),
            users: RefCell::default(),
            group: RefCell::new(false),
            enabled: RefCell::new(false),
            os_kernel: "5.15.0".into(),
            arch: "x86_64".into(),
            uid: 0,
            missing_packages: false,
            marker: None,
            firewall: false,
            fail_pubkey: false,
        }
    }
}
impl System for Fake {
    fn install_uid(&self) -> u32 {
        self.uid
    }
    #[allow(clippy::too_many_lines)] // Keep the literal command allow-list together.
    fn run(
        &self,
        program: Program,
        args: &[String],
        timeout: Duration,
    ) -> Result<ExecOutput, ExecError> {
        self.calls.borrow_mut().push((program, args.to_vec()));
        let mut status = 0;
        let text = match (program, args.first().map(String::as_str)) {
            (Program::Uname, Some("-r")) => self.os_kernel.clone(),
            (Program::Uname, _) => self.arch.clone(),
            (Program::DpkgQuery, _) => {
                if self.missing_packages {
                    status = 1;
                    String::new()
                } else {
                    "install ok installed".into()
                }
            }
            (Program::Getent, Some("passwd")) => {
                if self.users.borrow().contains(&args[1]) {
                    format!("{}:x:997:997::/nonexistent:/usr/sbin/nologin", args[1])
                } else {
                    status = 2;
                    String::new()
                }
            }
            (Program::Getent, _) => {
                if *self.group.borrow() {
                    "scupper-admin:x:996:".into()
                } else {
                    status = 2;
                    String::new()
                }
            }
            (Program::Groupadd, _) => {
                *self.group.borrow_mut() = true;
                String::new()
            }
            (Program::Useradd, _) => {
                self.users.borrow_mut().insert(args.last().unwrap().clone());
                String::new()
            }
            (Program::Systemctl, Some("list-unit-files")) => {
                if self.marker == Some("unit") {
                    "wg-quick@foreign.service enabled".into()
                } else {
                    String::new()
                }
            }
            (Program::Systemctl, Some("is-enabled")) => {
                if args[1].starts_with("wg-quick@") || *self.enabled.borrow() {
                    "enabled".into()
                } else {
                    status = 1;
                    "disabled".into()
                }
            }
            (Program::Systemctl, Some("enable")) => {
                assert!(timeout > Duration::from_secs(90));
                let root = self.run_root.borrow();
                let guard = scupper_sys::lock::WriterLock::try_acquire(root.as_ref().unwrap());
                assert!(
                    guard.is_ok(),
                    "systemctl enable must run after releasing the writer lock: {guard:?}"
                );
                let _guard = guard.unwrap();
                if self.enable_failure {
                    return Ok(ExecOutput {
                        status: Some(1),
                        stdout: String::new(),
                        stderr: "sensitive output".into(),
                    });
                }
                *self.enabled.borrow_mut() = true;
                String::new()
            }
            (Program::Systemctl, Some("daemon-reload")) => {
                let root = self.run_root.borrow();
                let guard = scupper_sys::lock::WriterLock::try_acquire(root.as_ref().unwrap());
                assert!(
                    guard.is_ok(),
                    "systemctl daemon-reload must run after releasing the writer lock: {guard:?}"
                );
                let _guard = guard.unwrap();
                String::new()
            }
            (Program::Nft, _) => {
                if self.marker == Some("table") {
                    r#"{"nftables":[{"table":{"family":"inet","name":"scupper"}}]}"#.into()
                } else if self.firewall && args.last().is_some_and(|a| a == "ruleset") {
                    r#"{"nftables":[{"chain":{"family":"inet","table":"filter","name":"input","hook":"input","policy":"drop"}}]}"#.into()
                } else {
                    r#"{"nftables":[]}"#.into()
                }
            }
            (Program::Ip, _) => {
                if args.iter().any(|a| a == "address") {
                    serde_json::json!([{"addr_info": self.addresses.iter().map(|ip| serde_json::json!({"scope":"global", "local":ip})).collect::<Vec<_>>()}]).to_string()
                } else if args.iter().any(|a| a == "addr") {
                    serde_json::json!([{"ifindex":3,"ifname":self.host_link.unwrap_or("wg0"),"addr_info":[]}]).to_string()
                } else if self.marker == Some("link") || self.host_link.is_some() {
                    serde_json::json!([{"ifindex":3,"ifname":self.host_link.unwrap_or("wg0"),"flags": if self.leftover { vec![] } else { vec!["UP"] },"mtu":1420,"linkinfo":{"info_kind":"wireguard"}}]).to_string()
                } else {
                    "[]".into()
                }
            }
            (Program::Wg, Some("show")) => String::new(),
            (Program::Scupper, _) => {
                if self.marker == Some("binary") {
                    "scupper 1.0 (v1)".into()
                } else {
                    "bundle validate".into()
                }
            }
            _ => return Err(ExecError::spawn("unexpected fake command")),
        };
        Ok(ExecOutput {
            status: Some(status),
            stdout: text,
            stderr: String::new(),
        })
    }
    fn run_with_stdin(
        &self,
        _: ExecTarget<'_>,
        program: Program,
        args: &[String],
        input: &[u8],
        _: Duration,
    ) -> Result<ExecOutput, ExecError> {
        self.calls.borrow_mut().push((program, args.to_vec()));
        assert_eq!(program, Program::Wg);
        assert_eq!(args, ["pubkey"]);
        if self.fail_pubkey {
            return Err(ExecError::spawn("injected failure"));
        }
        self.pubkey_inputs
            .borrow_mut()
            .push(Sha256::digest(input).into());
        Ok(ExecOutput {
            status: Some(0),
            stdout: format!("{}\n", public_for(input)),
            stderr: String::new(),
        })
    }
    fn now_unix_secs(&self) -> u64 {
        1000
    }
}
pub struct Host {
    pub root: PathBuf,
    pub paths: Paths,
    pub options: Options,
}
impl Host {
    pub fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "install-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(root.join("etc/systemd/system")).unwrap();
        fs::create_dir(root.join("source")).unwrap();
        fs::create_dir_all(root.join("usr/local/bin")).unwrap();
        fs::write(
            root.join("etc/os-release"),
            "ID=ubuntu\nVERSION_ID=\"22.04\"\n",
        )
        .unwrap();
        for name in model::BINARIES {
            fs::write(root.join("source").join(name), format!("new-{name}")).unwrap();
        }
        let options = Options {
            binaries: root.join("source"),
            gateway_id: Some("gw1".into()),
            uplink: Some("eth0".into()),
            exit_file: Some(root.join("provider.conf")),
            exit_id: Some("ch1".into()),
            ..Options::default()
        };
        let paths = Paths::new(&root);
        let host = Self {
            root,
            paths,
            options,
        };
        host.provider(PRIVATE);
        host
    }
    pub fn provider(&self, key: &str) {
        fs::write(self.root.join("provider.conf"), format!("# CH#1234\n[Interface]\nPrivateKey = {key}\nAddress = 10.2.0.2/32\nDNS = 10.2.0.1\n[Peer]\nPublicKey = {PEER}\nEndpoint = 203.0.113.10:51820\nAllowedIPs = 0.0.0.0/0\n")).unwrap();
    }
    pub fn prepare(&self, fake: &Fake) -> Result<install::Prepared, model::Refusal> {
        *fake.run_root.borrow_mut() = Some(self.paths.at(model::RUN_ROOT));
        install::prepare(fake, &self.paths, &self.options)
    }
    pub fn apply(&self, fake: &Fake) -> String {
        install::apply(fake, &self.paths, self.prepare(fake).unwrap()).unwrap()
    }
    pub fn key(&self) -> Vec<u8> {
        fs::read(self.paths.at(model::WG0_FILE)).unwrap()
    }
    pub fn snapshot(&self) -> BTreeMap<PathBuf, (Vec<u8>, u32)> {
        fn walk(root: &Path, out: &mut BTreeMap<PathBuf, (Vec<u8>, u32)>) {
            for e in fs::read_dir(root).unwrap() {
                let e = e.unwrap();
                let m = e.metadata().unwrap();
                let path = e.path();
                out.insert(
                    path.clone(),
                    (
                        if m.is_file() {
                            fs::read(&path).unwrap()
                        } else {
                            vec![]
                        },
                        m.mode() & 0o7777,
                    ),
                );
                if m.is_dir() {
                    walk(&path, out);
                }
            }
        }
        let mut out = BTreeMap::new();
        walk(&self.root, &mut out);
        out
    }
}
impl Drop for Host {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

// Deterministic fake derivation: binds public output to stdin without retaining
// secret bytes or requiring host WireGuard utilities.
pub fn public_for(input: &[u8]) -> String {
    base64(&Sha256::digest(input))
}
pub fn base64(bytes: &[u8]) -> String {
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let a = chunk[0];
        let b = chunk.get(1).copied().unwrap_or(0);
        let c = chunk.get(2).copied().unwrap_or(0);
        out.push(char::from(alphabet[usize::from(a >> 2)]));
        out.push(char::from(alphabet[usize::from((a & 3) << 4 | b >> 4)]));
        out.push(if chunk.len() > 1 {
            char::from(alphabet[usize::from((b & 15) << 2 | c >> 6)])
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            char::from(alphabet[usize::from(c & 63)])
        } else {
            '='
        });
    }
    out
}
