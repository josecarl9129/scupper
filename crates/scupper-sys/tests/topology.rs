//! Captured containment observations and synthetic edge cases; no networking commands run.

use std::{
    cell::{Cell, RefCell},
    collections::{BTreeMap, VecDeque},
    error::Error,
    io,
    net::IpAddr,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    time::Duration,
};

use scupper_sys::{
    canon::{
        CANON_TIMEOUT, OVERSIZED_LIVE_RULESET, WANT_NOT_COMPUTED_LIVE_OVERFLOW, canonicalize,
        fingerprint, observe_ruleset, run_isolated,
    },
    check::{ExitProbe, TopologySource, run_check},
    rules::{V1Config, ruleset},
    system::{EXEC_TIMEOUT, ExecError, ExecOutput, Program, Stream, System},
    topology::{HostTopology, LegacyTablesReader},
    verdict::{ConfigMismatch, ExitLink, FailClosed, Probe, ProbeError, RulesetObs, Verdict},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

struct EmptyLegacyTables;
impl LegacyTablesReader for EmptyLegacyTables {
    fn read(&self, _: &Path) -> io::Result<String> {
        Err(io::ErrorKind::NotFound.into())
    }
}

fn topology_source() -> impl TopologySource {
    HostTopology::with_legacy_reader(&EmptyLegacyTables)
}

const NFT_LIVE: &str = include_str!("fixtures/ubuntu-24.04/nft-live.json");
const NFT_WANT: &str = include_str!("fixtures/ubuntu-24.04/nft-want.json");
const NFT_EXTRA: &str = include_str!("fixtures/ubuntu-24.04/case-06-nft.json");

// Synthetic overrides below cover malformed output, races, and states absent
// from the lab captures. Healthy command defaults always use captured output.

fn output(stdout: &str) -> ExecOutput {
    ExecOutput {
        status: Some(0),
        stdout: stdout.into(),
        stderr: String::new(),
    }
}

fn failure(stderr: &str) -> ExecOutput {
    ExecOutput {
        status: Some(1),
        stdout: String::new(),
        stderr: stderr.into(),
    }
}

type Scripts = BTreeMap<(Program, Vec<String>), VecDeque<Result<ExecOutput, ExecError>>>;
type Call = (Program, Vec<String>, Duration);

struct FakeSystem {
    scripts: RefCell<Scripts>,
    calls: RefCell<Vec<Call>>,
    canon_results: RefCell<VecDeque<Result<ExecOutput, ExecError>>>,
    live_results: RefCell<VecDeque<Result<ExecOutput, ExecError>>>,
    temp_paths: RefCell<Vec<PathBuf>>,
}

impl FakeSystem {
    fn new() -> Self {
        Self {
            scripts: RefCell::new(BTreeMap::new()),
            calls: RefCell::new(Vec::new()),
            canon_results: RefCell::new(VecDeque::new()),
            live_results: RefCell::new(VecDeque::new()),
            temp_paths: RefCell::new(Vec::new()),
        }
    }

    fn push(&self, program: Program, args: &[&str], response: Result<ExecOutput, ExecError>) {
        self.scripts
            .borrow_mut()
            .entry((program, args.iter().map(|s| (*s).into()).collect()))
            .or_default()
            .push_back(response);
    }

    fn set(&self, program: Program, args: &[&str], stdout: &str) {
        self.push(program, args, Ok(output(stdout)));
    }

    fn assert_cleaned(&self) {
        for path in &*self.temp_paths.borrow() {
            assert!(!path.exists());
            assert!(!path.parent().is_some_and(Path::exists));
        }
    }

    fn run_unshare(&self, args: &[String], timeout: Duration) -> Result<ExecOutput, ExecError> {
        assert_eq!(timeout, CANON_TIMEOUT);
        assert_eq!(args.len(), 7);
        let exe =
            std::fs::read_link("/proc/self/exe").map_err(|e| ExecError::spawn(&e.to_string()))?;
        let outer_netns = std::fs::read_link("/proc/self/ns/net")
            .map_err(|e| ExecError::spawn(&e.to_string()))?;
        let path = PathBuf::from(&args[6]);
        // Fix the exact argv shape, including the parent's resolved executable.
        assert_eq!(
            args,
            [
                "--net",
                "--",
                exe.to_str()
                    .ok_or_else(|| ExecError::spawn("non-UTF-8 exe"))?,
                "canon",
                "--outer-netns",
                outer_netns
                    .to_str()
                    .ok_or_else(|| ExecError::spawn("non-UTF-8 netns"))?,
                path.to_str()
                    .ok_or_else(|| ExecError::spawn("non-UTF-8 file"))?
            ]
        );
        assert_eq!(path.file_name(), Some(std::ffi::OsStr::new("ruleset.nft")));
        let parent = path
            .parent()
            .ok_or_else(|| ExecError::spawn("missing temp parent"))?;
        assert_eq!(parent.parent(), Some(std::env::temp_dir().as_path()));
        assert_eq!(
            std::fs::metadata(parent)
                .map_err(|e| ExecError::spawn(&e.to_string()))?
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(&path)
                .map_err(|e| ExecError::spawn(&e.to_string()))?
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::read_to_string(&path).map_err(|e| ExecError::spawn(&e.to_string()))?,
            ruleset(&V1Config::default()).map_err(|e| ExecError::spawn(&e.to_string()))?
        );
        assert!(
            !self.temp_paths.borrow().contains(&path),
            "must never reuse a directory"
        );
        self.temp_paths.borrow_mut().push(path);
        self.canon_results
            .borrow_mut()
            .pop_front()
            .unwrap_or_else(|| Ok(output(NFT_WANT)))
    }
}

impl System for FakeSystem {
    fn run(
        &self,
        program: Program,
        args: &[String],
        timeout: Duration,
    ) -> Result<ExecOutput, ExecError> {
        self.calls
            .borrow_mut()
            .push((program, args.to_vec(), timeout));
        if let Some(response) = self
            .scripts
            .borrow_mut()
            .get_mut(&(program, args.to_vec()))
            .and_then(VecDeque::pop_front)
        {
            return response;
        }
        if program == Program::Unshare {
            return self.run_unshare(args, timeout);
        }
        assert_eq!(timeout, EXEC_TIMEOUT);
        let words: Vec<_> = args.iter().map(String::as_str).collect();
        let text = match (program, words.as_slice()) {
            (Program::Nft, ["-j", "list", "ruleset"]) => {
                return self
                    .live_results
                    .borrow_mut()
                    .pop_front()
                    .unwrap_or_else(|| Ok(output(NFT_LIVE)));
            }
            (Program::Ip, ["-d", "-j", "link", "show"]) => {
                include_str!("fixtures/ubuntu-24.04/ip-link.json")
            }
            (Program::Ip, ["-j", "route", "show", "default"]) => {
                include_str!("fixtures/ubuntu-24.04/ip-default.json")
            }
            (Program::Ip, ["-j", "addr", "show", "dev", "proton0"]) => {
                include_str!("fixtures/ubuntu-24.04/ip-addr-proton0.json")
            }
            (Program::Ip, ["-j", "addr", "show", "dev", "eth0"]) => {
                include_str!("fixtures/ubuntu-24.04/ip-addr-eth0.json")
            }
            (Program::Wg, ["show", "wg0", "allowed-ips"]) => {
                return Ok(output(
                    &include_str!("fixtures/ubuntu-24.04/wg-allowed-ips.txt")
                        .replace("PUBKEY4", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
                ));
            }
            (Program::Tc, ["-j", "qdisc", "show", "dev", "wg0"]) => {
                include_str!("fixtures/ubuntu-24.04/tc-qdisc-wg0.json")
            }
            (Program::Tc, ["-j", "qdisc", "show", "dev", "proton0"]) => {
                include_str!("fixtures/ubuntu-24.04/tc-qdisc-proton0.json")
            }
            (Program::Tc, ["-j", "filter", "show", "dev", "wg0"]) => {
                include_str!("fixtures/ubuntu-24.04/tc-filter-wg0.json")
            }
            (Program::Tc, ["-j", "filter", "show", "dev", "proton0"]) => {
                include_str!("fixtures/ubuntu-24.04/tc-filter-proton0.json")
            }
            _ => return Err(ExecError::spawn("unexpected command")),
        };
        Ok(output(text))
    }

    fn now_unix_secs(&self) -> u64 {
        1_794_160_067 // Ten seconds after the captured handshake.
    }
}

#[test]
fn ruleset_exact_and_private_file_argv() -> Result<(), Box<dyn Error>> {
    let sys = FakeSystem::new();
    assert_eq!(Program::Unshare.default_path(), "/usr/bin/unshare");
    assert_eq!(
        observe_ruleset(&sys, &V1Config::default())?,
        RulesetObs::Exact
    );
    assert_eq!(sys.calls.borrow().len(), 2);
    sys.assert_cleaned();
    Ok(())
}

#[test]
fn ruleset_differences_confirmed_with_both_fingerprints() -> Result<(), Box<dyn Error>> {
    // Rule ordering is not changed by the lab cases; retain this synthetic mutation.
    let mut swapped: Value = serde_json::from_str(NFT_LIVE)?;
    swapped["nftables"]
        .as_array_mut()
        .ok_or("fixture array")?
        .swap(5, 6);
    for live in [
        NFT_EXTRA.to_owned(),
        include_str!("fixtures/ubuntu-24.04/case-07-nft.json").to_owned(),
        include_str!("fixtures/ubuntu-24.04/case-08-nft.json").to_owned(),
        include_str!("fixtures/ubuntu-24.04/case-09-nft.json").to_owned(),
        swapped.to_string(),
    ] {
        let sys = FakeSystem::new();
        sys.live_results
            .borrow_mut()
            .extend([Ok(output(&live)), Ok(output(&live))]);
        assert_eq!(
            observe_ruleset(&sys, &V1Config::default())?,
            RulesetObs::Differs {
                live_sha256: fingerprint(&canonicalize(&live)?)?,
                want_sha256: fingerprint(&canonicalize(NFT_WANT)?)?,
            }
        );
        assert_eq!(
            sys.calls
                .borrow()
                .iter()
                .filter(|call| call.0 == Program::Unshare)
                .count(),
            2
        );
        assert_eq!(
            sys.calls
                .borrow()
                .iter()
                .filter(|call| call.0 == Program::Nft)
                .count(),
            2
        );
        sys.assert_cleaned();
    }
    Ok(())
}

#[test]
fn ruleset_repeat_is_fresh_and_can_recover() -> Result<(), Box<dyn Error>> {
    let sys = FakeSystem::new();
    sys.live_results
        .borrow_mut()
        .extend([Ok(output(NFT_EXTRA)), Ok(output(NFT_LIVE))]);
    assert_eq!(
        observe_ruleset(&sys, &V1Config::default())?,
        RulesetObs::Exact
    );
    assert_eq!(sys.temp_paths.borrow().len(), 2);
    sys.assert_cleaned();
    // Both sides of the repeat are fresh, including a changed desired form.
    let sys = FakeSystem::new();
    sys.canon_results
        .borrow_mut()
        .extend([Ok(output(NFT_LIVE)), Ok(output(NFT_EXTRA))]);
    sys.live_results
        .borrow_mut()
        .extend([Ok(output(NFT_EXTRA)), Ok(output(NFT_EXTRA))]);
    assert_eq!(
        observe_ruleset(&sys, &V1Config::default())?,
        RulesetObs::Exact
    );
    sys.assert_cleaned();
    Ok(())
}

#[test]
fn ruleset_missing() -> Result<(), Box<dyn Error>> {
    for live in [
        r#"{"nftables":[{"metainfo":{"version":"1.0.9"}}]}"#,
        r#"{"nftables":[{"table":{"family":"ip","name":"scupper"}}]}"#,
        r#"{"nftables":[{"table":{"family":"inet","name":"foreign"}}]}"#,
    ] {
        let sys = FakeSystem::new();
        sys.live_results.borrow_mut().push_back(Ok(output(live)));
        assert_eq!(
            observe_ruleset(&sys, &V1Config::default())?,
            RulesetObs::Missing
        );
        assert_eq!(sys.temp_paths.borrow().len(), 1);
        sys.assert_cleaned();
    }
    Ok(())
}

#[test]
fn namespace_guard_aborts_without_nft() {
    for unreadable in [None, Some("/proc/self/ns/net"), Some("/proc/1/ns/net")] {
        let sys = FakeSystem::new();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = run_isolated(
            &sys,
            Path::new("/ignored/ruleset.nft"),
            Path::new("net:[4026531840]"),
            |path| {
                if unreadable.is_some_and(|bad| path == Path::new(bad)) {
                    Err(io::ErrorKind::PermissionDenied.into())
                } else {
                    Ok(PathBuf::from("net:[4026531840]"))
                }
            },
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(code, 1);
        assert_eq!(stdout, Vec::<u8>::new());
        assert_ne!(stderr, Vec::<u8>::new());
        assert!(sys.calls.borrow().is_empty());
    }
}

fn isolated_run(sys: &FakeSystem) -> (u8, Vec<u8>, Vec<u8>) {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let code = run_isolated(
        sys,
        Path::new("/private/ruleset.nft"),
        Path::new("net:[789]"),
        |path| {
            Ok(PathBuf::from(if path == Path::new("/proc/self/ns/net") {
                "net:[123]"
            } else {
                "net:[456]"
            }))
        },
        &mut stdout,
        &mut stderr,
    );
    (code, stdout, stderr)
}

#[test]
fn isolated_canon_loads_then_lists_and_reports_failures() -> Result<(), Box<dyn Error>> {
    let sys = FakeSystem::new();
    sys.live_results
        .borrow_mut()
        .push_back(Ok(output(r#"{"nftables":[]}"#)));
    sys.set(Program::Nft, &["-f", "/private/ruleset.nft"], "");
    let (code, stdout, stderr) = isolated_run(&sys);
    assert_eq!(code, 0);
    assert_eq!(String::from_utf8(stdout)?, NFT_LIVE);
    assert_eq!(stderr, Vec::<u8>::new());
    assert_eq!(
        *sys.calls.borrow(),
        [
            (
                Program::Nft,
                vec!["-j".into(), "list".into(), "ruleset".into()],
                EXEC_TIMEOUT
            ),
            (
                Program::Nft,
                vec!["-f".into(), "/private/ruleset.nft".into()],
                EXEC_TIMEOUT
            ),
            (
                Program::Nft,
                vec!["-j".into(), "list".into(), "ruleset".into()],
                EXEC_TIMEOUT
            ),
        ]
    );
    for error in [
        Ok(failure("invalid ruleset")),
        Err(ExecError::Timeout {
            after: EXEC_TIMEOUT,
        }),
        Err(ExecError::spawn("nft unavailable")),
    ] {
        let sys = FakeSystem::new();
        sys.live_results
            .borrow_mut()
            .push_back(Ok(output(r#"{"nftables":[]}"#)));
        sys.push(Program::Nft, &["-f", "/private/ruleset.nft"], error);
        let (code, stdout, stderr) = isolated_run(&sys);
        assert_eq!(code, 1);
        assert_eq!(stdout, Vec::<u8>::new());
        assert_ne!(stderr, Vec::<u8>::new());
        assert_eq!(sys.calls.borrow().len(), 2);
    }
    let sys = FakeSystem::new();
    sys.live_results
        .borrow_mut()
        .push_back(Ok(output(r#"{"nftables":[]}"#)));
    sys.set(Program::Nft, &["-f", "/private/ruleset.nft"], "");
    sys.live_results
        .borrow_mut()
        .push_back(Ok(failure("cannot list ruleset")));
    let (code, stdout, stderr) = isolated_run(&sys);
    assert_eq!(code, 1);
    assert_eq!(stdout, Vec::<u8>::new());
    assert_ne!(stderr, Vec::<u8>::new());
    Ok(())
}

#[test]
fn ruleset_errors_are_observation_errors_and_cleanup() {
    let cfg = V1Config::default();
    for response in [
        Err(ExecError::spawn("unshare missing")),
        Err(ExecError::Timeout {
            after: CANON_TIMEOUT,
        }),
        Ok(failure("namespace creation failed")),
        Ok(output("malformed JSON")),
    ] {
        for want_side in [true, false] {
            let sys = FakeSystem::new();
            if want_side {
                sys.canon_results.borrow_mut().push_back(response.clone());
            } else {
                sys.live_results.borrow_mut().push_back(response.clone());
            }
            assert!(observe_ruleset(&sys, &cfg).is_err());
            sys.assert_cleaned();
        }
    }
    for message in [
        "unshare: unshare failed: Operation not permitted",
        "netlink: Error: cache initialization failed: Operation not permitted",
        "Permission denied (you must be root)",
    ] {
        let sys = FakeSystem::new();
        sys.canon_results
            .borrow_mut()
            .push_back(Ok(failure(message)));
        assert!(matches!(
            observe_ruleset(&sys, &cfg),
            Err(ProbeError::Setup(_))
        ));
        sys.assert_cleaned();
    }
    let sys = FakeSystem::new();
    sys.canon_results
        .borrow_mut()
        .push_back(Err(ExecError::spawn("Permission denied")));
    assert!(matches!(
        observe_ruleset(&sys, &cfg),
        Err(ProbeError::Setup(_))
    ));
}

#[test]
fn repeat_error_does_not_confirm_a_difference() {
    let sys = FakeSystem::new();
    sys.live_results
        .borrow_mut()
        .extend([Ok(output(NFT_EXTRA)), Ok(output("not JSON"))]);
    assert!(matches!(
        observe_ruleset(&sys, &V1Config::default()),
        Err(ProbeError::Parse(_))
    ));
    sys.assert_cleaned();
}

#[test]
fn healthy_topology_collects_everything() -> Result<(), Box<dyn Error>> {
    let sys = FakeSystem::new();
    let topology = topology_source().observe(&sys, &V1Config::default())?;
    assert_eq!(topology.exit_link, ExitLink::Up);
    assert_eq!(topology.ruleset, RulesetObs::Exact);
    assert_eq!(topology.tc_hooks, Vec::new());
    assert_eq!(topology.config_mismatches, Vec::new());
    assert_eq!(topology.legacy_tables, Vec::<String>::new());
    assert_eq!(
        topology.uplink_addrs,
        [
            "172.31.0.2".parse::<IpAddr>()?,
            "fe80::300d:a6ff:fe5f:c596".parse()?
        ]
    );
    assert_eq!(sys.calls.borrow().len(), 11);
    assert_eq!(sys.calls.borrow()[0].0, Program::Ip);
    assert_eq!(sys.calls.borrow()[10].0, Program::Unshare);
    sys.assert_cleaned();
    Ok(())
}

#[test]
fn captured_case_04_topology_is_down_without_violations() -> Result<(), Box<dyn Error>> {
    let sys = FakeSystem::new();
    sys.set(
        Program::Ip,
        &["-d", "-j", "link", "show"],
        include_str!("fixtures/ubuntu-24.04/case-04-ip-link.json"),
    );
    sys.set(
        Program::Ip,
        &["-j", "addr", "show", "dev", "proton0"],
        include_str!("fixtures/ubuntu-24.04/case-04-ip-addr-proton0.json"),
    );
    sys.set(
        Program::Tc,
        &["-j", "qdisc", "show", "dev", "proton0"],
        include_str!("fixtures/ubuntu-24.04/case-04-tc-qdisc-proton0.json"),
    );
    let topology = topology_source().observe(&sys, &V1Config::default())?;
    assert_eq!(topology.exit_link, ExitLink::Down);
    assert_eq!(topology.ruleset, RulesetObs::Exact);
    assert_eq!(topology.tc_hooks, Vec::new());
    assert_eq!(topology.legacy_tables, Vec::<String>::new());
    assert_eq!(topology.config_mismatches, Vec::new());
    assert_eq!(sys.calls.borrow().len(), 10);
    // A known-down exit skips its address query but still checks tc and nft.
    assert!(!sys.calls.borrow().iter().any(|(program, args, _)| {
        *program == Program::Ip && args == &["-j", "addr", "show", "dev", "proton0"]
    }));
    sys.assert_cleaned();
    Ok(())
}

#[test]
fn each_configuration_mismatch() -> Result<(), Box<dyn Error>> {
    let cfg = V1Config::default();
    for (program, args, text, expected) in [
        (
            Program::Ip,
            vec!["-d", "-j", "link", "show"],
            r#"[{"ifname":"eth0"},{"ifname":"proton0"}]"#,
            ConfigMismatch::InterfaceMissing(cfg.client_iface.clone()),
        ),
        (
            Program::Ip,
            vec!["-d", "-j", "link", "show"],
            r#"[{"ifname":"wg0"},{"ifname":"proton0"}]"#,
            ConfigMismatch::InterfaceMissing(cfg.uplink_iface.clone()),
        ),
        (
            Program::Ip,
            vec!["-j", "route", "show", "default"],
            "[]",
            ConfigMismatch::UplinkNotDefaultRouteDev,
        ),
        (
            Program::Ip,
            vec!["-j", "route", "show", "default"],
            r#"[{"dev":"eth0"},{"dev":"other0"}]"#,
            ConfigMismatch::UplinkNotDefaultRouteDev,
        ),
        (
            Program::Ip,
            vec!["-j", "addr", "show", "dev", "proton0"],
            r#"[{"ifname":"proton0","flags":["UP"],"addr_info":[{"local":"10.2.0.3"}]}]"#,
            ConfigMismatch::ExitAddrNotOnExitIface,
        ),
        (
            Program::Wg,
            vec!["show", "wg0", "allowed-ips"],
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\t(none)\n",
            ConfigMismatch::ClientAddrNotInPeerAllowedIps,
        ),
    ] {
        let sys = FakeSystem::new();
        sys.set(program, &args, text);
        let topology = topology_source().observe(&sys, &cfg)?;
        assert_eq!(topology.config_mismatches, [expected]);
        sys.assert_cleaned();
    }
    Ok(())
}

#[test]
fn tc_hooks_each_interface_once() -> Result<(), Box<dyn Error>> {
    let cfg = V1Config::default();
    for iface in [&cfg.client_iface, &cfg.exit_iface] {
        for qdisc in [
            "[]",
            r#"[{"kind":"ingress","parent":"ffff:fff1"}]"#,
            r#"[{"kind":"clsact","parent":"ffff:fff1"}]"#,
            r#"[{"kind":"fq_codel","root":true}]"#,
            r#"[{"kind":"noqueue","root":true},{"kind":"ingress"}]"#,
        ] {
            let sys = FakeSystem::new();
            sys.set(
                Program::Tc,
                &["-j", "qdisc", "show", "dev", iface.as_str()],
                qdisc,
            );
            sys.set(
                Program::Tc,
                &["-j", "filter", "show", "dev", iface.as_str()],
                r#"[{"kind":"bpf","protocol":"all"}]"#,
            );
            assert_eq!(
                topology_source().observe(&sys, &cfg)?.tc_hooks,
                std::slice::from_ref(iface)
            );
        }
        let sys = FakeSystem::new();
        sys.set(
            Program::Tc,
            &["-j", "filter", "show", "dev", iface.as_str()],
            r#"[{"kind":"flower","protocol":"ip"}]"#,
        );
        assert_eq!(
            topology_source().observe(&sys, &cfg)?.tc_hooks,
            std::slice::from_ref(iface)
        );
    }
    Ok(())
}

#[test]
fn all_violations_survive_other_collector_errors() -> Result<(), Box<dyn Error>> {
    let sys = FakeSystem::new();
    sys.set(Program::Ip, &["-j", "route", "show", "default"], "[]");
    sys.set(
        Program::Tc,
        &["-j", "qdisc", "show", "dev", "wg0"],
        r#"[{"kind":"clsact"}]"#,
    );
    sys.push(
        Program::Tc,
        &["-j", "filter", "show", "dev", "wg0"],
        Err(ExecError::spawn("filter failed")),
    );
    sys.set(
        Program::Ip,
        &["-j", "addr", "show", "dev", "eth0"],
        "bad JSON",
    );
    sys.live_results
        .borrow_mut()
        .extend([Ok(output(NFT_EXTRA)), Ok(output(NFT_EXTRA))]);
    let topology = topology_source().observe(&sys, &V1Config::default())?;
    assert!(matches!(topology.ruleset, RulesetObs::Differs { .. }));
    assert_eq!(topology.tc_hooks, [V1Config::default().client_iface]);
    assert_eq!(
        topology.config_mismatches,
        [ConfigMismatch::UplinkNotDefaultRouteDev]
    );
    assert_eq!(sys.calls.borrow().len(), 13);
    sys.assert_cleaned();
    // Also keep config evidence when canonicalization itself fails.
    let sys = FakeSystem::new();
    sys.set(Program::Ip, &["-j", "route", "show", "default"], "[]");
    sys.canon_results
        .borrow_mut()
        .push_back(Ok(failure("unshare failed")));
    assert_eq!(
        topology_source()
            .observe(&sys, &V1Config::default())?
            .config_mismatches,
        [ConfigMismatch::UplinkNotDefaultRouteDev]
    );
    Ok(())
}

#[test]
fn collector_error_alone_is_error_and_others_still_run() {
    for (program, args) in [
        (Program::Ip, vec!["-d", "-j", "link", "show"]),
        (Program::Ip, vec!["-j", "route", "show", "default"]),
        (Program::Ip, vec!["-j", "addr", "show", "dev", "proton0"]),
        (Program::Ip, vec!["-j", "addr", "show", "dev", "eth0"]),
        (Program::Wg, vec!["show", "wg0", "allowed-ips"]),
        (Program::Tc, vec!["-j", "qdisc", "show", "dev", "wg0"]),
        (Program::Tc, vec!["-j", "filter", "show", "dev", "proton0"]),
    ] {
        let sys = FakeSystem::new();
        sys.set(program, &args, "malformed output");
        assert!(matches!(
            topology_source().observe(&sys, &V1Config::default()),
            Err(ProbeError::Parse(_))
        ));
        let exit_query = args.contains(&"proton0");
        assert_eq!(sys.calls.borrow().len(), 11 + usize::from(exit_query));
        sys.assert_cleaned();
    }
}

#[test]
fn multiple_errors_are_bounded_and_include_later_errors() -> Result<(), Box<dyn Error>> {
    let sys = FakeSystem::new();
    sys.push(
        Program::Ip,
        &["-d", "-j", "link", "show"],
        Err(ExecError::spawn(&format!("first {}", "é".repeat(200)))),
    );
    sys.push(
        Program::Ip,
        &["-j", "route", "show", "default"],
        Err(ExecError::spawn("second failure")),
    );
    let Err(error) = topology_source().observe(&sys, &V1Config::default()) else {
        return Err("expected observation error".into());
    };
    assert!(error.to_string().contains("first"));
    assert!(error.to_string().contains("second failure"));
    if let ProbeError::Io(message) = error {
        assert!(message.chars().count() <= 200);
    }
    assert_eq!(sys.calls.borrow().len(), 11);
    Ok(())
}

struct FakeExitProbe(Cell<usize>);
impl ExitProbe for FakeExitProbe {
    fn probe(&self, _: &V1Config) -> Probe<IpAddr> {
        self.0.set(self.0.get() + 1);
        Ok(IpAddr::from([203, 0, 113, 20]))
    }
}

fn healthy_path(sys: &FakeSystem) {
    sys.set(
        Program::Wg,
        &["show", "proton0", "latest-handshakes"],
        &include_str!("fixtures/ubuntu-24.04/wg-handshakes.txt")
            .replace("PUBKEY3", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
    );
    sys.set(
        Program::Ip,
        &["route", "get", "1.1.1.1", "from", "10.99.0.2", "iif", "wg0"],
        include_str!("fixtures/ubuntu-24.04/ip-policy-route.txt"),
    );
}

#[test]
fn check_healthy_and_extra_rule() -> Result<(), Box<dyn Error>> {
    for extra in [false, true] {
        let sys = FakeSystem::new();
        let probe = FakeExitProbe(Cell::new(0));
        healthy_path(&sys);
        if extra {
            sys.live_results
                .borrow_mut()
                .extend([Ok(output(NFT_EXTRA)), Ok(output(NFT_EXTRA))]);
        }
        let report = run_check(&sys, &topology_source(), &probe, &V1Config::default())?;
        assert_eq!(report.verdict.exit_code(), if extra { 2 } else { 0 });
        assert_eq!(probe.0.get(), usize::from(!extra));
        sys.assert_cleaned();
    }
    Ok(())
}

fn without_exit(sys: &FakeSystem) {
    sys.set(
        Program::Ip,
        &["-d", "-j", "link", "show"],
        r#"[{"ifname":"lo"},{"ifname":"eth0"},{"ifname":"wg0"}]"#,
    );
}

#[test]
fn missing_exit_interface_is_fail_closed_code_four() -> Result<(), Box<dyn Error>> {
    let cfg = V1Config::default();
    let sys = FakeSystem::new();
    without_exit(&sys);
    let topology = topology_source().observe(&sys, &cfg)?;
    assert_eq!(topology.exit_link, ExitLink::Absent);
    assert_eq!(topology.ruleset, RulesetObs::Exact);
    assert_eq!(topology.config_mismatches, Vec::new());
    assert_eq!(topology.tc_hooks, Vec::new());
    assert!(
        !sys.calls
            .borrow()
            .iter()
            .any(|(_, args, _)| args.iter().any(|arg| arg == "proton0"))
    );
    sys.assert_cleaned();
    let sys = FakeSystem::new();
    without_exit(&sys);
    sys.push(
        Program::Wg,
        &["show", "proton0", "latest-handshakes"],
        Ok(failure("Unable to access interface: No such device\n")),
    );
    let probe = FakeExitProbe(Cell::new(0));
    assert_eq!(
        run_check(&sys, &topology_source(), &probe, &cfg)?
            .verdict
            .exit_code(),
        4
    );
    assert_eq!(probe.0.get(), 0);
    sys.assert_cleaned();
    Ok(())
}

#[test]
fn errors_on_both_ruleset_sides_are_retained() -> Result<(), Box<dyn Error>> {
    let sys = FakeSystem::new();
    sys.canon_results
        .borrow_mut()
        .push_back(Ok(failure("want failed")));
    sys.live_results
        .borrow_mut()
        .push_back(Ok(failure("live failed")));
    let Err(error) = observe_ruleset(&sys, &V1Config::default()) else {
        return Err("expected observation error".into());
    };
    assert!(error.to_string().contains("want failed"));
    assert!(error.to_string().contains("live failed"));
    sys.assert_cleaned();
    Ok(())
}

#[test]
fn check_error_is_one_and_violation_beats_exit_down() -> Result<(), Box<dyn Error>> {
    let cfg = V1Config::default();
    let sys = FakeSystem::new();
    sys.set(
        Program::Ip,
        &["-j", "route", "show", "default"],
        "invalid JSON",
    );
    let probe = FakeExitProbe(Cell::new(0));
    let error = run_check(&sys, &topology_source(), &probe, &cfg)
        .err()
        .ok_or("expected check error")?;
    assert_eq!(error.exit_code(), 1);
    assert_eq!(probe.0.get(), 0);
    let sys = FakeSystem::new();
    without_exit(&sys);
    sys.live_results
        .borrow_mut()
        .extend([Ok(output(NFT_EXTRA)), Ok(output(NFT_EXTRA))]);
    assert_eq!(
        run_check(&sys, &topology_source(), &probe, &cfg)?
            .verdict
            .exit_code(),
        2
    );
    assert_eq!(probe.0.get(), 0);
    sys.assert_cleaned();
    Ok(())
}

#[test]
fn oversized_live_ruleset_is_a_difference_without_canon_or_repeat() -> Result<(), Box<dyn Error>> {
    let sys = FakeSystem::new();
    sys.live_results
        .borrow_mut()
        .push_back(Err(ExecError::OutputTooLarge {
            stream: Stream::Stdout,
        }));
    assert_eq!(
        observe_ruleset(&sys, &V1Config::default())?,
        RulesetObs::Differs {
            live_sha256: Sha256::digest(OVERSIZED_LIVE_RULESET).into(),
            want_sha256: Sha256::digest(WANT_NOT_COMPUTED_LIVE_OVERFLOW).into(),
        }
    );
    assert_eq!(sys.calls.borrow().len(), 1);
    assert_eq!(sys.calls.borrow()[0].0, Program::Nft);
    assert!(sys.temp_paths.borrow().is_empty());
    sys.assert_cleaned();
    Ok(())
}

#[test]
fn stderr_and_canon_overflow_are_observation_errors() {
    for live in [false, true] {
        let sys = FakeSystem::new();
        let results = if live {
            &sys.live_results
        } else {
            &sys.canon_results
        };
        results
            .borrow_mut()
            .push_back(Err(ExecError::OutputTooLarge {
                stream: if live { Stream::Stderr } else { Stream::Stdout },
            }));
        assert!(observe_ruleset(&sys, &V1Config::default()).is_err());
        assert_eq!(sys.calls.borrow().len(), 2);
        sys.assert_cleaned();
    }
}

#[test]
fn present_down_exit_with_noop_and_no_address_is_fail_closed() -> Result<(), Box<dyn Error>> {
    for check in [false, true] {
        let sys = FakeSystem::new();
        sys.set(
            Program::Ip,
            &["-d", "-j", "link", "show"],
            include_str!("fixtures/ubuntu-24.04/case-04-ip-link.json"),
        );
        // An address query must be skipped entirely for a down exit.
        sys.push(
            Program::Ip,
            &["-j", "addr", "show", "dev", "proton0"],
            Err(ExecError::spawn("must not query address")),
        );
        for iface in ["wg0", "proton0"] {
            sys.set(
                Program::Tc,
                &["-j", "qdisc", "show", "dev", iface],
                r#"[{"kind":"noop","root":true}]"#,
            );
        }
        let cfg = V1Config::default();
        if check {
            sys.set(
                Program::Wg,
                &["show", "proton0", "latest-handshakes"],
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\t0\n",
            );
            let probe = FakeExitProbe(Cell::new(0));
            assert_eq!(
                run_check(&sys, &topology_source(), &probe, &cfg)?
                    .verdict
                    .exit_code(),
                4
            );
            assert_eq!(probe.0.get(), 0);
        } else {
            let topology = topology_source().observe(&sys, &cfg)?;
            assert_eq!(topology.exit_link, ExitLink::Down);
            assert_eq!(topology.ruleset, RulesetObs::Exact);
            assert_eq!(topology.config_mismatches, Vec::new());
            assert_eq!(topology.tc_hooks, Vec::new());
        }
        assert!(
            !sys.calls
                .borrow()
                .iter()
                .any(|(program, args, _)| *program == Program::Ip
                    && args == &["-j", "addr", "show", "dev", "proton0"])
        );
        sys.assert_cleaned();
    }
    Ok(())
}

#[test]
fn vanished_exit_discards_its_query_errors_and_is_fail_closed() -> Result<(), Box<dyn Error>> {
    for (program, args) in [
        (Program::Ip, vec!["-j", "addr", "show", "dev", "proton0"]),
        (Program::Tc, vec!["-j", "qdisc", "show", "dev", "proton0"]),
        (Program::Tc, vec!["-j", "filter", "show", "dev", "proton0"]),
    ] {
        for check in [false, true] {
            let sys = FakeSystem::new();
            sys.set(
                Program::Ip,
                &["-d", "-j", "link", "show"],
                r#"[{"ifname":"eth0"},{"ifname":"wg0"},{"ifname":"proton0","flags":["UP"]}]"#,
            );
            without_exit(&sys);
            sys.push(program, &args, Ok(failure("No such device")));
            if check {
                sys.push(
                    Program::Wg,
                    &["show", "proton0", "latest-handshakes"],
                    Ok(failure("Unable to access interface: No such device\n")),
                );
                let probe = FakeExitProbe(Cell::new(0));
                assert_eq!(
                    run_check(&sys, &topology_source(), &probe, &V1Config::default())?
                        .verdict
                        .exit_code(),
                    4
                );
                assert_eq!(probe.0.get(), 0);
            } else {
                let topology = topology_source().observe(&sys, &V1Config::default())?;
                assert_eq!(topology.exit_link, ExitLink::Absent);
                assert_eq!(topology.ruleset, RulesetObs::Exact);
                assert_eq!(topology.config_mismatches, Vec::new());
                assert_eq!(topology.tc_hooks, Vec::new());
            }
            assert_eq!(
                sys.calls
                    .borrow()
                    .iter()
                    .filter(|(program, args, _)| *program == Program::Ip
                        && args == &["-d", "-j", "link", "show"])
                    .count(),
                2
            );
            sys.assert_cleaned();
        }
    }
    Ok(())
}

#[test]
fn failed_links_observation_is_code_one_unless_a_violation_is_found() -> Result<(), Box<dyn Error>>
{
    for violation in [false, true] {
        let sys = FakeSystem::new();
        sys.push(
            Program::Ip,
            &["-d", "-j", "link", "show"],
            Err(ExecError::spawn("links failed")),
        );
        if violation {
            sys.set(
                Program::Tc,
                &["-j", "qdisc", "show", "dev", "wg0"],
                r#"[{"kind":"clsact"}]"#,
            );
        }
        let probe = FakeExitProbe(Cell::new(0));
        let result = run_check(&sys, &topology_source(), &probe, &V1Config::default());
        if violation {
            assert_eq!(result?.verdict.exit_code(), 2);
        } else {
            let error = result.err().ok_or("expected links observation error")?;
            assert_eq!(error.exit_code(), 1);
        }
        assert_eq!(probe.0.get(), 0);
        sys.assert_cleaned();
    }
    Ok(())
}

#[test]
fn xdp_on_either_interface_is_a_hook_regardless_of_value() -> Result<(), Box<dyn Error>> {
    let cfg = V1Config::default();
    for iface in [&cfg.client_iface, &cfg.exit_iface] {
        for value in [
            json!(null),
            json!({"mode":"generic"}),
            json!(false),
            json!(0),
        ] {
            let sys = FakeSystem::new();
            let mut links =
                json!([{"ifname":"eth0"},{"ifname":"wg0"},{"ifname":"proton0","flags":["UP"]}]);
            for link in links.as_array_mut().ok_or("fixture array")? {
                if link["ifname"] == iface.as_str() {
                    link["xdp"] = value.clone();
                }
            }
            sys.set(
                Program::Ip,
                &["-d", "-j", "link", "show"],
                &links.to_string(),
            );
            assert_eq!(
                topology_source().observe(&sys, &cfg)?.tc_hooks,
                std::slice::from_ref(iface)
            );
            sys.assert_cleaned();
        }
    }
    Ok(())
}

#[derive(Default)]
struct FakeLegacyTables {
    values: BTreeMap<&'static str, Result<String, io::ErrorKind>>,
    paths: RefCell<Vec<PathBuf>>,
}

impl LegacyTablesReader for FakeLegacyTables {
    fn read(&self, path: &Path) -> io::Result<String> {
        self.paths.borrow_mut().push(path.to_owned());
        self.values
            .get(path.to_str().unwrap_or_default())
            .cloned()
            .unwrap_or(Err(io::ErrorKind::NotFound))
            .map_err(Into::into)
    }
}

const LEGACY_PATHS: [&str; 3] = [
    "/proc/net/ip_tables_names",
    "/proc/net/ip6_tables_names",
    "/proc/net/arp_tables_names",
];

#[test]
fn captured_legacy_mangle_table_is_reported() -> Result<(), Box<dyn Error>> {
    let reader = FakeLegacyTables {
        values: BTreeMap::from([(
            LEGACY_PATHS[0],
            Ok(include_str!("fixtures/ubuntu-24.04/case-11-ip-tables-names.txt").into()),
        )]),
        ..FakeLegacyTables::default()
    };
    let sys = FakeSystem::new();
    let topology = HostTopology::with_legacy_reader(&reader).observe(&sys, &V1Config::default())?;
    assert_eq!(topology.legacy_tables, ["mangle"]);
    assert_eq!(*reader.paths.borrow(), LEGACY_PATHS.map(PathBuf::from));
    sys.assert_cleaned();
    Ok(())
}

#[test]
fn legacy_tables_missing_empty_and_whitespace_are_clean() -> Result<(), Box<dyn Error>> {
    for text in [None, Some(""), Some(" \t\n")] {
        let reader = FakeLegacyTables {
            values: text
                .map(|text| {
                    LEGACY_PATHS
                        .into_iter()
                        .map(|path| (path, Ok(text.into())))
                        .collect()
                })
                .unwrap_or_default(),
            ..FakeLegacyTables::default()
        };
        let sys = FakeSystem::new();
        let topology =
            HostTopology::with_legacy_reader(&reader).observe(&sys, &V1Config::default())?;
        assert_eq!(topology.legacy_tables, Vec::<String>::new());
        assert_eq!(*reader.paths.borrow(), LEGACY_PATHS.map(PathBuf::from));
        sys.assert_cleaned();
    }
    Ok(())
}

#[test]
fn legacy_tables_in_each_family_are_violations_and_names_are_bounded() -> Result<(), Box<dyn Error>>
{
    for path in LEGACY_PATHS {
        let reader = FakeLegacyTables {
            values: BTreeMap::from([(path, Ok("filter\nnat\n".into()))]),
            ..FakeLegacyTables::default()
        };
        let sys = FakeSystem::new();
        let source = HostTopology::with_legacy_reader(&reader);
        assert_eq!(
            source.observe(&sys, &V1Config::default())?.legacy_tables,
            ["filter", "nat"]
        );
        let probe = FakeExitProbe(Cell::new(0));
        assert_eq!(
            run_check(&sys, &source, &probe, &V1Config::default())?
                .verdict
                .exit_code(),
            2
        );
        assert_eq!(probe.0.get(), 0);
        sys.assert_cleaned();
    }
    let reader = FakeLegacyTables {
        values: LEGACY_PATHS
            .into_iter()
            .map(|path| (path, Ok(format!("{} a b c d e f g h i j", "é".repeat(100)))))
            .collect(),
        ..FakeLegacyTables::default()
    };
    let sys = FakeSystem::new();
    let names = HostTopology::with_legacy_reader(&reader)
        .observe(&sys, &V1Config::default())?
        .legacy_tables;
    assert_eq!(names.len(), 8);
    assert_eq!(names[0], "é".repeat(32));
    assert!(names.iter().all(|name| name.chars().count() <= 32));
    assert_eq!(*reader.paths.borrow(), LEGACY_PATHS.map(PathBuf::from));
    sys.assert_cleaned();
    Ok(())
}

#[test]
fn legacy_read_errors_are_observation_errors_but_known_tables_win() -> Result<(), Box<dyn Error>> {
    for path in LEGACY_PATHS {
        for kind in [io::ErrorKind::PermissionDenied, io::ErrorKind::InvalidData] {
            let reader = FakeLegacyTables {
                values: BTreeMap::from([(path, Err(kind))]),
                ..FakeLegacyTables::default()
            };
            let sys = FakeSystem::new();
            assert!(
                HostTopology::with_legacy_reader(&reader)
                    .observe(&sys, &V1Config::default())
                    .is_err()
            );
            assert_eq!(*reader.paths.borrow(), LEGACY_PATHS.map(PathBuf::from));
            sys.assert_cleaned();
        }
    }
    let reader = FakeLegacyTables {
        values: BTreeMap::from([
            (LEGACY_PATHS[0], Err(io::ErrorKind::PermissionDenied)),
            (LEGACY_PATHS[1], Ok("filter".into())),
        ]),
        ..FakeLegacyTables::default()
    };
    let sys = FakeSystem::new();
    assert_eq!(
        HostTopology::with_legacy_reader(&reader)
            .observe(&sys, &V1Config::default())?
            .legacy_tables,
        ["filter"]
    );
    sys.assert_cleaned();
    Ok(())
}

#[test]
fn combined_errors_preserve_later_setup_classification() {
    let sys = FakeSystem::new();
    sys.set(Program::Ip, &["-d", "-j", "link", "show"], "invalid JSON");
    sys.push(
        Program::Ip,
        &["-j", "route", "show", "default"],
        Ok(failure("Operation not permitted")),
    );
    assert!(matches!(
        topology_source().observe(&sys, &V1Config::default()),
        Err(ProbeError::Setup(_))
    ));
    sys.assert_cleaned();

    let sys = FakeSystem::new();
    sys.canon_results
        .borrow_mut()
        .push_back(Ok(failure("want failed")));
    sys.live_results
        .borrow_mut()
        .push_back(Ok(failure("Permission denied")));
    assert!(matches!(
        observe_ruleset(&sys, &V1Config::default()),
        Err(ProbeError::Setup(_))
    ));
    sys.assert_cleaned();
}

#[test]
fn relative_temp_dir_is_setup_error() -> Result<(), Box<dyn Error>> {
    let output = std::process::Command::new(std::env::current_exe()?)
        .args([
            "--ignored",
            "--exact",
            "relative_temp_dir_fixture",
            "--nocapture",
        ])
        .env("TMPDIR", "relative-canon-temp")
        .output()?;
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

#[test]
#[ignore = "subprocess fixture"]
fn relative_temp_dir_fixture() {
    assert!(!std::env::temp_dir().is_absolute());
    let sys = FakeSystem::new();
    assert!(matches!(
        observe_ruleset(&sys, &V1Config::default()),
        Err(ProbeError::Setup(_))
    ));
    assert!(
        sys.calls
            .borrow()
            .iter()
            .all(|call| call.0 != Program::Unshare)
    );
    assert!(!Path::new("relative-canon-temp").exists());
}

#[test]
fn exit_query_errors_recheck_links_only_once_and_preserve_other_errors()
-> Result<(), Box<dyn Error>> {
    for vanished in [false, true] {
        let sys = FakeSystem::new();
        if vanished {
            sys.set(
                Program::Ip,
                &["-d", "-j", "link", "show"],
                r#"[{"ifname":"eth0"},{"ifname":"wg0"},{"ifname":"proton0","flags":["UP"]}]"#,
            );
            without_exit(&sys);
            sys.push(
                Program::Ip,
                &["-j", "route", "show", "default"],
                Err(ExecError::spawn("unrelated route failure")),
            );
        }
        for (program, args) in [
            (Program::Ip, vec!["-j", "addr", "show", "dev", "proton0"]),
            (Program::Tc, vec!["-j", "qdisc", "show", "dev", "proton0"]),
            (Program::Tc, vec!["-j", "filter", "show", "dev", "proton0"]),
        ] {
            sys.push(program, &args, Err(ExecError::spawn("exit query failed")));
        }
        let error = topology_source()
            .observe(&sys, &V1Config::default())
            .err()
            .ok_or("expected observation error")?;
        if vanished {
            assert!(error.to_string().contains("unrelated route failure"));
            assert!(!error.to_string().contains("exit query failed"));
            assert!(
                !sys.calls
                    .borrow()
                    .iter()
                    .any(|(program, args, _)| *program == Program::Tc
                        && args.iter().any(|arg| arg == "proton0"))
            );
        } else {
            assert!(error.to_string().contains("exit query failed"));
        }
        assert_eq!(
            sys.calls
                .borrow()
                .iter()
                .filter(|(program, args, _)| *program == Program::Ip
                    && args == &["-d", "-j", "link", "show"])
                .count(),
            2
        );
        sys.assert_cleaned();
    }
    Ok(())
}

#[test]
fn exit_appearing_after_topology_never_reaches_availability_stages() -> Result<(), Box<dyn Error>> {
    let sys = FakeSystem::new();
    without_exit(&sys);
    healthy_path(&sys);
    let probe = FakeExitProbe(Cell::new(0));
    let report = run_check(&sys, &topology_source(), &probe, &V1Config::default())?;
    assert_eq!(
        report.verdict,
        Verdict::FailClosed(FailClosed::ExitLinkNotUp)
    );
    assert_eq!(report.verdict.exit_code(), 4);
    assert_eq!(probe.0.get(), 0);
    assert!(!sys.calls.borrow().iter().any(|(program, args, _)| {
        (*program == Program::Wg && args.iter().any(|arg| arg == "latest-handshakes"))
            || (*program == Program::Ip && args.first().is_some_and(|arg| arg == "route"))
    }));
    sys.assert_cleaned();
    Ok(())
}

#[test]
fn failed_links_uses_address_flags_to_decide_missing_exit_address() -> Result<(), Box<dyn Error>> {
    for up in [false, true] {
        let sys = FakeSystem::new();
        sys.push(
            Program::Ip,
            &["-d", "-j", "link", "show"],
            Err(ExecError::spawn("links failed")),
        );
        let addr = json!([{"ifname":"proton0", "flags": if up { vec!["UP"] } else { vec!["POINTOPOINT"] }, "addr_info":[]}]);
        sys.set(
            Program::Ip,
            &["-j", "addr", "show", "dev", "proton0"],
            &addr.to_string(),
        );
        let probe = FakeExitProbe(Cell::new(0));
        let result = run_check(&sys, &topology_source(), &probe, &V1Config::default());
        if up {
            assert_eq!(result?.verdict.exit_code(), 2);
        } else {
            let error = result.err().ok_or("expected links observation error")?;
            assert_eq!(error.exit_code(), 1);
            assert!(error.to_string().contains("links failed"));
        }
        assert_eq!(probe.0.get(), 0);
        sys.assert_cleaned();
    }
    Ok(())
}

#[test]
fn exit_down_in_address_observation_cannot_be_reported_up() -> Result<(), Box<dyn Error>> {
    let sys = FakeSystem::new();
    sys.set(
        Program::Ip,
        &["-j", "addr", "show", "dev", "proton0"],
        include_str!("fixtures/ubuntu-24.04/case-04-ip-addr-proton0.json"),
    );
    let topology = topology_source().observe(&sys, &V1Config::default())?;
    assert_eq!(topology.exit_link, ExitLink::Down);
    assert_eq!(topology.config_mismatches, Vec::new());
    sys.assert_cleaned();
    Ok(())
}
