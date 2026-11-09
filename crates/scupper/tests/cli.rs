//! In-process command tests; no host utilities or privileged paths are touched.

use std::{
    cell::{Cell, RefCell},
    collections::VecDeque,
    io::{self, Write},
    net::IpAddr,
    path::{Path, PathBuf},
    rc::Rc,
    time::{Duration, Instant},
};

use scupper::{
    apply::{Fs, TempFile},
    check::{ExitProbe, TopologySource},
    cli::{self, Dependencies, NamespaceReader, Privilege, Prompt, Sleeper, UnimplementedTopology},
    rules::V1Config,
    system::{EXEC_TIMEOUT, ExecError, ExecOutput, Program, SYSTEMCTL_TIMEOUT, System},
    verdict::{ExitLink, M1Topology, Probe, ProbeError, RulesetObs},
};

#[derive(Default)]
struct FakeFs {
    writes: Cell<usize>,
}

impl Fs for FakeFs {
    fn check_target(&self, _: &Path) -> io::Result<()> {
        Ok(())
    }
    fn cleanup_stale(&self, _: &Path) -> io::Result<()> {
        Ok(())
    }

    fn read(&self, _: &Path) -> io::Result<String> {
        Err(io::ErrorKind::NotFound.into())
    }
    fn create_temp(&self, _: &Path) -> io::Result<(PathBuf, Box<dyn TempFile>)> {
        self.writes.set(self.writes.get() + 1);
        Ok(("/etc/.fake.tmp".into(), Box::new(FakeFile(Vec::new()))))
    }
    fn rename(&self, _: &Path, _: &Path) -> io::Result<()> {
        Ok(())
    }
    fn sync_dir(&self, _: &Path) -> io::Result<()> {
        Ok(())
    }
    fn remove(&self, _: &Path) -> io::Result<()> {
        Ok(())
    }
}

struct FakeFile(Vec<u8>);
impl Write for FakeFile {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.0.write(data)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl TempFile for FakeFile {
    fn set_mode(&self, mode: u32) -> io::Result<()> {
        assert_eq!(mode, 0o644);
        Ok(())
    }

    fn sync_all(&self) -> io::Result<()> {
        Ok(())
    }
}

struct Call {
    program: Program,
    args: Vec<String>,
    timeout: Duration,
}

struct Harness {
    responses: RefCell<VecDeque<Result<ExecOutput, ExecError>>>,
    calls: RefCell<Vec<Call>>,
    now: Rc<Cell<u64>>,
    wg_delay: u64,
    wall_step: i64,
    monotonic: Cell<Duration>,
    epoch: Instant,
    topology_calls: Cell<usize>,
    fs: FakeFs,
    root: bool,
    self_netns: Option<&'static str>,
    pid1_netns: Option<&'static str>,
    tty: bool,
    answer: bool,
    prompt_error: Option<&'static str>,
    prompts: RefCell<Vec<String>>,
}

impl Default for Harness {
    fn default() -> Self {
        Self {
            responses: RefCell::default(),
            calls: RefCell::default(),
            now: Rc::new(Cell::new(1_000)),
            wg_delay: 0,
            wall_step: 0,
            monotonic: Cell::new(Duration::ZERO),
            epoch: Instant::now(),
            topology_calls: Cell::new(0),
            fs: FakeFs::default(),
            root: true,
            self_netns: Some("net:[123]"),
            pid1_netns: Some("net:[456]"),
            tty: false,
            answer: true,
            prompt_error: None,
            prompts: RefCell::default(),
        }
    }
}

impl System for Harness {
    fn run(
        &self,
        program: Program,
        args: &[String],
        timeout: Duration,
    ) -> Result<ExecOutput, ExecError> {
        self.calls.borrow_mut().push(Call {
            program,
            args: args.to_vec(),
            timeout,
        });
        if program == Program::Wg {
            let delay = self.wg_delay.min(timeout.as_secs());
            self.monotonic
                .set(self.monotonic.get() + Duration::from_secs(delay));
            self.now
                .set((self.now.get() + delay).saturating_add_signed(self.wall_step));
        }
        self.responses
            .borrow_mut()
            .pop_front()
            .unwrap_or_else(|| Err(ExecError::spawn("unexpected command")))
    }
    fn now_unix_secs(&self) -> u64 {
        self.now.get()
    }
}
impl NamespaceReader for Harness {
    fn gateway_marker(&self) -> io::Result<bool> {
        Ok(false)
    }
    fn read_namespace(&self, path: &Path) -> io::Result<PathBuf> {
        let value = if path == Path::new("/proc/self/ns/net") {
            self.self_netns
        } else {
            assert_eq!(path, Path::new("/proc/1/ns/net"));
            self.pid1_netns
        };
        value
            .map(PathBuf::from)
            .ok_or_else(|| io::ErrorKind::PermissionDenied.into())
    }
}
impl Privilege for Harness {
    fn is_root(&self) -> bool {
        self.root
    }
}
impl Prompt for Harness {
    fn is_terminal(&self) -> bool {
        self.tty
    }
    fn confirm(&self, question: &str, _: Option<&str>) -> io::Result<bool> {
        self.prompts.borrow_mut().push(question.into());
        if let Some(error) = self.prompt_error {
            return Err(io::Error::other(error));
        }
        Ok(self.answer)
    }
}
impl Sleeper for Harness {
    fn now(&self) -> Instant {
        self.epoch + self.monotonic.get()
    }

    fn sleep(&self, duration: Duration) {
        self.now.set(self.now.get() + duration.as_secs());
        self.monotonic.set(self.monotonic.get() + duration);
    }
}
impl TopologySource for Harness {
    fn observe(&self, _: &dyn System, _: &V1Config) -> Probe<M1Topology> {
        self.topology_calls.set(self.topology_calls.get() + 1);
        Ok(M1Topology {
            exit_link: ExitLink::Up,
            ruleset: RulesetObs::Exact,
            tc_hooks: vec![],
            legacy_tables: Vec::new(),
            config_mismatches: vec![],
            uplink_addrs: vec![IpAddr::from([192, 0, 2, 10])],
        })
    }
}
impl ExitProbe for Harness {
    fn probe(&self, _: &V1Config) -> Probe<IpAddr> {
        Ok(IpAddr::from([203, 0, 113, 20]))
    }
}
impl Harness {
    fn output(&self, stdout: &str) {
        self.responses.borrow_mut().push_back(Ok(ExecOutput {
            status: Some(0),
            stdout: stdout.into(),
            stderr: String::new(),
        }));
    }
    fn handshake(&self, timestamp: u64) {
        self.output(&format!("{}=\t{timestamp}\n", "A".repeat(43)));
    }
    fn run(&self, args: &[&str]) -> (u8, String, String) {
        self.run_topology(args, self)
    }
    fn run_topology(&self, args: &[&str], topology: &dyn TopologySource) -> (u8, String, String) {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = cli::run_with(
            std::iter::once("scupper").chain(args.iter().copied()),
            &Dependencies {
                state_root: Path::new("target/m1-without-head"),
                config_root: Path::new("target/m1-without-head"),
                probe_exec: &scupper::system::RealSystem::default(),
                system: self,
                namespaces: self,
                fs: &self.fs,
                privilege: self,
                prompt: self,
                sleeper: self,
                topology,
                exit_probe: self,
            },
            &mut stdout,
            &mut stderr,
        );
        (
            code,
            String::from_utf8_lossy(&stdout).into_owned(),
            String::from_utf8_lossy(&stderr).into_owned(),
        )
    }
}

#[test]
fn exit_codes_contract() {
    let h = Harness::default();
    for args in [
        vec!["bogus"],
        vec!["check", "--bad"],
        vec!["--nft-path", "/bin/true"],
        vec![],
    ] {
        let (code, out, err) = h.run(&args);
        assert_eq!(code, 1);
        assert_eq!(out, "");
        assert!(err.starts_with("scupper:"));
    }
    for args in [vec!["--help"], vec!["--version"], vec!["apply", "--help"]] {
        let (code, out, err) = h.run(&args);
        assert_eq!(code, 0);
        assert!(out.contains("scupper"));
        assert_eq!(err, "");
    }
    assert!(h.calls.borrow().is_empty());
}

#[test]
fn check_unimplemented_is_1() {
    let h = Harness::default();
    let (code, out, err) = h.run_topology(&["check"], &UnimplementedTopology);
    assert_eq!(code, 1);
    assert_eq!(out, "");
    assert!(err.contains("not implemented in this build"));
    assert!(h.calls.borrow().is_empty());
    assert_eq!(
        cli::UnimplementedExitProbe.probe(&V1Config::default()),
        Err(ProbeError::setup("not implemented in this build"))
    );
}

#[test]
fn check_prints_warnings_to_stderr() {
    let h = Harness {
        root: false,
        ..Harness::default()
    };
    h.handshake(1_003);
    h.output("1.1.1.1 dev proton0");
    let (code, out, err) = h.run(&["check"]);
    assert_eq!(code, 0);
    assert_eq!(
        out,
        "connected through 203.0.113.20, kill switch in place\n"
    );
    assert!(err.starts_with("warning: "));
    assert!(err.contains("clock skew"));
}

#[test]
fn check_verdict_codes() {
    struct Missing;
    impl TopologySource for Missing {
        fn observe(&self, _: &dyn System, _: &V1Config) -> Probe<M1Topology> {
            Ok(M1Topology {
                exit_link: ExitLink::Up,
                ruleset: RulesetObs::Missing,
                tc_hooks: vec![],
                legacy_tables: Vec::new(),
                config_mismatches: vec![],
                uplink_addrs: vec![],
            })
        }
    }
    for (timestamp, route, expected) in [(0, "", 4), (999, "1.1.1.1 dev eth0", 3)] {
        let h = Harness::default();
        h.handshake(timestamp);
        if !route.is_empty() {
            h.output(route);
        }
        assert_eq!(h.run(&["check"]).0, expected);
    }
    assert_eq!(Harness::default().run_topology(&["check"], &Missing).0, 2);
}

#[test]
fn status_always_exits_zero() {
    let h = Harness {
        root: false,
        ..Harness::default()
    };
    let (code, out, err) = h.run_topology(&["status"], &UnimplementedTopology);
    assert_eq!(code, 0);
    assert!(out.contains("client wg0:"));
    assert!(out.contains("not implemented in this build"));
    assert_eq!(err, "");
}

#[test]
fn rules_prints_golden() {
    let (code, out, err) = Harness::default().run(&["rules"]);
    assert_eq!(code, 0);
    assert_eq!(
        out,
        include_str!("../../scupper-core/tests/golden/ruleset.golden")
    );
    assert_eq!(err, "");
}

#[test]
fn root_required() {
    for command in ["connect", "disconnect", "apply"] {
        let h = Harness {
            root: false,
            ..Harness::default()
        };
        let (code, _, err) = h.run(&[command]);
        assert_eq!(code, 1);
        assert_eq!(err, format!("scupper: {command} must run as root\n"));
        assert!(h.calls.borrow().is_empty());
        assert_eq!(h.fs.writes.get(), 0);
        assert!(h.prompts.borrow().is_empty());
    }
}

#[test]
fn noninteractive_requires_yes() {
    for command in ["disconnect", "apply"] {
        let h = Harness::default();
        let (code, _, err) = h.run(&[command]);
        assert_eq!(code, 1);
        assert!(err.contains("--yes"));
        assert!(h.calls.borrow().is_empty());
        assert_eq!(h.fs.writes.get(), 0);
        assert!(
            h.prompts.borrow().is_empty(),
            "non-TTY must never read stdin"
        );
        h.output("");
        if command == "apply" {
            h.output("");
        }
        let (code, _, err) = h.run(&[command, "--yes"]);
        assert_eq!(code, 0, "{err}");
        assert!(!h.calls.borrow().is_empty());
        assert!(h.prompts.borrow().is_empty());
    }
}

#[test]
fn connect_polls_until_fresh() {
    let h = Harness::default();
    h.output("");
    h.handshake(0);
    h.handshake(800);
    h.handshake(1_001);
    let (code, _, err) = h.run(&["connect"]);
    assert_eq!(code, 0, "{err}");
    assert_eq!(h.now.get(), 1_002);
    let calls = h.calls.borrow();
    assert_eq!(calls.len(), 4);
    assert_eq!(calls[0].program, Program::Systemctl);
    assert_eq!(calls[0].args, ["start", "wg-quick@proton0"]);
    assert_eq!(calls[0].timeout, SYSTEMCTL_TIMEOUT);
    for call in &calls[1..] {
        assert_eq!(call.program, Program::Wg);
        assert_eq!(call.args, ["show", "proton0", "latest-handshakes"]);
        assert_eq!(call.timeout, EXEC_TIMEOUT);
    }
}

#[test]
fn connect_times_out_degraded() {
    let h = Harness::default();
    h.output("");
    for _ in 0..10 {
        h.handshake(0);
    }
    let (code, out, err) = h.run(&["connect"]);
    assert_eq!(code, 3, "{err}");
    assert!(out.contains("no fresh handshake"));
    assert_eq!(h.now.get(), 1_010);
    let calls = h.calls.borrow();
    assert_eq!(calls.len(), 11);
    assert_eq!(calls[10].timeout, Duration::from_secs(1));
}

#[test]
fn disconnect_stops_unit() {
    let h = Harness::default();
    h.output("");
    let (code, out, err) = h.run(&["disconnect", "--yes"]);
    assert_eq!(code, 0, "{err}");
    assert_eq!(out, "traffic is now blocked\n");
    let calls = h.calls.borrow();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].program, Program::Systemctl);
    assert_eq!(calls[0].args, ["stop", "wg-quick@proton0"]);
    assert_eq!(calls[0].timeout, SYSTEMCTL_TIMEOUT);
    assert_eq!(h.topology_calls.get(), 1);
    assert_eq!(Program::Systemctl.default_path(), "/usr/bin/systemctl");
}

#[test]
fn tty_confirmation_and_cancellation() {
    for (answer, prompt_error) in [(false, false), (true, true)] {
        for command in ["disconnect", "apply"] {
            let h = Harness {
                tty: true,
                answer,
                prompt_error: prompt_error.then_some("prompt failed"),
                ..Harness::default()
            };
            assert_eq!(h.run(&[command]).0, 1);
            assert!(h.calls.borrow().is_empty());
            assert_eq!(h.fs.writes.get(), 0);
            assert_eq!(h.prompts.borrow().len(), 1);
        }
    }
    let h = Harness {
        tty: true,
        ..Harness::default()
    };
    h.output("");
    assert_eq!(h.run(&["disconnect"]).0, 0);
    assert_eq!(*h.prompts.borrow(), ["Block all client traffic now? [y/N]"]);
}

#[test]
fn command_and_observation_errors_are_1() {
    for args in [vec!["connect"], vec!["disconnect", "--yes"]] {
        let h = Harness::default();
        h.responses.borrow_mut().push_back(Ok(ExecOutput {
            status: Some(1),
            stdout: String::new(),
            stderr: "unit failed".into(),
        }));
        let (code, out, err) = h.run(&args);
        assert_eq!(code, 1);
        assert_eq!(out, "");
        assert_eq!(h.topology_calls.get(), 0);
        assert!(err.starts_with("scupper:"));
        assert!(err.contains("unit failed"));
    }
    let h = Harness::default();
    h.output("");
    assert_eq!(h.run(&["connect"]).0, 1);
}

#[test]
fn connect_command_time_counts_toward_deadline() {
    let h = Harness {
        wg_delay: 3,
        ..Harness::default()
    };
    h.output("");
    h.handshake(0);
    h.handshake(0);
    h.responses.borrow_mut().push_back(Err(ExecError::Timeout {
        after: Duration::from_secs(2),
    }));
    let (code, out, err) = h.run(&["connect"]);
    assert_eq!(code, 3, "{err}");
    assert!(out.contains("no fresh handshake"));
    assert_eq!(h.now.get(), 1_010);
    let calls = h.calls.borrow();
    assert_eq!(calls.len(), 4);
    assert_eq!(calls[3].timeout, Duration::from_secs(2));
}

#[test]
fn confirmation_parsing_defaults_to_no() {
    for answer in ["y", "yes", "Y", "YES", " YeS ", "  y\n"] {
        assert!(cli::parse_confirmation(answer), "{answer:?}");
    }
    // read_line returns an empty string on EOF.
    for answer in [
        "",
        "\n",
        " \t\n",
        "no",
        "n",
        "yeah",
        "yes please",
        "true",
        "1",
    ] {
        assert!(!cli::parse_confirmation(answer), "{answer:?}");
    }
}

#[test]
fn disconnect_unknown_protection_is_1() {
    let h = Harness::default();
    h.output("");
    let (code, out, err) = h.run_topology(&["disconnect", "--yes"], &UnimplementedTopology);
    assert_eq!(code, 1);
    assert_eq!(out, "");
    assert_eq!(
        err,
        "exit tunnel stopped; kill switch state unknown, run 'scupper check'\n"
    );
}

#[test]
fn disconnect_checks_every_topology_violation_and_observation_error() -> Result<(), ProbeError> {
    struct Topology(Probe<M1Topology>);
    impl TopologySource for Topology {
        fn observe(&self, _: &dyn System, _: &V1Config) -> Probe<M1Topology> {
            self.0.clone()
        }
    }
    let cfg = V1Config::default();
    let clean = Harness::default().observe(&Harness::default(), &cfg);
    for kind in 0..4 {
        let mut topology = clean.clone()?;
        match kind {
            0 => topology.ruleset = RulesetObs::Missing,
            1 => {
                topology.ruleset = RulesetObs::Differs {
                    live_sha256: [1; 32],
                    want_sha256: [2; 32],
                }
            }
            2 => topology.tc_hooks.push(cfg.client_iface.clone()),
            _ => topology
                .config_mismatches
                .push(scupper::verdict::ConfigMismatch::ExitAddrNotOnExitIface),
        }
        let h = Harness::default();
        h.output("");
        let (code, out, err) = h.run_topology(&["disconnect", "--yes"], &Topology(Ok(topology)));
        assert_eq!(code, 2);
        assert_eq!(out, "");
        assert!(err.contains("exit tunnel stopped; kill switch is NOT in place"));
        assert_eq!(h.calls.borrow().len(), 1);
    }
    for error in [
        ProbeError::Timeout,
        ProbeError::io("permission denied"),
        ProbeError::setup("not implemented"),
    ] {
        let h = Harness::default();
        h.output("");
        let (code, out, err) = h.run_topology(&["disconnect", "--yes"], &Topology(Err(error)));
        assert_eq!(code, 1);
        assert_eq!(out, "");
        assert_eq!(
            err,
            "exit tunnel stopped; kill switch state unknown, run 'scupper check'\n"
        );
    }
    Ok(())
}

#[test]
fn connect_deadline_ignores_wall_clock_steps() {
    for wall_step in [-100, 100] {
        let h = Harness {
            wall_step,
            ..Harness::default()
        };
        h.output("");
        for _ in 0..10 {
            h.handshake(0);
        }
        let (code, out, err) = h.run(&["connect"]);
        assert_eq!(code, 3, "{err}");
        assert!(out.contains("no fresh handshake"));
        assert_eq!(h.monotonic.get(), Duration::from_secs(10));
        assert_eq!(h.calls.borrow().len(), 11);
    }
}

#[test]
fn connect_reuses_verdict_freshness_bounds() {
    for (timestamp, expected) in [(820, 0), (819, 3), (1_005, 0), (1_006, 3), (0, 3)] {
        let h = Harness::default();
        h.output("");
        h.handshake(timestamp);
        // Only the first poll can accept; a rejected timestamp must not end polling.
        for _ in 1..10 {
            h.handshake(0);
        }
        let (code, _, err) = h.run(&["connect"]);
        assert_eq!(code, expected, "timestamp {timestamp}: {err}");
        assert_eq!(err.contains("clock skew"), timestamp > 1_000);
        assert_eq!(err.lines().count(), usize::from(timestamp > 1_000));
    }
}

#[test]
fn canon_is_hidden_and_requires_one_path() {
    let h = Harness::default();
    let (code, out, err) = h.run(&["--help"]);
    assert_eq!(code, 0);
    assert!(!out.contains("canon"));
    assert_eq!(err, "");
    for args in [
        vec!["canon"],
        vec!["canon", "one"],
        vec!["canon", "--outer-netns", "net:[789]", "one", "two"],
    ] {
        let (code, out, err) = h.run(&args);
        assert_eq!(code, 1);
        assert_eq!(out, "");
        assert_ne!(err, "");
    }
    assert!(h.calls.borrow().is_empty());
}

#[test]
fn canon_namespace_guards_run_before_any_system_calls() {
    for (current, pid1) in [
        (Some("net:[789]"), Some("net:[456]")),
        (None, Some("net:[456]")),
        (Some("net:[123]"), Some("net:[123]")),
    ] {
        let h = Harness {
            self_netns: current,
            pid1_netns: pid1,
            ..Harness::default()
        };
        let (code, out, err) = h.run(&[
            "canon",
            "--outer-netns",
            "net:[789]",
            "/private/ruleset.nft",
        ]);
        assert_eq!(code, 1);
        assert_eq!(out, "");
        assert!(err.contains("canon:"));
        assert!(h.calls.borrow().is_empty());
    }
}

#[test]
fn canon_unreadable_pid1_is_optional_and_empty_ruleset_precedes_load() {
    let h = Harness {
        pid1_netns: None,
        ..Harness::default()
    };
    h.output(r#"{"nftables":[{"metainfo":{"version":"1"}}]}"#);
    h.output("");
    h.output(r#"{"nftables":[{"table":{"name":"scupper","family":"inet"}}]}"#);
    let (code, out, err) = h.run(&[
        "canon",
        "--outer-netns",
        "net:[789]",
        "/private/ruleset.nft",
    ]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("scupper"));
    let calls = h.calls.borrow();
    assert_eq!(calls.len(), 3);
    assert!(calls.iter().all(|call| call.program == Program::Nft));
    assert_eq!(calls[0].args, ["-j", "list", "ruleset"]);
    assert_eq!(calls[1].args, ["-f", "/private/ruleset.nft"]);
    assert_eq!(calls[2].args, calls[0].args);
}

#[test]
fn canon_refuses_nonempty_or_unreadable_preload_ruleset() {
    for before in [
        r#"{"nftables":[{"table":{"family":"inet","name":"foreign"}}]}"#,
        r#"{"nftables":[{"metainfo":{},"table":{}}]}"#,
        r#"{"nftables":[null]}"#,
        r#"{"nftables":[{"metainfo":null}]}"#,
        "{}",
        "invalid JSON",
    ] {
        let h = Harness::default();
        h.output(before);
        let (code, out, err) = h.run(&[
            "canon",
            "--outer-netns",
            "net:[789]",
            "/private/ruleset.nft",
        ]);
        assert_eq!(code, 1);
        assert_eq!(out, "");
        assert!(err.contains("canon:"));
        let calls = h.calls.borrow();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].args, ["-j", "list", "ruleset"]);
    }
}

#[test]
fn canon_rejects_malformed_outer_namespace_before_system_calls() {
    for outer in [
        "net:[]",
        "net:[12a]",
        "mnt:[1]",
        "",
        "net:[1]/",
        "net:[１２]",
        "net:[+1]",
        " net:[1]",
    ] {
        let h = Harness::default();
        let (code, out, err) = h.run(&["canon", "--outer-netns", outer, "/private/ruleset.nft"]);
        assert_eq!(code, 1, "{outer:?}");
        assert_eq!(out, "");
        assert_ne!(err, "");
        // Clap rejects an empty PathBuf before the canon guard runs.
        if !outer.is_empty() {
            assert!(err.contains("outer network namespace must be"), "{err}");
        }
        assert!(h.calls.borrow().is_empty());
    }
}

#[test]
fn m1_json_check_is_rejected_without_running_host_checks() {
    let h = Harness::default();
    let (code, out, _) = h.run(&["check", "--json"]);
    assert_eq!(code, 1);
    assert!(out.contains("check --json requires an M2 layout"));
    assert!(h.calls.borrow().is_empty());
}
