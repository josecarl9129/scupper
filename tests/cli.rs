//! In-process command tests; no host utilities or privileged paths are touched.

use std::{
    cell::{Cell, RefCell},
    collections::VecDeque,
    io::{self, Write},
    net::IpAddr,
    path::{Path, PathBuf},
    rc::Rc,
    time::Duration,
};

use scupper::{
    apply::{Fs, TempFile},
    check::{ExitProbe, TopologySource},
    cli::{self, Dependencies, Privilege, Prompt, Sleeper, UnimplementedTopology},
    rules::V1Config,
    system::{EXEC_TIMEOUT, ExecError, ExecOutput, Program, System},
    verdict::{M1Topology, Probe, ProbeError, RulesetObs},
};

#[derive(Default)]
struct FakeFs {
    writes: Cell<usize>,
}

impl Fs for FakeFs {
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
    fn set_mode(&self, _: &Path, mode: u32) -> io::Result<()> {
        assert_eq!(mode, 0o644);
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
    fs: FakeFs,
    root: bool,
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
            fs: FakeFs::default(),
            root: true,
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
            self.now
                .set(self.now.get() + self.wg_delay.min(timeout.as_secs()));
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
    fn sleep(&self, duration: Duration) {
        self.now.set(self.now.get() + duration.as_secs());
    }
}
impl TopologySource for Harness {
    fn observe(&self, _: &dyn System, _: &V1Config) -> Probe<M1Topology> {
        Ok(M1Topology {
            ruleset: RulesetObs::Exact,
            tc_hooks: vec![],
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
                system: self,
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
                ruleset: RulesetObs::Missing,
                tc_hooks: vec![],
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
    assert_eq!(out, include_str!("golden/ruleset.golden"));
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
    for call in &calls[1..] {
        assert_eq!(call.program, Program::Wg);
        assert_eq!(call.args, ["show", "proton0", "latest-handshakes"]);
        assert_eq!(call.timeout, EXEC_TIMEOUT);
    }
}

#[test]
fn connect_times_out_fail_closed() {
    let h = Harness::default();
    h.output("");
    for _ in 0..10 {
        h.handshake(0);
    }
    let (code, out, err) = h.run(&["connect"]);
    assert_eq!(code, 4, "{err}");
    assert!(out.contains("fail closed"));
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
        let (code, _, err) = h.run(&args);
        assert_eq!(code, 1);
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
    assert_eq!(code, 4, "{err}");
    assert!(out.contains("fail closed"));
    assert_eq!(h.now.get(), 1_010);
    let calls = h.calls.borrow();
    assert_eq!(calls.len(), 4);
    assert_eq!(calls[3].timeout, Duration::from_secs(2));
}
