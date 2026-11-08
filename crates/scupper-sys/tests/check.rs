//! Driver ordering, fail-closed parity and independently rendered status.
//! Synthetic handshakes use controlled timestamps for age and clock-skew cases;
//! alternate devices and malformed outputs cover cases absent from lab captures.

use std::{
    cell::{Cell, RefCell},
    error::Error,
    net::IpAddr,
    rc::Rc,
    time::Duration,
};

use scupper_sys::{
    check::{
        ExitProbe, KillSwitchStatus, TopologySource, observe_handshake, observe_route, run_check,
        run_status,
    },
    parse::{Handshake, HandshakeAge, route_probe_argv},
    rules::V1Config,
    system::{EXEC_TIMEOUT, ExecError, ExecOutput, Program, Stream, System, testing::FakeSystem},
    verdict::{
        ConfigMismatch, ExitLink, M1Topology, Probe, ProbeError, RulesetObs, Stage, Verdict,
    },
};

type Log = Rc<RefCell<Vec<&'static str>>>;

struct LoggedSystem {
    fake: FakeSystem,
    log: Log,
}

impl System for LoggedSystem {
    fn run(
        &self,
        program: Program,
        args: &[String],
        timeout: Duration,
    ) -> Result<ExecOutput, ExecError> {
        self.log.borrow_mut().push(match program {
            Program::Wg => "wg",
            Program::Ip => "ip",
            Program::Nft => "nft",
            Program::Tc => "tc",
            Program::Systemctl => "systemctl",
            Program::Unshare => "unshare",
        });
        self.fake.run(program, args, timeout)
    }

    fn now_unix_secs(&self) -> u64 {
        self.fake.now_unix_secs()
    }
}

struct FakeTopology {
    result: Probe<M1Topology>,
    log: Log,
}

impl TopologySource for FakeTopology {
    fn observe(&self, _sys: &dyn System, _cfg: &V1Config) -> Probe<M1Topology> {
        self.log.borrow_mut().push("topology");
        self.result.clone()
    }
}

struct FakeExitProbe {
    result: Probe<IpAddr>,
    log: Log,
}

impl ExitProbe for FakeExitProbe {
    fn probe(&self, _cfg: &V1Config) -> Probe<IpAddr> {
        self.log.borrow_mut().push("exit probe");
        self.result.clone()
    }
}

struct Harness {
    sys: LoggedSystem,
    topo: FakeTopology,
    probe: FakeExitProbe,
    cfg: V1Config,
    log: Log,
}

impl Harness {
    fn new() -> Self {
        let log = Log::default();
        Self {
            sys: LoggedSystem {
                fake: FakeSystem::new(1_000),
                log: log.clone(),
            },
            topo: FakeTopology {
                result: Ok(M1Topology {
                    exit_link: ExitLink::Up,
                    ruleset: RulesetObs::Exact,
                    tc_hooks: vec![],
                    legacy_tables: Vec::new(),
                    config_mismatches: vec![],
                    uplink_addrs: vec![IpAddr::from([192, 0, 2, 10])],
                }),
                log: log.clone(),
            },
            probe: FakeExitProbe {
                result: Ok(IpAddr::from([203, 0, 113, 20])),
                log: log.clone(),
            },
            cfg: V1Config::default(),
            log,
        }
    }

    fn exit_handshake(&self, result: Result<ExecOutput, ExecError>) {
        self.sys
            .fake
            .push(Program::Wg, &wg_args(self.cfg.exit_iface.as_str()), result);
    }

    fn client_handshake(&self, result: Result<ExecOutput, ExecError>) {
        self.sys.fake.push(
            Program::Wg,
            &wg_args(self.cfg.client_iface.as_str()),
            result,
        );
    }

    fn route(&self, result: Result<ExecOutput, ExecError>) {
        self.sys
            .fake
            .push(Program::Ip, &route_probe_argv(&self.cfg), result);
    }

    fn healthy_path(&self, device: &str) {
        self.exit_handshake(Ok(output(&handshake('A', 988))));
        let route = if device == "proton0" {
            include_str!("fixtures/ubuntu-24.04/ip-policy-route.txt").to_owned()
        } else {
            format!("192.0.2.1 dev {device}")
        };
        self.route(Ok(output(&route)));
    }

    fn assert_log(&self, expected: &[&str]) {
        assert_eq!(*self.log.borrow(), expected);
        assert!(
            self.sys
                .fake
                .calls()
                .iter()
                .all(|call| call.timeout == EXEC_TIMEOUT)
        );
    }
}

fn wg_args(iface: &str) -> Vec<String> {
    ["show", iface, "latest-handshakes"]
        .map(str::to_owned)
        .into()
}

fn handshake(last: char, timestamp: u64) -> String {
    format!("{}{last}=\t{timestamp}\n", "A".repeat(42))
}

fn output(stdout: &str) -> ExecOutput {
    ExecOutput {
        status: Some(0),
        stdout: stdout.into(),
        stderr: String::new(),
    }
}

fn failure(code: Option<i32>, stderr: &str) -> ExecOutput {
    ExecOutput {
        status: code,
        stdout: String::new(),
        stderr: stderr.into(),
    }
}

#[test]
fn check_connected() -> Result<(), Box<dyn Error>> {
    let h = Harness::new();
    h.healthy_path("proton0");
    let report = run_check(&h.sys, &h.topo, &h.probe, &h.cfg)?;
    assert!(matches!(report.verdict, Verdict::Protected { .. }));
    assert_eq!(report.verdict.exit_code(), 0);
    h.assert_log(&["topology", "wg", "ip", "exit probe"]);
    Ok(())
}

#[test]
fn check_bug4_route_via_uplink() -> Result<(), Box<dyn Error>> {
    let h = Harness::new();
    h.healthy_path("eth0");
    let report = run_check(&h.sys, &h.topo, &h.probe, &h.cfg)?;
    assert_eq!(report.verdict.exit_code(), 3);
    h.assert_log(&["topology", "wg", "ip"]);
    Ok(())
}

#[test]
fn check_tunnel_down() -> Result<(), Box<dyn Error>> {
    let h = Harness::new();
    h.exit_handshake(Ok(failure(
        Some(1),
        "Unable to access interface: No such device\n",
    )));
    let report = run_check(&h.sys, &h.topo, &h.probe, &h.cfg)?;
    assert_eq!(report.verdict.exit_code(), 4);
    h.assert_log(&["topology", "wg"]);
    Ok(())
}

#[test]
fn check_tunnel_permission_error() -> Result<(), Box<dyn Error>> {
    let h = Harness::new();
    h.exit_handshake(Ok(failure(
        Some(1),
        "Unable to access interface: Operation not permitted",
    )));
    let error = run_check(&h.sys, &h.topo, &h.probe, &h.cfg)
        .err()
        .ok_or("expected handshake error")?;
    assert_eq!(error.exit_code(), 1);
    assert_eq!(error.stage, Stage::Handshake);
    assert_eq!(
        error.source,
        ProbeError::exit_status(
            Some(1),
            "Unable to access interface: Operation not permitted"
        )
    );
    h.assert_log(&["topology", "wg"]);
    Ok(())
}

#[test]
fn check_route_rtnetlink_error() -> Result<(), Box<dyn Error>> {
    let h = Harness::new();
    h.exit_handshake(Ok(output(&handshake('A', 988))));
    let mut failed = failure(Some(2), "RTNETLINK answers: Network is unreachable");
    // Even plausible stdout from a failed command must not become a route.
    failed.stdout = "unreachable 192.0.2.1".into();
    h.route(Ok(failed));
    let error = run_check(&h.sys, &h.topo, &h.probe, &h.cfg)
        .err()
        .ok_or("expected route error")?;
    assert_eq!(error.exit_code(), 1);
    assert_eq!(error.stage, Stage::Route);
    assert_eq!(
        error.source,
        ProbeError::exit_status(Some(2), "RTNETLINK answers: Network is unreachable")
    );
    h.assert_log(&["topology", "wg", "ip"]);
    Ok(())
}

#[test]
fn check_stops_on_violation() -> Result<(), Box<dyn Error>> {
    let mut h = Harness::new();
    h.topo
        .result
        .as_mut()
        .map_err(|_| "topology failed")?
        .ruleset = RulesetObs::Missing;
    let report = run_check(&h.sys, &h.topo, &h.probe, &h.cfg)?;
    assert_eq!(report.verdict.exit_code(), 2);
    h.assert_log(&["topology"]);
    Ok(())
}

#[test]
fn check_no_repeat_calls() -> Result<(), Box<dyn Error>> {
    let h = Harness::new();
    h.healthy_path("proton0");
    run_check(&h.sys, &h.topo, &h.probe, &h.cfg)?;
    let log = h.log.borrow();
    for stage in ["topology", "wg", "ip", "exit probe"] {
        assert_eq!(log.iter().filter(|&&call| call == stage).count(), 1);
    }
    Ok(())
}

#[test]
fn check_exit_setup_and_path_errors() -> Result<(), Box<dyn Error>> {
    for (source, setup) in [
        (ProbeError::setup("binding device: permission denied"), true),
        (ProbeError::io("connection reset"), false),
        (ProbeError::Timeout, false),
        (ProbeError::exit_status(Some(1), "request failed"), false),
    ] {
        let mut h = Harness::new();
        h.healthy_path("proton0");
        h.probe.result = Err(source.clone());
        let result = run_check(&h.sys, &h.topo, &h.probe, &h.cfg);
        if setup {
            let error = result.err().ok_or("expected setup error")?;
            assert_eq!(error.exit_code(), 1);
            assert_eq!(error.stage, Stage::ExitProbe);
            assert_eq!(error.source, source);
        } else {
            assert_eq!(result?.verdict.exit_code(), 3);
        }
        h.assert_log(&["topology", "wg", "ip", "exit probe"]);
    }
    Ok(())
}

#[test]
fn check_observation_errors_stop_at_the_requested_stage() -> Result<(), Box<dyn Error>> {
    let mut h = Harness::new();
    h.topo.result = Err(ProbeError::Timeout);
    let error = run_check(&h.sys, &h.topo, &h.probe, &h.cfg)
        .err()
        .ok_or("expected topology error")?;
    assert_eq!(error.stage, Stage::Topology);
    h.assert_log(&["topology"]);

    for response in [
        Err(ExecError::Timeout {
            after: EXEC_TIMEOUT,
        }),
        Err(ExecError::OutputTooLarge {
            stream: Stream::Stdout,
        }),
        Err(ExecError::NonUtf8),
        Err(ExecError::spawn("not installed")),
        Ok(output("not a handshake")),
        Ok(failure(None, "terminated")),
    ] {
        let h = Harness::new();
        h.exit_handshake(response);
        let error = run_check(&h.sys, &h.topo, &h.probe, &h.cfg)
            .err()
            .ok_or("expected handshake error")?;
        assert_eq!(error.stage, Stage::Handshake);
        assert_eq!(error.exit_code(), 1);
        h.assert_log(&["topology", "wg"]);
    }
    Ok(())
}

#[test]
fn status_independent_fields() {
    let h = Harness::new();
    h.client_handshake(Ok(failure(Some(1), "Operation not permitted")));
    h.healthy_path("proton0");
    let report = run_status(&h.sys, &h.topo, &h.cfg);
    assert_eq!(
        report.to_string(),
        concat!(
            "client wg0:     unknown (probe exited unsuccessfully (code 1): Operation not permitted)\n",
            "exit   proton0: last handshake 12s ago\n",
            "client route:   via proton0\n",
            "kill switch:    in place"
        )
    );
    assert!(report.client_handshake.is_err());
    assert!(report.exit_handshake.is_ok());
    assert!(report.client_route.is_ok());
    assert_eq!(report.kill_switch, Ok(KillSwitchStatus::InPlace));
    h.assert_log(&["wg", "wg", "ip", "topology"]);
}

#[test]
fn status_snapshot() {
    for (device, route) in [
        ("proton0", "via proton0"),
        ("eth0", "via eth0, NOT proton0 (clients are blocked)"),
    ] {
        let h = Harness::new();
        h.client_handshake(Ok(output(&handshake('A', 959))));
        h.healthy_path(device);
        assert_eq!(
            run_status(&h.sys, &h.topo, &h.cfg).to_string(),
            format!(
                "client wg0:     last handshake 41s ago\nexit   proton0: last handshake 12s ago\nclient route:   {route}\nkill switch:    in place"
            )
        );
        h.assert_log(&["wg", "wg", "ip", "topology"]);
    }
}

#[test]
fn status_multi_peer_and_clock_skew() -> Result<(), Box<dyn Error>> {
    let h = Harness::new();
    h.client_handshake(Ok(output(&format!(
        "{}{}{}",
        handshake('A', 970),
        handshake('E', 0),
        handshake('I', 1_010)
    ))));
    h.exit_handshake(Ok(output(&handshake('A', 0))));
    h.route(Ok(output("192.0.2.1 dev proton0")));
    let status = run_status(&h.sys, &h.topo, &h.cfg);
    let client = status
        .client_handshake
        .as_ref()
        .map_err(|_| "client failed")?;
    assert_eq!(client.peer_count, 3);
    assert_eq!(client.age, HandshakeAge::InFuture(Duration::from_secs(10)));
    assert!(
        status
            .to_string()
            .starts_with("client wg0:     timestamp 10s in the future (clock skew?) (3 peers)\n")
    );
    assert!(
        status
            .to_string()
            .contains("exit   proton0: no handshake (interface down or peer never connected)")
    );
    Ok(())
}

#[test]
fn status_other_errors_and_missing_switch() {
    for topology in [
        Ok(M1Topology {
            exit_link: ExitLink::Up,
            ruleset: RulesetObs::Missing,
            tc_hooks: vec![],
            legacy_tables: Vec::new(),
            config_mismatches: vec![],
            uplink_addrs: vec![],
        }),
        Err(ProbeError::Timeout),
    ] {
        let mut h = Harness::new();
        h.topo.result = topology;
        h.client_handshake(Ok(output("")));
        h.exit_handshake(Err(ExecError::NonUtf8));
        h.route(Err(ExecError::Timeout {
            after: EXEC_TIMEOUT,
        }));
        let status = run_status(&h.sys, &h.topo, &h.cfg);
        let text = status.to_string();
        assert!(text.starts_with(
            "client wg0:     no handshake (interface down or peer never connected)\n"
        ));
        assert!(text.contains("exit   proton0: unknown (I/O error:"));
        assert!(text.contains("client route:   unknown (probe timed out)"));
        if h.topo.result.is_err() {
            assert!(text.ends_with("kill switch:    unknown (probe timed out)"));
        } else {
            assert!(text.ends_with("kill switch:    MISSING"));
        }
        h.assert_log(&["wg", "wg", "ip", "topology"]);
    }
}

#[test]
fn collectors_use_configured_interfaces_and_single_peer_parser() -> Result<(), Box<dyn Error>> {
    let h = Harness {
        cfg: V1Config::from_strs(
            "clients9",
            "vpn9",
            "wan9",
            "10.2.0.2".parse()?,
            "10.99.0.2".parse()?,
        )?,
        ..Harness::new()
    };
    h.exit_handshake(Ok(output(&handshake('A', 988))));
    h.route(Ok(output("192.0.2.1 dev vpn9")));
    assert_eq!(
        observe_handshake(&h.sys, &h.cfg)?,
        Handshake::At { unix_secs: 988 }
    );
    observe_route(&h.sys, &h.cfg)?;
    let calls = h.sys.fake.calls();
    assert_eq!(calls[0].args, wg_args("vpn9"));
    assert_eq!(calls[1].args, route_probe_argv(&h.cfg));
    h.exit_handshake(Ok(output(&format!(
        "{}{}",
        handshake('A', 988),
        handshake('E', 990)
    ))));
    assert!(matches!(
        observe_handshake(&h.sys, &h.cfg),
        Err(ProbeError::Parse(_))
    ));
    Ok(())
}

#[test]
fn check_wg_nonzero_without_missing_device_is_code_1() -> Result<(), Box<dyn Error>> {
    let h = Harness::new();
    h.exit_handshake(Ok(failure(Some(2), "unrelated command failure")));
    let error = run_check(&h.sys, &h.topo, &h.probe, &h.cfg)
        .err()
        .ok_or("expected observation error")?;
    assert_eq!(error.exit_code(), 1);
    assert_eq!(error.stage, Stage::Handshake);
    h.assert_log(&["topology", "wg"]);
    Ok(())
}

#[test]
fn missing_device_requires_exact_diagnostic_and_nonzero_status() -> Result<(), Box<dyn Error>> {
    for stderr in [
        "unrelated message: No such device while inspecting a route",
        "unrelated: Unable to access interface: No such device",
        "unrelated message\nUnable to access interface: No such device",
        "Unable to access interface: No such device (unrelated context)",
    ] {
        let h = Harness::new();
        h.exit_handshake(Ok(failure(Some(1), stderr)));
        assert!(matches!(
            observe_handshake(&h.sys, &h.cfg),
            Err(ProbeError::ExitStatus { .. })
        ));
    }
    for status in [Some(0), None] {
        let h = Harness::new();
        let mut response = failure(status, "Unable to access interface: No such device\n");
        response.stdout = handshake('A', 988);
        h.exit_handshake(Ok(response));
        let result = observe_handshake(&h.sys, &h.cfg);
        if status == Some(0) {
            assert_eq!(result?, Handshake::At { unix_secs: 988 });
        } else {
            assert!(matches!(result, Err(ProbeError::ExitStatus { .. })));
        }
    }
    Ok(())
}

fn status_with_topology(topology: M1Topology) -> String {
    let mut h = Harness::new();
    h.topo.result = Ok(topology);
    h.client_handshake(Ok(output(&handshake('A', 988))));
    h.healthy_path("proton0");
    run_status(&h.sys, &h.topo, &h.cfg).to_string()
}

#[test]
fn status_tc_hook_not_in_place() -> Result<(), Box<dyn Error>> {
    let h = Harness::new();
    let mut topology = h.topo.result?;
    topology.tc_hooks.push(h.cfg.client_iface);
    assert!(
        status_with_topology(topology)
            .ends_with("kill switch:    NOT VERIFIED: unexpected traffic-control hook on wg0")
    );
    Ok(())
}

#[test]
fn status_config_mismatch_not_in_place() -> Result<(), Box<dyn Error>> {
    let h = Harness::new();
    let mut topology = h.topo.result?;
    topology
        .config_mismatches
        .push(ConfigMismatch::ExitAddrNotOnExitIface);
    assert!(
        status_with_topology(topology)
            .ends_with("kill switch:    NOT VERIFIED: exit address is not on the exit interface")
    );
    Ok(())
}

#[test]
fn status_reports_all_topology_violations() -> Result<(), Box<dyn Error>> {
    let h = Harness::new();
    let mut topology = h.topo.result?;
    topology.ruleset = RulesetObs::Differs {
        live_sha256: [1; 32],
        want_sha256: [2; 32],
    };
    topology.tc_hooks.push(h.cfg.client_iface);
    topology
        .config_mismatches
        .push(ConfigMismatch::ExitAddrNotOnExitIface);
    assert!(status_with_topology(topology).ends_with(
        "kill switch:    NOT VERIFIED: ruleset differs from policy; unexpected traffic-control hook on wg0; exit address is not on the exit interface"
    ));
    Ok(())
}

#[test]
fn status_reads_clock_after_each_wg_call() -> Result<(), Box<dyn Error>> {
    struct AdvancingSystem {
        fake: FakeSystem,
        now: Cell<u64>,
    }
    impl System for AdvancingSystem {
        fn run(
            &self,
            program: Program,
            args: &[String],
            timeout: Duration,
        ) -> Result<ExecOutput, ExecError> {
            let result = self.fake.run(program, args, timeout);
            if program == Program::Wg {
                self.now.set(self.now.get() + 1);
            }
            result
        }
        fn now_unix_secs(&self) -> u64 {
            self.now.get()
        }
    }
    let h = Harness::new();
    h.client_handshake(Ok(output(&handshake('A', 1_001))));
    h.exit_handshake(Ok(output(&handshake('A', 1_002))));
    h.route(Ok(output("192.0.2.1 dev proton0")));
    let sys = AdvancingSystem {
        fake: h.sys.fake,
        now: Cell::new(1_000),
    };
    let status = run_status(&sys, &h.topo, &h.cfg);
    assert_eq!(
        status.client_handshake?.age,
        HandshakeAge::Age(Duration::ZERO)
    );
    assert_eq!(
        status.exit_handshake?.age,
        HandshakeAge::Age(Duration::ZERO)
    );
    Ok(())
}
