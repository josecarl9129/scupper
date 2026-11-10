//! Control faults reuse the guarded daemon lifecycle and uplink leak oracle.
use super::{
    A, DaemonGuard, Duration, Instant, Invocation, Lab, Path, Result, Signal, fail, flow_counts, fs,
};
use scupper_core::{
    config::{GatewayId, parse_site, validate},
    render::{VersionStamp, render_netns},
    verdict::v2::Selection,
};
use scupper_sys::{
    lock::WriterLock,
    state::{StateFile, StateRead},
    store::{MetaInput, VersionStore},
};
use sha2::{Digest, Sha256};

impl DaemonGuard<'_> {
    fn control_command(&mut self, root: &Path, args: &[&str], stem: &str) -> Result<(i32, String)> {
        let binary = Lab::boot_binary()?;
        let mut command = vec!["--test-root", root.to_str().ok_or("root path")?];
        command.extend_from_slice(args);
        let output_path = self
            .lab
            .artifacts
            .join(format!("{}-{stem}.stdout", self.case));
        let mut child = self.lab.runner.background(
            &Invocation::new("gwhost", binary.to_str().ok_or("binary path")?, &command),
            &output_path,
        )?;
        let status = child.wait_timeout(Duration::from_secs(55))?;
        let output = fs::read_to_string(&output_path)?;
        let diagnostic = fs::read_to_string(output_path.with_extension("stderr"))?;
        if args.contains(&"disconnect") {
            let snapshot = serde_json::json!({
                "v4": self.lab.cmd("scupper", "ip", &["-4", "route", "show", "default"] )?,
                "v6": self.lab.cmd("scupper", "ip", &["-6", "route", "show", "default"] )?,
                "exit": self.lab.cmd("scupper", "ip", &["-o", "link", "show", "ex-ch1"] )?,
            });
            fs::write(
                self.lab
                    .artifacts
                    .join(format!("{}-{stem}-closure.json", self.case)),
                serde_json::to_vec_pretty(&snapshot)?,
            )?;
        }
        Ok((
            status.code().unwrap_or(-1),
            format!("{output}\n{diagnostic}"),
        ))
    }
    fn assert_disconnect_snapshot(&self, stem: &str) -> Result<()> {
        let snapshot: serde_json::Value = serde_json::from_slice(&fs::read(
            self.lab
                .artifacts
                .join(format!("{}-{stem}-closure.json", self.case)),
        )?)?;
        if !snapshot["v4"]
            .as_str()
            .is_some_and(|s| s.contains("unreachable"))
            || !snapshot["v6"]
                .as_str()
                .is_some_and(|s| s.contains("unreachable"))
            || !snapshot["exit"]
                .as_str()
                .is_some_and(|s| !s.contains(",UP") && !s.contains("<UP"))
        {
            return fail(format!(
                "{} message preceded verified closure: {snapshot}",
                self.case
            ));
        }
        Ok(())
    }

    fn expect_check(&mut self, root: &Path, code: i32, stem: &str) -> Result<()> {
        let (got, report) = self.lab.check_result(&Lab::boot_binary()?, root)?;
        fs::write(
            self.lab
                .artifacts
                .join(format!("{}-{stem}.json", self.case)),
            serde_json::to_vec_pretty(&report)?,
        )?;
        if got != code {
            return fail(format!(
                "{} {stem}: expected {code}, got {got}: {report}",
                self.case
            ));
        }
        Ok(())
    }
    fn control_restart(&mut self, root: &Path, stage: &str) -> Result<()> {
        if let Some(mut child) = self.child.take() {
            child.signal(Signal::CONT);
            child.stop_timeout(Signal::TERM, Duration::from_secs(30))?;
        }
        if let Some(notify) = &self.notify {
            notify.drain()?;
        }
        self.child = Some(self.lab.daemon_spawn(&self.case, root, stage)?);
        self.lab
            .daemon_ready_tick(self.notify.as_ref().ok_or("missing notify")?)
    }
    fn control_stop(&mut self, signal: Signal) -> Result<()> {
        if let Some(mut child) = self.child.take() {
            child.signal(Signal::CONT);
            child.stop_timeout(signal, Duration::from_secs(30))?;
        }
        Ok(())
    }
    fn supervised_fixture(&mut self, root: &Path) -> Result<()> {
        let state_root = root.join("var-lib/scupper");
        let config_root = root.join("etc/scupper");
        let guard = WriterLock::acquire(root.join("run/scupper"))?;
        let store = VersionStore::open_with_mirror_root(&state_root, &config_root, Some(&guard))?;
        let head = store.head()?.ok_or("head missing")?;
        let (text, _) = store.read(head)?;
        let mut site = parse_site(&text)?;
        site.health.require_daemon = true;
        let text = toml::to_string(&site)?;
        self.lab.site = validate(site).map_err(|e| format!("supervised fixture: {e:?}"))?;
        let version = store.commit(
            &guard,
            Some(head),
            &text,
            MetaInput {
                actor: "lab".into(),
                at: 2,
                reason: "required supervisor control faults".into(),
            },
        )?;
        let file = StateFile::open(&state_root, Some(&guard))?;
        let StateRead::Present(mut state) = file.read()? else {
            return fail("missing safety state");
        };
        state.applied_version = Some(version);
        file.write(&guard, &state)?;
        let rules = render_netns(
            &self.lab.site,
            &GatewayId("gw1".into()),
            &VersionStamp {
                version,
                sha256: Sha256::digest(text.as_bytes()).into(),
            },
        )?;
        store.write_rendered(&guard, version, &rules)?;
        fs::write(&self.lab.rules, rules)?;
        Ok(())
    }
    pub(super) fn reset_control_fixture(&mut self) -> Result<()> {
        if !matches!(self.case.as_str(), "L10" | "L14" | "L43" | "L44" | "L50") {
            return Ok(());
        }
        let root = self.lab.private.join("boot-root");
        for marker in [
            "crash-after-selection",
            "pause-apply",
            "apply-paused",
            "incomplete-tick",
        ] {
            let _ = fs::remove_file(root.join("run/scupper").join(marker));
        }
        let guard = WriterLock::acquire(root.join("run/scupper"))?;
        let file = StateFile::open(root.join("var-lib/scupper"), Some(&guard))?;
        if let StateRead::Present(mut state) = file.read()? {
            state.selection = Selection::Auto;
            state.quarantine = None;
            file.write(&guard, &state)?;
        }
        Ok(())
    }
    fn assert_latched(&mut self, root: &Path, phase: &str) -> Result<()> {
        for key in ["net.ipv4.ip_forward", "net.ipv6.conf.all.forwarding"] {
            if self.lab.cmd("scupper", "sysctl", &["-n", key])?.trim() != "0" {
                return fail(format!("L43 {phase}: gate {key} opened"));
            }
        }
        let StateRead::Present(state) =
            StateFile::open(root.join("var-lib/scupper"), None)?.read()?
        else {
            return fail("L43 missing state");
        };
        if state.quarantine.is_none() {
            return fail(format!("L43 {phase}: latch missing"));
        }
        self.lab.daemon_route_healthy(Duration::from_secs(30))?;
        self.expect_check(root, 4, phase)?;
        let report: serde_json::Value = serde_json::from_slice(&fs::read(
            self.lab
                .artifacts
                .join(format!("{}-{phase}.json", self.case)),
        )?)?;
        if report["verdict"]["FailClosed"].get("Quarantined").is_none() {
            return fail(format!("L43 {phase}: expected Quarantined: {report}"));
        }
        Ok(())
    }
    #[allow(clippy::too_many_lines)] // Each fault retains its control and recovery assertions.
    pub(super) fn run_control(&mut self, case: &str) -> Result<String> {
        let root = self.lab.prepare_check_v2()?;
        self.supervised_fixture(&root)?;
        self.lab.boot_gateway(&[], &format!("{case}-boot"))?;
        let (child, notify) = self.lab.daemon_start(case, &root)?;
        self.child = Some(child);
        self.notify = Some(notify);
        self.lab
            .daemon_ready_tick(self.notify.as_ref().ok_or("notify missing")?)?;
        self.lab.daemon_route_healthy(Duration::from_secs(30))?;
        self.expect_check(&root, 0, "positive-control")?;
        let stem = format!("control-{case}");
        self.lab.capture("wan", A.gwhost.wan_if, &stem)?;
        let mut markers = Vec::new();
        self.lab.service_check(&mut markers)?;
        let start_port = self.lab.exit_port;
        let mut canary = if case == "L10" {
            None
        } else {
            let marker = Lab::marker()?;
            markers.push(marker.clone());
            let canary_stem = format!("{stem}-canary");
            let child = self
                .lab
                .daemon_flow("udp", "client", &marker, &canary_stem, 240)?;
            let path = self.lab.artifacts.join(format!("{canary_stem}-udp.jsonl"));
            self.lab
                .daemon_wait("control canary replies", Duration::from_secs(5), |_| {
                    Ok(flow_counts(&path)?.1 > 5)
                })?;
            Some(child)
        };
        match case {
            "L10" => {
                let marker = Lab::marker()?;
                markers.push(marker.clone());
                let mut flow = self.lab.daemon_flow("udp", "client", &marker, &stem, 90)?;
                let path = self.lab.artifacts.join(format!("{stem}-udp.jsonl"));
                self.lab
                    .daemon_wait("L10 canary control", Duration::from_secs(5), |_| {
                        Ok(flow_counts(&path)?.1 > 10)
                    })?;
                fs::write(root.join("run/scupper/incomplete-tick"), b"hold")?;
                self.lab.runner.dwell(Duration::from_secs(32))?;
                let (code, text) =
                    self.control_command(&root, &["check", "--json"], "responsive-stale")?;
                if code != 5 || !text.contains("transport: local socket") {
                    return fail(format!("L10 responsive stale supervisor: {code}: {text}"));
                }
                fs::remove_file(root.join("run/scupper/incomplete-tick"))?;
                self.lab.runner.dwell(Duration::from_secs(3))?;
                self.expect_check(&root, 0, "fresh-again")?;
                self.child
                    .as_ref()
                    .ok_or("daemon missing")?
                    .signal(Signal::STOP);
                let before = flow_counts(&path)?.1;
                let at = Instant::now();
                self.expect_check(&root, 5, "stopped")?;
                if at.elapsed() > Duration::from_secs(4) {
                    return fail(
                        "L10 stopped check exceeded Ping timeout plus local probe allowance",
                    );
                }
                self.lab.daemon_wait(
                    "L10 traffic while stopped",
                    Duration::from_secs(3),
                    |_| Ok(flow_counts(&path)?.1 > before),
                )?;
                self.child
                    .as_ref()
                    .ok_or("daemon missing")?
                    .signal(Signal::CONT);
                self.expect_check(&root, 0, "continued")?;
                self.control_stop(Signal::KILL)?;
                let before = flow_counts(&path)?.1;
                self.expect_check(&root, 5, "killed")?;
                self.lab.daemon_wait(
                    "L10 traffic after SIGKILL",
                    Duration::from_secs(3),
                    |_| Ok(flow_counts(&path)?.1 > before),
                )?;
                flow.stop(Signal::TERM)?;
                self.control_restart(&root, "after-kill")?;
                self.expect_check(&root, 0, "restarted")?;
            }
            "L14" => {
                let (code, text) = self.control_command(&root, &["disconnect"], "disconnect")?;
                if code != 0
                    || !text.contains("traffic is now blocked")
                    || !text.contains("transport: local socket")
                {
                    return fail(format!("L14 disconnect: {code}: {text}"));
                }
                self.assert_disconnect_snapshot("disconnect")?;
                self.expect_check(&root, 4, "disconnected")?;
                self.control_stop(Signal::TERM)?;
                self.lab.boot_gateway(&[], "L14-reboot")?;
                self.expect_check(&root, 4, "reboot-closed")?;
                self.control_restart(&root, "after-reboot")?;
                self.expect_check(&root, 4, "restart-closed")?;
                let (code, text) = self.control_command(&root, &["connect"], "connect")?;
                if code != 0 {
                    return fail(format!("L14 connect: {code}: {text}"));
                }
                self.expect_check(&root, 0, "connected")?;
            }
            "L43" => {
                for attempt in 0..5 {
                    self.lab.cmd(
                        "scupper",
                        "ip",
                        &["link", "add", "foreign0", "type", "dummy"],
                    )?;
                    self.lab
                        .cmd("scupper", "ip", &["link", "set", "foreign0", "up"])?;
                    self.lab.daemon_wait(
                        "L43 foreign link tightened",
                        Duration::from_secs(8),
                        |lab| {
                            Ok(!lab
                                .cmd("scupper", "ip", &["-o", "link", "show", "foreign0"])?
                                .contains(",UP"))
                        },
                    )?;
                    self.lab
                        .cmd("scupper", "ip", &["link", "del", "foreign0"])?;
                    let state = StateFile::open(root.join("var-lib/scupper"), None)?.read()?;
                    if matches!(state, StateRead::Present(ref state) if state.quarantine.is_some())
                    {
                        break;
                    }
                    if attempt == 4 {
                        return fail("L43 recurring foreign links did not latch");
                    }
                }
                self.assert_latched(&root, "quarantined")?;
                for phase in ["latched-restart", "latched-reboot"] {
                    self.control_stop(Signal::TERM)?;
                    if phase == "latched-reboot" {
                        self.lab.boot_gateway(&[], "L43-reboot")?;
                    }
                    if self
                        .lab
                        .cmd("scupper", "sysctl", &["-n", "net.ipv4.ip_forward"])?
                        .trim()
                        != "0"
                    {
                        return fail("L43 latch allowed forwarding");
                    }
                    self.control_restart(&root, phase)?;
                    self.assert_latched(&root, phase)?;
                }
                let (code, text) = self.control_command(
                    &root,
                    &["repair", "clear", "--reason", "lab recovery"],
                    "clear",
                )?;
                if code != 0 || !text.contains("transport: local socket") {
                    return fail(format!("L43 clear: {code}: {text}"));
                }
                self.lab.daemon_route_healthy(Duration::from_secs(30))?;
                self.expect_check(&root, 0, "cleared")?;
            }
            "L44" => {
                fs::write(root.join("run/scupper/pause-apply"), b"pause")?;
                let binary = Lab::boot_binary()?;
                let mut apply = self.lab.runner.background(
                    &Invocation::new(
                        "gwhost",
                        binary.to_str().ok_or("binary")?,
                        &["--test-root", root.to_str().ok_or("root")?, "apply"],
                    ),
                    &self.lab.artifacts.join("L44-apply.stdout"),
                )?;
                self.lab.daemon_wait(
                    "L44 socket apply holds writer",
                    Duration::from_secs(5),
                    |_| Ok(root.join("run/scupper/apply-paused").exists()),
                )?;
                if WriterLock::try_acquire(root.join("run/scupper")).is_ok() {
                    return fail("L44 socket apply did not hold the writer lock");
                }
                let (code, text) = self.control_command(&root, &["disconnect"], "busy-refusal")?;
                if code != 1
                    || !text.contains("scupperd is alive but unresponsive")
                    || text.contains("traffic is now blocked")
                {
                    return fail(format!("L44 busy daemon allowed fallback: {code}: {text}"));
                }
                let mut samples = Vec::new();
                for sample in 0..16 {
                    if sample == 4 {
                        fs::remove_file(root.join("run/scupper/pause-apply"))?;
                    }
                    let forwarding =
                        self.lab
                            .cmd("scupper", "sysctl", &["-n", "net.ipv4.ip_forward"])?;
                    let forwarding6 = self.lab.cmd(
                        "scupper",
                        "sysctl",
                        &["-n", "net.ipv6.conf.all.forwarding"],
                    )?;
                    samples.push(
                        serde_json::json!({"sample": sample, "forwarding_v4": forwarding.trim(), "forwarding_v6": forwarding6.trim()}),
                    );
                    if forwarding.trim() != "0" || forwarding6.trim() != "0" {
                        let (code, report) = self.lab.check_result(&Lab::boot_binary()?, &root)?;
                        if code != 0 {
                            return fail(format!("L44 open unsafe sample {sample}: {report}"));
                        }
                    }
                    self.lab.runner.dwell(Duration::from_millis(100))?;
                }
                fs::write(
                    self.lab.artifacts.join("L44-intermediate-samples.json"),
                    serde_json::to_vec_pretty(&samples)?,
                )?;
                // A completed apply or a bounded writer refusal is acceptable;
                // final convergence must be exact and connected.
                let status = apply.wait_timeout(Duration::from_secs(30))?;
                let output = fs::read_to_string(self.lab.artifacts.join("L44-apply.stdout"))?;
                let diagnostic = fs::read_to_string(self.lab.artifacts.join("L44-apply.stderr"))?;
                if !status.success() && !diagnostic.contains("writer lock") {
                    return fail(format!(
                        "L44 apply failed without writer contention: {status}: {output}: {diagnostic}"
                    ));
                }
                self.lab
                    .daemon_ready_tick(self.notify.as_ref().ok_or("notify missing")?)?;
                self.lab.daemon_route_healthy(Duration::from_secs(30))?;
                self.expect_check(&root, 0, "one-writer-recovered")?;
            }
            "L50" => {
                self.control_stop(Signal::TERM)?;
                fs::write(root.join("run/scupper/crash-after-selection"), b"crash")?;
                let (code, text) = self.control_command(&root, &["disconnect"], "crash")?;
                fs::remove_file(root.join("run/scupper/crash-after-selection"))?;
                if code == 0 || text.contains("traffic is now blocked") {
                    return fail("L50 crash claimed successful disconnect");
                }
                if !self
                    .lab
                    .cmd("scupper", "ip", &["route", "show", "default"])?
                    .contains("ex-ch1")
                {
                    return fail("L50 crash injection did not retain live exit route");
                }
                let (code, report) = self.lab.check_result(&Lab::boot_binary()?, &root)?;
                if code != 3 || !report.to_string().contains("DisconnectNotEffective") {
                    return fail(format!("L50 wrong intent-only failure: {code}: {report}"));
                }
                let (code, text) = self.control_command(&root, &["disconnect"], "tighten")?;
                if code != 0 || !text.contains("traffic is now blocked") {
                    return fail("L50 tightening did not verify closure");
                }
                self.expect_check(&root, 4, "tightened")?;
                self.control_restart(&root, "socket-closure")?;
                let (code, text) = self.control_command(&root, &["connect"], "socket-connect")?;
                if code != 0 {
                    return fail(format!("L50 connect: {code}: {text}"));
                }
                self.lab.daemon_route_healthy(Duration::from_secs(30))?;
                fs::write(root.join("run/scupper/incomplete-tick"), b"hold")?;
                let (code, text) =
                    self.control_command(&root, &["disconnect"], "socket-ineffective")?;
                fs::remove_file(root.join("run/scupper/incomplete-tick"))?;
                if code != 3
                    || !text.contains("DisconnectNotEffective")
                    || !text.contains("transport: local socket")
                    || text.contains("traffic is now blocked")
                {
                    return fail(format!("L50 socket ineffective disconnect: {code}: {text}"));
                }
                let (code, text) =
                    self.control_command(&root, &["disconnect"], "socket-tighten")?;
                if code != 0 || !text.contains("transport: local socket") {
                    return fail(format!("L50 socket closure: {code}: {text}"));
                }
                self.assert_disconnect_snapshot("socket-tighten")?;
                self.expect_check(&root, 4, "socket-closed")?;
            }
            _ => return fail("unknown control case"),
        }
        if let Some(child) = &mut canary {
            child.alive()?;
            child.stop(Signal::TERM)?;
        }
        self.lab.stop_captures()?;
        self.lab.exit_port = self
            .lab
            .cmd("scupper", "wg", &["show", "ex-ch1", "listen-port"])?
            .trim()
            .parse()?;
        self.lab
            .daemon_oracle(&stem, &markers, start_port, self.lab.exit_port)?;
        if case == "L50" {
            // The measured trial ends closed. Restore service before the
            // separate deliberate-leak control exercises the capture oracle.
            self.control_restart(&root, "after-closure")?;
            let (code, output) = self.control_command(&root, &["connect"], "restore")?;
            if code != 0 {
                return fail(format!("L50 control recovery failed: {code}: {output}"));
            }
            self.expect_check(&root, 0, "restored-control")?;
        }
        self.lab.daemon_capture_control(&stem)?;
        Ok("positive_check=0; control_fault_verified=true; uplink_violations=0; saved JSON, command output, notify, events and pcap".into())
    }
}
