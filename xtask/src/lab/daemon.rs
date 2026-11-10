//! Direct daemon execution in the lab host network and mount namespaces.
use super::{
    Lab, Result,
    addresses::A,
    command::{Group, Invocation},
    evidence::{self, Row},
    fail,
};
use rustix::process::Signal;
use scupper_sys::{events::read_since, netns::NetnsHandle};
use std::{
    fmt::Write as _,
    fs,
    io::{self, Write},
    os::unix::net::UnixDatagram,
    path::Path,
    time::{Duration, Instant},
};

// Own both the daemon and fixture cleanup before any fallible fault operation.
struct DaemonGuard<'a> {
    lab: &'a mut Lab,
    child: Option<Group>,
    armed: bool,
}
impl DaemonGuard<'_> {
    fn run(&mut self, case: &str) -> Result<String> {
        let (child, notify, root) = self.lab.daemon_start(case)?;
        self.child = Some(child);
        self.lab
            .daemon_wait("READY", Duration::from_secs(30), |lab| {
                Ok(lab.notifications(&notify)?.iter().any(|s| s == "READY=1"))
            })?;
        self.lab.daemon_route_healthy(Duration::from_secs(60))?;
        let child = self.child.as_mut().ok_or("missing daemon")?;
        let observed = self.lab.daemon_fault(case, child, &notify, &root)?;
        let before = self.lab.daemon_snapshot()?;
        child.stop_timeout(Signal::TERM, Duration::from_secs(30))?;
        if before != self.lab.daemon_snapshot()? {
            return fail("SIGTERM changed kernel state");
        }
        if !root.join("var-lib/scupper/events/clean").exists() {
            return fail("SIGTERM did not write clean event marker");
        }
        // L4 must also survive reopening the durable owned-link handoff.
        if case == "L4" {
            drop(self.child.take());
            let binary = Lab::boot_binary()?.with_file_name("scupperd");
            let notify_path = self.lab.private.join(format!("notify-{case}.sock"));
            let env = format!("NOTIFY_SOCKET={}", notify_path.display());
            self.lab.notifications(&notify)?;
            self.child = Some(self.lab.runner.background(
                &Invocation::new(
                    "gwhost",
                    "env",
                    &[
                        &env,
                        binary.to_str().ok_or("daemon path")?,
                        "--test-root",
                        root.to_str().ok_or("root path")?,
                    ],
                ),
                &self.lab.artifacts.join("daemon-restart.stdout"),
            )?);
            self.lab
                .daemon_wait("restart READY", Duration::from_secs(30), |lab| {
                    Ok(lab.notifications(&notify)?.iter().any(|s| s == "READY=1"))
                })?;
            self.lab.daemon_route_healthy(Duration::from_secs(60))?;
        }
        Ok(observed)
    }
    fn finish(&mut self) -> Result<()> {
        if !self.armed {
            return Ok(());
        }
        self.armed = false;
        // Cleanup has its own deadline even after a case deadline/cancellation.
        let cleanup = self.lab.runner.cleanup;
        let phase = self.lab.runner.phase;
        let whole = self.lab.runner.whole;
        self.lab.runner.cleanup = true;
        self.lab.runner.phase = Instant::now() + Duration::from_secs(90);
        self.lab.runner.whole = self.lab.runner.phase;
        if let Some(mut child) = self.child.take() {
            child.signal(Signal::CONT);
            let _ = child.stop_timeout(Signal::TERM, Duration::from_secs(5));
            drop(child); // Group kills/reaps on any failed graceful stop.
        }
        let _ = fs::remove_file(self.lab.private.join("boot-root/run/scupper/stall-tick"));
        let captures = self.lab.stop_captures();
        // Absent resources are fine. Verify the baseline after ordered boot.
        for (ns, program, args) in [
            (
                "scupper",
                "tc",
                vec!["qdisc", "del", "dev", "wg0", "clsact"],
            ),
            ("scupper", "ip", vec!["link", "del", "foreign0"]),
            ("gwhost", "ip", vec!["link", "del", "foreign-host"]),
            ("gwhost", "ip", vec!["link", "del", "foreign0"]),
            (
                "scupper",
                "ip",
                vec!["route", "del", "198.18.0.0/24", "dev", "ex-ch1"],
            ),
            (
                "wan",
                "nft",
                vec!["delete", "table", "inet", "daemon_exit_down"],
            ),
            ("wan", "nft", vec!["delete", "table", "inet", "lab_inject"]),
        ] {
            let _ = self
                .lab
                .runner
                .output(&Invocation::new(ns, program, &args), None);
        }
        let restored = self
            .lab
            .boot_gateway(&[], "daemon-restore")
            .and_then(|_| self.lab.daemon_clean_baseline());
        self.lab.runner.cleanup = cleanup;
        self.lab.runner.phase = phase;
        self.lab.runner.whole = whole;
        captures.and(restored)
    }
}
impl Drop for DaemonGuard<'_> {
    fn drop(&mut self) {
        let _ = self.finish();
    }
}

impl Lab {
    pub(super) fn daemon_case(&mut self) -> Result<String> {
        let mut failures = Vec::new();
        for case in [
            "L6", "L7", "L13", "L16", "L17-V14", "L52", "V03", "L3", "L4",
        ] {
            self.runner.phase = Instant::now() + Duration::from_secs(180);
            let started = Instant::now();
            let observed = self
                .daemon_clean_baseline()
                .and_then(|()| self.daemon_trial(case));
            self.rows.push(Row {
                name: format!("daemon-{case}"),
                wanted: daemon_wanted(case).into(),
                got: observed
                    .as_ref()
                    .cloned()
                    .unwrap_or_else(|e| format!("failed: {e}")),
                detail: format!(
                    "elapsed_ms={}; isolated daemon; cleanup guard",
                    started.elapsed().as_millis()
                ),
            });
            evidence::save_results(&self.artifacts, &self.rows)?;
            if let Err(error) = observed {
                failures.push(format!("{case}: {error}"));
            }
        }
        if !failures.is_empty() {
            return fail(failures.join("; "));
        }
        Ok("all daemon cases verified; guarded cleanup, notify evidence and clean shutdown".into())
    }
    fn daemon_trial(&mut self, case: &str) -> Result<String> {
        let mut guard = DaemonGuard {
            lab: self,
            child: None,
            armed: true,
        };
        let result = guard.run(case);
        let cleanup = guard.finish();
        match (result, cleanup) {
            (Ok(observed), Ok(())) => Ok(observed),
            (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
            (Err(error), Err(cleanup)) => fail(format!("{error}; cleanup: {cleanup}")),
        }
    }
    pub(super) fn daemon_clean_baseline(&mut self) -> Result<()> {
        let links: serde_json::Value =
            serde_json::from_str(&self.cmd("scupper", "ip", &["-j", "link", "show"])?)?;
        if links.as_array().is_none_or(|links| {
            links
                .iter()
                .any(|link| !matches!(link["ifname"].as_str(), Some("lo" | "wg0" | "ex-ch1")))
        }) {
            return fail("unclean baseline: foreign namespace links; operator attention required");
        }
        for direction in ["ingress", "egress"] {
            let hooks = self.cmd(
                "scupper",
                "tc",
                &["-j", "filter", "show", "dev", "wg0", direction],
            )?;
            if hooks.trim() != "[]" {
                return fail(format!("unclean baseline: wg0 {direction} tc hooks"));
            }
        }
        if self
            .cmd("scupper", "ip", &["route", "show", "table", "main"])?
            .contains("198.18.0.0/24")
        {
            return fail("unclean baseline: daemon extra route remains");
        }
        let tables = self.cmd("wan", "nft", &["list", "tables"])?;
        if tables.contains("lab_inject") || tables.contains("daemon_exit_down") {
            return fail("unclean baseline: daemon fault nft table remains");
        }
        self.service_check(&mut Vec::new())
            .map_err(|e| format!("unclean baseline: service check: {e}").into())
    }
    fn daemon_start(&mut self, case: &str) -> Result<(Group, UnixDatagram, std::path::PathBuf)> {
        let root = self.prepare_check_v2()?;
        self.boot_gateway(&[], "daemon-boot")?;
        let binary = Self::boot_binary()?;
        let daemon = binary.with_file_name("scupperd");
        let notify_path = self.private.join(format!("notify-{case}.sock"));
        let notify = UnixDatagram::bind(&notify_path)?;
        notify.set_nonblocking(true)?;
        let env = format!("NOTIFY_SOCKET={}", notify_path.display());
        let child = self.runner.background(
            &Invocation::new(
                "gwhost",
                "env",
                &[
                    &env,
                    daemon.to_str().ok_or("daemon path")?,
                    "--test-root",
                    root.to_str().ok_or("root path")?,
                ],
            ),
            &self.artifacts.join("daemon.stdout"),
        )?;
        Ok((child, notify, root))
    }
    fn daemon_snapshot(&mut self) -> Result<serde_json::Value> {
        Ok(serde_json::json!({
            "rules": scupper_core::canon::canonicalize(&self.cmd("scupper", "nft", &["-j", "list", "ruleset"])?)?,
            "routes4": self.cmd("scupper", "ip", &["-j", "-4", "route", "show", "table", "all"])?,
            "routes6": self.cmd("scupper", "ip", &["-j", "-6", "route", "show", "table", "all"])?,
            "links": self.cmd("scupper", "ip", &["-j", "link", "show"])?,
            "sysctls": self.daemon_sysctls()?,
        }))
    }
    fn notifications(&self, socket: &UnixDatagram) -> Result<Vec<String>> {
        let mut messages = Vec::new();
        let mut bytes = [0; 128];
        loop {
            match socket.recv(&mut bytes) {
                Ok(len) => {
                    let message = std::str::from_utf8(&bytes[..len])?.to_owned();
                    writeln!(
                        fs::OpenOptions::new()
                            .create(true)
                            .append(true)
                            .open(self.artifacts.join("notify.jsonl"))?,
                        "{}",
                        serde_json::json!({"at": std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_millis(), "message": message})
                    )?;
                    messages.push(message);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(messages),
                Err(e) => return Err(e.into()),
            }
        }
    }
    fn daemon_wait(
        &mut self,
        label: &str,
        bound: Duration,
        mut predicate: impl FnMut(&mut Self) -> Result<bool>,
    ) -> Result<u128> {
        let start = Instant::now();
        loop {
            if predicate(self)? {
                return Ok(start.elapsed().as_millis());
            }
            if start.elapsed() >= bound {
                return fail(format!(
                    "{label}: exceeded {} ms; inspect daemon.stderr, commands.jsonl and events",
                    bound.as_millis()
                ));
            }
            self.runner.dwell(Duration::from_millis(25))?;
        }
    }
    fn daemon_route_healthy(&mut self, bound: Duration) -> Result<u128> {
        self.daemon_wait("active exit route", bound, |lab| {
            Ok(lab
                .cmd("scupper", "ip", &["route", "show", "default"])?
                .contains("dev ex-ch1"))
        })
    }
    fn daemon_flow(&mut self, mode: &str, ns: &str, marker: &str, stem: &str) -> Result<Group> {
        let address = if mode == "udp" {
            format!("{}:8080", A.internet.peer)
        } else {
            format!("{}:8081", A.internet.peer)
        };
        self.runner.background(
            &Invocation::new(
                ns,
                &self.executable,
                &[
                    "flow",
                    "--mode",
                    mode,
                    "--address",
                    &address,
                    "--marker",
                    marker,
                    "--log",
                    self.artifacts
                        .join(format!("{stem}-{mode}.jsonl"))
                        .to_str()
                        .ok_or("flow log")?,
                ],
            ),
            &self.artifacts.join(format!("{stem}-{mode}.stdout")),
        )
    }
    #[allow(clippy::too_many_lines)]
    fn daemon_fault(
        &mut self,
        case: &str,
        child: &mut Group,
        notify: &UnixDatagram,
        root: &Path,
    ) -> Result<String> {
        let stem = format!("daemon-{case}");
        let mut markers = Vec::new();
        self.capture("wan", A.gwhost.wan_if, &stem)?;
        self.service_check(&mut markers)?;
        let start_port = self.exit_port;
        let measurement = match case {
            "L6" => {
                self.daemon_wait("pre-stall watchdog", Duration::from_secs(8), |lab| {
                    Ok(lab.notifications(notify)?.iter().any(|s| s == "WATCHDOG=1"))
                })?;
                self.daemon_wait(
                    "watchdog follows the two-second tick cadence",
                    Duration::from_secs(3),
                    |lab| Ok(lab.notifications(notify)?.iter().any(|s| s == "WATCHDOG=1")),
                )?;
                let before = read_since(&root.join("var-lib/scupper"), 0, None)
                    .filter_map(std::result::Result::ok)
                    .map(|e| e.seq)
                    .max()
                    .unwrap_or(0);
                let hook = root.join("run/scupper/stall-tick");
                fs::write(&hook, b"stall")?;
                self.runner.dwell(Duration::from_millis(2200))?;
                self.notifications(notify)?;
                self.cmd("scupper", "ip", &["route", "del", "default"])?;
                let (code, report) = self.check_result(&Self::boot_binary()?, root)?;
                if code != 3
                    || report["verdict"]["Degraded"]
                        .get("DefaultRouteWrong")
                        .is_none()
                {
                    return fail(format!("L6 expected route verdict 3: {code}: {report}"));
                }
                self.runner.dwell(Duration::from_millis(2200))?;
                if !self
                    .cmd("scupper", "ip", &["route", "show", "default"])?
                    .trim()
                    .is_empty()
                    || self
                        .notifications(notify)?
                        .iter()
                        .any(|s| s == "WATCHDOG=1")
                {
                    return fail("tick stall: repair or watchdog continued");
                }
                child.alive()?;
                child.assert_not_stopped()?;
                fs::remove_file(hook)?;
                let repaired = self.daemon_route_healthy(Duration::from_secs(10))?;
                self.daemon_wait("post-stall watchdog", Duration::from_secs(8), |lab| {
                    Ok(lab.notifications(notify)?.iter().any(|s| s == "WATCHDOG=1"))
                })?;
                self.daemon_wait("L6 route event", Duration::from_secs(5), |_| {
                    Ok(read_since(&root.join("var-lib/scupper"), before, None)
                        .filter_map(std::result::Result::ok)
                        .any(|e| {
                            matches!(
                                e.kind,
                                scupper_proto::EventKind::Repair {
                                    kind: scupper_proto::StepKind::RouteReplace,
                                    result: scupper_proto::Outcome::Succeeded,
                                    ..
                                }
                            )
                        }))
                })?;
                format!(
                    "check=3; tick_stall_min_ms=4400; stopped_watchdogs=0; repair_ms={repaired}"
                )
            }
            "L7" => {
                let marker = Self::marker()?;
                markers.push(marker.clone());
                let mut stream = self.daemon_flow("udp", "client", &marker, &stem)?;
                self.runner.dwell(Duration::from_millis(300))?;
                // Inject after a completed iteration and measure the actual closure.
                self.notifications(notify)?;
                self.daemon_wait("pre-flush watchdog", Duration::from_secs(8), |lab| {
                    Ok(lab.notifications(notify)?.iter().any(|s| s == "WATCHDOG=1"))
                })?;
                let before = read_since(&root.join("var-lib/scupper"), 0, None)
                    .filter_map(std::result::Result::ok)
                    .map(|e| e.seq)
                    .max()
                    .unwrap_or(0);
                let started = Instant::now();
                self.cmd("scupper", "nft", &["flush", "ruleset"])?;
                self.daemon_wait("L7 forwarding closed", Duration::from_secs(2), |lab| {
                    Ok(lab
                        .cmd("scupper", "sysctl", &["-n", "net.ipv4.ip_forward"])?
                        .trim()
                        == "0")
                })?;
                let closed = started.elapsed().as_millis();
                if closed > 2000 {
                    return fail(format!("L7 closure {closed} ms exceeds 2s"));
                }
                self.daemon_wait(
                    "L7 all forwarding gates closed",
                    Duration::from_secs(2),
                    |lab| {
                        let values = lab.daemon_sysctls()?;
                        Ok(values
                            .iter()
                            .filter(|(key, _)| {
                                key.ends_with(".forwarding")
                                    || key.as_str() == "net.ipv4.ip_forward"
                            })
                            .all(|(_, value)| value == "0"))
                    },
                )?;
                let all_closed = started.elapsed().as_millis();
                self.daemon_wait("L7 restored", Duration::from_secs(12), |lab| {
                    Ok(lab
                        .cmd("scupper", "sysctl", &["-n", "net.ipv4.ip_forward"])?
                        .trim()
                        == "1")
                })?;
                let restored = started.elapsed().as_millis();
                stream.stop(Signal::TERM)?;
                let events: Vec<_> = read_since(&root.join("var-lib/scupper"), before, None)
                    .collect::<io::Result<_>>()?;
                if !events.iter().any(|e| {
                    matches!(
                        e.kind,
                        scupper_proto::EventKind::Repair {
                            kind: scupper_proto::StepKind::FlushConntrack,
                            result: scupper_proto::Outcome::Succeeded,
                            ..
                        }
                    )
                }) {
                    return fail("L7 missing successful conntrack-flush event");
                }
                format!(
                    "forwarding_zero_ms={closed}; all_gates_zero_ms={all_closed}; restored_ms={restored}; conntrack_flush_event=true"
                )
            }
            "L13" => self.daemon_foreign(child, &mut markers, &stem, root)?,
            "L16" => {
                self.cmd("scupper", "ip", &["link", "set", "ex-ch1", "down"])?;
                let down = self.daemon_wait("L16 unreachable", Duration::from_secs(8), |lab| {
                    Ok(lab
                        .cmd("scupper", "ip", &["route", "show", "default"])?
                        .contains("unreachable"))
                })?;
                let (code, report) = self.check_result(&Self::boot_binary()?, root)?;
                if code != 4 {
                    return fail(format!("L16 expected 4: {code}: {report}"));
                }
                self.cmd("scupper", "ip", &["link", "set", "ex-ch1", "up"])?;
                let up = self.daemon_route_healthy(Duration::from_secs(70))?;
                let (code, report) = self.check_result(&Self::boot_binary()?, root)?;
                if code != 0 {
                    return fail(format!("L16 expected recovered check 0: {code}: {report}"));
                }
                format!(
                    "down_ms={down}; check_down=4; recovery_ms={up}; check_up=0; active_route_restored=true"
                )
            }
            "L17-V14" => {
                let marker = Self::marker()?;
                markers.push(marker.clone());
                let mut stream = self.daemon_flow("udp", "client", &marker, &stem)?;
                let stream_log = self.artifacts.join(format!("{stem}-udp.jsonl"));
                self.daemon_wait("L17 live canary control", Duration::from_secs(3), |_| {
                    Ok(flow_counts(&stream_log)?.1 > 0)
                })?;
                let (_, replies_before) = flow_counts(&stream_log)?;
                let before = NetnsHandle::open("/run/netns/scupper")?.identity();
                // Drop our test descriptor; only the daemon may preserve the inode.
                let start = Instant::now();
                self.cmd("", "ip", &["netns", "del", "scupper"])?;
                self.daemon_wait("held inode remount", Duration::from_secs(8), |_| {
                    Ok(Path::new("/run/netns/scupper").exists())
                })?;
                let after = NetnsHandle::open("/run/netns/scupper")?.identity();
                if before != after {
                    return fail("L17 created a second namespace");
                }
                let remount = start.elapsed().as_millis();
                self.daemon_wait(
                    "L17 canaries still acknowledged",
                    Duration::from_secs(3),
                    |_| Ok(flow_counts(&stream_log)?.1 > replies_before),
                )?;
                stream.stop(Signal::TERM)?;
                let (sent, replies) = flow_counts(&stream_log)?;
                if sent.saturating_sub(replies) > 2 {
                    return fail(format!("L17 canary loss: sent={sent}, replies={replies}"));
                }
                format!(
                    "remount_ms={remount}; same_inode=true; second_namespace=false; stream_sent={sent}; stream_replies={replies}"
                )
            }
            "L52" => {
                child.signal(Signal::STOP);
                self.cmd(
                    "scupper",
                    "ip",
                    &["route", "add", "198.18.0.0/24", "dev", "ex-ch1"],
                )?;
                let (code, report) = self.check_result(&Self::boot_binary()?, root)?;
                if code != 3 || report["verdict"]["Degraded"].get("RouteWrong").is_none() {
                    return fail(format!("L52 expected check 3 RouteWrong: {code}: {report}"));
                }
                child.signal(Signal::CONT);
                let elapsed =
                    self.daemon_wait("extra route removed", Duration::from_secs(8), |lab| {
                        Ok(!lab
                            .cmd("scupper", "ip", &["route", "show", "table", "main"])?
                            .contains("198.18.0.0/24"))
                    })?;
                format!("check=3 RouteWrong; extra_route_removed_ms={elapsed}")
            }
            "V03" => self.daemon_sysctl_fixture(child)?,
            "L3" | "L4" => self.daemon_dead_flow(case, &mut markers, &stem)?,
            _ => return fail("unknown daemon case"),
        };
        self.daemon_route_healthy(Duration::from_secs(70))?;
        self.service_check(&mut markers)?;
        self.stop_captures()?;
        self.exit_port = self
            .cmd("scupper", "wg", &["show", "ex-ch1", "listen-port"])?
            .trim()
            .parse()?;
        self.daemon_oracle(&stem, &markers, start_port, self.exit_port)?;
        self.daemon_capture_control(&stem)?;
        Ok(measurement)
    }
    fn daemon_oracle(
        &self,
        stem: &str,
        markers: &[String],
        old_port: u16,
        new_port: u16,
    ) -> Result<()> {
        let mut text = evidence::policy_with_exit_port(markers, false, old_port)?;
        if old_port != new_port {
            write!(
                text,
                "\n[[wireguard]]\ngateway = \"{}:{new_port}\"\npeer = \"{}:51820\"\n",
                A.gwhost.peer, A.provider.peer
            )?;
        }
        fs::write(self.artifacts.join(format!("{stem}.policy.toml")), &text)?;
        let report = crate::pcap::classify(
            &fs::read(self.artifacts.join(format!("{stem}.pcap")))?,
            &crate::pcap::Policy::from_toml(&text)?,
            30,
        )?;
        fs::write(
            self.artifacts.join(format!("{stem}.report.json")),
            serde_json::to_vec_pretty(&report)?,
        )?;
        if !evidence::contained(&report) {
            return fail(format!("{stem}: uplink capture leaked or was blind"));
        }
        Ok(())
    }
    fn daemon_capture_control(&mut self, stem: &str) -> Result<()> {
        let stem = format!("{stem}-control");
        self.capture("wan", A.gwhost.wan_if, &stem)?;
        let mut markers = Vec::new();
        self.service_check(&mut markers)?;
        self.uplink_fault(&mut markers)?;
        self.stop_captures()?;
        let report = evidence::report(&self.artifacts, &stem, &markers, false, self.exit_port)?;
        evidence::injected_only(
            &report,
            &fs::read(self.artifacts.join(format!("{stem}.pcap")))?,
            markers.last().ok_or("control marker")?,
        )?;
        self.cmd("wan", "nft", &["delete", "table", "inet", "lab_inject"])?;
        Ok(())
    }
    #[allow(clippy::too_many_lines)] // Keep foreign-link setup and its containment oracle together.
    fn daemon_foreign(
        &mut self,
        child: &mut Group,
        markers: &mut Vec<String>,
        stem: &str,
        root: &Path,
    ) -> Result<String> {
        child.signal(Signal::STOP);
        self.cmd("gwhost", "sysctl", &["-q", "-w", "net.ipv4.ip_forward=1"])?;
        self.cmd(
            "gwhost",
            "ip",
            &[
                "link",
                "add",
                "foreign-host",
                "type",
                "veth",
                "peer",
                "name",
                "foreign0",
            ],
        )?;
        self.cmd(
            "gwhost",
            "ip",
            &["link", "set", "foreign0", "netns", "scupper"],
        )?;
        self.cmd("gwhost", "ip", &["link", "set", "foreign-host", "up"])?;
        self.cmd("scupper", "ip", &["link", "set", "foreign0", "up"])?;
        self.cmd("scupper", "tc", &["qdisc", "add", "dev", "wg0", "clsact"])?;
        self.cmd(
            "scupper",
            "tc",
            &[
                "filter",
                "add",
                "dev",
                "wg0",
                "ingress",
                "protocol",
                "all",
                "pref",
                "1",
                "matchall",
                "action",
                "vlan",
                "push_eth",
                "dst_mac",
                "02:00:00:00:13:01",
                "src_mac",
                "02:00:00:00:13:02",
                "action",
                "mirred",
                "egress",
                "redirect",
                "dev",
                "foreign0",
            ],
        )?;
        let (code, report) = self.check_result(&Self::boot_binary()?, root)?;
        if code != 2 {
            return fail(format!("L13 expected check 2: {code}: {report}"));
        }
        let control_stem = format!("{stem}-foreign-control");
        self.capture("gwhost", "foreign-host", &control_stem)?;
        let marker = Self::marker()?;
        markers.push(marker.clone());
        let mut stream = self.daemon_flow("udp", "client", &marker, stem)?;
        self.runner.dwell(Duration::from_secs(1))?;
        self.stop_capture()?;
        let control = fs::read(self.artifacts.join(format!("{control_stem}.pcap")))?;
        if !contains_marker(&control, &marker)? {
            return fail("L13 foreign-side positive control was blind");
        }
        self.capture("gwhost", "foreign-host", &format!("{stem}-foreign"))?;
        let start = Instant::now();
        let resumed_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        child.signal(Signal::CONT);
        let down = self.daemon_wait(
            "L13 foreign link down and redirect removed",
            Duration::from_secs(8),
            |lab| {
                let links: serde_json::Value = serde_json::from_str(&lab.cmd(
                    "scupper",
                    "ip",
                    &["-j", "link", "show", "foreign0"],
                )?)?;
                let up = links[0]["flags"]
                    .as_array()
                    .is_some_and(|flags| flags.iter().any(|v| v == "UP"));
                let hooks = lab.cmd(
                    "scupper",
                    "tc",
                    &["-j", "filter", "show", "dev", "wg0", "ingress"],
                )?;
                Ok(!up && !hooks.contains("mirred"))
            },
        )?;
        self.runner.dwell(Duration::from_millis(500))?;
        self.stop_capture()?;
        let foreign = crate::pcap::observe(&fs::read(
            self.artifacts.join(format!("{stem}-foreign.pcap")),
        )?)?;
        let last_packet = foreign
            .iter()
            .filter(|p| p.protocol == 17 && p.payload.get(8..) == Some(marker.as_bytes()))
            .map(|p| {
                u128::from(p.timestamp.seconds) * 1_000_000_000
                    + u128::from(p.timestamp.nanoseconds)
            })
            .max()
            .unwrap_or(resumed_at);
        let window = last_packet.saturating_sub(resumed_at) / 1_000_000;
        if window > 8000 || window > down + 250 {
            return fail(format!(
                "L13 packets continued past containment: window_ms={window}, down_ms={down}"
            ));
        }
        stream.stop(Signal::TERM)?;
        self.cmd("gwhost", "ip", &["link", "del", "foreign-host"])?;
        self.daemon_wait("L13 forwarding restored", Duration::from_secs(12), |lab| {
            Ok(lab
                .cmd("scupper", "sysctl", &["-n", "net.ipv4.ip_forward"])?
                .trim()
                == "1")
        })?;
        Ok(format!(
            "check=2; detection_and_containment_ms={down}; observed_window_ms={window}; total_elapsed_ms={}; bound_ms=8000; foreign_capture_control=true; redirect_removed=true",
            start.elapsed().as_millis()
        ))
    }
    fn daemon_sysctl_fixture(&mut self, child: &mut Group) -> Result<String> {
        child.signal(Signal::STOP);
        let before = self.daemon_sysctls()?;
        self.cmd("scupper", "sysctl", &["-q", "-w", "net.ipv4.ip_forward=0"])?;
        let zero = self.daemon_sysctls()?;
        self.cmd(
            "scupper",
            "sysctl",
            &["-q", "-w", "net.ipv4.conf.wg0.accept_redirects=1"],
        )?;
        let at_resume = self.daemon_sysctls()?;
        if !before
            .iter()
            .any(|(key, value)| !key.ends_with("forwarding") && at_resume.get(key) != Some(value))
        {
            return fail("V03 positive control: no hardening drift at resume");
        }
        fs::write(
            self.artifacts.join("V03-ip-forward.json"),
            serde_json::to_vec_pretty(
                &serde_json::json!({"before":before,"zero":zero,"at_resume":at_resume}),
            )?,
        )?;
        for (key, before) in &before {
            if zero.get(key) != Some(before)
                && key != "net.ipv4.ip_forward"
                && !key.ends_with(".forwarding")
                && !key.ends_with(".accept_redirects")
            {
                return fail(format!(
                    "V03 ip_forward changed {key}; see V03-ip-forward.json"
                ));
            }
        }
        child.signal(Signal::CONT);
        let restored = self.daemon_wait(
            "V03 all hardening restored",
            Duration::from_secs(12),
            |lab| {
                let observed = lab.daemon_sysctls()?;
                Ok(before.iter().all(|(k, v)| observed.get(k) == Some(v)))
            },
        )?;
        self.boot_sysctls()?;
        Ok(format!(
            "reapply_all_hardening_ms={restored}; fixture=V03-ip-forward.json; rp_filter_unchanged=true"
        ))
    }
    fn daemon_sysctls(&mut self) -> Result<std::collections::BTreeMap<String, String>> {
        let mut values = std::collections::BTreeMap::new();
        let mut keys: Vec<_> = scupper_core::render::desired_sysctls(
            &[
                scupper_core::rules::IfName::new("lo")?,
                scupper_core::rules::IfName::new("wg0")?,
                scupper_core::rules::IfName::new("ex-ch1")?,
            ],
            true,
        )
        .into_iter()
        .map(|v| v.key.to_string())
        .collect();
        for name in ["all", "default", "lo", "wg0", "ex-ch1"] {
            for key in [
                "forwarding",
                "accept_redirects",
                "rp_filter",
                "send_redirects",
                "secure_redirects",
                "accept_source_route",
                "log_martians",
                "route_localnet",
            ] {
                keys.push(format!("net.ipv4.conf.{name}.{key}"));
            }
        }
        keys.sort();
        keys.dedup();
        let mut args = vec!["-n"];
        args.extend(keys.iter().map(String::as_str));
        let output = self.cmd("scupper", "sysctl", &args)?;
        let observed: Vec<_> = output.lines().map(str::trim).collect();
        if observed.len() != keys.len() {
            return fail("incomplete daemon sysctl inventory");
        }
        values.extend(
            keys.into_iter()
                .zip(observed.into_iter().map(str::to_owned)),
        );
        Ok(values)
    }
    fn daemon_dead_flow(
        &mut self,
        case: &str,
        markers: &mut Vec<String>,
        stem: &str,
    ) -> Result<String> {
        let marker = Self::marker()?;
        markers.push(marker.clone());
        let mut server = self.daemon_flow("server", "internet", &marker, stem)?;
        let mut client = self.daemon_flow("client", "client", &marker, stem)?;
        let artifact_root = self.artifacts.clone();
        self.daemon_wait(
            "established bidirectional flow",
            Duration::from_secs(5),
            |_| {
                for mode in ["client", "server"] {
                    let file = artifact_root.join(format!("{stem}-{mode}.jsonl"));
                    let text = fs::read_to_string(file).unwrap_or_default();
                    let active = text
                        .lines()
                        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
                        .any(|v| v["received"].as_u64().is_some_and(|n| n > 0));
                    if !active {
                        return Ok(false);
                    }
                }
                Ok(true)
            },
        )?;
        let server_log = artifact_root.join(format!("{stem}-server.jsonl"));
        let sent_before = flow_counts(&server_log)?.0;
        let started = Instant::now();
        if case == "L3" {
            self.runner.input(&Invocation::new("wan", "nft", &["-f", "-"]), Some(b"table inet daemon_exit_down { chain forward { type filter hook forward priority -100; ip daddr 203.0.113.2 udp dport 51820 drop; } }\n"))?;
            // L3 is the transport oracle: a stalled established stream cannot
            // emerge onto the physical uplink, even while the old session exists.
            self.daemon_wait("L3 automatic fail-closed", Duration::from_secs(40), |lab| {
                Ok(lab
                    .cmd("scupper", "ip", &["route", "show", "default"])?
                    .contains("unreachable"))
            })?;
            let root = self.private.join("boot-root");
            let (code, report) = self.check_result(&Self::boot_binary()?, &root)?;
            if code != 4 {
                return fail(format!("L3 expected check 4: {code}: {report}"));
            }
            self.cmd(
                "wan",
                "nft",
                &["delete", "table", "inet", "daemon_exit_down"],
            )?;
        } else {
            let before: serde_json::Value = serde_json::from_str(&self.cmd(
                "scupper",
                "ip",
                &["-j", "link", "show", "ex-ch1"],
            )?)?;
            self.cmd("scupper", "ip", &["link", "del", "ex-ch1"])?;
            self.daemon_wait("L4 recreated owned exit", Duration::from_secs(12), |lab| {
                let (_, text) = lab.runner.output(
                    &Invocation::new("scupper", "ip", &["-j", "link", "show", "ex-ch1"]),
                    None,
                )?;
                let after: serde_json::Value = serde_json::from_str(&text).unwrap_or_default();
                Ok(after[0]["ifindex"].as_u64().is_some()
                    && after[0]["ifindex"] != before[0]["ifindex"])
            })?;
            self.runner.dwell(Duration::from_secs(3))?;
            let root = self.private.join("boot-root");
            let report: scupper_sys::boot::BootReport =
                serde_json::from_slice(&fs::read(root.join("run/scupper/boot.json"))?)?;
            let after: serde_json::Value = serde_json::from_str(&self.cmd(
                "scupper",
                "ip",
                &["-j", "link", "show", "ex-ch1"],
            )?)?;
            if report.owned_links.get("ex-ch1").copied().map(u64::from)
                != after[0]["ifindex"].as_u64()
            {
                return fail("L4 boot.json retained stale owned identity");
            }
            self.exit_port = self
                .cmd("scupper", "wg", &["show", "ex-ch1", "listen-port"])?
                .trim()
                .parse()?;
        }
        self.daemon_wait(
            "remote sender continued after fault",
            Duration::from_secs(3),
            |_| Ok(flow_counts(&server_log)?.0 > sent_before),
        )?;
        client.stop(Signal::TERM)?;
        server.stop(Signal::TERM)?;
        let sent_after = flow_counts(&server_log)?.0;
        Ok(format!(
            "fault_ms={}; persistent_bidirectional_control=true; remote_sender_continued=true; remote_sent_before={sent_before}; remote_sent_after={sent_after}",
            started.elapsed().as_millis()
        ))
    }
}
fn flow_counts(path: &Path) -> Result<(u64, u64)> {
    let mut sent = 0;
    let mut received = 0;
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok((0, 0)),
        Err(e) => return Err(e.into()),
    };
    for line in text.lines() {
        // A concurrently appended final line may be incomplete; only complete
        // JSON records are evidence. The final read follows process shutdown.
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(line) {
            sent += u64::from(value["sent"].as_u64().is_some_and(|n| n > 0));
            received += u64::from(value["received"].as_u64().is_some_and(|n| n > 0));
        }
    }
    Ok((sent, received))
}
fn contains_marker(bytes: &[u8], marker: &str) -> Result<bool> {
    Ok(crate::pcap::observe(bytes)?
        .iter()
        .any(|p| p.protocol == 17 && p.payload.get(8..) == Some(marker.as_bytes())))
}

fn daemon_wanted(case: &str) -> &'static str {
    match case {
        "L6" => {
            "check 3 and route event; tick-only stall stops watchdog while process lives; watchdog resumes; repair <=10s"
        }
        "L7" => "forwarding 0 <=2000ms; exact restore and conntrack flush; zero uplink leaks",
        "L13" => {
            "check 2; foreign link down and redirect removed <=8000ms; packet window and total elapsed separate"
        }
        "L16" => "single exit down 4 then active route/healthy service by itself",
        "L17-V14" => "name restored <=8000ms; identical inode; healthy traffic",
        "L52" => "check 3 RouteWrong; extra main route removed <=8000ms",
        "V03" => "ip_forward changes only forwarding/accept_redirects; full hardening reapplied",
        "L3" | "L4" => "persistent established flow and remote sender; zero uplink leaks",
        _ => "unknown",
    }
}
