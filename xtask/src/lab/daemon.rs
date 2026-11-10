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
    os::unix::{fs::PermissionsExt, net::UnixDatagram},
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

const CASES: [&str; 10] = [
    "L6", "L7", "L13", "L16", "L17-V14", "L52", "L52b", "V03", "L3", "L4",
];

// Drain notifications continuously, including while fault commands or probes block.
struct NotifyCapture {
    messages: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    worker: Option<std::thread::JoinHandle<io::Result<()>>>,
}
impl NotifyCapture {
    fn drain(&self) -> Result<Vec<String>> {
        if self
            .worker
            .as_ref()
            .is_some_and(std::thread::JoinHandle::is_finished)
        {
            return fail("notify artifact worker stopped");
        }
        Ok(std::mem::take(
            &mut *self.messages.lock().map_err(|_| "notify lock poisoned")?,
        ))
    }

    fn start(socket: UnixDatagram, path: &Path) -> Result<Self> {
        socket.set_read_timeout(Some(Duration::from_millis(25)))?;
        let mut file = fs::File::create(path)?;
        let messages = Arc::new(Mutex::new(Vec::new()));
        let pending = messages.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = stop.clone();
        let worker = std::thread::spawn(move || {
            let mut bytes = vec![0; 65536];
            loop {
                match socket.recv(&mut bytes) {
                    Ok(len) => {
                        let message = String::from_utf8_lossy(&bytes[..len]).into_owned();
                        writeln!(
                            file,
                            "{}",
                            serde_json::json!({
                                "at": std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis(),
                                "message": message
                            })
                        )?;
                        pending
                            .lock()
                            .map_err(|_| io::Error::other("notify lock poisoned"))?
                            .push(message);
                    }
                    Err(e)
                        if matches!(
                            e.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                        ) =>
                    {
                        if stopping.load(Ordering::Relaxed) {
                            return file.sync_all();
                        }
                    }
                    Err(e) => return Err(e),
                }
            }
        });
        Ok(Self {
            messages,
            stop,
            worker: Some(worker),
        })
    }
}
impl Drop for NotifyCapture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

// Own both the daemon and fixture cleanup before any fallible fault operation.
struct DaemonGuard<'a> {
    lab: &'a mut Lab,
    child: Option<Group>,
    armed: bool,
    case: String,
    notify: Option<NotifyCapture>,
}
impl DaemonGuard<'_> {
    #[allow(clippy::too_many_lines)] // Keep start/restart continuity and fault cleanup ordering together.
    fn run(&mut self, case: &str) -> Result<String> {
        let root = self.lab.prepare_check_v2()?;
        self.lab.boot_gateway(&[], "daemon-boot")?;
        self.lab.service_check(&mut Vec::new())?;
        let stem = format!("daemon-{case}-startup");
        let marker = Lab::marker()?;
        let port = 8082
            + u16::try_from(
                CASES
                    .iter()
                    .position(|c| *c == case)
                    .ok_or("unknown daemon case")?,
            )?;
        let mut server = self
            .lab
            .daemon_flow_port("server", "internet", &marker, &stem, port, 90)?;
        self.lab
            .daemon_wait("startup TCP listener", Duration::from_secs(5), |lab| {
                Ok(lab
                    .cmd("internet", "ss", &["-ltnH"])?
                    .contains(&format!(":{port}")))
            })?;
        let mut client = self
            .lab
            .daemon_flow_port("client", "client", &marker, &stem, port, 90)?;
        let flow = self.lab.artifacts.join(format!("{stem}-client.jsonl"));
        self.lab
            .daemon_wait("pre-start established flow", Duration::from_secs(5), |_| {
                Ok(flow_counts(&flow)?.1 >= 5)
            })?;
        let before = self.lab.daemon_snapshot()?;
        let first_seq = read_since(&root.join("var-lib/scupper"), 0, None)
            .filter_map(std::result::Result::ok)
            .map(|event| event.seq)
            .max()
            .unwrap_or(0);
        let (child, notify) = self.lab.daemon_start(case, &root)?;
        self.child = Some(child);
        self.notify = Some(notify);
        let notify = self.notify.as_ref().ok_or("missing notify capture")?;
        self.lab.daemon_ready_tick(notify)?;
        self.lab.service_check(&mut Vec::new())?;
        if before != self.lab.daemon_snapshot()? {
            return fail("daemon start changed healthy kernel state");
        }
        self.child
            .as_mut()
            .ok_or("missing daemon")?
            .stop_timeout(Signal::TERM, Duration::from_secs(30))?;
        if before != self.lab.daemon_snapshot()? {
            return fail("SIGTERM changed healthy kernel state");
        }
        notify.drain()?;
        drop(self.child.take());
        // The supervisor can exit before the old audit worker releases its
        // lock. Fence that handoff before launching the restart measurement.
        let previous_writer = scupper_sys::lock::WriterLock::acquire_timeout(
            root.join("var-lib/scupper/events"),
            Duration::from_secs(5),
        )?;
        if !root.join("var-lib/scupper/events/clean").exists() {
            return fail("initial daemon stop did not finish its event log");
        }
        drop(previous_writer);
        self.child = Some(self.lab.daemon_spawn(case, &root, "restart")?);
        self.lab.daemon_ready_tick(notify)?;
        let replies_at_restart = flow_counts(&flow)?.1;
        self.lab.daemon_wait(
            "continuity reply after restart READY",
            Duration::from_secs(2),
            |_| Ok(flow_counts(&flow)?.1 > replies_at_restart),
        )?;
        self.lab.service_check(&mut Vec::new())?;
        if before != self.lab.daemon_snapshot()? {
            return fail("daemon restart changed healthy kernel state");
        }
        self.lab.runner.dwell(Duration::from_millis(500))?;
        client.stop(Signal::TERM)?;
        server.stop(Signal::TERM)?;
        verify_continuity(&flow)?;
        verify_continuity(&self.lab.artifacts.join(format!("{stem}-server.jsonl")))?;
        for event in read_since(&root.join("var-lib/scupper"), first_seq, None)
            .filter_map(std::result::Result::ok)
        {
            if matches!(
                event.kind,
                scupper_proto::EventKind::Repair {
                    kind: scupper_proto::StepKind::ForwardingOff
                        | scupper_proto::StepKind::RouteReplace
                        | scupper_proto::StepKind::FlushConntrack,
                    ..
                }
            ) {
                return fail("daemon startup/restart executed a closing repair");
            }
        }
        let child = self.child.as_mut().ok_or("missing daemon")?;
        let observed = self.lab.daemon_fault(case, child, notify, &root)?;
        let mounts = super::mounts::save(
            &self.lab.artifacts,
            &format!("daemon-{case}-before-stop"),
            child.supervised_pid()?,
        )?;
        if mounts > 1 {
            return fail(format!("{case} left {mounts} stacked namespace mounts"));
        }
        let before = self.lab.daemon_snapshot()?;
        child.stop_timeout(Signal::TERM, Duration::from_secs(30))?;
        if before != self.lab.daemon_snapshot()? {
            return fail("SIGTERM changed kernel state");
        }
        if !root.join("var-lib/scupper/events/clean").exists() {
            return fail("SIGTERM did not write clean event marker");
        }
        // This trial intentionally runs one initial process and one restart.
        // Check each process emitted exactly one start, with no false audit alarm.
        let events = read_since(&root.join("var-lib/scupper"), first_seq, None)
            .collect::<io::Result<Vec<_>>>()?;
        if events
            .iter()
            .filter(|event| matches!(event.kind, scupper_proto::EventKind::DaemonStarted { .. }))
            .count()
            != 2
        {
            return fail("expected exactly one DaemonStarted per initial/restarted process");
        }
        if events.iter().any(|event| {
            matches!(
                event.kind,
                scupper_proto::EventKind::PersistenceFailed {
                    reason: scupper_proto::Reason::EventWrite
                }
            )
        }) {
            return fail("ordinary daemon start/restart reported an event persistence failure");
        }
        // L4 must also survive reopening the durable owned-link handoff.
        if case == "L4" {
            drop(self.child.take());
            notify.drain()?;
            self.child = Some(self.lab.daemon_spawn(case, &root, "recreated-restart")?);
            self.lab.daemon_ready_tick(notify)?;
            self.lab.service_check(&mut Vec::new())?;
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
        let mounts = (|| {
            let pid = self
                .child
                .as_ref()
                .map(Group::supervised_pid)
                .transpose()?
                .flatten();
            let count = super::mounts::save(
                &self.lab.artifacts,
                &format!("daemon-{}-before-cleanup", self.case),
                pid,
            )?;
            if count > 1 {
                return fail(format!(
                    "{} left {count} stacked namespace mounts",
                    self.case
                ));
            }
            Ok(())
        })();
        if let Some(mut child) = self.child.take() {
            child.signal(Signal::CONT);
            let _ = child.stop_timeout(Signal::TERM, Duration::from_secs(5));
            drop(child); // Group kills/reaps on any failed graceful stop.
        }
        if let Some(notify) = self.notify.take() {
            drop(notify);
        }
        let saved = save_event_artifacts(
            &self.lab.private.join("boot-root/var-lib/scupper/events"),
            &self
                .lab
                .artifacts
                .join(format!("daemon-{}/events", self.case)),
        );
        let _ = fs::remove_file(self.lab.private.join("boot-root/run/scupper/stall-tick"));
        let marker = if self
            .lab
            .private
            .join("boot-root/run/scupper/route-switch")
            .exists()
        {
            fail("clean daemon stop left route-switch marker")
        } else {
            Ok(())
        };
        let captures = self.lab.stop_captures();
        // Absent resources are fine. Verify the baseline after ordered boot.
        for (ns, program, args) in [
            (
                "scupper",
                "tc",
                vec!["qdisc", "del", "dev", "wg0", "clsact"],
            ),
            ("scupper", "ip", vec!["link", "del", "foreign0"]),
            (
                "scupper",
                "ip",
                vec!["-6", "route", "del", "2001:db8:52::/64", "dev", "ex-ch1"],
            ),
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
        mounts.and(saved).and(marker).and(captures).and(restored)
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
        for case in CASES {
            self.runner.phase =
                Instant::now() + Duration::from_secs(if case == "L3" { 300 } else { 180 });
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
            case: case.into(),
            notify: None,
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
        if self
            .cmd("scupper", "ip", &["-6", "route", "show", "table", "main"])?
            .contains("2001:db8:52::/64")
        {
            return fail("unclean baseline: daemon IPv6 extra route remains");
        }
        let tables = self.cmd("wan", "nft", &["list", "tables"])?;
        if tables.contains("lab_inject") || tables.contains("daemon_exit_down") {
            return fail("unclean baseline: daemon fault nft table remains");
        }
        self.service_check(&mut Vec::new())
            .map_err(|e| format!("unclean baseline: service check: {e}").into())
    }
    fn daemon_start(&mut self, case: &str, root: &Path) -> Result<(Group, NotifyCapture)> {
        let artifacts = self.artifacts.join(format!("daemon-{case}"));
        fs::create_dir_all(&artifacts)?;
        let notify_path = self.private.join(format!("notify-{case}.sock"));
        let notify = NotifyCapture::start(
            UnixDatagram::bind(&notify_path)?,
            &artifacts.join("notify.jsonl"),
        )?;
        let child = self.daemon_spawn(case, root, "start")?;
        Ok((child, notify))
    }
    fn daemon_spawn(&mut self, case: &str, root: &Path, stage: &str) -> Result<Group> {
        let daemon = Self::boot_binary()?.with_file_name("scupperd");
        let env = format!(
            "NOTIFY_SOCKET={}",
            self.private.join(format!("notify-{case}.sock")).display()
        );
        self.runner.background(
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
            &self.artifacts.join(format!("daemon-{case}/{stage}.stdout")),
        )
    }
    fn daemon_ready_tick(&mut self, notify: &NotifyCapture) -> Result<()> {
        let mut ready = false;
        let mut complete = false;
        self.daemon_wait(
            "READY and first complete tick",
            Duration::from_secs(40),
            |_| {
                for message in notify.drain()? {
                    ready |= message == "READY=1";
                    complete |= message == "WATCHDOG=1";
                }
                Ok(ready && complete)
            },
        )?;
        Ok(())
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
    fn daemon_flow(
        &mut self,
        mode: &str,
        ns: &str,
        marker: &str,
        stem: &str,
        seconds: u64,
    ) -> Result<Group> {
        self.daemon_flow_port(
            mode,
            ns,
            marker,
            stem,
            if mode == "udp" { 8080 } else { 8081 },
            seconds,
        )
    }
    #[allow(clippy::too_many_arguments)] // Keep the flow endpoint and lifetime explicit.
    fn daemon_flow_port(
        &mut self,
        mode: &str,
        ns: &str,
        marker: &str,
        stem: &str,
        port: u16,
        seconds: u64,
    ) -> Result<Group> {
        let address = format!("{}:{port}", A.internet.peer);
        self.runner.background(
            &Invocation::new(
                ns,
                &self.executable,
                &[
                    "flow",
                    "--mode",
                    mode,
                    "--seconds",
                    &seconds.to_string(),
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
        notify: &NotifyCapture,
        root: &Path,
    ) -> Result<String> {
        let stem = format!("daemon-{case}");
        let mut markers = Vec::new();
        self.capture("wan", A.gwhost.wan_if, &stem)?;
        self.service_check(&mut markers)?;
        let start_port = self.exit_port;
        let measurement = match case {
            "L6" => {
                self.daemon_wait("pre-stall watchdog", Duration::from_secs(8), |_| {
                    Ok(notify.drain()?.iter().any(|s| s == "WATCHDOG=1"))
                })?;
                self.daemon_wait(
                    "watchdog follows the two-second tick cadence",
                    Duration::from_secs(3),
                    |_| Ok(notify.drain()?.iter().any(|s| s == "WATCHDOG=1")),
                )?;
                let before = read_since(&root.join("var-lib/scupper"), 0, None)
                    .filter_map(std::result::Result::ok)
                    .map(|e| e.seq)
                    .max()
                    .unwrap_or(0);
                let hook = root.join("run/scupper/stall-tick");
                fs::write(&hook, b"stall")?;
                self.runner.dwell(Duration::from_millis(2200))?;
                notify.drain()?;
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
                    || notify.drain()?.iter().any(|s| s == "WATCHDOG=1")
                {
                    return fail("tick stall: repair or watchdog continued");
                }
                child.alive()?;
                child.assert_not_stopped()?;
                fs::remove_file(hook)?;
                let repaired = self.daemon_route_healthy(Duration::from_secs(10))?;
                self.daemon_wait("post-stall watchdog", Duration::from_secs(8), |_| {
                    Ok(notify.drain()?.iter().any(|s| s == "WATCHDOG=1"))
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
                let mut stream = self.daemon_flow("udp", "client", &marker, &stem, 90)?;
                self.runner.dwell(Duration::from_millis(300))?;
                // Inject after a completed iteration and measure the actual closure.
                notify.drain()?;
                self.daemon_wait("pre-flush watchdog", Duration::from_secs(8), |_| {
                    Ok(notify.drain()?.iter().any(|s| s == "WATCHDOG=1"))
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
                let mut stream = self.daemon_flow("udp", "client", &marker, &stem, 90)?;
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
                    Ok(NetnsHandle::open("/run/netns/scupper")
                        .is_ok_and(|held| held.identity() == before))
                })?;
                let remount = start.elapsed().as_millis();
                let mounts = super::mounts::save(
                    &self.artifacts,
                    "daemon-L17-V14-after-restore",
                    Some(child.supervised_pid()?.ok_or("missing live L17 daemon")?),
                )?;
                if mounts != 1 {
                    return fail(format!("L17 restore left {mounts} namespace mounts"));
                }
                let after = NetnsHandle::open("/run/netns/scupper")?.identity();
                if before != after {
                    return fail("L17 created a second namespace");
                }
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
                    "remount_ms={remount}; mounts={mounts}; same_inode=true; second_namespace=false; stream_sent={sent}; stream_replies={replies}"
                )
            }
            "L52" | "L52b" => {
                child.signal(Signal::STOP);
                let first_seq = read_since(&root.join("var-lib/scupper"), 0, None)
                    .filter_map(std::result::Result::ok)
                    .map(|event| event.seq)
                    .max()
                    .unwrap_or(0);
                // M2 has one configured exit. IPv6 has no selected exit: its
                // desired default is Unreachable even while ex-ch1 is owned,
                // correctly configured and UP. This isolates the same-family
                // desired-default restriction without a foreign/down link.
                let (family, prefix) = if case == "L52b" {
                    ("-6", "2001:db8:52::/64")
                } else {
                    ("-4", "198.18.0.0/24")
                };
                self.cmd(
                    "scupper",
                    "ip",
                    &[family, "route", "add", prefix, "dev", "ex-ch1"],
                )?;
                let (code, report) = self.check_result(&Self::boot_binary()?, root)?;
                if (case == "L52"
                    && (code != 3 || report["verdict"]["Degraded"].get("RouteWrong").is_none()))
                    || (case == "L52b" && !matches!(code, 2 | 3))
                {
                    return fail(format!(
                        "{case} unexpected route-drift check: {code}: {report}"
                    ));
                }
                let recovery = Instant::now();
                child.signal(Signal::CONT);
                let elapsed =
                    self.daemon_wait("extra route removed", Duration::from_secs(8), |lab| {
                        Ok(!lab
                            .cmd("scupper", "ip", &[family, "route", "show", "table", "main"])?
                            .contains(prefix))
                    })?;
                if case == "L52b" {
                    self.daemon_wait(
                        "L52b forwarding recovered",
                        Duration::from_secs(20).saturating_sub(recovery.elapsed()),
                        |lab| {
                            Ok(lab
                                .cmd("scupper", "sysctl", &["-n", "net.ipv4.ip_forward"])?
                                .trim()
                                == "1"
                                && lab
                                    .cmd("scupper", "ip", &["route", "show", "default"])?
                                    .contains("dev ex-ch1"))
                        },
                    )?;
                    self.service_check(&mut markers)?;
                    if recovery.elapsed() > Duration::from_secs(20) {
                        return fail("L52b service did not recover within 20s");
                    }
                    self.daemon_wait("L52b closing repair events", Duration::from_secs(5), |_| {
                        let kinds: Vec<_> =
                            read_since(&root.join("var-lib/scupper"), first_seq, None)
                                .filter_map(std::result::Result::ok)
                                .filter_map(|event| match event.kind {
                                    scupper_proto::EventKind::Repair {
                                        kind,
                                        result: scupper_proto::Outcome::Succeeded,
                                        ..
                                    } => Some(kind),
                                    _ => None,
                                })
                                .collect();
                        Ok(kinds.contains(&scupper_proto::StepKind::ForwardingOff)
                            && kinds.contains(&scupper_proto::StepKind::FlushConntrack))
                    })?;
                }
                format!(
                    "check={code}; extra_route_removed_ms={elapsed}; closing_path={}",
                    case == "L52b"
                )
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
        // capture() waits for tcpdump's listening acknowledgement before any
        // injection. Distinct attempts also use fresh UDP tuples, avoiding a
        // single lost startup packet or a stale conntrack mapping blinding it.
        self.capture("gwhost", "foreign-host", &control_stem)?;
        let mut control_markers = Vec::new();
        for _ in 0..3 {
            let marker = Self::marker()?;
            markers.push(marker.clone());
            control_markers.push(marker.clone());
            self.send("client", "udp", A.internet.peer, &marker, false)?;
            self.runner.dwell(Duration::from_millis(250))?;
        }
        self.stop_capture()?;
        let control = fs::read(self.artifacts.join(format!("{control_stem}.pcap")))?;
        let control_seen = foreign_control(&control, &control_markers)?;
        fs::write(
            self.artifacts.join(format!("{control_stem}.json")),
            serde_json::to_vec_pretty(&serde_json::json!({
                "attempted": control_markers,
                "observed": control_seen,
            }))?,
        )?;
        // The continuous measurement keeps its own marker and all original
        // pre-containment packet and last-packet deadline requirements.
        let marker = Self::marker()?;
        markers.push(marker.clone());
        let mut stream = self.daemon_flow("udp", "client", &marker, stem, 90)?;
        self.capture("gwhost", "foreign-host", &format!("{stem}-foreign"))?;
        self.runner.dwell(Duration::from_millis(500))?;
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
        if !foreign.iter().any(|p| {
            p.protocol == 17
                && p.payload.get(8..) == Some(marker.as_bytes())
                && u128::from(p.timestamp.seconds) * 1_000_000_000
                    + u128::from(p.timestamp.nanoseconds)
                    <= resumed_at
        }) {
            return fail("L13 measurement capture missed pre-containment redirect packets");
        }
        let last_packet = foreign
            .iter()
            .filter(|p| p.protocol == 17 && p.payload.get(8..) == Some(marker.as_bytes()))
            .map(|p| {
                u128::from(p.timestamp.seconds) * 1_000_000_000
                    + u128::from(p.timestamp.nanoseconds)
            })
            .max()
            .ok_or("L13 measurement capture was blind to injected redirect packets")?;
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
            "check=2; detection_and_containment_ms={down}; observed_window_ms={window}; total_elapsed_ms={}; bound_ms=8000; foreign_capture_control=true; control_markers_seen={control_seen}/3; redirect_removed=true",
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
    #[allow(clippy::too_many_lines)] // Keep each fault and its live-flow evidence together.
    fn daemon_dead_flow(
        &mut self,
        case: &str,
        markers: &mut Vec<String>,
        stem: &str,
    ) -> Result<String> {
        let marker = Self::marker()?;
        markers.push(marker.clone());
        let stale_bound = self.site.health().handshake_stale() + Duration::from_secs(2 * 2 + 10);
        let seconds = if case == "L3" {
            stale_bound.as_secs() + 60
        } else {
            90
        };
        let mut server = self.daemon_flow("server", "internet", &marker, stem, seconds)?;
        let mut client = self.daemon_flow("client", "client", &marker, stem, seconds)?;
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
        let mut udp_counts = None;
        if case == "L3" {
            let udp_marker = Self::marker()?;
            markers.push(udp_marker.clone());
            let mut udp = self.daemon_flow("udp", "client", &udp_marker, stem, seconds)?;
            let udp_log = artifact_root.join(format!("{stem}-udp.jsonl"));
            self.daemon_wait("L3 established UDP canary", Duration::from_secs(5), |_| {
                udp.alive()?;
                Ok(flow_counts(&udp_log)?.1 > 0)
            })?;
            self.runner.input(&Invocation::new("wan", "nft", &["-f", "-"]), Some(b"table inet daemon_exit_down {\n  chain forward {\n    type filter hook forward priority -100;\n    ip daddr 203.0.113.2 udp dport 51820 drop;\n  }\n}\n"))?;
            // The UDP canary keeps client traffic entering the gateway while TCP
            // stalls. Neither flow may emerge onto the physical uplink.
            // With one exit, common-mode probe failures cannot mark it Down.
            // Wait through handshake staleness, two 2s ticks and scheduling slack.
            // The uplink capture stays active for this entire interval; the
            // case oracle below requires zero violations, including client data.
            self.daemon_wait("L3 automatic fail-closed", stale_bound, |lab| {
                Ok(lab
                    .cmd("scupper", "ip", &["route", "show", "default"])?
                    .contains("unreachable"))
            })?;
            udp_counts = Some(self.daemon_verify_closed_flow(
                &mut client,
                &mut server,
                &mut udp,
                &udp_log,
            )?);
            self.cmd(
                "wan",
                "nft",
                &["delete", "table", "inet", "daemon_exit_down"],
            )?;
            udp.stop(Signal::TERM)?;
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
            self.daemon_wait(
                "remote sender continued after fault",
                Duration::from_secs(3),
                |_| Ok(flow_counts(&server_log)?.0 > sent_before),
            )?;
        }
        client.stop(Signal::TERM)?;
        server.stop(Signal::TERM)?;
        let sent_after = flow_counts(&server_log)?.0;
        let continuity = udp_counts.map_or_else(
            || "remote_sender_continued=true".to_owned(),
            |(closed, after)| format!("udp_sent_at_closed={closed}; udp_sent_after={after}"),
        );
        let client_last_sent_ms =
            flow_last_sent_ms(&artifact_root.join(format!("{stem}-client.jsonl")))?;
        let server_last_sent_ms = flow_last_sent_ms(&server_log)?;
        Ok(format!(
            "fault_ms={}; persistent_bidirectional_control=true; {continuity}; remote_sent_before={sent_before}; remote_sent_after={sent_after}; client_last_sent_ms={client_last_sent_ms:?}; server_last_sent_ms={server_last_sent_ms:?}; flow_seconds={seconds}",
            started.elapsed().as_millis()
        ))
    }
    fn daemon_verify_closed_flow(
        &mut self,
        client: &mut Group,
        server: &mut Group,
        udp: &mut Group,
        udp_log: &Path,
    ) -> Result<(u64, u64)> {
        client.alive()?;
        server.alive()?;
        udp.alive()?;
        let closed_count = flow_counts(udp_log)?.0;
        self.daemon_wait(
            "client UDP continued after fail-closed",
            Duration::from_secs(3),
            |_| {
                client.alive()?;
                server.alive()?;
                udp.alive()?;
                Ok(flow_counts(udp_log)?.0 >= closed_count + 40)
            },
        )?;
        let root = self.private.join("boot-root");
        let (code, report) = self.check_result(&Self::boot_binary()?, &root)?;
        if code != 4 {
            return fail(format!("L3 expected check 4: {code}: {report}"));
        }
        let checked_count = flow_counts(udp_log)?.0;
        // Keep the drop and uplink capture in place through the post-closure
        // probe, and require fresh sends immediately before removing the drop.
        self.daemon_wait(
            "client UDP continued through closed-state checks",
            Duration::from_secs(3),
            |_| {
                client.alive()?;
                server.alive()?;
                udp.alive()?;
                Ok(flow_counts(udp_log)?.0 > checked_count)
            },
        )?;
        Ok((closed_count, flow_counts(udp_log)?.0))
    }
}
fn save_event_artifacts(source: &Path, target: &Path) -> Result<()> {
    fs::create_dir_all(target)?;
    if !source.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            let copy = target.join(entry.file_name());
            fs::copy(entry.path(), &copy)?;
            fs::set_permissions(copy, fs::Permissions::from_mode(0o644))?;
        }
    }
    Ok(())
}
fn verify_continuity(path: &Path) -> Result<()> {
    let mut previous = None;
    let mut received = 0;
    let mut last_record = 0;
    for line in fs::read_to_string(path)?.lines() {
        let value: serde_json::Value = serde_json::from_str(line)?;
        last_record = value["elapsed_ms"].as_u64().ok_or("missing flow time")?;
        if value["received"].as_u64().unwrap_or(0) > 0 {
            let at = value["elapsed_ms"].as_u64().ok_or("missing flow time")?;
            if previous.is_some_and(|before| at > before + 500) {
                return fail("startup/restart interrupted established TCP traffic for over 500 ms");
            }
            previous = Some(at);
            received += 1;
        }
    }
    if previous.is_none_or(|at| last_record > at + 500) {
        return fail("startup/restart traffic stopped before measurement ended");
    }
    if received < 10 {
        return fail("startup continuity capture had too few replies");
    }
    Ok(())
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
fn flow_last_sent_ms(path: &Path) -> Result<Option<u64>> {
    Ok(fs::read_to_string(path)?
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter(|value| value["sent"].as_u64().is_some_and(|n| n > 0))
        .filter_map(|value| value["elapsed_ms"].as_u64())
        .next_back())
}
pub(super) fn foreign_control(bytes: &[u8], markers: &[String]) -> Result<usize> {
    let packets = crate::pcap::observe(bytes)?;
    let seen = markers
        .iter()
        .filter(|marker| {
            packets
                .iter()
                .any(|p| p.protocol == 17 && p.payload.get(8..) == Some(marker.as_bytes()))
        })
        .count();
    if seen == 0 {
        return fail("L13 foreign-side positive control was blind");
    }
    Ok(seen)
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
        "L52b" => {
            "IPv6 prefix through owned UP exit with no selected IPv6 default closes forwarding; route deleted; service recovers <=20s; clean baseline"
        }
        "V03" => "ip_forward changes only forwarding/accept_redirects; full hardening reapplied",
        "L3" => {
            "persistent TCP control; client UDP grows through fail-closed/check 4; zero uplink leaks"
        }
        "L4" => "persistent established flow and remote sender; zero uplink leaks",
        _ => "unknown",
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn copied_event_artifacts_are_readable_without_changing_sources() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../target/daemon-event-artifacts")
            .join(std::process::id().to_string());
        let source = root.join("source");
        let target = root.join("saved");
        fs::create_dir_all(&source).unwrap();
        let event = source.join("2026-11.jsonl");
        fs::write(&event, b"event\n").unwrap();
        fs::set_permissions(&event, fs::Permissions::from_mode(0o640)).unwrap();
        save_event_artifacts(&source, &target).unwrap();
        assert_eq!(
            fs::metadata(&event).unwrap().permissions().mode() & 0o777,
            0o640
        );
        let saved = target.join("2026-11.jsonl");
        assert_eq!(
            fs::metadata(&saved).unwrap().permissions().mode() & 0o777,
            0o644
        );
        assert_eq!(fs::read(saved).unwrap(), b"event\n");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn notify_artifact_keeps_every_message_even_when_consumers_drain() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../target/daemon-notify-artifacts")
            .join(std::process::id().to_string());
        fs::create_dir_all(&root).unwrap();
        let path = root.join("notify.jsonl");
        let (send, receive) = UnixDatagram::pair().unwrap();
        let capture = NotifyCapture::start(receive, &path).unwrap();
        for number in 0..100 {
            send.send(format!("STATUS={number}").as_bytes()).unwrap();
            if number % 5 == 0 {
                capture.drain().unwrap();
            }
        }
        drop(capture);
        let saved: Vec<serde_json::Value> = fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(saved.len(), 100);
        for (number, value) in saved.iter().enumerate() {
            assert_eq!(value["message"], format!("STATUS={number}"));
            assert!(value["at"].is_number());
        }
        fs::remove_dir_all(root).unwrap();
    }
}
