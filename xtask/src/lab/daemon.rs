//! Direct daemon execution in the lab host network and mount namespaces.
use super::{
    Lab, Result,
    addresses::A,
    command::{Group, Invocation},
    evidence::{self},
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

mod control_cases;
mod heartbeat;
mod m2_cases;

pub(super) fn short_boot_root(case: &str) -> std::path::PathBuf {
    Path::new("/run/scupper-lab").join(format!("{}-{case}", std::process::id()))
}

pub(super) const CASES: [&str; 31] = [
    "L1",
    "L2",
    "L5",
    "L8",
    "L9",
    "L9b",
    "L11",
    "L12",
    "L15",
    "L18",
    "L20",
    "L17-rebuild",
    "L6",
    "L7",
    "L13",
    "L16",
    "L17-V14",
    "L52",
    "L52b",
    "V03",
    "L3",
    "L4",
    "L10",
    "L53",
    "L53b",
    "heartbeat",
    "L14",
    "L43",
    "L44",
    "L50",
    "L9-host-link",
];

pub(super) fn host_rule_defaults(family: &str) -> &'static [(&'static str, &'static str)] {
    if family == "-4" {
        &[("0", "local"), ("32766", "main"), ("32767", "default")]
    } else {
        &[("0", "local"), ("32766", "main")]
    }
}

// READY and startup WATCHDOG notifications precede the first reconciler tick.
fn startup_complete(
    ready: bool,
    result: Option<&std::result::Result<scupper_proto::OpResult, scupper_proto::ApiError>>,
) -> bool {
    ready
        && matches!(
            result,
            Some(Ok(scupper_proto::OpResult::Ping {
                last_complete_iteration_age: Some(0..=4),
                operation: None,
                ..
            }))
        )
}

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
                            io::ErrorKind::WouldBlock
                                | io::ErrorKind::TimedOut
                                | io::ErrorKind::Interrupted
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
    baseline_version: Option<u64>,
}
impl DaemonGuard<'_> {
    #[allow(clippy::too_many_lines)] // Keep start/restart continuity and fault cleanup ordering together.
    fn run(&mut self, case: &str) -> Result<String> {
        if matches!(case, "L53" | "L53b" | "heartbeat") {
            return self.run_heartbeat(case);
        }
        if m2_cases::is_m2(case) {
            return self.run_m2(case);
        }
        if matches!(case, "L10" | "L14" | "L43" | "L44" | "L50") {
            return self.run_control(case);
        }
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
        super::mounts::verify_restored_peers(child.supervised_pid()?)?;
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
    #[allow(clippy::too_many_lines)] // Keep cleanup ordering and deadline restoration visible.
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
            super::mounts::verify_restored_peers(pid)
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
        self.lab.runner.probe_ca = None;
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
            ("gwhost", "tc", vec!["qdisc", "del", "dev", "eth0", "root"]),
            (
                "gwhost",
                "nft",
                vec!["delete", "table", "inet", "scupper_hb_test"],
            ),
            ("wan", "ip", vec!["route", "del", "198.51.100.10/32"]),
            (
                "internet",
                "ip",
                vec!["addr", "del", "198.51.100.10/32", "dev", "lo"],
            ),
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
            .reset_control_fixture()
            .and_then(|()| self.lab.restore_inheritance())
            .and_then(|()| self.lab.daemon_restore_host())
            .and_then(|()| self.lab.restore_host_rules())
            .and_then(|()| self.lab.boot_gateway(&[], "daemon-restore"))
            .and_then(|_| self.reset_m2_network())
            .and_then(|()| self.lab.wait_provider())
            .and_then(|()| self.lab.boot_fresh_client_handshake())
            .and_then(|()| self.lab.daemon_clean_baseline())
            .and_then(|()| super::mounts::verify_restored_peers(None))
            .and_then(|()| {
                let run = self.lab.private.join("boot-root/run/scupper");
                let _lease = scupper_sys::lock::SupervisorLease::try_acquire(&run)?;
                let _writer = scupper_sys::lock::WriterLock::try_acquire(&run)?;
                if run.join("control.sock").exists() {
                    return fail("daemon cleanup left control socket");
                }
                self.lab.cmd("scupper", "conntrack", &["-F"])?;
                Ok(())
            });
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
    pub(super) fn daemon_case(&mut self, selected: &str) -> Result<String> {
        if !CASES.contains(&selected) {
            return fail(format!("unknown daemon selection: {selected}"));
        }
        self.boot_root = short_boot_root(selected);
        self.boot_root_ready = false;
        self.prepare_check_v2()?;
        let mut observation = String::new();
        let first_group = self.runner.background_checkpoint();
        if self.daemon_host_baseline.is_none() {
            self.daemon_host_baseline = Some(self.daemon_host_sysctls()?);
        }
        // Only this suite needs periodic client traffic during a real reboot.
        let key = self.cmd("client", "wg", &["show", "wg0", "peers"])?;
        let peer = key.trim();
        self.cmd(
            "client",
            "wg",
            &["set", "wg0", "peer", peer, "persistent-keepalive", "5"],
        )?;
        let mut failures = Vec::new();
        let mut blocked = None;
        for case in CASES.into_iter().filter(|case| *case == selected) {
            self.runner.phase = self.runner.phase.max(
                Instant::now()
                    + Duration::from_secs(match case {
                        "L9" => 1200,
                        "L9b" => 900,
                        "L3" | "L16" | "L50" | "L9-host-link" | "L11" | "L10" => 300,
                        _ => 180,
                    }),
            );
            let started = Instant::now();
            let observed = if let Some(cause) = &blocked {
                fail(format!("skipped: baseline unavailable after {cause}"))
            } else {
                self.daemon_clean_baseline()
                    .and_then(|()| self.daemon_trial(case))
            };
            eprintln!(
                "daemon-{case}: elapsed_ms={}; {}",
                started.elapsed().as_millis(),
                observed
                    .as_ref()
                    .map_or_else(ToString::to_string, Clone::clone)
            );
            if let Ok(detail) = &observed {
                observation.clone_from(detail);
            }
            if let Err(error) = observed {
                if blocked.is_none() && self.daemon_clean_baseline().is_err() {
                    blocked = Some(format!("{case}: {error}"));
                }
                failures.push(format!("{case}: {error}"));
            }
        }
        let saved_limits = (self.runner.cleanup, self.runner.phase, self.runner.whole);
        self.runner.cleanup = true;
        self.runner.phase = Instant::now() + Duration::from_secs(90);
        self.runner.whole = self.runner.phase;
        let isolation = (|| {
            self.cmd(
                "client",
                "wg",
                &["set", "wg0", "peer", peer, "persistent-keepalive", "0"],
            )?;
            self.daemon_wait("daemon processes released", Duration::from_secs(5), |lab| {
                Ok(lab.runner.assert_background_released(first_group).is_ok())
            })?;
            // Every daemon stream listener is allocated from this range.
            let sockets = self.cmd("internet", "ss", &["-H", "-lnt"])?;
            for port in 8081..=8120 {
                if sockets
                    .split_whitespace()
                    .any(|word| word.ends_with(&format!(":{port}")))
                {
                    return fail(format!("daemon suite left listener port {port} bound"));
                }
            }
            self.cmd("gwhost", "conntrack", &["-F"])?;
            self.daemon_clean_baseline()
        })();
        (self.runner.cleanup, self.runner.phase, self.runner.whole) = saved_limits;
        if let Err(error) = isolation {
            self.baseline_failure = Some(error.to_string());
            failures.push(format!("daemon suite final baseline: {error}"));
        }
        if !failures.is_empty() {
            return fail(failures.join("; "));
        }
        Ok(observation)
    }
    fn daemon_trial(&mut self, case: &str) -> Result<String> {
        self.fault_markers.clear();
        self.reset_boot_budget(&format!("{case}-initial"))?;
        let events = self.private.join("boot-root/var-lib/scupper/events");
        if events.exists() {
            fs::remove_dir_all(events)?;
        }
        let mut guard = DaemonGuard {
            lab: self,
            child: None,
            armed: true,
            case: case.into(),
            notify: None,
            baseline_version: None,
        };
        let result = guard.run(case);
        let cleanup = guard.finish();
        match (result, cleanup) {
            (Ok(observed), Ok(())) => Ok(observed),
            (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
            (Err(error), Err(cleanup)) => fail(format!("{error}; cleanup: {cleanup}")),
        }
    }
    pub(super) fn daemon_boot_crash(
        &mut self,
        stem: &str,
        point: &str,
    ) -> Result<std::process::ExitStatus> {
        let root = self.boot_root.clone();
        self.reset_boot_budget(stem)?;
        self.runner.boot_point = Some(point.into());
        self.runner.boot_marker = Some(
            root.join("run/scupper/boot-reached")
                .to_string_lossy()
                .into_owned(),
        );
        let spawned = self.daemon_start(stem, &root);
        self.runner.boot_point = None;
        self.runner.boot_marker = None;
        let (mut child, _notify) = spawned?;
        child.wait_timeout(Duration::from_secs(30))
    }
    pub(super) fn daemon_boot_recover(&mut self, stem: &str) -> Result<String> {
        let root = self.boot_root.clone();
        self.reset_boot_budget(stem)?;
        let (mut child, notify) = self.daemon_start(&format!("{stem}-retry"), &root)?;
        self.daemon_ready_tick(&notify)?;
        self.daemon_complete_tick(&root)?;
        self.daemon_route_healthy(Duration::from_secs(30))?;
        self.wait_provider()?;
        self.boot_fresh_client_handshake()?;
        self.exit_port = self
            .cmd("scupper", "wg", &["show", "ex-ch1", "listen-port"])?
            .trim()
            .parse()?;
        self.service_check(&mut Vec::new())?;
        let (code, report) = self.check_result(&Self::boot_binary()?, &root)?;
        fs::write(
            self.artifacts.join(format!("{stem}-supervised-check.json")),
            serde_json::to_vec_pretty(&report)?,
        )?;
        if code != 0 || report["verdict"].get("Protected").is_none() {
            return fail(format!("{stem} supervised retry: {code}: {report}"));
        }
        child.stop_timeout(Signal::TERM, Duration::from_secs(30))?;
        save_event_artifacts(
            &root.join("var-lib/scupper/events"),
            &self.artifacts.join(format!("{stem}-events")),
        )?;
        Ok(report.to_string())
    }
    // Each crash prefix represents a separate simulated boot, with its own /run
    // retry budget. Preserve the preceding budget as evidence before resetting.
    pub(super) fn reset_boot_budget(&self, stem: &str) -> Result<()> {
        let path = self.private.join("boot-root/run/scupper/boot-attempts");
        if path.exists() {
            fs::copy(
                &path,
                self.artifacts.join(format!("{stem}-boot-attempts.json")),
            )?;
            fs::remove_file(path)?;
        }
        Ok(())
    }
    fn daemon_host_sysctls(&mut self) -> Result<Vec<(String, String)>> {
        let mut values = Vec::new();
        for key in [
            "net.ipv4.ip_forward",
            "net.ipv4.conf.all.rp_filter",
            "net.ipv4.conf.default.rp_filter",
            "net.ipv4.conf.all.send_redirects",
            "net.ipv4.conf.default.send_redirects",
            "net.ipv6.conf.all.forwarding",
            "net.ipv6.conf.default.forwarding",
            "net.ipv6.conf.all.accept_ra",
            "net.ipv6.conf.default.accept_ra",
            "net.ipv6.conf.all.autoconf",
            "net.ipv6.conf.default.autoconf",
        ] {
            values.push((
                key.to_owned(),
                self.cmd("gwhost", "sysctl", &["-n", key])?
                    .trim()
                    .to_owned(),
            ));
        }
        Ok(values)
    }
    fn daemon_restore_host(&mut self) -> Result<()> {
        if let Some(values) = self.daemon_host_baseline.clone() {
            for (key, value) in values {
                self.cmd("gwhost", "sysctl", &["-q", "-w", &format!("{key}={value}")])?;
            }
        }
        self.cmd("gwhost", "conntrack", &["-F"])?;
        Ok(())
    }
    pub(super) fn restore_host_rules(&mut self) -> Result<()> {
        for family in ["-4", "-6"] {
            for &(pref, table) in host_rule_defaults(family) {
                let rules: serde_json::Value = serde_json::from_str(&self.cmd(
                    "gwhost",
                    "ip",
                    &[family, "-j", "rule", "show"],
                )?)?;
                if !rules.as_array().ok_or("host rules")?.iter().any(|r| {
                    r["priority"]
                        .as_u64()
                        .is_some_and(|p| p.to_string() == pref)
                        && r["table"] == table
                }) {
                    self.cmd(
                        "gwhost",
                        "ip",
                        &[family, "rule", "add", "pref", pref, "lookup", table],
                    )?;
                }
            }
        }
        Ok(())
    }
    pub(super) fn daemon_clean_baseline(&mut self) -> Result<()> {
        for family in ["-4", "-6"] {
            let rules: serde_json::Value = serde_json::from_str(&self.cmd(
                "gwhost",
                "ip",
                &[family, "-j", "rule", "show"],
            )?)?;
            for &(pref, table) in host_rule_defaults(family) {
                if !rules.as_array().ok_or("host rules")?.iter().any(|r| {
                    r["table"] == table
                        && r["priority"]
                            .as_u64()
                            .is_some_and(|p| p.to_string() == pref)
                }) {
                    return fail(format!(
                        "unclean baseline: missing host {family} pref {pref} {table} rule"
                    ));
                }
            }
        }
        if let Some(expected) = self.daemon_host_baseline.clone()
            && self.daemon_host_sysctls()? != expected
        {
            return fail("unclean baseline: gwhost sysctls differ");
        }
        if super::mounts::count(
            &fs::read_to_string("/proc/self/mountinfo")?,
            super::mounts::SCUPPER,
        )? != 1
        {
            return fail("unclean baseline: leftover scupper mounts");
        }
        let conntrack = self.cmd("gwhost", "conntrack", &["-L"])?;
        if conntrack.contains("198.18.") || conntrack.contains("2001:db8:52:") {
            return fail("unclean baseline: gwhost fault conntrack remains");
        }
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
        let notify_path = self.daemon_notify_path(case)?;
        let notify = NotifyCapture::start(
            UnixDatagram::bind(&notify_path)?,
            &artifacts.join("notify.jsonl"),
        )?;
        let child = self.daemon_spawn(case, root, "start")?;
        Ok((child, notify))
    }
    // L19 needs a real reconciler for the freeze and recovery controls. Keep
    // its lifetime around the entire trial, including restoration on failure.
    pub(super) fn meta_supervised<T>(
        &mut self,
        trial: impl FnOnce(&mut Self, &Path) -> Result<T>,
    ) -> Result<T> {
        let root = self.prepare_check_v2()?;
        let (mut child, notify) = self.daemon_start("L19-L3", &root)?;
        let result = self
            .daemon_ready_tick(&notify)
            .and_then(|()| trial(self, &root))
            .and_then(|value| {
                let (code, report) = self.check_result(&Self::boot_binary()?, &root)?;
                fs::write(
                    self.artifacts.join("L19-L3-repaired-check.json"),
                    serde_json::to_vec_pretty(&report)?,
                )?;
                if code != 0 || report["verdict"].get("Protected").is_none() {
                    return fail(format!("L19 restored baseline failed: {code}: {report}"));
                }
                Ok(value)
            });
        let unfrozen = match fs::remove_file(root.join("run/scupper/incomplete-tick")) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        };
        let stopped = child.stop_timeout(Signal::TERM, Duration::from_secs(30));
        let saved = save_event_artifacts(
            &root.join("var-lib/scupper/events"),
            &self.artifacts.join("L19-L3-events"),
        );
        super::mutation::finish(result, unfrozen.and(stopped).and(saved))
    }

    pub(super) fn meta_resume(&mut self, root: &Path, prefix: &str) -> Result<()> {
        fs::remove_file(root.join("run/scupper/incomplete-tick"))?;
        self.daemon_wait(
            "L19 bridge route and rules repaired",
            Duration::from_secs(30),
            |lab| {
                let routes = lab.cmd("scupper", "ip", &["route", "show", "exact", prefix])?;
                let rules = scupper_core::canon::canonicalize(&lab.cmd(
                    "scupper",
                    "nft",
                    &["-j", "list", "ruleset"],
                )?)?;
                Ok(routes.trim().is_empty() && rules == lab.expected_rules)
            },
        )?;
        self.daemon_complete_tick(root)?;
        let snapshot = self.daemon_snapshot()?;
        fs::write(
            self.artifacts.join("L19-L3-repaired.json"),
            serde_json::to_vec_pretty(&snapshot)?,
        )?;
        if snapshot["rules"] != self.expected_rules {
            return fail("L19 daemon recovery did not restore the ruleset");
        }
        self.service_check(&mut Vec::new())?;
        Ok(())
    }

    fn daemon_notify_path(&self, case: &str) -> Result<std::path::PathBuf> {
        use std::os::fd::AsRawFd as _;
        let directory = self
            .private_dir
            .as_ref()
            .ok_or("private directory not open")?;
        Ok(std::path::PathBuf::from(format!(
            "/proc/{}/fd/{}/notify-{case}.sock",
            std::process::id(),
            directory.as_raw_fd()
        )))
    }
    fn daemon_spawn(&mut self, case: &str, root: &Path, stage: &str) -> Result<Group> {
        // Unlike root-started probes, heartbeat exec happens after uid/gid drop.
        // Neither executable may require traversal through a runner's home.
        let daemon = if matches!(case, "L10" | "L53" | "L53b" | "heartbeat") {
            heartbeat::delivery_binaries(&Self::boot_binary()?, root)?
        } else {
            Self::boot_binary()?.with_file_name("scupperd")
        };
        let env = format!("NOTIFY_SOCKET={}", self.daemon_notify_path(case)?.display());
        let mut invocation = Invocation::new(
            "gwhost",
            "env",
            &[
                &env,
                daemon.to_str().ok_or("daemon path")?,
                "--test-root",
                root.to_str().ok_or("root path")?,
            ],
        );
        if matches!(case, "L10" | "L53" | "L53b" | "heartbeat") {
            // Apply the existing executable overlay first, then carry the
            // copied host accounts and fixture hosts into the daemon and its children.
            if let Some(fixture) = &self.runner.wg_fixture {
                invocation = super::transport::overlay(&invocation, fixture);
            }
            invocation = heartbeat::overlay(&invocation, root);
        }
        self.runner.background(
            &invocation,
            &self.artifacts.join(format!("daemon-{case}/{stage}.stdout")),
        )
    }
    fn daemon_ready_tick(&mut self, notify: &NotifyCapture) -> Result<()> {
        let mut ready = false;
        let root = self.boot_root.join("run/scupper");
        let mut last_ping = String::new();
        let waited = self.daemon_wait(
            "READY and first complete tick",
            Duration::from_secs(40),
            |_| {
                for message in notify.drain()? {
                    ready |= message == "READY=1";
                }
                let response = scupper_sys::daemon::control::call(
                    &root,
                    &scupper_sys::daemon::control::request(scupper_proto::Op::Ping {}),
                    Duration::from_millis(500),
                );
                last_ping = format!("{response:?}");
                Ok(startup_complete(
                    ready,
                    response.as_ref().ok().map(|r| &r.result),
                ))
            },
        );
        if let Err(error) = waited {
            return fail(format!("{error}; ready={ready}; last ping={last_ping}"));
        }
        self.assert_transport_ports()?;
        Ok(())
    }
    fn daemon_complete_tick(&mut self, root: &Path) -> Result<()> {
        self.daemon_wait(
            "first complete post-apply tick",
            Duration::from_secs(40),
            |_| {
                Ok(matches!(
                    scupper_sys::daemon::control::call(
                        &root.join("run/scupper"),
                        &scupper_sys::daemon::control::request(scupper_proto::Op::Ping {}),
                        Duration::from_secs(2),
                    ),
                    Ok(scupper_proto::Response {
                        result: Ok(scupper_proto::OpResult::Ping {
                            last_complete_iteration_age: Some(0..=4),
                            operation: None,
                            ..
                        }),
                        ..
                    })
                ))
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
    pub(super) fn daemon_wait(
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
    pub(super) fn daemon_flow(
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
                if code != 4 || report["verdict"]["FailClosed"] != "NoHealthyExit" {
                    return fail(format!("L16 expected 4: {code}: {report}"));
                }
                self.cmd("scupper", "ip", &["link", "set", "ex-ch1", "up"])?;
                let up = self.daemon_route_healthy(Duration::from_secs(70))?;
                let (code, report) = self.check_result(&Self::boot_binary()?, root)?;
                if code != 0 || report["verdict"].get("Protected").is_none() {
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
                super::mounts::verify_restored_peers(Some(
                    child.supervised_pid()?.ok_or("missing live L17 daemon")?,
                ))?;
                self.cmd("", "ip", &["netns", "exec", "scupper", "true"])?;
                super::mounts::save(
                    &self.artifacts,
                    "daemon-L17-V14-after-netns-exec",
                    child.supervised_pid()?,
                )?;
                super::mounts::verify_restored_peers(child.supervised_pid()?)?;
                // Reopen and audit the restored name without any intervening delete.
                let (code, report) = self.check_result(&Self::boot_binary()?, root)?;
                super::mounts::save(
                    &self.artifacts,
                    "daemon-L17-V14-after-check",
                    child.supervised_pid()?,
                )?;
                super::mounts::verify_restored_peers(child.supervised_pid()?)?;
                if code != 0 || report["verdict"].get("Protected").is_none() {
                    return fail(format!("L17 fresh check expected 0: {code}: {report}"));
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
                    "remount_ms={remount}; mounts={mounts}; same_inode=true; shared_peers=true; netns_exec=true; fresh_check=0; second_namespace=false; stream_sent={sent}; stream_replies={replies}"
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
    pub(super) fn daemon_oracle(
        &self,
        stem: &str,
        markers: &[String],
        old_port: u16,
        new_port: u16,
    ) -> Result<()> {
        let mut text = evidence::policy_for_case(markers, false, old_port, stem == "daemon-L11")?;
        if stem.contains("heartbeat") || stem == "control-L10" {
            text = format!("heartbeat = \"{}:443\"\n{text}", heartbeat::ENDPOINT);
        }
        let combined: Vec<_> = markers.iter().chain(&self.fault_markers).collect();
        text = text
            .lines()
            .map(|line| {
                if line.starts_with("canary_markers = ") {
                    Ok(format!(
                        "canary_markers = {}",
                        serde_json::to_string(&combined)?
                    ))
                } else {
                    Ok(line.to_owned())
                }
            })
            .collect::<Result<Vec<_>>>()?
            .join("\n");

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
        if code != 2
            || !control_cases::verdict_reason(&report["verdict"]["Unprotected"], "ForeignLink")
        {
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
            let root = self.boot_root.clone();
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
        let root = self.boot_root.clone();
        let (code, report) = self.check_result(&Self::boot_binary()?, &root)?;
        if code != 4 || report["verdict"]["FailClosed"] != "NoHealthyExit" {
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

pub(super) fn flow_counts(path: &Path) -> Result<(u64, u64)> {
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

pub(super) fn daemon_wanted(case: &str) -> &'static str {
    match case {
        "L1" => "baseline IPv4; WireGuard-only uplink and provider-NAT receipts",
        "L2" => "gateway replies only over wg0; M2 DNS/API service requests dropped",
        "L5" => "host RPDB/non-default route flush; check remains 0",
        "L8" => "host nft flush/forwarding/dup cannot affect client path",
        "L9" | "L9b" | "L9-host-link" => {
            "daemon boot SIGKILL prefixes contained; supervised retry check 0"
        }
        "L11" => "second client isolation; gateway/provider scans denied; allowed client echo",
        "L12" => "WireGuard source rejection; widened peer check 2; traced antispoof drop",
        "L15" => "real fake HTTPS exit-IP target: 0, uplink address 2, restored 0",
        "L18" => "host sysctl inheritance overridden; forwarding toggle reapplies hardening",
        "L20" => "supervised IPv4 PMTU; IPv6 renderer chain property, unsupervised",
        "L17-rebuild" => {
            "no-holder loss = daemon down; restart rebuilds; fresh namespace marker; check 0"
        }
        "L10" => {
            "SIGKILL/SIGSTOP: check 5, traffic continues, heartbeat stops; SIGCONT resumes heartbeat"
        }
        "L53" => {
            "orphan survives to deadline after TLS handshake and blocked GET; no late TCP payload"
        }
        "L53b" => {
            "stopped child remains alive past deadline; blocked GET never retransmits after drop removal"
        }
        "heartbeat" => {
            "healthy cadence control, failing ok_only suppression, parent status suffix evidence /0, /3, /4 (resolve unit test covers request path)"
        }
        "L14" => "disconnect verifies closure; check 4 across reboot; connect restores 0",
        "L43" => {
            "recurring foreign link latches; forwarding stays 0 across restart/reboot; repair clear restores 0"
        }
        "L44" => "local apply races restart; writer contention bounded; samples closed or exact",
        "L50" => {
            "crash after durable Disconnected: check 3 while exit route exists; tightened closure gives 4"
        }
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
    fn readiness_requires_ready_and_a_recent_completed_iteration() {
        // Startup can send READY, STATUS=unconfirmed and WATCHDOG while Ping
        // still has no completed iteration. Those notifications cannot pass.
        let ping = |age| {
            Ok(scupper_proto::OpResult::Ping {
                last_complete_iteration_age: age,
                current_iteration_age: None,
                operation: None,
                netns: scupper_core::verdict::v2::NetnsIdentity {
                    device: 1,
                    inode: 2,
                },
                version: 1,
                quarantined: false,
                selection: scupper_core::verdict::v2::Selection::Auto,
            })
        };
        assert!(!startup_complete(false, Some(&ping(Some(0)))));
        assert!(!startup_complete(true, None));
        assert!(!startup_complete(true, Some(&ping(None))));
        assert!(!startup_complete(true, Some(&ping(Some(5)))));
        assert!(startup_complete(true, Some(&ping(Some(0)))));
        assert!(startup_complete(true, Some(&ping(Some(4)))));
        let mut applying = ping(Some(0));
        if let Ok(scupper_proto::OpResult::Ping { operation, .. }) = &mut applying {
            *operation = Some(scupper_proto::OperationProgress {
                kind: scupper_proto::OperationKind::Rebuild,
                from: 1,
                to: 1,
                age: 0,
            });
        }
        assert!(!startup_complete(true, Some(&applying)));
    }

    #[test]
    fn copied_event_artifacts_are_readable_without_changing_sources() {
        let root = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
            .join("daemon-event-artifacts")
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
    fn notify_capture_survives_idle_and_sender_restart() {
        use std::os::fd::AsRawFd;
        let root = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("notify-restart-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let directory = fs::File::open(&root).unwrap();
        let path = format!("/proc/self/fd/{}/notify.sock", directory.as_raw_fd());
        let receive = UnixDatagram::bind(&path).unwrap();
        let capture = NotifyCapture::start(receive, &root.join("notify.jsonl")).unwrap();
        for message in ["READY=1", "WATCHDOG=1", "READY=1", "WATCHDOG=1"] {
            let sender = UnixDatagram::unbound().unwrap();
            sender.send_to(message.as_bytes(), &path).unwrap();
            drop(sender);
            std::thread::sleep(Duration::from_millis(100));
            assert_eq!(capture.drain().unwrap(), vec![message.to_owned()]);
        }
        drop(capture);
        assert_eq!(
            fs::read_to_string(root.join("notify.jsonl"))
                .unwrap()
                .lines()
                .count(),
            4
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn notify_artifact_keeps_every_message_even_when_consumers_drain() {
        let root = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
            .join("daemon-notify-artifacts")
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
