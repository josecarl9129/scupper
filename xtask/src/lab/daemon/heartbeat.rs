//! Heartbeat wire controls use TCP/ClientHello only, with no TLS test roots.
use super::{A, DaemonGuard, Duration, Group, Invocation, Path, Result, Signal, fail, fs};
use scupper_core::config::{HeartbeatReport, SiteConfig};
use std::os::unix::fs::{MetadataExt, PermissionsExt};

pub(super) const ENDPOINT: &str = "198.51.100.10";
impl DaemonGuard<'_> {
    pub(super) fn heartbeat_fixture(root: &Path, site: &mut SiteConfig) -> Result<()> {
        let report = if root.join("run/scupper/heartbeat-status").exists() {
            HeartbeatReport::StatusCode
        } else {
            HeartbeatReport::OkOnly
        };
        site.heartbeat = Some(serde_json::from_value(serde_json::json!({
            "kind":"healthchecks", "url_ref":"lab-heartbeat", "interval":"3s", "report":report
        }))?);
        let path = root.join("etc/scupper/secrets/url/lab-heartbeat");
        fs::write(&path, "https://heartbeat.invalid/lab-check")?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        // The mount overlay contains passwd/group and hosts. Only the disposable
        // account identity is copied; the endpoint remains a stdin-only secret.
        for name in ["passwd", "group"] {
            let mut text = fs::read_to_string(root.join("etc").join(name))?;
            if !text.lines().any(|line| line.starts_with("scupper-alert:")) {
                text.push_str(if name == "passwd" {
                    "\nscupper-alert:x:65533:65533::/:/usr/sbin/nologin\n"
                } else {
                    "\nscupper-alert:x:65533:\n"
                });
                fs::write(root.join("etc").join(name), text)?;
            }
        }
        fs::write(
            root.join("etc/hosts"),
            format!("127.0.0.1 localhost\n{ENDPOINT} heartbeat.invalid\n"),
        )?;
        Ok(())
    }
    pub(super) fn start_heartbeat_sink(&mut self) -> Result<Group> {
        self.lab.cmd(
            "internet",
            "ip",
            &["addr", "replace", &format!("{ENDPOINT}/32"), "dev", "lo"],
        )?;
        self.lab.cmd(
            "wan",
            "ip",
            &[
                "route",
                "replace",
                &format!("{ENDPOINT}/32"),
                "via",
                A.internet.peer,
            ],
        )?;
        let executable = std::env::current_exe()?;
        let log = self
            .lab
            .artifacts
            .join(format!("{}-heartbeat.jsonl", self.case));
        let child = self.lab.runner.background(
            &Invocation::new(
                "internet",
                executable.to_str().ok_or("xtask path")?,
                &[
                    "flow",
                    "--mode",
                    "heartbeat-sink",
                    "--address",
                    &format!("{ENDPOINT}:443"),
                    "--marker",
                    "heartbeat-control",
                    "--log",
                    log.to_str().ok_or("sink log path")?,
                    "--seconds",
                    "300",
                ],
            ),
            &self
                .lab
                .artifacts
                .join(format!("{}-heartbeat.stdout", self.case)),
        )?;
        self.lab
            .daemon_wait("heartbeat TCP listener", Duration::from_secs(5), |lab| {
                Ok(lab
                    .cmd("internet", "ss", &["-ltnH"])?
                    .contains(&format!("{ENDPOINT}:443")))
            })?;
        Ok(child)
    }
    pub(super) fn heartbeat_count(&self) -> Result<usize> {
        let path = self
            .lab
            .artifacts
            .join(format!("{}-heartbeat.jsonl", self.case));
        let text = match fs::read_to_string(path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(e.into()),
        };
        Ok(text
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .filter(|v| v["hello"] == true)
            .count())
    }
    fn wait_heartbeat_suffix(&mut self, root: &Path, suffix: &str) -> Result<()> {
        self.lab
            .daemon_wait("heartbeat status suffix", Duration::from_secs(25), |_| {
                let text = fs::read_to_string(root.join("run/scupper/heartbeat-trace.jsonl"))?;
                Ok(text
                    .lines()
                    .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
                    .any(|v| v["suffix"] == suffix))
            })?;
        Ok(())
    }
    pub(super) fn wait_heartbeat(&mut self, before: usize) -> Result<()> {
        let start = std::time::Instant::now();
        while start.elapsed() < Duration::from_secs(25) {
            if self.heartbeat_count()? > before {
                return Ok(());
            }
            self.lab.runner.dwell(Duration::from_millis(50))?;
        }
        fail(format!(
            "{}: no heartbeat ClientHello; inspect sink log, daemon stderr, heartbeat trace and uplink capture",
            self.case
        ))
    }
    pub(super) fn assert_heartbeat_quiet(
        &mut self,
        grace: Duration,
        window: Duration,
    ) -> Result<()> {
        self.lab.runner.dwell(grace)?;
        let before = self.heartbeat_count()?;
        self.lab.runner.dwell(window)?;
        let after = self.heartbeat_count()?;
        if before != after {
            return fail(format!(
                "{}: heartbeat continued after deadline: before={before}, after={after}",
                self.case
            ));
        }
        Ok(())
    }
    pub(super) fn run_heartbeat(&mut self, case: &str) -> Result<String> {
        let root = self.lab.prepare_check_v2()?;
        if let scupper_sys::state::StateRead::Present(state) =
            scupper_sys::state::StateFile::open(root.join("var-lib/scupper"), None)?.read()?
        {
            self.baseline_version = state.applied_version;
        }
        self.supervised_fixture(&root)?;
        self.lab.boot_gateway(&[], &format!("{case}-boot"))?;
        let mut sink = self.start_heartbeat_sink()?;
        let stem = format!("heartbeat-{case}");
        self.lab.capture("wan", A.gwhost.wan_if, &stem)?;
        let (child, notify) = self.lab.daemon_start(case, &root)?;
        self.child = Some(child);
        self.notify = Some(notify);
        self.lab
            .daemon_ready_tick(self.notify.as_ref().ok_or("missing notify")?)?;
        self.wait_heartbeat(0)?;
        self.expect_check(&root, 0, None, "heartbeat-control")?;
        if case == "L53" {
            self.orphan_deadline(&root)?;
        } else {
            self.heartbeat_reports(&root)?;
        }
        self.control_stop(Signal::TERM)?;
        sink.stop(Signal::TERM)?;
        self.lab.stop_captures()?;
        // Decode exact endpoint/host tuples, and require at least one ClientHello.
        let bytes = fs::read(self.lab.artifacts.join(format!("{stem}.pcap")))?;
        let hellos = crate::pcap::heartbeat_hellos(
            &bytes,
            A.gwhost.peer.parse()?,
            format!("{ENDPOINT}:443").parse()?,
        )?;
        if hellos.is_empty() {
            return fail("heartbeat uplink positive control was blind");
        }
        if case == "L53" {
            let timing: serde_json::Value =
                serde_json::from_slice(&fs::read(self.lab.artifacts.join("L53-deadline.json"))?)?;
            let deadline = timing["deadline_epoch_ns"]
                .as_u64()
                .ok_or("missing heartbeat deadline evidence")?;
            if hellos.iter().any(|hello| {
                u64::from(hello.seconds) * 1_000_000_000 + u64::from(hello.nanoseconds) >= deadline
            }) {
                return fail("L53: ClientHello observed after the child's original deadline");
            }
        }

        self.lab
            .daemon_oracle(&stem, &[], self.lab.exit_port, self.lab.exit_port)?;
        fs::write(
            self.lab
                .artifacts
                .join(format!("{case}-heartbeat-evidence.json")),
            serde_json::to_vec_pretty(
                &serde_json::json!({"client_hellos":hellos.len(), "host_only":true, "deadline_seconds":30}),
            )?,
        )?;
        Ok(format!(
            "healthy ClientHello control; host tuple verified; {case} suppression/deadline controls passed"
        ))
    }
    fn heartbeat_reports(&mut self, root: &Path) -> Result<()> {
        let (code, _) = self.control_command(root, &["disconnect"], "heartbeat-disconnect")?;
        if code != 0 {
            return fail("heartbeat disconnect failed");
        }
        self.expect_check(root, 4, None, "heartbeat-failing")?;
        self.assert_heartbeat_quiet(Duration::from_secs(10), Duration::from_secs(6))?;
        self.control_stop(Signal::TERM)?;
        fs::write(root.join("run/scupper/heartbeat-status"), b"status")?;
        self.supervised_fixture(root)?;
        self.lab.boot_gateway(&[], "heartbeat-status-boot")?;
        self.control_restart(root, "heartbeat-status")?;
        let before = self.heartbeat_count()?;
        self.wait_heartbeat(before)?;
        self.wait_heartbeat_suffix(root, "/4")?;
        let trace = fs::read_to_string(root.join("run/scupper/heartbeat-trace.jsonl"))?;
        if !trace
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .any(|v| v["suffix"] == "/4")
        {
            return fail("status_code failing verdict did not authorize /4");
        }
        let (code, _) = self.control_command(root, &["connect"], "heartbeat-connect")?;
        if code != 0 {
            return fail("heartbeat reconnect failed");
        }
        let before = self.heartbeat_count()?;
        self.wait_heartbeat_suffix(root, "/0")?;
        self.wait_heartbeat(before)?;
        let trace = fs::read_to_string(root.join("run/scupper/heartbeat-trace.jsonl"))?;
        let suffixes: Vec<_> = trace
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .map(|v| v["suffix"].clone())
            .collect();
        if !suffixes.iter().any(|s| s == "/0") || suffixes.iter().any(|s| s == "/5") {
            return fail("heartbeat status suffix control failed");
        }
        Ok(())
    }
    fn orphan_deadline(&mut self, root: &Path) -> Result<()> {
        let run = root.join("run/scupper");
        fs::write(run.join("heartbeat-pause"), b"hold before spawn")?;
        let before = fs::read_to_string(run.join("heartbeat-trace.jsonl"))?
            .lines()
            .count();
        self.lab.daemon_wait(
            "heartbeat queued before delayed uplink",
            Duration::from_secs(25),
            |_| {
                Ok(fs::read_to_string(run.join("heartbeat-trace.jsonl"))?
                    .lines()
                    .count()
                    > before)
            },
        )?;
        self.lab.cmd(
            "gwhost",
            "tc",
            &[
                "qdisc", "replace", "dev", "eth0", "root", "netem", "delay", "35000ms",
            ],
        )?;
        fs::remove_file(run.join("heartbeat-pause"))?;
        let pid = self
            .child
            .as_ref()
            .ok_or("daemon missing")?
            .supervised_pid()?
            .ok_or("daemon pid missing")?;
        self.lab
            .daemon_wait("heartbeat child started", Duration::from_secs(3), |_| {
                Ok(delivery_child(pid)?.is_some())
            })?;
        let child = delivery_child(pid)?.ok_or("delivery child vanished before daemon death")?;
        let child_ns = fs::metadata(format!("/proc/{child}/ns/net"))?;
        let host_ns = fs::metadata("/run/netns/gwhost")?;
        if (child_ns.dev(), child_ns.ino()) != (host_ns.dev(), host_ns.ino()) {
            return fail("heartbeat child entered a different network namespace");
        }
        let trace = fs::read_to_string(run.join("heartbeat-trace.jsonl"))?;
        let last: serde_json::Value =
            serde_json::from_str(trace.lines().last().ok_or("heartbeat trace missing")?)?;
        let deadline = last["deadline_ns"]
            .as_u64()
            .ok_or("heartbeat monotonic deadline missing")?;
        let wall = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let remaining = deadline.saturating_sub(scupper_sys::heartbeat::monotonic_ns());
        let deadline_epoch_ns = u64::try_from(wall + u128::from(remaining))?;
        fs::write(
            self.lab.artifacts.join("L53-deadline.json"),
            serde_json::to_vec(
                &serde_json::json!({"deadline_epoch_ns":deadline_epoch_ns,"child":child}),
            )?,
        )?;
        self.control_stop(Signal::KILL)?;
        if !Path::new(&format!("/proc/{child}")).exists() {
            return fail("L53 control: heartbeat child did not survive daemon death");
        }
        // The child is its own process group, so killing the daemon's group leaves
        // this orphan alive to enforce its own absolute deadline.
        self.lab.runner.dwell(Duration::from_secs(32))?;
        self.lab.cmd(
            "gwhost",
            "tc",
            &[
                "qdisc", "change", "dev", "eth0", "root", "netem", "delay", "0ms",
            ],
        )?;
        self.assert_heartbeat_quiet(Duration::ZERO, Duration::from_secs(10))?;
        self.lab
            .cmd("gwhost", "tc", &["qdisc", "del", "dev", "eth0", "root"])?;
        Ok(())
    }
}
fn delivery_child(pid: u32) -> Result<Option<u32>> {
    for task in fs::read_dir(format!("/proc/{pid}/task"))? {
        let path = task?.path().join("children");
        if let Ok(children) = fs::read_to_string(path) {
            for child in children.split_whitespace() {
                if let Ok(argv) = fs::read(format!("/proc/{child}/cmdline")) {
                    let words: Vec<_> = argv.split(|b| *b == 0).collect();
                    if words.get(1) == Some(&b"deliver".as_slice())
                        && words.get(2) == Some(&b"heartbeat".as_slice())
                    {
                        return Ok(Some(child.parse()?));
                    }
                }
            }
        }
    }
    Ok(None)
}
