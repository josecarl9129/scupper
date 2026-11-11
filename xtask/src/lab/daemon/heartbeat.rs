//! Heartbeat wire controls, with a disposable TLS CA for blocked-GET trials.
use super::{A, DaemonGuard, Duration, Group, Invocation, Path, Result, Signal, fail, fs};
use scupper_core::config::{HeartbeatReport, SiteConfig};
use scupper_proto::{EventKind, Reason};
use std::fmt::Write as _;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};

pub(super) const ENDPOINT: &str = "198.51.100.10";

fn check_account_failure(root: &Path) -> Result<()> {
    for event in scupper_sys::events::read_since(&root.join("var-lib/scupper"), 0, None) {
        if matches!(
            event?.kind,
            EventKind::HeartbeatFailed {
                reason: Reason::HeartbeatAccount
            }
        ) {
            return fail(
                "heartbeat lab setup failed: HeartbeatFailed { reason: HeartbeatAccount }; scupper-alert must exist in the daemon's passwd/group (created by lab prepare)",
            );
        }
    }
    Ok(())
}

fn executable_mount(flags: rustix::fs::StatVfsMountFlags, bin: &Path) -> Result<()> {
    if flags.contains(rustix::fs::StatVfsMountFlags::NOEXEC) {
        return fail(format!(
            "heartbeat lab setup: {} is on a noexec filesystem (statvfs ST_NOEXEC)",
            bin.display()
        ));
    }
    Ok(())
}

fn delivery_binaries(source: &Path, bin: &Path) -> Result<std::path::PathBuf> {
    executable_mount(rustix::fs::statvfs(bin)?.f_flag, bin)?;
    for name in ["scupper", "scupperd"] {
        let target = bin.join(name);
        fs::copy(source.with_file_name(name), &target)?;
        fs::set_permissions(target, fs::Permissions::from_mode(0o755))?;
    }
    Ok(bin.join("scupperd"))
}

impl super::Lab {
    pub(super) fn heartbeat_binaries(&mut self) -> Result<std::path::PathBuf> {
        let bin = Path::new("/var/lib").join(format!("scupper-lab-bin-{}", Self::marker()?));
        fs::DirBuilder::new().mode(0o755).create(&bin)?;
        self.registry
            .register(crate::lab::Resource::Directory(bin.clone()));
        fs::set_permissions(&bin, fs::Permissions::from_mode(0o755))?;
        if fs::metadata(&bin)?.uid() != 0 {
            return fail("heartbeat lab setup: executable directory must be root-owned");
        }
        for ancestor in bin.ancestors() {
            if fs::metadata(ancestor)?.mode() & 0o001 == 0 {
                return fail(format!(
                    "heartbeat lab setup: {} is not traversable by scupper-alert",
                    ancestor.display()
                ));
            }
        }
        delivery_binaries(&Self::boot_binary()?, &bin)
    }
}

pub(super) fn overlay(invocation: &Invocation, root: &Path) -> Invocation {
    let mut args = vec![
        "--mount".into(),
        "--propagation".into(),
        "unchanged".into(),
        "--".into(),
        "/bin/sh".into(),
        "-c".into(),
        r#"set -eu
mount --make-private /
if mountpoint -q /etc; then mount --make-private /etc; fi
for name in hosts passwd group; do
    mount --bind "$1/etc/$name" "/etc/$name"
    mount --make-private "/etc/$name"
done
shift
exec "$@"
"#
        .into(),
        "heartbeat-etc".into(),
        root.to_string_lossy().into_owned(),
        invocation.program.clone(),
    ];
    args.extend(invocation.args.iter().cloned());
    Invocation {
        program: "unshare".into(),
        args,
    }
}
impl DaemonGuard<'_> {
    pub(super) fn heartbeat_fixture(root: &Path, site: &mut SiteConfig) -> Result<()> {
        let report = if root.join("run/scupper/heartbeat-status").exists() {
            HeartbeatReport::StatusCode
        } else {
            HeartbeatReport::OkOnly
        };
        site.heartbeat = Some(serde_json::from_value(serde_json::json!({
            "kind":"healthchecks", "url_ref":"lab-heartbeat", "interval":"10s", "report":report
        }))?);
        let path = root.join("etc/scupper/secrets/url/lab-heartbeat");
        fs::write(&path, "https://heartbeat.invalid/lab-check")?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        // prepare_check_v2 copied the real lab accounts into this overlay.
        // Keep their allocated IDs; only name resolution needs fixture data.
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
                    "600",
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
    pub(super) fn start_heartbeat_tls(&mut self) -> Result<Group> {
        let tls = self
            .lab
            .private
            .join(format!("{}-heartbeat-tls", self.case));
        fs::create_dir(&tls)?;
        let ca = tls.join("ca.pem");
        let ca_key = tls.join("ca.key");
        let cert = tls.join("server.pem");
        let key = tls.join("server.key");
        let csr = tls.join("server.csr");
        let der = tls.join("ca.der");
        let ext = tls.join("extensions");
        fs::write(
            &ext,
            "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:heartbeat.invalid\n",
        )?;
        let path = |p: &std::path::PathBuf| p.to_str().ok_or("TLS path").map(str::to_owned);
        self.lab.cmd(
            "",
            "openssl",
            &[
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "1",
                "-subj",
                "/CN=Leak lab CA",
                "-addext",
                "basicConstraints=critical,CA:TRUE",
                "-keyout",
                &path(&ca_key)?,
                "-out",
                &path(&ca)?,
            ],
        )?;
        self.lab.cmd(
            "",
            "openssl",
            &[
                "req",
                "-new",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-subj",
                "/CN=heartbeat.invalid",
                "-keyout",
                &path(&key)?,
                "-out",
                &path(&csr)?,
            ],
        )?;
        self.lab.cmd(
            "",
            "openssl",
            &[
                "x509",
                "-req",
                "-in",
                &path(&csr)?,
                "-CA",
                &path(&ca)?,
                "-CAkey",
                &path(&ca_key)?,
                "-CAcreateserial",
                "-days",
                "1",
                "-extfile",
                &path(&ext)?,
                "-out",
                &path(&cert)?,
            ],
        )?;
        self.lab.cmd(
            "",
            "openssl",
            &[
                "x509",
                "-in",
                &path(&ca)?,
                "-outform",
                "DER",
                "-out",
                &path(&der)?,
            ],
        )?;
        let mut hex = String::new();
        for byte in fs::read(der)? {
            write!(hex, "{byte:02x}")?;
        }
        self.lab.runner.probe_ca = Some(hex);
        let server=self.lab.runner.background(&Invocation::new("internet","/bin/sh",&["-c","cd \"$1\"; exec openssl s_server -quiet -WWW -accept 443 -cert server.pem -key server.key","heartbeat-tls",tls.to_str().ok_or("TLS directory")?]),&self.lab.artifacts.join(format!("{}-heartbeat-tls.stdout", self.case)))?;
        self.lab
            .daemon_wait("heartbeat HTTPS listener", Duration::from_secs(5), |lab| {
                Ok(lab.cmd("internet", "ss", &["-ltnH"])?.contains(":443"))
            })?;
        Ok(server)
    }
    pub(super) fn heartbeat_count(&self) -> Result<usize> {
        check_account_failure(&self.lab.boot_root)?;
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
                check_account_failure(root)?;
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
    pub(super) fn heartbeat_cadence_control(&mut self) -> Result<()> {
        let before = self.heartbeat_count()?;
        self.heartbeat_dwell(Duration::from_secs(30))?;
        if self.heartbeat_count()?.saturating_sub(before) < 2 {
            return fail(
                "heartbeat cadence positive control saw fewer than two ClientHellos in 30s",
            );
        }
        Ok(())
    }
    fn heartbeat_launch_count(&self) -> Result<usize> {
        Ok(
            fs::read_to_string(self.lab.boot_root.join("run/scupper/heartbeat-trace.jsonl"))?
                .lines()
                .count(),
        )
    }
    fn heartbeat_dwell(&mut self, duration: Duration) -> Result<()> {
        let until = std::time::Instant::now() + duration;
        loop {
            check_account_failure(&self.lab.boot_root)?;
            let remaining = until.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return Ok(());
            }
            self.lab
                .runner
                .dwell(remaining.min(Duration::from_millis(50)))?;
        }
    }
    pub(super) fn assert_heartbeat_quiet(
        &mut self,
        grace: Duration,
        window: Duration,
    ) -> Result<()> {
        self.heartbeat_dwell(grace)?;
        let before = self.heartbeat_count()?;
        let launches = self.heartbeat_launch_count()?;
        self.heartbeat_dwell(window.max(Duration::from_secs(30)))?;
        let after = self.heartbeat_count()?;
        if before != after || launches != self.heartbeat_launch_count()? {
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
        if matches!(case, "L53" | "L53b") {
            sink.stop(Signal::TERM)?;
            self.control_stop(Signal::TERM)?;
            sink = self.start_heartbeat_tls()?;
            if case == "L53b" {
                self.lab.stop_captures()?;
                self.lab
                    .capture("wan", A.gwhost.wan_if, "L53b-late-release")?;
                self.late_request_deadline(&root)?;
                self.lab.stop_captures()?;
                let timing: serde_json::Value = serde_json::from_slice(&fs::read(
                    self.lab.artifacts.join("L53b-late-deadline.json"),
                )?)?;
                let deadline = timing["deadline_epoch_ns"]
                    .as_u64()
                    .ok_or("late deadline missing")?;
                let bytes = fs::read(self.lab.artifacts.join("L53b-late-release.pcap"))?;
                let packets = crate::pcap::heartbeat_payloads(
                    &bytes,
                    A.gwhost.peer.parse()?,
                    format!("{ENDPOINT}:443").parse()?,
                )?;
                if packets.iter().any(|packet| {
                    u64::from(packet.seconds) * 1_000_000_000 + u64::from(packet.nanoseconds)
                        >= deadline
                }) {
                    return fail("L53b late release sent TCP payload after deadline");
                }
                self.lab.capture("wan", A.gwhost.wan_if, &stem)?;
            }
            self.control_restart(&root, "tls-deadline")?;
            self.orphan_deadline(&root, case == "L53b")?;
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
        if matches!(case, "L53" | "L53b") {
            let timing: serde_json::Value = serde_json::from_slice(&fs::read(
                self.lab.artifacts.join(format!("{case}-deadline.json")),
            )?)?;
            let deadline = timing["deadline_epoch_ns"]
                .as_u64()
                .ok_or("missing heartbeat deadline evidence")?;
            let payloads = crate::pcap::heartbeat_payloads(
                &bytes,
                A.gwhost.peer.parse()?,
                format!("{ENDPOINT}:443").parse()?,
            )?;
            if payloads.iter().any(|hello| {
                u64::from(hello.seconds) * 1_000_000_000 + u64::from(hello.nanoseconds) >= deadline
            }) {
                return fail("L53: TCP payload observed after the child's original deadline");
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
        self.heartbeat_cadence_control()?;
        let (code, _) = self.control_command(root, &["disconnect"], "heartbeat-disconnect")?;
        if code != 0 {
            return fail("heartbeat disconnect failed");
        }
        self.expect_check(root, 4, None, "heartbeat-failing")?;
        self.assert_heartbeat_quiet(Duration::from_secs(32), Duration::from_secs(30))?;
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
        fs::write(root.join("run/scupper/heartbeat-test-code"), b"3")?;
        self.wait_heartbeat_suffix(root, "/3")?;
        fs::write(root.join("run/scupper/heartbeat-test-code"), b"5")?;
        self.assert_heartbeat_quiet(Duration::from_secs(32), Duration::from_secs(30))?;
        fs::remove_file(root.join("run/scupper/heartbeat-test-code"))?;
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
    fn block_heartbeat_request(&mut self) -> Result<()> {
        self.lab.cmd(
            "gwhost",
            "nft",
            &["add", "table", "inet", "scupper_hb_test"],
        )?;
        self.lab.cmd(
            "gwhost",
            "nft",
            &[
                "add",
                "chain",
                "inet",
                "scupper_hb_test",
                "output",
                "{ type filter hook output priority 0; policy accept; }",
            ],
        )?;
        self.lab.cmd(
            "gwhost",
            "nft",
            &[
                "add",
                "rule",
                "inet",
                "scupper_hb_test",
                "output",
                "ip",
                "daddr",
                ENDPOINT,
                "tcp",
                "dport",
                "443",
                "meta",
                "length",
                ">",
                "100",
                "counter",
                "drop",
            ],
        )?;
        Ok(())
    }
    fn drop_heartbeat_request(&mut self, hold: &Path) -> Result<()> {
        self.block_heartbeat_request()?;
        fs::remove_file(hold)?;
        self.lab.daemon_wait(
            "request queued behind endpoint drop",
            Duration::from_secs(2),
            |lab| {
                Ok(lab
                    .cmd(
                        "gwhost",
                        "nft",
                        &["list", "chain", "inet", "scupper_hb_test", "output"],
                    )?
                    .lines()
                    .any(|line| {
                        line.contains("counter packets") && !line.contains("counter packets 0 ")
                    }))
            },
        )?;
        Ok(())
    }
    fn late_request_deadline(&mut self, root: &Path) -> Result<()> {
        let hold = root.join("heartbeat-request-pause");
        fs::write(&hold, b"wait for handshake")?;
        fs::set_permissions(&hold, fs::Permissions::from_mode(0o666))?;
        self.control_restart(root, "late-release")?;
        self.lab.daemon_wait(
            "late-release TLS handshake",
            Duration::from_secs(25),
            |_| {
                check_account_failure(root)?;
                Ok(fs::read(&hold)? == b"handshake complete")
            },
        )?;
        let parent = self
            .child
            .as_ref()
            .ok_or("daemon missing")?
            .supervised_pid()?
            .ok_or("daemon pid missing")?;
        let child = delivery_child(parent)?.ok_or("late child missing")?;
        let _cleanup = DeliveryGuard::new(child)?;
        let trace = fs::read_to_string(root.join("run/scupper/heartbeat-trace.jsonl"))?;
        let last: serde_json::Value =
            serde_json::from_str(trace.lines().last().ok_or("late trace missing")?)?;
        let deadline = last["deadline_ns"]
            .as_u64()
            .ok_or("late deadline missing")?;
        let remaining = deadline.saturating_sub(scupper_sys::heartbeat::monotonic_ns());
        let wall = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        fs::write(
            self.lab.artifacts.join("L53b-late-deadline.json"),
            serde_json::to_vec(
                &serde_json::json!({"deadline_epoch_ns":u64::try_from(wall + u128::from(remaining))?,"child":child}),
            )?,
        )?;
        self.block_heartbeat_request()?;
        self.control_stop(Signal::KILL)?;
        self.lab.runner.dwell(Duration::from_nanos(
            deadline
                .saturating_sub(scupper_sys::heartbeat::monotonic_ns())
                .saturating_sub(1_000_000_000),
        ))?;
        if !process_alive(child)? {
            return fail("late-release child died before release");
        }
        // Release with <2s remaining; no request may be queued, even though TLS
        // already succeeded. Keep capturing well beyond the original deadline.
        fs::remove_file(&hold)?;
        self.lab.runner.dwell(Duration::from_secs(5))?;
        if process_alive(child)? {
            return fail("late-release child outlived deadline");
        }
        let counter = self.lab.cmd(
            "gwhost",
            "nft",
            &["list", "chain", "inet", "scupper_hb_test", "output"],
        )?;
        if counter
            .lines()
            .any(|line| line.contains("counter packets") && !line.contains("counter packets 0 "))
        {
            return fail("L53b late release queued a request without retransmission margin");
        }
        self.lab.cmd(
            "gwhost",
            "nft",
            &["delete", "table", "inet", "scupper_hb_test"],
        )?;
        self.lab.runner.dwell(Duration::from_secs(5))?;
        Ok(())
    }
    fn orphan_deadline(&mut self, root: &Path, stopped: bool) -> Result<()> {
        let run = root.join("run/scupper");
        let hold = root.join("heartbeat-request-pause");
        fs::write(&hold, b"wait for handshake")?;
        fs::set_permissions(&hold, fs::Permissions::from_mode(0o666))?;
        self.lab.daemon_wait(
            "TLS handshake before request",
            Duration::from_secs(25),
            |_| {
                check_account_failure(root)?;
                Ok(fs::read(&hold)? == b"handshake complete")
            },
        )?;
        let pid = self
            .child
            .as_ref()
            .ok_or("daemon missing")?
            .supervised_pid()?
            .ok_or("daemon pid missing")?;
        let child = delivery_child(pid)?.ok_or("TLS child missing")?;
        let _cleanup = DeliveryGuard::new(child)?;
        let child_ns = fs::metadata(format!("/proc/{child}/ns/net"))?;
        let host_ns = fs::metadata("/run/netns/gwhost")?;
        if (child_ns.dev(), child_ns.ino()) != (host_ns.dev(), host_ns.ino()) {
            return fail("heartbeat child entered a different network namespace");
        }
        let sockets = self.lab.cmd("gwhost", "ss", &["-tnpe"])?;
        let identity = scupper_sys::heartbeat::account(
            &fs::read_to_string(root.join("etc/passwd"))?,
            &fs::read_to_string(root.join("etc/group"))?,
        )?;
        if !sockets.lines().any(|line| {
            line.contains(&format!("{ENDPOINT}:443"))
                && line
                    .split_whitespace()
                    .any(|word| word == format!("uid:{}", identity.uid))
                && line.contains("ESTAB")
        }) {
            return fail(format!(
                "heartbeat child has no established endpoint socket as scupper-alert uid {}",
                identity.uid
            ));
        }
        let trace = fs::read_to_string(run.join("heartbeat-trace.jsonl"))?;
        let last: serde_json::Value =
            serde_json::from_str(trace.lines().last().ok_or("heartbeat trace missing")?)?;
        let deadline = last["deadline_ns"]
            .as_u64()
            .ok_or("heartbeat deadline missing")?;
        let wall = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let remaining = deadline.saturating_sub(scupper_sys::heartbeat::monotonic_ns());
        let deadline_epoch_ns = u64::try_from(wall + u128::from(remaining))?;
        fs::write(
            self.lab
                .artifacts
                .join(format!("{}-deadline.json", self.case)),
            serde_json::to_vec(
                &serde_json::json!({"deadline_epoch_ns":deadline_epoch_ns,"child":child,"tls_handshake_complete":true}),
            )?,
        )?;
        self.drop_heartbeat_request(&hold)?;
        self.control_stop(Signal::KILL)?;
        let remaining = deadline.saturating_sub(scupper_sys::heartbeat::monotonic_ns());
        self.lab.runner.dwell(Duration::from_nanos(
            remaining.saturating_sub(2_000_000_000),
        ))?;
        if !process_alive(child)? {
            return fail("heartbeat child died before deadline liveness control");
        }
        if stopped {
            rustix::process::kill_process(
                rustix::process::Pid::from_raw(i32::try_from(child)?).ok_or("child pid")?,
                Signal::STOP,
            )?;
        }
        self.lab.runner.dwell(Duration::from_secs(3))?;
        if stopped {
            if !process_alive(child)? {
                return fail("L53b stopped child did not stay alive past deadline");
            }
        } else if process_alive(child)? {
            return fail("L53 orphan outlived its deadline");
        }
        self.lab.cmd(
            "gwhost",
            "nft",
            &["delete", "table", "inet", "scupper_hb_test"],
        )?;
        // Leave the stopped child alive while the drop is removed: only the
        // kernel user timeout can discard its unacknowledged TLS request here.
        self.lab.runner.dwell(Duration::from_secs(30))?;
        if stopped {
            rustix::process::kill_process(
                rustix::process::Pid::from_raw(i32::try_from(child)?).ok_or("child pid")?,
                Signal::CONT,
            )?;
        }
        Ok(())
    }
}
// Installed as soon as the child is identified, before any assertion or STOP.
// Every error path resumes and kills the group. Init reaps orphans; a direct
// child is reaped here. Do not adopt unrelated daemon/probe descendants.
struct DeliveryGuard(rustix::process::Pid);
impl DeliveryGuard {
    fn new(pid: u32) -> Result<Self> {
        Ok(Self(
            rustix::process::Pid::from_raw(i32::try_from(pid)?).ok_or("delivery pid")?,
        ))
    }
}
impl Drop for DeliveryGuard {
    fn drop(&mut self) {
        let _ = rustix::process::kill_process_group(self.0, Signal::CONT);
        let _ = rustix::process::kill_process_group(self.0, Signal::KILL);
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            match rustix::process::waitpid(Some(self.0), rustix::process::WaitOptions::NOHANG) {
                Ok(Some(_)) => return,
                Err(rustix::io::Errno::INTR) => continue,
                _ => {}
            }
            if !Path::new(&format!("/proc/{}", self.0)).exists() {
                return;
            }
            if std::time::Instant::now() >= deadline {
                eprintln!("delivery cleanup: process still present after group kill");
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
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

fn process_alive(pid: u32) -> Result<bool> {
    match fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(stat) => Ok(stat
            .rsplit_once(") ")
            .is_some_and(|(_, tail)| !tail.starts_with('Z'))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn stopped_delivery_guard_drop_kills_group_and_reaps() {
        use std::os::unix::process::CommandExt;
        let mut command = std::process::Command::new("/bin/sleep");
        command.arg("60").process_group(0);
        let mut child = command.spawn().unwrap();
        let guard = DeliveryGuard::new(child.id()).unwrap();
        rustix::process::kill_process(guard.0, Signal::STOP).unwrap();
        let pid = guard.0;
        drop(guard);
        assert!(!process_alive(child.id()).unwrap());
        assert!(child.wait().is_err()); // The guard has already reaped it.
        assert!(matches!(
            rustix::process::waitpid(Some(pid), rustix::process::WaitOptions::NOHANG),
            Err(rustix::io::Errno::CHILD)
        ));
    }
    #[test]
    fn noexec_mount_has_a_clear_setup_error() {
        let error = executable_mount(
            rustix::fs::StatVfsMountFlags::NOEXEC,
            Path::new("/run/lab/bin"),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("noexec") && error.contains("ST_NOEXEC"));
        executable_mount(
            rustix::fs::StatVfsMountFlags::empty(),
            Path::new("/var/lib/lab/bin"),
        )
        .unwrap();
    }

    #[test]
    fn delivery_copy_escapes_inaccessible_source_ancestors() {
        let root = Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("delivery-copy-{}", std::process::id()));
        let source = root.join("private");
        fs::create_dir_all(&source).unwrap();
        fs::set_permissions(&source, fs::Permissions::from_mode(0o700)).unwrap();
        for name in ["scupper", "scupperd"] {
            fs::write(source.join(name), "#!/bin/sh\nexit 0\n").unwrap();
        }
        let bin = root.join("bin");
        fs::create_dir(&bin).unwrap();
        let daemon = delivery_binaries(&source.join("scupper"), &bin).unwrap();
        assert_eq!(daemon, root.join("bin/scupperd"));
        for name in ["scupper", "scupperd"] {
            assert_eq!(
                fs::metadata(root.join("bin").join(name)).unwrap().mode() & 0o777,
                0o755
            );
            assert!(
                std::process::Command::new(root.join("bin").join(name))
                    .status()
                    .unwrap()
                    .success()
            );
        }
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn heartbeat_fixture_keeps_system_account_text_and_lookup_uses_allocated_ids() {
        let root = Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("heartbeat-account-fixture-{}", std::process::id()));
        fs::create_dir_all(root.join("etc/scupper/secrets/url")).unwrap();
        // useradd --system --user-group --no-create-home --shell /usr/sbin/nologin:
        // IDs are allocated separately and the home field does not create a directory.
        let passwd = "root:x:0:0:root:/root:/bin/bash\nscupper-probe:x:998:997::/home/scupper-probe:/usr/sbin/nologin\nscupper-alert:x:997:996::/home/scupper-alert:/usr/sbin/nologin\n";
        let group = "root:x:0:\nscupper-probe:x:997:\nscupper-alert:x:996:\n";
        fs::write(root.join("etc/passwd"), passwd).unwrap();
        fs::write(root.join("etc/group"), group).unwrap();
        let mut site = scupper_core::config::parse_site(crate::lab::SITE).unwrap();
        DaemonGuard::heartbeat_fixture(&root, &mut site).unwrap();
        let copied_passwd = fs::read_to_string(root.join("etc/passwd")).unwrap();
        let copied_group = fs::read_to_string(root.join("etc/group")).unwrap();
        assert_eq!(copied_passwd, passwd);
        assert_eq!(copied_group, group);
        let identity = scupper_sys::heartbeat::account(&copied_passwd, &copied_group).unwrap();
        assert_eq!((identity.uid, identity.gid), (997, 996));
        assert!(
            scupper_sys::heartbeat::account("root:x:0:0:root:/root:/bin/bash\n", group).is_err()
        );
        assert!(scupper_sys::heartbeat::account(passwd, "root:x:0:\n").is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn heartbeat_account_event_fails_immediately_with_setup_diagnostic() {
        let root = Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("heartbeat-account-events-{}", std::process::id()));
        let events = root.join("var-lib/scupper/events");
        fs::create_dir_all(&events).unwrap();
        check_account_failure(&root).unwrap();
        let record = |reason| {
            serde_json::json!({
                "seq":6,"at":1_794_355_510,"kind":"HeartbeatFailed","data":{"reason":reason},
                "actor":"Daemon","gateway":"gw1","config_version":8
            })
            .to_string()
                + "\n"
        };
        let file = events.join("2026-11.jsonl");
        fs::write(&file, record("HeartbeatHttp")).unwrap();
        check_account_failure(&root).unwrap();
        fs::write(&file, record("HeartbeatAccount")).unwrap();
        let error = check_account_failure(&root).unwrap_err().to_string();
        assert!(error.contains("HeartbeatAccount"));
        assert!(error.contains("scupper-alert"));
        assert!(error.contains("lab prepare"));
        fs::remove_dir_all(root).unwrap();
    }
}
