//! Real unit faults, using the namespace lab's traffic and capture oracle.
use super::super::command::Group;
use super::{
    A, CLI, Duration, Instant, Invocation, Lab, Path, Result, SystemdLab, fail, fs, helpers,
};
use rustix::process::Signal;
use std::{
    io::Write,
    os::unix::{fs::MetadataExt, process::ExitStatusExt},
};

impl SystemdLab {
    pub(super) fn capture_control(&mut self) -> Result<()> {
        let stem = "oracle-positive-control";
        self.lab.capture("", "up0", stem)?;
        let mut markers = Vec::new();
        self.lab.service_check(&mut markers)?;
        let marker = Lab::marker()?;
        markers.push(marker.clone());
        self.lab.runner.input(&Invocation::new("wan", "nft", &["-f", "-"]), Some(b"table inet lab_inject { chain input { type filter hook input priority filter; ip saddr 198.51.100.2 ip daddr 198.51.100.1 udp sport { 40002, 40003 } udp dport { 53, 8080 } drop;\n\t}\n}\n"))?;
        for (index, bytes) in helpers::injection_packets(&marker)?.iter().enumerate() {
            let path = self.lab.private.join(format!("control-{index}.packet"));
            fs::write(&path, bytes)?;
            let exe = self.lab.executable.clone();
            self.lab.cmd(
                "",
                &exe,
                &[
                    "send-packet",
                    "--interface",
                    "up0",
                    "--file",
                    path.to_str().ok_or("packet path")?,
                ],
            )?;
        }
        self.lab.runner.dwell(Duration::from_secs(1))?;
        let report = self.evaluate(stem, &markers)?;
        let result = super::super::evidence::injected_only(
            &report,
            &fs::read(self.lab.artifacts.join(format!("{stem}.pcap")))?,
            &marker,
        );
        self.lab
            .cmd("wan", "nft", &["delete", "table", "inet", "lab_inject"])?;
        result
    }

    pub(super) fn case(&mut self, case: &str) -> Result<()> {
        if case == "L9" {
            for point in [
                "0",
                "1",
                "2",
                "3",
                "4",
                "5",
                "6",
                "7",
                "link-add-wg0",
                "link-add-ex-ch1",
            ] {
                self.guard(&format!("L9-{point}-before"))?;
                self.boot_prefix(point)?;
                self.guard(&format!("L9-{point}-after"))?;
            }
            return Ok(());
        }
        let mut markers = Vec::new();
        self.lab.capture("", "up0", case)?;
        let mut stream = self.stream(case, &mut markers)?;
        let trial = (|| {
            self.lab.service_check(&mut markers)?;
            match case {
                "L10" => self.daemon_faults(&mut markers)?,
                "L14" => self.disconnect_reboot(&mut markers)?,
                "L44" => self.writers(&mut markers)?,
                "V-13" => self.ufw(&mut markers)?,
                _ => return fail("unknown case"),
            }
            self.ready()?;
            self.safety()?;
            self.lab.service_check(&mut markers)
        })();
        let flow = self.finish_stream(&mut stream, case, case == "L10");
        let oracle = self.judge(case, &markers);
        super::super::mutation::finish(trial, super::super::mutation::finish(flow, oracle))
    }
    fn stream(&mut self, stem: &str, markers: &mut Vec<String>) -> Result<Group> {
        let marker = Lab::marker()?;
        markers.push(marker.clone());
        self.lab.runner.background(
            &Invocation::new(
                "client",
                &self.lab.executable,
                &[
                    "flow",
                    "--mode",
                    "udp",
                    "--address",
                    &format!("{}:8080", A.internet.peer),
                    "--marker",
                    &marker,
                    "--log",
                    self.lab
                        .artifacts
                        .join(format!("{stem}-flow.jsonl"))
                        .to_str()
                        .ok_or("flow path")?,
                    "--seconds",
                    "1400",
                ],
            ),
            &self.lab.artifacts.join(format!("{stem}-flow.stdout")),
        )
    }
    fn finish_stream(&mut self, stream: &mut Group, stem: &str, continuous: bool) -> Result<()> {
        stream.stop(Signal::TERM)?;
        let text = fs::read_to_string(self.lab.artifacts.join(format!("{stem}-flow.jsonl")))?;
        let records: Vec<serde_json::Value> = text
            .lines()
            .map(serde_json::from_str)
            .collect::<std::result::Result<_, _>>()?;
        let received: Vec<u64> = records
            .iter()
            .filter(|r| r["received"].as_u64().is_some_and(|n| n > 0))
            .filter_map(|r| r["elapsed_ms"].as_u64())
            .collect();
        if records.len() < 20 || received.len() < 2 {
            return fail("continuous canary was blind");
        }
        let end = records
            .last()
            .and_then(|r| r["elapsed_ms"].as_u64())
            .ok_or("missing flow duration")?;
        if continuous
            && (received.windows(2).any(|w| w[1] - w[0] > 2000)
                || received.first().copied().unwrap_or(0) > 2000
                || end.saturating_sub(received.last().copied().unwrap_or(0)) > 2000)
        {
            return fail("traffic interrupted during daemon kill/stop");
        }
        Ok(())
    }
    fn fresh_session(&mut self) -> Result<()> {
        self.lab
            .cmd("client", "ip", &["link", "set", "wg0", "down"])?;
        self.lab
            .cmd("client", "ip", &["link", "set", "wg0", "up"])?;
        for family in ["-4", "-6"] {
            self.lab.cmd(
                "client",
                "ip",
                &[family, "route", "replace", "default", "dev", "wg0"],
            )?;
        }
        Ok(())
    }
    #[allow(clippy::too_many_lines)] // Keep each killed prefix beside its ingress, adoption and reboot controls.
    fn boot_prefix(&mut self, point: &str) -> Result<()> {
        let stem = format!("L9-{point}");
        let mut markers = Vec::new();
        self.lab.capture("", "up0", &stem)?;
        let mut stream = self.stream(&stem, &mut markers)?;
        let trial = (|| {
            self.lab.service_check(&mut markers)?;
            self.reboot_stop()?;
            let args = if let Some(link) = point.strip_prefix("link-add-") {
                vec!["boot", "--stop-after-link-add", link]
            } else {
                vec!["boot", "--stop-after", point]
            };
            let (status, _) =
                self.lab
                    .runner
                    .output_timeout(&Invocation::new("", CLI, &args), None, 90)?;
            if status.signal() != Some(9) && status.code() != Some(137) {
                return fail(format!("boot checkpoint did not SIGKILL: {status}"));
            }
            let reached = fs::read_to_string("/run/scupper/boot-reached")?;
            fs::write(
                self.lab.artifacts.join(format!("{stem}-checkpoint.txt")),
                &reached,
            )?;
            if reached != format!("reached {point}\n") {
                return fail("wrong boot checkpoint");
            }
            self.cmd("udevadm", &["settle", "--timeout=10"])?;
            if let Some(link) = point.strip_prefix("link-add-") {
                let state = self.cmd("networkctl", &["--no-pager", "status", link])?;
                fs::write(
                    self.lab.artifacts.join(format!("{stem}-networkd.txt")),
                    state,
                )?;
                let links = scupper_core::parse::parse_ip_link(&self.lab.cmd(
                    "",
                    "ip",
                    &["-d", "-j", "link", "show", "dev", link],
                )?)?;
                if links.len() != 1
                    || links[0].kind.as_deref() != Some("wireguard")
                    || links[0].flags.iter().any(|f| f == "UP")
                    || !self
                        .lab
                        .cmd("", "wg", &["show", link, "peers"])?
                        .trim()
                        .is_empty()
                {
                    return fail("udev/networkd changed boot leftover");
                }
            }
            self.safety()?;
            if matches!(point, "4" | "5" | "6" | "7") {
                let port = self
                    .lab
                    .cmd("scupper", "wg", &["show", "ex-ch1", "listen-port"])?
                    .trim()
                    .parse()?;
                self.record_port(port);
            }
            self.fresh_session()?;
            let has_client = matches!(point, "4" | "5" | "6" | "7" | "link-add-ex-ch1");
            let rx = if has_client {
                let until = Instant::now() + Duration::from_secs(15);
                loop {
                    self.lab.runner.output(
                        &Invocation::new(
                            "client",
                            "ping",
                            &["-c", "1", "-W", "1", A.gateway_inner],
                        ),
                        None,
                    )?;
                    let handshakes =
                        self.lab
                            .cmd("scupper", "wg", &["show", "wg0", "latest-handshakes"])?;
                    if handshakes
                        .split_whitespace()
                        .nth(1)
                        .is_some_and(|v| v != "0")
                    {
                        break;
                    }
                    if Instant::now() >= until {
                        return fail("prefix client ingress control was blind");
                    }
                }
                self.lab
                    .capture("scupper", "wg0", &format!("{stem}-ingress"))?;
                Some(self.lab.boot_client_rx()?)
            } else {
                None
            };
            let marker = Lab::marker()?;
            markers.push(marker.clone());
            if matches!(point, "6" | "7") {
                if self
                    .lab
                    .send("client", "udp", A.internet.peer, &marker, false)?
                    != helpers::Outcome::Delivered
                {
                    return fail("open prefix canary failed");
                }
            } else {
                self.negative_udp("client", &marker)?;
            }
            if let Some(before) = rx {
                self.lab.stop_capture()?;
                super::super::boot::boot_canary_arrival(
                    before,
                    self.lab.boot_client_rx()?,
                    &fs::read(self.lab.artifacts.join(format!("{stem}-ingress.pcap")))?,
                    &[marker],
                )?;
            }
            // First recover without deleting the host leftover: adoption/removal
            // must be proved before the second reboot destroys runtime state.
            self.reboot_start()?;
            self.ready()?;
            self.safety()?;
            self.lab.service_check(&mut markers)?;
            self.reboot_stop()?;
            self.reboot_start()?;
            self.ready()?;
            self.fresh_session()?;
            self.lab.service_check(&mut markers)?;
            self.safety()
        })();
        let flow = self.finish_stream(&mut stream, &stem, false);
        let oracle = self.judge(&stem, &markers);
        let result =
            super::super::mutation::finish(trial, super::super::mutation::finish(flow, oracle));
        fs::write(
            self.lab.artifacts.join(format!("{stem}.json")),
            serde_json::to_vec_pretty(
                &serde_json::json!({"point":point,"passed":result.is_ok(),"error":result.as_ref().err().map(ToString::to_string)}),
            )?,
        )?;
        result
    }
    fn pid(&mut self) -> Result<u32> {
        let pid = self
            .systemctl(&["show", "scupperd", "--property=MainPID", "--value"])?
            .trim()
            .parse()?;
        if pid == 0 {
            return fail("scupperd has no MainPID");
        }
        Ok(pid)
    }
    fn daemon_faults(&mut self, markers: &mut Vec<String>) -> Result<()> {
        let first = self.pid()?;
        self.systemctl(&["kill", "--kill-who=main", "--signal=SIGKILL", "scupperd"])?;
        self.check_code(5)?;
        // Traffic must survive while the daemon is down, before readiness polling.
        self.lab.service_check(markers)?;
        self.ready()?;
        let second = self.pid()?;
        if second == first {
            return fail("systemd did not replace killed daemon");
        }
        self.systemctl(&["kill", "--kill-who=main", "--signal=SIGSTOP", "scupperd"])?;
        let started = Instant::now();
        let setting =
            self.systemctl(&["show", "scupperd", "--property=WatchdogUSec", "--value"])?;
        if !matches!(setting.trim(), "30s" | "30000000") {
            return fail(format!("unexpected watchdog setting: {setting}"));
        }
        let watchdog = Duration::from_secs(30);
        let until = Instant::now() + watchdog + Duration::from_secs(35);
        loop {
            self.lab.service_check(markers)?;
            self.safety()?;
            if let Ok(pid) = self.pid()
                && pid != second
                && started.elapsed() > watchdog + Duration::from_secs(3)
            {
                break;
            }
            if Instant::now() >= until {
                return fail("watchdog did not replace stopped daemon");
            }
            self.lab.runner.dwell(Duration::from_millis(200))?;
        }
        if started.elapsed() < watchdog {
            return fail("SIGSTOP did not exceed WatchdogSec");
        }
        self.ready()?;
        self.journal("L10-watchdog-journal.txt")?;
        let journal =
            fs::read_to_string(self.lab.artifacts.join("L10-watchdog-journal.txt"))?.to_lowercase();
        if !journal.contains("watchdog timeout") || !journal.contains("watchdog") {
            return fail("journal lacks watchdog timeout");
        }
        Ok(())
    }
    fn disconnect_reboot(&mut self, markers: &mut Vec<String>) -> Result<()> {
        self.cli(&["disconnect"])?;
        self.check_code(4)?;
        self.closed_canary(markers)?;
        self.reboot_stop()?;
        self.reboot_start()?;
        self.check_code(4)?;
        for key in ["net.ipv4.ip_forward", "net.ipv6.conf.all.forwarding"] {
            if self.lab.cmd("scupper", "sysctl", &["-n", key])?.trim() != "0" {
                return fail("disconnect lost across reboot");
            }
        }
        self.fresh_session()?;
        self.closed_canary(markers)?;
        self.cli(&["connect"])?;
        self.ready()
    }
    fn fault_dropin(&mut self, unit: &str, body: &str) -> Result<()> {
        let dir = format!("/run/systemd/system/{unit}.service.d");
        fs::create_dir_all(&dir)?;
        fs::write(
            format!("{dir}/90-scupper-lab.conf"),
            format!("[Service]\n{body}\n"),
        )?;
        self.systemctl(&["daemon-reload"])?;
        Ok(())
    }
    fn clear_faults(&mut self) -> Result<()> {
        for unit in ["scupper-net", "scupperd"] {
            let path = format!("/run/systemd/system/{unit}.service.d/90-scupper-lab.conf");
            if Path::new(&path).exists() {
                fs::remove_file(path)?;
            }
        }
        self.systemctl(&["daemon-reload"])?;
        Ok(())
    }
    fn writers(&mut self, markers: &mut Vec<String>) -> Result<()> {
        self.reboot_stop()?;
        self.fault_dropin(
            "scupper-net",
            "ExecStart=\nExecStart=/usr/local/bin/scupper boot --stop-after=3",
        )?;
        self.fault_dropin("scupperd", "Environment=SCUPPER_TEST_BOOT_POINT=3\nEnvironment=SCUPPER_TEST_BOOT_MARKER=/run/scupper/daemon-reached")?;
        let trial = (|| {
            let mut start = self.lab.runner.background(
                &Invocation::new("", "systemctl", &["start", "scupperd"]),
                &self.lab.artifacts.join("L44-initial-start.stdout"),
            )?;
            let until = Instant::now() + Duration::from_secs(90);
            while !Path::new("/run/scupper/daemon-reached").exists() {
                self.safety()?;
                if Instant::now() >= until {
                    return fail("daemon never retried failed unit boot");
                }
                self.lab.runner.dwell(Duration::from_millis(50))?;
            }
            fs::copy(
                "/run/scupper/daemon-reached",
                self.lab.artifacts.join("L44-daemon-retry.txt"),
            )?;
            self.clear_faults()?;
            // The daemon was killed at its boot retry; the local apply races
            // systemd's automatic restart and a manual namespace-unit restart.
            let guard = scupper_sys::lock::WriterLock::acquire(Path::new("/run/scupper"))?;
            let mut apply = self.lab.runner.background(
                &Invocation::new("", CLI, &["apply"]),
                &self.lab.artifacts.join("L44-apply.stdout"),
            )?;
            let mut restart = self.lab.runner.background(
                &Invocation::new("", "systemctl", &["restart", "scupper-net"]),
                &self.lab.artifacts.join("L44-net-restart.stdout"),
            )?;
            self.writer_sample()?;
            self.lab.runner.dwell(Duration::from_millis(200))?;
            self.writer_sample()?;
            drop(guard);
            let mut statuses = [None, None, None];
            let until = Instant::now() + Duration::from_secs(120);
            while statuses.iter().any(Option::is_none) {
                self.safety()?;
                self.writer_sample()?;
                for (index, child) in [&mut start, &mut apply, &mut restart]
                    .into_iter()
                    .enumerate()
                {
                    if statuses[index].is_none() {
                        statuses[index] = child.try_wait()?;
                    }
                }
                if Instant::now() >= until {
                    return fail("concurrent writers stuck");
                }
            }
            // Contention may be refused, but must be bounded and explicit.
            for (index, status) in statuses.into_iter().enumerate() {
                let status = status.ok_or("missing writer status")?;
                if !status.success() {
                    let log = [
                        "L44-initial-start.stderr",
                        "L44-apply.stderr",
                        "L44-net-restart.stderr",
                    ][index];
                    let text = fs::read_to_string(self.lab.artifacts.join(log))?;
                    if index == 0 && status.code() == Some(1) {
                        continue;
                    } // injected pre-READY crash
                    if index == 2 && status.code() == Some(1) {
                        self.journal("L44-contention-journal.txt")?;
                        let journal = fs::read_to_string(
                            self.lab.artifacts.join("L44-contention-journal.txt"),
                        )?;
                        if journal.contains("lease") || journal.contains("lock") {
                            continue;
                        }
                    }
                    if index != 1
                        || status.code() != Some(1)
                        || !["lock", "lease", "unavailable", "scupperd"]
                            .iter()
                            .any(|word| text.contains(word))
                    {
                        return fail(format!("unexpected writer failure: {status}: {text}"));
                    }
                }
            }
            self.ready()?;
            self.systemctl(&["start", "scupper-net"])?;
            self.safety()?;
            self.lab.service_check(markers)
        })();
        let cleanup = self.clear_faults();
        super::super::mutation::finish(trial, cleanup)
    }
    fn writer_sample(&mut self) -> Result<()> {
        let Ok(meta) = fs::metadata("/run/scupper/writer.lock") else {
            return Ok(());
        };
        let locks = fs::read_to_string("/proc/locks")?;
        let holders = writer_holders(&locks, meta.ino());
        if holders.len() > 1 {
            return fail("multiple writer lock holders");
        }
        let mut log = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.lab.artifacts.join("L44-locks.jsonl"))?;
        writeln!(
            log,
            "{}",
            serde_json::json!({"holders":holders,"inode":meta.ino()})
        )?;
        Ok(())
    }
    fn ufw(&mut self, markers: &mut Vec<String>) -> Result<()> {
        let status = self.cmd("ufw", &["status"])?;
        if status.trim() != "Status: inactive" {
            return fail("refusing an already active runner firewall");
        }
        let added = self.cmd("ufw", &["show", "added"])?;
        if added.lines().any(|line| line.trim().starts_with("ufw ")) {
            return fail("refusing pre-existing ufw user rules");
        }
        // Defaults accept every interface; the only deny rules name up0.
        for direction in ["incoming", "outgoing", "routed"] {
            self.cmd("ufw", &["default", "allow", direction])?;
        }
        self.cmd(
            "ufw",
            &[
                "deny", "in", "on", "up0", "proto", "udp", "to", "any", "port", "51820",
            ],
        )?;
        self.cmd(
            "ufw",
            &[
                "deny", "out", "on", "up0", "proto", "udp", "to", "any", "port", "51820",
            ],
        )?;
        let trial = (|| {
            self.cmd("ufw", &["--force", "enable"])?;
            self.guard("ufw-enabled")?;
            let rules = self.cmd("ufw", &["status", "verbose"])?;
            fs::write(self.lab.artifacts.join("V-13-ufw.txt"), rules)?;
            let out = self.cli(&["install", "--check"])?;
            fs::write(self.lab.artifacts.join("V-13-install-check.txt"), &out)?;
            if !out.contains("warning: host firewall may block UDP 51820")
                || !out.contains("install: no changes")
            {
                return fail("missing UDP firewall availability warning");
            }
            // Existing established UDP is accepted by ufw's before rules. Remove
            // only lab tuples, then require a fresh handshake to be blocked.
            for (source, destination) in [
                (A.client.peer, A.gwhost.peer),
                (A.gwhost.peer, A.provider.peer),
            ] {
                let (status, _) = self.lab.runner.output(
                    &Invocation::new(
                        "",
                        "conntrack",
                        &[
                            "-D",
                            "-p",
                            "udp",
                            "-s",
                            source,
                            "-d",
                            destination,
                            "--dport",
                            "51820",
                        ],
                    ),
                    None,
                )?;
                if !matches!(status.code(), Some(0 | 1)) {
                    return fail("scoped conntrack delete failed");
                }
            }
            // client2 has never sent traffic, so ufw's earlier ESTABLISHED
            // accept cannot mask the deny rule via an old gateway session.
            let marker = Lab::marker()?;
            markers.push(marker.clone());
            if self
                .lab
                .send("client2", "udp", A.internet.peer, &marker, false)?
                != helpers::Outcome::TimedOut
            {
                return fail("ufw did not block fresh client2 handshake");
            }
            Ok(())
        })();
        let disabled = self.cmd("ufw", &["--force", "disable"]).map(|_| ());
        super::super::mutation::finish(trial, disabled)?;
        if self.cmd("ufw", &["status"])?.trim() != "Status: inactive" {
            return fail("ufw remained active");
        }
        self.fresh_session()?;
        self.ready()?;
        let marker = Lab::marker()?;
        markers.push(marker.clone());
        if self
            .lab
            .send("client2", "udp", A.internet.peer, &marker, false)?
            != helpers::Outcome::Delivered
        {
            return fail("client2 did not recover after ufw disable");
        }
        let receipts =
            helpers::receipts(&fs::read_to_string(self.lab.artifacts.join("sink.jsonl"))?)?;
        if !receipts
            .iter()
            .any(|r| r.marker == marker && r.peer.ip().to_string() == A.provider.peer)
        {
            return fail("client2 positive control lacks provider NAT receipt");
        }
        Ok(())
    }
}

fn writer_holders(locks: &str, inode: u64) -> Vec<&str> {
    locks
        .lines()
        .filter(|line| {
            let words: Vec<_> = line.split_whitespace().collect();
            words.get(1..4) == Some(&["FLOCK", "ADVISORY", "WRITE"])
                && words
                    .get(5)
                    .and_then(|v| v.rsplit(':').next())
                    .and_then(|v| v.parse::<u64>().ok())
                    == Some(inode)
        })
        .collect()
}
#[cfg(test)]
mod tests {
    #[test]
    fn writer_lock_parser_excludes_waiters_and_other_locks() {
        let locks = "1: FLOCK  ADVISORY  WRITE 123 00:01:42 0 EOF\n1: -> FLOCK ADVISORY WRITE 124 00:01:42 0 EOF\n2: POSIX ADVISORY WRITE 125 00:01:42 0 EOF\n3: FLOCK ADVISORY WRITE 126 00:01:43 0 EOF\n";
        assert_eq!(super::writer_holders(locks, 42).len(), 1);
        assert_eq!(super::writer_holders(locks, 99).len(), 0);
        assert_eq!(super::writer_holders("garbage", 42).len(), 0);
    }
}
