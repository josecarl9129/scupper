//! Real boot CLI, crash prefixes, adoption and persisted disconnection.
use super::{
    Lab, Result,
    addresses::A,
    cleanup::Resource,
    command::Invocation,
    evidence::{self, Row},
    fail,
};
use scupper_core::{canon::canonicalize, render::desired_sysctls, rules::IfName};
use scupper_sys::boot::{BootReport, BootStep};
use std::{
    fs,
    os::unix::process::ExitStatusExt,
    path::PathBuf,
    time::{Duration, Instant},
};

pub(super) fn kill_points() -> Vec<String> {
    BootStep::ALL
        .iter()
        .map(|step| (*step as u8).to_string())
        .collect()
}

pub(super) fn at_or_after(point: &str, first: BootStep) -> bool {
    BootStep::ALL
        .iter()
        .skip_while(|step| **step != first)
        .any(|step| point == (*step as u8).to_string())
}

fn successful_report(status: std::process::ExitStatus, stdout: &str) -> Result<BootReport> {
    let report: BootReport = serde_json::from_str(stdout)
        .map_err(|error| format!("invalid boot report: {status}: {error}: {stdout}"))?;
    if !status.success() || !report.succeeded() {
        return fail(format!("boot failed: {status}: {stdout}"));
    }
    Ok(report)
}

pub(super) fn verify_modules(report: &BootReport) -> Result<()> {
    // succeeded enforces order and errors. Recovery additionally needs current
    // module evidence, even though upgrade handoffs accept the legacy report.
    if !report.succeeded()
        || report
            .steps
            .get(1)
            .is_none_or(|step| step.step != BootStep::Modules)
    {
        return fail(
            "boot did not load modules successfully immediately after Lock, before Inputs",
        );
    }
    Ok(())
}

pub(super) fn client_handshake(text: &str, expected: &str) -> u64 {
    text.lines()
        .find_map(|line| {
            let mut fields = line.split_whitespace();
            (fields.next()? == expected)
                .then(|| fields.next()?.parse().ok())
                .flatten()
        })
        .unwrap_or(0)
}

// ip_forward rewrites per-interface settings too: retain every IPv4 conf value,
// then restore only changed files after restoring ip_forward itself.
pub(super) struct InheritanceGuard {
    saved: Vec<(PathBuf, String)>,
    snapshot: Option<PathBuf>,
}
impl InheritanceGuard {
    pub(super) fn save() -> Result<Self> {
        let mut paths = vec![PathBuf::from("/proc/sys/net/ipv4/ip_forward")];
        for interface in fs::read_dir("/proc/sys/net/ipv4/conf")? {
            for key in fs::read_dir(interface?.path())? {
                paths.push(key?.path());
            }
        }
        for name in ["all", "default"] {
            paths.push(PathBuf::from(format!(
                "/proc/sys/net/ipv6/conf/{name}/accept_ra"
            )));
        }
        let saved = paths
            .into_iter()
            .map(|p| {
                let value = fs::read_to_string(&p)?;
                Ok((p, value))
            })
            .collect::<Result<_>>()?;
        Ok(Self {
            saved,
            snapshot: None,
        })
    }
    pub(super) fn persist(&mut self, path: PathBuf) -> Result<()> {
        use std::io::Write as _;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        file.write_all(&serde_json::to_vec_pretty(&self.saved)?)?;
        file.sync_all()?;
        fs::File::open(path.parent().ok_or("snapshot parent")?)?.sync_all()?;
        self.snapshot = Some(path);
        Ok(())
    }
    pub(super) fn restore(&mut self) -> Result<()> {
        let mut failures = Vec::new();
        // ip_forward is first: writing it can rewrite the remaining values.
        for (path, value) in &self.saved {
            let restored = match fs::read_to_string(path) {
                Ok(current) if current != *value => fs::write(path, value),
                Ok(_) => Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => Err(error),
            };
            if let Err(error) = restored {
                // A disappearing interface must not prevent restoring all/default.
                if error.kind() != std::io::ErrorKind::NotFound {
                    failures.push(format!("{}: {error}", path.display()));
                }
            }
        }
        if !failures.is_empty() {
            return fail(failures.join("; "));
        }
        if let Some(path) = &self.snapshot {
            fs::remove_file(path)?;
        }
        self.snapshot = None;
        self.saved.clear();
        Ok(())
    }
}
impl Drop for InheritanceGuard {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

pub(super) fn refuse_unrestored_sysctls(parent: &std::path::Path) -> Result<()> {
    for entry in fs::read_dir(parent)? {
        let entry = entry?;
        if entry
            .file_name()
            .to_string_lossy()
            .starts_with("scupper-lab-")
            && entry.path().join("host-sysctls.json").exists()
        {
            return fail(format!(
                "unrestored host sysctls: {}; restore these originals before restarting the lab",
                entry.path().join("host-sysctls.json").display()
            ));
        }
    }
    Ok(())
}

impl Lab {
    pub(super) fn boot_binary() -> Result<PathBuf> {
        Ok(fs::canonicalize(
            std::env::current_exe()?
                .parent()
                .and_then(std::path::Path::parent)
                .ok_or("lab executable must be in target/{profile}")?
                .join("debug/scupper"),
        )?)
    }
    fn boot_output(
        &mut self,
        extra: &[&str],
        stem: &str,
    ) -> Result<(std::process::ExitStatus, String)> {
        if self.sampler.take().is_some() {
            let until = std::time::Instant::now() + std::time::Duration::from_secs(15);
            loop {
                match scupper_sys::lock::WriterLock::try_acquire(
                    self.boot_root.join("run/scupper/client-sampler-owner"),
                ) {
                    Ok(owner) => {
                        drop(owner);
                        break;
                    }
                    Err(_) if std::time::Instant::now() < until => {
                        self.runner.dwell(std::time::Duration::from_millis(25))?;
                    }
                    Err(error) => return Err(error.into()),
                }
            }
        }
        // The check-only lab activates its sampler before boot. Product startup
        // boots first, then activates the daemon; daemon/systemd labs cover it.
        if !self.site.health().require_daemon()
            && let Ok(lease) =
                scupper_sys::lock::SupervisorLease::try_acquire(self.boot_root.join("run/scupper"))
        {
            let activation = scupper_sys::lock::WriterLock::try_acquire(
                self.boot_root.join("run/scupper/client-sampler-owner"),
            )?;
            let gateway = self
                .site
                .gateway(&scupper_core::config::GatewayId("gw1".into()))
                .ok_or("missing gateway")?;
            scupper_sys::client_sessions::activate(
                &self.boot_root.join("var-lib/scupper"),
                &self.boot_root.join("run/scupper"),
                gateway.client_tunnel().identity().public_key.as_str(),
                scupper_sys::system::System::now_unix_secs(
                    &scupper_sys::system::RealSystem::default(),
                ),
                &activation,
            )?;
            drop(activation);
            drop(lease);
        }
        let binary = Self::boot_binary()?;
        let root = self.boot_root.clone();
        let trace = self.artifacts.join(format!("{stem}.calls.json"));
        let mut args = vec![
            "--test-root",
            root.to_str().ok_or("non-UTF8 root")?,
            "boot",
            "--trace",
            trace.to_str().ok_or("non-UTF8 trace")?,
        ];
        args.extend_from_slice(extra);
        let (status, stdout) = self.runner.output(
            &Invocation::new("gwhost", binary.to_str().ok_or("non-UTF8 binary")?, &args),
            None,
        )?;
        fs::write(self.artifacts.join(format!("{stem}.json")), &stdout)?;
        // A killed boot may emit no report. Parse only the success path.
        Ok((status, stdout))
    }
    pub(super) fn boot_gateway(&mut self, extra: &[&str], stem: &str) -> Result<BootReport> {
        let (status, stdout) = self.boot_output(extra, stem)?;
        let report = successful_report(status, &stdout)?;
        self.exit_port = self
            .cmd("scupper", "wg", &["show", "ex-ch1", "listen-port"])?
            .trim()
            .parse()?;
        self.assert_transport_ports()?;
        self.start_lab_sampler()?;
        Ok(report)
    }
    pub(super) fn boot_adopt(&mut self) -> Result<()> {
        let report = self.boot_gateway(&[], "boot-adopt")?;
        if !report.adopted {
            return fail("second boot did not adopt");
        }
        let calls: Vec<serde_json::Value> =
            serde_json::from_slice(&fs::read(self.artifacts.join("boot-adopt.calls.json"))?)?;
        let mut routes = 0;
        for call in calls {
            let words = call["args"].as_array().ok_or("missing trace argv")?;
            let argv: Vec<_> = words.iter().filter_map(|v| v.as_str()).collect();
            match call["program"].as_str() {
                Some("Ip") if argv.contains(&"replace") => {
                    routes += 1;
                }
                Some("Ip") if argv.contains(&"show") => {}
                Some("Wg") if matches!(argv.first(), Some(&"show" | &"pubkey")) => {}
                Some("Sysctl") if argv.first() == Some(&"-n") => {}
                Some("Nft") if argv == ["-j", "list", "ruleset"] => {}
                Some("Tc" | "Unshare") => {}
                _ => return fail(format!("adoption unexpectedly mutated the gateway: {call}")),
            }
        }
        if routes != 2 {
            return fail("adoption did not reassert exactly two defaults");
        }
        self.rows.push(Row{name:"boot-adopt".into(),wanted:"verify only; two route replacements".into(),got:"adopted".into(),detail:"boot-adopt.calls.json records every public argv; no link, sysctl or live nft writes".into()});
        Ok(())
    }
    #[allow(clippy::too_many_lines)] // Injection and its independent inherited-value control share a guard.
    pub(super) fn boot_inheritance(&mut self) -> Result<()> {
        if self
            .site
            .gateways()
            .values()
            .next()
            .ok_or("missing gateway")?
            .client_tunnel()
            .address4()
            .addr()
            .to_string()
            != A.gateway_inner
        {
            return fail("lab gateway address differs from the address table");
        }
        self.inheritance = Some(InheritanceGuard::save()?);
        self.cmd(
            "",
            "sysctl",
            &[
                "-w",
                "net.ipv4.ip_forward=1",
                "net.ipv4.conf.all.rp_filter=2",
                "net.ipv4.conf.default.rp_filter=2",
                "net.ipv6.conf.all.accept_ra=1",
                "net.ipv6.conf.default.accept_ra=1",
            ],
        )?;
        self.cmd("gwhost", "ip", &["netns", "add", "scupper-inherit"])?;
        self.registry
            .register(Resource::Namespace("scupper-inherit".into()));
        let mut observed = serde_json::Map::new();
        for (key, expected) in [
            ("net.ipv4.ip_forward", "1"),
            ("net.ipv4.conf.all.rp_filter", "2"),
            ("net.ipv4.conf.default.rp_filter", "2"),
            ("net.ipv6.conf.all.accept_ra", "1"),
            ("net.ipv6.conf.default.accept_ra", "1"),
        ] {
            let value = self.cmd("scupper-inherit", "sysctl", &["-n", key])?;
            observed.insert(key.into(), value.trim().into());
            if value.trim() != expected {
                return fail(format!(
                    "L18 hostile inheritance positive control: {key}={value}, wanted {expected}"
                ));
            }
        }
        observed.insert(
            "accept_ra_control".into(),
            "compiled default, not inherited".into(),
        );
        fs::write(
            self.artifacts.join("L18-pre-boot.json"),
            serde_json::to_vec_pretty(&observed)?,
        )?;
        self.cmd("", "ip", &["netns", "delete", "scupper-inherit"])?;
        self.registry
            .unregister(&Resource::Namespace("scupper-inherit".into()));
        Ok(())
    }
    pub(super) fn restore_inheritance(&mut self) -> Result<()> {
        if let Some(guard) = &mut self.inheritance {
            guard.restore()?;
        }
        self.inheritance = None;
        Ok(())
    }
    pub(super) fn boot_sysctls(&mut self) -> Result<()> {
        let names = [
            IfName::new("lo")?,
            IfName::new("wg0")?,
            IfName::new("ex-ch1")?,
        ];
        for value in desired_sysctls(&names, true) {
            if self
                .cmd("scupper", "sysctl", &["-n", &value.key.to_string()])?
                .trim()
                != value.value
            {
                return fail(format!("L18 sysctl differs: {}", value.key));
            }
        }
        self.rows.push(Row{name:"L18".into(),wanted:"explicit namespace hardening overrides inherited host values".into(),got:"verified".into(),detail:"all desired namespace sysctls read back; L18-pre-boot.json records the inheritance trial separately".into()});
        Ok(())
    }
    pub(super) fn supervised_boot_cases(&mut self, case: &str) -> Result<()> {
        let points: Vec<String> = match case {
            "L9" => kill_points(),
            "L9b" => kill_points()
                .into_iter()
                .filter(|point| {
                    at_or_after(point, BootStep::Inputs) && !at_or_after(point, BootStep::Record)
                })
                .collect(),
            "L9-host-link" => vec!["link-add-wg0".into(), "link-add-ex-ch1".into()],
            _ => return fail("unknown boot crash group"),
        };
        // The caller supplied one initial healthy recovery. Every prefix's
        // after-recovery is the next prefix's before-control.
        for cli in [true, false] {
            for point in &points {
                self.boot_kill(point, case == "L9b", cli)?;
            }
        }
        Ok(())
    }
    pub(super) fn boot_client_rx(&mut self) -> Result<u64> {
        self.cmd("scupper", "wg", &["show", "wg0", "transfer"])?
            .lines()
            .filter(|line| line.split_whitespace().next() == Some(self.public_keys[3].as_str()))
            .map(|line| {
                line.split_whitespace()
                    .nth(1)
                    .ok_or("missing wg0 rx")?
                    .parse::<u64>()
                    .map_err(|_| "invalid wg0 rx")
            })
            .try_fold(0_u64, |total, value| {
                total.checked_add(value?).ok_or("wg0 rx overflow")
            })
            .map_err(Into::into)
    }
    pub(super) fn boot_fresh_client_handshake(&mut self) -> Result<()> {
        let expected = self.public_keys[3].clone();
        let before = client_handshake(
            &self.cmd("scupper", "wg", &["show", "wg0", "latest-handshakes"])?,
            &expected,
        );
        if before != 0 {
            self.runner.dwell(Duration::from_millis(1100))?;
        }
        // Down/up discards the old client session even if the gateway survived.
        self.cmd("client", "ip", &["link", "set", "wg0", "down"])?;
        self.cmd("client", "ip", &["link", "set", "wg0", "up"])?;
        self.assert_transport_ports()?;
        for family in ["-4", "-6"] {
            self.cmd(
                "client",
                "ip",
                &[family, "route", "replace", "default", "dev", "wg0"],
            )?;
        }
        let until = Instant::now() + Duration::from_secs(10);
        loop {
            // A reply is unnecessary: the authenticated request triggers a handshake.
            self.runner.output(
                &Invocation::new("client", "ping", &["-c", "1", "-W", "1", A.gateway_inner]),
                None,
            )?;
            let after = client_handshake(
                &self.cmd("scupper", "wg", &["show", "wg0", "latest-handshakes"])?,
                &expected,
            );
            if after > before {
                return Ok(());
            }
            if Instant::now() >= until {
                return fail("L9 fresh client handshake deadline exceeded");
            }
            self.runner.dwell(Duration::from_millis(100))?;
        }
    }
    #[allow(clippy::too_many_lines)] // Each crash assertion stays next to the retry and capture it protects.
    fn boot_kill(&mut self, point: &str, live: bool, cli: bool) -> Result<()> {
        let stem = format!(
            "{}-{}-{point}",
            if live { "L9b" } else { "L9" },
            if cli { "cli" } else { "daemon" }
        );
        // Lab reboot simulation: only the lab-owned gateway namespace is removed.
        // Boot itself never deletes an existing namespace, including during retry.
        if live {
            // The previous retry is healthy, with forwarding and clients live.
            self.cmd(
                "scupper",
                "sysctl",
                &["-w", "net.ipv4.conf.all.rp_filter=2"],
            )?;
        } else {
            self.cmd("", "ip", &["netns", "delete", "scupper"])?;
        }
        let record = self.private.join("boot-root/run/scupper/boot.json");
        if record.exists() {
            fs::remove_file(record)?;
        }
        self.capture("wan", A.gwhost.wan_if, &stem)?;
        let marker = self.private.join("boot-root/run/scupper/boot-reached");
        if marker.exists() {
            fs::remove_file(&marker)?;
        }
        let status = if cli {
            self.reset_boot_budget(&stem)?;
            let args = if let Some(name) = point.strip_prefix("link-add-") {
                vec!["--stop-after-link-add", name]
            } else {
                vec!["--stop-after", point]
            };
            self.boot_output(&args, &stem)?.0
        } else {
            self.daemon_boot_crash(&stem, point)?
        };
        let reached = fs::read_to_string(&marker)?;
        fs::write(self.artifacts.join(format!("{stem}-reached.txt")), &reached)?;
        if reached != format!("reached {point}\n") {
            return fail("L9 crash checkpoint mismatch");
        }
        if status.signal() != Some(9) && status.code() != Some(137) {
            return fail(format!("L9 did not kill boot at {point}: {status}"));
        }
        let exists = fs::symlink_metadata("/run/netns/scupper").is_ok();
        let expected_exists =
            live || at_or_after(point, BootStep::Inputs) || point.starts_with("link-add-");
        if exists != expected_exists {
            return fail(format!(
                "L9 {point}: namespace exists={exists}, expected={expected_exists}"
            ));
        }
        if exists {
            let links = scupper_core::parse::parse_ip_link(&self.cmd(
                "scupper",
                "ip",
                &["-d", "-j", "link", "show"],
            )?)?;
            if links.iter().any(|l| {
                l.ifname != "lo"
                    && (!["wg0", "ex-ch1"].contains(&l.ifname.as_str())
                        || l.kind.as_deref() != Some("wireguard"))
            }) {
                return fail("L9 foreign link in namespace");
            }
            for key in ["net.ipv4.ip_forward", "net.ipv6.conf.all.forwarding"] {
                let forwarding = self.cmd("scupper", "sysctl", &["-n", key])?;
                if forwarding.trim() == "1"
                    && (!at_or_after(point, BootStep::Forwarding)
                        || canonicalize(&self.cmd(
                            "scupper",
                            "nft",
                            &["-j", "list", "ruleset"],
                        )?)? != self.expected_rules)
                {
                    return fail("L9 forwarding without same-run ruleset verification");
                }
            }
        }
        if let Some(name) = point.strip_prefix("link-add-") {
            let links = scupper_core::parse::parse_ip_link(&self.cmd(
                "gwhost",
                "ip",
                &["-d", "-j", "link", "show"],
            )?)?;
            let link = links
                .iter()
                .find(|l| l.ifname == name)
                .ok_or("L9 leftover missing")?;
            if link.flags.iter().any(|f| f == "UP")
                || link.kind.as_deref() != Some("wireguard")
                || link.xdp
                || !self
                    .cmd("gwhost", "wg", &["show", name, "peers"])?
                    .trim()
                    .is_empty()
            {
                return fail("L9 host leftover is not down and peerless");
            }
        }
        let client_ready =
            exists && (live || at_or_after(point, BootStep::Links) || point == "link-add-ex-ch1");
        let rx_before = if client_ready {
            self.boot_fresh_client_handshake()?;
            self.capture("scupper", "wg0", &format!("{stem}-wg0"))?;
            Some(self.boot_client_rx()?)
        } else {
            None
        };
        let mut markers = vec![];
        for protocol in ["udp", "tcp"] {
            let marker = Self::marker()?;
            markers.push(marker.clone());
            let exe = self.executable.clone();
            let (status, stdout) = self.runner.output(
                &Invocation::new(
                    "client",
                    &exe,
                    &[
                        "probe",
                        "--protocol",
                        protocol,
                        "--target",
                        A.internet.peer,
                        "--port",
                        "8080",
                        "--marker",
                        &marker,
                    ],
                ),
                None,
            )?;
            if status.code().is_none_or(|code| code != 0 && code != 1) {
                return fail("L9 canary launcher failed");
            }
            let attempt: super::helpers::Attempt = serde_json::from_str(&stdout)?;
            if attempt.marker != marker || attempt.destination.ip().to_string() != A.internet.peer {
                return fail("L9 canary did not attempt the literal sink");
            }
        }
        self.runner.dwell(Duration::from_secs(1))?;
        self.stop_captures()?;
        if let Some(before) = rx_before {
            let after = self.boot_client_rx()?;
            boot_canary_arrival(
                before,
                after,
                &fs::read(self.artifacts.join(format!("{stem}-wg0.pcap")))?,
                &markers,
            )?;
        }
        // The port is a transport property, read while the killed namespace still
        // exists. Prefixes before exit creation have no exit transport to allow.
        let exit_port = if exists {
            self.runner
                .output(
                    &Invocation::new("scupper", "wg", &["show", "ex-ch1", "listen-port"]),
                    None,
                )?
                .1
                .trim()
                .parse()
                .unwrap_or(51821)
        } else {
            51821
        };
        evidence::boot_prefix(
            &self.artifacts,
            &stem,
            &markers,
            exit_port,
            at_or_after(point, BootStep::Forwarding),
        )?;
        self.registry
            .register(Resource::Namespace("scupper".into()));
        let after_stem = format!("{stem}-after");
        self.capture("wan", A.gwhost.wan_if, &after_stem)?;
        let report = self.daemon_boot_recover(&stem)?;
        self.stop_captures()?;
        self.daemon_oracle(&after_stem, &[], self.exit_port, self.exit_port)?;
        self.rows.push(Row {
            name: stem,
            wanted: "SIGKILL prefix closed; retry healthy".into(),
            got: "passed".into(),
            detail: report,
        });
        evidence::save_results(&self.artifacts, &self.rows)?;
        Ok(())
    }
}

// Require authenticated ingress as well as a clean uplink: stale WireGuard
// sessions must not make the crash-prefix oracle pass without any client traffic.
pub(super) fn boot_canary_arrival(
    before: u64,
    after: u64,
    pcap: &[u8],
    markers: &[String],
) -> Result<()> {
    if after <= before {
        return fail("L9 gateway wg0 rx did not increase");
    }
    let packets = crate::pcap::observe(pcap)?;
    // A TCP SYN has no application marker while forwarding is closed; the UDP
    // canary carries one and is sufficient to prove plaintext reached wg0.
    let marker = markers.first().ok_or("L9 missing UDP canary marker")?;
    if !packets.iter().any(|p| {
        p.source.to_string() == A.client_inner
            && p.protocol == 17
            && p.payload.get(8..) == Some(marker.as_bytes())
    }) {
        return fail("L9 UDP canary absent from gateway wg0 capture");
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod restore_tests {
    use super::*;

    fn current_report() -> BootReport {
        BootReport {
            steps: BootStep::ALL
                .iter()
                .map(|step| scupper_sys::boot::StepResult {
                    step: *step,
                    error: None,
                    adopted: false,
                })
                .collect(),
            ..BootReport::default()
        }
    }

    fn check_lab_matches_product(report: &BootReport) {
        let stdout = serde_json::to_string(report).unwrap();
        assert_eq!(
            successful_report(std::process::ExitStatus::from_raw(0), &stdout).is_ok(),
            report.succeeded()
        );
        assert!(successful_report(std::process::ExitStatus::from_raw(256), &stdout).is_err());
    }

    #[test]
    fn boot_success_uses_product_semantics_for_current_legacy_and_invalid_reports() {
        let current = current_report();
        assert!(current.succeeded());
        let legacy: BootReport = serde_json::from_str(include_str!(
            "../../../crates/scupper-sys/tests/fixtures/boot-pre-modules.json"
        ))
        .unwrap();
        assert!(legacy.succeeded());
        assert!(verify_modules(&legacy).is_err());
        for report in [current, legacy] {
            check_lab_matches_product(&report);
            for index in 0..report.steps.len() {
                let mut failed = report.clone();
                failed.steps[index].error = Some("failed checkpoint".into());
                check_lab_matches_product(&failed);
                assert!(verify_modules(&failed).is_err());

                let mut missing = report.clone();
                missing.steps.remove(index);
                check_lab_matches_product(&missing);

                let mut duplicate = report.clone();
                duplicate.steps.insert(index, report.steps[index].clone());
                check_lab_matches_product(&duplicate);

                if index + 1 < report.steps.len() {
                    let mut reordered = report.clone();
                    reordered.steps.swap(index, index + 1);
                    check_lab_matches_product(&reordered);
                }
            }
        }
        check_lab_matches_product(&BootReport::default());
        for stdout in [
            "",
            "null",
            "{}",
            "{",
            r#"{"steps":[{"step":"Unknown","error":null}]}"#,
        ] {
            assert!(successful_report(std::process::ExitStatus::from_raw(0), stdout).is_err());
        }
    }

    #[test]
    fn checkpoint_order_uses_execution_order_instead_of_numeric_ids() {
        let module = (BootStep::Modules as u8).to_string();
        assert!(at_or_after(&module, BootStep::Lock));
        assert!(!at_or_after(&module, BootStep::Inputs));
        assert!(!at_or_after(&module, BootStep::Forwarding));
        assert!(at_or_after(
            &(BootStep::Record as u8).to_string(),
            BootStep::Forwarding
        ));
        assert!(!at_or_after("link-add-ex-0", BootStep::Links));
    }

    #[test]
    fn restore_continues_after_missing_interfaces_and_other_errors() {
        let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("sysctl-restore-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let forward = root.join("ip_forward");
        let bad = root.join("unreadable-value");
        let rp_filter = root.join("rp_filter");
        fs::write(&forward, "1").unwrap();
        fs::write(&rp_filter, "2").unwrap();
        fs::create_dir(&bad).unwrap();
        let mut guard = InheritanceGuard {
            saved: vec![
                (forward.clone(), "0".into()),
                (root.join("vanished-interface"), "0".into()),
                (bad.clone(), "0".into()),
                (rp_filter.clone(), "1".into()),
            ],
            snapshot: None,
        };
        let directory = root.join("scupper-lab-interrupted");
        fs::create_dir(&directory).unwrap();
        guard.persist(directory.join("host-sysctls.json")).unwrap();
        assert!(refuse_unrestored_sysctls(&root).is_err());
        assert!(
            guard
                .restore()
                .unwrap_err()
                .to_string()
                .contains("unreadable-value")
        );
        assert_eq!(fs::read_to_string(&forward).unwrap(), "0");
        assert_eq!(fs::read_to_string(&rp_filter).unwrap(), "1");
        assert!(directory.join("host-sysctls.json").exists());
        fs::remove_dir(&bad).unwrap();
        fs::write(&bad, "2").unwrap();
        guard.restore().unwrap();
        assert_eq!(fs::read_to_string(bad).unwrap(), "0");
        assert_eq!(guard.saved.len(), 0);
        refuse_unrestored_sysctls(&root).unwrap();
        guard.restore().unwrap();
        fs::remove_dir_all(root).unwrap();
    }
}
