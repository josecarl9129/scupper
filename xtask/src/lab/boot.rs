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
use scupper_sys::{
    lock::WriterLock,
    state::{Selection, StateFile},
};
use std::{
    fs,
    os::unix::process::ExitStatusExt,
    path::PathBuf,
    time::{Duration, Instant},
};

impl Lab {
    fn boot_binary() -> Result<PathBuf> {
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
    ) -> Result<(std::process::ExitStatus, serde_json::Value)> {
        let binary = Self::boot_binary()?;
        let root = self.private.join("boot-root");
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
        let report = serde_json::from_str(&stdout).unwrap_or(serde_json::Value::Null);
        Ok((status, report))
    }
    pub(super) fn boot_gateway(&mut self, extra: &[&str], stem: &str) -> Result<serde_json::Value> {
        let (status, report) = self.boot_output(extra, stem)?;
        if !status.success()
            || report["steps"]
                .as_array()
                .is_none_or(|steps| steps.len() != 8 || steps.iter().any(|s| !s["error"].is_null()))
        {
            return fail(format!("boot failed: {status}: {report}"));
        }
        self.exit_port = self
            .cmd("scupper", "wg", &["show", "ex-ch1", "listen-port"])?
            .trim()
            .parse()?;
        Ok(report)
    }
    pub(super) fn boot_adopt(&mut self) -> Result<()> {
        let report = self.boot_gateway(&[], "boot-adopt")?;
        if report["adopted"] != true {
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
                Some("Wg") if argv.first() == Some(&"show") => {}
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
        self.cmd(
            "gwhost",
            "sysctl",
            &[
                "-w",
                "net.ipv4.conf.all.rp_filter=2",
                "net.ipv4.conf.default.rp_filter=2",
                "net.ipv4.ip_forward=1",
                "net.ipv6.conf.all.accept_ra=1",
                "net.ipv6.conf.default.accept_ra=1",
            ],
        )?;
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
        self.rows.push(Row{name:"L18".into(),wanted:"explicit namespace hardening overrides inherited host values".into(),got:"verified".into(),detail:"gwhost rp_filter=2, forwarding=1, accept_ra=1 before real boot; all desired namespace sysctls read back".into()});
        Ok(())
    }
    pub(super) fn boot_cases(&mut self) -> Result<()> {
        self.runner.phase = Instant::now() + Duration::from_secs(450);
        self.boot_disconnected()?;
        for point in (0_u8..=7)
            .map(|n| n.to_string())
            .chain(["link-add-wg0".into(), "link-add-ex-ch1".into()])
        {
            self.boot_kill(&point)?;
        }
        Ok(())
    }
    fn boot_disconnected(&mut self) -> Result<()> {
        let root = self.private.join("boot-root");
        let writer = WriterLock::acquire(root.join("run/scupper"))?;
        let state = StateFile::open(root.join("var-lib/scupper"), Some(&writer))?;
        state.update(&writer, |s| s.selection = Selection::Disconnected)?;
        drop(writer);
        self.boot_gateway(&[], "L14-boot")?;
        for family in ["-4", "-6"] {
            let routes: serde_json::Value = serde_json::from_str(&self.cmd(
                "scupper",
                "ip",
                &["-j", family, "route", "show", "default"],
            )?)?;
            if !routes
                .as_array()
                .is_some_and(|r| r.len() == 1 && r[0]["type"] == "unreachable")
            {
                return fail(format!("L14 boot defaults: {routes}"));
            }
        }
        let (code, report) = self.check_result(&Self::boot_binary()?, &root)?;
        if code != 4 || report["verdict"]["FailClosed"] != "AdminDisconnected" {
            return fail(format!("L14 check: {code}: {report}"));
        }
        let writer = WriterLock::acquire(root.join("run/scupper"))?;
        state.update(&writer, |s| s.selection = Selection::Auto)?;
        drop(writer);
        self.boot_gateway(&[], "L14-restore")?;
        self.rows.push(Row {
            name: "L14-boot".into(),
            wanted: "two unreachable defaults; check 4 Disconnected".into(),
            got: "verified".into(),
            detail: report.to_string(),
        });
        Ok(())
    }
    #[allow(clippy::too_many_lines)] // Each crash assertion stays next to the retry and capture it protects.
    fn boot_kill(&mut self, point: &str) -> Result<()> {
        let stem = format!("L9-{point}");
        // Lab reboot simulation: only the lab-owned gateway namespace is removed.
        // Boot itself never deletes an existing namespace, including during retry.
        self.cmd("", "ip", &["netns", "delete", "scupper"])?;
        let record = self.private.join("boot-root/run/scupper/boot.json");
        if record.exists() {
            fs::remove_file(record)?;
        }
        self.capture("wan", A.gwhost.wan_if, &stem)?;
        let flags = if let Some(name) = point.strip_prefix("link-add-") {
            vec!["--stop-after-link-add", name]
        } else {
            vec!["--stop-after", point]
        };
        let (status, _) = self.boot_output(&flags, &stem)?;
        if status.signal() != Some(9) && status.code() != Some(137) {
            return fail(format!("L9 did not kill boot at {point}: {status}"));
        }
        let exists = fs::symlink_metadata("/run/netns/scupper").is_ok();
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
                    && (point != "6" && point != "7"
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
        evidence::boot_prefix(&self.artifacts, &stem, &markers, exit_port)?;
        self.boot_gateway(&[], &format!("{stem}-retry"))?;
        self.registry
            .register(Resource::Namespace("scupper".into()));
        self.wait_provider()?;
        // Rekey the client after the reboot simulation, so its stale session
        // does not delay the test until WireGuard's next retry timer.
        self.cmd("client", "ip", &["link", "set", "wg0", "down"])?;
        self.cmd("client", "ip", &["link", "set", "wg0", "up"])?;
        self.cmd(
            "client",
            "ip",
            &["route", "replace", "default", "dev", "wg0"],
        )?;
        self.cmd(
            "client",
            "ip",
            &["-6", "route", "replace", "default", "dev", "wg0"],
        )?;
        let root = self.private.join("boot-root");
        let (code, report) = self.check_result(&Self::boot_binary()?, &root)?;
        let skip = (code == 3
            && report["verdict"]["Degraded"]
                .get("ExitProbeFailed")
                .is_some())
        .then(|| "runner internet unavailable after all local stages passed".to_owned());
        if code != 0 && skip.is_none() {
            return fail(format!("L9 retry check {point}: {code}: {report}"));
        }
        self.service_check(&mut Vec::new())?;
        self.rows.push(Row {
            name: stem,
            wanted: "SIGKILL prefix closed; retry healthy".into(),
            got: if skip.is_some() {
                "local stages verified; external probe skipped".into()
            } else {
                "verified".into()
            },
            detail: skip.unwrap_or_else(|| report.to_string()),
        });
        evidence::save_results(&self.artifacts, &self.rows)?;
        Ok(())
    }
}
