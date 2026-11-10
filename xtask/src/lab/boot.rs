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
use std::{
    fs,
    os::unix::process::ExitStatusExt,
    path::PathBuf,
    time::{Duration, Instant},
};

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
    pub(super) fn supervised_boot_cases(&mut self, case: &str) -> Result<()> {
        let points: Vec<String> = match case {
            "L9" => (0_u8..=7).map(|n| n.to_string()).collect(),
            "L9b" => (1_u8..=6).map(|n| n.to_string()).collect(),
            "L9-host-link" => vec!["link-add-wg0".into(), "link-add-ex-ch1".into()],
            _ => return fail("unknown boot crash group"),
        };
        for point in points {
            self.boot_kill(&point, case == "L9b")?;
        }
        Ok(())
    }
    fn boot_client_rx(&mut self) -> Result<u64> {
        self.cmd("scupper", "wg", &["show", "wg0", "transfer"])?
            .lines()
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
        let latest = |text: &str| {
            text.lines()
                .filter_map(|l| l.split_whitespace().nth(1)?.parse::<u64>().ok())
                .max()
                .unwrap_or(0)
        };
        let before = latest(&self.cmd("scupper", "wg", &["show", "wg0", "latest-handshakes"])?);
        if before != 0 {
            self.runner.dwell(Duration::from_millis(1100))?;
        }
        // Down/up discards the old client session even if the gateway survived.
        self.cmd("client", "ip", &["link", "set", "wg0", "down"])?;
        self.cmd("client", "ip", &["link", "set", "wg0", "up"])?;
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
            let after =
                latest(&self.cmd("scupper", "wg", &["show", "wg0", "latest-handshakes"])?);
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
    fn boot_kill(&mut self, point: &str, live: bool) -> Result<()> {
        let stem = format!("{}-{point}", if live { "L9b" } else { "L9" });
        let before_stem = format!("{stem}-before");
        self.capture("wan", A.gwhost.wan_if, &before_stem)?;
        self.daemon_boot_recover(&before_stem)?;
        self.stop_captures()?;
        self.daemon_oracle(&before_stem, &[], self.exit_port, self.exit_port)?;
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
        let status = self.daemon_boot_crash(&stem, point)?;
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
            exists && (live || matches!(point, "4" | "5" | "6" | "7" | "link-add-ex-ch1"));
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
            matches!(point, "6" | "7"),
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
