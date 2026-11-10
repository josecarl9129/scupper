//! Supervised M2 packet-path, host fault, boot and spoofing trials.
use super::{A, DaemonGuard, Duration, Invocation, Lab, Path, Result, Signal, fail, fs};
use crate::pcap::path::{self, Flow};
use scupper_sys::state::{StateFile, StateRead};
use std::net::IpAddr;

mod exit_ip;
mod pmtu;

pub(super) fn is_m2(case: &str) -> bool {
    matches!(
        case,
        "L1" | "L2"
            | "L5"
            | "L8"
            | "L9"
            | "L9b"
            | "L9-host-link"
            | "L11"
            | "L12"
            | "L15"
            | "L18"
            | "L20"
            | "L17-rebuild"
    )
}
impl DaemonGuard<'_> {
    pub(super) fn run_m2(&mut self, case: &str) -> Result<String> {
        let root = self.lab.prepare_check_v2()?;
        if let StateRead::Present(state) =
            StateFile::open(root.join("var-lib/scupper"), None)?.read()?
        {
            self.baseline_version = state.applied_version;
        }
        self.supervised_fixture(&root)?;
        self.lab.boot_gateway(&[], &format!("{case}-boot"))?;
        let (child, notify) = self.lab.daemon_start(case, &root)?;
        self.child = Some(child);
        self.notify = Some(notify);
        self.lab
            .daemon_ready_tick(self.notify.as_ref().ok_or("missing notify")?)?;
        self.expect_check(&root, 0, "before")?;
        let stem = format!("daemon-{case}");
        let start_port = self.lab.exit_port;
        self.lab.capture("wan", A.gwhost.wan_if, &stem)?;
        let mut markers = Vec::new();
        self.lab.service_check(&mut markers)?;
        match case {
            "L1" => self.lab.service_check(&mut markers)?,
            "L2" => self.gateway_local(&stem)?,
            "L5" => self.host_routes(&root)?,
            "L8" => self.host_nft(&root, &mut markers)?,
            "L11" => self.isolation(&stem)?,
            "L12" => self.spoof(&root, &stem)?,
            "L15" => self.exit_ip_target(&root)?,
            "L9" | "L9b" | "L9-host-link" => {
                // The daemon executes boot itself. Its testing checkpoint kills
                // the owning process, exactly as a crashed supervisor would.
                self.control_stop(Signal::TERM)?;
                self.lab.stop_captures()?;
                self.lab
                    .daemon_oracle(&stem, &markers, start_port, start_port)?;
                self.lab.supervised_boot_cases(case)?;
                self.control_restart(&root, "after-crashes")?;
                self.lab
                    .capture("wan", A.gwhost.wan_if, &format!("{stem}-after"))?;
                markers.clear();
                self.lab.service_check(&mut markers)?;
            }
            "L18" | "L17-rebuild" => self.rebuild(&root, case)?,
            "L20" => self.pmtu_trial(&root, &stem)?,
            _ => return fail("unknown M2 case"),
        }
        self.lab.daemon_route_healthy(Duration::from_secs(30))?;
        self.lab.service_check(&mut markers)?;
        self.expect_check(&root, 0, "after")?;
        self.lab.stop_captures()?;
        self.lab.exit_port = self
            .lab
            .cmd("scupper", "wg", &["show", "ex-ch1", "listen-port"])?
            .trim()
            .parse()?;
        if matches!(case, "L9" | "L9b" | "L9-host-link") {
            self.lab.daemon_oracle(
                &format!("{stem}-after"),
                &markers,
                self.lab.exit_port,
                self.lab.exit_port,
            )?;
        } else {
            self.lab
                .daemon_oracle(&stem, &markers, start_port, self.lab.exit_port)?;
        }
        self.lab.daemon_capture_control(&stem)?;
        Ok("supervised check=0 before/after; provider-NAT controls; strict uplink oracle; path captures and diagnostics saved".into())
    }
    fn ping(&mut self, ns: &str, target: &str, delivered: bool) -> Result<()> {
        let (status, output) = self.lab.runner.output(
            &Invocation::new(ns, "ping", &["-n", "-c", "2", "-W", "1", target]),
            None,
        )?;
        if status.code() != Some(i32::from(!delivered)) {
            return fail(format!("{ns} ping {target}: {status}: {output}"));
        }
        Ok(())
    }
    fn query(&mut self, ns: &str, target: &str, port: u16, protocol: &str) -> Result<Flow> {
        let marker = Lab::marker()?;
        let source_port = self.lab.next_source_port;
        self.lab.next_source_port += 1;
        let exe = self.lab.executable.clone();
        let (status, output) = self.lab.runner.output(
            &Invocation::new(
                ns,
                &exe,
                &[
                    "probe",
                    "--protocol",
                    protocol,
                    "--target",
                    target,
                    "--port",
                    &port.to_string(),
                    "--source-port",
                    &source_port.to_string(),
                    "--marker",
                    &marker,
                ],
            ),
            None,
        )?;
        let attempt: crate::lab::helpers::Attempt = serde_json::from_str(&output)?;
        if status.code() != Some(1) || attempt.outcome != crate::lab::helpers::Outcome::TimedOut {
            return fail(format!(
                "isolation query did not time out: {status}: {output}"
            ));
        }
        Ok(Flow {
            source: if ns == "client2" {
                "10.99.0.3"
            } else if ns == "provA" {
                A.provider_inner
            } else {
                A.client_inner
            }
            .parse()?,
            destination: target.parse()?,
            protocol: if protocol == "tcp" { 6 } else { 17 },
            ports: Some((source_port, port)),
        })
    }
    fn gateway_local(&mut self, stem: &str) -> Result<()> {
        self.lab.capture("scupper", "wg0", &format!("{stem}-wg0"))?;
        self.lab
            .capture("scupper", "ex-ch1", &format!("{stem}-exit"))?;
        self.ping("client", A.gateway_inner, true)?;
        self.query("client", A.gateway_inner, 53, "dns")?;
        for port in [53, 7380] {
            for protocol in ["tcp", "udp"] {
                self.query("client", A.gateway_inner, port, protocol)?;
            }
        }
        self.lab.service_check(&mut Vec::new())?;
        self.lab.stop_capture()?;
        self.lab.stop_capture()?;
        path::gateway(
            &fs::read(self.lab.artifacts.join(format!("{stem}-wg0.pcap")))?,
            &fs::read(self.lab.artifacts.join(format!("{stem}-exit.pcap")))?,
            A.gateway_inner.parse()?,
            A.client_inner.parse()?,
        )?;
        Ok(())
    }
    fn host_routes(&mut self, root: &Path) -> Result<()> {
        self.lab.cmd(
            "gwhost",
            "ip",
            &[
                "rule",
                "add",
                "pref",
                "100",
                "from",
                "198.18.5.0/24",
                "lookup",
                "100",
            ],
        )?;
        self.lab.cmd(
            "gwhost",
            "ip",
            &["route", "add", "198.18.5.0/24", "via", A.gwhost.wan],
        )?;
        for family in ["-4", "-6"] {
            self.lab.cmd("gwhost", "ip", &[family, "rule", "flush"])?;
            for (pref, table) in [("0", "local"), ("32766", "main"), ("32767", "default")] {
                let rules: serde_json::Value = serde_json::from_str(&self.lab.cmd(
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
                    self.lab.cmd(
                        "gwhost",
                        "ip",
                        &[family, "rule", "add", "pref", pref, "lookup", table],
                    )?;
                }
            }
            // Preserve kernel connected routes and the host default: losing
            // endpoint reachability is L46, not a containment fault.
            let routes: serde_json::Value = serde_json::from_str(&self.lab.cmd(
                "gwhost",
                "ip",
                &[family, "-j", "route", "show", "table", "main"],
            )?)?;
            for route in routes.as_array().ok_or("host routes")? {
                if let Some(dst) = route["dst"].as_str()
                    && dst != "default"
                    && route["protocol"] != "kernel"
                {
                    self.lab
                        .cmd("gwhost", "ip", &[family, "route", "del", dst])?;
                }
            }
        }
        // No networkd runs in the disposable host namespace. Never address the
        // runner's system bus, which belongs to the real host network stack.
        fs::write(
            self.lab.artifacts.join("L5-networkd.txt"),
            "gwhost has no networkd/systemd instance; restart inapplicable\n",
        )?;
        let observed = serde_json::json!({
            "rules4":self.lab.cmd("gwhost","ip",&["-4","-j","rule","show"])?,
            "rules6":self.lab.cmd("gwhost","ip",&["-6","-j","rule","show"])?,
            "routes4":self.lab.cmd("gwhost","ip",&["-4","-j","route","show","table","all"])?,
            "routes6":self.lab.cmd("gwhost","ip",&["-6","-j","route","show","table","all"])?,
        });
        fs::write(
            self.lab.artifacts.join("L5-host-network.json"),
            serde_json::to_vec_pretty(&observed)?,
        )?;
        self.expect_check(root, 0, "host-rules-flushed")
    }
    fn host_nft(&mut self, root: &Path, markers: &mut Vec<String>) -> Result<()> {
        self.lab.cmd("gwhost", "nft", &["flush", "ruleset"])?;
        self.lab
            .cmd("gwhost", "sysctl", &["-w", "net.ipv4.ip_forward=1"])?;
        let rules = format!(
            "table ip m2_host {{ chain forward {{ type filter hook forward priority filter; policy accept; dup to {} device eth0;\n\t}}\n}}\n",
            A.gwhost.wan
        );
        self.lab.runner.input(
            &Invocation::new("gwhost", "nft", &["-f", "-"]),
            Some(rules.as_bytes()),
        )?;
        fs::write(
            self.lab.artifacts.join("L8-host-ruleset.json"),
            self.lab.cmd("gwhost", "nft", &["-j", "list", "ruleset"])?,
        )?;
        self.lab.service_check(markers)?;
        self.expect_check(root, 0, "host-dup-installed")?;
        self.lab
            .cmd("gwhost", "nft", &["delete", "table", "ip", "m2_host"])?;
        Ok(())
    }
    #[allow(clippy::too_many_lines)] // Live controls and each protected path belong to the same measurement.
    fn isolation(&mut self, stem: &str) -> Result<()> {
        // Live listeners behind the drop policy distinguish filtering from an
        // unbound port. Their process guards release them on every error path.
        let exe = self.lab.executable.clone();
        let log = self.lab.artifacts.join("L11-listeners.jsonl");
        let mut listeners = Vec::new();
        for (protocol, port) in [
            ("tcp", 53),
            ("udp", 53),
            ("tcp", 7380),
            ("udp", 7380),
            ("tcp", 8080),
            ("udp", 8080),
        ] {
            listeners.push(
                self.lab.runner.background(
                    &Invocation::new(
                        "scupper",
                        &exe,
                        &[
                            "sink",
                            "--protocol",
                            protocol,
                            "--bind",
                            &format!("0.0.0.0:{port}"),
                            "--log",
                            log.to_str().ok_or("log")?,
                        ],
                    ),
                    &self
                        .lab
                        .artifacts
                        .join(format!("L11-{protocol}-{port}.stdout")),
                )?,
            );
        }
        self.lab
            .daemon_wait("L11 live listeners", Duration::from_secs(5), |lab| {
                let tcp = lab.cmd("scupper", "ss", &["-ltnH"])?;
                let udp = lab.cmd("scupper", "ss", &["-lunH"])?;
                Ok([53, 7380, 8080]
                    .iter()
                    .all(|p| tcp.contains(&format!(":{p} ")) && udp.contains(&format!(":{p} "))))
            })?;
        // Loopback is an allowed input path and proves the listeners respond.
        for protocol in ["tcp", "udp"] {
            let (status, _) = self.lab.runner.output(
                &Invocation::new(
                    "scupper",
                    &exe,
                    &[
                        "probe",
                        "--protocol",
                        protocol,
                        "--target",
                        "127.0.0.1",
                        "--port",
                        "8080",
                        "--marker",
                        &Lab::marker()?,
                    ],
                ),
                None,
            )?;
            if !status.success() {
                return fail("L11 listener positive control failed");
            }
        }
        for (ns, iface, suffix) in [
            ("client2", "wg0", "sender"),
            ("client", "wg0", "destination"),
            ("scupper", "wg0", "wg0"),
            ("scupper", "ex-ch1", "exit"),
        ] {
            self.lab.capture(ns, iface, &format!("{stem}-{suffix}"))?;
        }
        self.ping("client2", A.gateway_inner, true)?;
        self.ping("client2", A.client_inner, false)?;
        let mut client_queries = Vec::new();
        let mut provider_queries = Vec::new();
        for port in [22, 53, 7380, 8080] {
            for protocol in ["tcp", "udp"] {
                client_queries.push(self.query("client2", A.gateway_inner, port, protocol)?);
                provider_queries.push(self.query("provA", A.exit_inner, port, protocol)?);
            }
        }
        // Provider echo is also new input and must be dropped.
        self.ping("provA", A.exit_inner, false)?;
        self.lab.service_check(&mut Vec::new())?;
        for _ in 0..4 {
            self.lab.stop_capture()?;
        }
        path::dropped(
            &fs::read(self.lab.artifacts.join(format!("{stem}-sender.pcap")))?,
            &fs::read(self.lab.artifacts.join(format!("{stem}-destination.pcap")))?,
            &[Flow {
                source: "10.99.0.3".parse()?,
                destination: A.client_inner.parse()?,
                protocol: 1,
                ports: None,
            }],
        )?;
        fs::write(
            self.lab
                .artifacts
                .join(format!("{stem}-scan-manifest.json")),
            serde_json::to_vec_pretty(
                &serde_json::json!({"client":client_queries,"provider":provider_queries}),
            )?,
        )?;
        path::attempted(
            &fs::read(self.lab.artifacts.join(format!("{stem}-wg0.pcap")))?,
            &client_queries,
        )?;
        path::attempted(
            &fs::read(self.lab.artifacts.join(format!("{stem}-exit.pcap")))?,
            &provider_queries,
        )?;
        // Only loopback controls may reach the actual listening sockets.
        let receipts = crate::lab::helpers::receipts(&fs::read_to_string(log)?)?;
        if receipts.iter().any(|r| !r.peer.ip().is_loopback()) {
            return fail("L11 forbidden gateway service delivered");
        }
        for listener in &mut listeners {
            listener.alive()?;
            listener.stop(Signal::TERM)?;
        }
        Ok(())
    }
    #[allow(clippy::too_many_lines)] // Preserve the two source-validation layers and their trace ordering.
    fn spoof(&mut self, root: &Path, stem: &str) -> Result<()> {
        let forged: IpAddr = "198.18.12.2".parse()?;
        self.lab
            .capture("client", "wg0", &format!("{stem}-sender"))?;
        self.lab
            .capture("scupper", "wg0", &format!("{stem}-wg-filter"))?;
        self.lab
            .capture("scupper", "ex-ch1", &format!("{stem}-wg-exit"))?;
        self.raw_udp(
            "client",
            "wg0",
            (forged, A.internet.peer.parse()?),
            (40012, 8080),
            64,
        )?;
        self.lab.service_check(&mut Vec::new())?;
        self.lab.stop_capture()?;
        self.lab.stop_capture()?;
        self.lab.stop_capture()?;
        let flow = Flow {
            source: forged,
            destination: A.internet.peer.parse()?,
            protocol: 17,
            ports: Some((40012, 8080)),
        };
        path::dropped(
            &fs::read(self.lab.artifacts.join(format!("{stem}-sender.pcap")))?,
            &fs::read(self.lab.artifacts.join(format!("{stem}-wg-filter.pcap")))?,
            std::slice::from_ref(&flow),
        )?;
        self.child.as_mut().ok_or("daemon")?.signal(Signal::STOP);
        self.lab.cmd(
            "scupper",
            "wg",
            &[
                "set",
                "wg0",
                "peer",
                &self.lab.public_keys[3].clone(),
                "allowed-ips",
                &format!("{}/32,{forged}/32", A.client_inner),
            ],
        )?;
        self.expect_check(root, 2, "widened-allowed-ips")?;
        let report = fs::read_to_string(self.lab.artifacts.join("L12-widened-allowed-ips.json"))?;
        if !report.contains("PeerDiffers") {
            return fail("L12 check 2 did not identify peer drift");
        }
        self.lab.runner.input(&Invocation::new("scupper","nft",&["-f","-"]),Some(b"table inet m2_trace { chain pre { type filter hook prerouting priority -301; ip saddr 198.18.12.2 meta nftrace set 1;\n\t}\n}\n"))?;
        let trace_path = self.lab.artifacts.join("L12-antispoof.trace");
        let mut trace = self.lab.runner.background(
            &Invocation::new("scupper", "stdbuf", &["-oL", "nft", "monitor", "trace"]),
            &trace_path,
        )?;
        self.lab
            .capture("scupper", "wg0", &format!("{stem}-antispoof-ingress"))?;
        self.lab
            .capture("scupper", "ex-ch1", &format!("{stem}-antispoof-exit"))?;
        self.raw_udp(
            "client",
            "wg0",
            (forged, A.internet.peer.parse()?),
            (40012, 8080),
            64,
        )?;
        self.lab.service_check(&mut Vec::new())?;
        self.lab.runner.dwell(Duration::from_millis(300))?;
        trace.alive()?;
        trace.stop(Signal::TERM)?;
        self.lab.stop_capture()?;
        self.lab.stop_capture()?;
        path::dropped(
            &fs::read(
                self.lab
                    .artifacts
                    .join(format!("{stem}-antispoof-ingress.pcap")),
            )?,
            &fs::read(
                self.lab
                    .artifacts
                    .join(format!("{stem}-antispoof-exit.pcap")),
            )?,
            &[flow],
        )?;
        let text = fs::read_to_string(trace_path)?;
        let ids: Vec<_> = text
            .lines()
            .filter(|l| l.contains("ip saddr 198.18.12.2 "))
            .filter_map(|l| l.split_whitespace().nth(2))
            .collect();
        if !ids.iter().any(|id| {
            text.lines().any(|l| {
                l.split_whitespace().nth(2) == Some(*id)
                    && l.contains(" inet scupper antispoof ")
                    && l.contains("(verdict drop)")
            })
        }) {
            return fail("L12 antispoof drop trace missing");
        }
        self.lab
            .cmd("scupper", "nft", &["delete", "table", "inet", "m2_trace"])?;
        self.lab.cmd(
            "scupper",
            "wg",
            &[
                "set",
                "wg0",
                "peer",
                &self.lab.public_keys[3].clone(),
                "allowed-ips",
                &format!("{}/32", A.client_inner),
            ],
        )?;
        self.child.as_mut().ok_or("daemon")?.signal(Signal::CONT);
        self.lab.daemon_complete_tick(root)
    }
    fn rebuild(&mut self, root: &Path, case: &str) -> Result<()> {
        let before = self
            .lab
            .cmd("", "stat", &["-Lc", "%i", "/run/netns/scupper"])?;
        self.control_stop(Signal::TERM)?;
        if case == "L18" {
            self.lab.boot_inheritance()?;
        }
        self.lab.cmd("", "ip", &["netns", "delete", "scupper"])?;
        self.control_restart(root, "rebuild")?;
        self.lab.daemon_complete_tick(root)?;
        let after = self
            .lab
            .cmd("", "stat", &["-Lc", "%i", "/run/netns/scupper"])?;
        fs::write(
            self.lab.artifacts.join(format!("{case}-inodes.json")),
            serde_json::to_vec_pretty(
                &serde_json::json!({"before":before.trim(),"after":after.trim()}),
            )?,
        )?;
        if before == after {
            return fail("no-holder rebuild retained old namespace inode");
        }
        self.lab.wait_provider()?;
        self.lab.boot_sysctls()?;
        if case == "L18" {
            self.lab
                .daemon_sysctl_fixture(self.child.as_mut().ok_or("daemon")?)?;
        }
        Ok(())
    }
}
