//! Supervised M2 packet-path, host fault, boot and spoofing trials.
use super::{A, DaemonGuard, Duration, Invocation, Lab, Path, Result, Signal, fail, fs};
use crate::pcap::path::{self, Flow};
use scupper_sys::state::{StateFile, StateRead};
use std::{fmt::Write as _, net::IpAddr};

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
fn capture_control(source: &str, destination: &str, protocol: u8) -> Result<Flow> {
    Ok(Flow {
        source: source.parse()?,
        destination: destination.parse()?,
        protocol,
        ports: None,
    })
}

fn wg_rx_errors(text: &str) -> Result<u64> {
    let links: serde_json::Value = serde_json::from_str(text)?;
    links[0]["stats64"]["rx"]["errors"]
        .as_u64()
        .or_else(|| links[0]["stats"]["rx"]["errors"].as_u64())
        .ok_or_else(|| "wg0 rx error counter missing".into())
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
        self.expect_check(&root, 0, None, "before")?;
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
                // Both real CLI boot and daemon boot crash at each checkpoint;
                // a fresh supervised retry must recover every closed prefix.
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
        self.expect_check(&root, 0, None, "after")?;
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
        Ok(format!(
            "supervised check=0 before/after; provider-NAT controls; strict uplink oracle; {}",
            if case == "L20" {
                "IPv4 supervised; IPv6 renderer chain property, unsupervised"
            } else {
                "path captures and diagnostics saved"
            }
        ))
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
        self.lab.fault_markers.push(marker.clone());
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
        let mut queries = vec![self.query("client", A.gateway_inner, 53, "dns")?];
        for port in [53, 7380] {
            for protocol in ["tcp", "udp"] {
                queries.push(self.query("client", A.gateway_inner, port, protocol)?);
            }
        }
        self.lab.service_check(&mut Vec::new())?;
        self.lab.stop_capture()?;
        self.lab.stop_capture()?;
        path::attempted(
            &fs::read(self.lab.artifacts.join(format!("{stem}-wg0.pcap")))?,
            &queries,
        )?;
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
            for &(pref, table) in super::host_rule_defaults(family) {
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
        let rules: serde_json::Value =
            serde_json::from_str(observed["rules4"].as_str().ok_or("L5 rule readback")?)?;
        if rules
            .as_array()
            .is_none_or(|rules| rules.iter().any(|r| r["priority"] == 100))
            || observed["routes4"]
                .as_str()
                .is_none_or(|v| v.contains("198.18.5.0/24"))
        {
            return fail("L5 flush left injected rule or route");
        }
        self.expect_check(root, 0, None, "host-rules-flushed")
    }
    #[allow(clippy::too_many_lines)] // Host hooks, readback and positive counters describe one fault.
    fn host_nft(&mut self, root: &Path, markers: &mut Vec<String>) -> Result<()> {
        // A sentinel proves that flush removed a real table.
        self.lab
            .cmd("gwhost", "nft", &["add", "table", "ip", "m2_flush_control"])?;
        if !self
            .lab
            .cmd("gwhost", "nft", &["list", "tables"])?
            .contains("m2_flush_control")
        {
            return fail("L8 sentinel missing before flush");
        }
        self.lab.cmd("gwhost", "nft", &["flush", "ruleset"])?;
        if self
            .lab
            .cmd("gwhost", "nft", &["list", "tables"])?
            .contains("m2_flush_control")
        {
            return fail("L8 flush did not remove sentinel");
        }
        self.lab
            .cmd("gwhost", "sysctl", &["-w", "net.ipv4.ip_forward=1"])?;
        let mut rules = String::new();
        for family in ["ip", "inet"] {
            writeln!(rules, "table {family} m2_host {{")?;
            for hook in ["prerouting", "input", "forward", "output", "postrouting"] {
                write!(
                    rules,
                    "chain {hook} {{ type filter hook {hook} priority filter; policy accept; udp sport {{ 51820, {} }} udp dport {{ 51820, {} }} counter; ",
                    self.lab.exit_port, self.lab.exit_port
                )?;
                // Inbound copies would loop through the router. inet supports
                // the counters/accept policy; dup is family-specific.
                if family == "ip" && matches!(hook, "forward" | "output" | "postrouting") {
                    write!(rules, "counter dup to {} device eth0; ", A.gwhost.wan)?;
                }
                rules.push_str("\n}\n");
            }
            rules.push_str("}\n");
        }
        rules.push_str("table ip m2_nat { chain post { type nat hook postrouting priority srcnat; ip saddr { 10.99.0.0/24, 10.2.0.0/24 } masquerade;\n}\n}\n");
        fs::write(self.lab.artifacts.join("L8-host-ruleset.nft"), &rules)?;
        self.lab.runner.input(
            &Invocation::new("gwhost", "nft", &["-c", "-f", "-"]),
            Some(rules.as_bytes()),
        )?;
        self.lab.runner.input(
            &Invocation::new("gwhost", "nft", &["-f", "-"]),
            Some(rules.as_bytes()),
        )?;
        if self
            .lab
            .cmd("gwhost", "sysctl", &["-n", "net.ipv4.ip_forward"])?
            .trim()
            != "1"
        {
            return fail("L8 host forwarding fault absent");
        }
        self.lab.service_check(markers)?;
        let observed: serde_json::Value =
            serde_json::from_str(&self.lab.cmd("gwhost", "nft", &["-j", "list", "ruleset"])?)?;
        fs::write(
            self.lab.artifacts.join("L8-host-ruleset.json"),
            serde_json::to_vec_pretty(&observed)?,
        )?;
        for family in ["ip", "inet"] {
            for hook in ["prerouting", "input", "output", "postrouting"] {
                let live = observed["nftables"]
                    .as_array()
                    .ok_or("L8 rules")?
                    .iter()
                    .any(|entry| {
                        let rule = &entry["rule"];
                        rule["family"] == family
                            && rule["table"] == "m2_host"
                            && rule["chain"] == hook
                            && rule["expr"].as_array().is_some_and(|expr| {
                                expr.iter()
                                    .any(|e| e["match"]["left"]["payload"]["protocol"] == "udp")
                                    && expr.iter().any(|e| {
                                        e["counter"]["packets"].as_u64().is_some_and(|n| n > 0)
                                    })
                            })
                    });
                if !live {
                    return fail(format!("L8 hostile {family}/{hook} counter stayed zero"));
                }
            }
        }
        self.expect_check(root, 0, None, "host-dup-installed")?;
        for (family, table) in [("ip", "m2_host"), ("inet", "m2_host"), ("ip", "m2_nat")] {
            self.lab
                .cmd("gwhost", "nft", &["delete", "table", family, table])?;
        }
        Ok(())
    }
    #[allow(clippy::too_many_lines)] // Live controls and each protected path belong to the same measurement.
    fn isolation(&mut self, stem: &str) -> Result<()> {
        let transfers_before = self
            .lab
            .cmd("scupper", "wg", &["show", "wg0", "transfer"])?;
        self.lab.cmd(
            "provA",
            "wg",
            &[
                "set",
                "wgp",
                "peer",
                &self.lab.public_keys[1].clone(),
                "allowed-ips",
                "10.2.0.2/32,10.99.0.0/24",
            ],
        )?;
        self.lab.cmd(
            "provA",
            "ip",
            &["route", "add", "10.99.0.0/24", "dev", "wgp"],
        )?;
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
        let mut to_client = Vec::new();
        let mut to_client2 = Vec::new();
        for port in [22, 53, 7380, 8080] {
            for protocol in ["tcp", "udp"] {
                client_queries.push(self.query("client2", A.gateway_inner, port, protocol)?);
                for target in [A.exit_inner, A.gateway_inner, A.client_inner] {
                    provider_queries.push(self.query("provA", target, port, protocol)?);
                }
                to_client.push(self.query("client2", A.client_inner, port, protocol)?);
                to_client2.push(self.query("client", "10.99.0.3", port, protocol)?);
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
            &[capture_control(A.client_inner, A.internet.peer, 6)?],
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
        let wg_capture = fs::read(self.lab.artifacts.join(format!("{stem}-wg0.pcap")))?;
        let destination = fs::read(self.lab.artifacts.join(format!("{stem}-destination.pcap")))?;
        let client2_capture = fs::read(self.lab.artifacts.join(format!("{stem}-sender.pcap")))?;
        path::dropped(
            &wg_capture,
            &destination,
            &to_client,
            &[capture_control(A.client_inner, A.internet.peer, 6)?],
        )?;
        path::dropped(
            &wg_capture,
            &client2_capture,
            &to_client2,
            &[capture_control("10.99.0.3", A.gateway_inner, 1)?],
        )?;
        let exit_capture = fs::read(self.lab.artifacts.join(format!("{stem}-exit.pcap")))?;
        path::dropped(
            &exit_capture,
            &destination,
            &provider_queries,
            &[capture_control(A.client_inner, A.internet.peer, 6)?],
        )?;
        let transfers_after = self
            .lab
            .cmd("scupper", "wg", &["show", "wg0", "transfer"])?;
        for key in [&self.lab.public_keys[3], &self.lab.public_keys[4]] {
            let counters = |text: &str| -> Result<(u64, u64)> {
                let line = text
                    .lines()
                    .find(|l| l.split_whitespace().next() == Some(key.as_str()))
                    .ok_or("L11 missing client transfer")?;
                let mut fields = line.split_whitespace().skip(1);
                Ok((
                    fields.next().ok_or("rx")?.parse()?,
                    fields.next().ok_or("tx")?.parse()?,
                ))
            };
            let (rx, tx) = counters(&transfers_before)?;
            let (after_rx, after_tx) = counters(&transfers_after)?;
            if after_rx <= rx || after_tx <= tx {
                return fail("L11 client transfer control did not grow in both directions");
            }
        }
        fs::write(
            self.lab.artifacts.join("L11-transfers.json"),
            serde_json::to_vec_pretty(
                &serde_json::json!({"before":transfers_before,"after":transfers_after}),
            )?,
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
    fn wg_rx_errors(&mut self) -> Result<u64> {
        wg_rx_errors(
            &self
                .lab
                .cmd("scupper", "ip", &["-s", "-j", "link", "show", "wg0"])?,
        )
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
        self.lab
            .capture("gwhost", "eth0", &format!("{stem}-cipher-ingress"))?;
        let rx_before = self.wg_rx_errors()?;
        let forged_length = self.raw_udp(
            "client",
            "wg0",
            (forged, A.internet.peer.parse()?),
            (40012, 8080),
            64,
        )?;
        let mut rx_after = rx_before;
        let rejected = self.lab.daemon_wait(
            "L12 WireGuard source rejection",
            Duration::from_secs(3),
            |lab| {
                rx_after = wg_rx_errors(&lab.cmd(
                    "scupper",
                    "ip",
                    &["-s", "-j", "link", "show", "wg0"],
                )?)?;
                Ok(rx_after > rx_before)
            },
        );
        fs::write(
            self.lab.artifacts.join("L12-wireguard-rx.json"),
            serde_json::to_vec_pretty(
                &serde_json::json!({"rx_errors_before":rx_before,"rx_errors_after":rx_after}),
            )?,
        )?;
        rejected?;
        // Independent capture liveness control, after measuring source rejection.
        self.ping("client", A.gateway_inner, true)?;
        self.lab.stop_capture()?;
        self.lab.stop_capture()?;
        self.lab.stop_capture()?;
        self.lab.stop_capture()?;
        let ciphertext = crate::pcap::observe(&fs::read(
            self.lab
                .artifacts
                .join(format!("{stem}-cipher-ingress.pcap")),
        )?)?;
        let encrypted_size = 8 + 16 + forged_length.div_ceil(16) * 16 + 16;
        if !ciphertext.iter().any(|p| {
            p.source.to_string() == A.client.peer
                && p.destination.to_string() == A.gwhost.peer
                && p.protocol == 17
                && p.payload.len() == encrypted_size
                && p.payload.get(8..12) == Some(&[4, 0, 0, 0])
        }) {
            return fail("L12 gateway did not capture the forged-size WireGuard data message");
        }
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
            &[capture_control(A.client_inner, A.gateway_inner, 1)?],
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
        self.expect_check(
            root,
            2,
            Some(("Unprotected", "PeerDiffers")),
            "widened-allowed-ips",
        )?;
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
            &[capture_control(A.exit_inner, A.internet.peer, 6)?],
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
    #[allow(clippy::too_many_lines)] // Keep daemon-down loss, gap evidence and recovery adjacent.
    fn rebuild(&mut self, root: &Path, case: &str) -> Result<()> {
        let marker = Lab::marker()?;
        self.lab.fault_markers.push(marker.clone());
        let mut canary = self.lab.daemon_flow("udp", "client", &marker, case, 120)?;
        let flow = self.lab.artifacts.join(format!("{case}-udp.jsonl"));
        self.lab.daemon_wait(
            "rebuild traffic live before loss",
            Duration::from_secs(5),
            |_| Ok(super::flow_counts(&flow)?.1 > 0),
        )?;
        let before = self
            .lab
            .cmd("scupper", "readlink", &["/proc/self/ns/net"])?;
        self.control_stop(Signal::TERM)?;
        self.lab.cmd(
            "scupper",
            "ip",
            &["link", "set", "lo", "alias", "scupper-old-generation"],
        )?;
        if case == "L18" {
            self.lab.boot_inheritance()?;
        }
        self.lab.cmd("", "ip", &["netns", "delete", "scupper"])?;
        if std::path::Path::new("/run/netns/scupper").exists() {
            return fail("namespace deletion fault did not take effect");
        }
        let sent = super::flow_counts(&flow)?.0;
        self.lab.daemon_wait(
            "canary sends during namespace gap",
            Duration::from_secs(3),
            |_| Ok(super::flow_counts(&flow)?.0 > sent),
        )?;
        fs::write(
            self.lab.artifacts.join(format!("{case}-gap.json")),
            serde_json::to_vec_pretty(
                &serde_json::json!({"namespace_missing":true,"sent_before":sent,"sent_during_gap":super::flow_counts(&flow)?.0}),
            )?,
        )?;
        self.assert_namespace_released(before.trim())?;
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
        // Inodes may be reused after the last holder exits. The namespace-local
        // marker is the identity control for a destroyed namespace.
        if self
            .lab
            .cmd("scupper", "ip", &["-j", "link", "show", "lo"])?
            .contains("scupper-old-generation")
        {
            return fail("rebuild retained old namespace marker");
        }
        self.lab.restore_inheritance()?;
        self.lab.boot_fresh_client_handshake()?;
        self.lab.wait_provider()?;
        self.lab.boot_sysctls()?;
        if case == "L18" {
            self.lab
                .daemon_sysctl_fixture(self.child.as_mut().ok_or("daemon")?)?;
        }
        canary.stop(Signal::TERM)?;
        Ok(())
    }
}
