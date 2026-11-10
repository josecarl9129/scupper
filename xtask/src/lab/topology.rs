//! Boot-built gateway and containment cases. No machine-host networking writes.
mod bridge;
mod ipv6;
use super::{
    Lab, Result,
    addresses::{A, PORT, Segment},
    cleanup::Resource,
    evidence::{self, Case},
    fail, helpers,
};
use scupper_core::{canon::canonicalize, render::desired_sysctls, rules::IfName};
use std::{
    fmt::Write as _,
    fs,
    time::{Duration, Instant},
};

// Filter chains accept everything; exit-only NAT keeps provider DNS usable.
// The deliberate bridge leak remains un-NATed.
const PERMISSIVE_RULES: &[u8] = br#"flush ruleset
table inet permissive {
    chain input { type filter hook input priority filter; policy accept; }
    chain forward { type filter hook forward priority filter; policy accept; }
    chain output { type filter hook output priority filter; policy accept; }
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        oifname "ex-ch1" masquerade
    }
}
"#;

impl Lab {
    pub(super) fn build(&mut self) -> Result<()> {
        self.build_wan()?;
        self.build_gateway()?;
        self.build_provider()?;
        self.build_client()?;
        self.start_sinks()?;
        self.wait_provider()?;
        Ok(())
    }
    fn build_wan(&mut self) -> Result<()> {
        for ns in ["wan", "gwhost", "client", "provA", "internet"] {
            self.new_namespace(ns, "")?;
        }
        for segment in [A.gwhost, A.client, A.provider, A.internet] {
            self.veth(segment, "eth0")?;
        }
        for ns in ["wan", "gwhost", "client", "provA", "internet"] {
            self.cmd(
                ns,
                "sysctl",
                &[
                    "-q",
                    "-w",
                    "net.ipv4.conf.all.rp_filter=0",
                    "net.ipv4.conf.default.rp_filter=0",
                    "net.ipv4.conf.all.send_redirects=0",
                    "net.ipv4.conf.default.send_redirects=0",
                    "net.ipv6.conf.all.accept_ra=0",
                    "net.ipv6.conf.default.accept_ra=0",
                    "net.ipv6.conf.all.autoconf=0",
                    "net.ipv6.conf.default.autoconf=0",
                ],
            )?;
        }
        for ns in ["wan", "provA"] {
            self.cmd(
                ns,
                "sysctl",
                &[
                    "-q",
                    "-w",
                    "net.ipv4.ip_forward=1",
                    "net.ipv4.conf.all.send_redirects=0",
                    "net.ipv4.conf.default.send_redirects=0",
                ],
            )?;
        }
        let v6_prefix = A
            .internet_v6_net
            .split_once('/')
            .ok_or("invalid v6 sink network")?
            .1;
        self.cmd(
            "internet",
            "ip",
            &[
                "-6",
                "addr",
                "add",
                &format!("{}/{v6_prefix}", A.internet_v6),
                "dev",
                "eth0",
                "nodad",
            ],
        )?;
        self.cmd(
            "wan",
            "ip",
            &[
                "-6",
                "addr",
                "add",
                &format!("{}/64", A.wan_v6),
                "dev",
                A.internet.wan_if,
                "nodad",
            ],
        )?;
        self.cmd(
            "internet",
            "ip",
            &["-6", "route", "add", "default", "via", A.wan_v6],
        )?;

        self.internet_uplink()?;
        Ok(())
    }
    fn internet_uplink(&mut self) -> Result<()> {
        self.start(
            "",
            "slirp4netns",
            &[
                "--configure",
                "--disable-host-loopback",
                "--mtu=1500",
                "--netns-type=path",
                "/run/netns/wan",
                "lab-uplink",
            ],
            "internet-uplink",
        )?;
        let until = Instant::now() + Duration::from_secs(5);
        loop {
            self.ensure_services()?;
            let routes = self.cmd("wan", "ip", &["-j", "route", "show", "default"])?;
            if !scupper_core::parse::parse_ip_route(&routes)?.is_empty() {
                break;
            }
            if Instant::now() >= until {
                return fail("user-mode internet uplink did not become ready");
            }
            self.runner.dwell(Duration::from_millis(100))?;
        }
        self.runner.input(&super::command::Invocation::new("wan", "nft", &["-f", "-"]),
            Some(b"table ip lab_internet { chain postrouting { type nat hook postrouting priority srcnat; policy accept; oifname \"lab-uplink\" masquerade;\n\t}\n}\n"))?;
        Ok(())
    }
    fn build_gateway(&mut self) -> Result<()> {
        self.prepare_check_v2()?;
        self.boot_inheritance()?;
        self.registry
            .register(Resource::Namespace("scupper".into()));
        self.boot_gateway(&[], "boot-fresh")?;
        self.boot_sysctls()?;
        // Load the independently rendered transaction, never boot's live output.
        self.new_namespace("scupper-verify", "")?;
        let path = self.rules.to_string_lossy().into_owned();
        self.cmd("scupper-verify", "nft", &["-f", &path])?;
        self.expected_rules =
            canonicalize(&self.cmd("scupper-verify", "nft", &["-j", "list", "ruleset"])?)?;
        self.cmd("", "ip", &["netns", "delete", "scupper-verify"])?;
        self.registry
            .unregister(&Resource::Namespace("scupper-verify".into()));
        self.verify_rules()?;
        self.boot_adopt()?;
        Ok(())
    }
    fn build_provider(&mut self) -> Result<()> {
        self.cmd("provA", "ip", &["link", "add", "wgp", "type", "wireguard"])?;
        self.wg(
            "provA",
            "wgp",
            "provider",
            "51820",
            1,
            &["allowed-ips", &format!("{}/32", A.exit_inner)],
        )?;
        self.address_up("provA", "wgp", &format!("{}/24", A.provider_inner), 1420)?;
        self.cmd(
            "provA",
            "sysctl",
            &["-q", "-w", "net.ipv4.conf.wgp.rp_filter=0"],
        )?;
        self.runner.input(&super::command::Invocation::new("provA", "nft", &["-f", "-"]), Some(b"table ip lab_nat {\n\tchain postrouting {\n\t\ttype nat hook postrouting priority srcnat; policy accept;\n\t\toifname \"eth0\" masquerade\n\t}\n}\n"))?;
        self.start(
            "provA",
            "dnsmasq",
            &[
                "--keep-in-foreground",
                "--conf-file=/dev/null",
                "--no-resolv",
                "--server=10.0.2.3",
                "--no-hosts",
                "--bind-interfaces",
                "--interface=wgp",
                "--except-interface=lo",
                "--user=root",
                "--log-facility=-",
                &format!("--pid-file={}", self.private.join("dnsmasq.pid").display()),
                &format!("--listen-address={}", A.provider_inner),
                &format!("--address=/lab.test/{}", A.internet.peer),
                &format!("--address=/lab.test/{}", A.internet_v6),
                "--local=/lab.test/",
            ],
            "dnsmasq",
        )?;

        Ok(())
    }
    fn build_client(&mut self) -> Result<()> {
        self.cmd(
            "client",
            "ip",
            &[
                "route",
                "add",
                &format!("{}/32", A.gwhost.peer),
                "via",
                A.client.wan,
                "dev",
                "eth0",
            ],
        )?;
        // The endpoint /32 remains on eth0; all other client traffic uses wg0.
        self.cmd("client", "ip", &["route", "del", "default"])?;
        self.cmd("client", "ip", &["link", "add", "wg0", "type", "wireguard"])?;
        self.wg(
            "client",
            "wg0",
            "client",
            "51820",
            0,
            &[
                "endpoint",
                &format!("{}:51820", A.gwhost.peer),
                "allowed-ips",
                "0.0.0.0/0,::/0",
                "persistent-keepalive",
                "5",
            ],
        )?;
        self.address_up("client", "wg0", &format!("{}/32", A.client_inner), 1420)?;
        self.cmd(
            "client",
            "sysctl",
            &["-q", "-w", "net.ipv4.conf.wg0.rp_filter=0"],
        )?;
        self.cmd("client", "ip", &["route", "add", "default", "dev", "wg0"])?;
        self.cmd(
            "client",
            "ip",
            &["-6", "route", "add", "default", "dev", "wg0"],
        )?;
        Ok(())
    }
    fn start_sinks(&mut self) -> Result<()> {
        fs::write(self.artifacts.join("sink.jsonl"), "")?;
        let executable = self.executable.clone();
        let log = self
            .artifacts
            .join("sink.jsonl")
            .to_string_lossy()
            .into_owned();
        for (family, address) in [("v4", A.internet.peer), ("v6", A.internet_v6)] {
            for protocol in ["tcp", "udp"] {
                let bind = if family == "v4" {
                    format!("{address}:{PORT}")
                } else {
                    format!("[{address}]:{PORT}")
                };
                self.start(
                    "internet",
                    &executable,
                    &[
                        "sink",
                        "--protocol",
                        protocol,
                        "--bind",
                        &bind,
                        "--log",
                        &log,
                    ],
                    &format!("sink-{protocol}-{family}"),
                )?;
            }
        }
        Ok(())
    }
    pub(super) fn wait_provider(&mut self) -> Result<()> {
        self.runner.dwell(Duration::from_secs(2))?;
        // Keepalive initiates the exit handshake. Retry within a fixed setup
        // budget rather than treating the first asynchronous handshake as ready.
        let until = Instant::now() + Duration::from_secs(20);
        loop {
            self.ensure_services()?;
            let handshakes = self.cmd("scupper", "wg", &["show", "ex-ch1", "latest-handshakes"])?;
            if handshakes
                .split_whitespace()
                .nth(1)
                .is_some_and(|value| value != "0")
            {
                break;
            }
            if Instant::now() >= until {
                return fail("provider handshake deadline exceeded");
            }
            self.runner.dwell(Duration::from_millis(200))?;
        }
        Ok(())
    }
    fn veth(&mut self, segment: Segment, peer_if: &str) -> Result<()> {
        self.cmd(
            "",
            "ip",
            &[
                "link",
                "add",
                segment.staging,
                "type",
                "veth",
                "peer",
                "name",
                segment.wan_if,
            ],
        )?;
        for name in [segment.staging, segment.wan_if] {
            self.registry.register(Resource::Link(name.into()));
        }
        self.cmd(
            "",
            "ip",
            &["link", "set", segment.staging, "netns", segment.ns],
        )?;
        self.registry
            .unregister(&Resource::Link(segment.staging.into()));
        self.cmd("", "ip", &["link", "set", segment.wan_if, "netns", "wan"])?;
        self.registry
            .unregister(&Resource::Link(segment.wan_if.into()));
        self.cmd(
            segment.ns,
            "ip",
            &["link", "set", segment.staging, "name", peer_if],
        )?;
        // No automatically generated link-local addresses or router solicitations
        // on the physical lab links; the v6 sink uses only its explicit address.
        for (ns, iface, address) in [
            (segment.ns, peer_if, segment.peer),
            ("wan", segment.wan_if, segment.wan),
        ] {
            self.cmd(
                ns,
                "ip",
                &["link", "set", "dev", iface, "addrgenmode", "none"],
            )?;
            let prefix = segment.network.split_once('/').ok_or("invalid segment")?.1;
            self.address_up(ns, iface, &format!("{address}/{prefix}"), 1500)?;
            self.cmd(
                ns,
                "sysctl",
                &[
                    "-q",
                    "-w",
                    &format!("net.ipv4.conf.{iface}.rp_filter=0"),
                    &format!("net.ipv4.conf.{iface}.send_redirects=0"),
                    &format!("net.ipv6.conf.{iface}.accept_ra=0"),
                    &format!("net.ipv6.conf.{iface}.autoconf=0"),
                ],
            )?;
        }
        if segment.ns != "scupper" {
            self.cmd(
                segment.ns,
                "ip",
                &["route", "add", "default", "via", segment.wan],
            )?;
        }
        Ok(())
    }
    fn address_up(&mut self, ns: &str, iface: &str, address: &str, mtu: u32) -> Result<()> {
        self.cmd(ns, "ip", &["addr", "add", address, "dev", iface])?;
        self.cmd(
            ns,
            "ip",
            &["link", "set", iface, "mtu", &mtu.to_string(), "up"],
        )?;
        Ok(())
    }
    fn wg(
        &mut self,
        ns: &str,
        iface: &str,
        key: &str,
        port: &str,
        peer: usize,
        extra: &[&str],
    ) -> Result<()> {
        let private = self
            .private
            .join(format!("{key}.key"))
            .to_string_lossy()
            .into_owned();
        let public = self.public_keys[peer].clone();
        let mut args = vec![
            "set",
            iface,
            "private-key",
            &private,
            "listen-port",
            port,
            "peer",
            &public,
        ];
        args.extend(extra);
        self.cmd(ns, "wg", &args)?;
        Ok(())
    }
    fn apply_sysctls(&mut self, forwarding: bool, bridge: bool) -> Result<()> {
        let mut links = vec![
            IfName::new("lo")?,
            IfName::new("wg0")?,
            IfName::new("ex-ch1")?,
        ];
        if bridge {
            links.push(IfName::new("lab-bridge")?);
        }
        self.sysctls(&links, forwarding)
    }
    fn sysctls(&mut self, links: &[IfName], forwarding: bool) -> Result<()> {
        let values = desired_sysctls(links, forwarding);
        for value in &values {
            self.cmd(
                "scupper",
                "sysctl",
                &["-q", "-w", &format!("{}={}", value.key, value.value)],
            )?;
        }
        for value in values {
            if self
                .cmd("scupper", "sysctl", &["-n", &value.key.to_string()])?
                .trim()
                != value.value
            {
                return fail(format!("sysctl readback differs: {}", value.key));
            }
        }
        Ok(())
    }
    pub(super) fn load_real_rules(&mut self) -> Result<()> {
        let path = self.rules.to_string_lossy().into_owned();
        self.cmd("scupper", "nft", &["-f", &path])?;
        Ok(())
    }
    fn verify_rules(&mut self) -> Result<()> {
        if canonicalize(&self.cmd("scupper", "nft", &["-j", "list", "ruleset"])?)?
            != self.expected_rules
        {
            return fail("namespace ruleset readback differs");
        }
        Ok(())
    }
    fn restore(&mut self, case: Case) -> Result<()> {
        let mut failures = Vec::new();
        let specific = match case {
            Case::Bridge | Case::Permissive => self.restore_bridge(),
            Case::V6 => self.restore_v6(),
            Case::Uplink => self
                .cmd("wan", "nft", &["delete", "table", "inet", "lab_inject"])
                .map(|_| ()),
            Case::Baseline | Case::CheckV2 | Case::Daemon => Ok(()),
            Case::ProbeChild => self.restore_probe_child_routes(),
        };
        if let Err(error) = specific {
            failures.push(error.to_string());
        }
        for outcome in [
            self.load_real_rules(),
            // conntrack-tools 1.4.6 (Ubuntu 22.04) rejects `-f` with `-F`; a plain flush is
            // enough for the lab, which forwards IPv6 only in the explicit IPv6 variant.
            self.cmd("scupper", "conntrack", &["-F"]).map(|_| ()),
            self.verify_rules(),
            self.apply_sysctls(true, false),
        ] {
            if let Err(error) = outcome {
                failures.push(error.to_string());
            }
        }
        self.runner.dwell(Duration::from_secs(1))?;
        if failures.is_empty() {
            Ok(())
        } else {
            fail(failures.join("; "))
        }
    }
    pub(super) fn case(&mut self, case: Case) -> Result<String> {
        self.daemon_clean_baseline()?;
        if case == Case::Daemon {
            return self.daemon_case();
        }
        if case == Case::CheckV2 {
            return self.check_v2_case();
        }
        let stem = case.name();
        let mut markers = Vec::new();
        let fault = (|| {
            self.capture("wan", A.gwhost.wan_if, stem)?;
            self.service_check(&mut markers)?;
            match case {
                Case::Daemon => self.daemon_case().map(|_| ()),
                Case::Baseline => self.service_check(&mut markers),
                Case::ProbeChild => self.probe_child_case(),
                Case::CheckV2 => self.check_v2_case().map(|_| ()),
                Case::V6 => self.v6_fault(&mut markers),
                Case::Bridge | Case::Permissive => self.bridge_fault(case, &mut markers),
                Case::Uplink => self.uplink_fault(&mut markers),
            }
        })();
        // Attempt restoration and a positive service check even if the fault
        // assertion failed, preserving the original failure alongside diagnostics.
        let mut auxiliary_failures = Vec::new();
        while self.captures.len() > 1 {
            if let Err(error) = self.stop_capture() {
                auxiliary_failures.push(error.to_string());
            }
        }
        let auxiliary_stop = if auxiliary_failures.is_empty() {
            Ok(())
        } else {
            fail(auxiliary_failures.join("; "))
        };
        let restored = self.restore(case);
        let after = if restored.is_ok() {
            self.service_check(&mut markers)
        } else {
            fail("post-case service check unavailable: restoration failed")
        };
        let dwell = self.runner.dwell(Duration::from_secs(2));
        let alive = self.ensure_services();
        let stopped = self.stop_captures();
        let judged = self.judge(case, &markers);
        let observed = judged.as_ref().ok().cloned().unwrap_or_default();
        let failures: Vec<_> = [
            fault,
            auxiliary_stop,
            restored,
            after,
            dwell,
            alive,
            stopped,
            judged.map(|_| ()),
        ]
        .into_iter()
        .filter_map(std::result::Result::err)
        .map(|error| error.to_string())
        .collect();
        if failures.is_empty() {
            Ok(observed)
        } else {
            fail(failures.join("; "))
        }
    }
    fn judge(&self, case: Case, markers: &[String]) -> Result<String> {
        let stem = case.name();
        let uplink = evidence::report(&self.artifacts, stem, markers, false, self.exit_port)?;
        if case == Case::Uplink {
            let marker = markers.get(4).ok_or("injection marker missing")?;
            evidence::injected_only(
                &uplink,
                &fs::read(self.artifacts.join(format!("{stem}.pcap")))?,
                marker,
            )?;
        } else if uplink.violation_count != 0 {
            return fail(format!(
                "uplink oracle: {} violations",
                uplink.violation_count
            ));
        }
        let receipts = helpers::receipts(&fs::read_to_string(self.artifacts.join("sink.jsonl"))?)?;
        let seen: Vec<_> = receipts
            .iter()
            .filter(|r| markers.contains(&r.marker))
            .map(|r| r.marker.as_str())
            .collect();
        let mut observed = format!(
            "uplink_packets={}, violations={}, receipts={}, seen_markers={seen:?}",
            uplink.packet_count,
            uplink.violation_count,
            seen.len()
        );
        if matches!(case, Case::Bridge | Case::Permissive) {
            let report = evidence::report(
                &self.artifacts,
                &format!("{stem}-bridge"),
                markers,
                true,
                self.exit_port,
            )?;
            if case == Case::Bridge && !evidence::contained(&report) {
                return fail("bridge containment oracle failed");
            }
            write!(
                observed,
                ", bridge_packets={}, bridge_violations={}",
                report.packet_count, report.violation_count
            )?;
            if case == Case::Permissive {
                let outputs = [markers.get(8), markers.get(13)];
                let packets = crate::pcap::observe(&fs::read(
                    self.artifacts.join(format!("{stem}-bridge.pcap")),
                )?)?;
                for (output, source) in outputs.into_iter().zip([A.bridge.peer, A.bridge_v6]) {
                    let output = output.ok_or("bridge output marker missing")?;
                    if !packets.iter().any(|p| {
                        p.source.to_string() == source
                            && p.protocol == 17
                            && p.payload.get(8..) == Some(output.as_bytes())
                    }) {
                        return fail("permissive bridge output marker missing from capture");
                    }
                }
            }
            if case == Case::Permissive
                && (!evidence::leak_seen(&report) || !report.capture_failures.is_empty())
            {
                return fail("bridge positive control was blind");
            }
        }
        if case == Case::V6 {
            observed.push_str(", ipv6_ingress_and_controls=verified");
        }
        Ok(observed)
    }
    pub(super) fn uplink_fault(&mut self, markers: &mut Vec<String>) -> Result<()> {
        self.runner.dwell(Duration::from_secs(3))?;
        let marker = Self::marker()?;
        markers.push(marker.clone());
        self.runner.input(&super::command::Invocation::new("wan", "nft", &["-f", "-"]), Some(b"table inet lab_inject { chain input { type filter hook input priority filter; ip saddr 198.51.100.2 ip daddr 198.51.100.1 udp sport { 40002, 40003 } udp dport { 53, 8080 } drop;\n\t}\n}\n"))?;
        let exe = self.executable.clone();
        self.cmd("gwhost", &exe, &["inject", "--marker", &marker])?;
        self.runner.dwell(Duration::from_secs(3))?;
        Ok(())
    }
}
