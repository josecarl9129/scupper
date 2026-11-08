//! Reference builder and the first five cases. No host routes or host sysctls.
use super::{
    Lab, Result,
    addresses::{A, PORT, Segment},
    cleanup::Resource,
    evidence::{self, Case},
    fail, helpers,
};
use scupper_core::{
    canon::canonicalize,
    config::{ExitId, GatewayId},
    render::{desired_routes, desired_sysctls, route_argv},
    rules::IfName,
};
use std::{
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

        Ok(())
    }
    fn build_gateway(&mut self) -> Result<()> {
        // These links' UDP sockets belong to gwhost for their entire lifetime.
        for iface in ["wg0", "ex-ch1"] {
            self.cmd("gwhost", "ip", &["link", "add", iface, "type", "wireguard"])?;
        }
        self.wg(
            "gwhost",
            "wg0",
            "gateway",
            "51820",
            3,
            &["allowed-ips", &format!("{}/32", A.client_inner)],
        )?;
        self.wg(
            "gwhost",
            "ex-ch1",
            "exit",
            "51821",
            2,
            &[
                "endpoint",
                &format!("{}:51820", A.provider.peer),
                "allowed-ips",
                "0.0.0.0/0",
                "persistent-keepalive",
                "25",
            ],
        )?;
        // nsenter preserves the mount namespace. ip-netns-exec gwhost here would
        // hide the new scupper bind mount from the runner.
        self.new_namespace("scupper", "gwhost")?;
        self.cmd(
            "scupper",
            "sysctl",
            &[
                "-q",
                "-w",
                "net.ipv4.ip_forward=0",
                "net.ipv6.conf.all.forwarding=0",
            ],
        )?;
        for iface in ["wg0", "ex-ch1"] {
            self.cmd("gwhost", "ip", &["link", "set", iface, "netns", "scupper"])?;
        }
        let gateway = self
            .site
            .gateway(&GatewayId("gw1".into()))
            .ok_or("missing gateway")?
            .clone();
        if gateway.client_tunnel().address4().addr().to_string() != A.gateway_inner {
            return fail("lab gateway address differs from the address table");
        }
        self.address_up(
            "scupper",
            "wg0",
            &gateway.client_tunnel().address4().to_string(),
            gateway.client_tunnel().mtu(),
        )?;
        self.address_up(
            "scupper",
            "ex-ch1",
            &gateway.exits()[0].address4().to_string(),
            gateway.exits()[0].mtu(),
        )?;
        self.load_real_rules()?;
        self.apply_sysctls(false, false)?;
        for (family, target) in desired_routes(
            &self.site,
            &GatewayId("gw1".into()),
            Some(&ExitId("ch1".into())),
        ) {
            let args = route_argv(family, &target);
            let args: Vec<_> = args.iter().map(String::as_str).collect();
            self.cmd("scupper", "ip", &args)?;
        }
        // Compare independent kernel-normalized expected/live rules before
        // opening forwarding, using the same canonicalizer as the product.
        self.new_namespace("scupper-verify", "")?;
        let rules = self.rules.to_string_lossy().into_owned();
        self.cmd("scupper-verify", "nft", &["-f", &rules])?;
        self.expected_rules =
            canonicalize(&self.cmd("scupper-verify", "nft", &["-j", "list", "ruleset"])?)?;
        self.cmd("", "ip", &["netns", "delete", "scupper-verify"])?;
        self.verify_rules()?;
        // Forwarding is enabled only now. desired_sysctls deliberately writes
        // forwarding first, then reapplies every setting reset by that write.
        self.apply_sysctls(true, false)?;

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
        self.runner.input(&super::command::Invocation::new("provA", "nft", &["-f", "-"]), Some(b"table ip lab_nat { chain postrouting { type nat hook postrouting priority srcnat; policy accept; oifname \"eth0\" masquerade; } }\n"))?;
        self.start(
            "provA",
            "dnsmasq",
            &[
                "--keep-in-foreground",
                "--conf-file=/dev/null",
                "--no-resolv",
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
    fn wait_provider(&mut self) -> Result<()> {
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
        for name in [segment.staging, segment.wan_if] {
            self.registry.register(Resource::Link(name.into()));
        }
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
        self.cmd(
            "",
            "ip",
            &["link", "set", segment.staging, "netns", segment.ns],
        )?;
        self.cmd("", "ip", &["link", "set", segment.wan_if, "netns", "wan"])?;
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
        let values = desired_sysctls(&links, forwarding);
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
    fn load_real_rules(&mut self) -> Result<()> {
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
        if matches!(case, Case::Bridge | Case::Permissive) {
            // Delete the wan end explicitly, before any namespace disappears.
            self.cmd(
                "scupper",
                "ip",
                &["route", "del", &format!("{}/32", A.internet.peer)],
            )?;
            self.cmd("wan", "ip", &["route", "del", A.client_net])?;
            self.cmd("wan", "ip", &["link", "delete", A.bridge.wan_if])?;
            let until = Instant::now() + Duration::from_secs(3);
            while self
                .runner
                .output(
                    &super::command::Invocation::new(
                        "scupper",
                        "ip",
                        &["link", "show", "dev", "lab-bridge"],
                    ),
                    None,
                )?
                .0
                .success()
            {
                if Instant::now() >= until {
                    return fail("bridge peer did not disappear after deletion");
                }
                self.runner.dwell(Duration::from_millis(50))?;
            }
        }
        if case == Case::V6 {
            self.cmd(
                "client",
                "ip",
                &[
                    "-6",
                    "addr",
                    "del",
                    &format!("{}/64", A.client_v6),
                    "dev",
                    "wg0",
                ],
            )?;
            self.cmd(
                "scupper",
                "wg",
                &[
                    "set",
                    "wg0",
                    "peer",
                    &self.public_keys[3].clone(),
                    "allowed-ips",
                    &format!("{}/32", A.client_inner),
                ],
            )?;
        }
        self.load_real_rules()?;
        self.verify_rules()?;
        self.apply_sysctls(true, false)?;
        self.runner.dwell(Duration::from_secs(1))?;
        Ok(())
    }
    pub(super) fn case(&mut self, case: Case) -> Result<()> {
        let stem = case.name();
        let mut markers = Vec::new();
        self.capture("wan", A.gwhost.wan_if, stem, false)?;
        self.service_check(&mut markers)?;
        let fault = match case {
            Case::Baseline => self.service_check(&mut markers),
            Case::V6 => self.v6_fault(&mut markers),
            Case::Bridge | Case::Permissive => self.bridge_fault(case, &mut markers),
            Case::Uplink => self.uplink_fault(&mut markers),
        };
        // Attempt restoration and a positive service check even if the fault
        // assertion failed, preserving the original failure alongside diagnostics.
        let bridge_stop =
            if matches!(case, Case::Bridge | Case::Permissive) && self.captures.len() > 1 {
                self.stop_capture()
            } else {
                Ok(())
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
        let failures: Vec<_> = [
            fault,
            bridge_stop,
            restored,
            after,
            dwell,
            alive,
            stopped,
            judged,
        ]
        .into_iter()
        .filter_map(std::result::Result::err)
        .map(|error| error.to_string())
        .collect();
        if failures.is_empty() {
            Ok(())
        } else {
            fail(failures.join("; "))
        }
    }
    fn judge(&self, case: Case, markers: &[String]) -> Result<()> {
        let stem = case.name();
        let uplink = evidence::report(&self.artifacts, stem, markers, false)?;
        if case == Case::Uplink {
            if !evidence::leak_seen(&uplink) || !uplink.capture_failures.is_empty() {
                return fail(
                    "uplink positive control did not detect an actual leak with healthy WireGuard evidence",
                );
            }
        } else if uplink.violation_count != 0 {
            return fail(format!(
                "uplink oracle: {} violations",
                uplink.violation_count
            ));
        }
        if matches!(case, Case::Bridge | Case::Permissive) {
            let report =
                evidence::report(&self.artifacts, &format!("{stem}-bridge"), markers, true)?;
            if case == Case::Bridge && !evidence::contained(&report) {
                return fail("bridge containment oracle failed");
            }
            if case == Case::Permissive && !evidence::leak_seen(&report) {
                return fail("bridge positive control was blind");
            }
        }
        if case == Case::V6 {
            for suffix in ["provider-v6", "internet-v6"] {
                let report =
                    evidence::report(&self.artifacts, &format!("{stem}-{suffix}"), markers, true)?;
                if report.packet_count != 0 || !evidence::contained(&report) {
                    return fail(format!("IPv6 reached {suffix}"));
                }
            }
        }
        Ok(())
    }
    fn v6_fault(&mut self, markers: &mut Vec<String>) -> Result<()> {
        let stem = Case::V6.name();
        self.cmd(
            "client",
            "ip",
            &[
                "-6",
                "addr",
                "add",
                &format!("{}/64", A.client_v6),
                "dev",
                "wg0",
                "nodad",
            ],
        )?;
        // Admit the source at WireGuard so the real nft antispoof rule,
        // rather than WireGuard's cryptokey routing, enforces F4.
        self.cmd(
            "scupper",
            "wg",
            &[
                "set",
                "wg0",
                "peer",
                &self.public_keys[3].clone(),
                "allowed-ips",
                &format!("{}/32,{}/128", A.client_inner, A.client_v6),
            ],
        )?;
        self.capture("provA", "wgp", &format!("{stem}-provider-v6"), true)?;
        self.capture("internet", "eth0", &format!("{stem}-internet-v6"), true)?;
        self.runner.dwell(Duration::from_secs(3))?;
        let sent = self.canaries(markers, true, false)?;
        self.runner.dwell(Duration::from_secs(3))?;
        let receipts = helpers::receipts(&fs::read_to_string(self.artifacts.join("sink.jsonl"))?)?;
        if receipts.iter().any(|r| sent.contains(&r.marker)) {
            return fail("IPv6 marker reached the sink");
        }
        Ok(())
    }
    fn bridge_fault(&mut self, case: Case, markers: &mut Vec<String>) -> Result<()> {
        let stem = case.name();
        self.veth(A.bridge, "lab-bridge")?;
        self.apply_sysctls(true, true)?;
        self.cmd(
            "scupper",
            "ip",
            &[
                "route",
                "add",
                &format!("{}/32", A.internet.peer),
                "via",
                A.bridge.wan,
                "dev",
                "lab-bridge",
                "metric",
                "1",
            ],
        )?;
        self.cmd(
            "wan",
            "ip",
            &[
                "route",
                "add",
                A.client_net,
                "via",
                A.bridge.peer,
                "dev",
                A.bridge.wan_if,
            ],
        )?;
        self.capture("wan", A.bridge.wan_if, &format!("{stem}-bridge"), false)?;
        if case == Case::Permissive {
            self.runner.input(
                &super::command::Invocation::new("scupper", "nft", &["-f", "-"]),
                Some(PERMISSIVE_RULES),
            )?;
        }
        self.runner.dwell(Duration::from_secs(3))?;
        let sent = self.canaries(markers, false, case == Case::Permissive)?;
        // Exercise output containment as well as forwarded client traffic.
        let marker = Self::marker()?;
        markers.push(marker.clone());
        let success = self.send("scupper", "udp", A.internet.peer, &marker, false)?;
        if success != (case == Case::Permissive) {
            return fail("bridge output containment/control failed");
        }
        self.runner.dwell(Duration::from_secs(3))?;
        let receipts = helpers::receipts(&fs::read_to_string(self.artifacts.join("sink.jsonl"))?)?;
        if case == Case::Bridge
            && receipts
                .iter()
                .any(|r| sent.contains(&r.marker) || r.marker == marker)
        {
            return fail("real ruleset leaked a bridge marker");
        }
        if case == Case::Permissive
            && !sent.iter().all(|m| {
                receipts
                    .iter()
                    .any(|r| r.marker == *m && r.peer.ip().to_string() == A.client_inner)
            })
        {
            return fail("permissive bridge did not deliver client markers without NAT");
        }
        Ok(())
    }
    fn uplink_fault(&mut self, markers: &mut Vec<String>) -> Result<()> {
        self.runner.dwell(Duration::from_secs(3))?;
        let marker = Self::marker()?;
        markers.push(marker.clone());
        let exe = self.executable.clone();
        self.cmd("gwhost", &exe, &["inject", "--marker", &marker])?;
        self.runner.dwell(Duration::from_secs(3))?;
        Ok(())
    }
}
