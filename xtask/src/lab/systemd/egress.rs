//! Root ingress and per-interface egress evidence, with internal-path observations.
use super::{A, Invocation, Result, SystemdLab, fail, fs, helpers};
use serde_json::Value;
use std::{collections::BTreeSet, fmt::Write as _, net::SocketAddr};
const TABLE: &str = "scupper_lab_egress";
const PREFIXES: [(&str, &str); 2] = [
    (
        "ip",
        "{ 10.99.0.0/24, 10.2.0.0/24, 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 }",
    ),
    ("ip6", "{ 2001:db8::/32, fd00::/8 }"),
];
#[derive(Default, serde::Serialize)]
pub(super) struct Scope {
    judged: BTreeSet<String>,
    excluded: BTreeSet<String>,
    defaults: BTreeSet<String>,
    control_interface: String,
    #[serde(skip)]
    log_cursor: String,
    #[serde(skip)]
    control_active: bool,
    #[serde(skip)]
    installed: bool,
}
fn lab_links() -> BTreeSet<String> {
    let mut links: BTreeSet<_> = ["lo", "up0", "ctl0", "wg0", "ex-0", "ex-ch1"]
        .map(str::to_owned)
        .into();
    for segment in A.segments() {
        links.insert(segment.wan_if.into());
        links.insert(segment.staging.into());
    }
    links
}
impl Scope {
    fn new(links: &str, routes4: &str, routes6: &str, main4: &str) -> Result<Self> {
        let excluded = lab_links();
        let links: Vec<Value> = serde_json::from_str(links)?;
        let mut judged = BTreeSet::new();
        for link in links {
            let name = link["ifname"].as_str().ok_or("link name")?;
            if name != "lo" {
                if excluded.contains(name) {
                    return fail(format!("occupied lab link {name}"));
                }
                judged.insert(name.into());
            }
        }
        let mut defaults = BTreeSet::new();
        for text in [routes4, routes6] {
            let routes: Vec<Value> = serde_json::from_str(text)?;
            for route in routes {
                if let Some(dev) = route["dev"].as_str() {
                    defaults.insert(dev.into());
                }
                if let Some(hops) = route["nexthops"].as_array() {
                    for hop in hops {
                        defaults
                            .insert(hop["dev"].as_str().ok_or("default nexthop device")?.into());
                    }
                }
            }
        }
        let routes: Vec<Value> = serde_json::from_str(main4)?;
        let control_interface = routes
            .iter()
            .find_map(|r| r["dev"].as_str())
            .ok_or("no IPv4 main default-route interface")?
            .to_owned();
        if judged.is_empty()
            || defaults.is_empty()
            || !defaults.is_subset(&judged)
            || !defaults.contains(&control_interface)
        {
            return fail(
                "egress scope must contain every default-route interface and a real uplink",
            );
        }
        Ok(Self {
            judged,
            excluded,
            defaults,
            control_interface,
            log_cursor: String::new(),
            control_active: false,
            installed: false,
        })
    }
    fn selectors(&self) -> impl Iterator<Item = (&str, &str, &str, &str)> {
        [("judged", &self.judged), ("excluded", &self.excluded)]
            .into_iter()
            .flat_map(|(chain, interfaces)| {
                interfaces.iter().flat_map(move |interface| {
                    PREFIXES.into_iter().flat_map(move |(family, _)| {
                        ["saddr", "daddr"]
                            .map(move |direction| (chain, interface.as_str(), family, direction))
                    })
                })
            })
    }
    fn rules(&self, control: bool) -> String {
        let mut text = format!("table inet {TABLE} {{\n");
        text.push_str(
            " chain ingress {\n  type filter hook prerouting priority -300; policy accept;\n",
        );
        for (family, prefixes) in [
            ("ip", "{ 10.99.0.0/24, 10.2.0.0/24 }"),
            ("ip6", "{ fd00::/8, 2001:db8:2::/64 }"),
        ] {
            writeln!(text, "  {family} saddr {prefixes} counter limit rate 5/second burst 10 packets log prefix \"scupper-lab-egress-ingress \" comment \"judged:prerouting:{family}:saddr\"").ok();
        }
        text.push_str(" }\n");
        for chain in ["judged", "excluded"] {
            writeln!(
                text,
                " chain {chain} {{\n  type filter hook postrouting priority -300; policy accept;"
            )
            .ok();
            if chain == "judged" && control {
                // This temporary rule returns before the case selectors. Remove
                // it atomically when opening the case window, so no case packet
                // can inherit the positive control's exemption.
                let interface = serde_json::json!(self.control_interface);
                writeln!(text, "  oifname {interface} ip saddr {} ip daddr 198.18.255.254 ip ttl 1 udp sport 40001 udp dport 8080 counter log prefix \"scupper-lab-egress-control \" return comment \"positive-control\"", A.client_inner).ok();
            }
            for (_, interface, family, direction) in self.selectors().filter(|s| s.0 == chain) {
                let prefixes = PREFIXES.iter().find(|p| p.0 == family).map_or("", |p| p.1);
                // JSON string quoting is also valid nft string quoting.
                let interface_literal = serde_json::json!(interface).to_string();
                let comment =
                    serde_json::json!(format!("{chain}:{interface}:{family}:{direction}"));
                let log = if chain == "judged" {
                    " limit rate 5/second burst 10 packets log prefix \"scupper-lab-egress \""
                } else {
                    ""
                };
                writeln!(text, "  oifname {interface_literal} {family} {direction} {prefixes} counter{log} comment {comment}").ok();
            }
            text.push_str(" }\n");
        }
        text.push_str("}\n");
        text
    }
}
impl SystemdLab {
    pub(super) fn egress_inventory(&mut self) -> Result<()> {
        // Run before any namespace or link creation; docker0 and other existing
        // non-lab links stay in scope even when they carry no default route.
        let links = self.cmd("ip", &["-j", "link", "show"])?;
        let routes4 = self.cmd(
            "ip",
            &["-4", "-j", "route", "show", "table", "all", "default"],
        )?;
        let routes6 = self.cmd(
            "ip",
            &["-6", "-j", "route", "show", "table", "all", "default"],
        )?;
        let main4 = self.cmd("ip", &["-4", "-j", "route", "show", "default"])?;
        self.egress = Scope::new(&links, &routes4, &routes6, &main4)?;
        self.egress.log_cursor = self.journal_cursor()?;
        fs::write(
            self.lab.artifacts.join("root-egress-scope.json"),
            serde_json::to_vec_pretty(
                &serde_json::json!({"scope":self.egress,"links":serde_json::from_str::<Value>(&links)?,"defaults4":serde_json::from_str::<Value>(&routes4)?,"defaults6":serde_json::from_str::<Value>(&routes6)?}),
            )?,
        )?;
        Ok(())
    }
    pub(super) fn egress_setup(&mut self) -> Result<()> {
        let (status, _) = self.lab.runner.output(
            &Invocation::new("", "nft", &["list", "table", "inet", TABLE]),
            None,
        )?;
        if status.success() {
            return fail("occupied root egress detector");
        }
        let rules = self.egress.rules(true);
        fs::write(self.lab.artifacts.join("root-egress.nft"), &rules)?;
        self.lab.runner.input(
            &Invocation::new("", "nft", &["-f", "-"]),
            Some(rules.as_bytes()),
        )?;
        self.egress.installed = true;
        self.egress.control_active = true;
        let destination = "198.18.255.254";
        let packet = helpers::spoofed_packet(
            A.client_inner.parse()?,
            destination.parse()?,
            b"egress-control",
        )?;
        let socket = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::RAW,
            Some(socket2::Protocol::UDP),
        )?;
        socket.set_header_included_v4(true)?;
        socket.bind_device(Some(self.egress.control_interface.as_bytes()))?;
        // IP socket (not AF_PACKET): traverse postrouting on the actual uplink.
        // TTL 1 bounds the documentation-only control to the runner's next hop.
        let mut packet = packet;
        packet[8] = 1; // IP_HDRINCL makes the kernel recompute the IP checksum.
        socket.send_to(&packet, &SocketAddr::new(destination.parse()?, 0).into())?;
        let counts = self.egress_count("egress-uplink-positive-control")?;
        if counts["positive-control"] != 1
            || counts
                .iter()
                .any(|(key, n)| key.starts_with("judged:") && *n != 0)
        {
            return fail("real-uplink control was blind or counted in the case window");
        }
        let judged_before: u64 = counts
            .iter()
            .filter(|(k, _)| k.starts_with("judged:"))
            .map(|(_, n)| n)
            .sum();
        let lo_before = counts["excluded:lo:ip:daddr"];
        self.lab.runner.output(
            &Invocation::new("", "ping", &["-c", "1", "-W", "1", A.gwhost.peer]),
            None,
        )?;
        let counts = self.egress_count("egress-loopback-positive-control")?;
        if counts["excluded:lo:ip:daddr"] <= lo_before
            || counts
                .iter()
                .filter(|(k, _)| k.starts_with("judged:"))
                .map(|(_, n)| n)
                .sum::<u64>()
                != judged_before
        {
            return fail("loopback egress control was blind or counted as judged");
        }
        let until = super::Instant::now() + super::Duration::from_secs(5);
        loop {
            self.egress_log("positive-controls")?;
            let log = fs::read_to_string(
                self.lab
                    .artifacts
                    .join("positive-controls-root-egress-kernel.txt"),
            )?;
            if log.lines().any(|line| {
                line.contains(&format!("OUT={} ", self.egress.control_interface))
                    && line.contains(&format!("SRC={} ", A.client_inner))
                    && line.contains("DST=198.18.255.254 ")
                    && line.contains("PROTO=UDP")
            }) {
                break;
            }
            if super::Instant::now() >= until {
                return fail("real-uplink positive control missing attributed kernel log");
            }
            self.lab.runner.dwell(super::Duration::from_millis(100))?;
        }
        self.ingress_positive_control()?;
        let rules = self.egress.rules(false);
        fs::write(self.lab.artifacts.join("root-egress-case.nft"), &rules)?;
        // One nft transaction leaves no gap and no control exemption in the
        // judged window. All source and destination counters start at zero.
        self.lab.runner.input(
            &Invocation::new("", "nft", &["-f", "-"]),
            Some(format!("delete table inet {TABLE}\n{rules}").as_bytes()),
        )?;
        self.egress.control_active = false;
        let counts = self.egress_count("egress-reset")?;
        if counts.values().any(|n| *n != 0) {
            return fail("egress counters did not reset");
        }
        // Keep intentional control hits out of the case's kernel-log evidence.
        self.egress.log_cursor = self.journal_cursor()?;
        fs::write(
            self.lab.artifacts.join("root-egress-case-cursor.txt"),
            &self.egress.log_cursor,
        )?;
        Ok(())
    }
    fn ingress_positive_control(&mut self) -> Result<()> {
        // A helper-side raw IP socket traverses root prerouting, even when
        // rp_filter or a runner's FORWARD policy would later discard it.
        self.cmd(
            "ip",
            &[
                "link", "add", "ctl0", "type", "veth", "peer", "name", "ctlpeer",
            ],
        )?;
        let trial = (|| {
            self.cmd("ip", &["link", "set", "ctlpeer", "netns", "internet"])?;
            self.cmd("ip", &["addr", "add", "198.18.0.1/30", "dev", "ctl0"])?;
            self.cmd("ip", &["link", "set", "ctl0", "up"])?;
            self.lab.cmd(
                "internet",
                "ip",
                &["addr", "add", "198.18.0.2/30", "dev", "ctlpeer"],
            )?;
            self.lab
                .cmd("internet", "ip", &["link", "set", "ctlpeer", "up"])?;
            self.lab.cmd(
                "internet",
                "ip",
                &[
                    "route",
                    "add",
                    "198.18.255.254/32",
                    "via",
                    "198.18.0.1",
                    "dev",
                    "ctlpeer",
                ],
            )?;
            let mut packet = helpers::spoofed_packet(
                A.client_inner.parse()?,
                "198.18.255.254".parse()?,
                b"ingress-control",
            )?;
            packet[8] = 1; // IP_HDRINCL recomputes the checksum; TTL prevents onward transit.
            fs::write(
                self.lab.artifacts.join("root-ingress-control.packet"),
                &packet,
            )?;
            let before = self.egress_count("ingress-control-before")?;
            let mut hex = String::with_capacity(packet.len() * 2);
            for byte in &packet {
                write!(hex, "{byte:02x}").ok();
            }
            self.lab.cmd("internet", "python3", &["-c", "import socket,sys; s=socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_UDP); s.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1); s.setsockopt(socket.SOL_SOCKET,socket.SO_BINDTODEVICE,b'ctlpeer'); s.sendto(bytes.fromhex(sys.argv[1]),('198.18.255.254',0))", &hex])?;
            let until = super::Instant::now() + super::Duration::from_secs(5);
            loop {
                let counts = self.egress_count("ingress-positive-control")?;
                if counts["judged:prerouting:ip:saddr"] == before["judged:prerouting:ip:saddr"] + 1
                {
                    self.egress_log("ingress-positive-control")?;
                    let log = fs::read_to_string(
                        self.lab
                            .artifacts
                            .join("ingress-positive-control-root-egress-kernel.txt"),
                    )?;
                    if log.lines().any(|line| {
                        line.contains("scupper-lab-egress-ingress ")
                            && line.contains("IN=ctl0 ")
                            && line.contains(&format!("SRC={} ", A.client_inner))
                            && line.contains("DST=198.18.255.254 ")
                            && line.contains("PROTO=UDP")
                    }) {
                        break;
                    }
                }
                if super::Instant::now() >= until {
                    return fail("root prerouting source control missing count or attributed log");
                }
                self.lab.runner.dwell(super::Duration::from_millis(100))?;
            }
            Ok(())
        })();
        let cleanup = self.cmd("ip", &["link", "del", "ctl0"]).map(|_| ());
        super::super::mutation::finish(trial, cleanup)
    }
    fn egress_count(&mut self, label: &str) -> Result<std::collections::BTreeMap<String, u64>> {
        let text = self.cmd("nft", &["-j", "list", "table", "inet", TABLE])?;
        fs::write(
            self.lab.artifacts.join(format!("{label}-root-egress.json")),
            &text,
        )?;
        count(&text, &self.egress)
    }
    pub(super) fn egress_final(&mut self) -> Result<()> {
        if self.egress.installed && !self.egress.control_active {
            self.egress_zero("final")
        } else {
            self.egress_log("final")
        }
    }
    pub(super) fn egress_log(&mut self, label: &str) -> Result<()> {
        if self.egress.log_cursor.is_empty() {
            return Ok(());
        }
        let cursor = self.egress.log_cursor.clone();
        let (status, log) = self.lab.runner.output(
            &Invocation::new(
                "",
                "journalctl",
                &[
                    "--no-pager",
                    "-k",
                    "-o",
                    "short-monotonic",
                    "--after-cursor",
                    &cursor,
                    "--grep",
                    "scupper-lab-egress",
                ],
            ),
            None,
        )?;
        // journalctl --grep returns 1 when there are no matching messages.
        if !matches!(status.code(), Some(0 | 1)) {
            return fail("cannot read root egress kernel journal");
        }
        fs::write(
            self.lab
                .artifacts
                .join(format!("{label}-root-egress-kernel.txt")),
            log,
        )?;
        Ok(())
    }
    pub(super) fn egress_zero(&mut self, label: &str) -> Result<()> {
        if !self.egress.installed || self.egress.control_active {
            return fail("root egress case window has not opened");
        }
        let counts = self.egress_count(label)?;
        self.egress_log(label)?;
        if counts
            .iter()
            .any(|(key, n)| key.starts_with("judged:") && *n != 0)
        {
            return fail(
                "client/tunnel source reached root namespace or lab prefix escaped through a runner interface; see counters and kernel log",
            );
        }
        Ok(())
    }
}
fn count(text: &str, scope: &Scope) -> Result<std::collections::BTreeMap<String, u64>> {
    let json: Value = serde_json::from_str(text)?;
    let mut counts = std::collections::BTreeMap::new();
    for rule in json["nftables"]
        .as_array()
        .ok_or("nftables array")?
        .iter()
        .filter_map(|v| v.get("rule"))
    {
        let comment = rule["comment"]
            .as_str()
            .ok_or("missing egress rule attribution")?;
        let mut counters = rule["expr"]
            .as_array()
            .ok_or("rule expressions")?
            .iter()
            .filter_map(|e| e.get("counter"));
        let packets = counters.next().ok_or("missing egress counter")?["packets"]
            .as_u64()
            .ok_or("packet counter")?;
        if counters.next().is_some() || counts.insert(comment.to_owned(), packets).is_some() {
            return fail("duplicate egress counter");
        }
    }
    let mut expected: BTreeSet<_> = scope
        .selectors()
        .map(|(c, i, f, d)| format!("{c}:{i}:{f}:{d}"))
        .collect();
    expected.extend(["ip", "ip6"].map(|family| format!("judged:prerouting:{family}:saddr")));
    if scope.control_active {
        expected.insert("positive-control".into());
    }
    if counts.keys().cloned().collect::<BTreeSet<_>>() != expected {
        return fail("root egress detector missing per-interface counters");
    }
    Ok(counts)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn scope() -> Scope {
        Scope::new(
            r#"[{"ifname":"lo"},{"ifname":"eth0"},{"ifname":"docker0"},{"ifname":"eth1"}]"#,
            r#"[{"dev":"eth0"}]"#,
            r#"[{"nexthops":[{"dev":"eth1"}]}]"#,
            r#"[{"dev":"eth0"}]"#,
        )
        .unwrap()
    }
    #[test]
    fn scope_preserves_existing_links_and_all_default_devices() {
        let scope = scope();
        assert_eq!(
            scope.judged,
            ["docker0", "eth0", "eth1"].map(str::to_owned).into()
        );
        assert!(
            scope.excluded.contains("lo")
                && scope.excluded.contains("ctl0")
                && scope.excluded.contains("up0")
        );
        for (links, routes) in [
            (r#"[{"ifname":"lo"}]"#, r#"[{"dev":"eth0"}]"#),
            (r#"[{"ifname":"up0"}]"#, r#"[{"dev":"up0"}]"#),
            (r#"[{"ifname":"eth0"}]"#, r#"[{"dev":"eth1"}]"#),
        ] {
            assert!(Scope::new(links, routes, "[]", routes).is_err());
        }
        let rules = scope.rules(false);
        assert!(
            !rules.contains(" drop") && !rules.contains(" reject") && !rules.contains("oifname !=")
        );
        assert_eq!(
            rules.matches("log prefix").count(),
            scope.judged.len() * 4 + 2
        );
    }
    #[test]
    fn control_is_separate_and_exemption_is_removed_for_case_window() {
        let mut scope = scope();
        scope.control_active = true;
        let control_rules = scope.rules(true);
        let case_rules = scope.rules(false);
        assert!(control_rules.contains("return comment \"positive-control\""));
        assert!(
            control_rules.find("positive-control").unwrap()
                < control_rules.find("judged:docker0").unwrap()
        );
        assert!(!case_rules.contains("positive-control"));
        let mut rules: Vec<_> = scope.selectors().map(|(c,i,f,d)| serde_json::json!({"rule":{"comment":format!("{c}:{i}:{f}:{d}"),"expr":[{"counter":{"packets":0}}]}})).collect();
        rules.push(serde_json::json!({"rule":{"comment":"positive-control","expr":[{"counter":{"packets":1}}]}}));
        rules.extend(["ip", "ip6"].map(|f| serde_json::json!({"rule":{"comment":format!("judged:prerouting:{f}:saddr"),"expr":[{"counter":{"packets":0}}]}})));
        let snapshot = |rules: &Vec<Value>| serde_json::json!({"nftables":rules}).to_string();
        let counts = count(&snapshot(&rules), &scope).unwrap();
        assert_eq!(counts["positive-control"], 1);
        assert!(
            counts
                .iter()
                .filter(|(k, _)| k.starts_with("judged:"))
                .all(|(_, n)| *n == 0)
        );
        scope.control_active = false;
        assert!(count(&snapshot(&rules), &scope).is_err());
        rules.remove(rules.len() - 3);
        rules[0]["rule"]["expr"][0]["counter"]["packets"] = 1.into();
        let counts = count(&snapshot(&rules), &scope).unwrap();
        assert_eq!(counts["judged:docker0:ip:saddr"], 1);
    }
    #[test]
    fn counts_require_complete_unique_attribution_and_keep_excluded_separate() {
        let scope = scope();
        let mut rules: Vec<_> = scope.selectors().map(|(c,i,f,d)| serde_json::json!({"rule":{"comment":format!("{c}:{i}:{f}:{d}"),"expr":[{"counter":{"packets":u64::from(c == "excluded")}}]}})).collect();
        rules.extend(["ip", "ip6"].map(|f| serde_json::json!({"rule":{"comment":format!("judged:prerouting:{f}:saddr"),"expr":[{"counter":{"packets":0}}]}})));
        let snapshot = |rules: &Vec<Value>| serde_json::json!({"nftables":rules}).to_string();
        let counts = count(&snapshot(&rules), &scope).unwrap();
        assert!(
            counts
                .iter()
                .filter(|(k, _)| k.starts_with("judged:"))
                .all(|(_, n)| *n == 0)
        );
        assert_eq!(counts["excluded:lo:ip:daddr"], 1);
        rules.push(rules[0].clone());
        assert!(count(&snapshot(&rules), &scope).is_err());
        rules.pop();
        rules.pop();
        assert!(count(&snapshot(&rules), &scope).is_err());
    }
}
