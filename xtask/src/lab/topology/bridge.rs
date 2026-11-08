//! Preferred bridge paths with in-case liveness and leak controls.
use super::{A, Case, Lab, PERMISSIVE_RULES, Result, fail, helpers};
use crate::lab::command::Invocation;
use std::{
    fs,
    time::{Duration, Instant},
};

impl Lab {
    pub(super) fn bridge_fault(&mut self, case: Case, markers: &mut Vec<String>) -> Result<()> {
        self.bridge_setup(case)?;
        self.bridge_liveness(case)?;
        for ipv6 in [false, true] {
            self.bridge_canaries(case, markers, ipv6)?;
        }
        Ok(())
    }
    fn bridge_setup(&mut self, case: Case) -> Result<()> {
        self.veth(A.bridge, "lab-bridge")?;
        self.apply_sysctls(true, true)?;
        // Unicast probes use static IPv6 neighbours below. Avoid incidental MLD
        // from links without automatic link-local addresses in this capture.
        for (ns, iface) in [("scupper", "lab-bridge"), ("wan", A.bridge.wan_if)] {
            self.cmd(ns, "ip", &["link", "set", "dev", iface, "multicast", "off"])?;
        }
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
        for (ns, iface, address) in [
            ("scupper", "lab-bridge", A.bridge_v6),
            ("wan", A.bridge.wan_if, A.bridge_wan_v6),
        ] {
            self.cmd(
                ns,
                "ip",
                &[
                    "-6",
                    "addr",
                    "add",
                    &format!("{address}/64"),
                    "dev",
                    iface,
                    "nodad",
                ],
            )?;
        }
        self.cmd(
            "wan",
            "sysctl",
            &["-q", "-w", "net.ipv6.conf.all.forwarding=1"],
        )?;
        self.bridge_routes(case)?;
        self.bridge_neighbors()?;
        self.capture("wan", A.bridge.wan_if, &format!("{}-bridge", case.name()))?;
        if case == Case::Permissive {
            self.runner.input(
                &Invocation::new("scupper", "nft", &["-f", "-"]),
                Some(PERMISSIVE_RULES),
            )?;
        } else {
            // Admit the source through antispoof to exercise the IPv6 forward chain.
            self.cmd(
                "scupper",
                "nft",
                &[
                    "add",
                    "element",
                    "inet",
                    "scupper",
                    "client_nets6",
                    &format!("{{ {} }}", A.client_v6),
                ],
            )?;
        }
        Ok(())
    }
    fn bridge_routes(&mut self, case: Case) -> Result<()> {
        self.cmd(
            "scupper",
            "ip",
            &["-6", "route", "add", A.client_v6_net, "dev", "wg0"],
        )?;
        for (family, sink, source, via, client_net, back) in [
            (
                "-4",
                A.internet.peer,
                A.client_inner,
                A.bridge.wan,
                A.client_net,
                A.bridge.peer,
            ),
            (
                "-6",
                A.internet_v6,
                A.client_v6,
                A.bridge_wan_v6,
                A.client_v6_net,
                A.bridge_v6,
            ),
        ] {
            self.cmd(
                "scupper",
                "ip",
                &[
                    family,
                    "route",
                    "add",
                    &format!("{sink}/{}", if family == "-4" { 32 } else { 128 }),
                    "via",
                    via,
                    "dev",
                    "lab-bridge",
                ],
            )?;
            self.cmd(
                "wan",
                "ip",
                &[
                    family,
                    "route",
                    "add",
                    client_net,
                    "via",
                    back,
                    "dev",
                    A.bridge.wan_if,
                ],
            )?;
            let route = self.cmd(
                "scupper",
                "ip",
                &[family, "route", "get", sink, "from", source, "iif", "wg0"],
            )?;
            if !route
                .split_whitespace()
                .collect::<Vec<_>>()
                .windows(2)
                .any(|w| w == ["dev", "lab-bridge"])
            {
                return fail("bridge route lookup did not select lab-bridge");
            }
            fs::write(
                self.artifacts
                    .join(format!("{}-route{family}.txt", case.name())),
                route,
            )?;
        }
        Ok(())
    }
    fn bridge_neighbors(&mut self) -> Result<()> {
        // Static v6 neighbours let the ICMP-only liveness exception stay narrow.
        for (local_ns, local_iface, remote_ns, remote_iface, address) in [
            (
                "scupper",
                "lab-bridge",
                "wan",
                A.bridge.wan_if,
                A.bridge_wan_v6,
            ),
            ("wan", A.bridge.wan_if, "scupper", "lab-bridge", A.bridge_v6),
        ] {
            let links: serde_json::Value = serde_json::from_str(&self.cmd(
                remote_ns,
                "ip",
                &["-j", "link", "show", "dev", remote_iface],
            )?)?;
            let mac = links[0]["address"].as_str().ok_or("bridge MAC missing")?;
            self.cmd(
                local_ns,
                "ip",
                &[
                    "-6",
                    "neigh",
                    "replace",
                    address,
                    "lladdr",
                    mac,
                    "nud",
                    "permanent",
                    "dev",
                    local_iface,
                ],
            )?;
        }
        Ok(())
    }
    fn bridge_liveness(&mut self, case: Case) -> Result<()> {
        for (family, address, wan, icmp) in [
            ("-4", A.bridge.peer, A.bridge.wan, "icmp"),
            ("-6", A.bridge_v6, A.bridge_wan_v6, "icmpv6"),
        ] {
            if case == Case::Bridge {
                self.cmd(
                    "scupper",
                    "nft",
                    &[
                        "insert",
                        "rule",
                        "inet",
                        "scupper",
                        "output",
                        "oifname",
                        "lab-bridge",
                        if family == "-4" { "ip" } else { "ip6" },
                        "saddr",
                        address,
                        if family == "-4" { "ip" } else { "ip6" },
                        "daddr",
                        wan,
                        icmp,
                        "type",
                        "echo-request",
                        "accept",
                    ],
                )?;
            }
            if family == "-4" {
                self.cmd(
                    "scupper",
                    "ip",
                    &[family, "neigh", "flush", "dev", "lab-bridge"],
                )?;
            }
            self.cmd("scupper", "ping", &[family, "-c1", "-W2", wan])?;
        }
        self.runner.dwell(Duration::from_secs(1))
    }
    fn bridge_canaries(&mut self, case: Case, markers: &mut Vec<String>, ipv6: bool) -> Result<()> {
        let sent = self.canaries(markers, ipv6, case == Case::Permissive)?;
        let marker = Self::marker()?;
        markers.push(marker.clone());
        let success = self.send(
            "scupper",
            "udp",
            if ipv6 { A.internet_v6 } else { A.internet.peer },
            &marker,
            ipv6,
        )?;
        let expected = if case == Case::Permissive {
            helpers::Outcome::Delivered
        } else {
            helpers::Outcome::LocalReject(1)
        };
        if success != expected {
            return fail(format!(
                "bridge output wanted {expected:?}, got {success:?}"
            ));
        }
        self.runner.dwell(Duration::from_secs(1))?;
        let receipts = helpers::receipts(&fs::read_to_string(self.artifacts.join("sink.jsonl"))?)?;
        if case == Case::Bridge
            && receipts
                .iter()
                .any(|r| sent.contains(&r.marker) || r.marker == marker)
        {
            return fail("real ruleset leaked a bridge marker");
        }
        if case == Case::Permissive {
            for m in &sent {
                let matches: Vec<_> = receipts.iter().filter(|r| r.marker == *m).collect();
                if matches.len() != 1
                    || matches[0].peer.ip().to_string()
                        != if ipv6 { A.client_v6 } else { A.client_inner }
                {
                    return fail("permissive bridge did not deliver client markers without NAT");
                }
            }
        }
        Ok(())
    }
    pub(super) fn restore_bridge(&mut self) -> Result<()> {
        self.cmd("scupper", "ip", &["-6", "route", "del", A.client_v6_net])?;
        self.cmd(
            "scupper",
            "ip",
            &["route", "del", &format!("{}/32", A.internet.peer)],
        )?;
        self.cmd(
            "scupper",
            "ip",
            &["-6", "route", "del", &format!("{}/128", A.internet_v6)],
        )?;
        self.cmd("wan", "ip", &["route", "del", A.client_net])?;
        self.cmd("wan", "ip", &["-6", "route", "del", A.client_v6_net])?;
        self.cmd("wan", "ip", &["link", "delete", A.bridge.wan_if])?;
        self.cmd(
            "wan",
            "sysctl",
            &["-q", "-w", "net.ipv6.conf.all.forwarding=0"],
        )?;
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
        let until = Instant::now() + Duration::from_secs(3);
        while self
            .runner
            .output(
                &Invocation::new("scupper", "ip", &["link", "show", "dev", "lab-bridge"]),
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
        Ok(())
    }
}
