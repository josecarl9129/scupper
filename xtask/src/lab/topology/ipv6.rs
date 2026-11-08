//! IPv6 arrival, nft isolation and permissive controls.
use super::{A, Case, Lab, PERMISSIVE_RULES, Result, evidence, fail, helpers};
use crate::lab::addresses::V6_PATH;
use std::{fs, time::Duration};

impl Lab {
    pub(super) fn v6_fault(&mut self, markers: &mut Vec<String>) -> Result<()> {
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
            "client",
            "ip",
            &[
                "-6",
                "addr",
                "add",
                &format!("{}/64", A.client_link_local_v6),
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
                &format!(
                    "{}/32,{}/128,{}/128",
                    A.client_inner, A.client_v6, A.client_link_local_v6
                ),
            ],
        )?;
        self.v6_phase(markers, "original", false)?;
        self.v6_open_path()?;
        self.v6_phase(markers, "nft-only", false)?;
        self.runner.input(
            &crate::lab::command::Invocation::new("scupper", "nft", &["-f", "-"]),
            Some(PERMISSIVE_RULES),
        )?;
        self.cmd("scupper", "conntrack", &["-F"])?;
        self.v6_phase(markers, "permissive", true)
    }
    fn v6_open_path(&mut self) -> Result<()> {
        self.cmd(
            "scupper",
            "ip",
            &["-6", "route", "add", A.client_v6_net, "dev", "wg0"],
        )?;
        self.cmd(
            "scupper",
            "ip",
            &["-6", "route", "replace", "default", "dev", "ex-ch1"],
        )?;
        self.cmd(
            "scupper",
            "wg",
            &[
                "set",
                "ex-ch1",
                "peer",
                &self.public_keys[2].clone(),
                "allowed-ips",
                "0.0.0.0/0,::/0",
            ],
        )?;
        self.cmd(
            "provA",
            "wg",
            &[
                "set",
                "wgp",
                "peer",
                &self.public_keys[1].clone(),
                "allowed-ips",
                &format!("{}/32,::/0", A.exit_inner),
            ],
        )?;
        for (ns, iface, address) in V6_PATH {
            self.cmd(
                ns,
                "ip",
                &["-6", "addr", "add", address, "dev", iface, "nodad"],
            )?;
        }
        self.cmd(
            "provA",
            "ip",
            &["-6", "route", "add", "default", "via", "2001:db8:3::1"],
        )?;
        // De-NATed replies for the client prefix must go back through the tunnel.
        self.cmd(
            "provA",
            "ip",
            &["-6", "route", "add", A.client_v6_net, "dev", "wgp"],
        )?;
        for ns in ["wan", "provA"] {
            self.cmd(
                ns,
                "sysctl",
                &["-q", "-w", "net.ipv6.conf.all.forwarding=1"],
            )?;
        }
        self.runner.input(&crate::lab::command::Invocation::new("provA", "nft", &["-f", "-"]), Some(b"table ip6 lab_nat6 { chain postrouting { type nat hook postrouting priority srcnat; oifname \"eth0\" masquerade;\n\t}\n}\n"))?;
        Ok(())
    }
    fn v6_phase(&mut self, markers: &mut Vec<String>, phase: &str, permissive: bool) -> Result<()> {
        let stem = format!("{}-{phase}", Case::V6.name());
        for (ns, iface, suffix) in [
            ("scupper", "wg0", "ingress"),
            ("scupper", "ex-ch1", "exit"),
            ("provA", "wgp", "provider"),
            // Diagnostic only: where a permissive-phase IPv6 flow stops beyond the provider.
            ("provA", "eth0", "provider-uplink"),
            ("internet", "eth0", "internet"),
        ] {
            self.capture(ns, iface, &format!("{stem}-{suffix}"))?;
        }
        // These packets prove that all three capture instances see live traffic.
        self.service_check(markers)?;
        let mut trace = if permissive {
            None
        } else {
            self.runner.input(&crate::lab::command::Invocation::new("scupper", "nft", &["-f", "-"]), Some(b"table inet lab_trace { chain preraw { type filter hook prerouting priority -301; iifname \"wg0\" meta nfproto ipv6 meta nftrace set 1;\n\t}\n}\n"))?;
            Some(self.runner.background(
                &crate::lab::command::Invocation::new(
                    "scupper",
                    "stdbuf",
                    &["-oL", "nft", "monitor", "trace"],
                ),
                &self.artifacts.join(format!("{stem}.trace")),
            )?)
        };
        self.runner.dwell(Duration::from_secs(1))?;
        let sent = match self.canaries(markers, true, permissive) {
            Ok(sent) => sent,
            Err(error) => {
                let _ = self.v6_diagnostics(&stem);
                return Err(error);
            }
        };
        let mut sent = sent;
        if !permissive {
            let marker = Self::marker()?;
            markers.push(marker.clone());
            let outcome = self.send_from(
                "client",
                "udp",
                A.internet_v6,
                &marker,
                true,
                Some(A.client_link_local_v6),
            )?;
            if outcome != helpers::Outcome::TimedOut {
                return fail(format!("link-local probe: {outcome:?}"));
            }
            sent.push(marker);
        }
        self.service_check(markers)?;
        self.runner.dwell(Duration::from_secs(1))?;
        if let Some(trace) = &mut trace {
            trace.stop(rustix::process::Signal::TERM)?;
            self.cmd("scupper", "nft", &["delete", "table", "inet", "lab_trace"])?;
            let text = fs::read_to_string(self.artifacts.join(format!("{stem}.trace")))?;
            evidence::antispoof_trace(&text, &[A.client_v6, A.client_link_local_v6])?;
        }
        for _ in 0..5 {
            self.stop_capture()?;
        }
        self.v6_diagnostics(&stem)?;
        for suffix in ["ingress", "exit", "provider"] {
            let summary = evidence::v6_evidence(
                &fs::read(self.artifacts.join(format!("{stem}-{suffix}.pcap")))?,
                &sent,
                suffix == "ingress",
                permissive,
                A.client_link_local_v6,
            )?;
            fs::write(
                self.artifacts.join(format!("{stem}-{suffix}.evidence.txt")),
                summary,
            )?;
        }
        Ok(())
    }
    /// Diagnostic only: forwarding state of the IPv6 path after a phase.
    fn v6_diagnostics(&mut self, stem: &str) -> Result<()> {
        let mut parts = Vec::new();
        for (ns, args) in [
            ("wan", &["-6", "route", "show"][..]),
            ("wan", &["-6", "addr", "show"][..]),
            ("wan", &["-6", "neigh", "show"][..]),
            ("provA", &["-6", "route", "show"][..]),
            ("internet", &["-6", "addr", "show"][..]),
            ("internet", &["-6", "route", "show"][..]),
        ] {
            let out = self.cmd(ns, "ip", args).unwrap_or_else(|e| e.to_string());
            parts.push(format!("== {ns} ip {}\n{out}", args.join(" ")));
        }
        for ns in ["wan", "provA", "internet"] {
            let out = self
                .cmd(
                    ns,
                    "sysctl",
                    &[
                        "net.ipv6.conf.all.forwarding",
                        "net.ipv6.conf.all.disable_ipv6",
                    ],
                )
                .unwrap_or_else(|e| e.to_string());
            parts.push(format!("== {ns} sysctl\n{out}"));
            let out = self
                .cmd(ns, "nstat", &["-az"])
                .unwrap_or_else(|e| e.to_string());
            let keep: Vec<&str> = out.lines().filter(|l| l.contains("Ip6")).collect();
            parts.push(format!("== {ns} nstat Ip6\n{}", keep.join("\n")));
        }
        fs::write(
            self.artifacts.join(format!("{stem}.diag.txt")),
            parts.join("\n"),
        )?;
        Ok(())
    }
    pub(super) fn restore_v6(&mut self) -> Result<()> {
        let _ = self.runner.output(
            &crate::lab::command::Invocation::new(
                "scupper",
                "ip",
                &["-6", "route", "del", A.client_v6_net],
            ),
            None,
        )?;
        self.cmd(
            "client",
            "ip",
            &[
                "-6",
                "addr",
                "del",
                &format!("{}/64", A.client_link_local_v6),
                "dev",
                "wg0",
            ],
        )?;
        self.cmd(
            "scupper",
            "ip",
            &["-6", "route", "replace", "unreachable", "default"],
        )?;
        self.cmd(
            "scupper",
            "wg",
            &[
                "set",
                "ex-ch1",
                "peer",
                &self.public_keys[2].clone(),
                "allowed-ips",
                "0.0.0.0/0",
            ],
        )?;
        self.cmd(
            "provA",
            "wg",
            &[
                "set",
                "wgp",
                "peer",
                &self.public_keys[1].clone(),
                "allowed-ips",
                &format!("{}/32", A.exit_inner),
            ],
        )?;
        self.remove_v6_path()?;
        for ns in ["wan", "provA"] {
            self.cmd(
                ns,
                "sysctl",
                &["-q", "-w", "net.ipv6.conf.all.forwarding=0"],
            )?;
        }

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
        Ok(())
    }
    fn remove_v6_path(&mut self) -> Result<()> {
        // An early phase failure may precede these optional path additions.
        for (ns, iface, address) in V6_PATH {
            let _ = self.runner.output(
                &crate::lab::command::Invocation::new(
                    ns,
                    "ip",
                    &["-6", "addr", "del", address, "dev", iface],
                ),
                None,
            )?;
        }
        let _ = self.runner.output(
            &crate::lab::command::Invocation::new(
                "provA",
                "ip",
                &["-6", "route", "del", "default"],
            ),
            None,
        )?;
        let _ = self.runner.output(
            &crate::lab::command::Invocation::new(
                "provA",
                "ip",
                &["-6", "route", "del", A.client_v6_net, "dev", "wgp"],
            ),
            None,
        )?;
        let _ = self.runner.output(
            &crate::lab::command::Invocation::new(
                "provA",
                "nft",
                &["delete", "table", "ip6", "lab_nat6"],
            ),
            None,
        )?;
        Ok(())
    }
}
