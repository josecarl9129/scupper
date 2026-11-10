//! Case policies and durable, machine-readable results.
use super::{Result, addresses::A};
use crate::pcap::{Class, Policy, Reason, Report, classify};
use serde::{Deserialize, Serialize};
use std::{fmt::Write, fs, path::Path};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Case {
    Baseline,
    Daemon,
    ProbeChild,
    CheckV2,
    V6,
    Bridge,
    Permissive,
    Uplink,
}
impl Case {
    pub const ALL: [Self; 8] = [
        Self::Baseline,
        Self::ProbeChild,
        Self::CheckV2,
        Self::Daemon,
        Self::V6,
        Self::Bridge,
        Self::Permissive,
        Self::Uplink,
    ];
    pub fn name(self) -> &'static str {
        match self {
            Self::Baseline => "baseline",
            Self::Daemon => "daemon",
            Self::ProbeChild => "probe-child",
            Self::CheckV2 => "check-v2",
            Self::V6 => "client-v6-dropped",
            Self::Bridge => "bridged-real-ruleset",
            Self::Permissive => "positive-control-permissive",
            Self::Uplink => "positive-control-uplink",
        }
    }
    pub fn wanted(self) -> &'static str {
        match self {
            Self::Baseline => "clean",
            Self::Daemon => "measured L3/L4/L6/L7/L13/L16/L17/L52/V-03/V-14",
            Self::ProbeChild => "unprivileged-exit-dns",
            Self::CheckV2 => "0,3,0,2,0,4,0",
            Self::V6 => "v6-dropped",
            Self::Bridge => "bridge-contained",
            Self::Permissive | Self::Uplink => "leak-detected",
        }
    }
}
#[cfg(test)]
pub(super) fn policy(markers: &[String], auxiliary: bool) -> Result<String> {
    policy_with_exit_port(markers, auxiliary, 51821)
}
pub(super) fn policy_with_exit_port(
    markers: &[String],
    auxiliary: bool,
    exit_port: u16,
) -> Result<String> {
    let mut text = format!(
        "uplink_addrs = {}\nforbidden_addrs = {}\ncanary_markers = {}\narp = true\nndp = true\nmin_packets = {}\nexpect = {}\n",
        serde_json::to_string(&if auxiliary {
            vec![A.bridge.wan, A.bridge.peer, A.bridge_wan_v6, A.bridge_v6]
        } else {
            vec![A.gwhost.peer]
        })?,
        serde_json::to_string(&[
            A.client_net,
            A.exit_net,
            A.internet.peer,
            A.client_v6_net,
            A.internet_v6
        ])?,
        serde_json::to_string(markers)?,
        if auxiliary {
            2 * 2 + 2 // Two echo request/reply pairs plus an ARP request/reply.
        } else {
            markers.len().saturating_mul(4).max(1)
        },
        if auxiliary {
            "[\"arp\", \"host_allow[0]\", \"host_allow[1]\"]"
        } else {
            "[\"wireguard[0]\", \"wireguard[1]\"]"
        },
    );
    if auxiliary {
        write!(
            text,
            "\n[[host_allow]]\nproto = \"icmp\"\nremote_addr = \"{}\"\ntypes = [0, 8]\n",
            A.bridge.peer
        )?;
        write!(
            text,
            "\n[[host_allow]]\nproto = \"icmpv6\"\nremote_addr = \"{}\"\ntypes = [128, 129]\n",
            A.bridge_wan_v6
        )?;
    } else {
        for (local_port, remote, remote_port) in [
            (51820, A.client.peer, 51820),
            (exit_port, A.provider.peer, 51820),
        ] {
            write!(
                text,
                "\n[[wireguard]]\ngateway = \"{}:{local_port}\"\npeer = \"{remote}:{remote_port}\"\n",
                A.gwhost.peer
            )?;
        }
    }
    Policy::from_toml(&text)?;
    Ok(text)
}
pub(super) fn report(
    dir: &Path,
    stem: &str,
    markers: &[String],
    auxiliary: bool,
    port: u16,
) -> Result<Report> {
    let text = policy_with_exit_port(markers, auxiliary, port)?;
    fs::write(dir.join(format!("{stem}.policy.toml")), &text)?;
    let report = classify(
        &fs::read(dir.join(format!("{stem}.pcap")))?,
        &Policy::from_toml(&text)?,
        30,
    )?;
    fs::write(
        dir.join(format!("{stem}.report.json")),
        serde_json::to_vec_pretty(&report)?,
    )?;
    Ok(report)
}
pub(super) fn leak_seen(report: &Report) -> bool {
    report.packets.iter().any(|packet| {
        matches!(
            packet.class,
            Class::Violation(Reason::CanaryMarker | Reason::ForbiddenAddress { .. })
        )
    })
}
pub(super) fn contained(report: &Report) -> bool {
    report.violation_count == 0 && report.capture_failures.is_empty()
}

pub(super) fn injected_only(report: &Report, bytes: &[u8], marker: &str) -> Result<()> {
    use crate::pcap::{Location, observe};
    let expected = super::helpers::injection_packets(marker)?;
    let observed = observe(bytes)?;
    if report.violation_count != expected.len() || !report.capture_failures.is_empty() {
        return super::fail("uplink control: unexpected violation count or capture failure");
    }
    let mut seen = vec![false; expected.len()];
    for packet in &report.packets {
        let Class::Violation(reason) = &packet.class else {
            continue;
        };
        let actual = observed
            .iter()
            .find(|p| p.index == packet.index)
            .ok_or("violation is not an injected IP packet")?;
        let found = expected
            .iter()
            .position(|raw| {
                actual.source.to_string()
                    == std::net::Ipv4Addr::new(raw[12], raw[13], raw[14], raw[15]).to_string()
                    && actual.destination.to_string()
                        == std::net::Ipv4Addr::new(raw[16], raw[17], raw[18], raw[19]).to_string()
                    && actual.protocol == 17
                    && actual.payload == raw[20..]
            })
            .ok_or("uplink control: unrelated violation")?;
        let wanted = if found == 0 {
            Reason::ForbiddenAddress {
                addr: A.client_inner.parse()?,
                location: Location::Outer,
            }
        } else {
            Reason::CanaryMarker
        };
        if seen[found] || *reason != wanted {
            return super::fail("uplink control: duplicate packet or wrong violation reason");
        }
        seen[found] = true;
    }
    if !seen.iter().all(|seen| *seen) {
        return super::fail("uplink control: injected packet missing");
    }
    Ok(())
}

// Every v6 capture also carries a complete healthy IPv4 service check.
pub(super) fn v6_evidence(
    bytes: &[u8],
    markers: &[String],
    ingress: bool,
    permissive: bool,
    link_local: &str,
) -> Result<String> {
    if !matches!(markers.len(), 4 | 5) {
        return super::fail("incorrect IPv6 canary manifest");
    }
    let packets = crate::pcap::observe(bytes)?;
    let v4 = packets
        .iter()
        .filter(|p| p.source.is_ipv4() && p.destination.to_string() == A.internet.peer)
        .count();
    let v6: Vec<_> = packets.iter().filter(|p| p.source.is_ipv6()).collect();
    if v4 < 4 {
        return super::fail("IPv6 capture has no IPv4 liveness evidence");
    }
    if ingress {
        let tcp_ports: std::collections::BTreeSet<_> = v6
            .iter()
            .filter(|p| {
                p.source.to_string() == A.client_v6
                    && p.destination.to_string() == A.internet_v6
                    && p.protocol == 6
            })
            .filter_map(|p| p.payload.get(..2))
            .collect();
        if tcp_ports.len() < 2 {
            return super::fail("IPv6 TCP attempts missing at wg0");
        }
        for (i, marker) in markers.iter().enumerate() {
            let source = if i == 4 { link_local } else { A.client_v6 };
            let protocol = if i < 2 { 6 } else { 17 };
            if !v6.iter().any(|p| {
                p.source.to_string() == source
                    && p.destination.to_string() == A.internet_v6
                    && p.protocol == protocol
                    && (protocol == 6
                        || p.payload
                            .windows(marker.len())
                            .any(|w| w == marker.as_bytes()))
            }) {
                return super::fail(format!(
                    "IPv6 canary missing at wg0: {source} {protocol} {marker}"
                ));
            }
        }
    } else if permissive {
        for marker in &markers[2..4] {
            if !v6.iter().any(|p| {
                p.destination.to_string() == A.internet_v6
                    && p.protocol == 17
                    && p.payload
                        .windows(marker.len())
                        .any(|w| w == marker.as_bytes())
            }) {
                return super::fail("IPv6 positive control was blind");
            }
        }
    } else if !v6.is_empty() {
        return super::fail("IPv6 handed to exit/provider");
    }
    Ok(format!(
        "ipv4_liveness={v4}, ipv6_records={}, markers_checked={}",
        v6.len(),
        markers.len()
    ))
}
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(super) struct Row {
    pub name: String,
    pub wanted: String,
    pub got: String,
    pub detail: String,
}
pub(super) fn save_results(dir: &Path, rows: &[Row]) -> Result<()> {
    let mut tsv = "name\twanted\tgot\tdetail\n".to_owned();
    for row in rows {
        let cells = [&row.name, &row.wanted, &row.got, &row.detail]
            .map(|s| s.replace(['\t', '\n', '\r'], " "));
        tsv.push_str(&cells.join("\t"));
        tsv.push('\n');
    }
    fs::write(dir.join("results.tsv"), tsv)?;
    fs::write(dir.join("results.json"), serde_json::to_vec_pretty(rows)?)?;
    Ok(())
}

// A running tcpdump with a readable pcap is insufficient if its socket lost
// packets. Require its normal shutdown statistics and zero reported loss.
pub(super) fn check_capture_stats(stderr: &str) -> Result<()> {
    let mut kernel_stats = false;
    for line in stderr.lines() {
        if line.ends_with("packets dropped by kernel")
            || line.ends_with("packets dropped by interface")
        {
            let count = line
                .split_whitespace()
                .next()
                .ok_or("missing capture drop count")?
                .parse::<u64>()?;
            if count != 0 {
                return super::fail("tcpdump reported dropped packets");
            }
            if line.ends_with("packets dropped by kernel") {
                kernel_stats = true;
            }
        }
    }
    if !kernel_stats {
        return super::fail("tcpdump shutdown statistics missing");
    }
    Ok(())
}

pub(super) fn antispoof_trace(text: &str, sources: &[&str]) -> Result<()> {
    for source in sources {
        let ids: Vec<_> = text
            .lines()
            .filter(|line| line.contains(&format!("ip6 saddr {source} ")))
            .filter_map(|line| line.split_whitespace().nth(2))
            .collect();
        if !ids.iter().any(|id| {
            text.lines().any(|line| {
                line.split_whitespace().nth(2) == Some(*id)
                    && line.contains(" inet scupper antispoof ")
                    && line.contains("(verdict drop)")
            })
        }) {
            return super::fail(format!("no antispoof drop trace for {source}"));
        }
    }
    Ok(())
}

/// Prefixes permit `WireGuard` transport and host ICMP port-unreachable errors
/// before the client socket exists. Quoted plaintext remains forbidden. Open-gate
/// prefixes also require a provider data message, beyond handshake traffic.
pub(super) fn boot_prefix(
    dir: &Path,
    stem: &str,
    markers: &[String],
    port: u16,
    provider: bool,
) -> Result<()> {
    let base = policy_with_exit_port(markers, false, port)?;
    let base = base
        .lines()
        .map(|line| {
            if line.starts_with("min_packets = ") {
                "min_packets = 1"
            } else if line.starts_with("expect = ") {
                if provider {
                    "expect = [\"wireguard[0]\", \"wireguard[1]\"]"
                } else {
                    "expect = [\"wireguard[0]\"]"
                }
            } else {
                line
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    let text = format!(
        "{base}\n[[host_allow]]\nproto = \"icmp\"\nremote_addr = \"{}\"\ntypes = [3]\n",
        A.client.peer
    );
    fs::write(dir.join(format!("{stem}.policy.toml")), &text)?;
    let policy_with_icmp = Policy::from_toml(&text)?;
    let pcap = fs::read(dir.join(format!("{stem}.pcap")))?;
    let report = classify(&pcap, &policy_with_icmp, 30)?;
    fs::write(
        dir.join(format!("{stem}.report.json")),
        serde_json::to_vec_pretty(&report)?,
    )?;
    if report.violation_count != 0 || !report.capture_failures.is_empty() {
        return super::fail(format!("boot prefix oracle: {report:?}"));
    }
    if provider
        && !crate::pcap::observe(&pcap)?.iter().any(|p| {
            p.source.to_string() == A.gwhost.peer
                && p.destination.to_string() == A.provider.peer
                && p.protocol == 17
                && p.payload.get(8..12) == Some(&[4, 0, 0, 0])
        })
    {
        return super::fail("boot prefix lacks encrypted provider data positive control");
    }
    Ok(())
}
