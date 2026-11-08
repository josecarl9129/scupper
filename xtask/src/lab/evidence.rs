//! Case policies and durable, machine-readable results.
use super::{Result, addresses::A};
use crate::pcap::{Class, Policy, Reason, Report, classify};
use serde::{Deserialize, Serialize};
use std::{fmt::Write, fs, path::Path};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Case {
    Baseline,
    V6,
    Bridge,
    Permissive,
    Uplink,
}
impl Case {
    pub const ALL: [Self; 5] = [
        Self::Baseline,
        Self::V6,
        Self::Bridge,
        Self::Permissive,
        Self::Uplink,
    ];
    pub fn name(self) -> &'static str {
        match self {
            Self::Baseline => "baseline",
            Self::V6 => "client-v6-dropped",
            Self::Bridge => "bridged-real-ruleset",
            Self::Permissive => "positive-control-permissive",
            Self::Uplink => "positive-control-uplink",
        }
    }
    pub fn wanted(self) -> &'static str {
        match self {
            Self::Baseline => "clean",
            Self::V6 => "v6-dropped",
            Self::Bridge => "bridge-contained",
            Self::Permissive | Self::Uplink => "leak-detected",
        }
    }
}
pub(super) fn policy(markers: &[String], auxiliary: bool) -> Result<String> {
    let mut text = format!(
        "uplink_addrs = {}\nforbidden_addrs = {}\ncanary_markers = {}\narp = true\nndp = true\nmin_packets = {}\nexpect = {}\n",
        serde_json::to_string(&if auxiliary {
            vec![A.bridge.wan, A.bridge.peer]
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
        if auxiliary { 1 } else { 16 },
        if auxiliary {
            "[]"
        } else {
            "[\"wireguard[0]\", \"wireguard[1]\"]"
        },
    );
    if !auxiliary {
        for (local_port, remote, remote_port) in [
            (51820, A.client.peer, 51820),
            (51821, A.provider.peer, 51820),
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
) -> Result<Report> {
    let text = policy(markers, auxiliary)?;
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
// A monitored auxiliary interface may legitimately be silent. Container errors
// still fail in classify; only its explicit, sole EmptyCapture failure is expected.
pub(super) fn contained(report: &Report) -> bool {
    report.violation_count == 0
        || (report.packet_count == 0 && report.capture_failures == [Reason::EmptyCapture])
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
