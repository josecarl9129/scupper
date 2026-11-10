//! L19 historical-fault subtrials and strict expectation inversion.
use super::{A, Invocation, Lab, Result, fail};
use crate::pcap::{Class, Policy, Reason, classify, observe};
use scupper_core::{
    config::GatewayId,
    lab_mutation::{Mutation, active},
    verdict::v2::{HealthConfigV2, NetnsIdentity, RouteAnswer},
};
use serde::{Deserialize, Serialize};
use std::{fs, path::Path, time::Duration};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) enum CatchReason {
    GatewayLocalOnExit,
    ForbiddenAddress,
    RouteStageMissed,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[error("{mutation} caught by {case}: {reason:?}")]
pub(super) struct Caught {
    mutation: String,
    case: String,
    reason: CatchReason,
    evidence: Option<Evidence>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Evidence {
    golden_diff: String,
    live: serde_json::Value,
    observation: serde_json::Value,
}
fn golden(mutation: Mutation) -> &'static str {
    match mutation {
        Mutation::Src => include_str!("../../../tests/golden/M-src.diff"),
        Mutation::Ct => include_str!("../../../tests/golden/M-ct.diff"),
        Mutation::Out => include_str!("../../../tests/golden/M-out.diff"),
        Mutation::Probe => include_str!("../../../tests/golden/M-probe.diff"),
    }
}
fn expected(mutation: Mutation) -> Caught {
    let (case, reason) = match mutation {
        Mutation::Src => ("L2-provenance", CatchReason::GatewayLocalOnExit),
        Mutation::Ct => ("L3-established-bridge", CatchReason::ForbiddenAddress),
        Mutation::Out => ("L4-local-output-bridge", CatchReason::ForbiddenAddress),
        Mutation::Probe => ("L6-route-stage", CatchReason::RouteStageMissed),
    };
    Caught {
        mutation: mutation.name().into(),
        case: case.into(),
        reason,
        evidence: None,
    }
}
fn observed_catch(
    mutation: Mutation,
    live: serde_json::Value,
    observation: serde_json::Value,
) -> Result<Caught> {
    let (case, reason) = if observation["check"]["verdict"].get("Protected").is_some() {
        ("L6-route-stage", CatchReason::RouteStageMissed)
    } else if observation["source"] == A.gateway_inner
        && observation["packet_index"].as_u64().is_some_and(|n| n > 0)
    {
        ("L2-provenance", CatchReason::GatewayLocalOnExit)
    } else if observation["report"]["packets"]
        .as_array()
        .is_some_and(|a| {
            a.iter()
                .any(|p| !p["class"]["Violation"]["ForbiddenAddress"].is_null())
        })
    {
        let case = match observation["capture"].as_str() {
            Some("L19-L3.pcap") => "L3-established-bridge",
            Some("L19-L4.pcap") => "L4-local-output-bridge",
            _ => return fail("observed violation lacks a known capture"),
        };
        (case, CatchReason::ForbiddenAddress)
    } else {
        return fail("no typed observed mutation violation");
    };
    Ok(Caught {
        mutation: mutation.name().into(),
        case: case.into(),
        reason,
        evidence: Some(Evidence {
            golden_diff: golden(mutation).into(),
            live,
            observation,
        }),
    })
}

fn evidence_matches(mutation: Mutation, e: &Evidence) -> bool {
    let o = &e.observation;
    match mutation {
        Mutation::Ct | Mutation::Out => {
            !e.live["actual"].is_null()
                && e.live["actual"] == e.live["expected"]
                && e.live["actual"] != e.live["control"]
                && if mutation == Mutation::Ct {
                    o["destination"] == A.client_inner
                        && o["source"] == A.internet.peer
                        && o["established"]["reconciliation_frozen"] == true
                        && o["established"]["provider_nat"] == true
                        && o["established"]["source_port"]
                            .as_u64()
                            .and_then(|p| u16::try_from(p).ok())
                            .filter(|p| *p > 0)
                            .is_some_and(|port| {
                                o["established"]["tuple"] == serde_json::json!(udp_nat_tuple(port))
                            })
                } else {
                    o["destination"] == A.internet.peer
                }
                && o["packet_index"].as_u64().is_some_and(|n| n > 0)
                && o["marker"].as_str().is_some_and(|m| !m.is_empty())
                && o["report"]["packets"].as_array().is_some_and(|a| {
                    a.iter().any(|p| {
                        p["index"] == o["packet_index"]
                            && !p["class"]["Violation"]["ForbiddenAddress"].is_null()
                    })
                })
        }
        Mutation::Src => {
            o["packet_index"].as_u64().is_some_and(|n| n > 0)
                && o["source"] == A.gateway_inner
                && o["destination"] == A.client_inner
                && o["source_selector"] == A.client_net
                && o["live_rule"]["iif"].is_null()
        }
        Mutation::Probe => {
            o["check"]["verdict"].get("Protected").is_some()
                && o["route_fault_live"] == true
                && o["defaults_intact"] == true
                && o["routes_observed"] == false
                && o["defaults_observed"] == true
                && !o["defaults_before"].is_null()
                && o["defaults_before"] == o["defaults_after"]
                && o["client_routes"].as_array().is_some_and(|routes| {
                    !routes.is_empty() && routes.iter().all(|r| r["v4"]["Ok"] == "Unreachable")
                })
                && behavior(&o["control"])
                    .and_then(|control| Ok(format!("-{control}\n+{}\n", behavior(&o["observed"])?)))
                    .is_ok_and(|diff| diff == e.golden_diff)
        }
    }
}
fn invert(mutation: Mutation, failed: bool, caught: Option<&Caught>) -> Result<()> {
    let valid = caught.is_some_and(|caught| {
        let expected = expected(mutation);
        caught.mutation == expected.mutation
            && caught.case == expected.case
            && caught.reason == expected.reason
            && caught
                .evidence
                .as_ref()
                .is_some_and(|e| e.golden_diff == golden(mutation) && evidence_matches(mutation, e))
    });
    if failed && valid {
        Ok(())
    } else {
        fail(format!(
            "{} was not caught for the expected reason: failed={failed}, caught={caught:?}",
            mutation.name()
        ))
    }
}

/// Run a healthy control and a feature-selected mutant in separate processes.
/// Only a typed policy/check violation surviving cleanup counts as a catch.
///
/// # Errors
/// Rejects default builds, control failures, unrelated failures, or uncaught faults.
pub fn run_mutation(artifacts: &Path, mutation: Mutation) -> Result<()> {
    if !cfg!(feature = "lab-mutation") {
        return fail("--mutation requires the testing-only lab-mutation feature");
    }
    fs::create_dir_all(artifacts)?;
    for stage in ["control", "mutant"] {
        if artifacts.join(stage).exists() {
            return fail(format!(
                "refusing existing mutation artifacts {}",
                artifacts.join(stage).display()
            ));
        }
    }
    for (stage, mutant) in [("control", false), ("mutant", true)] {
        let directory = artifacts.join(stage);
        // Stale successful evidence must never satisfy a new run.
        if directory.exists() {
            return fail(format!(
                "refusing existing mutation artifacts {}",
                directory.display()
            ));
        }
        // Give each stage its own full budget, including namespace cleanup.
        let mut command = std::process::Command::new("timeout");
        command
            .arg("600")
            .arg(std::env::current_exe()?)
            .args(["leaktest", "--case", "L19", "--artifacts"])
            .arg(&directory);
        command.env_remove("SCUPPER_LAB_MUTATION");
        if mutant {
            command.env("SCUPPER_LAB_MUTATION", mutation.name());
        }
        let status = command.status()?;
        if !mutant && !status.success() {
            return fail("unmutated L19 control failed");
        }
        if mutant {
            let caught = match fs::read(directory.join("caught.json")) {
                Ok(bytes) => Some(serde_json::from_slice::<Caught>(&bytes)?),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
                Err(e) => return Err(e.into()),
            };
            let result = invert(mutation, status.code() == Some(1), caught.as_ref());
            fs::write(
                artifacts.join("mutation-report.json"),
                serde_json::to_vec_pretty(&serde_json::json!({
                    "mutation": mutation.name(), "selected_case": "L19", "expected": expected(mutation),
                    "caught": caught, "passed": result.is_ok(), "status": status.code(),
                }))?,
            )?;
            result?;
            println!("{}", caught.ok_or("missing catch after inversion")?);
        }
    }
    Ok(())
}

impl Lab {
    pub(super) fn meta_case(&mut self) -> Result<String> {
        let selected = active().map_or_else(|| Mutation::ALL.to_vec(), |m| vec![m]);
        for mutation in selected {
            let live = self.meta_live_rules()?;
            let caught = match mutation {
                Mutation::Src => self.meta_source(),
                Mutation::Ct | Mutation::Out => self.meta_bridge(mutation),
                Mutation::Probe => self.meta_probe(),
            }?;
            if let Some(observation) = caught {
                return Err(observed_catch(mutation, live, observation)?.into());
            }
        }
        Ok("L2 provenance; L3 established forwarding; L4 local output; L6 route stage all protected".into())
    }

    fn meta_live_rules(&mut self) -> Result<serde_json::Value> {
        let live = self.cmd("scupper", "nft", &["-j", "list", "ruleset"])?;
        let canonical = scupper_core::canon::canonicalize(&live)?;
        fs::write(self.artifacts.join("L19-live-rules.json"), &live)?;
        #[cfg(feature = "lab-mutation")]
        if let Some(mutation @ (Mutation::Ct | Mutation::Out)) = active() {
            use scupper_core::render::{VersionStamp, render_netns_unmutated};
            let control = render_netns_unmutated(
                &self.site,
                &GatewayId("gw1".into()),
                &VersionStamp {
                    version: 1,
                    sha256: [0; 32],
                },
            )?;
            let changed = apply_golden(&control, golden(mutation))?;
            let path = self.private.join("meta-golden.nft");
            fs::write(&path, &changed)?;
            // Independent nft parse of the control plus exactly the reviewed diff.
            self.cmd("", "ip", &["netns", "add", "scupper-verify"])?;
            let resource = super::cleanup::Resource::Namespace("scupper-verify".into());
            self.registry.register(resource.clone());
            let checked = (|| {
                let control_path = self.private.join("meta-control.nft");
                fs::write(&control_path, &control)?;
                self.cmd(
                    "scupper-verify",
                    "nft",
                    &["-f", &control_path.to_string_lossy()],
                )?;
                let control_canonical = scupper_core::canon::canonicalize(&self.cmd(
                    "scupper-verify",
                    "nft",
                    &["-j", "list", "ruleset"],
                )?)?;
                self.cmd("scupper-verify", "nft", &["-f", &path.to_string_lossy()])?;
                let expected = scupper_core::canon::canonicalize(&self.cmd(
                    "scupper-verify",
                    "nft",
                    &["-j", "list", "ruleset"],
                )?)?;
                if expected == canonical && canonical != control_canonical {
                    Ok(
                        serde_json::json!({"control":control_canonical,"expected":expected,"actual":canonical}),
                    )
                } else {
                    fail("mutation not live or differs beyond golden")
                }
            })();
            let cleanup = self
                .cmd("", "ip", &["netns", "delete", "scupper-verify"])
                .map(|_| ());
            if cleanup.is_ok() {
                self.registry.unregister(&resource);
            }
            return finish(checked, cleanup);
        }
        Ok(canonical)
    }

    fn meta_drop_counter(&mut self) -> Result<u64> {
        let json = self.cmd(
            "scupper",
            "nft",
            &["-j", "list", "counter", "inet", "scupper", "fwd_dropped"],
        )?;
        let value: serde_json::Value = serde_json::from_str(&json)?;
        value["nftables"]
            .as_array()
            .and_then(|a| a.iter().find_map(|e| e["counter"]["packets"].as_u64()))
            .ok_or_else(|| "missing fwd_dropped counter".into())
    }

    fn meta_source(&mut self) -> Result<Option<serde_json::Value>> {
        let trial = (|| {
            self.cmd(
                "scupper",
                "ip",
                &["route", "add", "table", "191", "default", "dev", "ex-ch1"],
            )?;
            let baseline = self.cmd("scupper", "ip", &["-j", "rule", "show"])?;
            let args = super::policy_fixture::policy_rule(A.client_net);
            fs::write(self.artifacts.join("L19-L2-policy.txt"), args.join(" "))?;
            self.cmd(
                "scupper",
                "ip",
                &args.iter().map(String::as_str).collect::<Vec<_>>(),
            )?;
            let live = self.cmd("scupper", "ip", &["-j", "rule", "show"])?;
            fs::write(self.artifacts.join("L19-L2-rules.json"), &live)?;
            let rules: serde_json::Value = serde_json::from_str(&live)?;
            let rule = rules
                .as_array()
                .and_then(|a| a.iter().find(|r| r["priority"] == 191))
                .ok_or("M-src fixture rule not live")?;
            let expected = if active() == Some(Mutation::Src) {
                serde_json::json!({"priority":191,"src":"10.99.0.0","srclen":24,"table":191})
            } else {
                serde_json::json!({"priority":191,"src":"all","iif":"wg0","table":191})
            };
            if !rules_equal(&serde_json::json!([rule]), &serde_json::json!([expected]))? {
                return fail(format!("M-src live rule differs: {rule}"));
            }
            let parsed =
                scupper_core::parse::parse_ip_rule(&serde_json::json!([rule]).to_string())?;
            let source_selector = parsed
                .first()
                .and_then(|r| r.src)
                .map_or_else(|| "all".into(), |net| net.to_string());
            let mut remainder = rules.as_array().ok_or("invalid live policy rules")?.clone();
            remainder.retain(|r| r["priority"] != 191);
            if serde_json::Value::Array(remainder)
                != serde_json::from_str::<serde_json::Value>(&baseline)?
            {
                return fail("M-src changed rules beyond the golden fixture diff");
            }
            self.capture("scupper", "wg0", "L19-L2-wg0")?;
            self.capture("scupper", "ex-ch1", "L19-L2-exit")?;
            let (status, _) = self.runner.output(
                &Invocation::new(
                    "client",
                    "ping",
                    &["-n", "-c", "2", "-W", "1", A.gateway_inner],
                ),
                None,
            )?;
            if !matches!(status.code(), Some(0 | 1)) {
                return fail("L2 ping harness failure");
            }
            self.service_check(&mut Vec::new())?;
            self.stop_captures()?;
            let wg = fs::read(self.artifacts.join("L19-L2-wg0.pcap"))?;
            let exit = fs::read(self.artifacts.join("L19-L2-exit.pcap"))?;
            let request = crate::pcap::path::Flow {
                source: A.client_inner.parse()?,
                destination: A.gateway_inner.parse()?,
                protocol: 1,
                ports: None,
            };
            crate::pcap::path::attempted(&wg, &[request])?;
            // A missing echo alone cannot be a mutation catch: require the
            // misdirected gateway reply on the decrypted exit capture.
            let packets = observe(&exit)?;
            let misplaced = packets.iter().find(|p| {
                p.source.to_string() == A.gateway_inner
                    && p.destination.to_string() == A.client_inner
                    && p.protocol == 1
                    && p.payload.first() == Some(&0)
            });
            if let Some(packet) = misplaced {
                return Ok(Some(
                    serde_json::json!({"capture":"L19-L2-exit.pcap", "packet_index":packet.index,"source": A.gateway_inner, "destination": A.client_inner, "baseline_rules": serde_json::from_str::<serde_json::Value>(&baseline)?, "live_rule":rule,"source_selector":source_selector,"live_rules":rules}),
                ));
            }
            crate::pcap::path::gateway(
                &wg,
                &exit,
                A.gateway_inner.parse()?,
                A.client_inner.parse()?,
            )?;
            Ok(None)
        })();
        let cleanup = cleanup_results([
            self.stop_captures(),
            self.cmd("scupper", "ip", &["rule", "del", "pref", "191"])
                .map(|_| ()),
            self.cmd("scupper", "ip", &["route", "flush", "table", "191"])
                .map(|_| ()),
            self.service_check(&mut Vec::new()),
        ]);
        finish(trial, cleanup)
    }

    fn meta_bridge(&mut self, mutation: Mutation) -> Result<Option<serde_json::Value>> {
        if mutation == Mutation::Ct {
            self.meta_supervised(|lab, root| lab.meta_bridge_trial(mutation, Some(root)))
        } else {
            self.meta_bridge_trial(mutation, None)
        }
    }

    #[allow(clippy::too_many_lines)] // Keep path setup, live controls, fault evidence and restoration together.
    fn meta_bridge_trial(
        &mut self,
        mutation: Mutation,
        root: Option<&Path>,
    ) -> Result<Option<serde_json::Value>> {
        let stem = if mutation == Mutation::Ct {
            "L19-L3"
        } else {
            "L19-L4"
        };
        let marker = Lab::marker()?;
        let mut flow = None;
        let mut established = None;
        let destination = if mutation == Mutation::Ct {
            A.client_inner
        } else {
            A.internet.peer
        };
        let prefix = format!("{destination}/32");
        let trial = (|| {
            if mutation == Mutation::Ct {
                flow = Some(self.daemon_flow("udp", "client", &marker, stem, 120)?);
                let log = self.artifacts.join(format!("{stem}-udp.jsonl"));
                self.daemon_wait(
                    "L19 established UDP replies",
                    Duration::from_secs(5),
                    |_| Ok(super::daemon::flow_counts(&log)?.1 > 4),
                )?;
                let first: serde_json::Value = serde_json::from_str(
                    fs::read_to_string(&log)?
                        .lines()
                        .next()
                        .ok_or("missing flow metadata")?,
                )?;
                let local: std::net::SocketAddr = first["local"]
                    .as_str()
                    .ok_or("missing UDP local tuple")?
                    .parse()?;
                let receipts: Vec<_> = super::helpers::receipts(&fs::read_to_string(
                    self.artifacts.join("sink.jsonl"),
                )?)?
                .into_iter()
                .filter(|r| r.marker == marker && r.protocol == "udp")
                .collect();
                fs::write(
                    self.artifacts.join("L19-L3-provider-receipts.json"),
                    serde_json::to_vec_pretty(&receipts)?,
                )?;
                if receipts.len() < 5
                    || receipts
                        .iter()
                        .any(|r| r.peer.ip().to_string() != A.provider.peer)
                {
                    return fail("L19 harness: established flow lacks provider-NAT receipts");
                }
                // Linux marks a UDP flow ASSURED only after traffic continues past
                // its ~2 s threshold: poll (sender still running) instead of
                // checking right after the first replies.
                let deadline = std::time::Instant::now() + Duration::from_secs(10);
                let before = loop {
                    match self.meta_conntrack(local.port(), "before") {
                        Ok(entries) => break entries,
                        Err(e) if std::time::Instant::now() >= deadline => {
                            return fail(format!("L19 harness: flow not ASSURED within 10 s: {e}"));
                        }
                        Err(_) => self.runner.dwell(Duration::from_millis(250))?,
                    }
                };
                // Stop the sender while changing the path; drain in-flight
                // replies before measuring so none can cross before readback.
                flow.as_ref()
                    .ok_or("missing flow")?
                    .signal(rustix::process::Signal::STOP);
                let root = root.ok_or("missing L19 daemon root")?;
                fs::write(root.join("run/scupper/incomplete-tick"), b"hold")?;
                self.runner.dwell(Duration::from_millis(2200))?;
                established = Some((local.port(), before));
            }
            self.veth(A.bridge, "lab-bridge")?;
            // Match the existing bridge fixture: incidental IPv6 MLD must not
            // obscure the IPv4 policy violation being measured here.
            for (ns, iface) in [("scupper", "lab-bridge"), ("wan", A.bridge.wan_if)] {
                self.cmd(ns, "ip", &["link", "set", "dev", iface, "multicast", "off"])?;
            }
            self.apply_sysctls(true, true)?;
            self.cmd(
                "wan",
                "ip",
                &["route", "add", A.exit_net, "via", A.bridge.peer],
            )?;
            if mutation == Mutation::Ct {
                // Capture the forbidden reply once, without routing it back
                // into scupper and creating an established-packet loop.
                self.cmd("wan", "ip", &["route", "add", "blackhole", A.client_net])?;
            } else {
                self.cmd(
                    "wan",
                    "ip",
                    &["route", "add", A.client_net, "via", A.bridge.peer],
                )?;
            }
            // Narrow output liveness exception, separate from client and exit sources.
            if active() != Some(Mutation::Out) {
                self.cmd(
                    "scupper",
                    "nft",
                    &[
                        "add",
                        "rule",
                        "inet",
                        "scupper",
                        "output",
                        "ip",
                        "saddr",
                        A.bridge.peer,
                        "icmp",
                        "type",
                        "echo-request",
                        "accept",
                    ],
                )?;
            }
            self.capture("wan", A.bridge.wan_if, stem)?;
            let (status, _) = self.runner.output(
                &Invocation::new(
                    "scupper",
                    "ping",
                    &["-n", "-I", "lab-bridge", "-c", "2", "-W", "1", A.bridge.wan],
                ),
                None,
            )?;
            if !status.success() {
                return fail("L19 veth liveness failed");
            }
            self.cmd(
                "scupper",
                "ip",
                &[
                    "route",
                    "add",
                    &prefix,
                    "via",
                    A.bridge.wan,
                    "dev",
                    "lab-bridge",
                ],
            )?;
            // Divert replies after reverse NAT, preserving the original
            // exit path. Moving a MASQUERADE flow's original output interface
            // can invalidate its conntrack mapping before it reaches the wire.
            let source = if mutation == Mutation::Ct {
                A.internet.peer
            } else {
                A.exit_inner
            };
            let mut args = vec!["route", "get", destination, "from", source];
            if mutation == Mutation::Ct {
                args.extend(["iif", "ex-ch1"]);
            }
            args.extend(["ipproto", "udp"]);
            let reply_port = established.as_ref().map(|(port, _)| port.to_string());
            if let Some(port) = &reply_port {
                // Route lookup sees the tuple after reverse NAT in prerouting.
                args.extend(["sport", "8080", "dport", port]);
            } else {
                args.extend(["dport", "8080"]);
            }
            let route = self.cmd("scupper", "ip", &args)?;
            fs::write(self.artifacts.join(format!("{stem}-route.txt")), &route)?;
            if !route
                .split_whitespace()
                .collect::<Vec<_>>()
                .windows(2)
                .any(|w| w == ["dev", "lab-bridge"])
            {
                return fail("L19 foreign path not preferred");
            }
            if mutation == Mutation::Ct {
                self.capture("scupper", "ex-ch1", &format!("{stem}-ingress"))?;
                let log = self.artifacts.join(format!("{stem}-udp.jsonl"));
                let before = self.meta_drop_counter()?;
                let sent = super::daemon::flow_counts(&log)?.0;
                let (port, initial) = established.as_ref().ok_or("missing conntrack baseline")?;
                let current = self.meta_conntrack(*port, "pre-send")?;
                if initial != &current {
                    return fail("L19 harness: established conntrack tuple changed before send");
                }
                flow.as_ref()
                    .ok_or("missing flow")?
                    .signal(rustix::process::Signal::CONT);
                self.daemon_wait(
                    "L19 established packets after route loss",
                    Duration::from_secs(3),
                    |_| Ok(super::daemon::flow_counts(&log)?.0 > sent + 40),
                )?;
                let sent_after = super::daemon::flow_counts(&log)?.0;
                let after = self.meta_drop_counter()?;
                if self.meta_conntrack(*port, "post-send")? != *initial {
                    return fail("L19 harness: conntrack changed during the frozen measurement");
                }
                let (sends, drops, required) = drop_window(before, sent, sent_after, after);
                fs::write(
                    self.artifacts.join("L19-L3-drops.json"),
                    serde_json::to_vec_pretty(
                        &serde_json::json!({"before":before,"after":after,"sent":sends,"drops":drops,"required":required}),
                    )?,
                )?;
                if active() != Some(Mutation::Ct) && drops < required {
                    return fail("L19 established control lacks nft fwd_dropped evidence");
                }
                flow.as_mut().ok_or("missing established flow")?.alive()?;
                flow.as_mut()
                    .ok_or("missing established flow")?
                    .stop(rustix::process::Signal::TERM)?;
            } else {
                let outcome = self.send_from(
                    "scupper",
                    "udp",
                    A.internet.peer,
                    &marker,
                    false,
                    Some(A.exit_inner),
                )?;
                let expected = if active() == Some(Mutation::Out) {
                    super::helpers::Outcome::Delivered
                } else {
                    super::helpers::Outcome::LocalReject(1)
                };
                if outcome != expected {
                    return fail(format!("L19 output unexpected outcome: {outcome:?}"));
                }
            }
            self.runner.dwell(Duration::from_millis(300))?;
            self.stop_captures()?;
            if mutation == Mutation::Ct {
                let packets = observe(&fs::read(
                    self.artifacts.join(format!("{stem}-ingress.pcap")),
                )?)?;
                if !packets.iter().any(|p| {
                    p.source.to_string() == A.internet.peer
                        && p.destination.to_string() == A.exit_inner
                        && p.protocol == 17
                        && established.as_ref().is_some_and(|(port, _)| {
                            let [a, b] = 8080_u16.to_be_bytes();
                            let [c, d] = port.to_be_bytes();
                            p.payload.get(..4) == Some(&[a, b, c, d])
                        })
                        && p.payload
                            .windows(marker.len())
                            .any(|w| w == marker.as_bytes())
                }) {
                    return fail("L19 established exit reply tuple/marker missing");
                }
            }
            let policy = format!(
                "uplink_addrs = {:?}\nforbidden_addrs = {:?}\ncanary_markers = {:?}\narp = true\nmin_packets = 4\nexpect = [\"arp\", \"host_allow\"]\n[[host_allow]]\nproto = \"icmp\"\nremote_addr = {:?}\ntypes = [0, 8]\n",
                [A.bridge.peer, A.bridge.wan],
                [A.client_net, A.exit_net, A.internet.peer],
                [&marker],
                A.bridge.wan
            );
            fs::write(self.artifacts.join(format!("{stem}.policy.toml")), &policy)?;
            let report = classify(
                &fs::read(self.artifacts.join(format!("{stem}.pcap")))?,
                &Policy::from_toml(&policy)?,
                30,
            )?;
            fs::write(
                self.artifacts.join(format!("{stem}.report.json")),
                serde_json::to_vec_pretty(&report)?,
            )?;
            if !report.capture_failures.is_empty() {
                return fail("L19 bridge capture controls missing");
            }
            if report.packets.iter().any(|p| matches!(&p.class, Class::Violation(reason) if !matches!(reason, Reason::ForbiddenAddress {..}))) { return fail("L19 bridge unrelated oracle violation"); }
            let leaked = report
                .packets
                .iter()
                .any(|p| matches!(p.class, Class::Violation(Reason::ForbiddenAddress { .. })));
            if !leaked {
                return Ok(None);
            }
            let packets = observe(&fs::read(self.artifacts.join(format!("{stem}.pcap")))?)?;
            let packet = packets
                .iter()
                .find(|p| {
                    p.destination.to_string() == destination
                        && p.source.to_string() == source
                        && p.protocol == 17
                        && established.as_ref().is_none_or(|(port, _)| {
                            let [a, b] = 8080_u16.to_be_bytes();
                            let [c, d] = port.to_be_bytes();
                            p.payload.get(..4) == Some(&[a, b, c, d])
                        })
                        && p.payload
                            .windows(marker.len())
                            .any(|w| w == marker.as_bytes())
                        && report.packets.iter().any(|verdict| {
                            verdict.index == p.index
                                && matches!(
                                    verdict.class,
                                    Class::Violation(Reason::ForbiddenAddress { .. })
                                )
                        })
                })
                .ok_or(
                    "L19 violation lacks the fault canary tuple/payload at the same packet index",
                )?;
            Ok(Some(
                serde_json::json!({"capture": format!("{stem}.pcap"), "report": report,
                "marker": marker, "destination": packet.destination, "source":packet.source, "packet_index":packet.index,"protocol":packet.protocol,
                "established": established.as_ref().map(|(port, tuple)| serde_json::json!({"source_port":port,"tuple":tuple,"reconciliation_frozen":true,"provider_nat":true}))}),
            ))
        })();
        if let Some(flow) = &flow {
            flow.signal(rustix::process::Signal::CONT);
        }
        let stopped = flow
            .as_mut()
            .map_or(Ok(()), |flow| flow.stop(rustix::process::Signal::TERM));
        let resumed = if let Some(root) = root {
            self.meta_resume(root, &prefix)
        } else {
            Ok(())
        };
        let route_cleanup = if root.is_none() {
            self.cmd("scupper", "ip", &["route", "del", &prefix])
                .map(|_| ())
        } else {
            Ok(())
        };
        let cleanup = cleanup_results([
            stopped,
            self.stop_captures(),
            resumed,
            route_cleanup,
            self.cmd("wan", "ip", &["route", "del", A.exit_net])
                .map(|_| ()),
            self.cmd("wan", "ip", &["route", "del", A.client_net])
                .map(|_| ()),
            self.cmd("wan", "ip", &["link", "del", A.bridge.wan_if])
                .map(|_| ()),
            self.load_real_rules(),
            self.cmd("scupper", "conntrack", &["-F"]).map(|_| ()),
            self.apply_sysctls(true, false),
            self.service_check(&mut Vec::new()),
        ]);
        finish(trial, cleanup)
    }

    fn meta_conntrack(&mut self, port: u16, stage: &str) -> Result<Vec<String>> {
        let entries = self.cmd(
            "scupper",
            "conntrack",
            &[
                "-L",
                "-p",
                "udp",
                "--orig-src",
                A.client_inner,
                "--orig-dst",
                A.internet.peer,
                "--sport",
                &port.to_string(),
                "--dport",
                "8080",
            ],
        )?;
        fs::write(
            self.artifacts.join(format!("L19-L3-conntrack-{stage}.txt")),
            &entries,
        )?;
        established_udp_tuple(&entries, port)
    }

    #[allow(clippy::too_many_lines)] // Keep timed policy drift, stage evidence and restoration together.
    fn meta_probe(&mut self) -> Result<Option<serde_json::Value>> {
        let root = self.prepare_check_v2()?;
        self.boot_gateway(&[], "L19-L6-boot")?;
        let binary = Self::boot_binary()?;
        let trial = (|| {
            let (code, report) = self.check_result(&binary, &root)?;
            fs::write(
                self.artifacts.join("L19-L6-before.json"),
                serde_json::to_vec_pretty(&report)?,
            )?;
            if code != 0 {
                return fail(format!("L19 check baseline failed: {code}: {report}"));
            }
            let defaults = self.cmd("scupper", "ip", &["-j", "route", "show", "default"])?;
            let baseline_rules = self.cmd("scupper", "ip", &["-j", "rule", "show"])?;
            let executable = std::env::current_exe()?;
            let (status, stdout) = self.runner.output_timeout(
                &Invocation::new(
                    "gwhost",
                    executable.to_str().ok_or("non-UTF8 executable")?,
                    &[
                        "route-check",
                        root.to_str().ok_or("non-UTF8 root")?,
                        binary.to_str().ok_or("non-UTF8 binary")?,
                    ],
                ),
                None,
                30,
            )?;
            let observed: serde_json::Value = serde_json::from_str(&stdout)?;
            fs::write(
                self.artifacts.join("L19-L6-observations.json"),
                serde_json::to_vec_pretty(&observed)?,
            )?;
            let code = status.code().ok_or("route check killed by signal")?;
            let report = &observed["report"];
            let defaults_after = self.cmd("scupper", "ip", &["-j", "route", "show", "default"])?;
            if observed["fault_installed"] != true || defaults_after != defaults {
                return fail("L19 policy drift missing or main default changed");
            }
            let live_rules: serde_json::Value =
                serde_json::from_str(&self.cmd("scupper", "ip", &["-j", "rule", "show"])?)?;
            let mut expected_rules: serde_json::Value = serde_json::from_str(&baseline_rules)?;
            expected_rules.as_array_mut().ok_or("invalid policy rules")?.insert(1, serde_json::json!({"priority":100,"src":"all","iif":"wg0","action":"unreachable"}));
            if !rules_equal(&live_rules, &expected_rules)? {
                return fail(format!("L19 policy fault readback differs: {live_rules}"));
            }
            fs::write(
                self.artifacts.join("L19-L6-policy.json"),
                serde_json::to_vec_pretty(&live_rules)?,
            )?;
            // Independently prove the historical blind spot even in the
            // unmutated run: the same HTTPS probe succeeds when device-bound.
            let handle = scupper_sys::netns::NetnsHandle::open("/run/netns/scupper")?;
            let request = serde_json::from_value(serde_json::json!({
                "kind": scupper_sys::probe_child::ProbeKind::ExitIp,
                "bind": "ex-ch1",
                "expected_netns": handle.identity(),
                "dns": A.provider_inner,
                "targets": self.site.health().probe_targets().iter().map(scupper_core::config::ValidatedUrl::as_str).collect::<Vec<_>>(),
                "deadline_ms": 0,
            }))?;
            self.runner.check()?;
            let bound = scupper_sys::probe_child::run_probe(
                &super::probe_child::Executable(binary.clone()),
                &handle,
                &request,
            )?;
            fs::write(
                self.artifacts.join("L19-L6-bound-control.json"),
                serde_json::to_vec_pretty(&bound)?,
            )?;
            if bound.result.into_probe()?.is_none() {
                return fail("L19 bound exit probe returned no address");
            }
            // Independent real lookup proves the fault remains live after check,
            // including when M-probe skipped the collector entirely.
            let identity = handle.identity();
            let health = HealthConfigV2::new(
                &self.site,
                &GatewayId("gw1".into()),
                NetnsIdentity {
                    device: identity.0,
                    inode: identity.1,
                },
                vec![A.gwhost.peer.parse()?],
                1,
            )?;
            let routes = scupper_sys::collect::routes(
                &scupper_sys::system::RealSystem::default(),
                &handle,
                &health,
            )?;
            if !routes
                .iter()
                .all(|(_, r)| r.v4 == Ok(RouteAnswer::Unreachable))
            {
                return fail(format!("L19 policy fault not live: {routes:?}"));
            }
            fs::write(
                self.artifacts.join("L19-L6-client-routes.txt"),
                format!("{routes:?}"),
            )?;
            if active() == Some(Mutation::Probe)
                && code == 0
                && report["verdict"].get("Protected").is_some()
            {
                let control: serde_json::Value = serde_json::from_slice(&fs::read(
                    self.artifacts
                        .parent()
                        .ok_or("missing artifact parent")?
                        .join("control/L19-L6-observations.json"),
                )?)?;
                let diff = format!("-{}\n+{}\n", behavior(&control)?, behavior(&observed)?);
                if diff != golden(Mutation::Probe) {
                    return fail(format!("M-probe behavior differs beyond golden: {diff}"));
                }
                return Ok(Some(
                    serde_json::json!({"check":report, "path":"L19-L6-observations.json", "route_fault_live":true,"defaults_intact":true,"routes_observed":observed["routes_observed"],"defaults_observed":observed["defaults_observed"],"control":control,"observed":observed,"live_rules":live_rules,"defaults_before":serde_json::from_str::<serde_json::Value>(&defaults)?,"defaults_after":serde_json::from_str::<serde_json::Value>(&defaults_after)?,"client_routes":routes.iter().map(|(source, route)| serde_json::json!({"source":source,"v4":route.v4})).collect::<Vec<_>>()}),
                ));
            }
            if active().is_none()
                && code == 3
                && report["verdict"]["Degraded"]["RouteWrong"]["client"] == A.client_inner
                && report["verdict"]["Degraded"]["RouteWrong"]["got"] == "Unreachable"
                && observed["routes_observed"] == true
                && observed["defaults_observed"] == true
            {
                return Ok(None);
            }
            fail(format!(
                "L19 wrong check stage after route loss: {code}: {report}"
            ))
        })();
        let cleanup = cleanup_results([
            self.cmd("scupper", "ip", &["rule", "del", "pref", "100"])
                .map(|_| ()),
            self.service_check(&mut Vec::new()),
        ]);
        finish(trial, cleanup)
    }
}
fn rules_equal(left: &serde_json::Value, right: &serde_json::Value) -> Result<bool> {
    let parse = |value: &serde_json::Value| -> Result<_> {
        let mut rules = scupper_core::parse::parse_ip_rule(&value.to_string())?;
        // Origin metadata is not a packet selector; iproute2 versions differ
        // in whether the implicit kernel/boot origin is printed.
        for rule in &mut rules {
            if matches!(
                rule.protocol.as_deref(),
                Some("kernel" | "2" | "boot" | "3")
            ) {
                rule.protocol = None;
            }
        }
        Ok(rules)
    };
    Ok(parse(left)? == parse(right)?)
}

fn behavior(observed: &serde_json::Value) -> Result<String> {
    let defaults = observed["defaults_observed"]
        .as_bool()
        .ok_or("missing default stage evidence")?;
    let routes = observed["routes_observed"]
        .as_bool()
        .ok_or("missing route stage evidence")?;
    let bind: Option<String> = serde_json::from_value(observed["probe_binding"].clone())?;
    Ok(format!(
        "defaults={defaults}; routes={routes}; bind={bind:?}"
    ))
}

fn cleanup_results<const N: usize>(results: [Result<()>; N]) -> Result<()> {
    let errors: Vec<_> = results
        .into_iter()
        .filter_map(Result::err)
        .map(|e| e.to_string())
        .collect();
    if errors.is_empty() {
        Ok(())
    } else {
        fail(errors.join("; "))
    }
}

#[cfg(any(test, feature = "lab-mutation"))]
fn apply_golden(control: &str, diff: &str) -> Result<String> {
    let removed: String =
        diff.lines()
            .filter_map(|s| s.strip_prefix('-'))
            .fold(String::new(), |mut text, line| {
                text.push_str(line);
                text.push('\n');
                text
            });
    let added: String =
        diff.lines()
            .filter_map(|s| s.strip_prefix('+'))
            .fold(String::new(), |mut text, line| {
                text.push_str(line);
                text.push('\n');
                text
            });
    if removed.is_empty() || control.matches(&removed).count() != 1 {
        return fail("golden removal must match control exactly once");
    }
    Ok(control.replacen(&removed, &added, 1))
}

pub(super) fn finish<T>(trial: Result<T>, cleanup: Result<()>) -> Result<T> {
    match (trial, cleanup) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (trial, Err(error)) => fail(format!(
            "lab finalization failed: {error}; trial: {:?}",
            trial.err()
        )),
    }
}

// UDP has no printed TCP-style ESTABLISHED label. ASSURED proves the
// bidirectional exchange (ct state established); reject UNREPLIED or a
// different original/reply tuple instead of treating absent state as protection.
fn established_udp_tuple(entries: &str, port: u16) -> Result<Vec<String>> {
    let lines: Vec<_> = entries
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect();
    if lines.len() != 1 {
        return fail("L19 harness: expected exactly one ESTABLISHED UDP conntrack entry");
    }
    let words: Vec<_> = lines[0].split_whitespace().collect();
    let tuple: Vec<_> = words
        .iter()
        .filter(|w| {
            ["src=", "dst=", "sport=", "dport="]
                .iter()
                .any(|prefix| w.starts_with(prefix))
        })
        .map(ToString::to_string)
        .collect();
    let expected = udp_nat_tuple(port);
    if words.first() != Some(&"udp")
        || !words.contains(&"[ASSURED]")
        || words.contains(&"[UNREPLIED]")
        || tuple != expected
    {
        return fail(
            "L19 harness: canary conntrack entry is not ESTABLISHED with the expected NAT tuple",
        );
    }
    Ok(tuple)
}

fn udp_nat_tuple(port: u16) -> Vec<String> {
    vec![
        format!("src={}", A.client_inner),
        format!("dst={}", A.internet.peer),
        format!("sport={port}"),
        "dport=8080".into(),
        format!("src={}", A.internet.peer),
        format!("dst={}", A.exit_inner),
        "sport=8080".into(),
        format!("dport={port}"),
    ]
}

// The counter reads surround the send reads. Allow five in-flight packets,
// but always require at least one observed nft drop in the control.
fn drop_window(before: u64, sent: u64, sent_after: u64, after: u64) -> (u64, u64, u64) {
    let sends = sent_after.saturating_sub(sent);
    (
        sends,
        after.saturating_sub(before),
        sends.saturating_sub(5).max(1),
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    #[test]
    fn conntrack_requires_the_exact_assured_bidirectional_udp_tuple() {
        let entry = "udp 17 179 src=10.99.0.2 dst=192.0.2.6 sport=42000 dport=8080 src=192.0.2.6 dst=10.2.0.2 sport=8080 dport=42000 [ASSURED] mark=0 use=1\n";
        let tuple = established_udp_tuple(entry, 42000).unwrap();
        assert_eq!(
            tuple,
            established_udp_tuple(&entry.replace("179", "130"), 42000).unwrap()
        );
        for invalid in [
            String::new(),
            entry.repeat(2),
            entry.replace("[ASSURED]", "[UNREPLIED]"),
            entry.replace("[ASSURED]", ""),
            entry.replace("src=10.99.0.2", "src=10.99.0.3"),
            entry.replace("dst=10.2.0.2", "dst=198.51.100.6"),
            entry.replace("dport=42000", "dport=42001"),
        ] {
            assert!(established_udp_tuple(&invalid, 42000).is_err(), "{invalid}");
        }
        assert!(established_udp_tuple(entry, 42001).is_err());
    }

    #[test]
    fn drop_window_counts_only_sends_inside_the_counter_window() {
        // Sends during either slow counter read lie outside the inner send
        // window; their drops can increase evidence but cannot raise the bar.
        assert_eq!(drop_window(100, 120, 170, 180), (50, 80, 45));
        assert_eq!(drop_window(100, 120, 170, 144), (50, 44, 45));
        assert_eq!(drop_window(100, 120, 170, 145), (50, 45, 45));
        assert_eq!(drop_window(100, 120, 124, 101), (4, 1, 1));
        assert_eq!(drop_window(100, 120, 120, 100), (0, 0, 1));
        assert_eq!(drop_window(100, 120, 119, 99), (0, 0, 1));
    }
    #[test]
    fn inversion_requires_a_failed_case_with_the_exact_reason() {
        for mutation in Mutation::ALL {
            let mut caught = expected(mutation);
            assert!(invert(mutation, true, Some(&caught)).is_err());
            caught.evidence = Some(Evidence {
                golden_diff: golden(mutation).into(),
                live: serde_json::json!({"actual":["mutant"],"expected":["mutant"],"control":["control"]}),
                observation: match mutation {
                    Mutation::Ct | Mutation::Out => {
                        serde_json::json!({"capture":if mutation == Mutation::Ct { "L19-L3.pcap" } else { "L19-L4.pcap" },"packet_index":1,"destination":if mutation == Mutation::Ct { A.client_inner } else { A.internet.peer },"source":if mutation == Mutation::Ct { A.internet.peer } else { A.exit_inner },"marker":"canary",
                        "established":{"source_port":42000,"tuple":["src=10.99.0.2","dst=192.0.2.6","sport=42000","dport=8080","src=192.0.2.6","dst=10.2.0.2","sport=8080","dport=42000"],"reconciliation_frozen":true,"provider_nat":true},
                        "report":{"packets":[{"index":1,"class":{"Violation":{"ForbiddenAddress":{"addr":A.internet.peer}}}}]}})
                    }
                    Mutation::Src => {
                        serde_json::json!({"packet_index":1,"source":A.gateway_inner,"destination":A.client_inner,"source_selector":A.client_net,"live_rule":{"src":"10.99.0.0","srclen":24}})
                    }
                    Mutation::Probe => {
                        serde_json::json!({"check":{"verdict":{"Protected":{}}},"route_fault_live":true,"defaults_intact":true,"routes_observed":false,"defaults_observed":true,
                        "defaults_before":["ex-ch1"],"defaults_after":["ex-ch1"],"client_routes":[{"v4":{"Ok":"Unreachable"}}],
                        "control":{"defaults_observed":true,"routes_observed":true,"probe_binding":null},
                        "observed":{"defaults_observed":true,"routes_observed":false,"probe_binding":"ex-ch1"}})
                    }
                },
            });
            let evidence = caught.evidence.as_ref().unwrap();
            let observed = observed_catch(
                mutation,
                evidence.live.clone(),
                evidence.observation.clone(),
            )
            .unwrap();
            assert_eq!(observed.case, caught.case);
            assert_eq!(observed.reason, caught.reason);
            assert!(invert(mutation, true, Some(&observed)).is_ok());
            assert!(invert(mutation, true, Some(&caught)).is_ok());
            if mutation == Mutation::Ct {
                for field in [
                    "reconciliation_frozen",
                    "provider_nat",
                    "tuple",
                    "source_port",
                ] {
                    let mut missing = caught.clone();
                    missing.evidence.as_mut().unwrap().observation["established"][field] =
                        serde_json::Value::Null;
                    assert!(invert(mutation, true, Some(&missing)).is_err());
                }
            }
            assert!(invert(mutation, false, None).is_err());
            assert!(invert(mutation, true, None).is_err()); // harness error/timeout
            assert!(invert(mutation, false, Some(&caught)).is_err());
            let mut absent = caught.clone();
            absent.evidence.as_mut().unwrap().live["actual"] = serde_json::json!(["control"]);
            match mutation {
                Mutation::Src => {
                    absent.evidence.as_mut().unwrap().observation["source_selector"] =
                        serde_json::json!("all");
                }
                Mutation::Probe => {
                    absent.evidence.as_mut().unwrap().observation["client_routes"] =
                        serde_json::json!([]);
                }
                Mutation::Ct | Mutation::Out => {}
            }
            assert!(invert(mutation, true, Some(&absent)).is_err());
            let mut wrong = caught.clone();
            wrong.case = "setup".into();
            assert!(invert(mutation, true, Some(&wrong)).is_err());
            wrong = caught.clone();
            wrong.reason = if caught.reason == CatchReason::RouteStageMissed {
                CatchReason::ForbiddenAddress
            } else {
                CatchReason::RouteStageMissed
            };
            assert!(invert(mutation, true, Some(&wrong)).is_err());
        }
    }
    #[test]
    fn golden_patch_is_exact() {
        let control =
            include_str!("../../../crates/scupper-core/tests/golden/netns-m2-one-exit.nft");
        for mutation in [Mutation::Ct, Mutation::Out] {
            assert_ne!(apply_golden(control, golden(mutation)).unwrap(), control);
            assert!(apply_golden("changed renderer", golden(mutation)).is_err());
        }
    }
    #[test]
    fn policy_readback_compares_all_selectors_after_format_normalization() {
        let expected =
            serde_json::json!([{"priority":191,"src":"10.99.0.0","srclen":24,"table":191}]);
        let live = serde_json::json!([{"priority":191,"src":"10.99.0.0","srclen":24,"table":"191","protocol":"boot"}]);
        assert!(rules_equal(&live, &expected).unwrap());
        let mut extra = live;
        extra[0]["iif"] = serde_json::json!("wg0");
        assert!(!rules_equal(&extra, &expected).unwrap());
        extra[0]["unexpected_selector"] = serde_json::json!(true);
        assert!(rules_equal(&extra, &expected).is_err());
    }
    #[test]
    fn cleanup_continues_after_a_dead_flow_and_keeps_every_error() {
        let restored = std::cell::Cell::new(false);
        let cleanup = cleanup_results([
            fail("background process exited"),
            {
                restored.set(true);
                Ok(())
            },
            fail("route cleanup failed"),
        ]);
        assert!(restored.get());
        let error = cleanup.unwrap_err().to_string();
        assert!(error.contains("background process exited"));
        assert!(error.contains("route cleanup failed"));
        let result: Result<()> = finish(Err(expected(Mutation::Ct).into()), Err(error.into()));
        assert!(result.unwrap_err().downcast_ref::<Caught>().is_none());
    }
    #[test]
    fn restoration_error_cannot_be_inverted() {
        let result: Result<()> = finish(Err(expected(Mutation::Ct).into()), fail("cleanup"));
        assert!(result.unwrap_err().downcast_ref::<Caught>().is_none());
    }
}
