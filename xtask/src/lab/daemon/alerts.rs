//! Self-checking alert delivery through the real daemon and HTTPS child.
use super::{A, DaemonGuard, Duration, Invocation, Path, Result, Signal, fail, fs};
use scupper_core::config::SiteConfig;
use scupper_proto::{Actor, EventKind, GatewayId, Identifier, Reason, UnixSeconds};
use std::{
    os::unix::fs::PermissionsExt,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

const SERVER: &str = r"
import http.server, ssl, json, sys, os, time
class Sink(http.server.BaseHTTPRequestHandler):
 def do_POST(self):
  n=int(self.headers.get('Content-Length','0'))
  if not 0<n<=16384: self.send_error(400); return
  raw=self.rfile.read(n).decode()
  if self.path=='/ntfy':
   assert self.headers.get('Content-Type')=='text/plain; charset=utf-8'
   assert self.headers.get('Title')=='Scupper failing closed'
   assert self.headers.get('Priority') in ('4','5')
   body={'text':raw}
  else:
   assert self.headers.get('Content-Type')=='application/json'
   body=json.loads(raw)
   if self.path=='/telegram': assert set(body)=={'text'}
  code=503 if self.path=='/backlog' and os.path.exists(sys.argv[4]) else 200
  with open(sys.argv[3],'a') as out:
   out.write(json.dumps({'path':self.path,'peer':self.client_address[0],'status':code,'alert':body,'at':time.monotonic()})+'\n'); out.flush(); os.fsync(out.fileno())
  self.send_response(code); self.send_header('Content-Length','0'); self.end_headers()
 def log_message(self,*args): pass
server=http.server.HTTPServer(('198.51.100.10',443),Sink)
context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.load_cert_chain(sys.argv[1],sys.argv[2])
server.socket=context.wrap_socket(server.socket,server_side=True)
server.serve_forever()
";
fn timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
impl DaemonGuard<'_> {
    pub(super) fn alerts_fixture(root: &Path, site: &mut SiteConfig) -> Result<()> {
        // Reuse the existing test-CA host resolver fixture, without heartbeat traffic.
        Self::heartbeat_fixture(root, site)?;
        site.heartbeat = None;
        site.alerts.sinks.clear();
        for (name, path, min) in [
            ("primary", "/primary", "critical"),
            ("coalesce", "/coalesce", "warning"),
            ("backlog", "/backlog", "critical"),
            ("telegram", "/telegram", "critical"),
            ("ntfy", "/ntfy", "critical"),
        ] {
            let settings = if name == "ntfy" {
                serde_json::json!({"kind":"ntfy","url_ref":format!("lab-{name}"),"min_severity":min})
            } else {
                serde_json::json!({"kind":"webhook","preset":if name=="telegram" {"telegram"} else {"generic"},"url_ref":format!("lab-{name}"),"min_severity":min})
            };
            site.alerts
                .sinks
                .insert(name.into(), serde_json::from_value(settings)?);
            let secret = root.join(format!("etc/scupper/secrets/url/lab-{name}"));
            fs::write(&secret, format!("https://heartbeat.invalid{path}"))?;
            fs::set_permissions(secret, fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }
    fn alert_records(&self, path: &str) -> Result<Vec<serde_json::Value>> {
        let text = match fs::read_to_string(self.lab.artifacts.join("alerts-sink.jsonl")) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };
        text.lines()
            .map(serde_json::from_str::<serde_json::Value>)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map(|rows| {
                rows.into_iter()
                    .filter(|r| r["path"] == path && r["status"] == 200)
                    .collect()
            })
            .map_err(Into::into)
    }
    fn wait_alert(&mut self, path: &str, key: &str, state: &str) -> Result<serde_json::Value> {
        let deadline = std::time::Instant::now() + Duration::from_secs(330);
        while std::time::Instant::now() < deadline {
            if let Some(row) = self
                .alert_records(path)?
                .into_iter()
                .find(|r| r["alert"]["key"] == key && r["alert"]["state"] == state)
            {
                return Ok(row);
            }
            self.lab.runner.dwell(Duration::from_millis(100))?;
        }
        fail(format!(
            "alerts: missing {path} {key}/{state}; inspect alerts-sink.jsonl, per-sink cursor, daemon stderr and alerts.pcap"
        ))
    }
    fn assert_alert_silence(&mut self) -> Result<()> {
        self.lab.runner.dwell(Duration::from_secs(6))?;
        match fs::read_to_string(self.lab.artifacts.join("alerts-sink.jsonl")) {
            Ok(text) if !text.is_empty() => fail("healthy restart or connect delivered an alert"),
            Ok(_) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
    fn seed_coalesced_events(root: &Path) -> Result<()> {
        // Seed after the sink cursor exists. The real worker must hold these
        // resolutions against its monotonic clock (120 seconds in this lab).
        let base = timestamp().saturating_sub(30);
        let clock = Arc::new(AtomicU64::new(base));
        let at = clock.clone();
        let log = scupper_sys::events::EventLog::open(
            &root.join("var-lib/scupper"),
            GatewayId("gw1".into()),
            move || UnixSeconds(at.load(Ordering::Acquire)),
        )?;
        let id = |name: &str| Identifier::try_from(name.to_owned()).map_err(std::io::Error::other);
        for (offset, kind) in [
            (
                0,
                EventKind::Failover {
                    from: id("ch1")?,
                    to: id("ch2")?,
                    cause: Reason::HealthFailure,
                },
            ),
            (
                10,
                EventKind::Failback {
                    from: id("ch2")?,
                    to: id("ch1")?,
                },
            ),
            (
                20,
                EventKind::Failover {
                    from: id("ch1")?,
                    to: id("ch2")?,
                    cause: Reason::HealthFailure,
                },
            ),
            (
                30,
                EventKind::Failback {
                    from: id("ch2")?,
                    to: id("ch1")?,
                },
            ),
        ] {
            clock.store(base.saturating_add(offset), Ordering::Release);
            log.handle.emit(kind, Actor::Daemon, None)?;
        }
        log.handle.flush_blocking(Duration::from_secs(5))?;
        Ok(())
    }
    #[allow(clippy::too_many_lines)] // One guarded fault and recovery sequence owns its evidence.
    pub(super) fn run_alerts(&mut self) -> Result<String> {
        let root = self.lab.prepare_check_v2()?;
        if let scupper_sys::state::StateRead::Present(state) =
            scupper_sys::state::StateFile::open(root.join("var-lib/scupper"), None)?.read()?
        {
            self.baseline_version = state.applied_version;
        }
        self.supervised_fixture(&root)?;
        self.lab.boot_gateway(&[], "alerts-boot")?;
        // Establish the exact endpoint route and generate the existing disposable CA.
        let mut observer = self.start_heartbeat_sink()?;
        observer.stop(Signal::TERM)?;
        let mut tls = self.start_heartbeat_tls()?;
        tls.stop(Signal::TERM)?;
        let cert = self.lab.private.join("alerts-heartbeat-tls/server.pem");
        let key = cert.with_file_name("server.key");
        let outage = self.lab.private.join("alerts-backlog-down");
        fs::write(&outage, b"503")?;
        let log = self.lab.artifacts.join("alerts-sink.jsonl");
        let mut server = self.lab.runner.background(
            &Invocation::new(
                "internet",
                "python3",
                &[
                    "-c",
                    SERVER,
                    cert.to_str().ok_or("certificate path")?,
                    key.to_str().ok_or("key path")?,
                    log.to_str().ok_or("log path")?,
                    outage.to_str().ok_or("outage path")?,
                ],
            ),
            &self.lab.artifacts.join("alerts-server.stdout"),
        )?;
        self.lab
            .daemon_wait("alert HTTPS listener", Duration::from_secs(5), |lab| {
                Ok(lab.cmd("internet", "ss", &["-ltnH"])?.contains(":443"))
            })?;
        // Mark the alert connection from its first locally generated packet,
        // then restore DSCP from conntrack even for late socketless kernel RSTs.
        // Forwarded client SYNs cannot receive cs7, even after source translation.
        let identity = scupper_sys::heartbeat::account(
            &fs::read_to_string(root.join("etc/passwd"))?,
            &fs::read_to_string(root.join("etc/group"))?,
        )
        .map_err(|_| "alert identity missing")?;
        let mark = format!(
            r"table inet alert_identity {{
  counter tracked_reset {{ }}
  counter invalid_reset {{ }}
  counter unmarked_tracked {{ }}
  counter unmarked_invalid {{ }}
  chain output {{
    type filter hook output priority -150;
    ip daddr {endpoint} tcp dport 443 ip dscp set cs0;
    meta skuid {uid} ip daddr {endpoint} tcp dport 443 ct mark set 0x5c;
    ct mark 0x5c ip daddr {endpoint} tcp dport 443 ip dscp set cs7;
    ip daddr {endpoint} tcp dport 443 tcp flags == rst ct state != invalid counter name tracked_reset;
    ip daddr {endpoint} tcp dport 443 tcp flags == rst ct state invalid counter name invalid_reset;
    ip daddr {endpoint} tcp dport 443 ip dscp cs0 ct state != invalid counter name unmarked_tracked;
    ip daddr {endpoint} tcp dport 443 ip dscp cs0 ct state invalid counter name unmarked_invalid;
  }}
  chain forward {{
    type filter hook forward priority -150;
    ip daddr {endpoint} tcp dport 443 ip dscp set cs0;
  }}
}}
",
            uid = identity.uid,
            endpoint = super::heartbeat::ENDPOINT
        );
        self.lab.runner.input(
            &Invocation::new("gwhost", "nft", &["-f", "-"]),
            Some(mark.as_bytes()),
        )?;
        self.lab.capture("wan", A.gwhost.wan_if, "alerts")?;
        let (child, notify) = self.lab.daemon_start("alerts", &root)?;
        self.child = Some(child);
        self.notify = Some(notify);
        self.lab
            .daemon_ready_tick(self.notify.as_ref().ok_or("missing notify")?)?;
        let mut markers = Vec::new();
        self.lab.service_check(&mut markers)?;
        self.lab
            .daemon_wait("sink cursors", Duration::from_secs(5), |_| {
                Ok(root.join("var-lib/scupper/sinks/coalesce.cursor").exists())
            })?;
        self.assert_alert_silence()?;
        self.control_restart(&root, "clean-restart")?;
        self.lab.daemon_route_healthy(Duration::from_secs(65))?;
        self.assert_alert_silence()?;
        for command in ["disconnect", "connect"] {
            let (code, text) = self.control_command_with_link_evidence(&root, command)?;
            if code != 0 {
                return fail(format!("healthy {command} failed: {text}"));
            }
        }
        self.lab.daemon_route_healthy(Duration::from_secs(30))?;
        self.assert_alert_silence()?;
        self.control_stop(Signal::TERM)?;
        Self::seed_coalesced_events(&root)?;
        self.control_restart(&root, "coalescing")?;
        let warning = self.wait_alert("/coalesce", "failover", "firing")?;
        // Complete the Warning-only phase before inducing repair warnings.
        // The outage then depends solely on the independent Critical allowance.
        self.control_stop(Signal::KILL)?;
        self.control_restart(&root, "coalescing-restart")?;
        let summary = self.wait_alert("/coalesce", "failover", "resolved")?;
        if summary["at"].as_f64().ok_or("summary time")?
            - warning["at"].as_f64().ok_or("warning time")?
            < 119.0
            || summary["alert"]["count"] != 2
        {
            return fail("coalescing did not hold and count the live incident");
        }
        // The real exit's encrypted transport fails; the alert path stays on uplink.
        self.lab.runner.input(&Invocation::new("wan","nft",&["-f","-"]),Some(b"table inet daemon_exit_down {\n  chain forward {\n    type filter hook forward priority -100;\n    ip daddr 203.0.113.2 udp dport 51820 drop;\n  }\n}\n"))?;
        // Replace the same public peer in one update to reset its handshake
        // without waiting 175 seconds for aging. Its transport is still blocked,
        // so the real kernel has no usable exit; endpoint/AllowedIPs stay exact.
        let peer = self
            .lab
            .cmd("scupper", "wg", &["show", "ex-ch1", "peers"])?;
        let allowed = self
            .lab
            .cmd("scupper", "wg", &["show", "ex-ch1", "allowed-ips"])?;
        let allowed = allowed
            .split_whitespace()
            .skip(1)
            .collect::<Vec<_>>()
            .join(",");
        let endpoint = format!("{}:51820", A.provider.peer);
        self.lab.cmd(
            "scupper",
            "wg",
            &[
                "set",
                "ex-ch1",
                "peer",
                peer.trim(),
                "remove",
                "peer",
                peer.trim(),
                "allowed-ips",
                &allowed,
                "endpoint",
                &endpoint,
                "persistent-keepalive",
                "25",
            ],
        )?;
        self.lab
            .daemon_wait("all exits down", Duration::from_secs(40), |lab| {
                Ok(lab
                    .cmd("scupper", "ip", &["route", "show", "default"])?
                    .contains("unreachable"))
            })?;
        let firing = self.wait_alert("/primary", "fail_closed", "firing")?;
        if firing["alert"]["severity"] != "critical" || firing["peer"] != A.gwhost.peer {
            return fail("Critical alert did not originate on the host uplink");
        }
        let first_seq = firing["alert"]["seq"].as_u64().ok_or("alert sequence")?;
        let critical = self.wait_alert("/coalesce", "fail_closed", "firing")?;
        if critical["alert"]["seq"] != firing["alert"]["seq"] {
            return fail("Critical outage state differed between sinks");
        }
        let marker = super::Lab::marker()?;
        self.lab.fault_markers.push(marker.clone());
        let mut canary = self
            .lab
            .daemon_flow("udp", "client", &marker, "alerts-canary", 180)?;
        let endpoint_marker = super::Lab::marker()?;
        self.lab.fault_markers.push(endpoint_marker.clone());
        let mut endpoint_canary = self.lab.daemon_flow_to(
            "connect",
            "client",
            &endpoint_marker,
            "alerts-endpoint",
            &format!("{}:443", super::heartbeat::ENDPOINT),
            180,
        )?;
        self.lab.daemon_wait(
            "client canary attempts during outage",
            Duration::from_secs(5),
            |lab| {
                Ok(
                    super::flow_counts(&lab.artifacts.join("alerts-canary-udp.jsonl"))?.0 > 0
                        && fs::read_to_string(lab.artifacts.join("alerts-endpoint-connect.jsonl"))
                            .is_ok_and(|text| {
                                text.lines().any(|line| {
                                    serde_json::from_str::<serde_json::Value>(line)
                                        .is_ok_and(|row| row["attempted"] == 1)
                                })
                            }),
                )
            },
        )?;

        self.control_stop(Signal::KILL)?;
        self.control_restart(&root, "after-delivery")?;
        canary.stop(Signal::TERM)?;
        endpoint_canary.stop(Signal::TERM)?;
        if super::flow_counts(&self.lab.artifacts.join("alerts-canary-udp.jsonl"))?.1 != 0
            || super::flow_counts(&self.lab.artifacts.join("alerts-endpoint-connect.jsonl"))?.1 != 0
        {
            return fail("client canary received a reply during all-exits-down");
        }
        self.lab.cmd(
            "wan",
            "nft",
            &["delete", "table", "inet", "daemon_exit_down"],
        )?;
        self.lab.daemon_route_healthy(Duration::from_secs(70))?;
        let resolved = self.wait_alert("/primary", "fail_closed", "resolved")?;
        if resolved["alert"]["duration"].as_u64().unwrap_or(0) == 0
            || resolved["alert"]["seq"].as_u64().unwrap_or(0) <= first_seq
        {
            return fail("recovery lost duration or event ordering");
        }
        if !self.alert_records("/backlog")?.is_empty() {
            return fail("unavailable sink accepted an alert");
        }
        fs::remove_file(outage)?;
        self.wait_alert("/backlog", "fail_closed", "resolved")?;
        let (code, text) = self.control_command(&root, &["alerts", "test", "primary"], "test")?;
        if code != 0 {
            return fail(format!("alerts test failed: {text}"));
        }
        self.wait_alert("/primary", "test", "firing")?;
        self.wait_alert("/coalesce", "fail_closed", "resolved")?;
        for path in ["/ntfy", "/telegram"] {
            let deadline = std::time::Instant::now() + Duration::from_secs(30);
            while !self.alert_records(path)?.iter().any(|r| {
                r["alert"]["text"]
                    .as_str()
                    .is_some_and(|s| s.contains(": resolved;"))
            }) {
                if std::time::Instant::now() >= deadline {
                    return fail("preset recovery missing");
                }
                self.lab.runner.dwell(Duration::from_millis(100))?;
            }
        }
        self.control_stop(Signal::TERM)?;
        for (path, expected) in [
            (
                "/primary",
                vec![
                    ("fail_closed", "firing"),
                    ("fail_closed", "resolved"),
                    ("test", "firing"),
                ],
            ),
            ("/backlog", vec![("fail_closed", "resolved")]),
            (
                "/coalesce",
                vec![
                    ("failover", "firing"),
                    ("failover", "resolved"),
                    ("fail_closed", "firing"),
                    ("fail_closed", "resolved"),
                ],
            ),
        ] {
            let mut rows = self.alert_records(path)?;
            if path == "/coalesce" {
                // Repair suppression is a genuine Warning with timing-dependent recovery.
                // Keep exact ordering for outage and seeded failover keys, and reject
                // every other Critical instead of depending on Warning counts.
                if rows.iter().any(|r| {
                    r["alert"]["key"] != "fail_closed" && r["alert"]["severity"] == "critical"
                }) {
                    return fail("unexpected Critical on coalescing sink");
                }
                rows.retain(|r| r["alert"]["key"] != "repair_suppressed");
            }
            assert_sequence(&rows, &expected)?;
        }
        for path in ["/ntfy", "/telegram"] {
            assert_preset_sequence(&self.alert_records(path)?)?;
        }
        server.stop(Signal::TERM)?;
        self.lab.stop_captures()?;
        // Keep kernel conntrack evidence alongside the pcap: a tracked flow must
        // never lose its identity mark. INVALID socketless resets cannot read a
        // ct mark; the oracle requires capture-local proof of that closing reply.
        let counters: serde_json::Value = serde_json::from_str(&self.lab.cmd(
            "gwhost",
            "nft",
            &["-j", "list", "table", "inet", "alert_identity"],
        )?)?;
        fs::write(
            self.lab.artifacts.join("alerts-conntrack.json"),
            serde_json::to_vec_pretty(&counters)?,
        )?;
        if identity_counter(&counters, "unmarked_tracked")? != 0 {
            return fail("alerts: a conntrack-associated delivery packet lost DSCP cs7");
        }
        // Require all counters to exist, even when the race does not fire.
        for name in ["tracked_reset", "invalid_reset", "unmarked_invalid"] {
            identity_counter(&counters, name)?;
        }
        let bytes = fs::read(self.lab.artifacts.join("alerts.pcap"))?;
        if crate::pcap::heartbeat_hellos(
            &bytes,
            A.gwhost.peer.parse()?,
            format!("{}:443", super::heartbeat::ENDPOINT).parse()?,
        )?
        .is_empty()
        {
            return fail("alert uplink flow observer was blind");
        }
        self.lab
            .daemon_oracle("alerts", &markers, self.lab.exit_port, self.lab.exit_port)?;
        let report: serde_json::Value =
            serde_json::from_slice(&fs::read(self.lab.artifacts.join("alerts.report.json"))?)?;
        assert_invalid_reset_evidence(&report, &counters)?;
        Ok("Critical host-uplink alert, exact per-sink sequences and preset shapes, client canaries, durable CLI receipt, live shortened coalescing hold".into())
    }
}

fn assert_invalid_reset_evidence(
    report: &serde_json::Value,
    counters: &serde_json::Value,
) -> Result<()> {
    let counts = report["counts"]
        .as_object()
        .ok_or("missing oracle counts")?;
    let exempted = counts
        .get("Allowed(heartbeat_late_reset)")
        .map_or(Ok(0), |v| v.as_u64().ok_or("invalid late reset count"))?;
    if exempted > identity_counter(counters, "unmarked_invalid")? {
        return fail("alerts: late-reset exemptions exceed kernel unmarked INVALID packets");
    }
    Ok(())
}

fn identity_counter(value: &serde_json::Value, name: &str) -> Result<u64> {
    let counters = value["nftables"]
        .as_array()
        .ok_or("missing nftables counters")?;
    let mut found = counters.iter().filter_map(|row| {
        let counter = &row["counter"];
        (counter["family"] == "inet"
            && counter["table"] == "alert_identity"
            && counter["name"] == name)
            .then_some(counter)
    });
    let packets = found
        .next()
        .and_then(|c| c["packets"].as_u64())
        .ok_or("missing alert identity counter")?;
    if found.next().is_some() {
        return fail("duplicate alert identity counter");
    }
    Ok(packets)
}

fn assert_sequence(rows: &[serde_json::Value], expected: &[(&str, &str)]) -> Result<()> {
    let mut delivered: Vec<_> = rows
        .iter()
        .map(|r| {
            (
                &r["alert"]["seq"],
                r["alert"]["key"].as_str().unwrap_or("invalid"),
                r["alert"]["state"].as_str().unwrap_or("invalid"),
            )
        })
        .collect();
    delivered.dedup(); // Only adjacent retransmissions of the same durable notification.
    let actual: Vec<_> = delivered
        .iter()
        .map(|(_, key, state)| (*key, *state))
        .collect();
    if actual != expected {
        return fail(format!("unexpected exact alert sequence: {actual:?}"));
    }
    Ok(())
}
fn assert_preset_sequence(rows: &[serde_json::Value]) -> Result<()> {
    let mut bodies: Vec<_> = rows
        .iter()
        .map(|r| r["alert"]["text"].as_str().unwrap_or("invalid"))
        .collect();
    bodies.dedup();
    if bodies.len() != 2
        || !bodies[0].starts_with("Scupper failing closed: firing;")
        || !bodies[1].starts_with("Scupper failing closed: resolved;")
    {
        return fail("unexpected exact preset sequence");
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn late_reset_exemptions_require_kernel_invalid_evidence() {
        for exempted in [0, 1, 2] {
            for invalid in [0, 1, 2] {
                let report =
                    serde_json::json!({"counts":{"Allowed(heartbeat_late_reset)":exempted}});
                let counters = serde_json::json!({"nftables":[{"counter":{
                    "family":"inet", "table":"alert_identity", "name":"unmarked_invalid", "packets":invalid
                }}]});
                assert_eq!(
                    assert_invalid_reset_evidence(&report, &counters).is_ok(),
                    exempted <= invalid
                );
            }
        }
    }
    #[test]
    fn identity_counter_requires_exact_scope_and_numeric_evidence() {
        let row = serde_json::json!({"counter":{
            "family":"inet", "table":"alert_identity", "name":"unmarked_tracked", "packets":0
        }});
        let good = serde_json::json!({"nftables":[row.clone()]});
        assert_eq!(identity_counter(&good, "unmarked_tracked").unwrap(), 0);
        assert!(identity_counter(&good, "invalid_reset").is_err());
        let mut nonzero = good.clone();
        nonzero["nftables"][0]["counter"]["packets"] = 1.into();
        assert_eq!(identity_counter(&nonzero, "unmarked_tracked").unwrap(), 1);
        for field in ["family", "table", "packets"] {
            let mut invalid = good.clone();
            invalid["nftables"][0]["counter"][field] = "wrong".into();
            assert!(identity_counter(&invalid, "unmarked_tracked").is_err());
        }
        let duplicate = serde_json::json!({"nftables":[row.clone(), row]});
        assert!(identity_counter(&duplicate, "unmarked_tracked").is_err());
    }

    #[test]
    fn exact_sequence_rejects_extras_missing_reordering_and_nonadjacent_duplicates() {
        let row =
            |seq, key, state| serde_json::json!({"alert":{"seq":seq,"key":key,"state":state}});
        let firing = row(1, "fail_closed", "firing");
        let resolved = row(2, "fail_closed", "resolved");
        let expected = [("fail_closed", "firing"), ("fail_closed", "resolved")];
        assert!(
            assert_sequence(
                &[firing.clone(), firing.clone(), resolved.clone()],
                &expected
            )
            .is_ok()
        );
        assert!(assert_sequence(std::slice::from_ref(&firing), &expected).is_err());
        assert!(assert_sequence(&[resolved.clone(), firing.clone()], &expected).is_err());
        assert!(
            assert_sequence(
                &[firing.clone(), resolved.clone(), firing.clone()],
                &expected
            )
            .is_err()
        );
        assert!(
            assert_sequence(
                &[firing, row(3, "unprotected", "firing"), resolved],
                &expected
            )
            .is_err()
        );
        assert!(assert_preset_sequence(&[]).is_err());
    }
}
