//! Control faults reuse the guarded daemon lifecycle and uplink leak oracle.
use super::{
    A, DaemonGuard, Duration, Instant, Invocation, Lab, Path, Result, Signal, fail, flow_counts, fs,
};
use scupper_core::{
    config::{GatewayId, parse_site, validate},
    render::{VersionStamp, render_netns},
    verdict::v2::Selection,
};
use scupper_sys::{
    lock::WriterLock,
    state::{StateFile, StateRead},
    store::{MetaInput, VersionStore},
};
use sha2::{Digest, Sha256};
use std::fmt::Write as _;

/// Whether a verdict payload carries `reason`.
///
/// A reason is a unit variant (`"X"`) or a single-variant object (`{"X": ..}`). `Unprotected`
/// carries a list of violations, which matches when any element carries the reason. The empty
/// reason means "any payload": `Protected` is a struct (`{"exit", "exit_ip"}`), not a variant.
pub(super) fn verdict_reason(value: &serde_json::Value, reason: &str) -> bool {
    if reason.is_empty() {
        return !value.is_null();
    }
    match value {
        serde_json::Value::String(s) => s == reason,
        serde_json::Value::Object(map) => map.len() == 1 && map.contains_key(reason),
        serde_json::Value::Array(items) => items.iter().any(|item| verdict_reason(item, reason)),
        _ => false,
    }
}

fn verdict_matches(report: &serde_json::Value, kind: &str, reason: &str) -> bool {
    let payload = &report["verdict"][kind];
    if kind == "Unsupervised" && !reason.is_empty() {
        verdict_reason(&payload["why"], reason)
    } else {
        verdict_reason(payload, reason)
    }
}

#[cfg(test)]
mod verdict_tests {
    use super::verdict_reason;
    #[test]
    fn unsupervised_matches_why_from_l10_stopped_report() {
        let report = serde_json::json!({"at":1_794_335_538_u64,"config_version":7,"schema":1,
            "verdict":{"Unsupervised":{"exit":"ch1","exit_ip":"3.42.157.37","why":"Dead"}},
            "warnings":["ClientHandshakesStale"]});
        assert!(super::verdict_matches(&report, "Unsupervised", "Dead"));
        assert!(!super::verdict_matches(&report, "Unsupervised", "Stale"));
        assert!(!super::verdict_matches(&report, "Protected", ""));
    }
    #[test]
    fn closure_requires_exactly_one_unreachable_default() {
        use serde_json::json;
        assert!(super::sole_unreachable(
            &json!([{"type":"unreachable","dst":"default"}])
        ));
        assert!(!super::sole_unreachable(&json!([])));
        assert!(!super::sole_unreachable(
            &json!([{"type":"unreachable"},{"dev":"ex-ch1"}])
        ));
        assert!(!super::sole_unreachable(&json!([{"dev":"ex-ch1"}])));
        // Run 5 used text here. Keep its exact kernel forms as regressions,
        // including the loopback device printed for IPv6 unreachable routes.
        for route in [
            json!("unreachable default \n"),
            json!("unreachable default dev lo metric 1024 pref medium\n"),
            json!([{"type":"unreachable","dst":"default","dev":"lo","metric":1024,"pref":"medium"}]),
        ] {
            assert!(super::sole_unreachable(&route));
        }
        assert!(!super::sole_unreachable(&json!("default dev ex-ch1\n")));
        assert!(!super::sole_unreachable(&json!(
            "unreachable default\ndefault dev ex-ch1\n"
        )));
    }
    #[test]
    fn l44_kernel_snapshot_is_closed_including_ipv6_loopback_route() {
        use serde_json::json;
        let mut snapshot = json!({
            "exit":"6: ex-ch1: <POINTOPOINT,NOARP> mtu 1420 qdisc noqueue state DOWN mode DEFAULT group default qlen 1000\\    link/none \n",
            "v4":"unreachable default \n",
            "v6":"unreachable default dev lo metric 1024 pref medium\n",
        });
        assert!(super::disconnect_snapshot_closed(&snapshot));
        snapshot["v4"] = json!([{"type":"unreachable","dst":"default"}]);
        snapshot["v6"] = json!([{"type":"unreachable","dst":"default","dev":"lo","metric":1024,"pref":"medium"}]);
        assert!(super::disconnect_snapshot_closed(&snapshot));
        snapshot["exit"] = json!("6: ex-ch1: <POINTOPOINT,NOARP,UP> state UNKNOWN");
        assert!(!super::disconnect_snapshot_closed(&snapshot));
        snapshot["exit"] = json!("");
        assert!(!super::disconnect_snapshot_closed(&snapshot));
    }
    #[test]
    fn closed_for_the_wrong_reason_is_rejected() {
        let stale = serde_json::json!({"FailClosed":"NoHealthyExit"});
        assert!(!verdict_reason(&stale["FailClosed"], "AdminDisconnected"));
        assert!(verdict_reason(
            &serde_json::json!("AdminDisconnected"),
            "AdminDisconnected"
        ));
        assert!(verdict_reason(
            &serde_json::json!({"Quarantined":{"reason":"SafetyDrift"}}),
            "Quarantined"
        ));
        assert!(!verdict_reason(
            &serde_json::json!({"NoHealthyExit":{"previous":"AdminDisconnected"}}),
            "AdminDisconnected"
        ));
        assert!(!verdict_reason(
            &serde_json::json!({"AdminDisconnected":null,"NoHealthyExit":null}),
            "AdminDisconnected"
        ));
        assert!(!verdict_reason(
            &serde_json::Value::Null,
            "AdminDisconnected"
        ));
    }
    #[test]
    fn protected_and_violation_lists_match_real_reports() {
        use serde_json::json;
        let protected = json!({"Protected":{"exit":"ch1","exit_ip":"20.64.174.66"}});
        assert!(verdict_reason(&protected["Protected"], ""));
        assert!(!verdict_reason(&protected["Unprotected"], ""));
        let violations = json!({"Unprotected":[
            {"ForeignLink":"foreign0"},{"LinkKind":"foreign0"},{"TrafficControlHook":"wg0"}
        ]});
        assert!(verdict_reason(&violations["Unprotected"], "ForeignLink"));
        assert!(verdict_reason(
            &violations["Unprotected"],
            "TrafficControlHook"
        ));
        assert!(!verdict_reason(&violations["Unprotected"], "PeerDiffers"));
        assert!(!verdict_reason(&json!([]), "ForeignLink"));
    }
}

fn sole_unreachable(routes: &serde_json::Value) -> bool {
    // Accept old saved text snapshots as well as the current `ip -j` output.
    if let Some(text) = routes.as_str() {
        return matches!(
            text.split_whitespace().collect::<Vec<_>>().as_slice(),
            ["unreachable", "default"]
                | [
                    "unreachable",
                    "default",
                    "dev",
                    "lo",
                    "metric",
                    "1024",
                    "pref",
                    "medium"
                ]
        );
    }
    routes.as_array().is_some_and(|routes| {
        routes.len() == 1 && routes[0]["type"] == "unreachable" && routes[0]["dst"] == "default"
    })
}

fn disconnect_snapshot_closed(snapshot: &serde_json::Value) -> bool {
    sole_unreachable(&snapshot["v4"])
        && sole_unreachable(&snapshot["v6"])
        && snapshot["exit"].as_str().is_some_and(|s| {
            s.contains("ex-ch1:")
                && s.contains("state DOWN")
                && !s.contains(",UP")
                && !s.contains("<UP")
        })
}

fn session_continues(before: &str, after: &str) -> bool {
    compare_sessions(before, after, false)
}

fn session_has_traffic(before: &str, after: &str) -> bool {
    compare_sessions(before, after, true)
}

fn compare_sessions(before: &str, after: &str, traffic: bool) -> bool {
    let sessions = |text: &str| {
        text.lines()
            .filter_map(|line| {
                let fields = line.split_whitespace().collect::<Vec<_>>();
                Some((
                    fields.first()?.to_string(),
                    (
                        fields.get(1)?.parse::<u64>().ok()?,
                        fields.get(2)?.parse::<u64>().ok()?,
                        fields.get(3)?.parse::<u64>().ok()?,
                    ),
                ))
            })
            .collect::<std::collections::BTreeMap<_, _>>()
    };
    let before = sessions(before);
    let after = sessions(after);
    !before.is_empty()
        && before.keys().eq(after.keys())
        && before.iter().all(|(key, (time, rx, tx))| {
            let (next_time, next_rx, next_tx) = after[key];
            *time > 0
                && next_time >= *time
                && next_rx >= *rx
                && next_tx >= *tx
                && (!traffic || (next_rx > *rx && next_tx > *tx))
        })
}

impl DaemonGuard<'_> {
    pub(super) fn control_command(
        &mut self,
        root: &Path,
        args: &[&str],
        stem: &str,
    ) -> Result<(i32, String)> {
        let binary = Lab::boot_binary()?;
        let mut command = vec!["--test-root", root.to_str().ok_or("root path")?];
        command.extend_from_slice(args);
        let output_path = self
            .lab
            .artifacts
            .join(format!("{}-{stem}.stdout", self.case));
        let trace_path = root.join("run/scupper/connect-verification.jsonl");
        if args.contains(&"connect") {
            fs::write(&trace_path, b"")?;
        }
        let mut child = self.lab.runner.background(
            &Invocation::new("gwhost", binary.to_str().ok_or("binary path")?, &command),
            &output_path,
        )?;
        let status = child.wait_timeout(Duration::from_secs(245))?;
        if args.contains(&"connect") {
            fs::copy(
                &trace_path,
                self.lab
                    .artifacts
                    .join(format!("{}-{stem}-verification.jsonl", self.case)),
            )?;
            fs::remove_file(&trace_path)?;
        }
        let output = fs::read_to_string(&output_path)?;
        let diagnostic = fs::read_to_string(output_path.with_extension("stderr"))?;
        if args.contains(&"disconnect") {
            let snapshot = serde_json::json!({
                "v4": serde_json::from_str::<serde_json::Value>(&self.lab.cmd("scupper", "ip", &["-j", "-4", "route", "show", "default"] )?)?,
                "v6": serde_json::from_str::<serde_json::Value>(&self.lab.cmd("scupper", "ip", &["-j", "-6", "route", "show", "default"] )?)?,
                "exit": self.lab.cmd("scupper", "ip", &["-o", "link", "show", "ex-ch1"] )?,
            });
            fs::write(
                self.lab
                    .artifacts
                    .join(format!("{}-{stem}-closure.json", self.case)),
                serde_json::to_vec_pretty(&snapshot)?,
            )?;
        }
        Ok((
            status.code().unwrap_or(-1),
            format!("{output}\n{diagnostic}"),
        ))
    }
    fn assert_disconnect_snapshot(&self, stem: &str) -> Result<()> {
        let snapshot: serde_json::Value = serde_json::from_slice(&fs::read(
            self.lab
                .artifacts
                .join(format!("{}-{stem}-closure.json", self.case)),
        )?)?;
        if !disconnect_snapshot_closed(&snapshot) {
            return fail(format!(
                "{} message preceded verified closure: {snapshot}",
                self.case
            ));
        }
        Ok(())
    }

    pub(super) fn expect_check(
        &mut self,
        root: &Path,
        code: i32,
        expected: Option<(&str, &str)>,
        stem: &str,
    ) -> Result<()> {
        let (got, report) = self.lab.check_result(&Lab::boot_binary()?, root)?;
        fs::write(
            self.lab
                .artifacts
                .join(format!("{}-{stem}.json", self.case)),
            serde_json::to_vec_pretty(&report)?,
        )?;
        let expected = expected.or(match code {
            0 => Some(("Protected", "")),
            5 => Some(("Unsupervised", "Dead")),
            _ => None,
        });
        if got != code
            || expected.is_some_and(|(kind, reason)| !verdict_matches(&report, kind, reason))
        {
            return fail(format!(
                "{} {stem}: expected {code}, got {got}: {report}",
                self.case
            ));
        }
        if expected == Some(("FailClosed", "AdminDisconnected")) {
            let snapshot = serde_json::json!({
                "v4": serde_json::from_str::<serde_json::Value>(&self.lab.cmd("scupper", "ip", &["-j", "-4", "route", "show", "default"])?)?,
                "v6": serde_json::from_str::<serde_json::Value>(&self.lab.cmd("scupper", "ip", &["-j", "-6", "route", "show", "default"])?)?,
                "exit": self.lab.cmd("scupper", "ip", &["-o", "link", "show", "ex-ch1"])?,
            });
            fs::write(
                self.lab
                    .artifacts
                    .join(format!("{}-{stem}-closure.json", self.case)),
                serde_json::to_vec_pretty(&snapshot)?,
            )?;
            self.assert_disconnect_snapshot(stem)?;
        }
        Ok(())
    }
    fn recover_client(&mut self, markers: &mut Vec<String>) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(30);
        let marker = Lab::marker()?;
        markers.push(marker.clone());
        let stem = format!("{}-recovery-{}", self.case, markers.len());
        let mut traffic = self.lab.daemon_flow("udp", "client", &marker, &stem, 30)?;
        let path = self.lab.artifacts.join(format!("{stem}-udp.jsonl"));
        loop {
            traffic.alive()?;
            let delivered = flow_counts(&path).is_ok_and(|(_, replies)| replies > 0);
            let handshake = self.client_session()?;
            if delivered
                && handshake.lines().any(|line| {
                    line.split_whitespace()
                        .nth(1)
                        .and_then(|time| time.parse::<u64>().ok())
                        .is_some_and(|time| time > 0)
                })
            {
                self.lab.service_check(markers)?;
                traffic.stop(Signal::TERM)?;
                if Instant::now() <= deadline {
                    return Ok(());
                }
                return fail("client handshake and delivery exceeded shared 30 s deadline");
            }
            if Instant::now() >= deadline {
                return fail("client handshake and delivery exceeded shared 30 s deadline");
            }
            self.lab.runner.dwell(Duration::from_millis(200))?;
        }
    }
    fn client_session(&mut self) -> Result<String> {
        let handshakes = self
            .lab
            .cmd("scupper", "wg", &["show", "wg0", "latest-handshakes"])?;
        let transfers = self
            .lab
            .cmd("scupper", "wg", &["show", "wg0", "transfer"])?;
        let times = handshakes
            .lines()
            .filter_map(|line| line.split_once(char::is_whitespace))
            .collect::<std::collections::BTreeMap<_, _>>();
        let mut sample = String::new();
        for line in transfers
            .lines()
            .filter(|line| line.split_whitespace().next() == Some(self.lab.public_keys[3].as_str()))
        {
            let (peer, counters) = line
                .split_once(char::is_whitespace)
                .ok_or("invalid peer counters")?;
            let time = times.get(peer).ok_or("missing peer handshake")?.trim();
            writeln!(sample, "{peer} {time} {}", counters.trim())?;
        }
        Ok(sample)
    }
    pub(super) fn assert_namespace_released(&mut self, identity: &str) -> Result<()> {
        self.lab
            .daemon_wait("old namespace released", Duration::from_secs(5), |_| {
                for process in fs::read_dir("/proc")? {
                    let process = process?.path();
                    if process
                        .file_name()
                        .is_none_or(|name| name.to_string_lossy().parse::<u32>().is_err())
                    {
                        continue;
                    }
                    if fs::read_link(process.join("ns/net"))
                        .is_ok_and(|link| link.to_string_lossy() == identity)
                    {
                        return Ok(false);
                    }
                    if let Ok(fds) = fs::read_dir(process.join("fd")) {
                        for fd in fds {
                            if fs::read_link(fd?.path())
                                .is_ok_and(|link| link.to_string_lossy() == identity)
                            {
                                return Ok(false);
                            }
                        }
                    }
                }
                let inode = identity.trim_start_matches("net:[").trim_end_matches(']');
                for line in fs::read_to_string("/proc/self/mountinfo")?.lines() {
                    let fields = line.split_whitespace().collect::<Vec<_>>();
                    if line.contains(" - nsfs ")
                        && fields.get(4).is_some_and(|path| {
                            fs::metadata(path).is_ok_and(|meta| {
                                std::os::unix::fs::MetadataExt::ino(&meta).to_string() == inode
                            })
                        })
                    {
                        return Ok(false);
                    }
                }
                Ok(true)
            })
            .map(|_| ())
    }
    fn assert_forwarding_open(&mut self) -> Result<()> {
        self.lab
            .daemon_wait(
                "forwarding reopened after clear",
                Duration::from_secs(20),
                |lab| {
                    for key in [
                        "net.ipv4.ip_forward",
                        "net.ipv6.conf.all.forwarding",
                        "net.ipv4.conf.default.forwarding",
                        "net.ipv6.conf.default.forwarding",
                        "net.ipv4.conf.wg0.forwarding",
                    ] {
                        if lab.cmd("scupper", "sysctl", &["-n", key])?.trim() != "1" {
                            return Ok(false);
                        }
                    }
                    Ok(true)
                },
            )
            .map(|_| ())
    }
    fn stage_exit_change(&mut self, root: &Path) -> Result<()> {
        let state_root = root.join("var-lib/scupper");
        let config_root = root.join("etc/scupper");
        let guard = WriterLock::acquire(root.join("run/scupper"))?;
        let store = VersionStore::open_with_mirror_root(&state_root, &config_root, Some(&guard))?;
        let head = store.head()?.ok_or("missing head")?;
        let StateRead::Present(state) = StateFile::open(&state_root, None)?.read()? else {
            return fail("missing applied state");
        };
        let (old, _) = store.read(state.applied_version.ok_or("missing applied version")?)?;
        let text = exit_change(&old)?;
        let version = store.commit(
            &guard,
            Some(head),
            &text,
            MetaInput {
                actor: "lab".into(),
                at: 3,
                reason: "exit-only apply preserves clients".into(),
            },
        )?;
        self.lab.site = validate(parse_site(&text)?).map_err(|e| format!("exit change: {e:?}"))?;
        let rules = render_netns(
            &self.lab.site,
            &GatewayId("gw1".into()),
            &VersionStamp {
                version,
                sha256: Sha256::digest(text.as_bytes()).into(),
            },
        )?;
        store.write_rendered(&guard, version, &rules)?;
        fs::write(&self.lab.rules, rules)?;
        Ok(())
    }
    fn assert_client_traffic(&mut self, markers: &mut Vec<String>) -> Result<()> {
        let before = self.client_session()?;
        self.lab.service_check(markers)?;
        let after = self.client_session()?;
        if !session_has_traffic(&before, &after) {
            return fail(format!(
                "canaries did not advance client counters: {before:?} -> {after:?}"
            ));
        }
        Ok(())
    }
    fn assert_client_session(&mut self, before: &str) -> Result<()> {
        let after = self.client_session()?;
        if !session_continues(before, &after) {
            return fail(format!(
                "apply reset client transfer counters: {before:?} -> {after:?}"
            ));
        }
        Ok(())
    }
    pub(super) fn control_restart(&mut self, root: &Path, stage: &str) -> Result<()> {
        if let Some(mut child) = self.child.take() {
            child.signal(Signal::CONT);
            child.stop_timeout(Signal::TERM, Duration::from_secs(30))?;
        }
        if let Some(notify) = &self.notify {
            notify.drain()?;
        }
        self.child = Some(self.lab.daemon_spawn(&self.case, root, stage)?);
        self.lab
            .daemon_ready_tick(self.notify.as_ref().ok_or("missing notify")?)
    }
    pub(super) fn control_stop(&mut self, signal: Signal) -> Result<()> {
        if let Some(mut child) = self.child.take() {
            child.signal(Signal::CONT);
            child.stop_timeout(signal, Duration::from_secs(30))?;
        }
        Ok(())
    }
    pub(super) fn supervised_fixture(&mut self, root: &Path) -> Result<()> {
        let state_root = root.join("var-lib/scupper");
        let config_root = root.join("etc/scupper");
        let guard = WriterLock::acquire(root.join("run/scupper"))?;
        let store = VersionStore::open_with_mirror_root(&state_root, &config_root, Some(&guard))?;
        let head = store.head()?.ok_or("head missing")?;
        let StateRead::Present(state) = StateFile::open(&state_root, None)?.read()? else {
            return fail("missing applied safety state");
        };
        let (text, _) = store.read(state.applied_version.ok_or("missing applied version")?)?;
        let mut site = parse_site(&text)?;
        site.health.require_daemon = true;
        if matches!(self.case.as_str(), "L10" | "L53" | "L53b" | "heartbeat") {
            Self::heartbeat_fixture(root, &mut site)?;
        }
        let text = toml::to_string(&site)?;
        self.lab.site = validate(site).map_err(|e| format!("supervised fixture: {e:?}"))?;
        let version = store.commit(
            &guard,
            Some(head),
            &text,
            MetaInput {
                actor: "lab".into(),
                at: 2,
                reason: "required supervisor control faults".into(),
            },
        )?;
        let file = StateFile::open(&state_root, Some(&guard))?;
        let StateRead::Present(mut state) = file.read()? else {
            return fail("missing safety state");
        };
        state.applied_version = Some(version);
        file.write(&guard, &state)?;
        let rules = render_netns(
            &self.lab.site,
            &GatewayId("gw1".into()),
            &VersionStamp {
                version,
                sha256: Sha256::digest(text.as_bytes()).into(),
            },
        )?;
        store.write_rendered(&guard, version, &rules)?;
        fs::write(&self.lab.rules, rules)?;
        Ok(())
    }
    pub(super) fn reset_control_fixture(&mut self) -> Result<()> {
        let root = self.lab.boot_root.clone();
        let _ = fs::remove_file(root.join("heartbeat-request-pause"));
        for marker in [
            "crash-after-selection",
            "pause-apply",
            "apply-paused",
            "incomplete-tick",
            "heartbeat-pause",
            "heartbeat-request-pause",
            "heartbeat-status",
            "heartbeat-test-code",
        ] {
            let _ = fs::remove_file(root.join("run/scupper").join(marker));
        }
        let guard = WriterLock::acquire(root.join("run/scupper"))?;
        let file = StateFile::open(root.join("var-lib/scupper"), Some(&guard))?;
        if let StateRead::Present(mut state) = file.read()? {
            if let Some(version) = self.baseline_version {
                state.applied_version = Some(version);
                let store = VersionStore::read_only(
                    &root.join("var-lib/scupper"),
                    &root.join("etc/scupper"),
                );
                let (text, _) = store.read(version)?;
                self.lab.site =
                    validate(parse_site(&text)?).map_err(|e| format!("baseline config: {e:?}"))?;
                let rules = render_netns(
                    &self.lab.site,
                    &GatewayId("gw1".into()),
                    &VersionStamp {
                        version,
                        sha256: Sha256::digest(text.as_bytes()).into(),
                    },
                )?;
                fs::write(&self.lab.rules, rules)?;
            }
            state.selection = Selection::Auto;
            state.quarantine = None;
            file.write(&guard, &state)?;
        }
        Ok(())
    }
    fn assert_latched(&mut self, root: &Path, phase: &str) -> Result<()> {
        for key in ["net.ipv4.ip_forward", "net.ipv6.conf.all.forwarding"] {
            if self.lab.cmd("scupper", "sysctl", &["-n", key])?.trim() != "0" {
                return fail(format!("L43 {phase}: gate {key} opened"));
            }
        }
        let StateRead::Present(state) =
            StateFile::open(root.join("var-lib/scupper"), None)?.read()?
        else {
            return fail("L43 missing state");
        };
        if state.quarantine.is_none() {
            return fail(format!("L43 {phase}: latch missing"));
        }
        self.lab.daemon_route_healthy(Duration::from_secs(30))?;
        self.expect_check(root, 4, Some(("FailClosed", "Quarantined")), phase)?;
        let report: serde_json::Value = serde_json::from_slice(&fs::read(
            self.lab
                .artifacts
                .join(format!("{}-{phase}.json", self.case)),
        )?)?;
        if report["verdict"]["FailClosed"].get("Quarantined").is_none() {
            return fail(format!("L43 {phase}: expected Quarantined: {report}"));
        }
        Ok(())
    }
    #[allow(clippy::too_many_lines)] // Each fault retains its control and recovery assertions.
    pub(super) fn run_control(&mut self, case: &str) -> Result<String> {
        let root = self.lab.prepare_check_v2()?;
        if let StateRead::Present(state) =
            StateFile::open(root.join("var-lib/scupper"), None)?.read()?
        {
            self.baseline_version = state.applied_version;
        }
        self.supervised_fixture(&root)?;
        self.lab.boot_gateway(&[], &format!("{case}-boot"))?;
        let _heartbeat_sink = if case == "L10" {
            Some(self.start_heartbeat_sink()?)
        } else {
            None
        };
        let (child, notify) = self.lab.daemon_start(case, &root)?;
        self.child = Some(child);
        self.notify = Some(notify);
        self.lab
            .daemon_ready_tick(self.notify.as_ref().ok_or("notify missing")?)?;
        self.lab.daemon_route_healthy(Duration::from_secs(30))?;
        self.expect_check(&root, 0, None, "positive-control")?;
        let stem = format!("control-{case}");
        self.lab.capture("wan", A.gwhost.wan_if, &stem)?;
        let mut markers = Vec::new();
        self.lab.service_check(&mut markers)?;
        let start_port = self.lab.exit_port;
        let mut canary = if case == "L10" {
            None
        } else {
            let marker = Lab::marker()?;
            markers.push(marker.clone());
            let canary_stem = format!("{stem}-canary");
            let child = self
                .lab
                .daemon_flow("udp", "client", &marker, &canary_stem, 240)?;
            let path = self.lab.artifacts.join(format!("{canary_stem}-udp.jsonl"));
            self.lab
                .daemon_wait("control canary replies", Duration::from_secs(5), |_| {
                    Ok(flow_counts(&path)?.1 > 5)
                })?;
            Some(child)
        };
        match case {
            "L10" => {
                self.wait_heartbeat(0)?;
                self.heartbeat_cadence_control()?;
                let marker = Lab::marker()?;
                markers.push(marker.clone());
                let mut flow = self.lab.daemon_flow("udp", "client", &marker, &stem, 360)?;
                let path = self.lab.artifacts.join(format!("{stem}-udp.jsonl"));
                self.lab
                    .daemon_wait("L10 canary control", Duration::from_secs(5), |_| {
                        Ok(flow_counts(&path)?.1 > 10)
                    })?;
                fs::write(root.join("run/scupper/incomplete-tick"), b"hold")?;
                self.lab.runner.dwell(Duration::from_secs(32))?;
                let (code, text) =
                    self.control_command(&root, &["check", "--json"], "responsive-stale")?;
                if code != 5 || !text.contains("transport: local observations") {
                    return fail(format!("L10 responsive stale supervisor: {code}: {text}"));
                }
                self.assert_heartbeat_quiet(Duration::ZERO, Duration::from_secs(5))?;
                fs::remove_file(root.join("run/scupper/incomplete-tick"))?;
                self.lab.runner.dwell(Duration::from_secs(3))?;
                self.expect_check(&root, 0, None, "fresh-again")?;
                self.heartbeat_cadence_control()?;
                self.child
                    .as_ref()
                    .ok_or("daemon missing")?
                    .signal(Signal::STOP);
                let before = flow_counts(&path)?.1;
                let at = Instant::now();
                self.expect_check(&root, 5, None, "stopped")?;
                if at.elapsed() > Duration::from_secs(4) {
                    return fail(
                        "L10 stopped check exceeded Ping timeout plus local probe allowance",
                    );
                }
                self.lab.daemon_wait(
                    "L10 traffic while stopped",
                    Duration::from_secs(3),
                    |_| Ok(flow_counts(&path)?.1 > before),
                )?;
                self.assert_heartbeat_quiet(Duration::from_secs(32), Duration::from_secs(5))?;
                let heartbeat_before = self.heartbeat_count()?;
                self.child
                    .as_ref()
                    .ok_or("daemon missing")?
                    .signal(Signal::CONT);
                self.lab.daemon_wait(
                    "L10 fresh tick after SIGCONT",
                    Duration::from_secs(10),
                    |_| {
                        use scupper_proto::{Op, OpResult, Response};
                        use scupper_sys::daemon::control;
                        Ok(matches!(
                            control::call(
                                &root.join("run/scupper"),
                                &control::request(Op::Ping {}),
                                Duration::from_millis(250)
                            ),
                            Ok(Response {
                                result: Ok(OpResult::Ping {
                                    last_complete_iteration_age: Some(0..=2),
                                    ..
                                }),
                                ..
                            })
                        ))
                    },
                )?;
                self.expect_check(&root, 0, None, "continued")?;
                self.wait_heartbeat(heartbeat_before)?;
                self.heartbeat_cadence_control()?;
                self.control_stop(Signal::KILL)?;
                let before = flow_counts(&path)?.1;
                self.expect_check(&root, 5, None, "killed")?;
                self.lab.daemon_wait(
                    "L10 traffic after SIGKILL",
                    Duration::from_secs(3),
                    |_| Ok(flow_counts(&path)?.1 > before),
                )?;
                self.assert_heartbeat_quiet(Duration::from_secs(32), Duration::from_secs(5))?;
                flow.stop(Signal::TERM)?;
                self.control_restart(&root, "after-kill")?;
                self.wait_heartbeat(self.heartbeat_count()?)?;
                self.expect_check(&root, 0, None, "restarted")?;
            }
            "L14" => {
                let (code, text) = self.control_command(&root, &["disconnect"], "disconnect")?;
                if code != 0
                    || !text.contains("traffic is now blocked")
                    || !text.contains("transport: local socket")
                {
                    return fail(format!("L14 disconnect: {code}: {text}"));
                }
                self.assert_disconnect_snapshot("disconnect")?;
                self.expect_check(
                    &root,
                    4,
                    Some(("FailClosed", "AdminDisconnected")),
                    "disconnected",
                )?;
                self.control_stop(Signal::TERM)?;
                self.lab.boot_gateway(&[], &format!("{case}-reboot"))?;
                let boot: serde_json::Value = serde_json::from_slice(&fs::read(
                    self.lab.artifacts.join(format!("{case}-reboot.json")),
                )?)?;
                if boot["adopted"] != true {
                    return fail("L14 disconnected reboot did not adopt");
                }
                self.expect_check(
                    &root,
                    4,
                    Some(("FailClosed", "AdminDisconnected")),
                    "reboot-closed",
                )?;
                self.control_restart(&root, "after-reboot")?;
                self.expect_check(
                    &root,
                    4,
                    Some(("FailClosed", "AdminDisconnected")),
                    "restart-closed",
                )?;
                let (code, text) = self.control_command(&root, &["connect"], "connect")?;
                if code != 0 || !text.contains("transport: local socket") {
                    return fail(format!("L14 connect: {code}: {text}"));
                }
                self.recover_client(&mut markers)?;
                self.expect_check(&root, 0, None, "connected")?;
                self.lab.service_check(&mut markers)?;
                let client_session = self.client_session()?;
                self.stage_exit_change(&root)?;
                let (code, text) = self.control_command(&root, &["apply"], "exit-only-apply")?;
                if code != 0 {
                    return fail(format!("L14 apply: {code}: {text}"));
                }
                self.assert_client_session(&client_session)?;
                self.assert_client_traffic(&mut markers)?;
                // A real reboot necessarily loses the server session. Do not
                // reset the client: its ordinary WireGuard rekey must recover.
                let (code, text) =
                    self.control_command(&root, &["disconnect"], "real-reboot-disconnect")?;
                if code != 0 {
                    return fail(text);
                }
                self.control_stop(Signal::TERM)?;
                let old_identity = self
                    .lab
                    .cmd("scupper", "readlink", &["/proc/self/ns/net"])?;
                self.lab.cmd("", "ip", &["netns", "delete", "scupper"])?;
                self.assert_namespace_released(old_identity.trim())?;
                self.lab.boot_gateway(&[], &format!("{case}-real-reboot"))?;
                self.expect_check(
                    &root,
                    4,
                    Some(("FailClosed", "AdminDisconnected")),
                    "real-reboot-closed",
                )?;
                self.control_restart(&root, "real-reboot")?;
                let (code, text) =
                    self.control_command(&root, &["connect"], "real-reboot-connect")?;
                if code != 0 {
                    return fail(text);
                }
                self.recover_client(&mut markers)?;
                self.expect_check(&root, 0, None, "real-reboot-connected")?;
            }
            "L43" => {
                for attempt in 0..5 {
                    self.lab.cmd(
                        "scupper",
                        "ip",
                        &["link", "add", "foreign0", "type", "dummy"],
                    )?;
                    self.lab
                        .cmd("scupper", "ip", &["link", "set", "foreign0", "up"])?;
                    self.lab.daemon_wait(
                        "L43 foreign link tightened",
                        Duration::from_secs(8),
                        |lab| {
                            Ok(!lab
                                .cmd("scupper", "ip", &["-o", "link", "show", "foreign0"])?
                                .contains(",UP"))
                        },
                    )?;
                    self.lab
                        .cmd("scupper", "ip", &["link", "del", "foreign0"])?;
                    let state = StateFile::open(root.join("var-lib/scupper"), None)?.read()?;
                    if matches!(state, StateRead::Present(ref state) if state.quarantine.is_some())
                    {
                        break;
                    }
                    // Each incident must finish reopening before the next one:
                    // the class budget charges reopenings, not repeated sightings
                    // during one continuously closed repair.
                    self.lab.daemon_route_healthy(Duration::from_secs(30))?;
                    self.lab.daemon_wait(
                        "L43 repair reopened",
                        Duration::from_secs(20),
                        |lab| {
                            Ok(lab
                                .cmd("scupper", "sysctl", &["-n", "net.ipv4.ip_forward"])?
                                .trim()
                                == "1")
                        },
                    )?;
                    if attempt == 4 {
                        return fail("L43 recurring foreign links did not latch");
                    }
                }
                self.assert_latched(&root, "quarantined")?;
                for phase in ["latched-restart", "latched-reboot"] {
                    self.control_stop(Signal::TERM)?;
                    if phase == "latched-reboot" {
                        self.lab.boot_gateway(&[], "L43-reboot")?;
                    }
                    if self
                        .lab
                        .cmd("scupper", "sysctl", &["-n", "net.ipv4.ip_forward"])?
                        .trim()
                        != "0"
                    {
                        return fail("L43 latch allowed forwarding");
                    }
                    self.control_restart(&root, phase)?;
                    self.assert_latched(&root, phase)?;
                }
                let (code, text) = self.control_command(
                    &root,
                    &["repair", "clear", "--reason", "lab recovery"],
                    "clear",
                )?;
                if code != 0 || !text.contains("transport: local socket") {
                    return fail(format!("L43 clear: {code}: {text}"));
                }
                self.lab.daemon_route_healthy(Duration::from_secs(30))?;
                self.assert_forwarding_open()?;
                self.expect_check(&root, 0, None, "cleared")?;
                self.recover_client(&mut markers)?;
                self.lab.service_check(&mut markers)?;
            }
            "L44" => {
                let client_session = self.client_session()?;
                self.stage_exit_change(&root)?;
                fs::write(root.join("run/scupper/pause-apply"), b"pause")?;
                let binary = Lab::boot_binary()?;
                let mut apply = self.lab.runner.background(
                    &Invocation::new(
                        "gwhost",
                        binary.to_str().ok_or("binary")?,
                        &["--test-root", root.to_str().ok_or("root")?, "apply"],
                    ),
                    &self.lab.artifacts.join("L44-apply.stdout"),
                )?;
                self.lab.daemon_wait(
                    "L44 socket apply holds writer",
                    Duration::from_secs(5),
                    |_| Ok(root.join("run/scupper/apply-paused").exists()),
                )?;
                if WriterLock::try_acquire(root.join("run/scupper")).is_ok() {
                    return fail("L44 socket apply did not hold the writer lock");
                }
                let (code, text) = self.control_command(&root, &["boot"], "busy-refusal")?;
                if code != 0
                    || !text.contains("scupperd owns the namespace")
                    || text.contains("traffic is now blocked")
                {
                    return fail(format!("L44 busy daemon allowed fallback: {code}: {text}"));
                }
                let mut samples = Vec::new();
                let deadline = Instant::now() + Duration::from_secs(150);
                let mut sample = 0;
                let mut saw_open = false;
                let mut finished = None;
                let status = loop {
                    if Instant::now() >= deadline {
                        return fail("L44 apply sampling deadline");
                    }
                    if sample == 4 {
                        fs::remove_file(root.join("run/scupper/pause-apply"))?;
                    }
                    let forwarding =
                        self.lab
                            .cmd("scupper", "sysctl", &["-n", "net.ipv4.ip_forward"])?;
                    let forwarding6 = self.lab.cmd(
                        "scupper",
                        "sysctl",
                        &["-n", "net.ipv6.conf.all.forwarding"],
                    )?;
                    samples.push(
                        serde_json::json!({"sample": sample, "forwarding_v4": forwarding.trim(), "forwarding_v6": forwarding6.trim()}),
                    );
                    if forwarding.trim() != "0" || forwarding6.trim() != "0" {
                        let (code, report) = self.lab.check_result(&Lab::boot_binary()?, &root)?;
                        saw_open = true;
                        let transitioning = code == 3
                            && report["verdict"]["Degraded"]
                                .get("OperationInProgress")
                                .is_some();
                        if !matches!(code, 0 | 4 | 5) && !transitioning {
                            return fail(format!("L44 open unsafe sample {sample}: {report}"));
                        }
                        if code == 5 {
                            // A complete tick may land while check returns. A fresh
                            // Ping on either side of that transition is acceptable.
                            let ping = scupper_sys::daemon::control::call(
                                &root.join("run/scupper"),
                                &scupper_sys::daemon::control::request(scupper_proto::Op::Ping {}),
                                Duration::from_secs(2),
                            );
                            if !matches!(
                                ping,
                                Ok(scupper_proto::Response {
                                    result: Ok(scupper_proto::OpResult::Ping {
                                        last_complete_iteration_age: None | Some(0..=2),
                                        ..
                                    }),
                                    ..
                                })
                            ) {
                                return fail(
                                    "L44 supervision stale beyond the first post-apply tick",
                                );
                            }
                        }
                        if code == 4
                            && (!self
                                .lab
                                .cmd("scupper", "ip", &["-j", "-4", "route", "show", "default"])?
                                .contains("unreachable")
                                || !self
                                    .lab
                                    .cmd(
                                        "scupper",
                                        "ip",
                                        &["-j", "-6", "route", "show", "default"],
                                    )?
                                    .contains("unreachable"))
                        {
                            return fail("L44 fail-closed report had reachable defaults");
                        }
                    }
                    if let Some(status) = finished {
                        break status;
                    }
                    if let Some(status) = apply.try_wait()? {
                        finished = Some(status);
                        if saw_open {
                            break status;
                        }
                        // Sample once after exit too, closing the race between
                        // the preceding sysctl read and the child's completion.
                    }
                    sample += 1;
                    self.lab.runner.dwell(Duration::from_millis(100))?;
                };
                if !saw_open {
                    return fail("L44 apply completed without an open forwarding sample");
                }
                fs::write(
                    self.lab.artifacts.join("L44-intermediate-samples.json"),
                    serde_json::to_vec_pretty(&samples)?,
                )?;
                // A completed apply or a bounded writer refusal is acceptable;
                // final convergence must be exact and connected.
                let output = fs::read_to_string(self.lab.artifacts.join("L44-apply.stdout"))?;
                let diagnostic = fs::read_to_string(self.lab.artifacts.join("L44-apply.stderr"))?;
                if !status.success() && !diagnostic.contains("writer lock") {
                    return fail(format!(
                        "L44 apply failed without writer contention: {status}: {output}: {diagnostic}"
                    ));
                }
                self.lab.daemon_complete_tick(&root)?;
                self.lab.daemon_route_healthy(Duration::from_secs(30))?;
                self.expect_check(&root, 0, None, "one-writer-recovered")?;
                self.assert_client_session(&client_session)?;
                self.assert_client_traffic(&mut markers)?;
                // Separately prove that a mutation queued during apply executes
                // afterwards and that its reply follows effective closure.
                fs::remove_file(root.join("run/scupper/apply-paused"))?;
                fs::write(root.join("run/scupper/pause-apply"), b"pause")?;
                let mut second = self.lab.runner.background(
                    &Invocation::new(
                        "gwhost",
                        binary.to_str().ok_or("binary")?,
                        &["--test-root", root.to_str().ok_or("root")?, "apply"],
                    ),
                    &self.lab.artifacts.join("L44-ordered-apply.stdout"),
                )?;
                self.lab
                    .daemon_wait("L44 second apply paused", Duration::from_secs(5), |_| {
                        Ok(root.join("run/scupper/apply-paused").exists())
                    })?;
                let mut disconnect = self.lab.runner.background(
                    &Invocation::new(
                        "gwhost",
                        binary.to_str().ok_or("binary")?,
                        &["--test-root", root.to_str().ok_or("root")?, "disconnect"],
                    ),
                    &self.lab.artifacts.join("L44-queued-disconnect.stdout"),
                )?;
                self.lab.runner.dwell(Duration::from_millis(250))?;
                if disconnect.try_wait()?.is_some() {
                    return fail("L44 disconnect replied before paused apply completed");
                }
                fs::remove_file(root.join("run/scupper/pause-apply"))?;
                if !second.wait_timeout(Duration::from_secs(150))?.success()
                    || !disconnect.wait_timeout(Duration::from_secs(60))?.success()
                {
                    return fail("L44 ordered mutation failed");
                }
                let output =
                    fs::read_to_string(self.lab.artifacts.join("L44-queued-disconnect.stdout"))?;
                if !output.contains("traffic is now blocked") {
                    return fail("L44 disconnect omitted effective-closure reply");
                }
                let snapshot = serde_json::json!({
                    "v4":serde_json::from_str::<serde_json::Value>(&self.lab.cmd("scupper","ip",&["-j","-4","route","show","default"])?)?,
                    "v6":serde_json::from_str::<serde_json::Value>(&self.lab.cmd("scupper","ip",&["-j","-6","route","show","default"])?)?,
                    "exit":self.lab.cmd("scupper","ip",&["-o","link","show","ex-ch1"])?,
                });
                fs::write(
                    self.lab
                        .artifacts
                        .join("L44-queued-disconnect-closure.json"),
                    serde_json::to_vec_pretty(&snapshot)?,
                )?;
                self.assert_disconnect_snapshot("queued-disconnect")?;
                self.expect_check(
                    &root,
                    4,
                    Some(("FailClosed", "AdminDisconnected")),
                    "queued-disconnect-closed",
                )?;
                for family in ["-4", "-6"] {
                    if !self
                        .lab
                        .cmd("scupper", "ip", &[family, "route", "show", "default"])?
                        .contains("unreachable")
                    {
                        return fail("L44 queued disconnect left reachable defaults");
                    }
                }
                let (code, text) =
                    self.control_command(&root, &["connect"], "ordered-reconnect")?;
                if code != 0 {
                    return fail(text);
                }
                self.lab.service_check(&mut markers)?;
            }
            "L50" => {
                self.control_stop(Signal::TERM)?;
                fs::write(root.join("run/scupper/crash-after-selection"), b"crash")?;
                let (code, text) = self.control_command(&root, &["disconnect"], "crash")?;
                fs::remove_file(root.join("run/scupper/crash-after-selection"))?;
                if code == 0 || text.contains("traffic is now blocked") {
                    return fail("L50 crash claimed successful disconnect");
                }
                if !self
                    .lab
                    .cmd("scupper", "ip", &["route", "show", "default"])?
                    .contains("ex-ch1")
                {
                    return fail("L50 crash injection did not retain live exit route");
                }
                let (code, report) = self.lab.check_result(&Lab::boot_binary()?, &root)?;
                if code != 3 || !report.to_string().contains("DisconnectNotEffective") {
                    return fail(format!("L50 wrong intent-only failure: {code}: {report}"));
                }
                let (code, text) = self.control_command(&root, &["disconnect"], "tighten")?;
                if code != 0 || !text.contains("traffic is now blocked") {
                    return fail("L50 tightening did not verify closure");
                }
                self.expect_check(
                    &root,
                    4,
                    Some(("FailClosed", "AdminDisconnected")),
                    "tightened",
                )?;
                self.control_restart(&root, "socket-closure")?;
                let (code, text) = self.control_command(&root, &["connect"], "socket-connect")?;
                if code != 0 {
                    return fail(format!("L50 connect: {code}: {text}"));
                }
                fs::write(root.join("run/scupper/incomplete-tick"), b"hold")?;
                // Freeze reconciliation before injecting the ineffective route.
                self.lab.runner.dwell(Duration::from_millis(2200))?;
                self.lab
                    .cmd("scupper", "ip", &["link", "set", "ex-ch1", "up"])?;
                self.lab.cmd(
                    "scupper",
                    "ip",
                    &["route", "replace", "default", "dev", "ex-ch1"],
                )?;
                self.lab.daemon_route_healthy(Duration::from_secs(2))?;
                let (code, text) =
                    self.control_command(&root, &["disconnect"], "socket-ineffective")?;
                fs::remove_file(root.join("run/scupper/incomplete-tick"))?;
                if code != 3
                    || !text.contains("DisconnectNotEffective")
                    || !text.contains("transport: local socket")
                    || text.contains("traffic is now blocked")
                {
                    return fail(format!("L50 socket ineffective disconnect: {code}: {text}"));
                }
                let (code, text) = self.control_command(&root, &["connect"], "socket-reconnect")?;
                if code != 0 {
                    return fail(format!(
                        "L50 reconnect before ordering check: {code}: {text}"
                    ));
                }
                self.lab.daemon_route_healthy(Duration::from_secs(5))?;
                let (code, text) =
                    self.control_command(&root, &["disconnect"], "socket-tighten")?;
                if code != 0 || !text.contains("transport: local socket") {
                    return fail(format!("L50 socket closure: {code}: {text}"));
                }
                self.assert_disconnect_snapshot("socket-tighten")?;
                self.expect_check(
                    &root,
                    4,
                    Some(("FailClosed", "AdminDisconnected")),
                    "socket-closed",
                )?;
            }
            _ => return fail("unknown control case"),
        }
        if let Some(child) = &mut canary {
            child.alive()?;
            child.stop(Signal::TERM)?;
        }
        self.lab.stop_captures()?;
        self.lab.exit_port = self
            .lab
            .cmd("scupper", "wg", &["show", "ex-ch1", "listen-port"])?
            .trim()
            .parse()?;
        self.lab
            .daemon_oracle(&stem, &markers, start_port, self.lab.exit_port)?;
        if case == "L50" {
            // The measured trial ends closed. Restore service before the
            // separate deliberate-leak control exercises the capture oracle.
            self.control_restart(&root, "after-closure")?;
            let (code, output) = self.control_command(&root, &["connect"], "restore")?;
            if code != 0 {
                return fail(format!("L50 control recovery failed: {code}: {output}"));
            }
            self.expect_check(&root, 0, None, "restored-control")?;
        }
        self.lab.daemon_capture_control(&stem)?;
        Ok("positive_check=0; control_fault_verified=true; uplink_violations=0; saved JSON, command output, notify, events and pcap".into())
    }
}

fn exit_change(old: &str) -> Result<String> {
    let text = if old.contains("keepalive = \"25s\"") {
        old.replace("keepalive = \"25s\"", "keepalive = \"24s\"")
    } else {
        old.replace("keepalive = \"24s\"", "keepalive = \"25s\"")
    };
    if text == old {
        return fail("exit-only change did not change keepalive");
    }
    // Include the validator diagnostics if the fixture ever becomes invalid.
    validate(parse_site(&text)?).map_err(|errors| format!("exit change: {errors:?}"))?;
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exit_only_keepalive_change_respects_lab_handshake_budget() {
        let mut config = parse_site(include_str!("../../../lab/site-lab.toml")).unwrap();
        config.health.handshake_stale = scupper_core::config::DurationStr("175s".into());
        let original = toml::to_string(&config).unwrap();
        let changed = exit_change(&original).unwrap();
        assert!(changed.contains("keepalive = \"24s\""));
        assert_eq!(exit_change(&changed).unwrap(), original);
    }
}

#[cfg(test)]
mod session_tests {
    use super::{session_continues, session_has_traffic};
    #[test]
    fn counters_allow_idle_sessions_and_rekeys_but_reject_resets() {
        let before = "peer 100 1000 2000\n";
        assert!(session_continues(before, "peer 220 1100 2100"));
        assert!(session_continues(before, before));
        assert!(session_continues(before, "peer 100 1100 2000"));
        assert!(session_has_traffic(before, "peer 220 1100 2100"));
        assert!(!session_has_traffic(before, before));
        assert!(!session_has_traffic(before, "peer 100 1100 2000"));
        assert!(!session_has_traffic(before, "peer 100 1000 2100"));
        for after in [
            "peer 220 1 2100",
            "peer 220 1100 1",
            "other 100 1100 2100",
            "peer 99 1100 2100",
        ] {
            assert!(!session_continues(before, after));
        }
    }
}
