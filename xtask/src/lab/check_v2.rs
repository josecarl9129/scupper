//! Real check CLI against an immutable store and the boot-built topology. Mount
//! overlays confine its fixed production roots to the lab's private directory.
use super::{
    Lab, Result,
    command::{Group, Invocation},
    evidence::{self, Row},
    fail, helpers,
};
use scupper_core::{
    config::{DurationStr, GatewayId, HealthSettings, parse_site, validate},
    render::{VersionStamp, render_netns},
};
use scupper_sys::{
    lock::WriterLock,
    state::{State, StateFile},
    store::{MetaInput, VersionStore},
};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Seek, SeekFrom},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

// Keep /run/netns propagation intact. Isolate only the two overlay destinations
// before binding: a recursive propagation change at / would include nsfs peers.
const CHECK: &str = r#"
set -eu
# / is always a mount point; never let a missing or failing `mountpoint` skip it.
mount --make-private /
for path in /etc /var /var/lib; do
    if mountpoint -q "$path"; then
        mount --make-private "$path"
    fi
done
mount --bind "$1/etc" /etc
mount --make-private /etc
mount --bind "$1/var-lib" /var/lib
mount --make-private /var/lib
exec nsenter --net=/run/netns/gwhost -- "$2" --test-root "$1" check --json
"#;

// Each row proves the intended stage, even when several verdicts share a code.
fn verdict_matches(name: &str, report: &serde_json::Value) -> bool {
    let verdict = &report["verdict"];
    match name {
        "default" => {
            verdict["Degraded"]["DefaultRouteWrong"]["family"] == "V4"
                && verdict["Degraded"]["DefaultRouteWrong"]["got"] == "Missing"
        }
        "ruleset" => verdict["Unprotected"]
            .as_array()
            .is_some_and(|found| found.iter().any(|v| v.get("RulesetDiffers").is_some())),
        "local-table" => verdict["Unprotected"].as_array().is_some_and(|found| {
            found.iter().any(|v| {
                v["ExtraRoute"]["table"] == "local"
                    && v["ExtraRoute"]["dst"] == "128.0.0.0/1"
                    && v["ExtraRoute"]["dev"] == "wg0"
            })
        }),
        "exit-down" => verdict["FailClosed"] == "NoHealthyExit",
        _ => verdict["Protected"]["exit_ip"]
            .as_str()
            .is_some_and(|ip| ip.parse::<std::net::IpAddr>().is_ok()),
    }
}

// JSON equivalent of Report::session_only: unknown diagnoses and missing warnings
// fail immediately. The parity test below uses actual serialized core Reports.
fn session_recovery_pending(code: i32, report: &serde_json::Value) -> bool {
    code == 3
        && matches!(
            report["verdict"]["Degraded"].as_str(),
            Some("ClientSessionsUnknown" | "ClientSessionsReset" | "ClientSessionTelemetryUnknown")
        )
        && report["warnings"].as_array().is_some_and(|warnings| {
            warnings.iter().all(|warning| {
                matches!(
                    warning.as_str(),
                    Some(
                        "ClientHandshakesStale"
                            | "IdleClientSessionsReset"
                            | "ClientSessionsPending"
                            | "ClientSessionPeerMissing"
                            | "ClientSessionTelemetryUnavailable"
                            | "ClientSessionsExpiredUnconfirmed"
                            | "ClientSessionHistoryUnavailable"
                    )
                )
            })
        })
}

// Keep marker identities and their reply logs with the process guards so every
// recovery caller (including daemon cases) uses the same served-traffic oracle.
pub(super) struct RecoveryFlow {
    ns: &'static str,
    marker: String,
    log: PathBuf,
    process: Group,
}

fn recovery_markers() -> Result<[(&'static str, String); 2]> {
    Ok([("client", Lab::marker()?), ("client2", Lab::marker()?)])
}

fn log_size(path: &Path) -> Result<u64> {
    match fs::metadata(path) {
        Ok(meta) => Ok(meta.len()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(error) => Err(error.into()),
    }
}

// Only complete records begun after the checkpoint count. A writer may have
// been halfway through a record at check exit, or still be appending its tail.
fn fresh_log(path: &Path, offset: u64) -> Result<String> {
    let mut file = match fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(String::new()),
        Err(error) => return Err(error.into()),
    };
    if file.metadata()?.len() < offset {
        return fail(format!("recovery log was truncated: {}", path.display()));
    }
    file.seek(SeekFrom::Start(offset.saturating_sub(1)))?;
    let mut text = String::new();
    file.read_to_string(&mut text)?;
    let tail = if offset == 0 {
        text.as_str()
    } else {
        text.split_once('\n').map_or("", |(_, tail)| tail)
    };
    Ok(tail
        .rsplit_once('\n')
        .map_or("", |(complete, _)| complete)
        .to_owned())
}

fn recovery_served(marker: &str, sink: &str, flow: &str) -> Result<(bool, bool)> {
    let receipt = helpers::receipts(sink)?.iter().any(|receipt| {
        receipt.marker == marker
            && receipt.protocol == "udp"
            && receipt.peer.ip().to_string() == super::addresses::A.provider.peer
    });
    let mut reply = false;
    for line in flow.lines() {
        let value: serde_json::Value = serde_json::from_str(line)?;
        reply |= value["received"].as_u64().is_some_and(|n| n > 0);
    }
    Ok((receipt, reply))
}

impl Lab {
    pub(super) fn check_v2_case(&mut self) -> Result<String> {
        let binary = fs::canonicalize(
            std::env::current_exe()?
                .parent()
                .and_then(Path::parent)
                .ok_or("lab executable must be in target/{profile}")?
                .join("debug/scupper"),
        )?;
        let root = self.prepare_check_v2()?;
        let result = self.check_v2_faults(&binary, &root);
        // Restore the boot-built state even after an assertion/launcher failure.
        let restored = (|| {
            // These faults may still be active after an assertion/launcher error.
            let _ = self.cmd(
                "scupper",
                "ip",
                &[
                    "route",
                    "del",
                    "128.0.0.0/1",
                    "dev",
                    "wg0",
                    "table",
                    "local",
                ],
            );
            let _ = self.cmd("gwhost", "ip", &["link", "del", "wg-legacy"]);
            self.cmd("scupper", "ip", &["link", "set", "ex-ch1", "up"])?;
            self.cmd(
                "scupper",
                "ip",
                &["route", "replace", "default", "dev", "ex-ch1"],
            )?;
            self.load_real_rules()?;
            self.wait_provider()?;
            self.service_check(&mut Vec::new())
        })();
        match (result, restored) {
            (Ok(result), Ok(())) => Ok(result),
            (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
            (Err(error), Err(restore)) => fail(format!("{error}; restore: {restore}")),
        }
    }

    pub(super) fn prepare_check_v2(&mut self) -> Result<PathBuf> {
        let root = self.private.join("boot-root");
        if root.is_dir() {
            return self.prepare_short_boot_root();
        }
        let etc = root.join("etc/scupper");
        let state = root.join("var-lib/scupper");
        fs::create_dir_all(&etc)?;
        fs::create_dir_all(&state)?;
        for account in ["passwd", "group"] {
            fs::copy(
                Path::new("/etc").join(account),
                root.join("etc").join(account),
            )?;
        }
        fs::write(etc.join("gateway-id"), "gw1\n")?;
        for kind in ["secrets", "secrets/wg", "secrets/url"] {
            let path = etc.join(kind);
            fs::create_dir(&path)?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        }
        fs::create_dir_all(root.join("run/scupper"))?;
        for (key, reference) in [("gateway", "lab-client"), ("exit", "lab-exit")] {
            let path = etc.join("secrets/wg").join(reference);
            fs::copy(self.private.join(format!("{key}.key")), &path)?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        }
        // Runtime public identities and real HTTPS probes describe the boot inputs.
        let text = fs::read_to_string(self.private.join("runtime-site.toml"))?;
        let mut config = parse_site(&text)?;
        config.health.probe_targets = HealthSettings::default().probe_targets;
        // Minimum allowed WireGuard rekey interval + slack. L3 must observe
        // staleness with a single exit, rather than relying on probe failures.
        config.health.handshake_stale = DurationStr("175s".into());
        config.health.failover_grace = DurationStr("30s".into());
        config.health.require_daemon = false; // scupperd is deliberately absent in this lab.
        let text = toml::to_string(&config)?;
        self.site = validate(config).map_err(|errors| format!("check lab config: {errors:?}"))?;
        let writer = WriterLock::acquire(root.join("writer"))?;
        let store = VersionStore::open_with_mirror_root(&state, &etc, Some(&writer))?;
        let version = store.commit(
            &writer,
            None,
            &text,
            MetaInput {
                actor: "lab".into(),
                at: 1,
                reason: "boot-built namespace lab".into(),
            },
        )?;
        StateFile::open(&state, Some(&writer))?.write(
            &writer,
            &State {
                applied_version: Some(version),
                ..State::default()
            },
        )?;
        let rules = render_netns(
            &self.site,
            &GatewayId("gw1".into()),
            &VersionStamp {
                version,
                sha256: Sha256::digest(text.as_bytes()).into(),
            },
        )?;
        store.write_rendered(&writer, version, &rules)?;
        fs::write(&self.rules, rules)?;
        let gateway = self
            .site
            .gateway(&GatewayId("gw1".into()))
            .ok_or("gateway missing")?;
        scupper_sys::client_sessions::provision(
            &state,
            gateway.client_tunnel().identity().public_key.as_str(),
            scupper_sys::system::System::now_unix_secs(&scupper_sys::system::RealSystem::default()),
            &writer,
        )?;
        self.prepare_short_boot_root()
    }

    pub(super) fn start_lab_sampler(&mut self) -> Result<()> {
        if self.sampler.is_none() && !self.site.health().require_daemon() {
            self.sampler = Some(scupper_sys::client_sessions::Sampler::start(
                self.boot_root.join("var-lib/scupper"),
                self.boot_root.join("run/scupper"),
                std::sync::Arc::new(scupper_sys::netns::NetnsHandle::open("/run/netns/scupper")?),
                Self::boot_binary()?,
                &self.site,
                &GatewayId("gw1".into()),
            )?);
        }
        Ok(())
    }
    // Keep private state in place; only the public runtime pathname needs shortening.
    fn prepare_short_boot_root(&mut self) -> Result<PathBuf> {
        use super::cleanup::Resource;
        use std::os::unix::fs::{DirBuilderExt, MetadataExt, symlink};
        if !self.boot_root_ready {
            let parent = Path::new("/run/scupper-lab");
            match fs::DirBuilder::new().mode(0o755).create(parent) {
                Ok(()) => {
                    self.registry.register(Resource::Directory(parent.into()));
                    fs::set_permissions(parent, fs::Permissions::from_mode(0o755))?;
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
            let meta = fs::symlink_metadata(parent)?;
            if !meta.is_dir() || meta.uid() != 0 || meta.mode() & 0o777 != 0o755 {
                return fail("/run/scupper-lab must be a root-owned 0755 directory");
            }
            fs::DirBuilder::new().mode(0o755).create(&self.boot_root)?;
            self.registry
                .register(Resource::Directory(self.boot_root.clone()));
            fs::set_permissions(&self.boot_root, fs::Permissions::from_mode(0o755))?;
            let storage = self.private.join("boot-root");
            for name in ["etc", "var-lib", "run"] {
                symlink(storage.join(name), self.boot_root.join(name))?;
            }
            self.boot_root_ready = true;
        }
        Ok(self.boot_root.clone())
    }

    pub(super) fn check_result(
        &mut self,
        binary: &Path,
        root: &Path,
    ) -> Result<(i32, serde_json::Value)> {
        let (status, stdout) = self.runner.output_timeout(
            &Invocation::new(
                "",
                "unshare",
                &[
                    "--mount",
                    "--propagation",
                    "unchanged",
                    "--",
                    "/bin/sh",
                    "-c",
                    CHECK,
                    "check-v2",
                    root.to_str().ok_or("non-UTF8 check root")?,
                    binary.to_str().ok_or("non-UTF8 binary")?,
                ],
            ),
            None,
            15,
        )?;
        let result = parse_check_output(&self.artifacts, status, &stdout)?;
        if result.0 == 0 {
            self.assert_client_link()?;
        }
        Ok(result)
    }

    // 180 s reconstruction + 15 s first-sample bound + 30 s check/startup
    // allowance + 15 s runner slack. Traffic continues for both configured peers.
    pub(super) fn recovery_traffic(&mut self, stem: &str) -> Result<Vec<RecoveryFlow>> {
        let mut flows = Vec::new();
        for (ns, marker) in recovery_markers()? {
            let stem = format!("session-recovery-{stem}-{ns}");
            let process = self.daemon_flow("udp", ns, &marker, &stem, 240)?;
            flows.push(RecoveryFlow {
                ns,
                marker,
                log: self.artifacts.join(format!("{stem}-udp.jsonl")),
                process,
            });
        }
        Ok(flows)
    }

    // Called only after observing check exit 0. Snapshot all logs at that point:
    // neither pre-recovery receipts nor replies can satisfy this assertion.
    pub(super) fn assert_recovery_served(&mut self, flows: &mut [RecoveryFlow]) -> Result<()> {
        let sink = self.artifacts.join("sink.jsonl");
        let sink_offset = log_size(&sink)?;
        let offsets = flows
            .iter()
            .map(|flow| log_size(&flow.log))
            .collect::<Result<Vec<_>>>()?;
        let until = Instant::now() + Duration::from_secs(5);
        loop {
            self.ensure_services().map_err(|error| {
                format!("false 0: check exited 0 but recovery service failed: {error}")
            })?;
            let receipts = fresh_log(&sink, sink_offset)?;
            let mut missing = Vec::new();
            for (flow, offset) in flows.iter_mut().zip(&offsets) {
                flow.process.alive().map_err(|error| {
                    format!(
                        "false 0: check exited 0 but {} recovery flow failed: {error}",
                        flow.ns
                    )
                })?;
                let (receipt, reply) =
                    recovery_served(&flow.marker, &receipts, &fresh_log(&flow.log, *offset)?)?;
                if !receipt || !reply {
                    missing.push(format!(
                        "{} marker {}: sink receipt={receipt}, flow received>0={reply}",
                        flow.ns, flow.marker
                    ));
                }
            }
            if missing.is_empty() {
                return Ok(());
            }
            if Instant::now() >= until {
                return fail(format!(
                    "false 0: check exited 0 without served recovery traffic from both clients within 5 s after exit: {}",
                    missing.join("; ")
                ));
            }
            self.runner.dwell(Duration::from_millis(50))?;
        }
    }
    pub(super) fn wait_session_recovery(
        &mut self,
        binary: &Path,
        root: &Path,
    ) -> Result<(i32, serde_json::Value)> {
        let mut traffic = self.recovery_traffic("check")?;
        let started = std::time::Instant::now();
        let until = started + std::time::Duration::from_secs(240);
        self.runner.phase = self.runner.phase.max(until).min(self.runner.whole);
        loop {
            let mut result = self.check_result(binary, root)?;
            if !session_recovery_pending(result.0, &result.1) {
                if result.0 == 0 {
                    result.1["session_time_to_0_ms"] =
                        serde_json::json!(started.elapsed().as_millis());
                    self.assert_recovery_served(&mut traffic)?;
                }
                return Ok(result);
            }
            if std::time::Instant::now() >= until {
                return fail(format!("session recovery exceeded 240 s: {}", result.1));
            }
            self.runner.dwell(std::time::Duration::from_secs(1))?;
        }
    }

    fn check_row(
        &mut self,
        name: &str,
        want: i32,
        code: i32,
        report: &serde_json::Value,
        skip: Option<&str>,
    ) -> Result<()> {
        self.rows.push(Row {
            name: format!("check-v2-{name}"),
            wanted: want.to_string(),
            got: if skip.is_some() {
                "skipped".into()
            } else {
                code.to_string()
            },
            detail: skip.map_or_else(|| report.to_string(), str::to_owned),
        });
        evidence::save_results(&self.artifacts, &self.rows)?;
        if skip.is_none() && (code != want || !verdict_matches(name, report)) {
            // Diagnostic only: the namespace route tables at the time of the mismatch.
            let mut dump = Vec::new();
            for args in [
                &["-d", "-j", "route", "show", "table", "all"][..],
                &["-6", "-d", "-j", "route", "show", "table", "all"][..],
                &["-j", "route", "show", "default"][..],
                &["-6", "-j", "route", "show", "default"][..],
            ] {
                let out = self
                    .cmd("scupper", "ip", args)
                    .unwrap_or_else(|e| e.to_string());
                dump.push(format!("== ip {}\n{out}", args.join(" ")));
            }
            fs::write(
                self.artifacts.join(format!("check-v2-{name}.routes.txt")),
                dump.join("\n"),
            )?;
            return fail(format!(
                "check-v2 {name}: wanted {want} and its specific verdict, got {code}: {report}"
            ));
        }
        Ok(())
    }

    #[allow(clippy::too_many_lines)] // Keep each injected fault beside its assertion and restoration.
    fn check_v2_faults(&mut self, binary: &Path, root: &Path) -> Result<String> {
        let (code, report) = self.wait_session_recovery(binary, root)?;
        // Skip only a classified exit-path error after every local stage passed.
        // A setup/collection error, wrong route or containment failure must fail.
        let no_internet = code == 3
            && report["verdict"]["Degraded"]
                .get("ExitProbeFailed")
                .is_some();
        let reason =
            no_internet.then(|| format!("runner internet unavailable through provA: {report}"));
        self.check_row("healthy", 0, code, &report, reason.as_deref())?;
        for fault in [
            "host-wg-other-port",
            "default",
            "ruleset",
            "local-table",
            "exit-down",
        ] {
            let expected = match fault {
                "host-wg-other-port" => {
                    self.cmd(
                        "gwhost",
                        "ip",
                        &["link", "add", "wg-legacy", "type", "wireguard"],
                    )?;
                    self.cmd(
                        "gwhost",
                        "wg",
                        &["set", "wg-legacy", "listen-port", "51822"],
                    )?;
                    0
                }
                "local-table" => {
                    self.cmd(
                        "scupper",
                        "ip",
                        &[
                            "route",
                            "add",
                            "128.0.0.0/1",
                            "dev",
                            "wg0",
                            "table",
                            "local",
                        ],
                    )?;
                    2
                }
                "default" => {
                    self.cmd("scupper", "ip", &["route", "del", "default"])?;
                    3
                }
                "ruleset" => {
                    self.cmd(
                        "scupper",
                        "nft",
                        &[
                            "add", "rule", "inet", "scupper", "forward", "iifname", "wg0",
                            "oifname", "lab-x", "accept",
                        ],
                    )?;
                    2
                }
                _ => {
                    self.cmd("scupper", "ip", &["link", "set", "ex-ch1", "down"])?;
                    4
                }
            };
            let (code, report) = self.check_result(binary, root)?;
            if fault == "exit-down" {
                let defaults: serde_json::Value = serde_json::from_str(&self.cmd(
                    "scupper",
                    "ip",
                    &["-j", "route", "show", "default"],
                )?)?;
                if !defaults.as_array().is_some_and(Vec::is_empty) {
                    return fail(format!("exit-down retained a default: {defaults}"));
                }
            }
            let skip = reason.as_deref().filter(|_| {
                fault == "default" && verdict_matches(fault, &report)
                    || fault == "host-wg-other-port"
                        && report["verdict"]["Degraded"]
                            .get("ExitProbeFailed")
                            .is_some()
            });
            self.check_row(fault, expected, code, &report, skip)?;
            if fault == "local-table" {
                self.cmd(
                    "scupper",
                    "ip",
                    &[
                        "route",
                        "del",
                        "128.0.0.0/1",
                        "dev",
                        "wg0",
                        "table",
                        "local",
                    ],
                )?;
            }
            if fault == "host-wg-other-port" {
                self.cmd("gwhost", "ip", &["link", "del", "wg-legacy"])?;
            }
            self.cmd("scupper", "ip", &["link", "set", "ex-ch1", "up"])?;
            self.cmd(
                "scupper",
                "ip",
                &["route", "replace", "default", "dev", "ex-ch1"],
            )?;
            self.load_real_rules()?;
            self.wait_provider()?;
            let (code, report) = self.wait_session_recovery(binary, root)?;
            self.check_row(
                &format!("restore-{fault}"),
                0,
                code,
                &report,
                reason.as_deref().filter(|_| {
                    code == 3
                        && report["verdict"]["Degraded"]
                            .get("ExitProbeFailed")
                            .is_some()
                }),
            )?;
        }
        Ok(reason.map_or_else(
            || "Protected and host wg on another port; DefaultRouteWrong, RulesetDiffers, ExtraRoute, NoHealthyExit; all restores Protected".into(),
            |reason| format!("skipped healthy, host-wg-other-port, default and restores: {reason}; RulesetDiffers, ExtraRoute and NoHealthyExit verified"),
        ))
    }
}

fn parse_check_output(
    artifacts: &Path,
    status: std::process::ExitStatus,
    stdout: &str,
) -> Result<(i32, serde_json::Value)> {
    static NEXT_OUTPUT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let output_path = artifacts.join(format!(
        "check-v2-{}.stdout",
        NEXT_OUTPUT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    // output_timeout has waited for exit and both pipe readers' EOF. Save
    // even invalid/partial output before interpreting the command's result.
    fs::write(&output_path, stdout)?;
    let code = status.code().filter(|code| (0..=5).contains(code)).ok_or_else(|| format!(
        "capture harness error: check-v2 command ended with {status}; raw output saved at {}",
        output_path.display()
    ))?;
    let report = serde_json::from_str(stdout).map_err(|error| {
        format!(
            "capture harness error: check-v2 JSON ({status}): {error}; raw output saved at {}",
            output_path.display()
        )
    })?;
    Ok((code, report))
}

#[cfg(test)]
mod tests {
    use super::{CHECK, parse_check_output, session_recovery_pending, verdict_matches};
    use serde_json::json;

    #[test]
    fn daemon_flow_markers_satisfy_sink_contract() -> super::Result<()> {
        // Ordinary daemon_flow callers use Lab::marker; recovery callers use
        // this builder. Validate both against the actual sink's contract.
        for _ in 0..32 {
            assert!(super::helpers::valid_marker(&super::Lab::marker()?));
            let markers = super::recovery_markers()?;
            assert_eq!(markers[0].0, "client");
            assert_eq!(markers[1].0, "client2");
            assert_ne!(markers[0].1, markers[1].1);
            for (_, marker) in markers {
                assert!(super::helpers::valid_marker(&marker), "{marker}");
            }
        }
        assert!(!super::helpers::valid_marker(
            "session-recovery-check-client"
        ));
        Ok(())
    }

    #[test]
    fn recovery_requires_each_clients_udp_receipt_and_positive_reply() -> super::Result<()> {
        let markers = super::recovery_markers()?;
        let receipt = |marker: &str, protocol: &str, peer: &str| {
            json!({"marker":marker,"protocol":protocol,"peer":peer}).to_string()
        };
        let sink = receipt(&markers[0].1, "udp", "192.0.2.6:12345");
        let nat = format!("{}:12345", super::super::addresses::A.provider.peer);
        let sink = format!("{sink}\n{}", receipt(&markers[0].1, "udp", &nat));
        let reply = "{\"received\":48,\"sent\":48}";
        assert_eq!(
            super::recovery_served(&markers[0].1, &sink, reply)?,
            (true, true)
        );
        // Serving client alone cannot prove client2 was served.
        assert_eq!(
            super::recovery_served(&markers[1].1, &sink, reply)?,
            (false, true)
        );
        let both = format!("{sink}\n{}", receipt(&markers[1].1, "udp", &nat));
        for (_, marker) in &markers {
            assert_eq!(super::recovery_served(marker, &both, reply)?, (true, true));
            assert_eq!(
                super::recovery_served(marker, &both, "{\"received\":0}")?,
                (true, false)
            );
            assert_eq!(super::recovery_served(marker, &both, "")?, (true, false));
            for invalid in [
                receipt(marker, "tcp", &nat),
                receipt(marker, "udp", "192.0.2.6:12345"),
                String::new(),
            ] {
                assert_eq!(
                    super::recovery_served(marker, &invalid, reply)?,
                    (false, true)
                );
            }
        }
        assert!(super::recovery_served(&markers[0].1, "bad JSON", reply).is_err());
        assert!(super::recovery_served(&markers[0].1, &both, "bad JSON").is_err());
        Ok(())
    }

    #[test]
    fn recovery_evidence_excludes_pre_zero_and_partial_records() -> super::Result<()> {
        use std::{fs, io::Write};
        let root = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("recovery-evidence-{}", std::process::id()));
        fs::create_dir_all(&root)?;
        let log = root.join("flow.jsonl");
        assert_eq!(super::log_size(&log)?, 0);
        assert_eq!(super::fresh_log(&log, 0)?, "");
        // This old successful record and in-progress record cannot be used
        // even after the in-progress record finishes following check exit 0.
        fs::write(&log, "{\"received\":48}\n{\"received\":")?;
        let offset = super::log_size(&log)?;
        let mut file = fs::OpenOptions::new().append(true).open(&log)?;
        file.write_all(b"48}\n{\"received\":0}\n{\"received\":48}")?;
        assert_eq!(super::fresh_log(&log, offset)?, "{\"received\":0}");
        file.write_all(b"\n")?;
        assert_eq!(
            super::fresh_log(&log, offset)?,
            "{\"received\":0}\n{\"received\":48}"
        );
        // A checkpoint on a record boundary includes the very next record.
        let boundary = super::log_size(&log)?;
        file.write_all(b"{\"received\":1}\n")?;
        assert_eq!(super::fresh_log(&log, boundary)?, "{\"received\":1}");
        assert!(super::fresh_log(&log, 0)?.starts_with("{\"received\":48}"));
        drop(file);
        fs::write(&log, "")?;
        assert!(super::fresh_log(&log, offset).is_err());
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn session_wait_retries_only_core_session_only_reports() -> super::Result<()> {
        use scupper_core::verdict::v2::{Degraded, Report, Verdict, Warning};
        let session_warnings = vec![
            Warning::ClientHandshakesStale,
            Warning::IdleClientSessionsReset,
            Warning::ClientSessionsPending,
            Warning::ClientSessionPeerMissing,
            Warning::ClientSessionTelemetryUnavailable,
            Warning::ClientSessionsExpiredUnconfirmed,
            Warning::ClientSessionHistoryUnavailable,
        ];
        for reason in [
            Degraded::ClientSessionsUnknown,
            Degraded::ClientSessionsReset,
            Degraded::ClientSessionTelemetryUnknown,
        ] {
            for warnings in [vec![], session_warnings.clone(), vec![Warning::ClockSkew]] {
                let report = Report {
                    verdict: Verdict::Degraded(reason.clone()),
                    warnings,
                    at: 1,
                    config_version: 1,
                };
                let json = serde_json::to_value(&report)?;
                assert_eq!(session_recovery_pending(3, &json), report.session_only());
                for code in [0, 1, 2, 4, 5] {
                    assert!(!session_recovery_pending(code, &json));
                }
            }
        }
        // Non-session verdicts and mixed/unknown warnings must return immediately.
        for verdict in [
            json!({"Degraded": {"DefaultRouteWrong": {"family": "V4", "got": "Missing"}}}),
            json!({"Degraded": "ExitHandshakeStale"}),
            json!({"Degraded": "ExitProbeFailed"}),
            json!({"FailClosed": "NoHealthyExit"}),
            json!({"Unprotected": []}),
            json!({"Unsupervised": {}}),
            json!({"Protected": {}}),
        ] {
            assert!(!session_recovery_pending(
                3,
                &json!({"verdict": verdict, "warnings": []})
            ));
        }
        for warnings in [
            json!(["ClientSessionsPending", "ClockSkew"]),
            json!(["FutureWarning"]),
            json!(null),
        ] {
            assert!(!session_recovery_pending(
                3,
                &json!({"verdict": {"Degraded": "ClientSessionsReset"}, "warnings": warnings})
            ));
        }
        Ok(())
    }

    #[test]
    fn check_json_errors_retain_raw_output_and_distinguish_timeout() -> super::Result<()> {
        use std::{fs, os::unix::process::ExitStatusExt, process::ExitStatus};
        let root = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("check-json-errors-{}", std::process::id()));
        fs::create_dir_all(&root)?;
        for (code, raw) in [(0, "{\"schema\":1,"), (124, "{\"schema\":1,")] {
            let error = parse_check_output(&root, ExitStatus::from_raw(code << 8), raw)
                .err()
                .ok_or("partial JSON accepted")?
                .to_string();
            assert!(error.contains("capture harness error"), "{error}");
            assert!(error.contains(&format!("exit status: {code}")), "{error}");
            let saved = error
                .split("raw output saved at ")
                .nth(1)
                .ok_or("missing raw path")?;
            assert_eq!(fs::read_to_string(saved)?, raw);
            if code == 124 {
                assert!(error.contains("command ended"), "{error}");
            } else {
                assert!(error.contains("EOF"), "{error}");
            }
        }
        // A valid adverse verdict is still data, rather than a harness failure.
        let (code, report) =
            parse_check_output(&root, ExitStatus::from_raw(5 << 8), "{\"schema\":1}")?;
        assert_eq!(code, 5);
        assert_eq!(report["schema"], 1);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn check_isolates_only_mounted_overlay_ancestors() -> Result<(), Box<dyn std::error::Error>> {
        // Exercise the actual shell decisions for ordinary and separately
        // mounted /etc and /var layouts, without issuing privileged syscalls.
        let setup = CHECK.split("exec nsenter").next().ok_or("missing setup")?;
        for (points, private) in [
            ("/", vec!["/"]),
            ("/|/etc|/var", vec!["/", "/etc", "/var"]),
            ("/|/var/lib", vec!["/", "/var/lib"]),
        ] {
            let script = format!(
                r#"
mountpoint() {{ case "$2" in {points}) return 0;; *) return 1;; esac; }}
mount() {{ printf '%s\n' "$*"; }}
{setup}
"#
            );
            let output = std::process::Command::new("/bin/sh")
                .args(["-c", &script, "check-test", "/lab-root"])
                .output()?;
            assert!(output.status.success());
            let mut expected: Vec<_> = private
                .into_iter()
                .map(|path| format!("--make-private {path}"))
                .collect();
            expected.extend([
                "--bind /lab-root/etc /etc".into(),
                "--make-private /etc".into(),
                "--bind /lab-root/var-lib /var/lib".into(),
                "--make-private /var/lib".into(),
            ]);
            assert_eq!(
                String::from_utf8(output.stdout)?,
                expected.join("\n") + "\n"
            );
        }
        Ok(())
    }

    #[test]
    fn lab_rows_require_specific_verdicts_and_healthy_exit_ip() {
        let probe_failure = json!({"verdict":{"Degraded":{"ExitProbeFailed":"path"}}});
        for row in [
            "healthy",
            "default",
            "ruleset",
            "local-table",
            "exit-down",
            "host-wg-other-port",
            "restore-default",
        ] {
            assert!(!verdict_matches(row, &probe_failure), "{row}");
        }
        assert!(verdict_matches(
            "healthy",
            &json!({"verdict":{"Protected":{"exit_ip":"8.8.4.4"}}})
        ));
        assert!(!verdict_matches(
            "healthy",
            &json!({"verdict":{"Protected":{}}})
        ));
        assert!(verdict_matches(
            "default",
            &json!({"verdict":{"Degraded":{"DefaultRouteWrong":{"family":"V4","got":"Missing"}}}})
        ));
        assert!(verdict_matches(
            "ruleset",
            &json!({"verdict":{"Unprotected":[{"RulesetDiffers":{}}]}})
        ));
        assert!(!verdict_matches(
            "ruleset",
            &json!({"verdict":{"Unprotected":[{"ForeignLink":"eth0"}]}})
        ));
        assert!(verdict_matches(
            "local-table",
            &json!({"verdict":{"Unprotected":[{"ExtraRoute":{"table":"local","dst":"128.0.0.0/1","dev":"wg0"}}]}})
        ));
        assert!(verdict_matches(
            "exit-down",
            &json!({"verdict":{"FailClosed":"NoHealthyExit"}})
        ));
    }
}
