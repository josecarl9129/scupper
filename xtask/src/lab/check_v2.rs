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
    collections::BTreeMap,
    fs,
    io::{Read, Seek, SeekFrom, Write},
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

// Idle peers may need their own WireGuard retry (2 x (10 s + 5 s),
// plus 5 s slack). Required active peers retain the strict five-second budget.
fn recovery_budget(
    report: &serde_json::Value,
    peer: Option<&serde_json::Value>,
    now: u64,
    activity: Option<&PeerActivity>,
) -> Duration {
    let idle = peer.is_some_and(|peer| {
        matches!(
            peer["state"].as_str(),
            Some("Unknown" | "ExpiredUnconfirmed")
        ) && match peer.get("lease_until") {
            Some(serde_json::Value::Null) => true,
            Some(value) => value.as_u64().is_some_and(|until| now >= until),
            None => false,
        }
    });
    if idle
        && activity.is_some_and(|activity| activity.idle_at(now))
        && report["warnings"].as_array().is_some_and(|warnings| {
            warnings
                .iter()
                .any(|warning| warning == "IdleClientSessionsReset")
        })
    {
        Duration::from_secs(35)
    } else {
        Duration::from_secs(5)
    }
}

// Lab evidence only. Missing/unreadable evidence never grants an idle allowance.
// Ten seconds covers sample/scheduling slack beyond the product's 180 s lease.
// This deliberately keeps the strict bound for about five seconds after a
// product lease can expire; that conservative overlap can cause lab flakes.
pub(super) fn lab_now() -> u64 {
    scupper_sys::system::System::now_unix_secs(&scupper_sys::system::RealSystem::default())
}
const LAB_LEASE_WINDOW: u64 = 190;
#[derive(Default)]
struct PeerActivity {
    last_served: Option<u64>,
}
impl PeerActivity {
    fn idle_at(&self, now: u64) -> bool {
        self.last_served
            .is_none_or(|last| now.saturating_sub(last) > LAB_LEASE_WINDOW)
    }
}

// Independent kernel observations, never scupper's persisted session telemetry.
// A reset or first nonzero sample has unknown history, so count it as active now.
#[derive(Default)]
pub(super) struct GatewayActivity {
    peers: BTreeMap<String, KernelActivity>,
}
#[derive(Default)]
struct KernelActivity {
    counters: Option<(u64, u64)>,
    last_active: Option<u64>,
    valid: bool,
}
impl GatewayActivity {
    fn observe(&mut self, ns: &str, rx: u64, tx: u64, handshake: u64, now: u64) {
        let peer = self.peers.entry(ns.into()).or_default();
        if peer
            .counters
            .map_or(rx > 0 || tx > 0, |old| old != (rx, tx))
        {
            peer.last_active = Some(now);
        }
        if handshake > 0 {
            peer.last_active = Some(peer.last_active.map_or(handshake, |old| old.max(handshake)));
        }
        peer.counters = Some((rx, tx));
        peer.valid = true;
    }

    fn include(&self, ns: &str, activity: Option<PeerActivity>) -> Option<PeerActivity> {
        let peer = self.peers.get(ns).filter(|peer| peer.valid)?;
        let mut activity = activity?;
        if let Some(at) = peer.last_active {
            activity.last_served = Some(activity.last_served.map_or(at, |old| old.max(at)));
        }
        Some(activity)
    }
}

// Public wg views contain peer keys and counters only; never request a dump.
fn kernel_samples(transfer: &str, handshakes: &str) -> Result<BTreeMap<[u8; 32], (u64, u64, u64)>> {
    let mut samples = BTreeMap::new();
    for line in transfer.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() != 3 {
            return fail("harness: malformed gateway transfer evidence");
        }
        let key = scupper_core::config::PublicKey(fields[0].into())
            .bytes()
            .map_err(|_| "harness: invalid gateway peer key")?;
        if samples.contains_key(&key) {
            return fail("harness: duplicate gateway transfer evidence");
        }
        samples.insert(key, (fields[1].parse()?, fields[2].parse()?, 0));
    }
    let mut seen = std::collections::BTreeSet::new();
    for line in handshakes.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() != 2 {
            return fail("harness: malformed gateway handshake evidence");
        }
        let key = scupper_core::config::PublicKey(fields[0].into())
            .bytes()
            .map_err(|_| "harness: invalid gateway peer key")?;
        if !seen.insert(key) {
            return fail("harness: duplicate gateway handshake evidence");
        }
        let sample = samples.get_mut(&key).ok_or("gateway peer views disagree")?;
        sample.2 = fields[1].parse()?;
    }
    if seen.len() != samples.len() {
        return fail("harness: incomplete gateway handshake evidence");
    }
    Ok(samples)
}

fn peer_activity(logs: &[(String, PathBuf)], ns: &str) -> Result<Option<PeerActivity>> {
    let mut activity = None;
    for (_, path) in logs.iter().filter(|(peer, _)| peer == ns) {
        if !path.try_exists()? {
            return Ok(None);
        }
        let evidence = activity.get_or_insert_with(PeerActivity::default);
        for line in fresh_log(path, 0)?.lines() {
            let value: serde_json::Value = serde_json::from_str(line)?;
            if value["received"].as_u64().is_some_and(|n| n > 0) {
                let at = value["at"]
                    .as_u64()
                    .ok_or("served flow record lacks lab timestamp")?;
                evidence.last_served = Some(evidence.last_served.map_or(at, |old| old.max(at)));
            }
        }
    }
    Ok(activity)
}

fn include_sink_activity(
    activity: Option<PeerActivity>,
    receipts: &[helpers::Receipt],
    markers: &std::collections::BTreeMap<String, String>,
    ns: &str,
) -> Option<PeerActivity> {
    let mut activity = activity?;
    for receipt in receipts
        .iter()
        .filter(|receipt| markers.get(&receipt.marker).is_some_and(|peer| peer == ns))
    {
        // Old/missing timestamps cannot establish idleness. A receipt alone is
        // enough to make the peer active, even when its reply was lost.
        let at = receipt.at?;
        activity.last_served = Some(activity.last_served.map_or(at, |old| old.max(at)));
    }
    Some(activity)
}

fn served_deadline(elapsed: Duration, budget: Duration, missing: &[String]) -> Result<()> {
    if !missing.is_empty() && elapsed >= budget {
        return fail(format!(
            "false 0: check exited 0 without served recovery traffic within the peer's served-check budget: {}",
            missing.join("; ")
        ));
    }
    Ok(())
}

pub(super) fn session_state_root(root: &Path) -> PathBuf {
    if root == Path::new("/") {
        root.join("var/lib/scupper")
    } else {
        root.join("var-lib/scupper")
    }
}

// Copy only session evidence, never configuration or tunnel key files. Preserve
// runtime readiness/invalidation/commit state as well as the durable record.
fn save_session_files(state: &Path, run: &Path, target: &Path) -> Result<()> {
    fs::create_dir_all(target)?;
    let mut errors = Vec::new();
    for (source, name) in [(state, "var-lib"), (run, "run")] {
        let destination = target.join(name);
        fs::create_dir_all(&destination)?;
        match fs::read_dir(source) {
            Ok(entries) => {
                for entry in entries {
                    let copied = (|| -> Result<()> {
                        let entry = entry?;
                        let name = entry.file_name();
                        if entry.file_type()?.is_file()
                            && (name.to_string_lossy().starts_with("client-session")
                                || name == "gateway-incarnation")
                        {
                            fs::copy(entry.path(), destination.join(name))?;
                        }
                        Ok(())
                    })();
                    if let Err(error) = copied {
                        errors.push(format!("{}: {error}", source.display()));
                    }
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::write(destination.join("missing.txt"), error.to_string())?;
            }
            Err(error) => errors.push(format!("{}: {error}", source.display())),
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        // A file can be atomically replaced while copying. Still attempt both
        // roots and every other file, and retain which evidence was unavailable.
        fs::write(target.join("copy-errors.txt"), errors.join("\n"))?;
        fail(errors.join("; "))
    }
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
    // Sample before every check, including pending iterations, so traffic seen
    // before a device rebuild remains active for the full lab lease window.
    pub(super) fn sample_gateway_activity(&mut self) {
        for peer in self.gateway_activity.peers.values_mut() {
            peer.valid = false;
        }
        let samples = (|| -> Result<_> {
            let transfer = self.cmd("scupper", "wg", &["show", "wg0", "transfer"])?;
            let handshakes = self.cmd("scupper", "wg", &["show", "wg0", "latest-handshakes"])?;
            kernel_samples(&transfer, &handshakes)
        })();
        let Ok(samples) = samples else {
            // Startup/missing devices or unreadable views cannot prove idleness.
            return;
        };
        let now = lab_now();
        for ns in ["client", "client2"] {
            if let Some((rx, tx, handshake)) = self
                .site
                .devices()
                .get(ns)
                .and_then(|device| samples.get(&device.public_key()))
            {
                self.gateway_activity.observe(ns, *rx, *tx, *handshake, now);
            }
        }
    }

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
        self.sample_gateway_activity();
        self.session_check_at = Some(lab_now());
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
        static NEXT_FLOW: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = NEXT_FLOW.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut flows = Vec::new();
        for (ns, marker) in recovery_markers()? {
            self.fault_markers.push(marker.clone());
            let stem = format!("session-recovery-{stem}-{id}-{ns}");
            let process =
                self.daemon_flow("udp", ns, &marker, &stem, self.recovery_flow_seconds())?;
            flows.push(RecoveryFlow {
                ns,
                marker,
                log: self.artifacts.join(format!("{stem}-udp.jsonl")),
                process,
            });
        }
        Ok(flows)
    }

    pub(super) fn recovery_flow_seconds(&self) -> u64 {
        // Include pre-fault traffic, reconstruction, served checks and cleanup.
        self.runner
            .whole
            .saturating_duration_since(Instant::now())
            .as_secs()
            + 30
    }

    // Snapshot all logs after check exit 0 (or an explicit rebuild activity
    // checkpoint): earlier receipts/replies cannot satisfy this assertion.
    pub(super) fn assert_recovery_served(
        &mut self,
        flows: &mut [RecoveryFlow],
        report: &serde_json::Value,
        root: &Path,
    ) -> Result<()> {
        let outcome = self.recovery_served_until(flows, report, root);
        if outcome.is_err() {
            self.save_session_failure(root, "served-traffic");
        }
        outcome
    }

    pub(super) fn save_session_failure(&mut self, root: &Path, label: &str) {
        static NEXT_FAILURE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = NEXT_FAILURE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let target = self.artifacts.join(format!("session-failure-{label}-{id}"));
        let state = session_state_root(root);
        if let Err(error) = save_session_files(&state, &root.join("run/scupper"), &target) {
            eprintln!("session artifacts: {error}");
        }
        // These public wg views contain the dump's useful counters and session
        // timestamps without ever requesting private or preshared keys.
        let _ = fs::create_dir_all(&target);
        for view in [
            "latest-handshakes",
            "transfer",
            "endpoints",
            "allowed-ips",
            "listen-port",
        ] {
            let output = self
                .cmd("scupper", "wg", &["show", "wg0", view])
                .unwrap_or_else(|error| error.to_string());
            let _ = fs::write(target.join(format!("wg-{view}.txt")), output);
        }
    }

    fn recovery_budgets(
        &self,
        flows: &[RecoveryFlow],
        report: &serde_json::Value,
        root: &Path,
    ) -> Result<Vec<(Duration, Option<u64>)>> {
        // An idle warning must never extend another, active peer's budget.
        // Prefer the newest durable/runtime record; missing evidence stays at 5 s.
        let record = [
            session_state_root(root).join("client-sessions.json"),
            root.join("run/scupper/client-sessions-fallback"),
        ]
        .iter()
        .filter_map(|path| serde_json::from_slice::<serde_json::Value>(&fs::read(path).ok()?).ok())
        .max_by_key(|record| record["sequence"].as_u64().unwrap_or(0));
        let now = self.session_check_at.unwrap_or_else(lab_now);
        let sink = self.artifacts.join("sink.jsonl");
        let receipts = if sink.try_exists()? {
            Some(helpers::receipts(&fresh_log(&sink, 0)?)?)
        } else {
            None
        };
        flows
            .iter()
            .map(|flow| {
                let key = self
                    .site
                    .devices()
                    .get(flow.ns)
                    .map(|device| serde_json::json!(device.public_key()));
                let peer = record
                    .as_ref()
                    .and_then(|record| record["peers"].as_array())
                    .and_then(|peers| {
                        peers
                            .iter()
                            .find(|peer| key.as_ref() == Some(&peer["baseline"]["key"]))
                    });
                let activity = peer_activity(&self.peer_flow_logs, flow.ns)?;
                let mut activity = receipts.as_ref().and_then(|receipts| {
                    include_sink_activity(activity, receipts, &self.peer_markers, flow.ns)
                });
                if let (Some(evidence), Some(at)) =
                    (&mut activity, self.last_probe_served.get(flow.ns))
                {
                    evidence.last_served =
                        Some(evidence.last_served.map_or(*at, |old| old.max(*at)));
                }
                let activity = self.gateway_activity.include(flow.ns, activity);
                let age = activity
                    .as_ref()
                    .and_then(|activity| activity.last_served)
                    .map(|last| now.saturating_sub(last));
                Ok((recovery_budget(report, peer, now, activity.as_ref()), age))
            })
            .collect()
    }

    fn recovery_served_until(
        &mut self,
        flows: &mut [RecoveryFlow],
        report: &serde_json::Value,
        root: &Path,
    ) -> Result<()> {
        let sink = self.artifacts.join("sink.jsonl");
        let sink_offset = log_size(&sink)?;
        let offsets = flows
            .iter()
            .map(|flow| log_size(&flow.log))
            .collect::<Result<Vec<_>>>()?;
        self.sample_gateway_activity();
        let budgets = self.recovery_budgets(flows, report, root)?;
        if budgets
            .iter()
            .any(|(budget, _)| *budget > Duration::from_secs(5))
        {
            let mut log = fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(self.artifacts.join("idle-warning-recovery.jsonl"))?;
            writeln!(
                log,
                "{}",
                serde_json::json!({
                    "budgets": flows.iter().zip(&budgets).map(|(flow,(budget,age))| (flow.ns,budget.as_secs(),age)).collect::<Vec<_>>(),
                    "report":report,
                })
            )?;
        }
        let mut confirmed = vec![false; flows.len()];
        // Snapshot freshness and compute activity budgets before timing service.
        // Historical log parsing and idle diagnostics must not consume this bound.
        let started = Instant::now();
        loop {
            self.ensure_services()
                .map_err(|error| format!("harness: recovery service failed: {error}"))?;
            let receipts = fresh_log(&sink, sink_offset)?;
            let mut missing = Vec::new();

            for (index, ((flow, offset), (budget, age))) in
                flows.iter_mut().zip(&offsets).zip(&budgets).enumerate()
            {
                if let Err(error) = flow.process.alive() {
                    let stderr = fs::read_to_string(flow.log.with_extension("stderr"))
                        .unwrap_or_else(|read_error| read_error.to_string());
                    let tail: String = stderr
                        .chars()
                        .rev()
                        .take(2048)
                        .collect::<Vec<_>>()
                        .into_iter()
                        .rev()
                        .collect();
                    return fail(format!(
                        "harness: {} recovery flow died: {error}; stderr: {tail}",
                        flow.ns
                    ));
                }
                if confirmed[index] {
                    continue;
                }
                let (receipt, reply) =
                    recovery_served(&flow.marker, &receipts, &fresh_log(&flow.log, *offset)?)?;
                // Only the new tails above are read inside the served bound.
                // Never accept service first observed after its deadline.
                if !receipt || !reply || started.elapsed() >= *budget {
                    missing.push(format!(
                        "{} marker {}: sink receipt={receipt}, flow received>0={reply}, budget={} s",
                        flow.ns, flow.marker, budget.as_secs()
                    ));
                    if let Some(age) = age.filter(|age| *age <= LAB_LEASE_WINDOW) {
                        missing.push(format!(
                            "{}: peer active {age} s ago in lab evidence",
                            flow.ns
                        ));
                    }
                    served_deadline(started.elapsed(), *budget, &missing)?;
                } else {
                    confirmed[index] = true;
                }
            }
            if missing.is_empty() {
                return Ok(());
            }
            self.runner.dwell(Duration::from_millis(50))?;
        }
    }
    pub(super) fn wait_session_recovery(
        &mut self,
        binary: &Path,
        root: &Path,
    ) -> Result<(i32, serde_json::Value)> {
        let outcome = self.wait_session_recovery_inner(binary, root);
        if outcome.is_err() {
            self.save_session_failure(root, "check");
        }
        outcome
    }

    fn wait_session_recovery_inner(
        &mut self,
        binary: &Path,
        root: &Path,
    ) -> Result<(i32, serde_json::Value)> {
        let mut traffic = self.recovery_traffic("check")?;
        self.wait_session_recovery_using(binary, root, &mut traffic, false)
    }

    // Rebuilds establish activity for every peer before the fault. An idle
    // warning must not turn a premature 0 into a longer recovery allowance.
    pub(super) fn wait_required_session_recovery(
        &mut self,
        binary: &Path,
        root: &Path,
        traffic: &mut [RecoveryFlow],
    ) -> Result<(i32, serde_json::Value)> {
        let outcome = self.wait_session_recovery_using(binary, root, traffic, true);
        if outcome.is_err() {
            self.save_session_failure(root, "required-recovery");
        }
        outcome
    }

    fn wait_session_recovery_using(
        &mut self,
        binary: &Path,
        root: &Path,
        traffic: &mut [RecoveryFlow],
        required: bool,
    ) -> Result<(i32, serde_json::Value)> {
        let started = std::time::Instant::now();
        let until = started + std::time::Duration::from_secs(240);
        self.runner.phase = self.runner.phase.max(until).min(self.runner.whole);
        loop {
            let mut result = self.check_result(binary, root)?;
            if !session_recovery_pending(result.0, &result.1) {
                if result.0 == 0 {
                    result.1["session_time_to_0_ms"] =
                        serde_json::json!(started.elapsed().as_millis());
                    let budget_report = if required {
                        serde_json::json!({})
                    } else {
                        result.1.clone()
                    };
                    self.assert_recovery_served(traffic, &budget_report, root)?;
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
            let root = self.boot_root.clone();
            self.save_session_failure(&root, "verdict");
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
    fn only_explicit_idle_warning_extends_the_served_traffic_budget() {
        use std::time::Duration;
        for report in [
            json!({}),
            json!({"warnings":[]}),
            json!({"warnings":["ClientHandshakesStale"]}),
        ] {
            assert_eq!(
                super::recovery_budget(
                    &report,
                    Some(&json!({"state":"Unknown","lease_until":null})),
                    1000,
                    Some(&super::PeerActivity::default())
                ),
                Duration::from_secs(5)
            );
        }
        assert_eq!(
            super::recovery_budget(
                &json!({"warnings":["IdleClientSessionsReset"]}),
                Some(&json!({"state":"Unknown","lease_until":null})),
                1000,
                Some(&super::PeerActivity::default())
            ),
            Duration::from_secs(35)
        );
        let report = json!({"warnings":["IdleClientSessionsReset"]});
        for peer in [
            None,
            Some(json!({})),
            Some(json!({"state":"Recovered","lease_until":1180})),
            Some(json!({"state":"RequiredPending","lease_until":1180})),
        ] {
            assert_eq!(
                super::recovery_budget(
                    &report,
                    peer.as_ref(),
                    1000,
                    Some(&super::PeerActivity::default())
                ),
                Duration::from_secs(5)
            );
        }
        assert_eq!(
            super::recovery_budget(
                &report,
                Some(&json!({"state":"ExpiredUnconfirmed","lease_until":999})),
                1000,
                Some(&super::PeerActivity::default())
            ),
            Duration::from_secs(35)
        );
    }

    #[test]
    fn lab_active_peer_cannot_get_idle_budget_or_pass_unserved() -> super::Result<()> {
        use std::{fs, time::Duration};
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../target/tmp")
            .join(format!("lab-peer-ledger-{}", std::process::id()));
        fs::create_dir_all(&root)?;
        let old = root.join("previous-fault.jsonl");
        let current = root.join("current-fault.jsonl");
        fs::write(&old, "{\"at\":980,\"received\":48}\n")?;
        fs::write(&current, "{\"at\":1000,\"received\":0}\n")?;
        let logs = vec![
            ("client2".into(), old),
            ("client2".into(), current.clone()),
            ("client".into(), current),
        ];
        let report = json!({"warnings":["IdleClientSessionsReset"]});
        let peer = json!({"state":"Unknown","lease_until":null});
        let activity = super::peer_activity(&logs, "client2")?.unwrap();
        assert_eq!(activity.last_served, Some(980));
        for now in [1000, 1170] {
            // includes the entire lease plus slack
            let budget = super::recovery_budget(&report, Some(&peer), now, Some(&activity));
            assert_eq!(budget, Duration::from_secs(5));
            let error = super::served_deadline(
                Duration::from_secs(5),
                budget,
                &["client2 unserved".into()],
            )
            .unwrap_err();
            assert!(error.to_string().contains("false 0"));
        }
        assert_eq!(
            super::recovery_budget(&report, Some(&peer), 1171, Some(&activity)),
            Duration::from_secs(35)
        );
        assert_eq!(
            super::recovery_budget(&report, Some(&peer), 1000, None),
            Duration::from_secs(5)
        );
        let idle = super::peer_activity(&logs, "client")?.unwrap();
        assert_eq!(
            super::recovery_budget(&report, Some(&peer), 1000, Some(&idle)),
            Duration::from_secs(35)
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn kernel_activity_without_flow_receipts_keeps_the_strict_bound() -> super::Result<()> {
        use super::{GatewayActivity, PeerActivity, kernel_samples, recovery_budget};
        use std::time::Duration;
        let report = json!({"warnings":["IdleClientSessionsReset"]});
        let peer = json!({"state":"Unknown","lease_until":null});
        let key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let mut ledger = GatewayActivity::default();
        let budget = |ledger: &GatewayActivity, now| {
            // All flow evidence is old. No new reply/receipt is recorded.
            let activity = ledger.include(
                "client",
                Some(PeerActivity {
                    last_served: Some(700),
                }),
            );
            recovery_budget(&report, Some(&peer), now, activity.as_ref())
        };
        assert_eq!(budget(&ledger, 1000), Duration::from_secs(5));
        ledger.observe("client", 0, 0, 0, 1000);
        assert_eq!(budget(&ledger, 1000), Duration::from_secs(35));
        for (rx, tx) in [(92, 0), (92, 92)] {
            // Even handshake-sized rx and tx-only growth count conservatively.
            let samples = kernel_samples(&format!("{key} {rx} {tx}\n"), &format!("{key} 0\n"))?;
            let (rx, tx, handshake) = samples[&[0; 32]];
            ledger.observe("client", rx, tx, handshake, 1001);
            assert_eq!(budget(&ledger, 1191), Duration::from_secs(5));
            assert_eq!(budget(&ledger, 1192), Duration::from_secs(35));
        }
        ledger.observe("client", 92, 92, 1200, 1200);
        assert_eq!(budget(&ledger, 1390), Duration::from_secs(5));
        assert_eq!(budget(&ledger, 1391), Duration::from_secs(35));
        ledger.observe("client", 92, 92, 1200, 1391);
        assert_eq!(budget(&ledger, 1391), Duration::from_secs(35));
        ledger.peers.get_mut("client").unwrap().valid = false;
        assert_eq!(budget(&ledger, 1391), Duration::from_secs(5));
        ledger.observe("client", 0, 0, 0, 1400); // device/counter reset
        assert_eq!(budget(&ledger, 1400), Duration::from_secs(5));
        assert!(kernel_samples(&format!("{key} 1 2\n"), "").is_err());
        assert!(kernel_samples(&format!("{key} 1 2\n"), "other 3\n").is_err());
        assert!(kernel_samples(&format!("{key} bad 2\n"), &format!("{key} 3\n")).is_err());
        Ok(())
    }

    #[test]
    fn sink_receipt_without_a_flow_reply_still_requires_five_seconds() -> super::Result<()> {
        use std::{collections::BTreeMap, time::Duration};
        let marker = "scupper-canary-receipt-only";
        let markers = BTreeMap::from([(marker.into(), "client2".into())]);
        let report = json!({"warnings":["IdleClientSessionsReset"]});
        let peer = json!({"state":"Unknown","lease_until":null});
        let sink = json!({"at":980,"protocol":"udp","marker":marker,"peer":"203.0.113.2:40000"});
        let receipts = super::helpers::receipts(&sink.to_string())?;
        let activity = super::include_sink_activity(
            Some(super::PeerActivity::default()),
            &receipts,
            &markers,
            "client2",
        );
        assert_eq!(activity.as_ref().unwrap().last_served, Some(980));
        let budget = super::recovery_budget(&report, Some(&peer), 1000, activity.as_ref());
        assert_eq!(budget, Duration::from_secs(5));
        assert!(
            super::served_deadline(
                Duration::from_secs(5),
                budget,
                &["client2 has no new reply".into()]
            )
            .is_err()
        );
        // No unrelated peer inherits the receipt, and legacy timestamps remain unknown.
        let other = super::include_sink_activity(
            Some(super::PeerActivity::default()),
            &receipts,
            &markers,
            "client",
        );
        assert_eq!(
            super::recovery_budget(&report, Some(&peer), 1000, other.as_ref()),
            Duration::from_secs(35)
        );
        let mut receipt = receipts.into_iter().next().unwrap();
        receipt.at = None;
        assert!(
            super::include_sink_activity(
                Some(super::PeerActivity::default()),
                &[receipt],
                &markers,
                "client2"
            )
            .is_none()
        );
        Ok(())
    }

    #[test]
    fn session_failure_artifacts_preserve_durable_and_runtime_records() -> super::Result<()> {
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../target/tmp")
            .join(format!("session-artifacts-{}", std::process::id()));
        let state = root.join("state");
        let run = root.join("run");
        let target = root.join("artifacts");
        std::fs::create_dir_all(&state)?;
        std::fs::create_dir_all(&run)?;
        std::fs::write(state.join("client-sessions.json"), b"durable record")?;
        std::fs::write(state.join("gateway-incarnation"), b"generation")?;
        std::fs::write(state.join("configuration"), b"excluded")?;
        std::fs::write(run.join("client-sessions-fallback"), b"runtime record")?;
        std::fs::write(run.join("client-session-invalidation"), b"fence")?;
        super::save_session_files(&state, &run, &target)?;
        assert_eq!(
            std::fs::read(target.join("var-lib/client-sessions.json"))?,
            b"durable record"
        );
        assert_eq!(
            std::fs::read(target.join("run/client-sessions-fallback"))?,
            b"runtime record"
        );
        assert_eq!(
            std::fs::read(target.join("run/client-session-invalidation"))?,
            b"fence"
        );
        assert!(!target.join("var-lib/configuration").exists());
        assert!(state.join("client-sessions.json").exists());
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

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
