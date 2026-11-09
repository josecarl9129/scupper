//! Disposable Linux network-namespace reference lab for the M2 leak suite.
mod addresses;
mod boot;
mod check_v2;
mod cleanup;
mod command;
mod evidence;
mod fixtures;
mod helpers;
mod probe_child;
mod topology;

use addresses::A;
use cleanup::{Registry, Resource};
use command::{Group, Invocation, Runner};
use evidence::{Case, Row};
pub use helpers::{inject, probe, sink};
use rustix::process::Signal;
use scupper_core::{
    config::{GatewayId, ValidatedSite},
    render::{VersionStamp, render_netns},
};
use sha2::{Digest, Sha256};
use std::{
    fmt::Write as _,
    fs,
    io::Write as _,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::{Arc, atomic::AtomicBool},
    time::{Duration, Instant},
};

/// Errors from the development lab and its namespace-local helpers.
pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
fn fail<T>(message: impl Into<String>) -> Result<T> {
    Err(message.into().into())
}

const NAMESPACES: [&str; 8] = [
    "rulecap",
    "wan",
    "gwhost",
    "scupper",
    "client",
    "provA",
    "internet",
    "scupper-verify",
];
const SITE: &str = include_str!("../../lab/site-lab.toml");

struct Capture {
    process: Group,
    stderr: PathBuf,
}

struct Lab {
    runner: Runner,
    registry: Registry,
    services: Vec<Group>,
    captures: Vec<Capture>,
    artifacts: PathBuf,
    private: PathBuf,
    executable: String,
    public_keys: Vec<String>,
    site: ValidatedSite,
    rules: PathBuf,
    expected_rules: serde_json::Value,
    rows: Vec<Row>,
    cleaned: bool,
    next_source_port: u16,
    exit_port: u16,
}

/// Runs the reference namespace lab, preserving captures, policies and reports.
///
/// # Errors
/// Refuses non-Linux/non-root execution, occupied resource names, command failures,
/// timeouts, failed service checks, leaks or blind positive controls.
pub fn run(artifacts: &Path, capture_fixtures: Option<&Path>) -> Result<()> {
    if !rustix::process::geteuid().is_root() {
        return fail("leaktest requires root on a disposable Linux machine");
    }
    let cancel = Arc::new(AtomicBool::new(false));
    let signals: Vec<_> = [
        signal_hook::consts::SIGINT,
        signal_hook::consts::SIGTERM,
        signal_hook::consts::SIGHUP,
    ]
    .into_iter()
    .map(|signal| signal_hook::flag::register(signal, Arc::clone(&cancel)))
    .collect::<std::io::Result<_>>()?;
    let result = run_inner(artifacts, capture_fixtures, cancel);
    for signal in signals {
        signal_hook::low_level::unregister(signal);
    }
    result
}
fn run_inner(
    artifacts: &Path,
    capture_fixtures: Option<&Path>,
    cancel: Arc<AtomicBool>,
) -> Result<()> {
    fs::create_dir_all(artifacts)?;
    let artifacts = fs::canonicalize(artifacts)?;
    let runner = Runner::new(fs::File::create(artifacts.join("commands.jsonl"))?, cancel);
    let config = scupper_core::config::parse_site(SITE)?;
    let site = scupper_core::config::validate(config)
        .map_err(|errors| format!("lab config: {errors:?}"))?;
    let private = PathBuf::from("/run").join(format!("scupper-lab-{}", Lab::marker()?));
    if private.starts_with(&artifacts) {
        return fail("artifact directory must not contain the private /run directory");
    }
    let rules = private.join("netns.nft");
    let mut lab = Lab {
        runner,
        registry: Registry::default(),
        services: Vec::new(),
        captures: Vec::new(),
        artifacts,
        private,
        executable: std::env::current_exe()?.to_string_lossy().into_owned(),
        public_keys: Vec::new(),
        site,
        rules,
        expected_rules: serde_json::Value::Null,
        rows: Vec::new(),
        cleaned: false,
        next_source_port: 41000,
        exit_port: 51821,
    };
    let outcome: Result<()> = (|| {
        lab.preflight()?;
        lab.prepare()?;
        lab.build()?;
        Lab::verify_handle_execution()?;
        lab.service_check(&mut Vec::new())?;
        lab.boot_cases()?;
        if let Some(dir) = capture_fixtures {
            lab.fixtures(dir)?;
        }
        let mut failures = Vec::new();
        for case in Case::ALL {
            lab.runner.phase = Instant::now() + Duration::from_secs(140);
            let result = lab.case(case);
            let (got, detail) = match &result {
                Ok(observed) => (
                    observed.clone(),
                    "before/after provider-NAT service checks and oracle assertions passed".into(),
                ),
                Err(error) => (format!("failed: {error}"), error.to_string()),
            };
            lab.rows.push(Row {
                name: case.name().into(),
                wanted: case.wanted().into(),
                got,
                detail,
            });
            evidence::save_results(&lab.artifacts, &lab.rows)?;
            if let Err(error) = result {
                failures.push(format!("{}: {error}", case.name()));
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            fail(failures.join("; "))
        }
    })();
    if let Err(error) = &outcome {
        fs::write(lab.artifacts.join("failure.txt"), error.to_string())?;
        if lab.rows.is_empty() {
            lab.rows.push(Row {
                name: "setup".into(),
                wanted: "healthy-topology".into(),
                got: "failed".into(),
                detail: error.to_string(),
            });
        }
    }
    evidence::save_results(&lab.artifacts, &lab.rows)?;
    let cleanup = lab.cleanup();
    match (outcome, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(error), Err(cleanup)) => fail(format!("{error}; cleanup: {cleanup}")),
    }
}
impl Lab {
    fn cmd(&mut self, ns: &str, program: &str, args: &[&str]) -> Result<String> {
        self.runner.run(&Invocation::new(ns, program, args))
    }
    fn preflight(&mut self) -> Result<()> {
        for path in ["/etc/passwd", "/etc/group"] {
            if fs::read_to_string(path)?
                .lines()
                .any(|line| line.split(':').next() == Some("scupper-probe"))
            {
                return fail("refusing occupied scupper-probe lab account/group");
            }
        }
        for ns in NAMESPACES {
            for path in [format!("/run/netns/{ns}"), format!("/etc/netns/{ns}")] {
                if fs::symlink_metadata(&path).is_ok() {
                    return fail(format!("refusing occupied lab name: {path}"));
                }
            }
        }
        if fs::symlink_metadata(&self.private).is_ok() {
            return fail("lab private directory already exists");
        }
        for segment in A.segments() {
            for name in [segment.staging, segment.wan_if] {
                if self
                    .runner
                    .output(
                        &Invocation::new("", "ip", &["link", "show", "dev", name]),
                        None,
                    )?
                    .0
                    .success()
                {
                    return fail(format!("refusing occupied staging link: {name}"));
                }
            }
        }
        Ok(())
    }
    fn prepare(&mut self) -> Result<()> {
        self.cmd(
            "",
            "useradd",
            &[
                "--system",
                "--user-group",
                "--no-create-home",
                "--shell",
                "/usr/sbin/nologin",
                "scupper-probe",
            ],
        )?;
        self.registry
            .register(Resource::User("scupper-probe".into()));
        fs::DirBuilder::new().mode(0o700).create(&self.private)?;
        self.registry
            .register(Resource::Directory(self.private.clone()));
        let resolver_dir = PathBuf::from("/etc/netns/scupper");
        fs::create_dir_all(&resolver_dir)?;
        self.registry
            .register(Resource::Directory(resolver_dir.clone()));
        fs::write(resolver_dir.join("resolv.conf"), "nameserver 127.0.0.53\n")?;
        for key in ["gateway", "exit", "provider", "client"] {
            let private = self.cmd("", "wg", &["genkey"])?;
            let path = self.private.join(format!("{key}.key"));
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)?;
            file.write_all(private.as_bytes())?;
            let public = self.runner.input(
                &Invocation::new("", "wg", &["pubkey"]),
                Some(private.as_bytes()),
            )?;
            self.public_keys.push(public.trim().into());
        }
        // Runtime public identities describe the keys actually installed. Only the
        // fixed template is committed; no private key is part of the site model.
        let mut config = scupper_core::config::parse_site(SITE)?;
        config
            .identities
            .get_mut("edge")
            .ok_or("missing lab identity")?
            .public_key
            .0
            .clone_from(&self.public_keys[0]);
        config
            .gateways
            .get_mut(&GatewayId("gw1".into()))
            .ok_or("missing lab gateway")?
            .exits[0]
            .peer_public_key
            .0
            .clone_from(&self.public_keys[2]);
        config
            .devices
            .get_mut("client")
            .ok_or("missing lab device")?
            .public_key
            .0
            .clone_from(&self.public_keys[3]);
        fs::write(
            self.private.join("runtime-site.toml"),
            toml::to_string(&config)?,
        )?;
        self.site = scupper_core::config::validate(config)
            .map_err(|errors| format!("runtime lab config: {errors:?}"))?;
        let rules = render_netns(
            &self.site,
            &GatewayId("gw1".into()),
            &VersionStamp {
                version: 1,
                sha256: Sha256::digest(SITE.as_bytes()).into(),
            },
        )?;
        fs::write(&self.rules, rules)?;
        Ok(())
    }
    fn new_namespace(&mut self, ns: &str, from: &str) -> Result<()> {
        self.cmd(from, "ip", &["netns", "add", ns])?;
        self.registry.register(Resource::Namespace(ns.into()));
        self.cmd(
            ns,
            "sysctl",
            &[
                "-q",
                "-w",
                if ns == "gwhost" {
                    "net.ipv4.ip_forward=1"
                } else {
                    "net.ipv4.ip_forward=0"
                },
                "net.ipv6.conf.all.forwarding=0",
            ],
        )?;
        self.cmd(ns, "ip", &["link", "set", "lo", "up"])?;
        Ok(())
    }
    fn start(&mut self, ns: &str, program: &str, args: &[&str], name: &str) -> Result<()> {
        let group = self.runner.background(
            &Invocation::new(ns, program, args),
            &self.artifacts.join(format!("{name}.stdout")),
        )?;
        self.services.push(group);
        Ok(())
    }
    fn ensure_services(&mut self) -> Result<()> {
        for group in &mut self.services {
            group.alive()?;
        }
        for capture in &mut self.captures {
            capture.process.alive()?;
        }
        Ok(())
    }
    fn marker() -> Result<String> {
        let mut bytes = [0_u8; 16];
        let mut at = 0;
        while at < bytes.len() {
            let len =
                rustix::rand::getrandom(&mut bytes[at..], rustix::rand::GetRandomFlags::empty())
                    .map_err(|error| std::io::Error::from_raw_os_error(error.raw_os_error()))?;
            if len == 0 {
                return fail("random source returned no bytes");
            }
            at += len;
        }
        let mut marker = "scupper-canary-".to_owned();
        for byte in bytes {
            write!(marker, "{byte:02x}")?;
        }
        Ok(marker)
    }
    fn send(
        &mut self,
        namespace: &str,
        protocol: &str,
        target: &str,
        marker: &str,
        ipv6: bool,
    ) -> Result<helpers::Outcome> {
        self.send_from(namespace, protocol, target, marker, ipv6, None)
    }
    fn send_from(
        &mut self,
        namespace: &str,
        protocol: &str,
        target: &str,
        marker: &str,
        ipv6: bool,
        source: Option<&str>,
    ) -> Result<helpers::Outcome> {
        let exe = self.executable.clone();
        // A unique UDP tuple avoids reusing an earlier case's conntrack NAT
        // mapping when the permissive ruleset temporarily removes masquerading.
        let source_port = self.next_source_port.to_string();
        self.next_source_port = self
            .next_source_port
            .checked_add(1)
            .ok_or("probe source ports exhausted")?;
        let mut args = vec![
            "probe",
            "--protocol",
            protocol,
            "--target",
            target,
            "--port",
            "8080",
            "--marker",
            marker,
            "--source-port",
            &source_port,
        ];
        if ipv6 {
            args.push("--ipv6");
        }
        if let Some(source) = source {
            args.extend(["--source", source]);
        }
        let (status, stdout) = self
            .runner
            .output(&Invocation::new(namespace, &exe, &args), None)?;
        let attempt: helpers::Attempt = serde_json::from_str(&stdout)
            .map_err(|_| "probe failed before resolving and attempting its destination")?;
        let expected: std::net::IpAddr =
            if ipv6 { A.internet_v6 } else { A.internet.peer }.parse()?;
        if attempt.destination.ip() != expected
            || attempt.destination.port() != addresses::PORT
            || attempt.marker != marker
            || attempt.protocol != protocol
        {
            return fail("probe attempted an unexpected destination or marker");
        }
        let mut log = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.artifacts.join("probes.jsonl"))?;
        writeln!(
            log,
            "{}",
            serde_json::json!({"namespace": namespace, "attempt": attempt, "status": status.code()})
        )?;
        // GNU timeout, signals and launcher errors must never masquerade as a drop.
        if !status.success() && status.code() != Some(1) {
            return fail(format!("probe launcher failed: {status}"));
        }
        if status.success() != (attempt.outcome == helpers::Outcome::Delivered) {
            return fail("probe status/outcome mismatch");
        }
        if matches!(attempt.outcome, helpers::Outcome::HarnessError { .. }) {
            return fail(format!("probe harness error: {:?}", attempt.outcome));
        }
        Ok(attempt.outcome)
    }
    fn canaries(
        &mut self,
        markers: &mut Vec<String>,
        ipv6: bool,
        healthy: bool,
    ) -> Result<Vec<String>> {
        let mut sent = Vec::new();
        for protocol in ["tcp", "udp"] {
            for by_name in [false, true] {
                self.runner.check()?;
                let marker = Self::marker()?;
                let target = if by_name {
                    format!("{marker}.lab.test")
                } else if ipv6 {
                    A.internet_v6.into()
                } else {
                    A.internet.peer.into()
                };
                markers.push(marker.clone());
                sent.push(marker.clone());
                let success = self.send("client", protocol, &target, &marker, ipv6)?;
                let expected = if healthy {
                    helpers::Outcome::Delivered
                } else {
                    helpers::Outcome::TimedOut
                };
                if success != expected {
                    return fail(format!(
                        "{protocol} canary for {target}: wanted {expected:?}, got {success:?}"
                    ));
                }
            }
        }
        Ok(sent)
    }
    fn service_check(&mut self, markers: &mut Vec<String>) -> Result<()> {
        self.ensure_services()?;
        let sent = self.canaries(markers, false, true)?;
        let receipts = helpers::receipts(&fs::read_to_string(self.artifacts.join("sink.jsonl"))?)?;
        for marker in sent {
            let matches: Vec<_> = receipts.iter().filter(|r| r.marker == marker).collect();
            if matches.len() != 1 || matches[0].peer.ip().to_string() != A.provider.peer {
                return fail(format!(
                    "marker {marker}: expected exactly one receipt from provider NAT {}",
                    A.provider.peer
                ));
            }
        }
        Ok(())
    }
    fn capture(&mut self, ns: &str, iface: &str, stem: &str) -> Result<()> {
        let pcap = self.artifacts.join(format!("{stem}.pcap"));
        let log = self.artifacts.join(format!("{stem}.tcpdump.stdout"));
        let args = vec![
            "-n",
            "-Z",
            "root",
            "-U",
            "-s",
            "0",
            "-i",
            iface,
            "-w",
            pcap.to_str().ok_or("non-UTF8 artifact path")?,
        ];
        let group = self
            .runner
            .background(&Invocation::new(ns, "tcpdump", &args), &log)?;
        self.captures.push(Capture {
            process: group,
            stderr: log.with_extension("stderr"),
        });
        let until = Instant::now() + Duration::from_secs(5);
        loop {
            self.ensure_services()?;
            if fs::read_to_string(log.with_extension("stderr"))
                .is_ok_and(|text| text.contains("listening on"))
            {
                break;
            }
            if Instant::now() >= until {
                return fail("tcpdump did not become ready");
            }
            self.runner.dwell(Duration::from_millis(50))?;
        }
        self.runner.dwell(Duration::from_secs(1))?;
        Ok(())
    }
    fn stop_capture(&mut self) -> Result<()> {
        let mut capture = self.captures.pop().ok_or("missing capture process")?;
        capture.process.stop(Signal::INT)?;
        evidence::check_capture_stats(&fs::read_to_string(capture.stderr)?)
    }
    fn stop_captures(&mut self) -> Result<()> {
        let mut failures = Vec::new();
        while !self.captures.is_empty() {
            if let Err(error) = self.stop_capture() {
                failures.push(error.to_string());
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            fail(failures.join("; "))
        }
    }
    fn cleanup(&mut self) -> Result<()> {
        if self.cleaned {
            return Ok(());
        }
        self.cleaned = true;
        let mut failures = Vec::new();
        if let Err(error) = self.stop_captures() {
            failures.push(error.to_string());
        }
        for service in &mut self.services {
            if let Err(error) = service.stop(Signal::TERM) {
                failures.push(error.to_string());
            }
        }
        self.services.clear();
        if let Err(error) = self.registry.cleanup(&mut self.runner) {
            failures.push(error.to_string());
        }
        let text = if failures.is_empty() {
            "ok\n".into()
        } else {
            failures.join("\n")
        };
        fs::write(self.artifacts.join("cleanup.txt"), &text)?;
        if failures.is_empty() {
            Ok(())
        } else {
            fail(text)
        }
    }
}
impl Drop for Lab {
    fn drop(&mut self) {
        if !self.cleaned {
            let _ = self.cleanup();
        }
    }
}

#[cfg(test)]
mod tests;
