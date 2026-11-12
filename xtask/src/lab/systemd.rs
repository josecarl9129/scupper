//! Installed-unit lab. Only CI runs this against the real root namespace.
mod cases;
mod egress;
mod guards;
mod routes;
use super::{
    Lab, Result, SITE,
    addresses::A,
    cleanup::Registry,
    command::{Invocation, Runner},
    evidence, fail, helpers,
};
use guards::HostSnapshot;
use scupper_core::config::{parse_site, validate};
use std::{
    fmt::Write as _,
    fs,
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::Path,
    sync::{Arc, atomic::AtomicBool},
    time::{Duration, Instant},
};

const CLI: &str = "/usr/local/bin/scupper";
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum RebootStep {
    StopUnits,
    FlushHostConntrack,
    FlushConntrack,
    DeleteLinks,
    DeleteNamespace,
    DeleteHostLinks,
    RemoveRuntime,
    StartUnits,
}
const REBOOT_STEPS: &[RebootStep] = &[
    RebootStep::StopUnits,
    RebootStep::FlushHostConntrack,
    RebootStep::FlushConntrack,
    RebootStep::DeleteLinks,
    RebootStep::DeleteNamespace,
    RebootStep::DeleteHostLinks,
    RebootStep::RemoveRuntime,
    RebootStep::StartUnits,
];

struct SystemdLab {
    lab: Lab,
    baseline: HostSnapshot,
    egress: egress::Scope,
    ports: Vec<u16>,
    root_routes: Vec<(&'static str, &'static str)>,
    samples: usize,
    timings: Vec<serde_json::Value>,
}

/// Run one systemd case on an otherwise unused ephemeral Linux CI runner.
/// # Errors
/// Refuses occupied resources, non-root/non-systemd hosts, host drift, blind
/// controls, capture drops, leaks and failed recovery.
#[allow(clippy::too_many_lines)]
pub fn run(artifacts: &Path, binaries: &Path, case: &str) -> Result<()> {
    if !matches!(case, "L9" | "L10" | "L14" | "L44" | "V-13") {
        return fail("unknown systemd case");
    }
    if !rustix::process::geteuid().is_root()
        || fs::read_to_string("/proc/1/comm")?.trim() != "systemd"
    {
        return fail("systemd-lab requires root and real systemd on an ephemeral CI runner");
    }
    fs::create_dir_all(artifacts)?;
    let artifacts = fs::canonicalize(artifacts)?;
    let binaries = fs::canonicalize(binaries)?;
    let cancel = Arc::new(AtomicBool::new(false));
    let mut runner = Runner::new(
        fs::File::create(artifacts.join("commands.jsonl"))?,
        Arc::clone(&cancel),
    );
    runner.whole = Instant::now() + Duration::from_mins(20);
    runner.phase = runner.whole;
    let baseline = HostSnapshot::read(&mut runner)?;
    fs::write(
        artifacts.join("host-before.json"),
        serde_json::to_vec_pretty(&baseline)?,
    )?;
    let private = std::env::current_dir()?
        .join("target")
        .join(format!("systemd-private-{}", std::process::id()));
    let site = validate(parse_site(SITE)?).map_err(|e| format!("lab config: {e:?}"))?;
    let mut harness = SystemdLab {
        baseline,
        egress: egress::Scope::default(),
        ports: Vec::new(),
        root_routes: Vec::new(),
        samples: 0,
        timings: Vec::new(),
        lab: Lab {
            boot_root: private.clone(),
            boot_root_ready: false,
            runner,
            registry: Registry::default(),
            services: Vec::new(),
            captures: Vec::new(),
            artifacts,
            private: private.clone(),
            private_dir: None,
            executable: std::env::current_exe()?.to_string_lossy().into_owned(),
            public_keys: Vec::new(),
            site,
            rules: private.join("rules.nft"),
            expected_rules: serde_json::Value::Null,
            rows: Vec::new(),
            cleaned: true,
            baseline_failure: None,
            daemon_host_baseline: None,
            inheritance: None,
            host_sysctls: None,
            fault_markers: Vec::new(),
            next_source_port: 20000,
            exit_port: 51821,
            client_ports_ready: false,
        },
    };
    let signals = [signal_hook::consts::SIGINT, signal_hook::consts::SIGTERM]
        .into_iter()
        .map(|s| signal_hook::flag::register(s, Arc::clone(&cancel)))
        .collect::<std::io::Result<Vec<_>>>()?;
    let outcome = (|| {
        harness.preflight()?;
        harness.egress_inventory()?;
        harness.setup(&binaries)?;
        harness.capture_control()?;
        harness.guard("case-before")?;
        harness.case(case)
    })();
    // Always take diagnostics and host snapshots, including on fault assertions.
    harness.lab.runner.cleanup = true;
    harness.lab.runner.whole = Instant::now() + Duration::from_secs(120);
    harness.lab.runner.phase = harness.lab.runner.whole;
    let guard = harness.guard("case-after");
    let journal = harness.journal("journal.txt");
    let egress_log = harness.egress_final();
    let captures = harness.lab.stop_captures();
    let routes_cleanup = harness.root_routes_cleanup();
    let diagnostics = if outcome.is_err()
        || guard.is_err()
        || journal.is_err()
        || egress_log.is_err()
        || captures.is_err()
        || routes_cleanup.is_err()
    {
        harness.failure_diagnostics()
    } else {
        Ok(())
    };
    let result = super::mutation::finish(
        super::mutation::finish(outcome, routes_cleanup),
        super::mutation::finish(
            guard,
            super::mutation::finish(
                diagnostics,
                super::mutation::finish(journal, super::mutation::finish(egress_log, captures)),
            ),
        ),
    );
    fs::write(
        harness.lab.artifacts.join(format!("{case}.json")),
        serde_json::to_vec_pretty(&serde_json::json!({
            "case":case, "passed":result.is_ok(),
            "outcome":if result.is_ok() { "passed" } else if result.as_ref().err().is_some_and(|e| e.to_string().contains("INCONCLUSIVE:")) { "inconclusive" } else { "failed" },
            "error":result.as_ref().err().map(ToString::to_string),
            "safety_samples":harness.samples, "exit_ports":harness.ports,
            "reboot_steps":REBOOT_STEPS, "point_timings":harness.timings,
        }))?,
    )?;
    // No uninstall: the runner is ephemeral. Stop only harness children; retain
    // installed services and public diagnostics for investigation.
    harness.lab.services.clear();
    for signal in signals {
        signal_hook::low_level::unregister(signal);
    }
    super::mutation::finish(
        result,
        super::make_artifacts_readable(&harness.lab.artifacts),
    )
}

impl SystemdLab {
    fn cmd(&mut self, program: &str, args: &[&str]) -> Result<String> {
        let (status, out) =
            self.lab
                .runner
                .output_timeout(&Invocation::new("", program, args), None, 120)?;
        if !status.success() {
            return fail(format!("{program} {args:?}: {status}; see commands.jsonl"));
        }
        Ok(out)
    }
    fn cli(&mut self, args: &[&str]) -> Result<String> {
        self.cmd(CLI, args)
    }
    fn systemctl(&mut self, args: &[&str]) -> Result<String> {
        self.cmd("systemctl", args)
    }
    fn guard(&mut self, label: &str) -> Result<()> {
        let now = HostSnapshot::read(&mut self.lab.runner)?;
        fs::write(
            self.lab.artifacts.join(format!("host-{label}.json")),
            serde_json::to_vec_pretty(&now)?,
        )?;
        self.baseline.verify(&now)?;
        self.root_routes_verify(label)?;
        if Path::new("/sys/class/net/up0").exists() {
            let state = self.cmd("networkctl", &["--no-pager", "status", "up0"])?;
            fs::write(
                self.lab.artifacts.join(format!("networkd-{label}.txt")),
                &state,
            )?;
            if !guards::unmanaged(&state) {
                return fail("networkd began managing up0");
            }
        }
        Ok(())
    }
    fn journal(&mut self, name: &str) -> Result<()> {
        let journal = self.cmd(
            "journalctl",
            &[
                "--no-pager",
                "-o",
                "short-monotonic",
                "-u",
                "scupper-net",
                "-u",
                "scupperd",
            ],
        )?;
        fs::write(self.lab.artifacts.join(name), journal)?;
        Ok(())
    }
    fn failure_diagnostics(&mut self) -> Result<()> {
        // A failed check or inactive unit is diagnostic data, not a reason to
        // skip the remaining commands. Keep each attempt independently bounded.
        let mut errors = Vec::new();
        for (name, program, args) in [
            ("failure-status.json", CLI, vec!["status", "--json"]),
            ("failure-check.json", CLI, vec!["check", "--json"]),
            ("failure-boot.json", "cat", vec!["/run/scupper/boot.json"]),
            (
                "failure-units.txt",
                "systemctl",
                vec!["--no-pager", "--full", "status", "scupper-net", "scupperd"],
            ),
            (
                "failure-journal.txt",
                "journalctl",
                vec![
                    "--no-pager",
                    "-n",
                    "1000",
                    "-o",
                    "short-monotonic",
                    "-u",
                    "scupperd",
                ],
            ),
        ] {
            let output = self
                .lab
                .runner
                .output(&Invocation::new("", program, &args), None);
            let text = match output {
                Ok((_, text)) => text,
                Err(error) => {
                    errors.push(format!("{name}: {error}"));
                    format!("diagnostic unavailable: {error}\n")
                }
            };
            fs::write(self.lab.artifacts.join(name), text)?;
        }
        // Read newest months first, requesting only the records still needed.
        // This keeps a long history from overwhelming the command output cap.
        let events = (|| -> Result<String> {
            let mut files = fs::read_dir("/var/lib/scupper/events")?
                .map(|entry| entry.map(|e| e.path()))
                .collect::<std::io::Result<Vec<_>>>()?;
            files.retain(|p| p.extension().is_some_and(|ext| ext == "jsonl"));
            files.sort();
            let mut remaining: usize = 200;
            let mut chunks = Vec::new();
            for path in files.iter().rev() {
                let count = remaining.to_string();
                let (_, text) = self.lab.runner.output(
                    &Invocation::new(
                        "",
                        "tail",
                        &["-n", &count, "--", path.to_str().ok_or("event path")?],
                    ),
                    None,
                )?;
                let lines = text.lines().map(str::to_owned).collect::<Vec<_>>();
                remaining = remaining.saturating_sub(lines.len());
                chunks.push(lines);
                if remaining == 0 {
                    break;
                }
            }
            Ok(chunks
                .into_iter()
                .rev()
                .flatten()
                .collect::<Vec<_>>()
                .join("\n"))
        })();
        let text = match events {
            Ok(text) => text,
            Err(error) => {
                errors.push(format!("events: {error}"));
                format!("diagnostic unavailable: {error}\n")
            }
        };
        fs::write(self.lab.artifacts.join("failure-events.jsonl"), text)?;
        fs::write(
            self.lab.artifacts.join("failure-diagnostics-errors.json"),
            serde_json::to_vec_pretty(&errors)?,
        )?;
        Ok(())
    }
    fn journal_cursor(&mut self) -> Result<String> {
        let text = self.cmd("journalctl", &["--no-pager", "-n", "0", "--show-cursor"])?;
        Ok(text
            .lines()
            .find_map(|l| l.strip_prefix("-- cursor: "))
            .ok_or("missing journal cursor")?
            .to_owned())
    }
    fn journal_since(&mut self, cursor: &str, name: &str) -> Result<String> {
        let text = self.cmd(
            "journalctl",
            &[
                "--no-pager",
                "-o",
                "short-iso-precise",
                "--after-cursor",
                cursor,
                "-u",
                "scupper-net.service",
                "-u",
                "scupperd.service",
            ],
        )?;
        fs::write(self.lab.artifacts.join(name), &text)?;
        Ok(text)
    }
    fn preflight(&mut self) -> Result<()> {
        for path in [
            "/etc/scupper",
            "/var/lib/scupper",
            "/run/scupper",
            "/usr/local/bin/scupper",
            "/usr/local/bin/scupperd",
            "/etc/systemd/system/scupper-net.service",
            "/etc/systemd/system/scupperd.service",
        ] {
            if fs::symlink_metadata(path).is_ok() {
                return fail(format!("occupied systemd lab path: {path}"));
            }
        }
        for ns in super::NAMESPACES {
            if Path::new(&format!("/run/netns/{ns}")).exists() {
                return fail(format!("occupied namespace {ns}"));
            }
        }
        for link in ["ctl0", "up0", "wg0", "ex-0", "ex-ch1", A.gwhost.wan_if] {
            if self
                .lab
                .runner
                .output(
                    &Invocation::new("", "ip", &["link", "show", "dev", link]),
                    None,
                )?
                .0
                .success()
            {
                return fail(format!("occupied host link {link}"));
            }
        }
        for service in ["systemd-udevd", "systemd-networkd"] {
            self.systemctl(&["is-active", service])?;
        }
        Ok(())
    }
    #[allow(clippy::too_many_lines)] // Keep install flags, device load and idempotence assertions together.
    fn setup(&mut self, binaries: &Path) -> Result<()> {
        fs::create_dir_all(self.lab.private.parent().ok_or("private parent")?)?;
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&self.lab.private)?;
        self.lab.public_keys.push(String::new()); // installer generates the gateway identity
        for key in ["exit", "provider", "client", "client2"] {
            let secret = self.lab.cmd("", "wg", &["genkey"])?;
            let mut file = fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(self.lab.private.join(format!("{key}.key")))?;
            file.write_all(secret.as_bytes())?;
            self.lab.public_keys.push(
                self.lab
                    .runner
                    .input(
                        &Invocation::new("", "wg", &["pubkey"]),
                        Some(secret.as_bytes()),
                    )?
                    .trim()
                    .into(),
            );
        }
        self.lab.build_wan_mode(true)?;
        self.uplink()?;
        self.egress_setup()?;
        self.root_routes_setup()?;
        self.lab.capture("", "up0", "install-uplink")?;
        self.lab.build_provider()?;
        let provider = self.lab.private.join("provider.conf");
        let text = format!(
            "[Interface]\nPrivateKey = {}\nAddress = 10.2.0.2/32\nDNS = 10.2.0.1\n[Peer]\nPublicKey = {}\nEndpoint = 203.0.113.2:51820\nAllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 25\n",
            fs::read_to_string(self.lab.private.join("exit.key"))?.trim(),
            self.lab.public_keys[2]
        );
        fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&provider)?
            .write_all(text.as_bytes())?;
        let args = [
            "install",
            "--gateway-id",
            "gw1",
            "--uplink",
            "up0",
            "--endpoint",
            A.gwhost.peer,
            "--exit-file",
            provider.to_str().ok_or("provider path")?,
            "--exit-id",
            "ch1",
            "--binaries",
            binaries.to_str().ok_or("binary path")?,
            "--yes",
        ];
        // Ephemeral CI images can ship a group-writable binary directory.
        // Preserve evidence and satisfy the product's existing refusal contract.
        let before = self.cmd("stat", &["-c", "%u:%g %a", "/usr/local/bin"])?;
        self.cmd("chown", &["root:root", "/usr/local/bin"])?;
        self.cmd("chmod", &["0755", "/usr/local/bin"])?;
        let after = self.cmd("stat", &["-c", "%u:%g %a", "/usr/local/bin"])?;
        fs::write(
            self.lab.artifacts.join("install-bin-directory.json"),
            serde_json::to_vec_pretty(
                &serde_json::json!({"before":before.trim(),"after":after.trim()}),
            )?,
        )?;
        let plan = self.cmd(
            binaries.join("scupper").to_str().ok_or("binary path")?,
            &[&args[..], &["--plan"]].concat(),
        )?;
        fs::write(self.lab.artifacts.join("install-plan.txt"), plan)?;
        let installed = self.install_output(
            "install",
            binaries.join("scupper").to_str().ok_or("binary path")?,
            &args,
        )?;
        fs::write(self.lab.artifacts.join("install.txt"), installed)?;
        let first_port: u16 = self
            .lab
            .cmd("scupper", "wg", &["show", "ex-0", "listen-port"])?
            .trim()
            .parse()?;
        if first_port == 0 {
            return fail("installed exit has zero listen port");
        }
        self.record_port(first_port);
        let mut site = parse_site(&self.cli(&["config", "show"])?)?;
        self.lab.public_keys[0].clone_from(&site.identities["edge"].public_key.0);
        self.lab.site = validate(site.clone()).map_err(|e| format!("site: {e:?}"))?;
        self.ready()?;
        site = site_with_clients(site, &self.lab.public_keys[3], &self.lab.public_keys[4])?;
        let config = self.lab.private.join("site.toml");
        fs::write(&config, toml::to_string(&site)?)?;
        self.cli(&[
            "config",
            "load",
            config.to_str().ok_or("config path")?,
            "--yes",
        ])?;
        // Loading changes head only; check still observes the applied version.
        self.ready()?;
        self.cli(&["apply"])?;
        self.lab.site = validate(site).map_err(|e| format!("site: {e:?}"))?;
        self.lab.build_client()?;
        self.lab.build_second_client_mode(false)?;
        // Production exit ports are recorded, while both lab clients stay fixed.
        for ns in ["client", "client2"] {
            if self
                .lab
                .cmd(ns, "wg", &["show", "wg0", "listen-port"])?
                .trim()
                != "51820"
            {
                return fail("client listen port changed");
            }
        }
        self.lab.start_sinks()?;
        self.ready()?;
        let units = self.systemctl(&["cat", "scupper-net", "scupperd"])?;
        if !["TimeoutStartSec=90", "TimeoutStopSec=10s", "WatchdogSec=30"]
            .iter()
            .all(|s| units.contains(s))
        {
            return fail("installed unit deadlines differ from design");
        }
        fs::write(self.lab.artifacts.join("installed-units.txt"), units)?;
        let rendered = self.cli(&["rules"])?;
        fs::write(&self.lab.rules, rendered)?;
        self.lab.new_namespace("scupper-verify", "")?;
        self.lab.cmd(
            "scupper-verify",
            "nft",
            &["-f", self.lab.rules.clone().to_str().ok_or("rules")?],
        )?;
        self.lab.expected_rules = scupper_core::canon::canonicalize(&self.lab.cmd(
            "scupper-verify",
            "nft",
            &["-j", "list", "ruleset"],
        )?)?;
        self.lab
            .cmd("", "ip", &["netns", "delete", "scupper-verify"])?;
        let checked = self.cli(&[
            "install",
            "--check",
            "--binaries",
            binaries.to_str().ok_or("binaries")?,
        ])?;
        if !checked.contains("install: no changes") {
            return fail("install drift after config load");
        }
        let again = self.install_output(
            "install-again",
            CLI,
            &[
                "install",
                "--binaries",
                binaries.to_str().ok_or("binaries")?,
                "--yes",
            ],
        )?;
        if !again.contains("install: no changes") {
            return fail("second install was not a no-op");
        }
        fs::write(self.lab.artifacts.join("install-check.txt"), checked)?;
        fs::write(self.lab.artifacts.join("install-again.txt"), again)?;
        self.ready()?;
        let mut markers = Vec::new();
        self.lab.service_check(&mut markers)?;
        self.judge("install-uplink", &markers)?;
        self.guard("setup-after")
    }
    fn install_output(&mut self, label: &str, binary: &str, args: &[&str]) -> Result<String> {
        let (status, out) =
            self.lab
                .runner
                .output_timeout(&Invocation::new("", binary, args), None, 120)?;
        fs::write(self.lab.artifacts.join(format!("{label}.txt")), &out)?;
        let installed = out.contains("scupper check:") && out.contains("Mac scupper0.conf:");
        fs::write(
            self.lab.artifacts.join(format!("{label}-result.json")),
            serde_json::to_vec_pretty(
                &serde_json::json!({"install_completed":installed,"final_check_exit":status.code()}),
            )?,
        )?;
        if !installed || !matches!(status.code(), Some(0..=5)) {
            return fail(format!("install did not complete: {status}"));
        }
        Ok(out)
    }
    fn ready(&mut self) -> Result<()> {
        self.ready_recorded(None)
    }
    fn ready_recorded(&mut self, label: Option<&str>) -> Result<()> {
        let started = Instant::now();
        let until = started + Duration::from_secs(90);
        loop {
            self.lab.runner.check()?;
            let (status, output) = self
                .lab
                .runner
                .output(&Invocation::new("", CLI, &["check", "--json"]), None)?;
            if let Some(label) = label {
                let mut log = fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(self.lab.artifacts.join(format!("{label}-check.jsonl")))?;
                writeln!(
                    log,
                    "{}",
                    serde_json::json!({"elapsed_ms":started.elapsed().as_millis(),"exit":status.code(),"output":output})
                )?;
            }
            if status.code() == Some(0) {
                break;
            }
            if Instant::now() >= until {
                return fail("check did not recover to 0");
            }
            self.lab.runner.dwell(Duration::from_millis(300))?;
        }
        self.lab.wait_provider()?;
        let port = self
            .lab
            .cmd("scupper", "wg", &["show", "ex-0", "listen-port"])?
            .trim()
            .parse()?;
        if port == 0 {
            return fail("ready exit has zero listen port");
        }
        self.record_port(port);
        Ok(())
    }
    fn record_port(&mut self, port: u16) {
        self.lab.exit_port = port;
        if !self.ports.contains(&port) {
            self.ports.push(port);
        }
    }
    fn check_code(&mut self, expected: i32) -> Result<()> {
        let (status, out) = self
            .lab
            .runner
            .output(&Invocation::new("", CLI, &["check"]), None)?;
        if status.code() != Some(expected) {
            return fail(format!("check wanted {expected}, got {status}: {out}"));
        }
        Ok(())
    }
    fn reboot_stop(&mut self) -> Result<()> {
        dispatch_reboot_steps(&REBOOT_STEPS[..REBOOT_STEPS.len() - 1], |step| {
            self.reboot_step(step)
        })
    }
    fn reboot_start(&mut self) -> Result<()> {
        self.reboot_step(RebootStep::StartUnits)
    }
    #[allow(clippy::too_many_lines)] // Keep the ordered reboot effects and their assertions together.
    fn reboot_step(&mut self, step: RebootStep) -> Result<()> {
        let exists = Path::new("/run/netns/scupper").exists();
        match step {
            RebootStep::StopUnits => {
                self.systemctl(&["stop", "scupperd", "scupper-net"])?;
            }
            RebootStep::FlushHostConntrack => {
                // A reboot loses outer WireGuard conntrack too. Never flush
                // the runner's table: remove only both directions of lab pairs.
                for peer in [A.client.peer, A.client2.peer, A.provider.peer] {
                    for (source, destination) in [(A.gwhost.peer, peer), (peer, A.gwhost.peer)] {
                        let (status, _) = self.lab.runner.output(
                            &Invocation::new(
                                "",
                                "conntrack",
                                &["-D", "-p", "udp", "-s", source, "-d", destination],
                            ),
                            None,
                        )?;
                        if !matches!(status.code(), Some(0 | 1)) {
                            return fail("reboot outer conntrack deletion failed");
                        }
                    }
                }
            }
            RebootStep::FlushConntrack if exists => {
                self.lab.cmd("scupper", "conntrack", &["-F"])?;
            }
            RebootStep::DeleteLinks if exists => {
                let links: serde_json::Value = serde_json::from_str(&self.lab.cmd(
                    "scupper",
                    "ip",
                    &["-j", "link", "show"],
                )?)?;
                for link in links.as_array().ok_or("link array")? {
                    let name = link["ifname"].as_str().ok_or("link name")?;
                    if name != "lo" {
                        self.lab
                            .cmd("scupper", "ip", &["link", "delete", "dev", name])?;
                    }
                }
            }
            RebootStep::DeleteNamespace => {
                if exists {
                    self.lab.cmd("", "ip", &["netns", "delete", "scupper"])?;
                }
                if Path::new("/run/netns/scupper").exists() {
                    return fail("reboot left named namespace");
                }
            }
            RebootStep::DeleteHostLinks => {
                // A real reboot destroys host links too. Snapshot and refuse
                // unexpected leftovers before deleting only configured names.
                let links = self.host_wireguard("reboot-host-links")?;
                if links
                    .iter()
                    .any(|l| !matches!(l["ifname"].as_str(), Some("wg0" | "ex-0")))
                {
                    return fail("unexpected foreign root WireGuard link");
                }
                let mut unexpected = Vec::new();
                for name in ["wg0", "ex-0"] {
                    let (status, _) = self.lab.runner.output(
                        &Invocation::new("", "ip", &["link", "show", "dev", name]),
                        None,
                    )?;
                    if status.success() {
                        unexpected.push(name);
                        self.cmd("ip", &["link", "delete", "dev", name])?;
                    }
                }
                if !unexpected.is_empty() {
                    return fail(format!(
                        "unexpected root leftovers before reboot deletion: {unexpected:?}"
                    ));
                }
            }
            RebootStep::RemoveRuntime => {
                if Path::new("/run/scupper").exists() {
                    fs::remove_dir_all("/run/scupper")?;
                }
            }
            RebootStep::StartUnits => {
                self.lab.runner.output(
                    &Invocation::new(
                        "",
                        "systemctl",
                        &["reset-failed", "scupper-net", "scupperd"],
                    ),
                    None,
                )?;
                let ifindex = fs::read_to_string("/sys/class/net/up0/ifindex")?;
                self.lab.ensure_services()?;
                self.cmd("ip", &["link", "set", "up0", "down"])?;
                let net = self.systemctl(&["start", "scupper-net"]);
                // Restore even on failed boot, so diagnostics retain lab access.
                let up = self.cmd("ip", &["link", "set", "up0", "up"]).map(|_| ());
                super::mutation::finish(net.map(|_| ()), up)?;
                self.restore_uplink_routes()?;
                if fs::read_to_string("/sys/class/net/up0/ifindex")? != ifindex {
                    return fail("uplink ifindex changed across reboot capture");
                }
                self.lab.ensure_services()?;
                self.systemctl(&["start", "scupperd"])?;
                // A disconnected exit has no socket. Record only live ports.
                let port: u16 = self
                    .lab
                    .cmd("scupper", "wg", &["show", "ex-0", "listen-port"])?
                    .trim()
                    .parse()?;
                if port != 0 {
                    self.record_port(port);
                }
            }
            RebootStep::FlushConntrack | RebootStep::DeleteLinks => {}
        }
        Ok(())
    }
    fn host_wireguard(&mut self, label: &str) -> Result<Vec<serde_json::Value>> {
        let text = self.cmd("ip", &["-d", "-j", "link", "show", "type", "wireguard"])?;
        fs::write(self.lab.artifacts.join(format!("{label}.json")), &text)?;
        Ok(serde_json::from_str(&text)?)
    }
    fn assert_no_host_wireguard(&mut self, label: &str) -> Result<()> {
        if !self.host_wireguard(label)?.is_empty() {
            return fail("recovery left root WireGuard links");
        }
        let text = self.cmd("ip", &["-j", "address", "show"])?;
        fs::write(
            self.lab.artifacts.join(format!("{label}-addresses.json")),
            &text,
        )?;
        let links: Vec<serde_json::Value> = serde_json::from_str(&text)?;
        if links.iter().any(|l| {
            matches!(l["ifname"].as_str(), Some("wg0" | "ex-0"))
                || l["addr_info"].as_array().into_iter().flatten().any(|a| {
                    a["local"].as_str().is_some_and(|ip| {
                        ip.starts_with("10.99.")
                            || ip.starts_with("10.2.")
                            || ip.starts_with("fd00:99:")
                            || ip.starts_with("2001:db8:")
                    })
                })
        }) {
            return fail("recovery left root scupper addresses or links");
        }
        Ok(())
    }
    fn evaluate(&mut self, stem: &str, markers: &[String]) -> Result<crate::pcap::Report> {
        self.lab.stop_captures()?;
        let policy = uplink_policy(markers, &self.ports, self.lab.exit_port)?;
        fs::write(
            self.lab.artifacts.join(format!("{stem}.policy.toml")),
            &policy,
        )?;
        let report = crate::pcap::classify(
            &fs::read(self.lab.artifacts.join(format!("{stem}.pcap")))?,
            &crate::pcap::Policy::from_toml(&policy)?,
            30,
        )?;
        fs::write(
            self.lab.artifacts.join(format!("{stem}.oracle.json")),
            serde_json::to_vec_pretty(&report)?,
        )?;
        Ok(report)
    }
    fn judge(&mut self, stem: &str, markers: &[String]) -> Result<()> {
        let evaluated = self.evaluate(stem, markers);
        let egress = self.egress_zero(stem);
        let report = evaluated?;
        egress?;
        if !evidence::contained(&report) {
            return fail(format!("uplink oracle failed: {report:?}"));
        }
        Ok(())
    }
    fn safety(&mut self) -> Result<()> {
        self.samples += 1;
        let exists = Path::new("/run/netns/scupper").exists();
        let mut forwarding = Vec::new();
        let mut exact = None;
        if exists {
            for key in ["net.ipv4.ip_forward", "net.ipv6.conf.all.forwarding"] {
                let value = self
                    .lab
                    .cmd("scupper", "sysctl", &["-n", key])?
                    .trim()
                    .to_owned();
                if value != "0" && value != "1" {
                    return fail("invalid forwarding readback");
                }
                forwarding.push(value);
            }
            if forwarding.iter().any(|v| v == "1") {
                exact = Some(
                    scupper_core::canon::canonicalize(&self.lab.cmd(
                        "scupper",
                        "nft",
                        &["-j", "list", "ruleset"],
                    )?)? == self.lab.expected_rules,
                );
            }
        }
        let mut log = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.lab.artifacts.join("safety.jsonl"))?;
        writeln!(
            log,
            "{}",
            serde_json::json!({"sample":self.samples,"namespace":exists,"forwarding":forwarding,"exact_ruleset":exact})
        )?;
        if exact == Some(false) {
            return fail("forwarding enabled without exact verified ruleset");
        }
        Ok(())
    }
    fn negative_udp(&mut self, namespace: &str, marker: &str) -> Result<()> {
        // A closed forwarding gate or unreachable route can return ICMP
        // instead of timing out. Verify the sender's route before accepting
        // those errors; launcher, bind, key and malformed-response errors fail.
        let route = self
            .lab
            .cmd(namespace, "ip", &["route", "get", A.internet.peer])?;
        if !route
            .split_whitespace()
            .collect::<Vec<_>>()
            .windows(2)
            .any(|w| w == ["dev", "wg0"])
        {
            return fail("negative canary has no client tunnel route");
        }
        let (status, text) = self.lab.runner.output(
            &Invocation::new(
                namespace,
                &self.lab.executable,
                &[
                    "probe",
                    "--protocol",
                    "udp",
                    "--target",
                    A.internet.peer,
                    "--port",
                    "8080",
                    "--marker",
                    marker,
                ],
            ),
            None,
        )?;
        let attempt: helpers::Attempt = serde_json::from_str(&text)?;
        let valid = matches!(
            attempt.outcome,
            helpers::Outcome::TimedOut
                | helpers::Outcome::LocalReject(1)
                | helpers::Outcome::HarnessError {
                    errno: Some(101 | 111 | 113),
                    ..
                }
        );
        let mut log = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.lab.artifacts.join("negative-probes.jsonl"))?;
        writeln!(
            log,
            "{}",
            serde_json::json!({"namespace":namespace,"attempt":attempt,"exit":status.code()})
        )?;
        if status.code() != Some(1)
            || attempt.destination.ip().to_string() != A.internet.peer
            || attempt.destination.port() != 8080
            || attempt.marker != marker
            || attempt.protocol != "udp"
            || !valid
        {
            return fail(format!("negative UDP canary failed: {status}: {text}"));
        }
        Ok(())
    }
}

// Add lab clients to the installed site without changing exit names, secret
// references, health settings or selection IDs. A rename leaves a foreign link
// in the live namespace, which boot correctly refuses rather than deleting.
fn site_with_clients(
    mut site: scupper_core::config::SiteConfig,
    client: &str,
    second_client: &str,
) -> Result<scupper_core::config::SiteConfig> {
    let template = parse_site(SITE)?;
    site.users = template.users;
    site.devices = template.devices;
    site.devices.get_mut("client").ok_or("client")?.public_key.0 = client.into();
    super::add_second_client(&mut site, second_client)?;
    Ok(site)
}

fn dispatch_reboot_steps(
    steps: &[RebootStep],
    mut execute: impl FnMut(RebootStep) -> Result<()>,
) -> Result<()> {
    steps.iter().try_for_each(|step| execute(*step))
}

fn uplink_policy(markers: &[String], ports: &[u16], current_port: u16) -> Result<String> {
    let mut policy = evidence::policy_for_case(markers, false, current_port, true)?;
    for port in ports.iter().filter(|port| **port != current_port) {
        write!(
            policy,
            "\n[[wireguard]]\ngateway = \"{}:{port}\"\npeer = \"{}:51820\"\n",
            A.gwhost.peer, A.provider.peer
        )?;
    }
    // Absent boot sockets can elicit ICMP quoting encrypted WireGuard only;
    // the same decoder still rejects quoted client addresses and markers.
    for remote in [A.client.peer, A.provider.peer] {
        write!(
            policy,
            "\n[[host_allow]]\nproto = \"icmp\"\nremote_addr = \"{remote}\"\ntypes = [3]\n"
        )?;
    }
    Ok(policy)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn adding_clients_preserves_installed_gateway_and_secrets() {
        let mut installed = parse_site(SITE).unwrap();
        let gateway = installed.gateways.values_mut().next().unwrap();
        gateway.exits[0].ifname = "ex-0".into();
        let before = toml::to_string(&installed.gateways).unwrap();
        let identities = toml::to_string(&installed.identities).unwrap();
        let client = installed.devices["client"].public_key.0.clone();
        let configured = site_with_clients(
            installed,
            &client,
            "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=",
        )
        .unwrap();
        assert_eq!(toml::to_string(&configured.gateways).unwrap(), before);
        assert_eq!(toml::to_string(&configured.identities).unwrap(), identities);
        assert!(configured.devices.contains_key("client2"));
        assert!(validate(configured).is_ok());
    }
    #[test]
    fn reboot_dispatch_executes_in_order_and_stops_on_failure() {
        let mut calls = Vec::new();
        dispatch_reboot_steps(REBOOT_STEPS, |step| {
            calls.push(step);
            Ok(())
        })
        .unwrap();
        assert_eq!(
            calls,
            vec![
                RebootStep::StopUnits,
                RebootStep::FlushHostConntrack,
                RebootStep::FlushConntrack,
                RebootStep::DeleteLinks,
                RebootStep::DeleteNamespace,
                RebootStep::DeleteHostLinks,
                RebootStep::RemoveRuntime,
                RebootStep::StartUnits
            ]
        );
        calls.clear();
        assert!(
            dispatch_reboot_steps(REBOOT_STEPS, |step| {
                calls.push(step);
                if step == RebootStep::DeleteLinks {
                    return fail("injected dispatcher failure");
                }
                Ok(())
            })
            .is_err()
        );
        assert_eq!(calls.last(), Some(&RebootStep::DeleteLinks));
        assert_eq!(calls.len(), 4);
    }
}
