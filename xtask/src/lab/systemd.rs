//! Installed-unit lab. Only CI runs this against the real root namespace.
mod cases;
mod guards;
use super::{
    Lab, Result, SITE,
    addresses::A,
    cleanup::Registry,
    command::{Invocation, Runner},
    evidence, fail, helpers,
};
use guards::HostSnapshot;
use scupper_core::config::{GatewayId, parse_site, validate};
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
    RemoveRuntime,
    StartUnits,
}
const REBOOT_STEPS: &[RebootStep] = &[
    RebootStep::StopUnits,
    RebootStep::FlushHostConntrack,
    RebootStep::FlushConntrack,
    RebootStep::DeleteLinks,
    RebootStep::DeleteNamespace,
    RebootStep::RemoveRuntime,
    RebootStep::StartUnits,
];

struct SystemdLab {
    lab: Lab,
    baseline: HostSnapshot,
    ports: Vec<u16>,
    samples: usize,
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
    runner.whole = Instant::now() + Duration::from_mins(25);
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
        ports: Vec::new(),
        samples: 0,
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
    let captures = harness.lab.stop_captures();
    let result = super::mutation::finish(
        outcome,
        super::mutation::finish(guard, super::mutation::finish(journal, captures)),
    );
    fs::write(
        harness.lab.artifacts.join(format!("{case}.json")),
        serde_json::to_vec_pretty(&serde_json::json!({
            "case":case, "passed":result.is_ok(), "error":result.as_ref().err().map(ToString::to_string),
            "safety_samples":harness.samples, "exit_ports":harness.ports,
            "reboot_steps":REBOOT_STEPS,
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
        for link in ["up0", "wg0", "ex-0", "ex-ch1", A.gwhost.wan_if] {
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
        let plan = self.cmd(
            binaries.join("scupper").to_str().ok_or("binary path")?,
            &[&args[..], &["--plan"]].concat(),
        )?;
        fs::write(self.lab.artifacts.join("install-plan.txt"), plan)?;
        let installed = self.cmd(
            binaries.join("scupper").to_str().ok_or("binary path")?,
            &args,
        )?;
        fs::write(self.lab.artifacts.join("install.txt"), installed)?;
        let mut site = parse_site(&self.cli(&["config", "show"])?)?;
        self.lab.public_keys[0].clone_from(&site.identities["edge"].public_key.0);
        let template = parse_site(SITE)?;
        site.users = template.users;
        site.devices = template.devices;
        site.devices
            .get_mut("client")
            .ok_or("client")?
            .public_key
            .0
            .clone_from(&self.lab.public_keys[3]);
        super::add_second_client(&mut site, &self.lab.public_keys[4])?;
        site.gateways
            .get_mut(&GatewayId("gw1".into()))
            .ok_or("gw1")?
            .exits[0]
            .ifname = "ex-ch1".into();
        let config = self.lab.private.join("site.toml");
        fs::write(&config, toml::to_string(&site)?)?;
        self.cli(&[
            "config",
            "load",
            config.to_str().ok_or("config path")?,
            "--yes",
        ])?;
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
        let again = self.cli(&[
            "install",
            "--binaries",
            binaries.to_str().ok_or("binaries")?,
            "--yes",
        ])?;
        if !again.contains("install: no changes") {
            return fail("second install was not a no-op");
        }
        fs::write(self.lab.artifacts.join("install-check.txt"), checked)?;
        fs::write(self.lab.artifacts.join("install-again.txt"), again)?;
        self.guard("setup-after")
    }
    fn ready(&mut self) -> Result<()> {
        let until = Instant::now() + Duration::from_secs(90);
        loop {
            self.lab.runner.check()?;
            let (status, _) = self
                .lab
                .runner
                .output(&Invocation::new("", CLI, &["check"]), None)?;
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
            .cmd("scupper", "wg", &["show", "ex-ch1", "listen-port"])?
            .trim()
            .parse()?;
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
        for step in &REBOOT_STEPS[..REBOOT_STEPS.len() - 1] {
            self.reboot_step(*step)?;
        }
        Ok(())
    }
    fn reboot_start(&mut self) -> Result<()> {
        self.reboot_step(RebootStep::StartUnits)
    }
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
            RebootStep::RemoveRuntime => {
                if Path::new("/run/scupper").exists() {
                    fs::remove_dir_all("/run/scupper")?;
                }
            }
            RebootStep::StartUnits => {
                self.systemctl(&["reset-failed", "scupper-net", "scupperd"])?;
                self.systemctl(&["start", "scupper-net", "scupperd"])?;
                let port = self
                    .lab
                    .cmd("scupper", "wg", &["show", "ex-ch1", "listen-port"])?
                    .trim()
                    .parse()?;
                self.record_port(port);
            }
            RebootStep::FlushConntrack | RebootStep::DeleteLinks => {}
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
        let report = self.evaluate(stem, markers)?;
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
    fn closed_canary(&mut self, markers: &mut Vec<String>) -> Result<()> {
        let marker = Lab::marker()?;
        markers.push(marker.clone());
        self.negative_udp("client", &marker)?;
        Ok(())
    }
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
