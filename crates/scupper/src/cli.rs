//! The v1 command line with injectable operating-system and interaction boundaries.

use std::{
    ffi::OsString,
    io::{self, IsTerminal, Write},
    net::IpAddr,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use clap::{Parser, Subcommand, error::ErrorKind};

use crate::{
    apply::{self, Fs, RULESET_PATH, RealFs},
    canon,
    check::{self, ExitProbe, TopologySource},
    parse::HandshakeAge,
    probe::{BoundHttpsProbe, default_targets},
    rules::{self, V1Config},
    system::{ExecError, ExecOutput, Program, RealSystem, SYSTEMCTL_TIMEOUT, System},
    topology::HostTopology,
    verdict::{self, HealthConfig, M1Topology, Probe, ProbeError, Warning},
};

#[derive(Parser)]
#[command(name = "scupper", version, about = "Fail-closed VPN gateway")]
struct Cli {
    /// Render a schema-1 machine-readable report.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Subcommand)]
enum Command {
    /// Run one isolated namespace observation using stdin as a namespace fd.
    #[command(hide = true)]
    Probe {
        /// One JSON `ProbeRequest` (stdin is not a byte stream).
        request: String,
    },
    /// Canonicalize a ruleset only inside an isolated network namespace.
    #[command(hide = true)]
    Canon {
        /// Namespace inspected by the parent, which must never be modified.
        #[arg(long)]
        outer_netns: PathBuf,
        /// Held gateway identity, also forbidden as a canonicalization target.
        #[arg(long)]
        gateway_netns: Option<PathBuf>,
        /// Rendered ruleset to load in the isolated namespace.
        path: std::path::PathBuf,
    },
    /// Show an informational human-readable status report.
    Status,
    /// Check protection and return the verdict as an exit code.
    Check,
    /// Start the exit tunnel and wait up to ten seconds for a fresh handshake.
    Connect,
    /// Stop the exit tunnel and verify the kill switch.
    ///
    /// Over the SSH wrapper without a TTY, --yes is required.
    Disconnect {
        /// Skip confirmation.
        #[arg(long)]
        yes: bool,
    },
    /// Print the generated nftables ruleset.
    Rules,
    /// Validate, replace and load /etc/nftables.conf.
    ///
    /// Over the SSH wrapper without a TTY, --yes is required.
    Apply {
        /// Skip confirmation.
        #[arg(long)]
        yes: bool,
    },
}

/// Namespace identity reader used before any canon command execution.
pub trait NamespaceReader {
    /// Reads a namespace symlink such as `/proc/self/ns/net`.
    ///
    /// # Errors
    /// Returns the symlink read error.
    fn read_namespace(&self, path: &Path) -> io::Result<PathBuf>;

    /// Whether the owned namespace name exists, including an invalid handle.
    ///
    /// # Errors
    /// Returns filesystem errors other than absence.
    fn gateway_marker(&self) -> io::Result<bool> {
        match std::fs::symlink_metadata("/run/netns/scupper") {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        }
    }

    /// Opens the owned namespace once; all later commands borrow this handle.
    ///
    /// # Errors
    /// Returns invalid, host or inaccessible namespace errors; absence is None.
    fn open_gateway(&self) -> Result<Option<scupper_sys::netns::NetnsHandle>, String> {
        use scupper_sys::netns::{NetnsError, NetnsHandle};
        match NetnsHandle::open("/run/netns/scupper") {
            Ok(handle) => Ok(Some(handle)),
            Err(NetnsError::Io(rustix::io::Errno::NOENT)) => Ok(None),
            Err(error) => Err(error.to_string()),
        }
    }
}

/// Reads namespace identities from procfs.
#[derive(Debug, Default)]
pub struct ProcNamespaces;

impl NamespaceReader for ProcNamespaces {
    fn read_namespace(&self, path: &Path) -> io::Result<PathBuf> {
        std::fs::read_link(path)
    }
}

/// Effective-user-ID boundary for commands that mutate the host.
pub trait Privilege {
    /// Whether the effective uid is zero.
    fn is_root(&self) -> bool;
}

/// Reads the host's effective uid through rustix.
#[derive(Debug, Default)]
pub struct EffectiveUid;

impl Privilege for EffectiveUid {
    fn is_root(&self) -> bool {
        rustix::process::geteuid().is_root()
    }
}

/// Confirmation boundary, including detection of interactive input and output.
pub trait Prompt {
    /// Whether both input and prompt output are terminals.
    fn is_terminal(&self) -> bool;

    /// Shows the optional preview, then asks the question; the default is no.
    ///
    /// # Errors
    /// Returns input or output errors.
    fn confirm(&self, question: &str, preview: Option<&str>) -> io::Result<bool>;
}

/// Prompts on stderr and reads stdin without a prompt-library dependency.
#[derive(Debug, Default)]
pub struct TerminalPrompt;

impl Prompt for TerminalPrompt {
    fn is_terminal(&self) -> bool {
        io::stdin().is_terminal() && io::stderr().is_terminal()
    }

    fn confirm(&self, question: &str, preview: Option<&str>) -> io::Result<bool> {
        let mut output = io::stderr();
        if let Some(preview) = preview {
            write!(output, "{preview}")?;
        }
        write!(output, "{question} ")?;
        output.flush()?;
        let mut answer = String::new();
        io::stdin().read_line(&mut answer)?;
        Ok(parse_confirmation(&answer))
    }
}

/// Accepts only a trimmed, case-insensitive `y` or `yes`; empty input/EOF is no.
#[must_use]
pub fn parse_confirmation(answer: &str) -> bool {
    matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

/// Waiting and monotonic clock boundary for the connect polling loop.
pub trait Sleeper {
    /// Current monotonic instant, independent of wall-clock corrections.
    fn now(&self) -> Instant;

    /// Waits for the requested duration.
    fn sleep(&self, duration: Duration);
}

/// Host thread sleeper.
#[derive(Debug, Default)]
pub struct ThreadSleeper;

impl Sleeper for ThreadSleeper {
    fn now(&self) -> Instant {
        Instant::now()
    }

    fn sleep(&self, duration: Duration) {
        std::thread::sleep(duration);
    }
}

/// Placeholder containment source retained for injected command tests.
#[derive(Debug, Default)]
pub struct UnimplementedTopology;

impl TopologySource for UnimplementedTopology {
    fn observe(&self, _sys: &dyn System, _cfg: &V1Config) -> Probe<M1Topology> {
        Err(ProbeError::setup("not implemented in this build"))
    }
}

/// Placeholder bound exit probe retained for injected command tests.
#[derive(Debug, Default)]
pub struct UnimplementedExitProbe;

impl ExitProbe for UnimplementedExitProbe {
    fn probe(&self, _cfg: &V1Config) -> Probe<IpAddr> {
        Err(ProbeError::setup("not implemented in this build"))
    }
}

/// Dependencies shared by commands; M2 checks read the validated immutable head.
pub struct Dependencies<'a> {
    /// Persistent M2 config, boot and state root.
    pub state_root: &'a Path,
    /// Gateway-id, mirror and secrets root; check never opens private keys.
    pub config_root: &'a Path,
    /// Namespace probe child execution.
    pub probe_exec: &'a dyn scupper_sys::probe_child::ProbeExec,
    /// Command execution and clock.
    pub system: &'a dyn System,
    /// Network namespace identities for the canon safety guard.
    pub namespaces: &'a dyn NamespaceReader,
    /// Ruleset storage.
    pub fs: &'a dyn Fs,
    /// Effective uid check.
    pub privilege: &'a dyn Privilege,
    /// Terminal detection and confirmations.
    pub prompt: &'a dyn Prompt,
    /// Connect polling delays.
    pub sleeper: &'a dyn Sleeper,
    /// Containment observations.
    pub topology: &'a dyn TopologySource,
    /// Bound public exit-address observation.
    pub exit_probe: &'a dyn ExitProbe,
}

/// Runs the CLI against the host using only default executable paths.
#[must_use]
pub fn run<I, T>(args: I) -> u8
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    run_with(
        args,
        &Dependencies {
            state_root: Path::new("/var/lib/scupper"),
            config_root: Path::new("/etc/scupper"),
            probe_exec: &RealSystem::default(),
            system: &RealSystem::default(),
            namespaces: &ProcNamespaces,
            fs: &RealFs,
            privilege: &EffectiveUid,
            prompt: &TerminalPrompt,
            sleeper: &ThreadSleeper,
            topology: &HostTopology,
            exit_probe: &BoundHttpsProbe::new(default_targets()),
        },
        &mut io::stdout(),
        &mut io::stderr(),
    )
}

/// Runs in-process with injected dependencies and captured output streams.
/// Argument errors use code 1 so they cannot collide with unprotected code 2.
#[must_use]
pub fn run_with<I, T>(
    args: I,
    deps: &Dependencies<'_>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> u8
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(error) => {
            if matches!(
                error.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            ) {
                let _ = write!(stdout, "{error}");
                return 0;
            }
            let _ = writeln!(stderr, "scupper: {error}");
            return 1;
        }
    };
    match dispatch(cli.command, cli.json, deps, stdout, stderr) {
        Ok(code) => code,
        Err(error) => {
            if cli.json {
                let _ = serde_json::to_writer(
                    &mut *stdout,
                    &serde_json::json!({"schema": 1, "error": json_error(None, &error)}),
                );
                let _ = writeln!(stdout);
            }
            let _ = writeln!(stderr, "scupper: {error}");
            1
        }
    }
}

fn disconnect(
    deps: &Dependencies<'_>,
    cfg: &V1Config,
    yes: bool,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Result<u8, String> {
    require_root(deps, "disconnect")?;
    confirm(
        deps,
        "disconnect",
        yes,
        "Block all client traffic now? [y/N]",
        None,
    )?;
    systemctl(deps.system, "stop", cfg)?;
    if let Ok(topology) = deps.topology.observe(deps.system, cfg) {
        if let Some(violations) = verdict::topology_violations(&topology) {
            writeln!(
                stderr,
                "exit tunnel stopped; kill switch is NOT in place: {}",
                verdict::Verdict::Unprotected(violations)
            )
            .map_err(output_error)?;
            Ok(2)
        } else {
            writeln!(stdout, "traffic is now blocked").map_err(output_error)?;
            Ok(0)
        }
    } else {
        writeln!(
            stderr,
            "exit tunnel stopped; kill switch state unknown, run 'scupper check'"
        )
        .map_err(output_error)?;
        Ok(1)
    }
}

#[allow(clippy::too_many_lines)] // Keep command dispatch and M1 behavior together.
fn dispatch(
    command: Command,
    json: bool,
    deps: &Dependencies<'_>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Result<u8, String> {
    let cfg = V1Config::default();
    match command {
        Command::Probe { request } => {
            let outcome = scupper_sys::probe_child::child_main(&request)?;
            serde_json::to_writer(&mut *stdout, &outcome).map_err(|error| error.to_string())?;
            writeln!(stdout).map_err(output_error)?;
            Ok(0)
        }
        Command::Canon {
            outer_netns,
            gateway_netns: Some(gateway),
            path,
        } => {
            let text =
                canon::isolated_netns_ruleset(deps.system, &path, &outer_netns, &gateway, |path| {
                    deps.namespaces.read_namespace(path)
                })
                .map_err(|error| error.to_string())?;
            write!(stdout, "{text}").map_err(output_error)?;
            Ok(0)
        }
        Command::Canon {
            outer_netns,
            gateway_netns: None,
            path,
        } => Ok(canon::run_isolated(
            deps.system,
            &path,
            &outer_netns,
            |path| deps.namespaces.read_namespace(path),
            stdout,
            stderr,
        )),
        Command::Status => {
            match m2_config(deps) {
                Ok(Some(config)) => return m2_check(deps, &config, true, json, stdout, stderr),
                Err(error) => {
                    return status_error(stdout, json, &error);
                }
                Ok(None) => {}
            }
            // Status is informational, including when observations fail.
            let _ = writeln!(
                stdout,
                "{}",
                check::run_status(deps.system, deps.topology, &cfg)
            );
            Ok(0)
        }
        Command::Check => {
            if let Some(config) = m2_config(deps)? {
                return m2_check(deps, &config, false, json, stdout, stderr);
            }
            if json {
                return Err("check --json requires an M2 layout".into());
            }
            let report = check::run_check(deps.system, deps.topology, deps.exit_probe, &cfg)
                .map_err(|error| error.to_string())?;
            writeln!(stdout, "{}", report.verdict).map_err(output_error)?;
            for warning in report.warnings {
                writeln!(stderr, "warning: {}", warning_text(warning)).map_err(output_error)?;
            }
            Ok(report.verdict.exit_code())
        }
        Command::Rules => {
            write!(
                stdout,
                "{}",
                rules::ruleset(&cfg).map_err(|error| error.to_string())?
            )
            .map_err(output_error)?;
            Ok(0)
        }
        Command::Connect => {
            require_root(deps, "connect")?;
            connect(deps, &cfg, stdout, stderr)
        }
        Command::Disconnect { yes } => disconnect(deps, &cfg, yes, stdout, stderr),
        Command::Apply { yes } => {
            require_root(deps, "apply")?;
            let rules = rules::ruleset(&cfg).map_err(|error| error.to_string())?;
            let destination = Path::new(RULESET_PATH);
            deps.fs
                .check_target(destination)
                .map_err(|error| format!("inspect {RULESET_PATH}: {error}"))?;
            let old = match deps.fs.read(destination) {
                Ok(old) => Some(old),
                Err(error) if error.kind() == io::ErrorKind::NotFound => None,
                Err(error) => return Err(format!("read {RULESET_PATH}: {error}")),
            };
            let unchanged = old.as_deref() == Some(&rules);
            if unchanged {
                writeln!(stdout, "ruleset unchanged; reloading").map_err(output_error)?;
            } else {
                let preview = old.as_deref().map(|old| apply::ruleset_diff(old, &rules));
                confirm(
                    deps,
                    "apply",
                    yes,
                    "Replace /etc/nftables.conf and load it? [y/N]",
                    preview.as_deref(),
                )?;
            }
            apply::apply(deps.system, deps.fs, &rules)?;
            if !unchanged {
                writeln!(stdout, "ruleset written and loaded").map_err(output_error)?;
            }
            Ok(0)
        }
    }
}

struct AppliedConfig {
    site: scupper_core::config::ValidatedSite,
    gateway: scupper_core::config::GatewayId,
    stamp: scupper_core::render::VersionStamp,
}

fn m2_config(deps: &Dependencies<'_>) -> Result<Option<AppliedConfig>, String> {
    let store = scupper_sys::store::VersionStore::read_only(deps.state_root, deps.config_root);
    let Some(version) = store.head().map_err(|error| error.to_string())? else {
        for path in [
            deps.state_root.to_path_buf(),
            deps.state_root.join("boot.json"),
            deps.state_root.join("state.json"),
            deps.config_root.join("gateway-id"),
        ] {
            match std::fs::symlink_metadata(&path) {
                Ok(_) => return Err("M2 layout without an applied head".into()),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(format!("inspect M2 marker: {error}")),
            }
        }
        if deps
            .namespaces
            .gateway_marker()
            .map_err(|error| format!("inspect M2 namespace marker: {error}"))?
        {
            return Err("M2 layout without an applied head".into());
        }
        return Ok(None);
    };
    let (text, meta) = store.read(version).map_err(|error| error.to_string())?;
    let site = scupper_core::config::parse_site(&text).map_err(|error| error.to_string())?;
    let site = scupper_core::config::validate(site).map_err(|_| "invalid applied site")?;
    let gateway = scupper_core::config::GatewayId(
        RealFs
            .read(&deps.config_root.join("gateway-id"))
            .map_err(|error| format!("read gateway-id: {error}"))?
            .trim()
            .into(),
    );
    if site.gateway(&gateway).is_none() {
        return Err("gateway-id is absent from applied site".into());
    }
    let mut sha256 = [0; 32];
    for (index, byte) in sha256.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&meta.sha256[index * 2..index * 2 + 2], 16)
            .map_err(|_| "invalid applied digest")?;
    }
    Ok(Some(AppliedConfig {
        site,
        gateway,
        stamp: scupper_core::render::VersionStamp { version, sha256 },
    }))
}

fn json_error(stage: Option<scupper_core::verdict::v2::Stage>, message: &str) -> serde_json::Value {
    serde_json::json!({"stage": stage, "message": message})
}

fn redact_endpoints(obs: &mut scupper_core::verdict::v2::Observations) {
    if let Some(Ok(topology)) = &mut obs.topology {
        for peer in topology.peers.values_mut().flatten() {
            peer.endpoint = None;
        }
    }
}

fn status_error(stdout: &mut dyn Write, json: bool, error: &str) -> Result<u8, String> {
    if json {
        serde_json::to_writer(
            &mut *stdout,
            &serde_json::json!({"schema": 1, "error": json_error(None, error)}),
        )
        .map_err(|error| error.to_string())?;
        writeln!(stdout).map_err(output_error)?;
    } else {
        writeln!(stdout, "M2 observations failed: {error}").map_err(output_error)?;
    }
    Ok(0)
}

fn status_json(
    stdout: &mut dyn Write,
    result: &Result<scupper_core::verdict::v2::Report, scupper_core::verdict::v2::CheckError>,
    obs: &scupper_core::verdict::v2::Observations,
) -> Result<(), String> {
    // Status retains a diagnostic representation of every stage, including
    // explicitly unrequested stages. Check's machine interface is the Report.
    let value = serde_json::json!({"schema": 1, "report": result.as_ref().ok(),
    "error": result.as_ref().err().map(|error| json_error(Some(error.stage), &error.source.to_string())), "observations": {
        "topology": format!("{:?}", obs.topology),
        "selection": format!("{:?}", obs.selection),
        "active": format!("{:?}", obs.active),
        "defaults": format!("{:?}", obs.defaults),
        "handshakes": format!("{:?}", obs.handshakes),
        "forwarding": format!("{:?}", obs.forwarding),
        "routes": format!("{:?}", obs.routes),
        "exit_probe": format!("{:?}", obs.exit_probe),
        "standby_probe": format!("{:?}", obs.standby_probe),
        "dns": format!("{:?}", obs.dns),
        "supervisor": format!("{:?}", obs.supervisor),
    }});
    serde_json::to_writer(&mut *stdout, &value).map_err(|error| error.to_string())?;
    writeln!(stdout).map_err(output_error)
}

fn m2_check(
    deps: &Dependencies<'_>,
    config: &AppliedConfig,
    status: bool,
    json: bool,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Result<u8, String> {
    let handle = match deps.namespaces.open_gateway() {
        Ok(handle) => handle,
        Err(error) if status => {
            return status_error(stdout, json, &error);
        }
        Err(error) => return Err(error),
    };
    let (result, mut observations) = scupper_sys::check_v2::run_with_observations(
        &scupper_sys::check_v2::Dependencies {
            system: deps.system,
            probe_exec: deps.probe_exec,
            handle: handle.as_ref(),
            state_root: deps.state_root,
        },
        &scupper_sys::check_v2::Config {
            site: &config.site,
            gateway: &config.gateway,
            stamp: config.stamp,
        },
    );
    if status {
        redact_endpoints(&mut observations);
        if json {
            status_json(stdout, &result, &observations)?;
            return Ok(0);
        }
        writeln!(
            stdout,
            "M2 observations (None = not requested):\n{observations:#?}"
        )
        .map_err(output_error)?;
        match result {
            Ok(report) => writeln!(stdout, "{}", report.verdict).map_err(output_error)?,
            Err(error) => writeln!(stdout, "{error}").map_err(output_error)?,
        }
        return Ok(0);
    }
    match result {
        Ok(report) => {
            if json {
                serde_json::to_writer(&mut *stdout, &report).map_err(|error| error.to_string())?;
                writeln!(stdout).map_err(output_error)?;
            } else {
                writeln!(stdout, "{}", report.verdict).map_err(output_error)?;
                for warning in &report.warnings {
                    writeln!(stderr, "warning: {warning:?}").map_err(output_error)?;
                }
            }
            Ok(report.verdict.exit_code())
        }
        Err(error) => {
            if json {
                serde_json::to_writer(
                    &mut *stdout,
                    &serde_json::json!({"schema": 1, "error": json_error(Some(error.stage), &error.source.to_string())}),
                )
                .map_err(|error| error.to_string())?;
                writeln!(stdout).map_err(output_error)?;
                Ok(1)
            } else {
                Err(error.to_string())
            }
        }
    }
}

#[allow(clippy::needless_pass_by_value)] // Used directly as a map_err callback.
fn output_error(error: io::Error) -> String {
    format!("write output: {error}")
}

fn require_root(deps: &Dependencies<'_>, command: &str) -> Result<(), String> {
    if deps.privilege.is_root() {
        Ok(())
    } else {
        Err(format!("{command} must run as root"))
    }
}

fn require_interactive_or_yes(
    deps: &Dependencies<'_>,
    command: &str,
    yes: bool,
) -> Result<(), String> {
    if yes || deps.prompt.is_terminal() {
        Ok(())
    } else {
        Err(format!(
            "{command} requires confirmation; add --yes without a TTY"
        ))
    }
}

fn confirm(
    deps: &Dependencies<'_>,
    command: &str,
    yes: bool,
    question: &str,
    preview: Option<&str>,
) -> Result<(), String> {
    require_interactive_or_yes(deps, command, yes)?;
    if yes {
        return Ok(());
    }
    if deps
        .prompt
        .confirm(question, preview)
        .map_err(|error| format!("confirmation: {error}"))?
    {
        Ok(())
    } else {
        Err(format!("{command} cancelled"))
    }
}

fn systemctl(sys: &dyn System, action: &str, cfg: &V1Config) -> Result<(), String> {
    let output = sys
        .run(
            Program::Systemctl,
            &[action.into(), format!("wg-quick@{}", cfg.exit_iface)],
            SYSTEMCTL_TIMEOUT,
        )
        .map_err(|error| format!("systemctl {action}: {error}"))?;
    if output.status == Some(0) {
        Ok(())
    } else {
        Err(format!(
            "systemctl {action} failed (status {:?}): {}",
            output.status,
            output.stderr.trim()
        ))
    }
}

// Caps handshake command execution at the remaining polling budget.
struct PollSystem<'a> {
    inner: &'a dyn System,
    clock: &'a dyn Sleeper,
    deadline: Instant,
}

impl System for PollSystem<'_> {
    fn run(
        &self,
        program: Program,
        args: &[String],
        timeout: Duration,
    ) -> Result<ExecOutput, ExecError> {
        let remaining = self.deadline.saturating_duration_since(self.clock.now());
        self.inner.run(program, args, timeout.min(remaining))
    }

    fn now_unix_secs(&self) -> u64 {
        self.inner.now_unix_secs()
    }
}

fn connect(
    deps: &Dependencies<'_>,
    cfg: &V1Config,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Result<u8, String> {
    systemctl(deps.system, "start", cfg)?;
    let health = HealthConfig::from(cfg);
    let sys = PollSystem {
        inner: deps.system,
        clock: deps.sleeper,
        deadline: deps.sleeper.now() + Duration::from_secs(10),
    };
    let mut warned = false;
    while deps.sleeper.now() < sys.deadline {
        let observed = check::observe_handshake(&sys, cfg);
        let now = sys.now_unix_secs();
        let handshake = match observed {
            Ok(handshake) => handshake,
            Err(_) if deps.sleeper.now() >= sys.deadline => break,
            Err(error) => return Err(error.to_string()),
        };
        if matches!(handshake.age_at(now), HandshakeAge::InFuture(_)) && !warned {
            writeln!(stderr, "warning: {}", warning_text(Warning::ClockSkew))
                .map_err(output_error)?;
            warned = true;
        }
        if check::handshake_is_fresh(handshake, &health, now) && deps.sleeper.now() <= sys.deadline
        {
            writeln!(stdout, "exit tunnel has a fresh handshake").map_err(output_error)?;
            return Ok(0);
        }
        let remaining = sys.deadline.saturating_duration_since(deps.sleeper.now());
        if !remaining.is_zero() {
            deps.sleeper.sleep(Duration::from_secs(1).min(remaining));
        }
    }
    writeln!(
        stdout,
        "exit tunnel started; no fresh handshake within ten seconds"
    )
    .map_err(output_error)?;
    Ok(3)
}

fn warning_text(warning: Warning) -> &'static str {
    match warning {
        Warning::ClockSkew => "handshake timestamp is in the future (clock skew?)",
    }
}
