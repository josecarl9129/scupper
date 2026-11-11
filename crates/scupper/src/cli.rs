//! M2 commands with injectable operating-system and interaction boundaries.

use std::{
    ffi::OsString,
    io::{self, IsTerminal, Write},
    path::{Path, PathBuf},
};

use crate::{
    canon,
    system::{RealSystem, System},
};
use clap::{Parser, Subcommand, error::ErrorKind};

mod alerts;
mod config;
mod control;
use config::ConfigCommand;

#[derive(Parser)]
#[command(name = "scupper", version, about = "Fail-closed VPN gateway")]
struct Cli {
    /// Test-only isolated filesystem roots for the disposable namespace lab.
    #[cfg(feature = "testing")]
    #[arg(long, global = true, hide = true)]
    test_root: Option<PathBuf>,
    /// Render a schema-1 machine-readable health report (check/status).
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Subcommand)]
enum Command {
    /// Construct or adopt the gateway namespace, stopping at the first failure.
    #[command(hide = true)]
    Boot {
        /// Test-only process kill after a numbered checkpoint.
        #[cfg(feature = "testing")]
        #[arg(long, value_parser = clap::value_parser!(u8).range(0..=7))]
        stop_after: Option<u8>,
        /// Test-only process kill between host link creation and movement.
        #[cfg(feature = "testing")]
        #[arg(long, num_args = 0..=1, default_missing_value = "any")]
        stop_after_link_add: Option<String>,
        /// Test-only public argv trace (no stdin contents).
        #[cfg(feature = "testing")]
        #[arg(long)]
        trace: Option<PathBuf>,
    },
    /// Run one isolated namespace observation using stdin as a namespace fd.
    #[command(hide = true)]
    Probe {
        /// One JSON `ProbeRequest` (stdin is not a byte stream).
        request: String,
    },
    /// Internal unprivileged delivery using a secret stdin protocol.
    #[command(hide = true)]
    Deliver {
        #[command(subcommand)]
        command: DeliverCommand,
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
    /// Clear disconnection and optionally prefer a configured exit.
    Connect { exit: Option<String> },
    /// Close the data path and independently verify kernel closure.
    Disconnect,
    /// Converge to the committed head configuration.
    Apply {
        #[arg(long)]
        dry_run: bool,
    },
    /// Inspect or explicitly clear persistent quarantine.
    Repair {
        #[command(subcommand)]
        command: control::RepairCommand,
    },
    /// Inspect and version the M2 site configuration.
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    /// Inspect alert sinks or send a test notification.
    Alerts {
        #[command(subcommand)]
        command: alerts::AlertsCommand,
    },
    /// Print head's rendered namespace ruleset or compare it with live rules.
    Rules {
        /// Show a canonical diff against the live scupper namespace.
        #[arg(long)]
        diff: bool,
    },
}

#[derive(Clone, Subcommand)]
enum DeliverCommand {
    Heartbeat,
    Alert,
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

    /// Local account name recorded in configuration history.
    ///
    /// # Errors
    /// Returns account database read errors or an unmapped effective uid.
    fn user_name(&self) -> io::Result<String> {
        let uid = rustix::process::geteuid().as_raw().to_string();
        std::fs::read_to_string("/etc/passwd")?
            .lines()
            .find_map(|line| {
                let fields: Vec<_> = line.split(':').collect();
                (fields.get(2) == Some(&uid.as_str())).then(|| fields[0].to_owned())
            })
            .ok_or_else(|| io::Error::other("effective uid has no local account name"))
    }
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
    /// Whether input, preview output and prompt output are terminals.
    fn is_terminal(&self) -> bool;

    /// Select an exact or uniquely matching configured sink on a terminal.
    /// # Errors
    /// Returns cancellation, ambiguity or input/output failures.
    fn choose(&self, candidates: &[&str]) -> io::Result<String> {
        if !self.is_terminal() || candidates.is_empty() {
            return Err(io::Error::other("no interactive choices"));
        }
        let mut output = io::stderr();
        writeln!(output, "Sinks: {}", candidates.join(", "))?;
        write!(output, "Filter or exact sink: ")?;
        output.flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let input = input.trim();
        let exact = candidates.iter().find(|s| **s == input);
        if let Some(name) = exact {
            return Ok((*name).to_owned());
        }
        let matches: Vec<_> = candidates
            .iter()
            .filter(|s| !input.is_empty() && s.contains(input))
            .collect();
        match matches.as_slice() {
            [name] => Ok((***name).to_owned()),
            _ => Err(io::Error::other("sink filter must match one choice")),
        }
    }

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
        io::stdin().is_terminal() && io::stdout().is_terminal() && io::stderr().is_terminal()
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

/// Dependencies shared by commands; M2 checks read the validated immutable head.
pub struct Dependencies<'a> {
    /// Persistent M2 config and safety-state root.
    pub state_root: &'a Path,
    /// Gateway-id, mirror and secrets root; check never opens private keys.
    pub config_root: &'a Path,
    /// Namespace probe child execution.
    pub probe_exec: &'a dyn scupper_sys::probe_child::ProbeExec,
    /// Command execution and clock.
    pub system: &'a dyn System,
    /// Network namespace identities for the canon safety guard.
    pub namespaces: &'a dyn NamespaceReader,
    /// Effective uid check.
    pub privilege: &'a dyn Privilege,
    /// Terminal detection and confirmations.
    pub prompt: &'a dyn Prompt,
    /// Global writer lock directory (`/run/scupper` in production).
    pub writer_root: &'a Path,
}

/// Runs the CLI against the host using only default executable paths.
#[must_use]
pub fn run<I, T>(args: I) -> u8
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let args: Vec<OsString> = args.into_iter().map(Into::into).collect();
    #[cfg(feature = "testing")]
    let run_root = Cli::try_parse_from(args.clone())
        .ok()
        .and_then(|cli| cli.test_root.map(|root| root.join("run/scupper")))
        .unwrap_or_else(|| PathBuf::from("/run/scupper"));
    #[cfg(not(feature = "testing"))]
    let run_root = PathBuf::from("/run/scupper");
    let executable =
        std::env::current_exe().unwrap_or_else(|_| PathBuf::from("/usr/local/bin/scupper"));
    let system = RealSystem::default().with_canon_paths(executable, run_root);
    run_with(
        args,
        &Dependencies {
            state_root: Path::new("/var/lib/scupper"),
            config_root: Path::new("/etc/scupper"),
            probe_exec: &system,
            system: &system,
            namespaces: &ProcNamespaces,
            privilege: &EffectiveUid,
            prompt: &TerminalPrompt,
            writer_root: Path::new("/run/scupper"),
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
    #[cfg(feature = "testing")]
    let test_state = cli.test_root.as_ref().map(|r| r.join("var-lib/scupper"));
    #[cfg(feature = "testing")]
    let test_config = cli.test_root.as_ref().map(|r| r.join("etc/scupper"));
    #[cfg(feature = "testing")]
    let test_run = cli.test_root.as_ref().map(|r| r.join("run/scupper"));
    #[cfg(feature = "testing")]
    let overridden = Dependencies {
        state_root: test_state.as_deref().unwrap_or(deps.state_root),
        config_root: test_config.as_deref().unwrap_or(deps.config_root),
        writer_root: test_run.as_deref().unwrap_or(deps.writer_root),
        system: deps.system,
        probe_exec: deps.probe_exec,
        namespaces: deps.namespaces,
        privilege: deps.privilege,
        prompt: deps.prompt,
    };
    #[cfg(feature = "testing")]
    let deps = &overridden;
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

#[allow(clippy::too_many_lines)] // Keep the hidden boot lifecycle alongside the command dispatch.
fn dispatch(
    command: Command,
    json: bool,
    deps: &Dependencies<'_>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Result<u8, String> {
    if json && matches!(command, Command::Config { .. } | Command::Rules { .. }) {
        return Err("--json is supported only for check and status".into());
    }
    match command {
        Command::Boot {
            #[cfg(feature = "testing")]
            stop_after,
            #[cfg(feature = "testing")]
            stop_after_link_add,
            #[cfg(feature = "testing")]
            trace,
        } => {
            require_root(deps, "boot")?;
            let _lease = match scupper_sys::lock::SupervisorLease::try_acquire(deps.writer_root) {
                Ok(lease) => lease,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    let ping = scupper_sys::daemon::control::call(
                        deps.writer_root,
                        &scupper_sys::daemon::control::request(scupper_proto::Op::Ping {}),
                        std::time::Duration::from_secs(2),
                    );
                    let held = deps.namespaces.open_gateway().ok().flatten();
                    let matching = matches!((ping, held),
                        (Ok(scupper_proto::Response { result: Ok(scupper_proto::OpResult::Ping { netns, .. }), .. }), Some(held))
                        if held.identity() == (netns.device, netns.inode));
                    if !matching {
                        return Err(format!(
                            "{error}; holder is not an initialized, responsive scupperd attached to the named namespace; boot refused; stop scupperd, then rerun"
                        ));
                    }
                    writeln!(stderr, "scupperd owns the namespace; boot skipped successfully; use scupper apply for a verified update").map_err(output_error)?;
                    return Ok(0);
                }
                Err(error) => return Err(format!("supervisor lease unavailable: {error}")),
            };
            #[cfg(feature = "testing")]
            let hook = |point: scupper_sys::boot::BootPoint| {
                use scupper_sys::boot::BootPoint;
                let stop = match &point {
                    BootPoint::After(step) => stop_after == Some(*step as u8),
                    BootPoint::LinkAdded(name) => stop_after_link_add
                        .as_deref()
                        .is_some_and(|wanted| wanted == "any" || wanted == name.as_str()),
                };
                if stop {
                    scupper_sys::boot::testing_checkpoint(
                        &deps.writer_root.join("boot-reached"),
                        &point,
                    )?;
                    rustix::process::kill_process(
                        rustix::process::getpid(),
                        rustix::process::Signal::KILL,
                    )
                    .map_err(|e| e.to_string())?;
                    return Err("injected boot stop".into());
                }
                Ok(())
            };
            #[cfg(feature = "testing")]
            let recorder = scupper_sys::system::testing::RecordingSystem::new(deps.system);
            #[cfg(feature = "testing")]
            let system: &dyn System = &recorder;
            #[cfg(not(feature = "testing"))]
            let system = deps.system;
            let report = scupper_sys::boot::boot(&scupper_sys::boot::BootDeps {
                system,
                namespace: &BootNamespaces(deps.namespaces),
                state_root: deps.state_root,
                config_root: deps.config_root,
                run_root: deps.writer_root,
                #[cfg(feature = "testing")]
                hook: Some(&hook),
                #[cfg(feature = "testing")]
                secret_owner: 0,
            });
            #[cfg(feature = "testing")]
            if let Some(path) = trace {
                std::fs::write(
                    path,
                    serde_json::to_vec_pretty(&recorder.calls()).map_err(|e| e.to_string())?,
                )
                .map_err(|e| e.to_string())?;
            }
            serde_json::to_writer_pretty(&mut *stdout, &report).map_err(|e| e.to_string())?;
            writeln!(stdout).map_err(output_error)?;
            Ok(u8::from(!report.succeeded()))
        }
        Command::Deliver {
            command: DeliverCommand::Heartbeat,
        } => Ok(scupper_sys::heartbeat::child(std::io::stdin().lock())
            .map_or_else(scupper_sys::heartbeat::Failure::exit_code, |()| 0)),
        Command::Deliver {
            command: DeliverCommand::Alert,
        } => Ok(scupper_sys::heartbeat::alert_child(std::io::stdin().lock())
            .map_or_else(scupper_sys::heartbeat::Failure::exit_code, |()| 0)),
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
        Command::Connect { exit } => {
            control::mutation(deps, control::connect(deps, exit)?, json, stdout, stderr)
        }
        Command::Disconnect => {
            control::mutation(deps, scupper_proto::Op::Disconnect {}, json, stdout, stderr)
        }
        Command::Apply { dry_run } => control::mutation(
            deps,
            scupper_proto::Op::Apply {
                version: None,
                dry_run,
            },
            json,
            stdout,
            stderr,
        ),
        Command::Repair { command } => control::repair(deps, command, json, stdout, stderr),
        Command::Status | Command::Check => {
            let status = matches!(command, Command::Status);
            let (supervisor, version) = match control::read(deps, status, json, stdout, stderr)? {
                control::ReadOutcome::Rendered(code) => return Ok(code),
                control::ReadOutcome::Local {
                    supervisor,
                    version,
                } => (supervisor, version),
            };
            let config = match m2_config_at(deps, version) {
                Ok(Some(config)) => config,
                Ok(None) => return Err("not an M2 gateway (no /var/lib/scupper store)".into()),
                Err(error) if status => return status_error(stdout, json, &error),
                Err(error) => return Err(error),
            };
            m2_check(deps, &config, status, json, supervisor, stdout, stderr)
        }
        Command::Alerts { command } => alerts::run(command, deps, json, stdout),
        Command::Config { command } => config::run(command, deps, stdout),
        Command::Rules { diff } => config::rules(deps, diff, stdout),
    }
}

struct AppliedConfig {
    site: scupper_core::config::ValidatedSite,
    gateway: scupper_core::config::GatewayId,
    stamp: scupper_core::render::VersionStamp,
}

fn m2_config(deps: &Dependencies<'_>) -> Result<Option<AppliedConfig>, String> {
    m2_config_at(deps, None)
}
fn m2_config_at(
    deps: &Dependencies<'_>,
    attached: Option<u64>,
) -> Result<Option<AppliedConfig>, String> {
    let store = scupper_sys::store::VersionStore::read_only(deps.state_root, deps.config_root);
    let Some(version) = store.head().map_err(|error| error.to_string())? else {
        for path in [
            deps.state_root.to_path_buf(),
            deps.writer_root.join("boot.json"),
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
    let version = match scupper_sys::state::StateFile::open(deps.state_root, None)
        .and_then(|file| file.read())
    {
        Ok(scupper_sys::state::StateRead::Present(state)) => {
            state.applied_version.unwrap_or(version)
        }
        // The driver inventories containment before reporting missing/corrupt state.
        _ => version,
    };
    let version = attached.unwrap_or(version);
    let (text, meta) = store.read(version).map_err(|error| error.to_string())?;
    let site = config::validate_text(&text)?;
    let gateway = config::gateway_id(deps, &site)?;
    Ok(Some(AppliedConfig {
        site,
        gateway,
        stamp: config::stamp(version, &meta.sha256)?,
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

#[allow(clippy::too_many_lines)] // Keep the single bounded retry beside the final verdict.
fn m2_check(
    deps: &Dependencies<'_>,
    config: &AppliedConfig,
    status: bool,
    json: bool,
    supervisor: scupper_core::verdict::v2::Supervisor,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Result<u8, String> {
    let mut refreshed_config = None;
    let mut supervisor = supervisor;
    loop {
        let config = refreshed_config.as_ref().unwrap_or(config);
        let handle = match deps.namespaces.open_gateway() {
            Ok(handle) => handle,
            Err(error) if status => {
                return status_error(stdout, json, &error);
            }
            Err(error) => return Err(error),
        };
        let check_deps = scupper_sys::check_v2::Dependencies {
            system: deps.system,
            probe_exec: deps.probe_exec,
            handle: handle.as_ref(),
            state_root: deps.state_root,
            run_root: deps.writer_root,
        };
        let check_config = scupper_sys::check_v2::Config {
            site: &config.site,
            gateway: &config.gateway,
            stamp: config.stamp,
        };
        let (result, mut observations) = if status {
            scupper_sys::check_v2::run_with_observations(&check_deps, &check_config)
        } else {
            scupper_sys::check_v2::run_with_supervisor(&check_deps, &check_config, supervisor)
        };
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
        return match result {
            Ok(report) => {
                if report.verdict.exit_code() == 2
                    && matches!(
                        supervisor,
                        scupper_core::verdict::v2::Supervisor::Alive { .. }
                    )
                    && let Some(outcome) = control::transition_after_observation(
                        deps,
                        config.stamp.version,
                        supervisor,
                        json,
                        stdout,
                        stderr,
                    )?
                {
                    match outcome {
                        control::ReadOutcome::Rendered(code) => return Ok(code),
                        control::ReadOutcome::Local {
                            supervisor: fresh,
                            version,
                        } if refreshed_config.is_none() => {
                            refreshed_config = Some(
                                m2_config_at(deps, version)?
                                    .ok_or("not an M2 gateway (no /var/lib/scupper store)")?,
                            );
                            supervisor = fresh;
                            continue;
                        }
                        control::ReadOutcome::Local { .. } => {}
                    }
                }
                if json {
                    serde_json::to_writer(&mut *stdout, &report)
                        .map_err(|error| error.to_string())?;
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
        };
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

struct BootNamespaces<'a>(&'a dyn NamespaceReader);
impl scupper_sys::boot::BootNamespace for BootNamespaces<'_> {
    fn open(
        &self,
    ) -> Result<Option<scupper_sys::netns::NetnsHandle>, scupper_sys::netns::NetnsError> {
        self.0
            .open_gateway()
            .map_err(|error| scupper_sys::netns::NetnsError::Proc(io::Error::other(error)))
    }
}
