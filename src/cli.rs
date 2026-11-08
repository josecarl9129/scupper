//! The v1 command line with injectable operating-system and interaction boundaries.

use std::{
    ffi::OsString,
    io::{self, IsTerminal, Write},
    net::IpAddr,
    path::Path,
    time::{Duration, Instant},
};

use clap::{Parser, Subcommand, error::ErrorKind};

use crate::{
    apply::{self, Fs, RULESET_PATH, RealFs},
    check::{self, ExitProbe, TopologySource},
    parse::HandshakeAge,
    probe::BoundHttpsProbe,
    rules::{self, V1Config},
    system::{ExecError, ExecOutput, Program, RealSystem, SYSTEMCTL_TIMEOUT, System},
    verdict::{self, HealthConfig, M1Topology, Probe, ProbeError, Warning},
};

#[derive(Parser)]
#[command(name = "scupper", version, about = "Fail-closed VPN gateway")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Copy, Subcommand)]
enum Command {
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

/// Placeholder containment source, replaced by the next milestone step.
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

/// Dependencies shared by all commands; configuration remains the fixed v1 default.
pub struct Dependencies<'a> {
    /// Command execution and clock.
    pub system: &'a dyn System,
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
            system: &RealSystem::default(),
            fs: &RealFs,
            privilege: &EffectiveUid,
            prompt: &TerminalPrompt,
            sleeper: &ThreadSleeper,
            topology: &UnimplementedTopology,
            exit_probe: &BoundHttpsProbe::from(&V1Config::default()),
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
    match dispatch(cli.command, deps, stdout, stderr) {
        Ok(code) => code,
        Err(error) => {
            let _ = writeln!(stderr, "scupper: {error}");
            1
        }
    }
}

fn dispatch(
    command: Command,
    deps: &Dependencies<'_>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Result<u8, String> {
    let cfg = V1Config::default();
    match command {
        Command::Status => {
            // Status is informational, including when observations fail.
            let _ = writeln!(
                stdout,
                "{}",
                check::run_status(deps.system, deps.topology, &cfg)
            );
            Ok(0)
        }
        Command::Check => {
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
        Command::Disconnect { yes } => {
            require_root(deps, "disconnect")?;
            confirm(
                deps,
                "disconnect",
                yes,
                "Block all client traffic now? [y/N]",
                None,
            )?;
            systemctl(deps.system, "stop", &cfg)?;
            if let Ok(topology) = deps.topology.observe(deps.system, &cfg) {
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
