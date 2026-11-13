//! Mac/Linux deploy client. All variable remote inputs travel as JSON data.
use clap::Args;
use scupper_core::release;
use scupper_proto::{
    Identifier,
    deploy::{DeployOp, DeployPlan, DeployRequest, ReleaseHash, SwitchOutcome},
};
use std::{
    ffi::OsString,
    fs,
    io::{self, IsTerminal, Write},
    net::IpAddr,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

/// Deploy flags accepted on both operator platforms.
#[derive(Clone, Debug, Args)]
pub struct DeployArgs {
    /// Literal public IP or DNS host name (root login).
    #[arg(long)]
    pub host: String,
    /// Release archive, with SHA256SUMS beside it (default: dist/).
    #[arg(long)]
    pub archive: Option<PathBuf>,
    /// Apply the displayed plan without an interactive prompt.
    #[arg(long)]
    pub yes: bool,
    /// Allow-listed SSH option, e.g. "-i /path/to/key", "-p 22".
    #[arg(long, allow_hyphen_values = true)]
    pub ssh_option: Vec<String>,
}
/// One fixed command for hosts with or without scupper. Bootstrap only stages files.
pub const REMOTE_COMMAND: &str = concat!(
    "if test -x /usr/local/bin/scupper; then if timeout 15 /usr/local/bin/scupper remote --help >/dev/null 2>&1; then exec timeout 420 /usr/local/bin/scupper remote; else echo 'Deployment requires scupper ",
    env!("CARGO_PKG_VERSION"),
    " with M2-2u remote support. Manually copy the matching release archive to the gateway, verify SHA256SUMS and MANIFEST, extract it, then run the extracted scupper install --binaries with that directory.' >&2; exit 1; fi; else exec timeout 120 python3 -c '",
    include_str!("deploy_bootstrap.py"),
    "'; fi"
);
/// External transport invocation captured by fake transports in tests.
#[derive(Debug, Clone)]
pub struct Invocation {
    /// System executable, always ssh or scp.
    pub program: &'static str,
    /// Individual local argv elements, never local shell text.
    pub args: Vec<OsString>,
    /// Bounded JSON request; empty for constant uname and scp.
    pub stdin: Vec<u8>,
    /// Wall-clock budget covering input, output and child completion.
    pub timeout: Duration,
    /// Deployment step used in timeout and failure diagnostics.
    pub step: &'static str,
}
/// Completed transport process, preserving the remote status and both output streams.
#[derive(Debug, Clone)]
pub struct TransportOutput {
    /// Exit status, including reserved switch outcome codes.
    pub code: u8,
    /// Captured standard output.
    pub stdout: String,
    /// Captured standard error.
    pub stderr: String,
}
impl TransportOutput {
    pub(crate) fn success(self) -> Result<String, String> {
        if self.code == 0 {
            Ok(self.stdout)
        } else {
            Err(format!(
                "child exited {}\n{}{}",
                self.code, self.stdout, self.stderr
            ))
        }
    }
}
pub(crate) fn switch_message(outcome: SwitchOutcome, reason: &str) -> String {
    let reason = reason.trim_end();
    match outcome {
        SwitchOutcome::FailedAfterChange | SwitchOutcome::PossiblyChanged => {
            if reason.starts_with("Switch changed:")
                || reason.starts_with("Switch possibly changed:")
            {
                reason.into()
            } else {
                format!(
                    "Switch {}: {reason}",
                    if outcome == SwitchOutcome::PossiblyChanged {
                        "possibly changed"
                    } else {
                        "changed"
                    }
                )
            }
        }
        SwitchOutcome::RefusedNoChange
            if reason.starts_with("Switch refused, nothing changed: ") =>
        {
            reason.into()
        }
        SwitchOutcome::RefusedNoChange => format!("Switch refused, nothing changed: {reason}"),
        // The gateway already renders its diagnostic. Reuse it once, while still
        // generating recovery locally when a typed status arrives without text.
        SwitchOutcome::FailedAfterRename | SwitchOutcome::Unknown
            if reason.contains(scupper_core::install::RESTORE_COMMANDS) =>
        {
            reason.into()
        }
        SwitchOutcome::FailedAfterRename | SwitchOutcome::Unknown => format!(
            "Switch {}: {reason}. Gateway binaries may be mixed or services stopped. Restore manually:\n{}",
            if outcome == SwitchOutcome::Unknown {
                "outcome unknown (possibly changed; files in the confirmed plan)"
            } else {
                "failed after binary rename"
            },
            scupper_core::install::RESTORE_COMMANDS
        ),
    }
}
/// SSH/SCP execution boundary.
pub trait Transport {
    /// Execute a command, preserving its status and output streams.
    /// # Errors
    /// Returns transport failure, including timeouts and lost connections.
    fn execute(&self, invocation: Invocation) -> Result<TransportOutput, String>;
}
/// Production system SSH/SCP adapter.
pub struct Ssh;
impl Transport for Ssh {
    fn execute(&self, call: Invocation) -> Result<TransportOutput, String> {
        let mut command = Command::new(call.program);
        command.args(call.args);
        crate::deploy_process::execute(command, &call.stdin, call.timeout)
            .map_err(|e| format!("{} step failed: {e}. {}", call.step, step_state(call.step)))
    }
}
/// Interactive confirmation boundary shared by operator platforms.
pub trait Confirmation {
    /// All interaction streams are terminals.
    fn terminal(&self) -> bool;
    /// Ask after displaying the installation plan.
    /// # Errors
    /// Returns input/output errors.
    fn confirm(&self) -> Result<bool, String>;
}
/// Terminal interaction implementation.
pub struct Terminal;
impl Confirmation for Terminal {
    fn terminal(&self) -> bool {
        io::stdin().is_terminal() && io::stdout().is_terminal() && io::stderr().is_terminal()
    }
    fn confirm(&self) -> Result<bool, String> {
        eprint!("Apply this deployment? [y/N] ");
        io::stderr().flush().map_err(|e| e.to_string())?;
        let mut line = String::new();
        io::stdin()
            .read_line(&mut line)
            .map_err(|e| e.to_string())?;
        Ok(matches!(
            line.trim().to_ascii_lowercase().as_str(),
            "y" | "yes"
        ))
    }
}
/// Validates the entire destination before adding a fixed root login.
/// # Errors
/// Rejects option-like values, user names, shell syntax and malformed hosts.
pub fn host(value: &str) -> Result<String, String> {
    let valid = value.parse::<IpAddr>().is_ok()
        || (!value.is_empty()
            && value.len() <= 253
            && value.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && label.as_bytes()[0].is_ascii_alphanumeric()
                    && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            })
            && !value.bytes().all(|b| b.is_ascii_digit() || b == b'.'));
    if valid {
        Ok(format!("root@{value}"))
    } else {
        Err("invalid SSH host".into())
    }
}
/// Select only Linux musl gateway architectures.
/// # Errors
/// Refuses every other uname value.
pub fn target(uname: &str) -> Result<&'static str, String> {
    match uname.trim() {
        "x86_64" => Ok("x86_64-unknown-linux-musl"),
        "aarch64" => Ok("aarch64-unknown-linux-musl"),
        _ => Err("unsupported gateway architecture".into()),
    }
}
fn step_state(step: &str) -> &'static str {
    match step {
        "Switch" => "Gateway binaries may be mixed or services stopped; switch outcome is unknown.",
        "Check" => "Switch completed; gateway health is unconfirmed.",
        _ => "Live binaries were not switched by this deployment; staging may be incomplete.",
    }
}
fn budget(step: &str) -> Duration {
    Duration::from_secs(match step {
        "Switch" => 480, // Two bounded 120s unit starts, preparation and re-exec.
        "Plan" | "Stage" | "Check" => 180,
        _ => 60,
    })
}
fn copy_budget(bytes: u64) -> Duration {
    // Allow 128 KiB/s plus connection/setup time, rounded upward.
    Duration::from_secs(60 + bytes.div_ceil(128 * 1024))
}
fn options(values: &[String], scp: bool) -> Result<Vec<OsString>, String> {
    let mut args: Vec<OsString> = [
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=15",
        "-o",
        "ServerAliveInterval=15",
        "-o",
        "ServerAliveCountMax=4",
        "-o",
        "ControlMaster=no",
        "-o",
        "ControlPath=none",
    ]
    .into_iter()
    .map(Into::into)
    .collect();
    for value in values {
        let (flag, data) = value
            .split_once(' ')
            .ok_or("SSH option must contain a flag and value")?;
        match flag {
            "-i" if data.starts_with('/')
                && data
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"/._-".contains(&b)) =>
            {
                args.push(flag.into());
                args.push(data.into());
            }
            "-p" if data.parse::<u16>().is_ok_and(|p| p > 0) => {
                args.push(if scp { "-P" } else { "-p" }.into());
                args.push(data.into());
            }
            "-o" if data == "StrictHostKeyChecking=yes" => {
                args.push(flag.into());
                args.push(data.into());
            }
            _ => return Err("SSH option is not allowed".into()),
        }
    }
    Ok(args)
}
struct Client<'a> {
    transport: &'a dyn Transport,
    destination: String,
    options: &'a [String],
}
impl Client<'_> {
    fn ssh(
        &self,
        command: &'static str,
        stdin: Vec<u8>,
        step: &'static str,
    ) -> Result<String, String> {
        self.invoke(command, stdin, step)?.success()
    }
    fn invoke(
        &self,
        command: &'static str,
        stdin: Vec<u8>,
        step: &'static str,
    ) -> Result<TransportOutput, String> {
        let mut args = options(self.options, false)?;
        args.extend(["--".into(), self.destination.clone().into(), command.into()]);
        self.transport.execute(Invocation {
            program: "ssh",
            args,
            stdin,
            timeout: budget(step),
            step,
        })
    }
    fn remote(&self, operation: DeployOp, request_id: &Identifier) -> Result<String, String> {
        let step = match operation {
            DeployOp::Prepare { .. } => "Prepare",
            DeployOp::Stage { .. } => "Stage",
            DeployOp::Plan { .. } => "Plan",
            DeployOp::Switch { .. } => "Switch",
            DeployOp::Check { .. } => "Check",
        };
        self.request(operation, request_id, step)?
            .success()
            .map_err(|e| format!("{step} step: {e}. {}", step_state(step)))
    }
    fn request(
        &self,
        operation: DeployOp,
        request_id: &Identifier,
        step: &'static str,
    ) -> Result<TransportOutput, String> {
        self.invoke(
            REMOTE_COMMAND,
            serde_json::to_vec(&DeployRequest {
                request_id: request_id.clone(),
                operation,
            })
            .map_err(|e| e.to_string())?,
            step,
        )
        .map_err(|e| format!("{step} step: {e}. {}", step_state(step)))
    }
    fn copy(&self, path: &Path, id: &str) -> Result<(), String> {
        let mut args = options(self.options, true)?;
        let dest = if let Some(ip) = self
            .destination
            .strip_prefix("root@")
            .filter(|s| s.contains(':'))
        {
            format!("root@[{ip}]")
        } else {
            self.destination.clone()
        };
        // Absolute local source prevents scp interpreting colon-bearing names as hosts.
        args.extend([
            "--".into(),
            path.as_os_str().into(),
            format!("{dest}:/usr/local/lib/scupper/deploy/{id}/new/archive.tar.gz").into(),
        ]);
        self.transport
            .execute(Invocation {
                program: "scp",
                args,
                stdin: Vec::new(),
                timeout: copy_budget(fs::metadata(path).map_err(|e| e.to_string())?.len()),
                step: "Copy",
            })
            .and_then(TransportOutput::success)
            .map_err(|e| format!("Copy step: {e}. {}", step_state("Copy")))?;
        Ok(())
    }
}
fn verified_archive(path: &Path, triple: &str) -> Result<(PathBuf, String), String> {
    let path = path.canonicalize().map_err(|e| e.to_string())?;
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or("invalid archive filename")?;
    if !name.ends_with(".tar.gz")
        || !name.as_bytes()[0].is_ascii_alphanumeric()
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
    {
        return Err("invalid archive filename".into());
    }
    let metadata = fs::metadata(&path).map_err(|e| e.to_string())?;
    if !metadata.is_file() || metadata.len() > (release::MAX_RELEASE + 65536) as u64 {
        return Err("archive exceeds size limit".into());
    }
    let bytes = fs::read(&path).map_err(|e| e.to_string())?;
    let digest = release::hash(&bytes);
    let sums = fs::read_to_string(path.with_file_name("SHA256SUMS")).map_err(|e| e.to_string())?;
    if sums
        .lines()
        .filter(|l| l.ends_with(&format!("  {name}")))
        .collect::<Vec<_>>()
        != vec![format!("{digest}  {name}").as_str()]
    {
        return Err("release SHA256SUMS mismatch".into());
    }
    let members = release::decode(&bytes, true).map_err(|e| e.to_string())?;
    for name in ["scupper", "scupperd"] {
        let binary = &members[name];
        let machine: &[u8] = if triple == "x86_64-unknown-linux-musl" {
            &[62, 0]
        } else {
            &[183, 0]
        };
        if binary.get(..6) != Some(b"\x7fELF\x02\x01")
            || !matches!(binary.get(16..18), Some([2 | 3, 0]))
            || binary.get(18..20) != Some(machine)
        {
            return Err("archive binaries do not match gateway architecture".into());
        }
    }
    Ok((path, digest))
}

/// Performs M2 deploy steps, leaving a fresh host staged for a local install.
/// # Errors
/// Refuses invalid destinations, checksums, architecture, confirmation or remote failures.
pub fn run(
    args: &DeployArgs,
    transport: &dyn Transport,
    prompt: &dyn Confirmation,
    out: &mut dyn Write,
) -> Result<u8, String> {
    let client = Client {
        transport,
        destination: host(&args.host)?,
        options: &args.ssh_option,
    };
    options(&args.ssh_option, false)?;
    if !args.yes && !prompt.terminal() {
        return Err("deploy requires --yes without a TTY".into());
    }
    let triple = target(&client.ssh("timeout 15 uname -m", Vec::new(), "Architecture")?)?;
    let name = format!("scupper-{}-{triple}.tar.gz", env!("CARGO_PKG_VERSION"));
    let path = args
        .archive
        .clone()
        .unwrap_or_else(|| PathBuf::from("dist").join(&name));
    let (path, digest) = verified_archive(&path, triple)?;
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_nanos();
    let id = Identifier::try_from(format!("d{stamp:x}"))?;
    let id_text = String::from(id.clone());
    let installed = match client
        .remote(DeployOp::Prepare { id: id.clone() }, &id)?
        .trim()
    {
        "installed" => true,
        "fresh" => false,
        _ => return Err("invalid remote preparation response".into()),
    };
    client.copy(&path, &id_text)?;
    let staged = client.remote(
        DeployOp::Stage {
            id: id.clone(),
            sha256: ReleaseHash::try_from(digest)?,
        },
        &id,
    )?;
    write!(out, "{staged}").map_err(|e| e.to_string())?;
    if !installed {
        writeln!(out, "Archive verified. Run on the gateway next:\n/usr/local/lib/scupper/deploy/{id_text}/new/scupper install --binaries /usr/local/lib/scupper/deploy/{id_text}/new\nSupply initial install flags or --bundle using files already on the gateway.").map_err(|e| e.to_string())?;
        return Ok(0);
    }
    let plan: DeployPlan =
        serde_json::from_str(&client.remote(DeployOp::Plan { id: id.clone() }, &id)?)
            .map_err(|_| "invalid remote plan response")?;
    write!(out, "{}", plan.plan)
        .and_then(|()| out.flush())
        .map_err(|e| e.to_string())?;
    if !args.yes && !prompt.confirm()? {
        return Err("deploy cancelled".into());
    }
    let switched = client.request(
        DeployOp::Switch {
            id: id.clone(),
            plan_sha256: plan.plan_sha256,
        },
        &id,
        "Switch",
    );
    let switched = match switched {
        Ok(result) if result.code == 0 => result.stdout,
        result => {
            let message = match result {
                Ok(result) => {
                    let outcome = SwitchOutcome::from_exit_code(result.code);
                    let reason = format!("{}{}", result.stdout, result.stderr);
                    switch_message(outcome, &reason)
                }
                Err(error) => switch_message(SwitchOutcome::Unknown, &error),
            };
            let message = format!("Deploy {id_text}: Switch step: {message}");
            let _ = writeln!(out, "{message}");
            return Err(message);
        }
    };
    write!(out, "{switched}").map_err(|e| e.to_string())?;
    write!(
        out,
        "{}",
        client.remote(DeployOp::Check { id: id.clone() }, &id)?
    )
    .map_err(|e| e.to_string())?;
    Ok(0)
}
