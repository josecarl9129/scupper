//! Flag-only M2 install with one confirmation after complete preflight.
use super::{Command, Dependencies, confirm, dispatch, output_error, require_root};
use clap::Args;
use scupper_sys::install::{self, Options, Paths};
use std::{
    io::Write,
    path::{Path, PathBuf},
};

#[derive(Clone, Args)]
pub(super) struct InstallArgs {
    /// Show the stable plan without changes.
    #[arg(long, conflicts_with = "check")]
    plan: bool,
    /// Exit nonzero on drift, without changes.
    #[arg(long)]
    check: bool,
    /// Directory containing scupper and scupperd (default: running executable's directory).
    #[arg(long)]
    binaries: Option<PathBuf>,
    /// Restore a verified configuration bundle.
    #[arg(long, conflicts_with_all = ["uplink", "endpoint", "exit_file", "exit_id"])]
    bundle: Option<PathBuf>,
    #[arg(long)]
    gateway_id: Option<String>,
    #[arg(long)]
    uplink: Option<String>,
    /// Public endpoint as a literal IPv4 address (required for multiple uplink addresses).
    #[arg(long)]
    endpoint: Option<String>,
    #[arg(long, requires = "exit_id")]
    exit_file: Option<PathBuf>,
    #[arg(long, requires = "exit_file")]
    exit_id: Option<String>,
    /// Confirm the fully verified plan without prompting.
    #[arg(long)]
    yes: bool,
}
pub(super) fn run(
    args: InstallArgs,
    deps: &Dependencies<'_>,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<u8, String> {
    require_root(deps, "install")?;
    let binaries = match args.binaries {
        Some(path) => path,
        None => std::env::current_exe()
            .map_err(|_| "cannot locate running executable")?
            .parent()
            .ok_or("cannot locate binary directory")?
            .to_path_buf(),
    };
    let options = Options {
        binaries,
        bundle: args.bundle,
        gateway_id: args.gateway_id,
        uplink: args.uplink,
        endpoint: args.endpoint,
        exit_file: args.exit_file,
        exit_id: args.exit_id,
    };
    let root = deps
        .config_root
        .parent()
        .and_then(Path::parent)
        .ok_or("invalid configuration root")?;
    let paths = Paths::new(root);
    let prepared = install::prepare(deps.system, &paths, &options).map_err(|e| {
        if let scupper_core::install::Refusal::Packages(line) = &e {
            let _ = writeln!(out, "{line}");
        }
        e.to_string()
    })?;
    write!(out, "{}", prepared.plan.text()).map_err(output_error)?;
    out.flush().map_err(output_error)?;
    if args.plan {
        return Ok(0);
    }
    if args.check {
        return Ok(u8::from(!prepared.plan.steps.is_empty()));
    }
    if !prepared.plan.steps.is_empty() {
        confirm(
            deps,
            "install",
            args.yes,
            "Apply this installation plan? [y/N]",
            None,
        )?;
    }
    let peer = install::apply(deps.system, &paths, prepared)?;
    writeln!(out, "scupper check:").map_err(output_error)?;
    let check = match dispatch(Command::Check, false, deps, out, err) {
        Ok(code) => code,
        Err(error) => {
            writeln!(out, "check failed: {error}").map_err(output_error)?;
            1
        }
    };
    writeln!(
        out,
        "Mac scupper0.conf:\n{peer}Delete the downloaded provider file: it contains a private key."
    )
    .map_err(output_error)?;
    Ok(check)
}
