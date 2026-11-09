//! Namespace ruleset equality using kernel canonicalization in a private netns.

use std::{
    collections::hash_map::RandomState,
    fs::{self, DirBuilder, OpenOptions},
    hash::BuildHasher,
    io::{self, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
    time::Duration,
};

use serde_json::Value;

use crate::{
    system::{EXEC_TIMEOUT, ExecError, ExecOutput, Program, Stream, System},
    verdict::{Probe, ProbeError},
};

pub use scupper_core::canon::{
    CANON_TIMEOUT, OVERSIZED_LIVE_RULESET, WANT_NOT_COMPUTED_LIVE_OVERFLOW, canonicalize,
    fingerprint,
};
use scupper_core::canon::{compare_rulesets, oversized_live_ruleset};

fn permission_failure(message: &str) -> bool {
    let message = message.to_ascii_lowercase();
    [
        "permission denied",
        "operation not permitted",
        "must be root",
        "you must be root",
    ]
    .iter()
    .any(|needle| message.contains(needle))
}

pub(crate) fn command(
    sys: &dyn System,
    program: Program,
    args: &[String],
    timeout: Duration,
) -> Probe<String> {
    command_result(sys.run(program, args, timeout))
}

pub(crate) fn command_result(result: Result<ExecOutput, ExecError>) -> Probe<String> {
    let output = result.map_err(|error| match error {
        ExecError::Timeout { .. } => ProbeError::Timeout,
        other if permission_failure(&other.to_string()) => ProbeError::setup(&other.to_string()),
        other => ProbeError::io(&other.to_string()),
    })?;
    if output.status == Some(0) {
        Ok(output.stdout)
    } else if permission_failure(&output.stderr) {
        Err(ProbeError::setup(&output.stderr))
    } else {
        Err(ProbeError::exit_status(output.status, &output.stderr))
    }
}

pub(crate) fn combined_error(first: ProbeError, others: &[ProbeError]) -> ProbeError {
    if others.is_empty() {
        return first;
    }
    // Reserve space for later diagnostics instead of letting a long first error
    // consume the entire bound. Any permission failure keeps Setup classification.
    let mut message: String = first.to_string().chars().take(90).collect();
    for error in others {
        message.push_str("; also: ");
        message.extend(error.to_string().chars().take(60));
    }
    if std::iter::once(&first)
        .chain(others)
        .any(|error| matches!(error, ProbeError::Setup(_)))
    {
        return ProbeError::setup(&message);
    }
    match first {
        ProbeError::ExitStatus { code, .. } => ProbeError::exit_status(code, &message),
        _ => ProbeError::io(&message),
    }
}

fn file_error(error: &io::Error) -> ProbeError {
    if error.kind() == io::ErrorKind::PermissionDenied {
        ProbeError::setup(&error.to_string())
    } else {
        ProbeError::io(&error.to_string())
    }
}

struct PrivateRuleset(PathBuf);

impl PrivateRuleset {
    fn create(rendered: &str) -> Probe<Self> {
        // RandomState uses randomized hashing keys. Two hashes make the name
        // unpredictable without extra dependencies.
        let name = format!(
            "scupper-canon-{:016x}{:016x}",
            RandomState::new().hash_one(std::process::id()),
            RandomState::new().hash_one(std::process::id()),
        );
        let temp_dir = std::env::temp_dir();
        if !temp_dir.is_absolute() {
            return Err(ProbeError::setup(
                "canonicalization temp directory must be absolute",
            ));
        }
        let directory = temp_dir.join(name);
        // A killed check can leave a scupper-canon-* directory behind (0700,
        // no secrets). Normal completion removes it through the guard below.
        // create (not create_dir_all) is exclusive: collisions fail, never reuse.
        DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .map_err(|error| file_error(&error))?;
        let guard = Self(directory);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(guard.path())
            .map_err(|error| file_error(&error))?;
        file.write_all(rendered.as_bytes())
            .map_err(|error| file_error(&error))?;
        Ok(guard)
    }

    fn path(&self) -> PathBuf {
        self.0.join("ruleset.nft")
    }
}

impl Drop for PrivateRuleset {
    fn drop(&mut self) {
        let _ = fs::remove_file(self.path());
        let _ = fs::remove_dir(&self.0);
    }
}

fn path_arg(path: &Path) -> Probe<String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| ProbeError::setup("canonicalization path is not UTF-8"))
}

fn unshare_argv(executable: &Path, outer_netns: &Path, file: &Path) -> Probe<Vec<String>> {
    Ok(vec![
        "--net".into(),
        "--".into(),
        path_arg(executable)?,
        "canon".into(),
        "--outer-netns".into(),
        path_arg(outer_netns)?,
        path_arg(file)?,
    ])
}

fn isolated_ruleset(
    sys: &dyn System,
    path: &Path,
    outer_netns: &Path,
    gateway_netns: Option<&Path>,
    read_namespace: impl Fn(&Path) -> io::Result<PathBuf>,
) -> Probe<String> {
    let valid_identity = |path: &Path| {
        path.to_str()
            .and_then(|value| value.strip_prefix("net:["))
            .and_then(|value| value.strip_suffix(']'))
            .is_some_and(|digits| {
                !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit())
            })
    };
    if !valid_identity(outer_netns) || gateway_netns.is_some_and(|gateway| !valid_identity(gateway))
    {
        return Err(ProbeError::setup(
            "outer network namespace must be net:[<decimal digits>]; gateway identity must use the same format",
        ));
    }
    // M2 requires proof against both the parent and PID 1, as well as the held
    // gateway. The parent's namespace can itself be a lab host namespace.
    let current = read_namespace(Path::new("/proc/self/ns/net"))
        .map_err(|error| ProbeError::setup(&format!("read current network namespace: {error}")))?;
    let host = read_namespace(Path::new("/proc/1/ns/net"));
    if gateway_netns.is_some() && host.is_err() {
        return Err(ProbeError::setup("cannot verify host network namespace"));
    }
    if gateway_netns.is_some_and(|gateway| current == gateway)
        || current == outer_netns
        || host.is_ok_and(|host| current == host)
    {
        return Err(ProbeError::setup(
            "canon refused to load rules in the outer, gateway or host network namespace",
        ));
    }
    let before = command(
        sys,
        Program::Nft,
        &["-j".into(), "list".into(), "ruleset".into()],
        EXEC_TIMEOUT,
    )?;
    let before: Value = serde_json::from_str(&before)
        .map_err(|_| ProbeError::setup("canon cannot verify an empty ruleset"))?;
    if !before
        .get("nftables")
        .and_then(Value::as_array)
        .is_some_and(|entries| {
            entries.iter().all(|entry| {
                entry.as_object().is_some_and(|fields| {
                    fields.len() == 1 && fields.get("metainfo").is_some_and(Value::is_object)
                })
            })
        })
    {
        return Err(ProbeError::setup(
            "canon refused to load rules over a non-empty ruleset",
        ));
    }
    command(
        sys,
        Program::Nft,
        &["-f".into(), path_arg(path)?],
        EXEC_TIMEOUT,
    )?;
    command(
        sys,
        Program::Nft,
        &["-j".into(), "list".into(), "ruleset".into()],
        EXEC_TIMEOUT,
    )
}

/// Runs the hidden `canon` command with an injectable namespace reader.
/// Returns 1 with stderr on any failure, including namespace reads or equality;
/// no nft command can run until self differs from outer and any readable PID 1.
/// The production child uses the default program paths.
pub fn run_isolated(
    sys: &dyn System,
    path: &Path,
    outer_netns: &Path,
    read_namespace: impl Fn(&Path) -> io::Result<PathBuf>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> u8 {
    match isolated_ruleset(sys, path, outer_netns, None, read_namespace) {
        Ok(json) => match stdout.write_all(json.as_bytes()) {
            Ok(()) => 0,
            Err(error) => {
                let _ = writeln!(stderr, "canon: write output: {error}");
                1
            }
        },
        Err(error) => {
            let _ = writeln!(stderr, "canon: {error}");
            1
        }
    }
}

/// Canon child for M2: also refuses the held gateway namespace before any nft call.
///
/// # Errors
/// Returns an observation error before loading rules on failed namespace guards.
pub fn isolated_netns_ruleset(
    sys: &dyn System,
    path: &Path,
    outer_netns: &Path,
    gateway_netns: &Path,
    read_namespace: impl Fn(&Path) -> io::Result<PathBuf>,
) -> Probe<String> {
    isolated_ruleset(sys, path, outer_netns, Some(gateway_netns), read_namespace)
}

/// Compares the entire held gateway namespace with a kernel-canonicalized render.
/// Any semantic difference is confirmed with a second fresh comparison.
///
/// # Errors
/// Returns command, namespace, temporary-file and JSON observation errors.
pub fn observe_netns_ruleset(
    sys: &dyn System,
    handle: &crate::netns::NetnsHandle,
    rendered: &str,
) -> Probe<scupper_core::verdict::v2::RulesetObs> {
    let once = || {
        let live = crate::cmd::run_cmd(
            sys,
            crate::system::ExecTarget::Netns(handle),
            &crate::cmd::KernelCmd::Nft(crate::cmd::NftCmd::ListRulesetJson),
            EXEC_TIMEOUT,
        );
        if live
            == Err(ExecError::OutputTooLarge {
                stream: Stream::Stdout,
            })
        {
            return Ok((oversized_live_ruleset(), false));
        }
        let (want, live) = canonical_pair(sys, handle, rendered, live)?;
        compare_rulesets(&want, &live)
    };
    let (observation, confirm) = once()?;
    Ok(if confirm { once()?.0 } else { observation }.into())
}

/// Reads canonical rendered and live rulesets for a held namespace.
/// Shares the exact comparison's isolated loader and metadata stripping.
///
/// # Errors
/// Returns namespace, command, output-limit, JSON or temporary-file errors.
pub fn netns_rulesets(
    sys: &dyn System,
    handle: &crate::netns::NetnsHandle,
    rendered: &str,
) -> Probe<(Value, Value)> {
    let live = crate::cmd::run_cmd(
        sys,
        crate::system::ExecTarget::Netns(handle),
        &crate::cmd::KernelCmd::Nft(crate::cmd::NftCmd::ListRulesetJson),
        EXEC_TIMEOUT,
    );
    let (want, live) = canonical_pair(sys, handle, rendered, live)?;
    if compare_rulesets(&want, &live)?.1 {
        let live = crate::cmd::run_cmd(
            sys,
            crate::system::ExecTarget::Netns(handle),
            &crate::cmd::KernelCmd::Nft(crate::cmd::NftCmd::ListRulesetJson),
            EXEC_TIMEOUT,
        );
        canonical_pair(sys, handle, rendered, live)
    } else {
        Ok((want, live))
    }
}

fn canonical_pair(
    sys: &dyn System,
    handle: &crate::netns::NetnsHandle,
    rendered: &str,
    live: Result<ExecOutput, ExecError>,
) -> Probe<(Value, Value)> {
    let executable = fs::read_link("/proc/self/exe").map_err(|error| file_error(&error))?;
    let outer = fs::read_link("/proc/self/ns/net").map_err(|error| file_error(&error))?;
    let file = PrivateRuleset::create(rendered)?;
    let mut args = unshare_argv(&executable, &outer, &file.path())?;
    args.splice(
        6..6,
        [
            "--gateway-netns".into(),
            format!("net:[{}]", handle.identity().1),
        ],
    );
    let want = command(sys, Program::Unshare, &args, CANON_TIMEOUT)
        .and_then(|text| Ok(canonicalize(&text)?));
    let live = command_result(live).and_then(|text| Ok(canonicalize(&text)?));
    match (want, live) {
        (Ok(want), Ok(live)) => Ok((want, live)),
        (Err(first), Err(second)) => Err(combined_error(first, &[second])),
        (Err(error), _) | (_, Err(error)) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalization_argv_shape() -> Probe<()> {
        assert_eq!(
            unshare_argv(
                Path::new("/usr/local/bin/scupper"),
                Path::new("net:[123]"),
                Path::new("/private/ruleset.nft")
            )?,
            [
                "--net",
                "--",
                "/usr/local/bin/scupper",
                "canon",
                "--outer-netns",
                "net:[123]",
                "/private/ruleset.nft"
            ]
        );
        Ok(())
    }
}
