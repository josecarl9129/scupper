//! Whole-host ruleset equality using kernel canonicalization in a private netns.
//!
//! M1 uses no cache. Caching is an optional optimization of DESIGN §5.1; even
//! without it, a difference is confirmed by a fresh canonicalization/live read.

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
use sha2::{Digest, Sha256};

use crate::{
    parse::ParseError,
    rules::{self, V1Config},
    system::{EXEC_TIMEOUT, ExecError, ExecOutput, Program, Stream, System},
    verdict::{Probe, ProbeError, RulesetObs},
};

/// Deadline for the namespace creation, ruleset load and JSON dump together.
pub const CANON_TIMEOUT: Duration = Duration::from_secs(8);

/// Diagnostic hash input for live rulesets exceeding the exec output cap.
/// Such output cannot be the roughly 3 KB policy; no repeat is needed.
pub const OVERSIZED_LIVE_RULESET: &[u8] = b"live ruleset exceeded output cap";

/// Diagnostic hash input when live stdout overflow makes canonicalization unnecessary.
pub const WANT_NOT_COMPUTED_LIVE_OVERFLOW: &[u8] =
    b"want side not computed: live ruleset exceeded output cap";

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

fn command_result(result: Result<ExecOutput, ExecError>) -> Probe<String> {
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

fn want(sys: &dyn System, cfg: &V1Config) -> Probe<String> {
    let rendered = rules::ruleset(cfg).map_err(|error| ProbeError::setup(&error.to_string()))?;
    // Resolve in the parent: /proc/self/exe in the child would name unshare.
    let executable = fs::read_link("/proc/self/exe").map_err(|error| file_error(&error))?;
    let outer_netns = fs::read_link("/proc/self/ns/net").map_err(|error| file_error(&error))?;
    let file = PrivateRuleset::create(&rendered)?;
    // The canon child uses default program paths, not the parent's overrides.
    command(
        sys,
        Program::Unshare,
        &unshare_argv(&executable, &outer_netns, &file.path())?,
        CANON_TIMEOUT,
    )
}

fn isolated_ruleset(
    sys: &dyn System,
    path: &Path,
    outer_netns: &Path,
    read_namespace: impl Fn(&Path) -> io::Result<PathBuf>,
) -> Probe<String> {
    let valid_outer = outer_netns
        .to_str()
        .and_then(|value| value.strip_prefix("net:["))
        .and_then(|value| value.strip_suffix(']'))
        .is_some_and(|digits| {
            !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit())
        });
    if !valid_outer {
        return Err(ProbeError::setup(
            "outer network namespace must be net:[<decimal digits>]",
        ));
    }
    // Any read failure or equality aborts before nft.
    let current = read_namespace(Path::new("/proc/self/ns/net"))
        .map_err(|error| ProbeError::setup(&format!("read current network namespace: {error}")))?;
    if current == outer_netns
        || read_namespace(Path::new("/proc/1/ns/net")).is_ok_and(|host| current == host)
    {
        return Err(ProbeError::setup(
            "canon refused to load rules in the outer or host network namespace",
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
    match isolated_ruleset(sys, path, outer_netns, read_namespace) {
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

/// Removes only nft runtime metadata, retaining every other field and array order.
///
/// # Errors
/// Returns a parse error for malformed JSON or an invalid nftables envelope.
pub fn canonicalize(json: &str) -> Result<Value, ParseError> {
    let mut value: Value =
        serde_json::from_str(json).map_err(|_| ParseError::Topology("malformed nft JSON"))?;
    let entries = value
        .get_mut("nftables")
        .and_then(Value::as_array_mut)
        .ok_or(ParseError::Topology("expected an nftables array"))?;
    if entries.iter().any(|entry| !entry.is_object()) {
        return Err(ParseError::Topology("expected nftables object entries"));
    }
    entries.retain(|entry| !entry.get("metainfo").is_some_and(Value::is_object));
    strip_metadata(&mut value);
    Ok(value)
}

fn strip_metadata(value: &mut Value) {
    match value {
        Value::Object(fields) => {
            fields.remove("handle");
            if let Some(Value::Object(counter)) = fields.get_mut("counter") {
                counter.remove("packets");
                counter.remove("bytes");
            }
            for child in fields.values_mut() {
                strip_metadata(child);
            }
        }
        Value::Array(values) => {
            for child in values {
                strip_metadata(child);
            }
        }
        _ => {}
    }
}

/// Hashes a canonical JSON value for a ruleset diagnostic.
///
/// # Errors
/// Returns a parse error if the canonical value cannot be serialized.
pub fn fingerprint(value: &Value) -> Result<[u8; 32], ParseError> {
    // serde_json's default map is ordered (no preserve_order feature), making
    // to_vec deterministic even when input object keys were in another order.
    let bytes = serde_json::to_vec(value)
        .map_err(|_| ParseError::Topology("cannot serialize canonical nft JSON"))?;
    Ok(Sha256::digest(bytes).into())
}

// The boolean requests confirmation of an ordinary ruleset difference.
fn compare_once(sys: &dyn System, cfg: &V1Config) -> Probe<(RulesetObs, bool)> {
    let live = sys.run(
        Program::Nft,
        &["-j".into(), "list".into(), "ruleset".into()],
        EXEC_TIMEOUT,
    );
    if live
        == Err(ExecError::OutputTooLarge {
            stream: Stream::Stdout,
        })
    {
        return Ok((
            RulesetObs::Differs {
                live_sha256: Sha256::digest(OVERSIZED_LIVE_RULESET).into(),
                want_sha256: Sha256::digest(WANT_NOT_COMPUTED_LIVE_OVERFLOW).into(),
            },
            false,
        ));
    }
    // Otherwise collect both sides even if one fails, preserving both diagnostics.
    let want = want(sys, cfg).and_then(|json| Ok(canonicalize(&json)?));
    let live = command_result(live).and_then(|json| Ok(canonicalize(&json)?));
    let (want, live) = match (want, live) {
        (Ok(want), Ok(live)) => (want, live),
        (Err(first), Err(second)) => return Err(combined_error(first, &[second])),
        (Err(error), _) | (_, Err(error)) => return Err(error),
    };
    if live == want {
        Ok((RulesetObs::Exact, false))
    } else if !live["nftables"].as_array().is_some_and(|entries| {
        entries
            .iter()
            .any(|entry| entry["table"]["family"] == "inet" && entry["table"]["name"] == "scupper")
    }) {
        Ok((RulesetObs::Missing, false))
    } else {
        Ok((
            RulesetObs::Differs {
                live_sha256: fingerprint(&live)?,
                want_sha256: fingerprint(&want)?,
            },
            true,
        ))
    }
}

/// Observes complete host ruleset equality, confirming any difference once.
///
/// # Errors
/// Returns execution, permission, file or JSON errors as observation errors.
pub fn observe_ruleset(sys: &dyn System, cfg: &V1Config) -> Probe<RulesetObs> {
    let (observation, confirm) = compare_once(sys, cfg)?;
    if confirm {
        compare_once(sys, cfg).map(|(observation, _)| observation)
    } else {
        Ok(observation)
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
