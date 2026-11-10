//! Namespace ruleset equality using kernel canonicalization in a private netns.

use std::{
    collections::hash_map::RandomState,
    fs::{self, DirBuilder, OpenOptions},
    hash::BuildHasher,
    io::{self, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
    time::{Duration, Instant},
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

/// Complete toolchain identity for an in-memory canonical rendering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheKey {
    /// SHA-256 of the rendered source.
    pub rendered: [u8; 32],
    /// Exact nft version output.
    pub nft_version: String,
    /// nft device, inode, modification seconds and nanoseconds.
    pub nft_identity: (u64, u64, i64, i64),
    /// Kernel release (the value returned by uname -r).
    pub kernel_release: String,
}
/// One-entry, process-lifetime cache; no cache files are created.
#[derive(Debug, Default)]
pub struct CanonCache {
    cached: Option<(CacheKey, Value)>,
    facts: Option<(Instant, CacheKey)>,
    checked_at: Option<Instant>,
    pending: Option<PendingCanon>,
    verified: Option<(CacheKey, [u8; 32])>,
    confirmed: Option<(CacheKey, [u8; 32])>,
}
#[derive(Debug)]
struct PendingCanon {
    rendered: [u8; 32],
    live: [u8; 32],
    started: Instant,
    receive: std::sync::mpsc::Receiver<Probe<(CacheKey, Value)>>,
}
impl CanonCache {
    /// Return a cached value or replace it with a fresh canonicalization.
    /// A suspected difference must set `fresh` before it can be reported.
    ///
    /// # Errors
    /// Propagates canonicalization errors without caching failures.
    pub fn get_or_try(
        &mut self,
        key: CacheKey,
        fresh: bool,
        load: impl FnOnce() -> Probe<Value>,
    ) -> Probe<Value> {
        if !fresh
            && let Some((old, value)) = &self.cached
            && *old == key
        {
            return Ok(value.clone());
        }
        let value = load()?;
        self.cached = Some((key, value.clone()));
        Ok(value)
    }
}

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
    fn create(root: &Path, rendered: &str) -> Probe<Self> {
        // RandomState uses randomized hashing keys. Two hashes make the name
        // unpredictable without extra dependencies.
        let name = format!(
            "scupper-canon-{:016x}{:016x}",
            RandomState::new().hash_one(std::process::id()),
            RandomState::new().hash_one(std::process::id()),
        );
        let temp_dir = root;
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
    let once = |fresh| {
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
        let (want, live) = canonical_pair(sys, handle, rendered, live, fresh)?;
        compare_rulesets(&want, &live)
    };
    let (observation, confirm) = once(false)?;
    Ok(if confirm { once(true)?.0 } else { observation }.into())
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
    let (want, live) = canonical_pair(sys, handle, rendered, live, false)?;
    if compare_rulesets(&want, &live)?.1 {
        let live = crate::cmd::run_cmd(
            sys,
            crate::system::ExecTarget::Netns(handle),
            &crate::cmd::KernelCmd::Nft(crate::cmd::NftCmd::ListRulesetJson),
            EXEC_TIMEOUT,
        );
        canonical_pair(sys, handle, rendered, live, true)
    } else {
        Ok((want, live))
    }
}

fn tool_facts(sys: &dyn System) -> Probe<CacheKey> {
    use std::os::unix::fs::MetadataExt;
    let (_, nft) = sys
        .canon_cache()
        .ok_or_else(|| ProbeError::setup("no canonical cache"))?;
    let meta = fs::metadata(nft).map_err(|e| file_error(&e))?;
    Ok(CacheKey {
        rendered: [0; 32],
        nft_version: command(sys, Program::Nft, &["--version".into()], EXEC_TIMEOUT)?,
        nft_identity: (meta.dev(), meta.ino(), meta.mtime(), meta.mtime_nsec()),
        kernel_release: fs::read_to_string("/proc/sys/kernel/osrelease")
            .map_err(|e| file_error(&e))?,
    })
}

/// Refresh tool identity outside safety observation, at most once per minute.
/// Misses also refresh it before loading a canonical rendering.
///
/// # Errors
/// Returns tool or metadata errors, retaining the last usable cache entry.
pub fn refresh_tool_facts(sys: &dyn System, now: Instant) -> Probe<()> {
    if let Some((cache, _)) = sys.canon_cache() {
        let due = cache
            .borrow()
            .checked_at
            .is_none_or(|at| now.saturating_duration_since(at) >= Duration::from_secs(60));
        if due {
            cache.borrow_mut().checked_at = Some(now);
            let facts = tool_facts(sys)?;
            cache.borrow_mut().facts = Some((now, facts));
        }
    }
    Ok(())
}

fn load_want(sys: &dyn System, inode: u64, rendered: &str) -> Probe<(CacheKey, Value)> {
    use sha2::{Digest, Sha256};
    let mut key = tool_facts(sys)?;
    key.rendered = Sha256::digest(rendered.as_bytes()).into();
    let outer = fs::read_link("/proc/self/ns/net").map_err(|error| file_error(&error))?;
    let file = PrivateRuleset::create(sys.canon_run_root(), rendered)?;
    let mut args = unshare_argv(sys.canon_executable(), &outer, &file.path())?;
    args.splice(6..6, ["--gateway-netns".into(), format!("net:[{inode}]")]);
    let value = canonicalize(&command(sys, Program::Unshare, &args, CANON_TIMEOUT)?)?;
    Ok((key, value))
}

fn cache_matches(cache: &CanonCache, key: &CacheKey, rendered: [u8; 32]) -> bool {
    key.rendered == rendered
        && cache.facts.as_ref().is_some_and(|(_, facts)| {
            let mut facts = facts.clone();
            facts.rendered = rendered;
            *key == facts
        })
}

// One outstanding worker per cache, including a worker stuck in filesystem I/O.
// Safety waits only on the channel, for at most one second in its group budget.
fn worker_want(
    sys: &dyn System,
    inode: u64,
    rendered: &str,
    live: [u8; 32],
    fresh: bool,
    deadline: Option<Instant>,
) -> Probe<Value> {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(rendered.as_bytes()).into();
    let (cell, _) = sys
        .canon_cache()
        .ok_or_else(|| ProbeError::setup("no canonical cache"))?;
    let deadline = deadline.unwrap_or_else(|| Instant::now() + Duration::from_secs(1));
    let mut cache = cell.borrow_mut();
    loop {
        // A normal hit must not perform any filesystem or tool work.
        if !fresh
            && let Some((key, value)) = &cache.cached
            && cache_matches(&cache, key, hash)
        {
            return Ok(value.clone());
        }
        if cache.pending.is_none() {
            let worker = sys
                .canon_worker()
                .ok_or_else(|| ProbeError::setup("no canonical worker"))?;
            let text = rendered.to_owned();
            let (send, receive) = std::sync::mpsc::sync_channel(1);
            std::thread::Builder::new()
                .name("scupper-canon".into())
                .spawn(move || {
                    let _ = send.send(load_want(worker.as_ref(), inode, &text));
                })
                .map_err(|e| file_error(&e))?;
            cache.pending = Some(PendingCanon {
                rendered: hash,
                live,
                started: Instant::now(),
                receive,
            });
        }
        let pending = cache.pending.as_ref().ok_or(ProbeError::Timeout)?;
        let result = pending
            .receive
            .recv_timeout(deadline.saturating_duration_since(Instant::now()));
        match result {
            Ok(result) => {
                let requested = (pending.rendered, pending.live);
                cache.pending = None;
                let (key, value) = result.inspect_err(|_| {
                    // A failed fresh canonicalization revokes the keep rule until
                    // a new worker succeeds; retrying must remain Unknown.
                    cache.verified = None;
                    cache.cached = None;
                    cache.confirmed = None;
                })?;
                let now = Instant::now();
                cache.facts = Some((now, key.clone()));
                cache.checked_at = Some(now);
                cache.confirmed = Some((key.clone(), requested.1));
                cache.cached = Some((key, value.clone()));
                if requested.0 == hash {
                    return Ok(value);
                }
                if Instant::now() >= deadline {
                    return Err(ProbeError::Timeout);
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                if let Some((key, verified_live)) = &cache.verified
                    && *verified_live == live
                    && key.rendered == hash
                    && cache
                        .facts
                        .as_ref()
                        .is_some_and(|(_, facts)| key.kernel_release == facts.kernel_release)
                    && cache
                        .pending
                        .as_ref()
                        .is_some_and(|pending| pending.started.elapsed() <= CANON_TIMEOUT)
                    && let Some((old_key, value)) = &cache.cached
                    && key == old_key
                {
                    return Ok(value.clone());
                }
                return Err(ProbeError::Timeout);
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                cache.pending = None;
                cache.verified = None;
                cache.cached = None;
                cache.confirmed = None;
                return Err(ProbeError::io("canonical worker stopped"));
            }
        }
    }
}

/// Compute the first canonical rendering before READY, bounded by the startup deadline.
/// Filesystem work remains owned by the cache worker after a timeout.
///
/// # Errors
/// Returns an observation error (including Timeout) without authorizing a rebuild.
pub fn prepare_netns_ruleset(
    sys: &dyn System,
    handle: &crate::netns::NetnsHandle,
    rendered: &str,
    deadline: Instant,
) -> Probe<Value> {
    worker_want(
        sys,
        handle.identity().1,
        rendered,
        [0; 32],
        false,
        Some(deadline),
    )
}

/// Safety observation: cache misses and fresh confirmations run on an owned worker.
/// Pending work preserves only a previously verified, unchanged live JSON hash.
///
/// # Errors
/// Returns Unknown's observation error while no verified pair is available.
pub fn netns_rulesets_safety(
    sys: &dyn System,
    handle: &crate::netns::NetnsHandle,
    rendered: &str,
) -> Probe<(Value, Value)> {
    use sha2::{Digest, Sha256};
    let text = command_result(crate::cmd::run_cmd(
        sys,
        crate::system::ExecTarget::Netns(handle),
        &crate::cmd::KernelCmd::Nft(crate::cmd::NftCmd::ListRulesetJson),
        EXEC_TIMEOUT,
    ))?;
    let hash = Sha256::digest(text.as_bytes()).into();
    let live = canonicalize(&text)?;
    let deadline = sys.canon_safety_deadline().map_or_else(
        || Instant::now() + Duration::from_secs(1),
        |group| group.min(Instant::now() + Duration::from_secs(1)),
    );
    let mut want = worker_want(
        sys,
        handle.identity().1,
        rendered,
        hash,
        false,
        Some(deadline),
    )?;
    let (cache, _) = sys
        .canon_cache()
        .ok_or_else(|| ProbeError::setup("no canonical cache"))?;
    if want != live {
        let confirmed = {
            let cache = cache.borrow();
            cache
                .cached
                .as_ref()
                .is_some_and(|(key, _)| cache.confirmed.as_ref() == Some(&(key.clone(), hash)))
        };
        if !confirmed {
            want = worker_want(
                sys,
                handle.identity().1,
                rendered,
                hash,
                true,
                Some(deadline),
            )?;
        }
    }
    if want == live {
        let mut cache = cache.borrow_mut();
        if let Some((key, _)) = &cache.cached {
            cache.verified = Some((key.clone(), hash));
        }
    }
    Ok((want, live))
}

fn canonical_pair(
    sys: &dyn System,
    handle: &crate::netns::NetnsHandle,
    rendered: &str,
    live: Result<ExecOutput, ExecError>,
    fresh: bool,
) -> Probe<(Value, Value)> {
    use sha2::{Digest, Sha256};
    let rendered_hash = Sha256::digest(rendered.as_bytes()).into();
    let load = || {
        let outer = fs::read_link("/proc/self/ns/net").map_err(|error| file_error(&error))?;
        let file = PrivateRuleset::create(sys.canon_run_root(), rendered)?;
        let mut args = unshare_argv(sys.canon_executable(), &outer, &file.path())?;
        args.splice(
            6..6,
            [
                "--gateway-netns".into(),
                format!("net:[{}]", handle.identity().1),
            ],
        );
        command(sys, Program::Unshare, &args, CANON_TIMEOUT)
            .and_then(|text| Ok(canonicalize(&text)?))
    };
    let want = if sys.canon_worker().is_some() {
        let live_hash = live
            .as_ref()
            .map_or([0; 32], |o| Sha256::digest(o.stdout.as_bytes()).into());
        worker_want(
            sys,
            handle.identity().1,
            rendered,
            live_hash,
            fresh,
            Some(Instant::now() + CANON_TIMEOUT + EXEC_TIMEOUT),
        )
    } else if let Some((cache, _)) = sys.canon_cache() {
        // The hit path uses memory only: even a failed miss must not poison it.
        let hit = {
            let cache = cache.borrow();
            cache
                .cached
                .as_ref()
                .filter(|(key, _)| {
                    !fresh
                        && key.rendered == rendered_hash
                        && cache.facts.as_ref().is_some_and(|(_, facts)| {
                            let mut facts = facts.clone();
                            facts.rendered = rendered_hash;
                            *key == facts
                        })
                })
                .map(|(_, value)| value.clone())
        };
        if let Some(value) = hit {
            Ok(value)
        } else {
            tool_facts(sys).and_then(|mut key| {
                key.rendered = rendered_hash;
                let now = Instant::now();
                cache.borrow_mut().checked_at = Some(now);
                cache.borrow_mut().facts = Some((now, key.clone()));
                cache.borrow_mut().get_or_try(key, fresh, load)
            })
        }
    } else {
        load()
    };
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
