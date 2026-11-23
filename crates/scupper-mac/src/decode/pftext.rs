//! Exact pfctl text rows. Unknown builds, streams and suffixes fail closed.
//! Enable rows are supplied by R2; CI 45067680869 captured acquisition and
//! release rows on both builds (sole row: CI 45079241070). Production promotion remains R11.
use super::pftoken::{Assumption, Assumptions};
use crate::platform::{
    PfEnable, PfInfo, Release, SysError, ToolOutcome,
    runtime::{Output, Reap},
};

/// OS build provenance required by every pfctl text parser. No default build exists.
#[derive(Debug)]
pub struct Build(String);
impl Build {
    /// Read the same kernel OS version for production and live qualification.
    ///
    /// # Errors
    /// Missing, empty or malformed OS version evidence.
    #[cfg(target_os = "macos")]
    pub(crate) fn system() -> Result<Self, SysError> {
        let value =
            scupper_darwin::sysctl_string("kern.osversion").map_err(|_| SysError::Unknown)?;
        Self::osversion(&value).ok_or(SysError::Unknown)
    }
    #[cfg(any(target_os = "macos", test))]
    fn osversion(value: &str) -> Option<Self> {
        let value = value.trim();
        (!value.is_empty() && value.bytes().all(|b| b.is_ascii_alphanumeric()))
            .then(|| Self(value.to_owned()))
    }
    /// Snapshot provenance comes only from complete kern.osversion evidence.
    #[cfg(all(feature = "qualification", any(target_os = "macos", test)))]
    pub(crate) fn observed(
        observations: &std::collections::BTreeMap<String, crate::qual::Evidence>,
    ) -> Option<Self> {
        let evidence = observations.get("osversion").filter(|e| e.complete())?;
        if !evidence.stderr.is_empty() {
            return None;
        }
        Self::osversion(&evidence.stdout)
    }
    /// Exact build value, for captures and qualified-table lookup.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
    #[cfg(test)]
    pub(crate) fn fixture(value: &str) -> Self {
        Self::osversion(value).expect("nonempty fixture OS build")
    }
}

/// Portable bounded tool evidence; constructing this does not interpret it.
#[derive(Clone, Copy, Debug)]
#[allow(clippy::struct_excessive_bools)] // Independent raw failure flags, combined only by status().
pub struct ToolEvidence<'a> {
    /// Spawned PID, retained independently of parsed text.
    pub pid: u32,
    /// Exact wait evidence, including `NoChild` and `Pending`.
    pub reap: Reap,
    /// Entire retained stdout.
    pub stdout: &'a [u8],
    /// Entire retained stderr.
    pub stderr: &'a [u8],
    /// Bounded stdout lost bytes.
    pub stdout_truncated: bool,
    /// Bounded stderr lost bytes.
    pub stderr_truncated: bool,
    /// Execution deadline triggered.
    pub timed_out: bool,
    /// Pipe/poll failure.
    pub io_failed: bool,
    /// Caller input not delivered.
    pub stdin_unsent: usize,
}
impl<'a> ToolEvidence<'a> {
    /// Borrow bounded native streams with their independent loss flags intact.
    #[must_use]
    pub fn from_output(
        pid: u32,
        reap: Reap,
        stdout: &'a Output,
        stderr: &'a Output,
        timed_out: bool,
        io_failed: bool,
        stdin_unsent: usize,
    ) -> Self {
        Self {
            pid,
            reap,
            stdout: &stdout.bytes,
            stderr: &stderr.bytes,
            stdout_truncated: stdout.truncated,
            stderr_truncated: stderr.truncated,
            timed_out,
            io_failed,
            stdin_unsent,
        }
    }
}
/// Return a status only from complete streams and an actual normal wait status.
///
/// # Errors
/// Any missing evidence, signal exit, `NoChild`, timeout or stream failure.
pub fn status(result: &ToolEvidence<'_>) -> Result<i32, SysError> {
    if result.timed_out
        || result.io_failed
        || result.stdin_unsent != 0
        || result.stdout_truncated
        || result.stderr_truncated
    {
        return Err(SysError::Unknown);
    }
    match result.reap {
        Reap::Status(status) if status.trailing_zeros() >= 7 => Ok((status >> 8) & 0xff),
        _ => Err(SysError::Unknown),
    }
}
/// A pre-spawn error or the full evidence of an attempted pfctl operation.
pub type Attempt<'a> = Result<(&'a Build, ToolEvidence<'a>), SysError>;
/// Interpret pf-info only with complete streams and a successful normal exit.
#[must_use]
pub fn info_outcome(attempt: Attempt<'_>) -> PfInfo {
    let result = attempt.and_then(|(build, e)| info(build, status(&e)?, e.stdout, e.stderr));
    result.unwrap_or_else(PfInfo::Incomplete)
}
/// Interpret -e evidence with the build and EEXIST assumption gates.
///
/// # Errors
/// Pre-spawn refusal or any unrecognized/incomplete post-spawn evidence.
pub fn enable_outcome(attempt: Attempt<'_>, gates: Assumptions) -> Result<PfEnable, SysError> {
    let (build, result) = attempt?;
    if result.timed_out {
        return Err(SysError::TimedOut);
    }
    enable(build, status(&result)?, result.stdout, result.stderr, gates)
}
/// Interpret -E evidence. Only a pre-spawn refusal can mean `NotStarted`.
#[must_use]
pub fn acquire_outcome(attempt: Attempt<'_>) -> ToolOutcome<(u64, u32)> {
    let (build, result) = match attempt {
        Ok(evidence) => evidence,
        Err(error) => return ToolOutcome::NotStarted(error),
    };
    match status(&result).and_then(|rc| acquire(build, rc, result.stdout, result.stderr)) {
        Ok(token) => ToolOutcome::Ok((token, result.pid)),
        Err(_) => ToolOutcome::Unknown {
            reaped: result.reap.settled(),
        },
    }
}
/// Interpret -X evidence without inferring absence from an error.
#[must_use]
pub fn release_outcome(attempt: Attempt<'_>, token: u64) -> ToolOutcome<Release> {
    let (build, result) = match attempt {
        Ok(evidence) => evidence,
        Err(error) => return ToolOutcome::NotStarted(error),
    };
    match status(&result).and_then(|rc| release(build, rc, result.stdout, result.stderr, token)) {
        Ok(released) => ToolOutcome::Ok(released),
        Err(_) => ToolOutcome::Unknown {
            reaped: result.reap.settled(),
        },
    }
}
/// Builds covered by the disposable-runner campaign.
pub const BUILDS: [&str; 2] = ["24H232", "25G332"];
fn supported(build: &Build) -> bool {
    BUILDS.contains(&build.as_str())
}
/// Exact stderr preamble observed in CI 45050965328 on both qualified builds.
pub const ALTQ_PREAMBLE: &[u8] = b"No ALTQ support in kernel\nALTQ related functions disabled\n";
/// Remove one exact leading preamble only on builds with captured evidence.
/// The caller must still apply its complete, exact stderr rule to the remainder.
#[must_use]
pub fn stderr<'a>(build: &Build, bytes: &'a [u8]) -> &'a [u8] {
    if supported(build) {
        bytes.strip_prefix(ALTQ_PREAMBLE).unwrap_or(bytes)
    } else {
        bytes
    }
}
/// Complete read-only pfctl text with no remaining diagnostics (rules, NAT, anchors).
///
/// # Errors
/// Failed exit or any stderr beyond the qualified prefix.
pub fn read<'a>(
    build: &Build,
    rc: i32,
    stdout: &'a [u8],
    stderr: &[u8],
) -> Result<&'a [u8], SysError> {
    if rc != 0 || !self::stderr(build, stderr).is_empty() {
        return Err(SysError::Unknown);
    }
    Ok(stdout)
}
/// Recognize only an explicit empty-reference row, in its captured stream.
#[must_use]
pub fn references_empty(build: &Build, stdout: &[u8], stderr: &[u8]) -> bool {
    let stderr = self::stderr(build, stderr);
    let empty_row = |bytes: &[u8]| {
        matches!(
            bytes,
            b"No pf starter references held" | b"No pf starter references held\n"
        )
    };
    (stdout.is_empty() && empty_row(stderr)) || (stderr.is_empty() && empty_row(stdout))
}
/// Exact harness-only global disable row; unexpected text remains inconclusive.
///
/// # Errors
/// Unsupported build, failed exit or unrecognized streams.
pub fn disable(build: &Build, rc: i32, stdout: &[u8], stderr: &[u8]) -> Result<(), SysError> {
    if supported(build)
        && rc == 0
        && stdout.is_empty()
        && self::stderr(build, stderr) == b"pf disabled\n"
    {
        Ok(())
    } else {
        Err(SysError::Unknown)
    }
}
/// Exact global anonymous enable outcome, including the EEXIST assumption gate.
///
/// # Errors
/// Unsupported build, unrecognized bytes/status or unqualified EEXIST.
pub fn enable(
    build: &Build,
    rc: i32,
    stdout: &[u8],
    stderr: &[u8],
    gates: Assumptions,
) -> Result<PfEnable, SysError> {
    let stderr = self::stderr(build, stderr);
    if supported(build) && stdout.is_empty() {
        match (rc, stderr) {
            (0, b"pf enabled\n") => return Ok(PfEnable::Started),
            (1, b"pfctl: pf already enabled\n")
                if gates.eexist_establishes_anonymous == Assumption::Established =>
            {
                return Ok(PfEnable::AlreadyRunning);
            }
            _ => (),
        }
    }
    Err(SysError::Unknown)
}
fn token_line(line: &str) -> Option<u64> {
    let digits = line.strip_prefix("Token : ")?;
    if digits.is_empty()
        || !digits.bytes().all(|b| b.is_ascii_digit())
        || (digits.len() > 1 && digits.starts_with('0'))
    {
        return None;
    }
    digits.parse().ok().filter(|n| *n != 0)
}
/// Parse the entire acquisition capture, preserving the spawned PID separately.
///
/// # Errors
/// Every unrecognized byte/status, duplicate token or unsupported build.
pub fn acquire(build: &Build, rc: i32, stdout: &[u8], stderr: &[u8]) -> Result<u64, SysError> {
    if !supported(build) || rc != 0 || !stdout.is_empty() {
        return Err(SysError::Unknown);
    }
    let text = std::str::from_utf8(self::stderr(build, stderr)).map_err(|_| SysError::Unknown)?;
    let text = text.strip_prefix("pf enabled\n").unwrap_or(text);
    text.strip_suffix('\n')
        .and_then(token_line)
        .ok_or(SysError::Unknown)
}
/// Qualified request acknowledgement only. No text row proves release or absence.
/// The engine must obtain a fresh complete post-call fingerprint inventory.
/// `SoleReleased` is pinned to the full preamble and `pf disabled\n` bytes.
/// Only the native exact -X invocation supplies this parser; -d is never a fallback.
///
/// # Errors
/// Unsupported builds, nonzero exits, unrecognized text or noncanonical counts.
pub fn release(
    build: &Build,
    rc: i32,
    stdout: &[u8],
    stderr: &[u8],
    token: u64,
) -> Result<Release, SysError> {
    // Preserve the raw preamble: the sole-reference row requires it exactly.
    if supported(build)
        && token != 0
        && rc == 0
        && stdout.is_empty()
        && stderr == [ALTQ_PREAMBLE, b"pf disabled\n"].concat()
    {
        return Ok(Release::Requested);
    }
    let stderr = self::stderr(build, stderr);
    let count = std::str::from_utf8(stderr).ok().and_then(|text| {
        text.strip_prefix("disable request successful. ")?
            .strip_suffix(" more pf enable reference(s) remaining, pf still enabled.\n")
    });
    if supported(build)
        && token != 0
        && rc == 0
        && stdout.is_empty()
        && count.is_some_and(|n| {
            !n.is_empty() && !n.starts_with('0') && n.bytes().all(|b| b.is_ascii_digit())
        })
    {
        Ok(Release::Requested)
    } else {
        Err(SysError::Unknown)
    }
}
/// Parse all pf-info stdout only after a successful exit, accepting no unknown stderr.
///
/// # Errors
/// Failed exit, unexpected stderr, invalid UTF-8 or any unparsed info line.
pub fn info(
    build: &Build,
    rc: i32,
    stdout: &[u8],
    stderr: &[u8],
) -> Result<crate::platform::PfInfo, SysError> {
    let stdout = read(build, rc, stdout, stderr)?;
    let text = std::str::from_utf8(stdout).map_err(|_| SysError::Unknown)?;
    let parsed = scupper_core::mac::parse::pf_info(text).map_err(|_| SysError::Unknown)?;
    Ok(if parsed.enabled {
        crate::platform::PfInfo::Enabled
    } else {
        crate::platform::PfInfo::Disabled
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn every_native_parser_uses_system_build_attempt() {
        let native = include_str!("../native/mod.rs");
        for method in ["enable_pf", "acquire", "release", "pf_info"] {
            let signature = format!("    fn {method}(");
            let body = native
                .split_once(&signature)
                .expect("native method")
                .1
                .split("\n    fn ")
                .next()
                .expect("method body");
            assert!(
                body.contains("let attempt = self.pf_attempt("),
                "assertion: {method} must supply the system build"
            );
            assert!(
                !body.contains("String::new()"),
                "assertion: empty native build"
            );
        }
        let pf = include_str!("../native/pf.rs");
        let body = pf
            .split_once("pub(super) fn pf_attempt(")
            .expect("shared helper")
            .1
            .split("pub(super) fn read_references(")
            .next()
            .expect("helper body");
        assert!(body.contains("let build = crate::decode::pftext::Build::system()?;"));
        assert!(!body.contains("String::new()"));
        let source = include_str!("pftext.rs");
        let system = source
            .split_once("pub(crate) fn system()")
            .expect("system source")
            .1
            .split("fn osversion(")
            .next()
            .expect("build constructor");
        assert!(system.contains("scupper_darwin::sysctl_string(\"kern.osversion\")"));
        assert!(!system.contains("String::new()"));
        assert!(Build::osversion("").is_none());
        assert!(Build::osversion(" \n").is_none());
    }

    #[test]
    fn sole_release_raw_per_build_rows_fail_closed() {
        let fixtures: &[(&str, &[u8], &[u8])] = &[
            (
                "24H232",
                include_bytes!("../../tests/fixtures/pf-sole-release-24H232.stdout"),
                include_bytes!("../../tests/fixtures/pf-sole-release-24H232.stderr"),
            ),
            (
                "25G332",
                include_bytes!("../../tests/fixtures/pf-sole-release-25G332.stdout"),
                include_bytes!("../../tests/fixtures/pf-sole-release-25G332.stderr"),
            ),
        ];
        for &(name, stdout, stderr) in fixtures {
            let build = Build::fixture(name);
            assert_eq!(
                release(&build, 0, stdout, stderr, 42),
                Ok(Release::Requested)
            );
            for bad in [
                b"pf disabled\n".to_vec(),
                [b"altered\n".as_slice(), b"pf disabled\n"].concat(),
                [ALTQ_PREAMBLE, b"pf disabled"].concat(),
                [stderr, b"trailing"].concat(),
                [ALTQ_PREAMBLE, b"pf enabled\n"].concat(),
            ] {
                assert_eq!(
                    release_outcome(Ok((&build, evidence(&bad))), 42),
                    ToolOutcome::Unknown { reaped: true }
                );
            }
            let mut e = evidence(stderr);
            e.stdout = b"unexpected";
            assert_eq!(
                release_outcome(Ok((&build, e)), 42),
                ToolOutcome::Unknown { reaped: true }
            );
            e = evidence(stderr);
            e.reap = Reap::Status(1 << 8);
            assert_eq!(
                release_outcome(Ok((&build, e)), 42),
                ToolOutcome::Unknown { reaped: true }
            );
            assert_eq!(
                release_outcome(Ok((&Build::fixture("unqualified"), evidence(stderr))), 42),
                ToolOutcome::Unknown { reaped: true }
            );
            assert!(release(&build, 0, stdout, stderr, 0).is_err());
        }
    }
    #[test]
    fn release_invocation_is_exact_x_without_disable_fallback() {
        let native = include_str!("../native/mod.rs");
        let body = native
            .split_once("    fn release(&mut self,")
            .unwrap()
            .1
            .split("    fn references(")
            .next()
            .unwrap();
        assert!(body.contains(
            "self.pf_attempt(&[crate::engine::PFCTL, \"-X\", &token.to_string()], deadline)"
        ));
        assert!(!body.contains("\"-d\""));
        assert_eq!(body.matches("self.pf_attempt(").count(), 1);
    }

    #[test]
    fn references_require_exactly_one_stream_and_disable_requires_exact_streams() {
        for name in BUILDS {
            let build = Build::fixture(name);
            let row = b"No pf starter references held\n";
            assert!(references_empty(&build, row, ALTQ_PREAMBLE));
            assert!(references_empty(
                &build,
                b"",
                &[ALTQ_PREAMBLE, row].concat()
            ));
            assert!(!references_empty(
                &build,
                row,
                &[ALTQ_PREAMBLE, row].concat()
            ));
            assert!(!references_empty(&build, row, row));
            assert!(disable(&build, 0, b"unexpected", b"pf disabled\n").is_err());
            assert!(disable(&build, 0, b"", b"unexpected\n").is_err());
        }
    }

    fn evidence(stderr: &[u8]) -> ToolEvidence<'_> {
        ToolEvidence {
            pid: 123,
            reap: Reap::Status(0),
            stdout: b"",
            stderr,
            stdout_truncated: false,
            stderr_truncated: false,
            timed_out: false,
            io_failed: false,
            stdin_unsent: 0,
        }
    }
    #[test]
    fn native_output_mapping_preserves_each_stream_truncation_flag() {
        for out_lost in [false, true] {
            for err_lost in [false, true] {
                let mut stdout = Output::default();
                stdout.append(b"Status: Disabled\n", 1024);
                let mut stderr = Output::default();
                stderr.append(ALTQ_PREAMBLE, 1024);
                if out_lost {
                    stdout.append(b"discarded", stdout.bytes.len());
                }
                if err_lost {
                    stderr.append(b"discarded", stderr.bytes.len());
                }
                let e = ToolEvidence::from_output(
                    123,
                    Reap::Status(0),
                    &stdout,
                    &stderr,
                    false,
                    false,
                    0,
                );
                assert_eq!(e.stdout, b"Status: Disabled\n");
                assert_eq!(e.stderr, ALTQ_PREAMBLE);
                assert_eq!(e.stdout_truncated, out_lost);
                assert_eq!(e.stderr_truncated, err_lost);
                assert_eq!(
                    info_outcome(Ok((&Build::fixture("24H232"), e))),
                    if out_lost || err_lost {
                        PfInfo::Incomplete(SysError::Unknown)
                    } else {
                        PfInfo::Disabled
                    }
                );
            }
        }
    }
    #[test]
    fn altq_prefix_is_exact_once_build_qualified_for_every_row() {
        // Both enable gates and the captured acquisition/release rows remain exact.
        let rows: &[(&[u8], &[u8])] = &[
            (b"Status: Disabled\n", b""),
            (b"Status: Enabled\n", b""),
            (b"", b"pf enabled\n"),
            (b"", b"pfctl: pf already enabled\n"),
            (b"", b"Token : 42\n"),
            (b"", b"pf enabled\nToken : 42\n"),
            (b"", b"disable request successful. 1 more pf enable reference(s) remaining, pf still enabled.\n"),
            (b"", b"disable request successful. 7 more pf enable reference(s) remaining, pf still enabled.\n"),
            (b"", b"pf disabled\n"),
            (b"No pf starter references held\n", b""),
            (b"", b"No pf starter references held\n"),
            (b"com.apple\n", b""), // recursive anchors
            (b"", b""),            // empty rules, NAT and Apple anchors
        ];
        for (row, &(stdout, tail)) in rows.iter().enumerate() {
            let parse = |build: &Build, bytes: &[u8]| match row {
                0 | 1 => info(build, 0, stdout, bytes).is_ok(),
                2 | 3 => enable(
                    build,
                    i32::from(row == 3),
                    stdout,
                    bytes,
                    Assumptions {
                        eexist_establishes_anonymous: Assumption::Established,
                        ..Assumptions::default()
                    },
                )
                .is_ok(),
                4 | 5 => acquire(build, 0, stdout, bytes) == Ok(42),
                6 | 7 => release(build, 0, stdout, bytes, 42) == Ok(Release::Requested),
                8 => disable(build, 0, stdout, bytes).is_ok(),
                9 | 10 => references_empty(build, stdout, bytes),
                _ => read(build, 0, stdout, bytes).is_ok(),
            };
            for name in BUILDS {
                let build = &Build::fixture(name);
                assert!(parse(build, tail), "assertion: plain row {row} {build:?}");
                let prefixed = [ALTQ_PREAMBLE, tail].concat();
                assert!(
                    parse(build, &prefixed),
                    "assertion: ALTQ row {row} {build:?}"
                );
                for bad in [
                    [ALTQ_PREAMBLE, ALTQ_PREAMBLE, tail].concat(),
                    [b"other\n", ALTQ_PREAMBLE, tail].concat(),
                    [ALTQ_PREAMBLE, b"other\n", tail].concat(),
                    [ALTQ_PREAMBLE, tail, b"other\n"].concat(),
                    [tail, ALTQ_PREAMBLE].concat(),
                    [b"No ALTQ support in kernel\n", tail].concat(),
                    [b"ALTQ related functions disabled\n", tail].concat(),
                    [ALTQ_PREAMBLE.strip_suffix(b"\n").unwrap_or_default(), tail].concat(),
                ] {
                    // For empty tails the suffix construction is the valid prefix itself.
                    if bad != prefixed {
                        assert!(
                            !parse(build, &bad),
                            "assertion: bad row {row} {build:?}: {bad:?}"
                        );
                    }
                }
                assert!(
                    !parse(&Build::fixture("unsupported"), &prefixed),
                    "assertion: unsupported row {row}"
                );
                for length in 1..ALTQ_PREAMBLE.len() {
                    assert!(
                        !parse(build, &[&ALTQ_PREAMBLE[..length], tail].concat()),
                        "assertion: partial row {row}"
                    );
                }
            }
        }
        for name in BUILDS {
            let build = &Build::fixture(name);
            assert!(
                enable(
                    build,
                    1,
                    b"",
                    &[ALTQ_PREAMBLE, b"pfctl: pf already enabled\n"].concat(),
                    Assumptions::default()
                )
                .is_err()
            );
            assert!(read(build, 1, b"", ALTQ_PREAMBLE).is_err());
            assert!(disable(build, 1, b"", &[ALTQ_PREAMBLE, b"pf disabled\n"].concat()).is_err());
            assert!(
                disable(
                    build,
                    0,
                    b"unexpected",
                    &[ALTQ_PREAMBLE, b"pf disabled\n"].concat()
                )
                .is_err()
            );
        }
    }
    #[test]
    fn portable_outcomes_require_complete_post_spawn_evidence() {
        let error = SysError::Unknown;
        assert_eq!(
            acquire_outcome(Err(error.clone())),
            ToolOutcome::NotStarted(error.clone())
        );
        assert_eq!(
            release_outcome(Err(error.clone()), 42),
            ToolOutcome::NotStarted(error.clone())
        );
        assert_eq!(
            enable_outcome(Err(error), Assumptions::default()),
            Err(SysError::Unknown)
        );
        for name in BUILDS {
            let build = &Build::fixture(name);
            assert_eq!(
                acquire_outcome(Ok((build, evidence(b"Token : 42\n")))),
                ToolOutcome::Ok((42, 123))
            );
            assert_eq!(
                release_outcome(Ok((build, evidence(b"disable request successful. 1 more pf enable reference(s) remaining, pf still enabled.\n"))), 42),
                ToolOutcome::Ok(Release::Requested)
            );
            assert_eq!(
                enable_outcome(
                    Ok((build, evidence(b"pf enabled\n"))),
                    Assumptions::default()
                ),
                Ok(PfEnable::Started)
            );
            // Each row retains plausible successful text, so missing guards fail.
            for row in 0..11 {
                for reap in [Reap::Status(0), Reap::NoChild, Reap::Pending] {
                    let corrupt = |mut e: ToolEvidence<'static>| {
                        e.reap = reap;
                        match row {
                            0 => e.stderr = b"unknown\n",
                            1 => e.reap = Reap::Status(2 << 8),
                            2 => e.stdout_truncated = true,
                            10 => e.stderr_truncated = true,
                            3 => e.timed_out = true,
                            4 => e.io_failed = true,
                            5 => e.stdin_unsent = 1,
                            6 => e.reap = Reap::NoChild,
                            7 => e.reap = Reap::Pending,
                            8 => e.reap = Reap::Status(9),
                            _ => e.stdout = b"unexpected",
                        }
                        e
                    };
                    let a = corrupt(evidence(b"Token : 42\n"));
                    let r = corrupt(evidence(b"disable request successful. 1 more pf enable reference(s) remaining, pf still enabled.\n"));
                    let e = corrupt(evidence(b"pf enabled\n"));
                    assert_eq!(
                        acquire_outcome(Ok((build, a))),
                        ToolOutcome::Unknown {
                            reaped: a.reap.settled()
                        },
                        "row {row}"
                    );
                    assert_eq!(
                        release_outcome(Ok((build, r)), 42),
                        ToolOutcome::Unknown {
                            reaped: r.reap.settled()
                        },
                        "row {row}"
                    );
                    assert_eq!(
                        enable_outcome(Ok((build, e)), Assumptions::default()),
                        Err(if e.timed_out {
                            SysError::TimedOut
                        } else {
                            SysError::Unknown
                        }),
                        "row {row}"
                    );
                    if !matches!(row, 0 | 1 | 9) {
                        assert_eq!(status(&a), Err(SysError::Unknown), "status row {row}");
                    }
                }
            }
            assert_eq!(status(&evidence(b"")), Ok(0));
            assert_eq!(
                status(&ToolEvidence {
                    reap: Reap::Status(1 << 8),
                    ..evidence(b"")
                }),
                Ok(1)
            );
        }
        assert_eq!(
            acquire_outcome(Ok((&Build::fixture("unknown"), evidence(b"Token : 42\n")))),
            ToolOutcome::Unknown { reaped: true }
        );
    }
    #[test]
    fn release_real_text_is_only_a_request_acknowledgement() {
        for name in BUILDS {
            let build = Build::fixture(name);
            for n in ["1", "2", "999999999999999999999999999999"] {
                let row = format!(
                    "disable request successful. {n} more pf enable reference(s) remaining, pf still enabled.\n"
                );
                assert_eq!(
                    release(&build, 0, b"", row.as_bytes(), 42),
                    Ok(Release::Requested)
                );
                for rc in [1, -1, 256] {
                    assert!(release(&build, rc, b"", row.as_bytes(), 42).is_err());
                }
            }
            for n in ["0", "01", "", "-1", "+1", "1 ", " 1"] {
                let row = format!(
                    "disable request successful. {n} more pf enable reference(s) remaining, pf still enabled.\n"
                );
                assert!(
                    release(&build, 0, b"", row.as_bytes(), 42).is_err(),
                    "assertion: noncanonical remaining count {n}"
                );
            }
            for row in [
                "disable request successful. 1 more pf enable reference(s) remaining, pf still enabled.\nextra",
                "disable request successful. 1 more pf enable reference(s) remaining, pf still enabled.",
                "Token : 42 revoked.\n",
                "Token : 42 revoked.\npf disabled\n",
                "pfctl: pf not enabled\n",
            ] {
                for rc in [0, 1] {
                    assert_eq!(
                        release_outcome(
                            Ok((
                                &build,
                                ToolEvidence {
                                    reap: Reap::Status(rc << 8),
                                    ..evidence(row.as_bytes())
                                }
                            )),
                            42
                        ),
                        ToolOutcome::Unknown { reaped: true }
                    );
                }
            }
        }
    }
    #[test]
    fn info_outcome_requires_complete_evidence() {
        assert_eq!(
            info_outcome(Err(SysError::Unknown)),
            PfInfo::Incomplete(SysError::Unknown)
        );
        for row in 0..11 {
            let mut e = evidence(b"");
            e.stdout = b"Status: Disabled\n";
            match row {
                0 => {}
                1 => e.reap = Reap::NoChild,
                2 => e.reap = Reap::Pending,
                3 => e.reap = Reap::Status(9),
                4 => e.reap = Reap::Status(1 << 8),
                5 => e.stdout_truncated = true,
                6 => e.stderr_truncated = true,
                7 => e.timed_out = true,
                8 => e.io_failed = true,
                9 => e.stdin_unsent = 1,
                _ => e.stderr = b"unknown",
            }
            assert_eq!(
                info_outcome(Ok((&Build::fixture("24H232"), e))),
                if row == 0 {
                    PfInfo::Disabled
                } else {
                    PfInfo::Incomplete(SysError::Unknown)
                },
                "row {row}"
            );
        }
    }
    #[test]
    fn info_requires_zero_exit_and_every_line_parsed() {
        use crate::platform::PfInfo;
        assert_eq!(
            info(&Build::fixture("24H232"), 0, b"Status: Enabled\n", b""),
            Ok(PfInfo::Enabled)
        );
        assert_eq!(
            info(&Build::fixture("24H232"), 0, b"Status: Disabled\n", b""),
            Ok(PfInfo::Disabled)
        );
        assert_eq!(
            info(
                &Build::fixture("24H232"),
                0,
                include_bytes!(
                    "../../../scupper-core/tests/fixtures/mac/pf-info-disabled-24H232.txt"
                ),
                b""
            ),
            Ok(PfInfo::Disabled)
        );
        for (rc, stdout, stderr) in [
            (1, &b"Status: Disabled\n"[..], &b""[..]),
            (0, b"Status: Disabled\nunknown\n", b""),
            (0, b"Status: Disabled\n", b"unknown"),
            (0, b"Status: Enabled\nStatus: Disabled\n", b""),
            (0, b"", b""),
            (0, b"\xff", b""),
        ] {
            assert!(info(&Build::fixture("24H232"), rc, stdout, stderr).is_err());
        }
    }
    #[test]
    fn every_build_row_and_eexist_gate() {
        for name in BUILDS {
            let build = &Build::fixture(name);
            assert_eq!(
                enable(build, 0, b"", b"pf enabled\n", Assumptions::default()),
                Ok(PfEnable::Started)
            );
            for gate in [
                Assumption::Unknown,
                Assumption::Refuted,
                Assumption::Established,
            ] {
                let gates = Assumptions {
                    eexist_establishes_anonymous: gate,
                    ..Assumptions::default()
                };
                assert_eq!(
                    enable(build, 1, b"", b"pfctl: pf already enabled\n", gates),
                    if gate == Assumption::Established {
                        Ok(PfEnable::AlreadyRunning)
                    } else {
                        Err(SysError::Unknown)
                    }
                );
            }
            for prefix in ["", "pf enabled\n"] {
                assert_eq!(
                    acquire(build, 0, b"", format!("{prefix}Token : 42\n").as_bytes()),
                    Ok(42)
                );
            }
            for count in [1, 7] {
                assert_eq!(
                    release(
                        build,
                        0,
                        b"",
                        format!("disable request successful. {count} more pf enable reference(s) remaining, pf still enabled.\n").as_bytes(),
                        42
                    ),
                    Ok(Release::Requested)
                );
            }
        }
    }
    #[test]
    fn unknown_text_status_streams_and_builds_grant_nothing() {
        for name in ["24H232", "25G332", "unknown"] {
            let build = &Build::fixture(name);
            for text in [
                "",
                "Token : 0\n",
                "Token : 43 revoked.\n",
                "Token : 01\n",
                "Token : +1\n",
                "Token : 1",
                "Token : 1\nextra\n",
                "Token : 1\nToken : 2\n",
                "Token : 18446744073709551616\n",
                "pfctl: pf not enabled\n",
                "pfctl: invalid token\n",
            ] {
                assert!(acquire(build, 0, b"", text.as_bytes()).is_err());
                assert!(release(build, 0, b"", text.as_bytes(), 42).is_err());
                assert!(enable(build, 0, b"", text.as_bytes(), Assumptions::default()).is_err());
            }
        }
        for rc in [1, -1, 256] {
            assert!(acquire(&Build::fixture("24H232"), rc, b"", b"Token : 42\n").is_err());
            assert!(
                release(
                    &Build::fixture("24H232"),
                    rc,
                    b"",
                    b"disable request successful. 1 more pf enable reference(s) remaining, pf still enabled.\n",
                    42
                )
                .is_err()
            );
        }
        assert!(acquire(&Build::fixture("24H232"), 0, b"extra", b"Token : 42\n").is_err());
        assert!(
            release(
                &Build::fixture("24H232"),
                0,
                b"extra",
                b"disable request successful. 1 more pf enable reference(s) remaining, pf still enabled.\n",
                42
            )
            .is_err()
        );
        assert!(
            enable(
                &Build::fixture("24H232"),
                0,
                b"extra",
                b"pf enabled\n",
                Assumptions::default()
            )
            .is_err()
        );
        assert!(
            enable(
                &Build::fixture("unknown"),
                0,
                b"",
                b"pf enabled\n",
                Assumptions::default()
            )
            .is_err()
        );
        assert!(acquire(&Build::fixture("unknown"), 0, b"", b"Token : 42\n").is_err());
        assert!(
            release(
                &Build::fixture("unknown"),
                0,
                b"",
                b"disable request successful. 1 more pf enable reference(s) remaining, pf still enabled.\n",
                42
            )
            .is_err()
        );
    }
}
