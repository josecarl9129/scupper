//! Exact pfctl text rows. Unknown builds, streams and suffixes fail closed.
//! Enable rows are supplied by R2; acquisition/release templates must be
//! cross-checked against full Q-ENABLE captures before promotion (R11).
use super::pftoken::{Assumption, Assumptions};
use crate::platform::{PfEnable, Release, SysError, ToolOutcome, runtime::Reap};

/// Portable bounded tool evidence; constructing this does not interpret it.
#[derive(Clone, Copy, Debug)]
pub struct ToolEvidence<'a> {
    /// Spawned PID, retained independently of parsed text.
    pub pid: u32,
    /// Exact wait evidence, including `NoChild` and `Pending`.
    pub reap: Reap,
    /// Entire retained stdout.
    pub stdout: &'a [u8],
    /// Entire retained stderr.
    pub stderr: &'a [u8],
    /// Either bounded stream lost bytes.
    pub truncated: bool,
    /// Execution deadline triggered.
    pub timed_out: bool,
    /// Pipe/poll failure.
    pub io_failed: bool,
    /// Caller input not delivered.
    pub stdin_unsent: usize,
}
/// Return a status only from complete streams and an actual normal wait status.
///
/// # Errors
/// Any missing evidence, signal exit, `NoChild`, timeout or stream failure.
pub fn status(result: &ToolEvidence<'_>) -> Result<i32, SysError> {
    if result.timed_out || result.io_failed || result.stdin_unsent != 0 || result.truncated {
        return Err(SysError::Unknown);
    }
    match result.reap {
        Reap::Status(status) if status.trailing_zeros() >= 7 => Ok((status >> 8) & 0xff),
        _ => Err(SysError::Unknown),
    }
}
/// A pre-spawn error or the full evidence of an attempted pfctl operation.
pub type Attempt<'a> = Result<(&'a str, ToolEvidence<'a>), SysError>;
/// Interpret -e evidence with the build and EEXIST assumption gates.
///
/// # Errors
/// Pre-spawn refusal or any unrecognized/incomplete post-spawn evidence.
pub fn enable_outcome(attempt: Attempt<'_>, gates: Assumptions) -> Result<PfEnable, SysError> {
    let (build, result) = attempt?;
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
fn supported(build: &str) -> bool {
    BUILDS.contains(&build)
}
/// Exact global anonymous enable outcome, including the EEXIST assumption gate.
///
/// # Errors
/// Unsupported build, unrecognized bytes/status or unqualified EEXIST.
pub fn enable(
    build: &str,
    rc: i32,
    stdout: &[u8],
    stderr: &[u8],
    gates: Assumptions,
) -> Result<PfEnable, SysError> {
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
pub fn acquire(build: &str, rc: i32, stdout: &[u8], stderr: &[u8]) -> Result<u64, SysError> {
    if !supported(build) || rc != 0 || !stdout.is_empty() {
        return Err(SysError::Unknown);
    }
    let text = std::str::from_utf8(stderr).map_err(|_| SysError::Unknown)?;
    let text = text.strip_prefix("pf enabled\n").unwrap_or(text);
    text.strip_suffix('\n')
        .and_then(token_line)
        .ok_or(SysError::Unknown)
}
/// Exact successful release only. There is deliberately no invalid-token row:
/// neither disabled-pf errors nor stale numeric values establish safe absence
/// in the presence of token recurrence. Q-X-STALE records enabled-pf recurrence as measurement.
///
/// # Errors
/// All nonzero exits and all unrecognized text.
pub fn release(
    build: &str,
    rc: i32,
    stdout: &[u8],
    stderr: &[u8],
    token: u64,
) -> Result<Release, SysError> {
    let row = format!("Token : {token} revoked.\n");
    if supported(build)
        && token != 0
        && rc == 0
        && stdout.is_empty()
        && (stderr == row.as_bytes() || stderr == format!("{row}pf disabled\n").as_bytes())
    {
        Ok(Release::Released)
    } else {
        Err(SysError::Unknown)
    }
}
/// Parse all pf-info stdout only after a successful exit, accepting no unknown stderr.
///
/// # Errors
/// Failed exit, unexpected stderr, invalid UTF-8 or any unparsed info line.
pub fn info(rc: i32, stdout: &[u8], stderr: &[u8]) -> Result<crate::platform::PfInfo, SysError> {
    if rc != 0 || !stderr.is_empty() {
        return Err(SysError::Unknown);
    }
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
    fn evidence(stderr: &[u8]) -> ToolEvidence<'_> {
        ToolEvidence {
            pid: 123,
            reap: Reap::Status(0),
            stdout: b"",
            stderr,
            truncated: false,
            timed_out: false,
            io_failed: false,
            stdin_unsent: 0,
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
        for build in BUILDS {
            assert_eq!(
                acquire_outcome(Ok((build, evidence(b"Token : 42\n")))),
                ToolOutcome::Ok((42, 123))
            );
            assert_eq!(
                release_outcome(Ok((build, evidence(b"Token : 42 revoked.\n"))), 42),
                ToolOutcome::Ok(Release::Released)
            );
            assert_eq!(
                enable_outcome(
                    Ok((build, evidence(b"pf enabled\n"))),
                    Assumptions::default()
                ),
                Ok(PfEnable::Started)
            );
            // Each row retains plausible successful text, so missing guards fail.
            for row in 0..10 {
                for reap in [Reap::Status(0), Reap::NoChild, Reap::Pending] {
                    let corrupt = |mut e: ToolEvidence<'static>| {
                        e.reap = reap;
                        match row {
                            0 => e.stderr = b"unknown\n",
                            1 => e.reap = Reap::Status(2 << 8),
                            2 => e.truncated = true,
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
                    let r = corrupt(evidence(b"Token : 42 revoked.\n"));
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
                        Err(SysError::Unknown),
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
            acquire_outcome(Ok(("unknown", evidence(b"Token : 42\n")))),
            ToolOutcome::Unknown { reaped: true }
        );
    }
    #[test]
    fn info_requires_zero_exit_and_every_line_parsed() {
        use crate::platform::PfInfo;
        assert_eq!(info(0, b"Status: Enabled\n", b""), Ok(PfInfo::Enabled));
        assert_eq!(info(0, b"Status: Disabled\n", b""), Ok(PfInfo::Disabled));
        assert_eq!(
            info(
                0,
                include_bytes!(
                    "../../../scupper-core/tests/fixtures/mac/pf-info-disabled-source.txt"
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
            assert!(info(rc, stdout, stderr).is_err());
        }
    }
    #[test]
    fn every_build_row_and_eexist_gate() {
        for build in BUILDS {
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
            for suffix in ["", "pf disabled\n"] {
                assert_eq!(
                    release(
                        build,
                        0,
                        b"",
                        format!("Token : 42 revoked.\n{suffix}").as_bytes(),
                        42
                    ),
                    Ok(Release::Released)
                );
            }
        }
    }
    #[test]
    fn unknown_text_status_streams_and_builds_grant_nothing() {
        for build in ["24H232", "25G332", "unknown"] {
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
            assert!(acquire("24H232", rc, b"", b"Token : 42\n").is_err());
            assert!(release("24H232", rc, b"", b"Token : 42 revoked.\n", 42).is_err());
        }
        assert!(acquire("24H232", 0, b"extra", b"Token : 42\n").is_err());
        assert!(release("24H232", 0, b"extra", b"Token : 42 revoked.\n", 42).is_err());
        assert!(
            enable(
                "24H232",
                0,
                b"extra",
                b"pf enabled\n",
                Assumptions::default()
            )
            .is_err()
        );
        assert!(enable("unknown", 0, b"", b"pf enabled\n", Assumptions::default()).is_err());
        assert!(acquire("unknown", 0, b"", b"Token : 42\n").is_err());
        assert!(release("unknown", 0, b"", b"Token : 42 revoked.\n", 42).is_err());
    }
}
