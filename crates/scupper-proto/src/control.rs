//! Bounded newline-delimited JSON for the local control socket.
use crate::{Identifier, Reason, UnixSeconds, VerdictCode, sampled_enum, vocabulary};
use serde::{Deserialize, Serialize};

/// Maximum wire request size, including its optional terminating newline.
pub const MAX_REQUEST_SIZE: usize = 64 * 1024;

/// Schema marker that can only serialize as 1 and refuses other versions.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "u32", into = "u32")]
pub struct Schema;
impl From<Schema> for u32 {
    fn from(_: Schema) -> Self {
        1
    }
}
impl TryFrom<u32> for Schema {
    type Error = &'static str;
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        if value == 1 {
            Ok(Self)
        } else {
            Err("unsupported schema")
        }
    }
}

/// One correlated control request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    /// Bounded caller identity for correlation and mutation outcome lookup.
    pub request_id: Identifier,
    /// Authorized operation and its arguments.
    pub op: Op,
}
sampled_enum! {
/// Operations to be dispatched by the supervisor; no command strings or paths.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "args", deny_unknown_fields)]
pub enum Op, op_samples {
    /// Supervisor liveness and completed iteration age.
    Ping {},
    /// Cached overview.
    Status {},
    /// Fresh staged health check.
    Check {},
    /// Clear administrative disconnection and optionally prefer an exit.
    Connect {
        /// Validated immutable exit identity.
        exit: Option<Identifier> = Some(Identifier("ch1".into())),
    },
    /// Close routes and lower exits, verifying closure before success.
    Disconnect {},
    /// Converge to an immutable version (head when omitted).
    Apply {
        /// Selected version; None means head.
        version: Option<u64> = Some(2),
        /// Render a plan without executing it.
        dry_run: bool = true,
    },
    /// Inspect the persistent quarantine latch.
    RepairStatus {},
    /// Explicitly clear quarantine. Optional CLI prose is reduced to an enum.
    RepairClear {},
    /// Commit validated site TOML with an optimistic parent precondition.
    Commit {
        /// Expected head; None means a fresh store.
        parent: Option<u64> = Some(1),
        /// Public configuration with secret references, never key material.
        toml: String = include_str!("../../scupper-core/tests/fixtures/site-m2.toml").into(),
        /// Bounded audit reason.
        reason: Reason = Reason::Operator,
    },
}
}

vocabulary!(
    ApiErrorCode,
    "Stable machine-readable error codes.",
    InvalidRequest,
    RequestTooLarge,
    UnsupportedSchema,
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    SupervisorUnavailable,
    PersistenceUnavailable,
    Timeout,
    Internal
);
/// Public error with a stable code and no reflected input or diagnostic string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiError {
    /// Stable caller-visible classification.
    pub code: ApiErrorCode,
}
impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.code)
    }
}
impl std::error::Error for ApiError {}

/// A bounded health summary. Full standalone check JSON remains [`crate::Report`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthSummary {
    /// Health classification, corresponding to CLI exit codes.
    pub verdict: VerdictCode,
    /// Report timestamp.
    pub at: UnixSeconds,
    /// Applied version.
    pub config_version: u64,
    /// Number of caveats; detailed check output is the unchanged core report.
    pub warnings: u32,
}
impl From<&crate::Report> for HealthSummary {
    fn from(report: &crate::Report) -> Self {
        use scupper_core::verdict::v2::Verdict;
        let verdict = match &report.verdict {
            Verdict::Protected { .. } => VerdictCode::Protected,
            Verdict::Unprotected(_) => VerdictCode::Unprotected,
            Verdict::Degraded(_) => VerdictCode::Degraded,
            Verdict::FailClosed(_) => VerdictCode::FailClosed,
            Verdict::Unsupervised { .. } => VerdictCode::Unsupervised,
        };
        Self {
            verdict,
            at: UnixSeconds(report.at),
            config_version: report.config_version,
            warnings: u32::try_from(report.warnings.len()).unwrap_or(u32::MAX),
        }
    }
}
sampled_enum! {
/// Successful reply alphabet, with one result per operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data", deny_unknown_fields)]
pub enum OpResult, result_samples {
    /// A missing age means no complete iteration has finished yet.
    Ping {
        /// Monotonic age in whole seconds, supplied by the supervisor.
        last_complete_iteration_age: Option<u64> = Some(2),
    },
    /// Cached health and its age.
    Status {
        /// Cached health.
        health: HealthSummary = sample_health(),
        /// Monotonic age in seconds.
        age: u64 = 3,
    },
    /// Fresh health summary.
    Check {
        /// Fresh result.
        health: HealthSummary = sample_health(),
    },
    /// Selected exit after connection was verified.
    Connect {
        /// Observed active exit.
        exit: Identifier = Identifier("ch1".into()),
    },
    /// Observed closure completed.
    Disconnect {},
    /// Applied version or proposed version for a dry run.
    Apply {
        /// Selected immutable version.
        version: u64 = 2,
        /// True when no mutation was executed.
        dry_run: bool = false,
    },
    /// Persistent quarantine summary.
    RepairStatus {
        /// Whether the latch is set.
        quarantined: bool = true,
        /// Bounded explanation when set.
        reason: Option<Reason> = Some(Reason::RepairBudget),
    },
    /// Quarantine was explicitly cleared.
    RepairClear {},
    /// Committed immutable version.
    Commit {
        /// New version.
        version: u64 = 2,
    },
}
}
/// Correlated schema-1 control response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
    /// Echoed correlation identifier.
    pub request_id: Identifier,
    /// Fixed schema discriminator.
    pub schema: Schema,
    /// Typed success or stable error.
    pub result: Result<OpResult, ApiError>,
}

/// Decodes exactly one bounded JSON line and validates operation arguments.
/// TOML is structured configuration, so quotes in valid TOML are intentional;
/// IDs and audit reasons never accept shell syntax or arbitrary strings.
///
/// # Errors
/// Returns a value-free error for oversize, malformed, unknown-field or invalid input.
pub fn decode_request(line: &[u8]) -> Result<Request, ApiError> {
    if line.len() > MAX_REQUEST_SIZE {
        return Err(ApiError {
            code: ApiErrorCode::RequestTooLarge,
        });
    }
    let invalid = || ApiError {
        code: ApiErrorCode::InvalidRequest,
    };
    let body = line.strip_suffix(b"\n").unwrap_or(line);
    if body.contains(&b'\n') || body.contains(&b'\r') {
        return Err(invalid());
    }
    let request: Request = serde_json::from_slice(body).map_err(|_| invalid())?;
    match &request.op {
        Op::Apply {
            version: Some(0), ..
        }
        | Op::Commit {
            parent: Some(0), ..
        } => return Err(invalid()),
        Op::Commit { toml, .. } => {
            let config = scupper_core::config::parse_site(toml).map_err(|_| invalid())?;
            scupper_core::config::validate(config).map_err(|_| invalid())?;
        }
        Op::Ping {}
        | Op::Status {}
        | Op::Check {}
        | Op::Connect { .. }
        | Op::Disconnect {}
        | Op::Apply { .. }
        | Op::RepairStatus {}
        | Op::RepairClear {} => {}
    }
    Ok(request)
}

#[cfg(test)]
mod tests;

#[cfg(test)]
fn sample_health() -> HealthSummary {
    HealthSummary {
        verdict: VerdictCode::Protected,
        at: UnixSeconds(1),
        config_version: 1,
        warnings: 0,
    }
}
