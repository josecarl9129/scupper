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
    /// Explicitly clear quarantine and retain bounded operator context.
    RepairClear {
        /// One line, at most 1024 bytes; retained in durable safety state.
        reason: Option<String> = Some("operator recovery".into()),
    },
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
    Internal,
    DisconnectNotEffective,
    Quarantined,
    NotReady
);
/// Public error with a stable code and no reflected input or diagnostic string.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiError {
    /// Stable caller-visible classification.
    pub code: ApiErrorCode,
    /// Fresh staged report when a disconnect could not prove kernel closure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observation: Option<serde_json::Value>,
}
impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.code)?;
        if let Some(rollback) = self.observation.as_ref().and_then(|o| o.get("rollback")) {
            if rollback["verified"] == true {
                write!(f, ": rolled back to {} (verified)", rollback["version"])?;
            } else if rollback["closed"] == true {
                write!(f, ": rollback failed: closed")?;
            } else {
                write!(f, ": rollback failed: closure unverified")?;
            }
        }
        Ok(())
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
/// Cached public kernel facts; unknown values remain null.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelObservation {
    /// Canonical match with the applied ruleset.
    pub ruleset_exact: Option<bool>,
    /// Observed global IPv4 forwarding gate.
    pub forwarding_v4: Option<i64>,
    /// Observed global IPv6 forwarding gate.
    pub forwarding_v6: Option<i64>,
    /// Observed IPv4 default, including missing and unreachable.
    pub default_v4: Option<String>,
    /// Observed IPv6 default, including missing and unreachable.
    pub default_v6: Option<String>,
    /// Observed link state without addresses, peer keys or endpoints.
    pub links: Vec<LinkObservation>,
}
/// Cached operational state of one namespace link.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinkObservation {
    /// Kernel interface name, including foreign names.
    pub name: String,
    /// Whether the link was up.
    pub up: Option<bool>,
    /// Whether any peers were present.
    pub peers_present: Option<bool>,
}

/// Last completed reconciler observation and attempted action categories.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TickObservation {
    /// Whether all required tick observations completed.
    pub complete: bool,
    /// Safety observation time in milliseconds.
    pub safety_ms: u64,
    /// Attempted action categories, without addresses or command strings.
    pub steps: Vec<crate::StepKind>,
    /// Failed action categories.
    pub failed_steps: Vec<crate::StepKind>,
    /// Last kernel snapshot, independent of the actions attempted afterward.
    pub kernel: Option<KernelObservation>,
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
        /// Age of the running tick in seconds; null while idle.
        #[serde(default)]
        current_iteration_age: Option<u64> = None,
        /// Identity of the supervisor's held namespace.
        netns: scupper_core::verdict::v2::NetnsIdentity = scupper_core::verdict::v2::NetnsIdentity { device: 1, inode: 2 },
        /// Applied immutable version.
        version: u64 = 1,
        /// Persistent quarantine state.
        quarantined: bool = false,
        /// Durable administrative intent.
        selection: scupper_core::verdict::v2::Selection = scupper_core::verdict::v2::Selection::Auto,
    },
    /// Cached health and its age.
    Status {
        /// Cached health.
        health: HealthSummary = sample_health(),
        /// Monotonic age in seconds.
        age: u64 = 3,
        /// Cached reconcile observations; this is not a fresh full check.
        observations: TickObservation = TickObservation { kernel: Some(KernelObservation { links: vec![LinkObservation { name: "ex-ch1".into(), up: Some(true), peers_present: Some(true) }], ..KernelObservation::default() }), ..TickObservation::default() },
    },
    /// Fresh health summary.
    Check {
        /// Fresh result.
        health: HealthSummary = sample_health(),
        /// Complete schema-1 staged report, retaining violation details.
        report: serde_json::Value = serde_json::Value::Null,
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
        /// Same-version repair preview; never executed before the full boot.
        repair_plan: Vec<crate::StepKind> = vec![crate::StepKind::WriteSysctl],
        /// Ordered target-version boot operations, without kernel command text.
        plan: Vec<crate::StepKind> = vec![crate::StepKind::VerifyRuleset],
    },
    /// Persistent quarantine summary.
    RepairStatus {
        /// Whether the latch is set.
        quarantined: bool = true,
        /// Bounded explanation when set.
        reason: Option<String> = Some("safety repair budget exhausted".into()),
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
    /// True when the result is a retained outcome of an earlier execution.
    #[serde(default)]
    pub replayed: bool,
    /// Wall-clock time of the original observation; cached claims retain this time.
    #[serde(default)]
    pub observed_at: Option<UnixSeconds>,
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
            observation: None,
        });
    }
    let invalid = || ApiError {
        code: ApiErrorCode::InvalidRequest,
        observation: None,
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
        | Op::RepairStatus {} => {}
        Op::RepairClear { reason } => {
            if reason
                .as_ref()
                .is_some_and(|text| text.len() > 1024 || text.contains(['\n', '\r']))
            {
                return Err(invalid());
            }
        }
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
