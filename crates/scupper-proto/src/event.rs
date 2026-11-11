//! Audit records deliberately exclude arbitrary strings and network observations.
use crate::{Identifier, UnixSeconds, sampled_enum, vocabulary};
use scupper_core::{
    failover::{FailClosedReason, FailoverEvent},
    planner::{ClearLatch, PlannerEvent, Step},
};
use serde::{Deserialize, Serialize};
use std::time::Duration;

sampled_enum! {
/// Identity that authorized or originated an event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum Actor, actor_samples {
    /// Supervisor or its worker.
    Daemon,
    /// Local peer credentials.
    Local {
        /// Unix user ID.
        uid: u32 = 1000,
    },
    /// Authenticated tunnel principal.
    Device {
        /// Immutable device ID.
        id: Identifier = Identifier("device-1".into()),
        /// Site user ID.
        user: Identifier = Identifier("user-1".into()),
    },
    /// Boot process.
    Boot,
}
}

vocabulary!(
    Reason,
    "Closed, value-free operational reasons.",
    Operator,
    HealthFailure,
    AdminDisconnected,
    NoHealthyExit,
    PinnedExitDown,
    Quarantined,
    ObservationUnknown,
    EdgeDead,
    RepairBudget,
    SafetyDrift,
    ExecutionFailed,
    StateWrite,
    BootWrite,
    EventWrite,
    TornLine,
    Recovery,
    UncleanStop,
    QueueOverflow,
    UnknownObject,
    HeartbeatSecret,
    HeartbeatAccount,
    HeartbeatHttp,
    HeartbeatDeadline,
    HeartbeatExec,
    HeartbeatTls,
    HeartbeatTransport,
    HeartbeatRtoRead,
    HeartbeatWriteRefused,
    HeartbeatReset,
    HeartbeatCertificate,
    HeartbeatWorkerLimit,
    Stale,
    AlertPermanent,
    AlertGiveUp,
    AlertSecret,
    AlertAccount,
    AlertExec,
    AlertInternal,
    AlertPersistence
);
vocabulary!(
    ObjectKind,
    "Bounded repair object categories; raw planner keys never enter the log.",
    Ruleset,
    ForeignLink,
    Peer,
    ExitIp,
    TcHook,
    Forwarding,
    Sysctl,
    Route,
    Link,
    Endpoint,
    Rule,
    Latch,
    Unknown
);
vocabulary!(
    RepairClass,
    "Effect of a repair on applied policy.",
    Restore,
    Tighten
);
vocabulary!(
    Outcome,
    "Bounded operation outcome.",
    Succeeded,
    Failed,
    Recovered
);
vocabulary!(
    Health,
    "Bounded exit health.",
    Unknown,
    Healthy,
    Unconfirmed,
    Suspect,
    Down,
    Recovering
);
vocabulary!(
    VerdictCode,
    "Health codes from DESIGN section 12.",
    Protected,
    ObservationError,
    Unprotected,
    Degraded,
    FailClosed,
    Unsupervised
);
vocabulary!(
    Command,
    "Administrative action alphabet.",
    Connect,
    Disconnect,
    Apply,
    RepairClear,
    Commit
);
vocabulary!(
    StepKind,
    "Execution category only; no step arguments or rendered source.",
    ForwardingOff,
    ForwardingOn,
    LoadRuleset,
    VerifyRuleset,
    FlushConntrack,
    WriteSysctl,
    ReadBackSysctls,
    RouteReplace,
    RouteDelete,
    LinkDown,
    LinkForwardingOff,
    LinkCreate,
    LinkReconfigure,
    RuleDelete,
    TcDelete,
    ReResolveEndpoint,
    PersistLatch,
    Emit,
    EventLog
);

/// Numeric release identity, avoiding unbounded version strings in audit records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Release {
    /// Major version.
    pub major: u32,
    /// Minor version.
    pub minor: u32,
    /// Patch version.
    pub patch: u32,
}

// Every declaration requires a sample. Both enumeration and exhaustive sample
// matching are generated here, so a new kind cannot silently escape privacy tests.
macro_rules! event_kinds {
    ($( $name:ident { $( $field:ident : $ty:ty = $sample:expr ),* $(,)? } ),+ $(,)?) => {
        /// Closed audit alphabet. `kind` names the variant and `data` holds its fields.
        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(tag = "kind", content = "data", deny_unknown_fields)]
        pub enum EventKind { $(#[doc = stringify!($name)] $name { $(#[doc = stringify!($field)] $field: $ty),* }),+ }
        #[cfg(test)]
        impl EventKind {
            pub(crate) const NAMES: &'static [&'static str] = &[$(stringify!($name)),+];
        }
        #[cfg(test)]
        pub(crate) fn event_samples() -> Vec<EventKind> {
            fn sample(kind: EventKind) -> EventKind {
                match kind { $(EventKind::$name { .. } => EventKind::$name { $($field: $sample),* }),+ }
            }
            vec![$(sample(EventKind::$name { $($field: $sample),* })),+]
        }
    }
}
event_kinds! {
    ConfigCommitted { version: u64 = 2, parent: Option<u64> = Some(1), sha: [u8; 32] = [0; 32], reason: Reason = Reason::Operator },
    ConfigApplied { version: u64 = 2 },
    ApplyFailed { version: Option<u64> = Some(2), step: StepKind = StepKind::LoadRuleset, reason: Reason = Reason::ExecutionFailed },
    Failover { from: Identifier = Identifier("ch1".into()), to: Identifier = Identifier("ch2".into()), cause: Reason = Reason::HealthFailure },
    Failback { from: Identifier = Identifier("ch2".into()), to: Identifier = Identifier("ch1".into()) },
    FailClosedStarted { reason: Reason = Reason::NoHealthyExit, exit: Option<Identifier> = Some(Identifier("ch1".into())) },
    FailClosedEnded { duration: Duration = Duration::from_secs(4) },
    ExitHealthChanged { exit: Identifier = Identifier("ch1".into()), from: Health = Health::Healthy, to: Health = Health::Down },
    DriftDetected { object: ObjectKind = ObjectKind::Ruleset, reason: Reason = Reason::SafetyDrift },
    Repair { kind: StepKind = StepKind::LoadRuleset, class: RepairClass = RepairClass::Restore, result: Outcome = Outcome::Succeeded },
    RepairSuppressed { object: ObjectKind = ObjectKind::Ruleset },
    CheckVerdictChanged { from: VerdictCode = VerdictCode::Protected, to: VerdictCode = VerdictCode::Unprotected, reason: ObjectKind = ObjectKind::Ruleset },
    VerdictChanged { from: VerdictCode = VerdictCode::Protected, to: VerdictCode = VerdictCode::FailClosed },
    AdminAction { command: Command = Command::RepairClear, reason: Option<String> = None },
    ControlUnavailable { count: u64 = 1 },
    DaemonStarted { version: Release = Release {major: 0, minor: 1, patch: 0} },
    Boot { result: Outcome = Outcome::Recovered, step: StepKind = StepKind::EventLog },
    QuarantineChanged { active: bool = true },
    EventSkipped { seq: u64 = 1 },
    SinkFailed { sink: Identifier = Identifier("primary".into()), reason: Reason = Reason::ExecutionFailed },
    HeartbeatFailed { reason: Reason = Reason::EdgeDead },
    HeartbeatSkipped { reason: Reason = Reason::Stale },
    HeartbeatCheckDetached {},
    PersistenceFailed { reason: Reason = Reason::EventWrite },
    Flapping {},
    MemoryReplay { dropped: u64 = 0, local_first: u64 = 1, local_last: u64 = 3, replayed: u64 = 3 },
    EventGap { reason: Reason = Reason::QueueOverflow, dropped: u64 = 3, first_seq: u64 = 1, last_seq: u64 = 3 },
}

/// Exactly the seven top-level fields specified by DESIGN section 13.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    /// Monotonic sequence within one gateway's audit history.
    pub seq: u64,
    /// Caller-supplied UTC timestamp.
    pub at: UnixSeconds,
    /// Event discriminator and its typed data, flattened to `kind` and `data`.
    #[serde(flatten)]
    pub kind: EventKind,
    /// Originating identity.
    pub actor: Actor,
    /// Immutable gateway identity.
    pub gateway: Identifier,
    /// Applied or relevant immutable configuration version, if established.
    pub config_version: Option<u64>,
}

impl From<FailoverEvent> for EventKind {
    fn from(event: FailoverEvent) -> Self {
        match event {
            FailoverEvent::Failover { from, to } => Self::Failover {
                from: Identifier::from(&from),
                to: Identifier::from(&to),
                cause: Reason::HealthFailure,
            },
            FailoverEvent::Failback { from, to } => Self::Failback {
                from: Identifier::from(&from),
                to: Identifier::from(&to),
            },
            FailoverEvent::FailClosedStarted(reason) => {
                let (reason, exit) = match reason {
                    FailClosedReason::AdminDisconnected => (Reason::AdminDisconnected, None),
                    FailClosedReason::NoHealthyExit => (Reason::NoHealthyExit, None),
                    FailClosedReason::PinnedExitDown(exit) => {
                        (Reason::PinnedExitDown, Some(Identifier::from(&exit)))
                    }
                };
                Self::FailClosedStarted { reason, exit }
            }
            FailoverEvent::FailClosedEnded { duration } => Self::FailClosedEnded { duration },
            FailoverEvent::Flapping => Self::Flapping {},
        }
    }
}
impl From<PlannerEvent> for EventKind {
    fn from(event: PlannerEvent) -> Self {
        match event {
            PlannerEvent::RepairSuppressed { object } => Self::RepairSuppressed {
                object: object_kind(&object),
            },
            PlannerEvent::SafetyDrift { object } => Self::DriftDetected {
                object: object_kind(&object),
                reason: Reason::SafetyDrift,
            },
            PlannerEvent::ObservationUnknown => Self::DriftDetected {
                object: ObjectKind::Unknown,
                reason: Reason::ObservationUnknown,
            },
            PlannerEvent::IngressQuarantined => Self::QuarantineChanged { active: true },
            PlannerEvent::PersistenceFailed => Self::PersistenceFailed {
                reason: Reason::StateWrite,
            },
            PlannerEvent::EdgeDead => Self::DriftDetected {
                object: ObjectKind::Unknown,
                reason: Reason::EdgeDead,
            },
            PlannerEvent::ReplanAfterFailure {
                failed,
                applied_version,
            } => Self::ApplyFailed {
                version: Some(applied_version),
                step: StepKind::from(failed.as_ref()),
                reason: Reason::ExecutionFailed,
            },
            PlannerEvent::AdminAction { action } => Self::AdminAction {
                reason: None,
                command: match action {
                    ClearLatch::RepairClear => Command::RepairClear,
                    ClearLatch::VerifiedFullApply => Command::Apply,
                },
            },
        }
    }
}
fn object_kind(object: &str) -> ObjectKind {
    match object.split(':').next().unwrap_or("") {
        "safety" => match object {
            "safety:ruleset" => ObjectKind::Ruleset,
            "safety:foreign-link" => ObjectKind::ForeignLink,
            "safety:tc-hook" => ObjectKind::TcHook,
            _ => ObjectKind::Unknown,
        },
        "ruleset" => ObjectKind::Ruleset,
        "forwarding" => ObjectKind::Forwarding,
        "sysctl" => ObjectKind::Sysctl,
        "route" | "extra-route" => ObjectKind::Route,
        "link" | "exit-down" | "host-link" | "peer-containment" => ObjectKind::Link,
        "foreign-link" => ObjectKind::ForeignLink,
        "tc" => ObjectKind::TcHook,
        "rule" => ObjectKind::Rule,
        "endpoint" => ObjectKind::Endpoint,
        "latch" => ObjectKind::Latch,
        _ => ObjectKind::Unknown,
    }
}
impl From<&Step> for StepKind {
    fn from(step: &Step) -> Self {
        match step {
            Step::ForwardingOff => Self::ForwardingOff,
            Step::ForwardingOn { .. } => Self::ForwardingOn,
            Step::LoadRuleset { .. } => Self::LoadRuleset,
            Step::VerifyRuleset { .. } => Self::VerifyRuleset,
            Step::FlushConntrack => Self::FlushConntrack,
            Step::WriteSysctl { .. } => Self::WriteSysctl,
            Step::ReadBackSysctls => Self::ReadBackSysctls,
            Step::RouteReplace { .. } => Self::RouteReplace,
            Step::RouteDelete { .. } => Self::RouteDelete,
            Step::LinkDown { .. } => Self::LinkDown,
            Step::LinkForwardingOff { .. } => Self::LinkForwardingOff,
            Step::LinkCreate { .. } => Self::LinkCreate,
            Step::LinkReconfigure { .. } => Self::LinkReconfigure,
            Step::RuleDelete { .. } => Self::RuleDelete,
            Step::TcDelete { .. } => Self::TcDelete,
            Step::ReResolveEndpoint { .. } => Self::ReResolveEndpoint,
            Step::PersistLatch { .. } => Self::PersistLatch,
            Step::Emit(_) => Self::Emit,
        }
    }
}
