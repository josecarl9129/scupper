//! Closed repair and execution alphabets and caller-owned planning state.

use crate::{
    config::ExitId,
    failover::MonoTime,
    parse::RouteEntry,
    render::{Family, RouteTarget, SysctlKey},
    verdict::v2::PeerObs,
};
use ipnet::IpNet;
use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};

/// Canonical rendered ruleset identity (not a hash of nft source text).
pub type Fingerprint = [u8; 32];

/// Failed observations cannot establish safety.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Known<T> {
    /// The observation failed or was not collected.
    #[default]
    Unknown,
    /// A successfully observed value.
    Value(T),
}
impl<T> Known<T> {
    /// Borrows a successfully observed value.
    #[must_use]
    pub const fn value(&self) -> Option<&T> {
        match self {
            Self::Unknown => None,
            Self::Value(value) => Some(value),
        }
    }
}

/// Whole-namespace semantic ruleset state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ruleset {
    /// No ruleset is installed.
    Absent,
    /// Canonical equality was checked on this tick.
    Verified(Fingerprint),
    /// Loaded or observed, but not verified against desired state.
    Unverified(Fingerprint),
}

/// Exact route identity for deletion; collectors must retain these fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteKey {
    /// Address family, including rejecting defaults with no IP literal.
    pub family: Family,
    /// Reused parser record preserves source selectors, metrics and next hops;
    /// health summaries alone cannot identify a safe deletion command.
    pub entry: RouteEntry,
}

/// Public link settings not included in the existing peer/address observations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkSettings {
    /// Tunnel MTU.
    pub mtu: u32,
    /// Client public identity; exits use their configured local secret reference.
    pub public_key: Option<[u8; 32]>,
    /// Client listener port; zero for exits.
    pub listen_port: u32,
    /// Per-peer persistent keepalive, absent for client peers.
    pub keepalives: BTreeMap<[u8; 32], Duration>,
}

/// Validated public configuration to reapply; contains no secret material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkSpec {
    /// Namespace interface name.
    pub name: String,
    /// Configured addresses with prefix lengths.
    pub addresses: Vec<IpNet>,
    /// Public peers; exit endpoints are reset only by explicit handshake repair.
    pub peers: Vec<PeerObs>,
    /// Listener, MTU and keepalive configuration.
    pub settings: LinkSettings,
    /// Whether the final link should be administratively up.
    pub up: bool,
}

/// Independently cuttable boundaries of boot step 4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkPhase {
    /// Delete only a positively owned, down, empty leftover in the host.
    CleanupHost,
    /// Add `WireGuard` in the host, administratively down.
    HostAddDown,
    /// Move the down link into the held namespace.
    Move,
    /// Configure peers, addresses and public link settings, still down.
    Configure,
    /// Raise only a configured link (or leave a disconnected exit down).
    Up,
}

/// Persisted quarantine identity. Persistence supplies the wall-clock timestamp.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Latch {
    /// Failed persistence or unreadable safety evidence, clearable by connect.
    pub uncertain: bool,
    /// Why recurring safety drift closed the gateway.
    pub reason: String,
    /// Stable budget object key.
    pub object: String,
}

/// Repairs restore applied policy or tighten containment, exhaustively.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepairClass {
    /// Restore the already applied configuration.
    Restore,
    /// Remove a possible path or close the forwarding gate.
    Tighten,
}

/// One budgeted drift repair, plus unbudgeted emergency controls.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Repair {
    /// Reload, verify and flush with the forwarding gate closed.
    RulesetReload,
    /// Raise forwarding with the executor's same-tick fingerprint check.
    ForwardingRestore,
    /// Write one hardening key and read back.
    HardeningSysctl {
        /// Desired key.
        key: String,
    },
    /// Replace a family default with applied failover intent.
    RouteReplace {
        /// Family.
        family: Family,
        /// Permitted target.
        target: RouteTarget,
    },
    /// Delete an unexpected route.
    ExtraRouteDelete {
        /// Complete deletion identity.
        route: RouteKey,
    },
    /// Rebuild a missing owned tunnel using boot step 4.
    LinkRecreate {
        /// Configured name.
        name: String,
    },
    /// Reapply addresses, peers or link settings.
    LinkReconfigure {
        /// Configured name.
        name: String,
    },
    /// Disable, but never delete, a foreign link.
    ForeignLinkDown {
        /// Raw interface name.
        name: String,
    },
    /// Close ingress on an owned link with positively mismatched `AllowedIPs`.
    PeerContainment {
        /// Configured link name.
        name: String,
    },
    /// Delete an unexpected RPDB entry.
    ExtraRuleDelete {
        /// Exact rule identity.
        rule: String,
    },
    /// Remove an unexpected tc/XDP hook.
    TcHookDelete {
        /// Raw interface name.
        name: String,
        /// Exact hook identity.
        hook: String,
    },
    /// Re-resolve and reset the configured endpoint to provoke a handshake.
    ExitRehandshake {
        /// Configured exit identity.
        exit: ExitId,
    },
    /// Record a new memory quarantine after closing forwarding.
    PersistLatch {
        /// Reason.
        reason: String,
        /// Budget object.
        object: String,
    },
    /// Emergency gate, never budgeted or debounced.
    ForwardingOff,
    /// Administrative disconnect also closes exit links.
    ExitDown {
        /// Configured exit name.
        name: String,
    },
    /// Remove a positively owned leftover host link before resuming boot.
    HostLinkCleanup {
        /// Configured link name.
        name: String,
    },
}
impl Repair {
    /// Total classification; adding a repair requires an explicit decision.
    #[must_use]
    pub const fn class(&self) -> RepairClass {
        match self {
            Self::RulesetReload
            | Self::ForwardingRestore
            | Self::HardeningSysctl { .. }
            | Self::LinkRecreate { .. }
            | Self::LinkReconfigure { .. }
            | Self::ExitRehandshake { .. }
            | Self::HostLinkCleanup { .. } => RepairClass::Restore,
            Self::RouteReplace { target, .. } => match target {
                RouteTarget::Exit(_) => RepairClass::Restore,
                RouteTarget::Unreachable => RepairClass::Tighten,
            },
            Self::ExtraRouteDelete { .. }
            | Self::ForeignLinkDown { .. }
            | Self::PeerContainment { .. }
            | Self::ExtraRuleDelete { .. }
            | Self::TcHookDelete { .. }
            | Self::PersistLatch { .. }
            | Self::ForwardingOff
            | Self::ExitDown { .. } => RepairClass::Tighten,
        }
    }
    pub(super) fn object(&self) -> String {
        match self {
            Self::RulesetReload => "ruleset".into(),
            Self::ForwardingRestore | Self::ForwardingOff => "forwarding".into(),
            Self::HardeningSysctl { key } => format!("sysctl:{key}"),
            Self::RouteReplace { family, .. } => format!("route:{family:?}"),
            Self::ExtraRouteDelete { route } => format!(
                "extra-route:{:?}:{:?}:{:?}:{:?}:{:?}:{:?}",
                route.family,
                route.entry.table,
                route.entry.dst,
                route.entry.from,
                route.entry.metric,
                route.entry.dev
            ),
            Self::LinkRecreate { name } | Self::LinkReconfigure { name } => format!("link:{name}"),
            Self::ExitDown { name } => format!("exit-down:{name}"),
            Self::HostLinkCleanup { name } => format!("host-link:{name}"),
            Self::PeerContainment { name } => format!("peer-containment:{name}"),
            Self::ForeignLinkDown { name } => format!("foreign-link:{name}"),
            Self::ExtraRuleDelete { rule } => format!("rule:{rule}"),
            Self::TcHookDelete { name, hook } => format!("tc:{name}:{hook}"),
            Self::ExitRehandshake { exit } => format!("endpoint:{exit}"),
            Self::PersistLatch { object, .. } => object.clone(),
        }
    }
    /// Namespace-wide safety class, independent of deletion identity.
    #[must_use]
    pub const fn safety_class(&self) -> Option<SafetyClass> {
        match self {
            Self::RulesetReload => Some(SafetyClass::Ruleset),
            Self::ForeignLinkDown { .. } => Some(SafetyClass::ForeignLink),
            Self::TcHookDelete { .. } => Some(SafetyClass::TcHook),
            _ => None,
        }
    }
}

/// Stable namespace-wide budgets for reopening after containment drift.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SafetyClass {
    /// Positive ruleset mismatch; Unknown never counts.
    Ruleset,
    /// Any unexpected live link.
    ForeignLink,
    /// Any unexpected tc/XDP hook.
    TcHook,
}
impl SafetyClass {
    /// Stable bookkeeping key; deletion identities never enter this key.
    #[must_use]
    pub const fn key(self) -> &'static str {
        match self {
            Self::Ruleset => "safety:ruleset",
            Self::ForeignLink => "safety:foreign-link",
            Self::TcHook => "safety:tc-hook",
        }
    }
}

/// A structured hardening key that cannot name a forwarding control.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HardeningKey(SysctlKey);
impl HardeningKey {
    /// Rejects every forwarding key, including per-device and default scopes.
    #[must_use]
    pub fn new(key: SysctlKey) -> Option<Self> {
        matches!(
            key.name,
            "rp_filter"
                | "accept_redirects"
                | "send_redirects"
                | "accept_source_route"
                | "accept_ra"
                | "autoconf"
                | "proxy_arp"
                | "proxy_ndp"
                | "route_localnet"
                | "nf_conntrack_tcp_loose"
        )
        .then_some(Self(key))
    }
    /// Structured kernel key.
    #[must_use]
    pub const fn sysctl(&self) -> &SysctlKey {
        &self.0
    }
}
impl std::fmt::Display for HardeningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// Escalations require lifecycle work outside this pure kernel planner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Escalation {
    /// Rebind the name to the held inode; do not create another namespace.
    NamespaceNameGone,
    /// Stop edge, rebuild through boot, then restart edge.
    NamespaceInodeGone,
    /// Restart edge in the held namespace.
    EdgeInAnotherNamespace,
    /// Boot must refuse to delete a host link that is not positively ours.
    HostLinkCollision(String),
    /// A configured namespace name belongs to a foreign device.
    NamespaceLinkCollision(String),
}

/// Namespace lifecycle information supplied by the held-handle collector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamespaceState {
    /// The expected held namespace identity has not been established.
    Unknown,
    /// Name, held inode and edge all agree.
    Ready,
    /// Owned name is missing, but the held inode is alive.
    NameGone,
    /// No holder of the owned inode remains.
    InodeGone,
    /// Edge and the held namespace disagree.
    EdgeElsewhere,
}

/// Local event alphabet; event storage maps this in M2-2m.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlannerEvent {
    /// A fourth repair in the sliding window was refused.
    RepairSuppressed {
        /// Budget object.
        object: String,
    },
    /// Containment drift was acted on immediately.
    SafetyDrift {
        /// Affected object.
        object: String,
    },
    /// Failed collection forces the emergency gate closed.
    ObservationUnknown,
    /// Two consecutive incomplete link/tc inventories stopped client ingress.
    IngressQuarantined,
    /// Non-fatal latch persistence failure; the executor retains the memory latch.
    PersistenceFailed,
    /// The edge is supervised by systemd; the planner only alerts.
    EdgeDead,
    /// A failed execution is being reconciled toward the previous applied version.
    ReplanAfterFailure {
        /// Failed step, for bounded operational diagnostics.
        failed: Box<Step>,
        /// Previous applied version, unchanged by planning.
        applied_version: u64,
    },
    /// An authorized administrative transition cleared quarantine.
    AdminAction {
        /// Explicit administrative source.
        action: ClearLatch,
    },
}

/// The complete idempotent execution alphabet. No arbitrary accept-rule writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// Write global forwarding zero first in both families, then default and
    /// per-link forwarding. An absent client device is already closed (ENOENT
    /// is non-fatal for that device). Other failures still allow later tightening.
    ForwardingOff,
    /// Recheck canonical equality on this tick and refuse while quarantined,
    /// including a memory latch. Write global, default and per-link forwarding
    /// in both families only after the preceding same-plan conntrack flush.
    ForwardingOn {
        /// Required whole-namespace fingerprint.
        requires: Fingerprint,
    },
    /// Check and load the rendered applied ruleset atomically.
    LoadRuleset {
        /// Canonical expected identity.
        fingerprint: Fingerprint,
        /// Applied rendered source.
        rendered: String,
    },
    /// Verify canonical equality after the load; failure stops execution.
    VerifyRuleset {
        /// Required fingerprint.
        fingerprint: Fingerprint,
    },
    /// Drop flows established during a ruleset gap or route switch.
    FlushConntrack,
    /// Write a hardening key only; forwarding uses guarded steps above.
    WriteSysctl {
        /// Structured kernel key.
        key: HardeningKey,
        /// Desired decimal value.
        value: String,
    },
    /// Read back all hardening values; mismatch stops execution.
    ReadBackSysctls,
    /// Replace a family default with a configured exit or unreachable.
    RouteReplace {
        /// Address family.
        family: Family,
        /// Permitted target.
        target: RouteTarget,
    },
    /// Delete one extra route by its complete identity.
    RouteDelete {
        /// Route identity.
        route: RouteKey,
    },
    /// Bring down a named interface, never delete it.
    LinkDown {
        /// Raw interface name.
        name: String,
    },
    /// Close forwarding on a newly moved or reconfigured device before `LinkUp`.
    LinkForwardingOff {
        /// Namespace interface name.
        name: String,
    },
    /// One independently executable part of the boot link sequence.
    LinkCreate {
        /// Public validated configuration.
        link: LinkSpec,
        /// Failure boundary.
        phase: LinkPhase,
    },
    /// Restore configuration; executor keeps the link down until complete.
    LinkReconfigure {
        /// Public validated configuration.
        link: LinkSpec,
    },
    /// Delete an unexpected rule by its exact identity.
    RuleDelete {
        /// RPDB entry.
        rule: String,
    },
    /// Delete an unexpected traffic-control or XDP hook.
    TcDelete {
        /// Interface name.
        name: String,
        /// Hook identity.
        hook: String,
    },
    /// Re-set the configured endpoint (never compare learned endpoints).
    ReResolveEndpoint {
        /// Configured exit.
        exit: ExitId,
    },
    /// Persist the latch already adopted from `Plan::latch`, after tightening.
    /// Non-fatal: on failure continue execution, retain the memory latch and
    /// raise `PlannerEvent::PersistenceFailed`. Disk I/O never blocks tightening.
    PersistLatch {
        /// Reason.
        reason: String,
        /// Budget object.
        object: String,
    },
    /// Publish a local operational event. Non-fatal: continue if delivery fails.
    Emit(PlannerEvent),
}

/// Executor action after a failed step. Policies are intrinsic to [`Step`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepFailure {
    /// Stop immediately, re-observe and replan.
    Stop,
    /// Continue later `Contain`/`NonFatal` steps, skipping every later `Stop` step.
    Contain,
    /// Failure changes nothing; continue with the existing failure policy.
    NonFatal,
}
impl Step {
    /// Failure policy carried by this step. Failed containment blocks every
    /// later `Stop` (Restore) step, while later `Contain`/`NonFatal` steps still run.
    /// `NonFatal` failures neither block Restore nor clear containment failure.
    #[must_use]
    pub const fn failure(&self) -> StepFailure {
        match self {
            Self::ForwardingOff
            | Self::LinkDown { .. }
            | Self::LinkForwardingOff { .. }
            | Self::TcDelete { .. }
            | Self::RuleDelete { .. }
            | Self::RouteDelete { .. }
            | Self::RouteReplace {
                target: RouteTarget::Unreachable,
                ..
            } => StepFailure::Contain,
            Self::PersistLatch { .. } | Self::Emit(_) => StepFailure::NonFatal,
            Self::ForwardingOn { .. }
            | Self::LoadRuleset { .. }
            | Self::VerifyRuleset { .. }
            | Self::FlushConntrack
            | Self::WriteSysctl { .. }
            | Self::ReadBackSysctls
            | Self::RouteReplace {
                target: RouteTarget::Exit(_),
                ..
            }
            | Self::LinkCreate { .. }
            | Self::LinkReconfigure { .. }
            | Self::ReResolveEndpoint { .. } => StepFailure::Stop,
        }
    }
}

/// Three repair attempts per object in a ten-minute sliding window.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Budgets {
    /// Successful planning reservations; execution failure still counts an attempt.
    pub attempts: BTreeMap<String, Vec<MonoTime>>,
    /// Suppression transitions already reported; expires with its budget.
    pub suppressed: BTreeSet<String>,
    /// Tightening seen while reopening was blocked; charge these classes when
    /// forwarding is eventually restored, including on a later observation.
    pub pending_safety: BTreeSet<SafetyClass>,
    /// A planner-issued gate closure awaits reopening or observed recovery.
    /// Its reopening is not charged to the external forwarding-fight budget.
    pub closed_by_planner: bool,
    /// Client links downed for unknown-inventory quarantine, cleared when
    /// observed up. Restoring only their UP state consumes no repair budget.
    pub downed_by_planner: BTreeSet<String>,
    /// The executor has reported a failed latch persistence attempt. Retain
    /// until persistence is observed or an administrator clears the latch.
    pub persistence_failed: bool,
}
impl Budgets {
    pub(super) fn expire(&mut self, now: MonoTime) {
        self.attempts.retain(|_, times| {
            times.retain(|time| now.elapsed_since(*time) < Duration::from_secs(600));
            !times.is_empty()
        });
        self.suppressed
            .retain(|key| self.attempts.contains_key(key));
    }
    pub(super) fn reserve(&mut self, object: &str, now: MonoTime) -> bool {
        let times = self.attempts.entry(object.into()).or_default();
        if times.len() >= 3 {
            return false;
        }
        times.push(now);
        true
    }
}

/// Only immediately preceding drift sightings count toward restore debounce.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Debounce {
    /// Object keys seen on the previous call; absence resets that object's streak.
    pub previous: BTreeSet<String>,
    /// Client ingress has already been quarantined for this incomplete inventory.
    pub ingress_quarantined: bool,
}

/// Pure planner output; callers persist/retain returned bookkeeping.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Plan {
    /// Execute in order using each step's [`Step::failure`] policy.
    pub steps: Vec<Step>,
    /// New quarantine decision. Adopt in memory before executing step zero,
    /// without I/O, and union it with persisted quarantine on every later tick.
    pub latch: Option<Latch>,
    /// Updated sliding windows.
    pub budgets: Budgets,
    /// Updated consecutive sightings.
    pub debounce: Debounce,
    /// Lifecycle work; only a gone namespace inode prevents kernel steps.
    pub escalations: Vec<Escalation>,
    /// Admitted repairs, including emergency controls, for classification/auditing.
    pub repairs: Vec<Repair>,
}

/// The only authorized sources of a quarantine-clear transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClearLatch {
    /// Explicit `repair clear` administrative action.
    RepairClear,
    /// Full apply has already been verified by its executor.
    VerifiedFullApply,
}

/// Pure administrative transition; the caller durably persists the cleared latch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LatchTransition {
    /// Safety reservations and pending classes reset by the authorized action.
    pub budgets: Budgets,
    /// Always clear after an authorized explicit action.
    pub latch: Option<Latch>,
    /// Required administrative audit event.
    pub event: PlannerEvent,
}
