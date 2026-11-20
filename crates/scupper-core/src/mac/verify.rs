//! Qualified path walking, planned baseline capture, and evidence-only verdicts.

use super::{
    Error, HopLimitPolicy, Inputs, Interface, PhysicalInterface, Tunnel,
    parse::{self, PfInfo, Resolver, Route, Rule, Rules, SkipFlags},
    policy::{self, Form, Kind, Policy, State},
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

/// Stable, structured refusal causes. Callers persist/notify these separately.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Reason {
    /// Translation can alter or bypass filtering for governed traffic.
    #[error("pf translation present")]
    TranslationPresent,
    /// Nothing of ours is evaluated; responsible process is unknown.
    #[error("Required pf hook missing; responsible process unknown")]
    HookMissing,
    /// An earlier or sibling quick pass could match governed traffic.
    #[error("earlier or sibling quick pass could match governed traffic")]
    QuickPass,
    /// A non-loopback interface bypasses pf.
    #[error("pf skip on non-loopback interface {0}")]
    Skip(Interface),
    /// Unsupported or unqualified surrounding configuration.
    #[error("unsupported pf configuration: {0}")]
    Unsupported(&'static str),
    /// An observation could not be parsed, or a privileged step failed/hung.
    #[error("verification failure: {0}")]
    Observation(&'static str),
    /// A full observation requested repair; retained separately from verifier inputs.
    #[error("enforcement repair required: {0:?}")]
    Repair(Action),
    /// Enforcement could not be established at this observation time.
    #[error("enforcement unknown since {since}")]
    Unknown {
        /// Start of the observation gap in the sleep-counting clock domain.
        since: u64,
    },
    /// Endpoint route recurses into the tunnel.
    #[error("endpoint route recurses into tunnel")]
    RouteRecursion,
    /// No supported physical gateway exists.
    #[error("missing physical gateway")]
    MissingGateway,
    /// No unambiguous selected endpoint path.
    #[error("no unambiguous selected physical endpoint path")]
    AmbiguousPath,
    /// Recorded executable hash or ownership does not match.
    #[error("installed tool hash/owner mismatch")]
    ToolIntegrity,
}
/// Checked recovery sequence; execution belongs to the future helper.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    /// Load/read-back pre-tunnel, flush all states, full verify, then rejoin.
    Rejoin,
    /// Take/record a new pf reference first, then the Rejoin sequence.
    EnableAndRejoin,
    /// Pre-tunnel, flush, full verify, clean old resources, recreate generation.
    RecreateChild,
    /// Replace/read back the current form without stopping the child.
    /// The lifecycle preserves states only while cleanliness remains valid.
    Rerender {
        /// Current installed form.
        form: Form,
    },
}
/// Injected monotonic clock whose elapsed time MUST include system suspension.
/// A wall clock or a monotonic clock which pauses during sleep is not suitable.
pub trait SleepCountingClock {
    /// Elapsed seconds in the same domain as observation start times.
    fn now(&self) -> u64;
}
/// Identity of an intended policy and lifecycle observation round.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Context {
    /// Incremented for every planned anchor replacement.
    pub policy_generation: u64,
    /// Incremented on invalidating lifecycle transitions.
    pub lifecycle_revision: u64,
    /// Incremented only when a reference acquisition is recorded.
    pub acquisition_revision: u64,
    /// Incremented whenever state cleanliness is lost.
    pub state_epoch: u64,
}
/// Evidence about states, supplied by the bounded observation collector.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StateEvidence {
    /// States may have survived an observation gap or bypass.
    Unproven,
    /// Checked all-state flush or qualified exhaustive state validation.
    Clean {
        /// State epoch to which the operation belongs.
        epoch: u64,
        /// Completion time; cannot postdate any required read.
        completed_at: u64,
    },
}
/// An unforgeable successful verification; only `verify` constructs one.
///
/// ```compile_fail
/// use scupper_core::mac::verify::Proof;
/// let proof = Proof { verified_at: 1 };
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof {
    verified_at: u64,
    completed_at: u64,
    expires_at: u64,
    context: Context,
    form: Form,
    tunnel: Option<Tunnel>,
    kind: Kind,
    baseline_hash: [u8; 32],
    states_clean_at: u64,
    transport: Option<Transport>,
}
impl Proof {
    /// Exact verified policy kind; cannot be changed by a consumer.
    #[must_use]
    pub fn kind(&self) -> Kind {
        self.kind
    }

    /// Oldest required observation start, never verification completion time.
    #[must_use]
    pub fn verified_at(&self) -> u64 {
        self.verified_at
    }
    /// Time at which the full verification finished.
    #[must_use]
    pub fn completed_at(&self) -> u64 {
        self.completed_at
    }
    /// Intended policy and lifecycle generations.
    #[must_use]
    pub fn context(&self) -> Context {
        self.context
    }
    /// Observed policy form.
    #[must_use]
    pub fn form(&self) -> Form {
        self.form
    }
    /// Observed child incarnation.
    #[must_use]
    pub fn tunnel(&self) -> Option<&Tunnel> {
        self.tunnel.as_ref()
    }
    /// Expected normalized read-back identity.
    #[must_use]
    pub fn baseline_hash(&self) -> [u8; 32] {
        self.baseline_hash
    }
    /// Checked flush/validation completion.
    #[must_use]
    pub fn states_clean_at(&self) -> u64 {
        self.states_clean_at
    }
    /// Checked selected local address and complete endpoint-route identity.
    #[must_use]
    pub fn transport(&self) -> Option<&Transport> {
        self.transport.as_ref()
    }
    /// Expiry fixed by the verifier and checked by every consumer.
    #[must_use]
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }
}
/// Enforcement status; tunnel handshake health is deliberately absent.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)] // Proofs stay inline for the pure transition API.
pub enum Verdict {
    /// Constructible only by successful complete verification.
    Protected(Proof),
    /// A serialized checked recovery is required.
    Repair(Action),
    /// Known failure; age cannot erase it.
    NotProtected(Reason),
    /// Evidence has never been established in this run.
    NeverVerified,
    /// Observations expired. This is not a cached Protected result.
    Unknown {
        /// First instant at which the evidence became stale.
        since: u64,
    },
}
impl Verdict {
    /// Expire at the status consumer even when the helper stops running.
    #[must_use]
    pub fn at(&self, clock: &impl SleepCountingClock) -> Self {
        if let Self::Protected(proof) = self {
            let expiry = proof.expires_at;
            if clock.now() > expiry {
                return Self::Unknown { since: expiry };
            }
        }
        self.clone()
    }
}
/// Per-OS normalization decisions, supplied by reviewed qualification evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Normalization {
    /// Accept semantic list expansion and preserve actual read-back order.
    pub expanded_lists: bool,
    /// Accept the four documented `ICMPv6` symbolic names.
    pub named_icmp: bool,
    /// Accept pf's implicit `flags S/SA` on TCP.
    pub implicit_tcp_flags: bool,
}
/// Qualified OS record. An empty/mismatched record cannot authorize protection.
#[derive(Clone, Debug)]
pub struct Qualification {
    /// Exact OS build identifier.
    pub os_build: String,
    /// Expected main filter ruleset, including hook and its position.
    pub main: Rules,
    /// Exact qualified top-level translation hooks. No translation rules are qualified.
    pub main_translation: parse::Translation,
    /// Exact filter contents of every stock storage path, including structural parents.
    pub siblings: BTreeMap<String, Rules>,
    /// Exact translation-hook contents for every stock path; translation-rule exception set is empty.
    pub anchor_translation: BTreeMap<String, parse::Translation>,
    /// DHCP-enabled service interfaces, independently qualified for this OS.
    pub physical: BTreeSet<PhysicalInterface>,
    /// OS-specific normalized read-back transformations.
    pub normalization: Normalization,
    /// OS-specific ND hop-limit decision.
    pub hop_limit: HopLimitPolicy,
}
/// One anchor's independently collected filter and translation rulesets.
#[derive(Clone, Debug)]
pub struct AnchorObservation {
    /// `pfctl -a <path> -sr`, not a copy of the qualification record.
    pub rules: Result<Rules, Error>,
    /// `pfctl -a <path> -s nat`, including anchors after ours.
    pub translation: Result<parse::Translation, Error>,
}
/// Completeness evidence from a bounded recursive live collection, not qualification.
#[derive(Clone, Debug)]
pub struct LiveTree {
    /// Recursive enumeration before reading anchor contents.
    pub before: parse::AnchorInventory,
    /// Re-enumeration after all contents have been read.
    pub after: parse::AnchorInventory,
    /// One pair of live reads for every enumerated path, including structural parents.
    pub anchors: BTreeMap<String, AnchorObservation>,
    /// Collector confirms recursive traversal, command completion and depth/output/time bounds.
    pub complete: bool,
}
const OWN: &str = "com.apple/scupper";
/// Derive invocation paths from unconditional hooks and strcmp wildcard expansion.
/// Conditional/quick hooks, absolute/parent references and unfamiliar constructs
/// are refused rather than assumed to reach our all-traffic decision.
///
/// # Errors
/// Rejects incomplete traversal, unknown/changed stock, translation and bypasses.
pub fn walk_path(
    main: &Rules,
    translation: &parse::Translation,
    tree: &LiveTree,
    interfaces: &BTreeSet<Interface>,
    skips: &SkipFlags,
    qualified: &Qualification,
) -> Result<(), Reason> {
    for (interface, skip) in skips {
        if *skip && !interface.is_loopback() {
            return Err(Reason::Skip(interface.clone()));
        }
    }
    if interfaces.iter().any(|i| !skips.contains_key(i)) {
        return Err(Reason::Observation("interface inventory race"));
    }
    if !tree.complete
        || tree.before != tree.after
        || tree.anchors.keys().cloned().collect::<BTreeSet<_>>() != *tree.before.names()
    {
        return Err(Reason::Observation("incomplete live anchor traversal"));
    }
    if !tree.before.names().contains(OWN) {
        return Err(Reason::HookMissing);
    }
    // Translation is evaluated separately, on all governed traffic. The qualified
    // noninterfering translation-rule set is deliberately EMPTY until qualification.
    check_translation("", translation, tree)?;
    for (name, anchor) in &tree.anchors {
        check_translation(name, read(&anchor.translation)?, tree)?;
        read(&anchor.rules)?;
    }
    if !read(&tree.anchors[OWN].translation)?
        .normalized()
        .is_empty()
    {
        return Err(Reason::TranslationPresent);
    }
    let total_bytes = tree.anchors.values().try_fold(0usize, |total, a| {
        Ok::<_, Reason>(
            total
                .saturating_add(read(&a.rules)?.normalized().len())
                .saturating_add(read(&a.translation)?.normalized().len()),
        )
    })?;
    if total_bytes > 8 * 1024 * 1024 {
        return Err(Reason::Unsupported("live tree output budget"));
    }
    let mut reference_budget = 8192;
    validate_references("", main, tree, qualified, &mut reference_budget)?;
    for (path, a) in &tree.anchors {
        if path != OWN {
            validate_references(
                path,
                read(&a.rules)?,
                tree,
                qualified,
                &mut reference_budget,
            )?;
        }
    }
    if translation != &qualified.main_translation {
        return Err(Reason::Unsupported("unqualified translation hooks"));
    }
    let mut reached = BTreeSet::new();
    let mut stack = BTreeSet::new();
    let mut budget = 8192;
    walk_filter("", main, tree, &mut reached, &mut stack, &mut budget)?;
    if !reached.contains(OWN) {
        return Err(Reason::HookMissing);
    }
    if main.normalized() != qualified.main.normalized() {
        return Err(Reason::Unsupported("unqualified main ruleset"));
    }
    let qualified_names: BTreeSet<_> = tree
        .anchors
        .keys()
        .filter(|n| n.as_str() != OWN)
        .cloned()
        .collect();
    if qualified_names != qualified.siblings.keys().cloned().collect()
        || qualified_names != qualified.anchor_translation.keys().cloned().collect()
    {
        return Err(Reason::Unsupported("unknown or missing live anchor"));
    }
    for name in qualified_names {
        if read(&tree.anchors[&name].translation)? != &qualified.anchor_translation[&name] {
            return Err(Reason::Unsupported("changed stock translation hooks"));
        }
        if read(&tree.anchors[&name].rules)?.normalized() != qualified.siblings[&name].normalized()
        {
            return Err(Reason::Unsupported("unknown or changed sibling"));
        }
    }
    Ok(())
}
fn targets(parent: &str, reference: &str, tree: &LiveTree) -> Result<Vec<String>, Reason> {
    if reference.starts_with('/')
        || reference
            .split('/')
            .any(|p| p.is_empty() || p == "." || p == "..")
    {
        return Err(Reason::Unsupported("unsupported anchor reference"));
    }
    let full = if parent.is_empty() {
        reference.to_owned()
    } else {
        format!("{parent}/{reference}")
    };
    if let Some(prefix) = full.strip_suffix("/*") {
        let prefix = format!("{prefix}/");
        Ok(tree
            .before
            .names()
            .iter()
            .filter(|n| {
                n.strip_prefix(&prefix)
                    .is_some_and(|tail| !tail.contains('/'))
            })
            .cloned()
            .collect())
    } else if !full.contains('*') && tree.anchors.contains_key(&full) {
        Ok(vec![full])
    } else {
        Err(Reason::Unsupported(
            "unsupported or missing anchor reference",
        ))
    }
}
fn hook_reference(line: &str) -> Option<&str> {
    let (_, rest) = line.split_once(' ')?;
    rest.strip_prefix('"')?
        .split_once('"')
        .map(|(name, _)| name)
}
fn check_translation(
    parent: &str,
    rules: &parse::Translation,
    tree: &LiveTree,
) -> Result<(), Reason> {
    for line in rules.normalized().lines() {
        let Some(name) = hook_reference(line) else {
            return Err(Reason::TranslationPresent);
        };
        if line != format!("nat-anchor \"{name}\" all")
            && line != format!("rdr-anchor \"{name}\" all")
        {
            return Err(Reason::TranslationPresent);
        }
        targets(parent, name, tree)?;
    }
    Ok(())
}
fn validate_references(
    path: &str,
    rules: &Rules,
    tree: &LiveTree,
    qualified: &Qualification,
    budget: &mut usize,
) -> Result<(), Reason> {
    let mut scrub_checked = false;
    for rule in rules.rules() {
        *budget = budget
            .checked_sub(1)
            .ok_or(Reason::Unsupported("anchor traversal budget"))?;
        match rule {
            Rule::Anchor { name, quick: false } => {
                targets(path, name, tree)?;
            }
            Rule::Anchor { quick: true, .. } => {
                return Err(Reason::Unsupported("quick anchor reference"));
            }
            Rule::Unsupported(kind) if kind == "scrub-anchor" => {
                if scrub_checked {
                    continue;
                }
                scrub_checked = true;
                for line in rules
                    .normalized()
                    .lines()
                    .filter(|l| l.starts_with("scrub-anchor "))
                {
                    let name = hook_reference(line).ok_or(Reason::Unsupported("scrub hook"))?;
                    if line != format!("scrub-anchor \"{name}\" all fragment reassemble") {
                        return Err(Reason::Unsupported("scrub hook predicates"));
                    }
                    for child in targets(path, name, tree)? {
                        if child != OWN
                            && qualified.siblings.get(&child).is_none_or(|expected| {
                                !tree.anchors[&child]
                                    .rules
                                    .as_ref()
                                    .is_ok_and(|live| live.normalized() == expected.normalized())
                            })
                        {
                            return Err(Reason::Unsupported(
                                "unqualified or changed scrub-hook child",
                            ));
                        }
                    }
                }
            }
            Rule::Unsupported(_) => {
                return Err(Reason::Unsupported("construct before required hook"));
            }
            _ => {}
        }
    }
    Ok(())
}
fn walk_filter(
    path: &str,
    rules: &Rules,
    tree: &LiveTree,
    reached: &mut BTreeSet<String>,
    stack: &mut BTreeSet<String>,
    budget: &mut usize,
) -> Result<(), Reason> {
    if stack.len() >= 16 || !stack.insert(path.to_owned()) {
        return Err(Reason::Unsupported("anchor recursion/depth"));
    }
    for rule in rules.rules() {
        *budget = budget
            .checked_sub(1)
            .ok_or(Reason::Unsupported("anchor traversal budget"))?;
        match rule {
            Rule::Anchor { name, quick: false } => {
                for child in targets(path, name, tree)? {
                    reached.insert(child.clone());
                    if child != OWN {
                        walk_filter(
                            &child,
                            read(&tree.anchors[&child].rules)?,
                            tree,
                            reached,
                            stack,
                            budget,
                        )?;
                    }
                }
            }
            Rule::Pass(pass) if pass.quick && !reached.contains(OWN) => {
                return Err(Reason::QuickPass);
            }
            Rule::Pass(_) | Rule::Block { quick: false }
                if path.is_empty() || reached.contains(OWN) => {}
            Rule::Unsupported(kind) if kind == "scrub-anchor" => {}
            _ => return Err(Reason::Unsupported("construct before required hook")),
        }
    }
    stack.remove(path);
    Ok(())
}
/// Semantic mismatch in a planned anchor read-back.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum MismatchKind {
    /// No rules were returned.
    #[error("empty anchor read-back")]
    Empty,
    /// The terminating quick block is absent.
    #[error("missing final block")]
    FinalBlock,
    /// A non-pass statement precedes the final block.
    #[error("unexpected anchor statement")]
    Statement,
    /// Expanded permissions differ from the planned policy.
    #[error("anchor read-back policy mismatch")]
    Policy,
}
/// Normalization feature that has not been qualified.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum UnqualifiedKind {
    /// Named ICMP printing.
    #[error("unqualified ICMP normalization")]
    Icmp,
    /// Implicit state or TCP flags.
    #[error("unqualified anchor state/flags")]
    StateFlags,
    /// Rule list expansion.
    #[error("unqualified list expansion")]
    ListExpansion,
}
/// Typed planned-capture failure; observation errors never become mismatches.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CaptureError {
    /// A parsed policy differs from the intended policy.
    #[error("{0}")]
    Mismatch(MismatchKind),
    /// Interpretation requires an unqualified normalization feature.
    #[error("{0}")]
    Unqualified(UnqualifiedKind),
    /// The read-back could not be parsed.
    #[error("{0}")]
    Parse(#[from] Error),
}
/// Immutable expected normalized read-back for one planned policy generation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Baseline {
    text: String,
    hash: [u8; 32],
    inputs: Option<Inputs>,
    form: Form,
    normalization: Normalization,
}
impl Baseline {
    /// Capture only after a planned load. Semantic verification precedes storage;
    /// later unexplained changes must go through `verify`, never this constructor.
    ///
    /// # Errors
    /// Rejects invalid, incomplete, out-of-order or unsupported supplied evidence.
    pub fn capture(
        readback: &Rules,
        inputs: &Inputs,
        form: Form,
        normalization: &Normalization,
    ) -> Result<Self, CaptureError> {
        Self::capture_policy(readback, Policy::Installed(inputs, form), normalization)
    }
    /// Capture the exact read-back of either policy kind after a planned load.
    ///
    /// # Errors
    /// Rejects incomplete or semantically different anchor rules.
    pub fn capture_policy(
        readback: &Rules,
        policy: Policy<'_>,
        normalization: &Normalization,
    ) -> Result<Self, CaptureError> {
        if readback.uses_named_icmp() && !normalization.named_icmp {
            return Err(CaptureError::Unqualified(UnqualifiedKind::Icmp));
        }
        let mut actual = Vec::new();
        let Some((last, preceding)) = readback.rules().split_last() else {
            return Err(CaptureError::Mismatch(MismatchKind::Empty));
        };
        if *last != (Rule::Block { quick: true }) {
            return Err(CaptureError::Mismatch(MismatchKind::FinalBlock));
        }
        for rule in preceding {
            let Rule::Pass(pass) = rule else {
                return Err(CaptureError::Mismatch(MismatchKind::Statement));
            };
            if pass.state == State::Implicit
                || (pass.tcp_flags
                    && (!normalization.implicit_tcp_flags || pass.state != State::IfBound))
            {
                return Err(CaptureError::Unqualified(UnqualifiedKind::StateFlags));
            }
            actual.extend(pass.expanded());
        }
        let expected = policy::policy_table(policy);
        if !normalization.expanded_lists {
            let passes: Vec<_> = preceding
                .iter()
                .filter_map(|r| {
                    if let Rule::Pass(p) = r {
                        Some(p.clone())
                    } else {
                        None
                    }
                })
                .map(|mut p| {
                    p.tcp_flags = false;
                    p
                })
                .collect();
            if passes != expected {
                return Err(CaptureError::Unqualified(UnqualifiedKind::ListExpansion));
            }
        }
        let expected: Vec<_> = expected.iter().flat_map(policy::Pass::expanded).collect();
        if actual != expected {
            return Err(CaptureError::Mismatch(MismatchKind::Policy));
        }
        let text = readback.normalized().to_owned();
        let hash = Sha256::digest(text.as_bytes()).into();
        Ok(Self {
            text,
            hash,
            inputs: match policy {
                Policy::Installed(inputs, _) => Some(inputs.clone()),
                Policy::Lockdown => None,
            },
            form: match policy {
                Policy::Installed(_, form) => form,
                Policy::Lockdown => Form::PreTunnel,
            },
            normalization: normalization.clone(),
        })
    }
    pub(super) fn interfaces(&self) -> BTreeSet<PhysicalInterface> {
        self.inputs
            .iter()
            .flat_map(|i| i.physical().keys().cloned())
            .collect()
    }
    pub(super) fn same_stateful_permissions(&self, other: &Self) -> bool {
        let stateful = |b: &Self| {
            policy::policy_table(b.policy())
                .into_iter()
                .filter(|pass| pass.state != State::None)
                .collect::<Vec<_>>()
        };
        self.kind() == other.kind()
            && self.normalization == other.normalization
            && match (&self.inputs, &other.inputs) {
                (Some(a), Some(b)) => {
                    a.selected() == b.selected()
                        && a.endpoint() == b.endpoint()
                        && a.tunnel() == b.tunnel()
                        && a.hop_limit() == b.hop_limit()
                }
                (None, None) => true,
                _ => false,
            }
            && stateful(self) == stateful(other)
    }
    /// Exact expected policy kind.
    #[must_use]
    pub fn kind(&self) -> Kind {
        self.policy().kind()
    }
    fn policy(&self) -> Policy<'_> {
        self.inputs
            .as_ref()
            .map_or(Policy::Lockdown, |i| Policy::Installed(i, self.form))
    }
    /// Intended policy form, checked during planned capture.
    #[must_use]
    pub fn form(&self) -> Form {
        self.form
    }
    /// Stored normalized text; never renderer text.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }
    /// Stored SHA-256.
    #[must_use]
    pub fn hash(&self) -> [u8; 32] {
        self.hash
    }
}
/// Identity proof mechanism is deliberately an explicit 5a2 input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IdentityEvidence {
    /// Mechanism not yet decided/qualified; cannot authorize joined protection.
    Unresolved5a2,
    /// Supervisor has checked generation, readiness and stale socket/name rejection.
    CurrentGeneration(Tunnel),
    /// Child death, restart, reused utun, or stale previous-generation artifact.
    LostOrStale,
}
/// Explicit 5a2 endpoint-path selection outcome; multiple leases alone are valid.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SelectedPath {
    /// Validated independently of helper-installed routes.
    Selected,
    /// No supported tie-breaking result.
    Ambiguous,
    /// Physical gateway is unavailable.
    MissingGateway,
}
/// Timeout/status mapping must be supplied by 5a2, not inferred from poll targets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StepOutcome {
    /// Every required read/privileged step completed.
    Complete,
    /// Failed or timed-out step, classified by the caller.
    Failed(&'static str),
    /// Helper unavailable/suspended; no new observations available.
    Unavailable,
}
/// Integrity is checked only after pre-tunnel enforcement, never before it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ToolIntegrity {
    /// Checks have not run yet; valid only for pre-tunnel enforcement verification.
    PendingAfterEnforcement,
    /// Recorded hashes and ownership match.
    Match,
    /// Refuse join after the enforcement attempt; persist and notify the failure.
    Mismatch,
}
/// Transport facts independently selected before collection, then re-observed.
/// The route includes the query endpoint, interface and gateway; the local
/// address must come from bounded interface/address evidence in 5a2.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transport {
    /// Selected uplink's validated local IPv4 address.
    pub local_address: std::net::Ipv4Addr,
    /// Complete endpoint-route identity, including gateway.
    pub endpoint_route: Route,
}
/// Full observation bundle. Every parse failure can be carried in `Result` to verify.
#[derive(Clone, Debug)]
pub struct Observations {
    /// Start of every required read, keyed by `required_reads`; cheap checks cannot refresh these.
    pub started_at: BTreeMap<String, u64>,
    /// Checked state flush or qualified validation for this epoch.
    pub states: StateEvidence,
    /// Exact observed OS build.
    pub os_build: String,
    /// Enabled/reference information.
    pub pf: Result<PfInfo, Error>,
    /// Missing anchor is distinct from an unreadable anchor.
    pub anchor: Result<Option<Rules>, Error>,
    /// Main filter ruleset.
    pub main: Result<Rules, Error>,
    /// Top-level `pfctl -s nat`, separate from filter output.
    pub translation: Result<parse::Translation, Error>,
    /// Complete recursively enumerated live tree with filter and nat reads.
    pub live_tree: Result<LiveTree, Error>,
    /// All interfaces from ifconfig, not only en/utun.
    pub interfaces: Result<BTreeSet<Interface>, Error>,
    /// pf interface skip observations.
    pub skips: Result<SkipFlags, Error>,
    /// Effective DNS resolver read-back (functionality; never a firewall bypass).
    pub dns: Result<Vec<Resolver>, Error>,
    /// Independently observed selected uplink local IPv4 address.
    pub local_address: Result<std::net::Ipv4Addr, Error>,
    /// Numeric endpoint route read-back.
    pub route: Result<Route, Error>,
    /// Lease evidence/timers converted to explicit phases by 5a2.
    pub policy_inputs: Result<Inputs, Error>,
    /// Supervised child identity and generation evidence.
    pub identity: IdentityEvidence,
    /// Independent physical path selection.
    pub selected_path: SelectedPath,
    /// Installed child/tool hash and ownership checks, ordered after pre-tunnel verification.
    pub tool_integrity: ToolIntegrity,
    /// External ND 255 enforcement, if selected by the qualification record.
    pub external_hop_limit_verified: bool,
    /// Privileged step result; no guessed timeout mapping.
    pub step: StepOutcome,
}
/// Intended enforcement plus explicit freshness/qualification policy.
#[derive(Clone, Debug)]
pub struct Expected {
    /// Current policy, lifecycle and state identity; supplied before collection.
    pub context: Context,
    /// Intended policy inputs (not derived from live unexplained changes).
    pub inputs: Inputs,
    /// Independently selected address and endpoint route; changes require full rejoin.
    pub transport: Transport,
    /// Pre-tunnel or current-generation joined policy.
    pub form: Form,
    /// Baseline captured for this exact generation and intended policy.
    pub baseline: Baseline,
    /// Reviewed qualification record.
    pub qualification: Qualification,
    /// Explicit stale threshold, in the same clock units as `now`; fixed in 5a2.
    pub max_age: u64,
    /// Persisted intent; tool mismatch is refusal only while joining/joined.
    pub join_intended: bool,
}
/// Verify complete supplied evidence. Known failures take precedence over age;
/// unsupported paths take precedence over repairs that would otherwise rejoin.
#[must_use]
pub fn verify(
    observations: &Observations,
    expected: &Expected,
    clock: &impl SleepCountingClock,
) -> Verdict {
    let started = clock.now();
    match check(observations, expected, started) {
        Ok(mut verdict) => {
            let completed = clock.now();
            if completed < started {
                return Verdict::NotProtected(Reason::Observation("clock regressed"));
            }
            if matches!(verdict, Verdict::Protected(_) | Verdict::Repair(_)) {
                let oldest = observations
                    .started_at
                    .values()
                    .min()
                    .copied()
                    .unwrap_or(started);
                let expiry = oldest.saturating_add(expected.max_age);
                if completed > expiry {
                    return Verdict::Unknown { since: expiry };
                }
            }
            if let Verdict::Protected(proof) = &mut verdict {
                proof.completed_at = completed;
            }
            verdict
        }
        Err(reason) => Verdict::NotProtected(reason),
    }
}
#[allow(clippy::too_many_lines)] // Safety precedence is kept in one auditable decision table.
fn check(o: &Observations, e: &Expected, now: u64) -> Result<Verdict, Reason> {
    if let StepOutcome::Failed(reason) = o.step {
        return Err(Reason::Observation(reason));
    }
    let observed_at = match check_global(o, &e.qualification, Kind::Installed(e.form), now) {
        Err(Reason::Observation("interface inventory race")) => {
            return Ok(Verdict::Unknown {
                since: o.started_at.values().min().copied().unwrap_or(now),
            });
        }
        other => other?,
    };
    let pf = read(&o.pf)?;
    let anchor = read(&o.anchor)?;
    let tree = read(&o.live_tree)?;
    let interfaces = read(&o.interfaces)?;
    let dns = read(&o.dns)?;
    let route = read(&o.route)?;
    let local_address = *read(&o.local_address)?;
    if local_address.is_unspecified()
        || local_address.is_loopback()
        || local_address.is_multicast()
        || local_address.is_broadcast()
    {
        return Err(Reason::Observation("invalid selected local address"));
    }
    let inputs = read(&o.policy_inputs)?;
    if dns.is_empty() {
        return Err(Reason::Observation("missing resolver evidence"));
    }
    check_qualification(o, e)?;
    if route.route_to != std::net::IpAddr::V4(e.inputs.endpoint().address()) {
        return Err(Reason::Observation("route lookup target mismatch"));
    }
    if e.join_intended {
        match o.tool_integrity {
            ToolIntegrity::Mismatch => return Err(Reason::ToolIntegrity),
            ToolIntegrity::PendingAfterEnforcement if e.form == Form::Joined => {
                return Err(Reason::Observation("tool integrity unverified"));
            }
            _ => {}
        }
    }
    let stale_at = observed_at.saturating_add(e.max_age);
    if o.step == StepOutcome::Unavailable {
        return Ok(Verdict::Unknown { since: observed_at });
    }
    if now > stale_at {
        return Ok(Verdict::Unknown { since: stale_at });
    }
    if e.form == Form::Joined && !interfaces.contains(e.inputs.tunnel().name.interface()) {
        return Ok(Verdict::Repair(Action::RecreateChild));
    }
    if inputs
        .physical()
        .keys()
        .any(|p| !interfaces.contains(p.interface()))
    {
        return Ok(Verdict::Unknown { since: observed_at });
    }
    if o.selected_path == SelectedPath::Ambiguous {
        return Err(Reason::AmbiguousPath);
    }
    if route.interface.to_string().starts_with("utun") {
        return Err(Reason::RouteRecursion);
    }
    if o.selected_path == SelectedPath::MissingGateway
        || !matches!(route.gateway, Some(std::net::IpAddr::V4(ip)) if !ip.is_unspecified() && !ip.is_loopback() && !ip.is_multicast() && !ip.is_broadcast())
    {
        return Err(Reason::MissingGateway);
    }
    if route.interface != *inputs.selected().interface() {
        return Err(Reason::AmbiguousPath);
    }
    if !pf.enabled {
        return Ok(Verdict::Repair(Action::EnableAndRejoin));
    }
    if e.baseline.inputs.as_ref() != Some(&e.inputs)
        || e.baseline.form != e.form
        || e.baseline.normalization != e.qualification.normalization
    {
        return Err(Reason::Observation(
            "baseline belongs to different policy generation",
        ));
    }
    if let Some(verdict) = check_anchor(anchor.as_ref(), tree, &e.baseline)? {
        return Ok(verdict);
    }
    if e.form == Form::Joined {
        match &o.identity {
            IdentityEvidence::CurrentGeneration(tunnel) if tunnel == e.inputs.tunnel() => {}
            IdentityEvidence::Unresolved5a2 => {
                return Err(Reason::Unsupported("5a2 tunnel identity proof unresolved"));
            }
            _ => return Ok(Verdict::Repair(Action::RecreateChild)),
        }
    }
    let transport = Transport {
        local_address,
        endpoint_route: route.clone(),
    };
    if transport != e.transport {
        return Ok(Verdict::Repair(Action::Rejoin));
    }
    if inputs != &e.inputs {
        let same_path = inputs.selected() == e.inputs.selected()
            && inputs.endpoint() == e.inputs.endpoint()
            && inputs.tunnel() == e.inputs.tunnel()
            && inputs.hop_limit() == e.inputs.hop_limit();
        if inputs
            .physical()
            .keys()
            .any(|p| !e.qualification.physical.contains(p))
        {
            return Err(Reason::Unsupported("unqualified physical service"));
        }
        let same_stateful = policy::policy_table(Policy::Installed(inputs, e.form))
            .into_iter()
            .filter(|p| p.state != State::None)
            .collect::<Vec<_>>()
            == policy::policy_table(Policy::Installed(&e.inputs, e.form))
                .into_iter()
                .filter(|p| p.state != State::None)
                .collect::<Vec<_>>();
        return Ok(Verdict::Repair(if same_path && same_stateful {
            Action::Rerender { form: e.form }
        } else {
            Action::Rejoin
        }));
    }
    let StateEvidence::Clean {
        epoch,
        completed_at,
    } = o.states
    else {
        return Ok(Verdict::Unknown { since: observed_at });
    };
    if epoch != e.context.state_epoch || completed_at > observed_at {
        return Ok(Verdict::Unknown { since: observed_at });
    }
    Ok(Verdict::Protected(Proof {
        verified_at: observed_at,
        completed_at: now,
        expires_at: stale_at,
        context: e.context,
        form: e.form,
        tunnel: Some(e.inputs.tunnel().clone()),
        kind: Kind::Installed(e.form),
        baseline_hash: e.baseline.hash(),
        states_clean_at: completed_at,
        transport: Some(transport),
    }))
}
/// Input-free expected lockdown verification. Qualification comes from the
/// platform's reviewed OS record, never from an unreadable installation record.
pub struct LockdownExpected {
    /// Observation identity captured before collection.
    pub context: Context,
    /// Planned exact lockdown read-back.
    pub baseline: Baseline,
    /// Reviewed firewall qualification.
    pub qualification: Qualification,
    /// Maximum age in the sleep-counting clock domain.
    pub max_age: u64,
}
/// Check the effective blocking policy before enabling pf. This checks the
/// qualified invocation path, anchor and observation age without requiring pf
/// to be running or manufacturing a protection proof.
///
/// # Errors
/// Rejects incomplete, stale, unreachable or mismatched policy observations.
pub fn verify_lockdown_policy(
    o: &Observations,
    e: &LockdownExpected,
    clock: &impl SleepCountingClock,
) -> Result<(), Reason> {
    let now = clock.now();
    let observed_at = check_global_policy(o, &e.qualification, Kind::Lockdown, now)?;
    if e.baseline.kind() != Kind::Lockdown
        || e.baseline.normalization != e.qualification.normalization
        || now > observed_at.saturating_add(e.max_age)
    {
        return Err(Reason::Observation("blocking policy unavailable"));
    }
    if check_anchor(read(&o.anchor)?.as_ref(), read(&o.live_tree)?, &e.baseline)?.is_some() {
        return Err(Reason::Observation("blocking policy mismatch"));
    }
    Ok(())
}
/// Verify lockdown with all the same global checks as installed policies.
#[must_use]
pub fn verify_lockdown(
    o: &Observations,
    e: &LockdownExpected,
    clock: &impl SleepCountingClock,
) -> Verdict {
    let now = clock.now();
    let result = (|| {
        let observed_at = match check_global(o, &e.qualification, Kind::Lockdown, now) {
            Err(Reason::Observation("interface inventory race")) => {
                return Ok(Verdict::Unknown {
                    since: o.started_at.values().min().copied().unwrap_or(now),
                });
            }
            other => other?,
        };
        if e.baseline.kind() != Kind::Lockdown
            || e.baseline.normalization != e.qualification.normalization
        {
            return Err(Reason::Observation(
                "baseline belongs to different policy generation",
            ));
        }
        if !read(&o.pf)?.enabled {
            return Ok(Verdict::Repair(Action::EnableAndRejoin));
        }
        if let Some(verdict) =
            check_anchor(read(&o.anchor)?.as_ref(), read(&o.live_tree)?, &e.baseline)?
        {
            return Ok(verdict);
        }
        let expires_at = observed_at.saturating_add(e.max_age);
        if now > expires_at || o.step == StepOutcome::Unavailable {
            return Ok(Verdict::Unknown { since: expires_at });
        }
        let StateEvidence::Clean {
            epoch,
            completed_at,
        } = o.states
        else {
            return Ok(Verdict::Unknown { since: observed_at });
        };
        if epoch != e.context.state_epoch || completed_at > observed_at {
            return Ok(Verdict::Unknown { since: observed_at });
        }
        Ok(Verdict::Protected(Proof {
            verified_at: observed_at,
            completed_at: now,
            expires_at,
            context: e.context,
            form: Form::PreTunnel,
            kind: Kind::Lockdown,
            tunnel: None,
            transport: None,
            baseline_hash: e.baseline.hash(),
            states_clean_at: completed_at,
        }))
    })();
    let completed = clock.now();
    match result {
        _ if completed < now => Verdict::NotProtected(Reason::Observation("clock regressed")),
        Ok(Verdict::Protected(mut p)) if completed <= p.expires_at => {
            p.completed_at = completed;
            Verdict::Protected(p)
        }
        Ok(Verdict::Protected(p)) => Verdict::Unknown {
            since: p.expires_at,
        },
        Ok(v) => v,
        Err(r) => Verdict::NotProtected(r),
    }
}
fn check_global(
    o: &Observations,
    qualification: &Qualification,
    kind: Kind,
    now: u64,
) -> Result<u64, Reason> {
    if let StepOutcome::Failed(reason) = o.step {
        return Err(Reason::Observation(reason));
    }
    check_global_policy(o, qualification, kind, now)
}

// Static policy observations can guide pre-enable containment beside stale
// writers. Only check_global's separate effect fence can publish a proof.
fn check_global_policy(
    o: &Observations,
    qualification: &Qualification,
    kind: Kind,
    now: u64,
) -> Result<u64, Reason> {
    read(&o.pf)?;
    read(&o.anchor)?;
    let main = read(&o.main)?;
    let translation = read(&o.translation)?;
    let tree = read(&o.live_tree)?;
    let interfaces = read(&o.interfaces)?;
    let skips = read(&o.skips)?;
    let required = if kind == Kind::Lockdown {
        required_lockdown_reads(tree)
    } else {
        required_reads(tree)
    };
    if o.started_at.keys().cloned().collect::<BTreeSet<_>>() != required {
        return Err(Reason::Observation("missing required observation start"));
    }
    let observed_at = *o
        .started_at
        .values()
        .min()
        .ok_or(Reason::Observation("missing observation times"))?;
    if o.started_at.values().any(|t| *t > now) {
        return Err(Reason::Observation("observation from future"));
    }
    let before = o.started_at["inventory-before"];
    let after = o.started_at["inventory-after"];
    if before > after
        || tree.before.names().iter().any(|name| {
            ["filter", "nat"].iter().any(|kind| {
                let time = o.started_at[&format!("{name}:{kind}")];
                time < before || time > after
            })
        })
    {
        return Err(Reason::Observation("anchor collection order"));
    }
    if o.os_build.is_empty() || o.os_build != qualification.os_build {
        return Err(Reason::Unsupported("unqualified OS build"));
    }
    walk_path(main, translation, tree, interfaces, skips, qualification)?;
    Ok(observed_at)
}
fn check_anchor(
    anchor: Option<&Rules>,
    tree: &LiveTree,
    baseline: &Baseline,
) -> Result<Option<Verdict>, Reason> {
    let exact = anchor.as_ref().is_some_and(|rules| {
        rules.normalized() == baseline.text
            && <[u8; 32]>::from(Sha256::digest(rules.normalized().as_bytes())) == baseline.hash
    });
    if !exact {
        return Ok(Some(Verdict::Repair(Action::Rejoin)));
    }
    let own_live = read(&tree.anchors[OWN].rules)?;
    if own_live.normalized() != baseline.text {
        return Ok(Some(Verdict::Repair(Action::Rejoin)));
    }
    Ok(None)
}
/// Capture an input-free lockdown baseline from the exact planned read-back.
///
/// # Errors
/// Rejects any anchor other than the qualified lockdown policy.
pub fn capture_lockdown_baseline(
    text: &str,
    normalization: &Normalization,
) -> Result<Baseline, CaptureError> {
    Baseline::capture_policy(&parse::pf_rules(text)?, Policy::Lockdown, normalization)
}
/// Required start-time keys, derived from the live tree rather than a caller's aggregate.
#[must_use]
pub fn required_reads(tree: &LiveTree) -> BTreeSet<String> {
    let mut reads: BTreeSet<_> = [
        "pf",
        "anchor",
        "main",
        "nat",
        "inventory-before",
        "inventory-after",
        "interfaces",
        "skips",
        "dns",
        "route",
        "local-address",
        "policy",
        "identity",
        "path",
        "tools",
        "hop-limit",
        "os",
        "states",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    for name in tree.before.names() {
        reads.insert(format!("{name}:filter"));
        reads.insert(format!("{name}:nat"));
    }
    reads
}
/// Only actual global reads are required without installation metadata.
#[must_use]
pub fn required_lockdown_reads(tree: &LiveTree) -> BTreeSet<String> {
    let mut reads = required_reads(tree);
    for key in [
        "dns",
        "route",
        "local-address",
        "policy",
        "identity",
        "path",
        "tools",
        "hop-limit",
    ] {
        reads.remove(key);
    }
    reads
}
fn check_qualification(o: &Observations, e: &Expected) -> Result<(), Reason> {
    if o.os_build.is_empty() || o.os_build != e.qualification.os_build {
        return Err(Reason::Unsupported("unqualified OS build"));
    }
    if e.qualification.hop_limit != *e.inputs.hop_limit() {
        return Err(Reason::Unsupported("hop-limit qualification mismatch"));
    }
    if e.inputs
        .physical()
        .keys()
        .any(|p| !e.qualification.physical.contains(p))
    {
        return Err(Reason::Unsupported("unqualified physical service"));
    }
    if matches!(e.inputs.hop_limit(), HopLimitPolicy::External255) && !o.external_hop_limit_verified
    {
        return Err(Reason::Observation("ND hop-limit enforcement unverified"));
    }
    Ok(())
}
fn read<T>(value: &Result<T, Error>) -> Result<&T, Reason> {
    value.as_ref().map_err(|e| Reason::Observation(e.0))
}
/// Convenience parser for planned capture; does not update an existing baseline.
///
/// # Errors
/// Rejects invalid, incomplete, out-of-order or unsupported supplied evidence.
pub fn capture_baseline(
    text: &str,
    inputs: &Inputs,
    form: Form,
    normalization: &Normalization,
) -> Result<Baseline, CaptureError> {
    Baseline::capture(&parse::pf_rules(text)?, inputs, form, normalization)
}

#[cfg(test)]
mod policy_kind_tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::mac::lifecycle::{Durable, Event, Machine, Step};
    struct Clock;
    impl SleepCountingClock for Clock {
        fn now(&self) -> u64 {
            100
        }
    }
    fn capture_error(text: &str) -> CaptureError {
        capture_lockdown_baseline(
            text,
            &Normalization {
                expanded_lists: true,
                named_icmp: true,
                implicit_tcp_flags: true,
            },
        )
        .unwrap_err()
    }
    #[test]
    fn capture_empty_is_typed_mismatch() {
        assert_eq!(
            capture_error(""),
            CaptureError::Mismatch(MismatchKind::Empty)
        );
    }
    #[test]
    fn capture_missing_final_block_is_typed_mismatch() {
        assert_eq!(
            capture_error("pass all\n"),
            CaptureError::Mismatch(MismatchKind::FinalBlock)
        );
    }
    #[test]
    fn capture_unexpected_statement_is_typed_mismatch() {
        assert_eq!(
            capture_error("anchor \"foreign/target\" all\nblock drop quick all\n"),
            CaptureError::Mismatch(MismatchKind::Statement)
        );
    }
    #[test]
    fn capture_extra_permission_is_typed_mismatch() {
        let extra = policy::render_lockdown().as_str().replace(
            "block drop quick all",
            "pass out quick all keep state (if-bound)\nblock drop quick all",
        );
        assert_eq!(
            capture_error(&extra),
            CaptureError::Mismatch(MismatchKind::Policy)
        );
    }
    #[test]
    fn capture_parse_failure_is_not_a_semantic_mismatch() {
        assert!(matches!(
            capture_error("unknown output"),
            CaptureError::Parse(_)
        ));
    }
    #[test]
    fn held_verify_requires_policy_kind_even_if_other_evidence_matches() {
        let mut machine = Machine::restart_lockdown(Durable {
            join_intended: true,
            hold: true,
            uncertain_acquires: vec![1, 2],
            reference_sequence: 2,
            ..Durable::default()
        });
        machine = machine
            .transition(Event::Failed(Reason::Observation("reference debt")), &Clock)
            .unwrap();
        assert_eq!(machine.pending(), Some(Step::LoadPreTunnel));
        machine = machine
            .transition(Event::Completed(Step::LoadPreTunnel), &Clock)
            .unwrap();
        let normalization = Normalization {
            expanded_lists: false,
            named_icmp: false,
            implicit_tcp_flags: false,
        };
        let baseline =
            capture_lockdown_baseline(policy::render_lockdown().as_str(), &normalization).unwrap();
        machine = machine
            .transition(Event::ReadbackValidated(baseline.clone()), &Clock)
            .unwrap();
        machine = machine
            .transition(
                Event::StatesClean {
                    epoch: machine.context().state_epoch,
                    completed_at: 100,
                },
                &Clock,
            )
            .unwrap();
        // Private-field fixture independently pins the kind guard. Its other
        // fields intentionally match, so the baseline hash cannot hide a missing
        // kind check. No production constructor can create this malformed proof.
        let mut proof = Proof {
            verified_at: 100,
            completed_at: 100,
            expires_at: 105,
            context: machine.context(),
            form: Form::PreTunnel,
            kind: Kind::Installed(Form::PreTunnel),
            tunnel: None,
            transport: None,
            baseline_hash: baseline.hash(),
            states_clean_at: 100,
        };
        assert!(
            machine
                .transition(
                    Event::Observed {
                        context: machine.context(),
                        form: Form::PreTunnel,
                        verdict: Verdict::Protected(proof.clone())
                    },
                    &Clock
                )
                .is_err()
        );
        proof.kind = Kind::Lockdown;
        let next = machine
            .transition(
                Event::Observed {
                    context: machine.context(),
                    form: Form::PreTunnel,
                    verdict: Verdict::Protected(proof),
                },
                &Clock,
            )
            .unwrap();
        assert!(next.blocking_verified_at(&Clock));
        assert!(!matches!(
            next.enforcement_at(&Clock),
            Verdict::Protected(_)
        ));
    }
}
