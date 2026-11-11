use super::{
    Budgets, ClearLatch, Debounce, Desired, Escalation, HardeningKey, KernelModel, Known, Latch,
    LatchTransition, LinkPhase, NamespaceState, Plan, PlannerEvent, Repair, RepairClass, Ruleset,
    SafetyClass, Step,
    model::{host_leftover, route_obs, same_peers},
    safe,
};
use crate::{
    failover::MonoTime,
    render::{Family, RouteTarget, Scope},
    verdict::v2::DefaultRouteObs,
};
use std::collections::BTreeSet;

/// Plans only toward the last verified applied configuration. Reservations count
/// attempts, even if execution later fails. No caller state is mutated.
#[must_use]
#[allow(clippy::too_many_lines)] // Keep the safety-critical execution order visible together.
pub fn plan(
    desired: &Desired,
    observed: &KernelModel,
    budgets: &Budgets,
    latch: Option<&Latch>,
    debounce: &Debounce,
    now: MonoTime,
) -> Plan {
    let mut current_budgets = budgets.clone();
    current_budgets.expire(now);
    if observed.latch.is_some() {
        current_budgets.persistence_failed = false;
    }
    if observed.forwarding_on() {
        current_budgets.closed_by_planner = false;
    }
    current_budgets.downed_by_planner.retain(|name| {
        !observed
            .links
            .get(name)
            .is_some_and(|link| link.up == Known::Value(true))
    });
    let detected_classes = detect(desired, observed)
        .iter()
        .filter_map(Repair::safety_class)
        .collect::<BTreeSet<_>>();
    let mut classes = detected_classes.clone();
    classes.extend(current_budgets.pending_safety.iter().copied());
    let mut suppressed = detected_classes
        .iter()
        .filter(|class| {
            current_budgets
                .attempts
                .get(class.key())
                .is_some_and(|v| v.len() >= 3)
        })
        .map(|class| (class.key().to_owned(), true))
        .collect::<Vec<_>>();
    // First build determines executable repairs. Only their emitted steps can
    // reserve budgets; blocked route/forwarding restores consume nothing.
    let provisional = build_plan(
        desired,
        observed,
        &current_budgets,
        latch,
        debounce,
        &suppressed,
    );
    for key in reservation_keys(&provisional, &classes, desired, observed) {
        if classes.iter().any(|c| c.key() == key)
            && !detected_classes.iter().any(|c| c.key() == key)
        {
            continue;
        }
        if current_budgets
            .attempts
            .get(&key)
            .is_some_and(|v| v.len() >= 3)
            && !suppressed.iter().any(|(k, _)| k == &key)
        {
            suppressed.push((key.clone(), classes.iter().any(|c| c.key() == key)));
        }
    }
    let mut result = build_plan(
        desired,
        observed,
        &current_budgets,
        latch,
        debounce,
        &suppressed,
    );
    for key in reservation_keys(&result, &classes, desired, observed) {
        result.budgets.reserve(&key, now);
    }
    result.budgets.pending_safety = if result
        .steps
        .iter()
        .any(|s| matches!(s, Step::ForwardingOn { .. }))
    {
        BTreeSet::new()
    } else {
        classes
            .into_iter()
            .filter(|c| *c != SafetyClass::Ruleset)
            .collect()
    };
    for (key, _) in suppressed {
        result.budgets.suppressed.insert(key);
    }
    // Ownership ends at our reopening; a later external closure must be charged.
    // A failed enable is re-armed by replan_after_failure.
    if let Some(closed) = result.steps.iter().rev().find_map(|step| match step {
        Step::ForwardingOn { .. } => Some(false),
        Step::ForwardingOff | Step::LinkForwardingOff { .. } => Some(true),
        _ => None,
    }) {
        result.budgets.closed_by_planner = closed;
    }
    // Ownership of a planner-downed link ends when this plan brings it up again, so a
    // later external down is charged like any other fight.
    let raised: BTreeSet<String> = result
        .steps
        .iter()
        .filter_map(|step| match step {
            Step::LinkCreate {
                link,
                phase: LinkPhase::Up,
            }
            | Step::LinkReconfigure { link } => Some(link.name.clone()),
            _ => None,
        })
        .collect();
    result
        .budgets
        .downed_by_planner
        .retain(|name| !raised.contains(name));
    result
}
fn reservation_keys(
    p: &Plan,
    classes: &BTreeSet<SafetyClass>,
    desired: &Desired,
    observed: &KernelModel,
) -> BTreeSet<String> {
    let mut keys = p
        .repairs
        .iter()
        .filter(|r| {
            r.class() == RepairClass::Restore
                && !matches!(r, Repair::LinkReconfigure { name }
                if p.budgets.downed_by_planner.contains(name)
                    && observed.links.get(name).is_some_and(|link| {
                        desired.links.get(name).is_some_and(|want| link.matches_config(want))
                    }))
                && (**r != Repair::ForwardingRestore
                    || classes.is_empty()
                        && !p.budgets.closed_by_planner
                        && !p.steps.iter().any(|s| {
                            matches!(s, Step::ForwardingOff | Step::LinkForwardingOff { .. })
                        }))
        })
        .map(|r| {
            if *r == Repair::RulesetReload {
                SafetyClass::Ruleset.key().into()
            } else {
                r.object()
            }
        })
        .collect::<BTreeSet<_>>();
    if p.steps
        .iter()
        .any(|s| matches!(s, Step::ForwardingOn { .. }))
    {
        for class in classes {
            if *class != SafetyClass::Ruleset {
                keys.insert(class.key().into());
            }
        }
    }
    keys
}
#[allow(clippy::too_many_lines)] // Execution order is reviewed as one sequence.
fn build_plan(
    desired: &Desired,
    observed: &KernelModel,
    budgets: &Budgets,
    latch: Option<&Latch>,
    debounce: &Debounce,
    suppressed: &[(String, bool)],
) -> Plan {
    let mut result = Plan {
        budgets: budgets.clone(),
        ..Plan::default()
    };
    result.escalations = escalations(observed, desired);
    if observed.namespace == NamespaceState::InodeGone {
        result.debounce = debounce.clone();
        // Namespace loss prevents kernel operations, not durable quarantine.
        if let Some(latch) = latch.filter(|_| observed.latch.is_none()) {
            if budgets.persistence_failed {
                result
                    .steps
                    .push(Step::Emit(PlannerEvent::PersistenceFailed));
            }
            result.repairs.push(Repair::PersistLatch {
                reason: latch.reason.clone(),
                object: latch.object.clone(),
            });
            result.steps.push(Step::PersistLatch {
                reason: latch.reason.clone(),
                object: latch.object.clone(),
            });
        }
        return result;
    }
    let effective_latch = latch.or(observed.latch.as_ref());
    let candidates = detect(desired, observed);
    let safety_reopen = candidates.iter().any(|r| {
        matches!(
            r.safety_class(),
            Some(SafetyClass::TcHook | SafetyClass::ForeignLink)
        )
    });
    let unknown_inventory = !observed.links_complete
        || observed
            .links
            .values()
            .any(|l| l.tc_hooks == Known::Unknown);
    let mut admitted = Vec::new();
    for repair in candidates {
        if effective_latch.is_some() && repair == Repair::ForwardingRestore {
            continue;
        }
        let object = repair.object();
        result.debounce.previous.insert(object.clone());
        if repair.class() == RepairClass::Restore {
            if suppressed.iter().any(|(key, _)| {
                key == &object || repair.safety_class().is_some_and(|c| c.key() == key)
            }) {
                continue;
            }
            if repair != Repair::RulesetReload
                && !(repair == Repair::ForwardingRestore && safety_reopen)
                && !debounce.previous.contains(&object)
            {
                continue;
            }
        }
        admitted.push(repair);
    }
    if unknown_inventory {
        result.debounce.previous.insert("unknown-inventory".into());
    }
    let fresh = desired
        .links
        .keys()
        .all(|name| !observed.links.contains_key(name));
    let reload = admitted.contains(&Repair::RulesetReload);
    let mut builder = Builder {
        result,
        model: observed.clone(),
        desired,
        suppressed_keys: suppressed.iter().map(|(k, _)| k.clone()).collect(),
    };
    // Adopt without I/O before step zero; the first kernel step closes the gate.
    let new_latch = if effective_latch.is_none() {
        suppressed
            .iter()
            .find(|(_, safety)| *safety)
            .map(|(object, _)| Latch {
                reason: "safety repair budget exhausted".into(),
                object: object.clone(),
            })
    } else {
        None
    };
    builder.result.latch.clone_from(&new_latch);
    builder.model.latch = effective_latch.cloned().or(new_latch.clone());
    let closed = new_latch.is_some()
        || effective_latch.is_some()
        || !safe(observed, desired)
        || observed.ruleset != Known::Value(Ruleset::Verified(desired.fingerprint));
    let forwarding_change =
        closed && !observed.forwarding_off() || reload || fresh || new_latch.is_some();
    if forwarding_change {
        builder.result.repairs.push(Repair::ForwardingOff);
        builder.push(Step::ForwardingOff);
    }
    for (object, _) in suppressed {
        if builder.result.budgets.suppressed.contains(object) {
            continue;
        }
        builder.push(Step::Emit(PlannerEvent::RepairSuppressed {
            object: object.clone(),
        }));
    }
    if budgets.persistence_failed && observed.latch.is_none() && builder.model.latch.is_some() {
        builder.push(Step::Emit(PlannerEvent::PersistenceFailed));
    }
    // Tighten all known bypasses before touching any restoring operation.
    let mut tighten = admitted
        .iter()
        .filter(|r| r.class() == RepairClass::Tighten)
        .collect::<Vec<_>>();
    tighten.sort_by_key(|repair| match repair {
        Repair::ForeignLinkDown { .. } | Repair::ExitDown { .. } => 0,
        Repair::TcHookDelete { .. } => 1,
        Repair::ExtraRuleDelete { .. } => 2,
        _ => 3,
    });
    for repair in tighten {
        builder.tighten(repair);
    }
    builder.result.debounce.ingress_quarantined = unknown_inventory
        && (debounce.ingress_quarantined || debounce.previous.contains("unknown-inventory"));
    if builder.result.debounce.ingress_quarantined {
        // Only a positively down or positively absent device is contained.
        // Omission from incomplete inventory must still trigger a down attempt.
        let client = &desired.link_order[0];
        let contained = builder
            .model
            .links
            .get(client)
            .map_or(builder.model.links_complete, |link| {
                link.up == Known::Value(false)
            });
        if !contained {
            builder
                .result
                .budgets
                .downed_by_planner
                .insert(client.clone());
            builder.push(Step::LinkDown {
                name: client.clone(),
            });
        }
        if !debounce.ingress_quarantined {
            builder.push(Step::Emit(PlannerEvent::IngressQuarantined));
        }
    }
    // Tightening, including ingress quarantine, precedes synchronous disk I/O.
    // Containment failure still permits persistence, and memory-only latches retry.
    if let Some(latch) = builder
        .model
        .latch
        .clone()
        .filter(|_| observed.latch.is_none())
    {
        builder.result.repairs.push(Repair::PersistLatch {
            reason: latch.reason.clone(),
            object: latch.object.clone(),
        });
        builder.push(Step::PersistLatch {
            reason: latch.reason,
            object: latch.object,
        });
    }
    // Boot steps 2 and 3: close/harden/read back, then load and verify, before
    // creating links. Ordinary ruleset reload keeps its exact §7 sequence.
    if fresh {
        builder.harden_all();
    }
    if reload {
        builder.result.repairs.push(Repair::RulesetReload);
        builder.push(Step::LoadRuleset {
            fingerprint: desired.fingerprint,
            rendered: desired.rendered.clone(),
        });
        builder.push(Step::VerifyRuleset {
            fingerprint: desired.fingerprint,
        });
        builder.push(Step::FlushConntrack);
    }
    // Restore link configuration before route promotion. LinkCreate contains
    // every host/down/move/configure/up failure boundary from boot step 4.
    for repair in admitted
        .iter()
        .filter(|r| r.class() == RepairClass::Restore)
    {
        match repair {
            Repair::LinkRecreate { name } => {
                if unknown_inventory && name == &desired.link_order[0] {
                    continue;
                }
                builder.result.repairs.push(repair.clone());
                if let Some(link) = desired.links.get(name) {
                    for phase in [
                        LinkPhase::CleanupHost,
                        LinkPhase::HostAddDown,
                        LinkPhase::Move,
                        LinkPhase::Configure,
                    ] {
                        builder.push(Step::LinkCreate {
                            link: link.clone(),
                            phase,
                        });
                    }
                    builder.push(Step::LinkForwardingOff { name: name.clone() });
                    builder.harden_all();
                    builder.push(Step::LinkCreate {
                        link: link.clone(),
                        phase: LinkPhase::Up,
                    });
                }
            }
            Repair::LinkReconfigure { name } => {
                if unknown_inventory && name == &desired.link_order[0] {
                    continue;
                }
                builder.result.repairs.push(repair.clone());
                builder.push(Step::LinkDown { name: name.clone() });
                if let Some(link) = desired.links.get(name) {
                    let mut down = link.clone();
                    down.up = false;
                    builder.push(Step::LinkReconfigure { link: down });
                    builder.push(Step::LinkForwardingOff { name: name.clone() });
                    builder.harden_all();
                    builder.push(Step::LinkCreate {
                        link: link.clone(),
                        phase: LinkPhase::Up,
                    });
                }
            }
            Repair::HostLinkCleanup { name } => {
                builder.result.repairs.push(repair.clone());
                if let Some(link) = desired.links.get(name) {
                    builder.push(Step::LinkCreate {
                        link: link.clone(),
                        phase: LinkPhase::CleanupHost,
                    });
                }
            }
            Repair::ExitRehandshake { exit } => {
                builder.result.repairs.push(repair.clone());
                builder.push(Step::ReResolveEndpoint { exit: exit.clone() });
            }
            Repair::HardeningSysctl { .. }
            | Repair::RouteReplace { .. }
            | Repair::RulesetReload
            | Repair::ForwardingRestore
            | Repair::ExtraRouteDelete { .. }
            | Repair::ForeignLinkDown { .. }
            | Repair::PeerContainment { .. }
            | Repair::ExtraRuleDelete { .. }
            | Repair::TcHookDelete { .. }
            | Repair::PersistLatch { .. }
            | Repair::ForwardingOff
            | Repair::ExitDown { .. } => {}
        }
    }
    let mut switched = false;
    for (family, target) in &desired.routes {
        let route_admitted = admitted
            .iter()
            .any(|r| matches!(r, Repair::RouteReplace { family: f, .. } if f == family));
        if route_admitted
            && builder.model.default(*family) != &Known::Value(route_obs(target))
            && !builder
                .suppressed_keys
                .contains(&format!("route:{family:?}"))
            && builder.route_ready(target)
        {
            builder.result.repairs.push(Repair::RouteReplace {
                family: *family,
                target: target.clone(),
            });
            builder.push(Step::RouteReplace {
                family: *family,
                target: target.clone(),
            });
            switched = true;
        }
    }
    if switched {
        builder.push(Step::FlushConntrack);
    }
    let link_work = builder
        .result
        .steps
        .iter()
        .any(|s| matches!(s, Step::LinkForwardingOff { .. }));
    let restore_forwarding = admitted.contains(&Repair::ForwardingRestore)
        || reload
        || observed.forwarding_on() && link_work;
    if restore_forwarding
        && (!fresh
            || desired
                .links
                .iter()
                .all(|(name, want)| builder.model.links.get(name).is_some_and(|l| l.ready(want)))
                && desired.routes.iter().all(|(family, target)| {
                    builder.model.default(*family) == &Known::Value(route_obs(target))
                }))
        && !builder.model.forwarding_on()
        && !closed_by_policy(suppressed, effective_latch)
        && builder.can_forward()
    {
        builder.forward_on();
    } else if forwarding_change && builder.model.forwarding_off() && !fresh {
        builder.harden_all();
    }
    // A forwarding write already reapplied all hardening values. Otherwise only
    // the debounced, admitted hardening objects are written.
    let mut hardening_written = false;
    for repair in &admitted {
        if let Repair::HardeningSysctl { key } = repair
            && let Some(value) = desired.hardening.iter().find(|s| s.key.to_string() == *key)
            && builder.model.hardening.get(key) != Some(&Known::Value(value.value.clone()))
            && let Some(key) = HardeningKey::new(value.key.clone())
        {
            builder.result.repairs.push(repair.clone());
            builder.push(Step::WriteSysctl {
                key: key.clone(),
                value: value.value.clone(),
            });
            hardening_written = true;
        }
    }
    if hardening_written {
        builder.push(Step::ReadBackSysctls);
    }
    if !safe(&builder.model, desired) && !builder.model.forwarding_off() {
        builder.result.repairs.push(Repair::ForwardingOff);
        builder.push(Step::ForwardingOff);
        builder.harden_all();
    }
    if has_unknown_safety(observed) {
        builder.push(Step::Emit(PlannerEvent::ObservationUnknown));
    }
    if observed.edge_dead {
        builder.push(Step::Emit(PlannerEvent::EdgeDead));
    }
    builder.result
}
fn closed_by_policy(suppressed: &[(String, bool)], latch: Option<&Latch>) -> bool {
    suppressed.iter().any(|(_, safety)| *safety) || latch.is_some()
}
impl KernelModel {
    fn forwarding_on(&self) -> bool {
        self.forwarding_v4 == Known::Value(1)
            && self.forwarding_v6 == Known::Value(1)
            && self.client_forwarding_v4 == Known::Value(1)
            && self.default_forwarding_v4 == Known::Value(1)
            && self.default_forwarding_v6 == Known::Value(1)
            && self
                .links
                .values()
                .filter(|link| link.up == Known::Value(true) && link.owned())
                .all(|link| {
                    link.forwarding_v4 == Known::Value(1) && link.forwarding_v6 == Known::Value(1)
                })
    }
}
fn escalations(m: &KernelModel, desired: &Desired) -> Vec<Escalation> {
    let namespace = match m.namespace {
        NamespaceState::Ready | NamespaceState::Unknown => None,
        NamespaceState::NameGone => Some(Escalation::NamespaceNameGone),
        NamespaceState::InodeGone => Some(Escalation::NamespaceInodeGone),
        NamespaceState::EdgeElsewhere => Some(Escalation::EdgeInAnotherNamespace),
    };
    namespace
        .into_iter()
        .chain(
            m.host_links
                .iter()
                .filter(|(name, link)| desired.links.contains_key(*name) && !host_leftover(link))
                .map(|(name, _)| Escalation::HostLinkCollision(name.clone())),
        )
        .chain(
            m.links
                .iter()
                .filter(|(name, link)| desired.links.contains_key(*name) && !link.owned())
                .map(|(name, _)| Escalation::NamespaceLinkCollision(name.clone())),
        )
        .collect()
}
#[allow(clippy::too_many_lines)] // One explicit pass over each drift category.
fn detect(d: &Desired, m: &KernelModel) -> Vec<Repair> {
    let mut out = Vec::new();
    if matches!(m.ruleset, Known::Value(_))
        && m.ruleset != Known::Value(Ruleset::Verified(d.fingerprint))
    {
        out.push(Repair::RulesetReload);
    }
    let safety_reopen = m.links.iter().any(|(name, link)| {
        matches!(&link.tc_hooks, Known::Value(hooks) if !hooks.is_empty())
            || (!d.links.contains_key(name)
                && link.kind != Known::Value("loopback".into())
                && link.up != Known::Value(false))
    });
    if (!m.forwarding_on() || safety_reopen)
        && m.latch.is_none()
        && m.ruleset == Known::Value(Ruleset::Verified(d.fingerprint))
    {
        out.push(Repair::ForwardingRestore);
    }
    for value in &d.hardening {
        if let Scope::Link(name) = &value.key.scope
            && !m.links.contains_key(name.as_str())
        {
            continue;
        }
        let key = value.key.to_string();
        if m.hardening.get(&key) != Some(&Known::Value(value.value.clone())) {
            out.push(Repair::HardeningSysctl { key });
        }
    }
    for (family, target) in &d.routes {
        let desired_exit_unready = match target {
            RouteTarget::Exit(name) => !m.links.get(name.as_str()).is_some_and(|link| {
                d.links
                    .get(name.as_str())
                    .is_some_and(|want| link.ready(want))
            }),
            RouteTarget::Unreachable => false,
        };
        let rejecting = match m.default(*family) {
            Known::Value(DefaultRouteObs::Dev(name)) => {
                desired_exit_unready
                    || !d.exits.values().any(|n| n == name)
                    || !m
                        .links
                        .get(name)
                        .is_some_and(|l| d.links.get(name).is_some_and(|want| l.ready(want)))
            }
            Known::Unknown | Known::Value(DefaultRouteObs::Other(_)) => true,
            Known::Value(DefaultRouteObs::Missing | DefaultRouteObs::Unreachable) => false,
        };
        if rejecting {
            out.push(Repair::RouteReplace {
                family: *family,
                target: RouteTarget::Unreachable,
            });
        } else if m.default(*family) != &Known::Value(route_obs(target)) {
            out.push(Repair::RouteReplace {
                family: *family,
                target: target.clone(),
            });
        }
    }
    if let Known::Value(routes) = &m.extra_routes {
        let mut routes = routes.clone();
        routes.sort_by_cached_key(|route| format!("{route:?}"));
        routes.dedup();
        out.extend(
            routes
                .into_iter()
                .map(|route| Repair::ExtraRouteDelete { route }),
        );
    }
    for name in &d.link_order {
        let want = &d.links[name];
        match m.links.get(name) {
            None if m.links_complete && m.host_links.get(name).is_none_or(host_leftover) => {
                out.push(Repair::LinkRecreate { name: name.clone() });
            }
            Some(link)
                if link.owned()
                    && (!link.matches_config(want) || want.up && link.up != Known::Value(true)) =>
            {
                out.push(Repair::LinkReconfigure { name: name.clone() });
            }
            _ => {}
        }
    }
    for (name, link) in &m.links {
        if let Some(want) = d.links.get(name)
            && link.owned()
            && link.up != Known::Value(false)
            && let Known::Value(peers) = &link.peers
            && !same_peers(peers, &want.peers)
        {
            out.push(Repair::PeerContainment { name: name.clone() });
        }
        let foreign = !(d.links.contains_key(name) && link.owned()
            || link.kind == Known::Value("loopback".into()));
        if foreign && link.up != Known::Value(false) {
            out.push(Repair::ForeignLinkDown { name: name.clone() });
        }
        if d.disconnected && d.exits.values().any(|n| n == name) && link.up != Known::Value(false) {
            out.push(Repair::ExitDown { name: name.clone() });
        }
        if let Known::Value(hooks) = &link.tc_hooks {
            let mut hooks = hooks.clone();
            hooks.sort();
            hooks.dedup();
            out.extend(hooks.into_iter().map(|hook| Repair::TcHookDelete {
                name: name.clone(),
                hook,
            }));
        }
    }
    if let Known::Value(rules) = &m.extra_rules {
        let mut rules = rules.clone();
        rules.sort();
        rules.dedup();
        out.extend(
            rules
                .into_iter()
                .map(|rule| Repair::ExtraRuleDelete { rule }),
        );
    }
    for exit in &m.stale_exits {
        if d.exits.contains_key(exit) {
            out.push(Repair::ExitRehandshake { exit: exit.clone() });
        }
    }
    for name in m.host_links.keys() {
        if d.links.contains_key(name)
            && m.links.contains_key(name)
            && m.host_links.get(name).is_some_and(host_leftover)
        {
            out.push(Repair::HostLinkCleanup { name: name.clone() });
        }
        // Missing namespace links include host cleanup in LinkRecreate's budget.
    }
    out
}
fn has_unknown_safety(m: &KernelModel) -> bool {
    m.namespace == NamespaceState::Unknown
        || !m.links_complete
        || matches!(m.ruleset, Known::Unknown)
        || matches!(m.forwarding_v4, Known::Unknown)
        || matches!(m.forwarding_v6, Known::Unknown)
        || matches!(m.client_forwarding_v4, Known::Unknown)
        || matches!(m.default_forwarding_v4, Known::Unknown)
        || matches!(m.default_forwarding_v6, Known::Unknown)
        || matches!(m.extra_rules, Known::Unknown)
        || matches!(m.extra_routes, Known::Unknown)
        || matches!(m.default_v4, Known::Unknown)
        || matches!(m.default_v6, Known::Unknown)
        || m.links.values().any(|l| {
            matches!(l.tc_hooks, Known::Unknown)
                || matches!(l.forwarding_v4, Known::Unknown)
                || matches!(l.forwarding_v6, Known::Unknown)
                || matches!(l.kind, Known::Unknown)
                || matches!(l.ours, Known::Unknown)
                || matches!(l.up, Known::Unknown)
                || matches!(l.peers, Known::Unknown)
        })
}
struct Builder<'a> {
    result: Plan,
    model: KernelModel,
    desired: &'a Desired,
    suppressed_keys: BTreeSet<String>,
}
impl Builder<'_> {
    fn push(&mut self, step: Step) {
        self.model = self.model.apply(&step);
        self.result.steps.push(step);
    }
    fn harden_all(&mut self) {
        for value in &self.desired.hardening {
            if let Scope::Link(name) = &value.key.scope
                && !self.model.links.contains_key(name.as_str())
            {
                continue;
            }
            if let Some(key) = HardeningKey::new(value.key.clone())
                && !self
                    .suppressed_keys
                    .contains(&format!("sysctl:{}", value.key))
            {
                self.push(Step::WriteSysctl {
                    key,
                    value: value.value.clone(),
                });
            }
        }
        self.push(Step::ReadBackSysctls);
    }
    fn can_forward(&self) -> bool {
        let mut closed = self.model.clone();
        closed.forwarding_v4 = Known::Value(0);
        closed.forwarding_v6 = Known::Value(0);
        closed.client_forwarding_v4 = Known::Value(0);
        !self.desired.disconnected
            && self.model.latch.is_none()
            && self.model.ruleset == Known::Value(Ruleset::Verified(self.desired.fingerprint))
            && safe(&closed, self.desired)
    }
    fn forward_on(&mut self) {
        if self.result.steps.last() != Some(&Step::FlushConntrack) {
            self.push(Step::FlushConntrack);
        }
        self.result.repairs.push(Repair::ForwardingRestore);
        self.push(Step::ForwardingOn {
            requires: self.desired.fingerprint,
        });
        self.harden_all();
    }
    fn route_ready(&self, target: &RouteTarget) -> bool {
        self.model.route_ready(self.desired, target)
    }

    fn tighten(&mut self, repair: &Repair) {
        self.result.repairs.push(repair.clone());
        match repair {
            Repair::PeerContainment { name } => {
                self.push(Step::LinkDown { name: name.clone() });
            }
            Repair::ForeignLinkDown { name } => {
                self.push(Step::LinkDown { name: name.clone() });
                self.push(Step::Emit(PlannerEvent::SafetyDrift {
                    object: repair.object(),
                }));
            }
            Repair::ExitDown { name } => {
                for family in [Family::V4, Family::V6] {
                    if self.model.default(family)
                        == &Known::Value(DefaultRouteObs::Dev(name.clone()))
                    {
                        self.push(Step::RouteReplace {
                            family,
                            target: RouteTarget::Unreachable,
                        });
                    }
                }
                self.push(Step::LinkDown { name: name.clone() });
            }
            Repair::TcHookDelete { name, hook } => {
                let foreign = !self.desired.links.contains_key(name)
                    || self.model.links.get(name).is_none_or(|l| !l.owned());
                if foreign
                    && self
                        .model
                        .links
                        .get(name)
                        .is_some_and(|l| l.up != Known::Value(false))
                {
                    self.push(Step::LinkDown { name: name.clone() });
                }
                self.push(Step::TcDelete {
                    name: name.clone(),
                    hook: hook.clone(),
                });
                self.push(Step::Emit(PlannerEvent::SafetyDrift {
                    object: repair.object(),
                }));
            }
            Repair::ExtraRouteDelete { route } => self.push(Step::RouteDelete {
                route: route.clone(),
            }),
            Repair::ExtraRuleDelete { rule } => self.push(Step::RuleDelete { rule: rule.clone() }),
            Repair::RouteReplace {
                family,
                target: RouteTarget::Unreachable,
            } => {
                if self.model.default(*family) != &Known::Value(DefaultRouteObs::Unreachable) {
                    self.push(Step::RouteReplace {
                        family: *family,
                        target: RouteTarget::Unreachable,
                    });
                }
            }
            Repair::RulesetReload
            | Repair::ForwardingRestore
            | Repair::HardeningSysctl { .. }
            | Repair::RouteReplace {
                target: RouteTarget::Exit(_),
                ..
            }
            | Repair::LinkRecreate { .. }
            | Repair::LinkReconfigure { .. }
            | Repair::ExitRehandshake { .. }
            | Repair::PersistLatch { .. }
            | Repair::ForwardingOff
            | Repair::HostLinkCleanup { .. } => {}
        }
    }
}

/// Administrative transition only. The caller has authorized `repair clear` or
/// already verified a full apply; the daemon must never call this on its own.
#[must_use]
pub fn clear_latch(_latch: &Latch, action: ClearLatch, budgets: &Budgets) -> LatchTransition {
    let mut budgets = budgets.clone();
    budgets.pending_safety.clear();
    budgets.persistence_failed = false;
    for class in [
        SafetyClass::Ruleset,
        SafetyClass::ForeignLink,
        SafetyClass::TcHook,
    ] {
        budgets.attempts.remove(class.key());
        budgets.suppressed.remove(class.key());
    }
    LatchTransition {
        budgets,
        latch: None,
        event: PlannerEvent::AdminAction { action },
    }
}

/// Re-observe after failure and converge toward the *previous* applied version.
/// This function cannot advance the persisted `applied_version`.
#[must_use]
pub fn replan_after_failure(
    failed: &Step,
    desired_prev: &Desired,
    observed: &KernelModel,
    budgets: &Budgets,
    latch: Option<&Latch>,
    debounce: &Debounce,
    now: MonoTime,
) -> Plan {
    let mut budgets = budgets.clone();
    if matches!(failed, Step::PersistLatch { .. }) {
        budgets.persistence_failed = true;
    }
    // Whatever failed, the forwarding gate is closed by this replan, never by an external
    // writer, so the reopen that follows must not be charged to the forwarding budget.
    budgets.closed_by_planner = true;
    let mut result = plan(desired_prev, observed, &budgets, latch, debounce, now);
    if observed.namespace != NamespaceState::InodeGone
        && result.steps.first() != Some(&Step::ForwardingOff)
    {
        result.steps.insert(0, Step::ForwardingOff);
        result.repairs.push(Repair::ForwardingOff);
        result.budgets.closed_by_planner = !result
            .steps
            .iter()
            .any(|step| matches!(step, Step::ForwardingOn { .. }));
    }
    // Alert before persistence and every fallible tightening operation.
    let boundary = usize::from(result.steps.first() == Some(&Step::ForwardingOff));
    result.steps.insert(
        boundary,
        Step::Emit(PlannerEvent::ReplanAfterFailure {
            failed: Box::new(failed.clone()),
            applied_version: desired_prev.applied_version(),
        }),
    );
    result
}
