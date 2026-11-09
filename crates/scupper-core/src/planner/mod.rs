//! Pure, single-writer repair planning for the last verified applied version.
//!
//! Callers supply monotonic time and fresh observations on every tick. Execution
//! follows each step's [`StepFailure`] policy and re-observes before calling
//! [`replan_after_failure`]. The planner never changes `applied_version`, reads
//! credentials, clears quarantine automatically, or performs kernel operations.
//!
//! # Execution and fighting contract
//!
//! Adopt [`Plan::latch`] in memory before step zero and union it with persisted
//! quarantine on every tick. A new latch orders forwarding off, failure and
//! suppression alerts, tightening, then non-fatal persistence before Restore.
//! Every memory-only latch is retried on every plan until fresh observations
//! confirm persistence. Keep persisted observations separate from the memory
//! latch: adopting a memory latch does not make `observed.latch` Some.
//!
//! [`Step::failure`] carries the executor policy. A failed `Contain` step
//! (including forwarding off) sets containment failure: continue later `Contain`
//! and `NonFatal` steps but skip every later `Stop` (Restore) step, including all
//! gate raises. Then re-observe and replan. A failed `Stop` step stops immediately.
//! No rollback is assumed. `NonFatal` persistence and event failures do not
//! change this policy or block later work. On failed persistence, retain the
//! memory latch and report the attempt through [`replan_after_failure`] with
//! the failed `PersistLatch` step, or set
//! [`Budgets::persistence_failed`] before continuing and retain those budgets.
//! Subsequent plans emit [`PlannerEvent::PersistenceFailed`] before retrying;
//! observing persisted quarantine clears that failure flag. A failed global
//! forwarding write must not prevent hook deletion or foreign-link containment.
//!
//! Budgets stop Restore operations, never Tighten operations. Safety budgets
//! cover the namespace-wide [`SafetyClass`], rather than volatile link or hook
//! identities. Reopening after tc/link removal counts once per class per plan;
//! ruleset loading counts only positively observed mismatches. Pending safety
//! classes survive a blocked reopening in [`Budgets`]. Other Restore budgets
//! remain per object. Reservations count emitted attempts even if execution
//! later fails. Repeated suppression preserves the first latch and emits its
//! suppression event only once per budget window. Only safety suppression
//! (the latch) blocks reopening; other suppression skips that object's Restore.
//! [`Budgets::closed_by_planner`] tracks issued gate closures until an emitted
//! reopening or observed recovery, so Unknown handling, reload and link work
//! never spend the generic external-forwarding budget. An external closure
//! after an emitted reopening is charged. [`Budgets::downed_by_planner`] exempts
//! restoration of only the client UP state after ingress quarantine, until
//! observed up; concurrent configuration drift remains budgeted.
//! Explicit administrative clearing resets safety attempts and pending classes
//! for both repair clear and verified full apply.
//! Three attempts per safety class permit nine mixed-class reopenings in ten
//! minutes; the next detected exhausted class latches. This is the accepted
//! bound for independent class budgets (ADR 0031).
//!
//! | Drift | Immediate Tighten | Restore |
//! | --- | --- | --- |
//! | Known ruleset mismatch | Forwarding off | Budgeted load and verify |
//! | Unknown ruleset | Forwarding off | Wait for a positive observation |
//! | Known tc/foreign link | Delete hook / link down | Class-budgeted reopening |
//! | Unknown tc/link inventory | Forwarding off; client down on second tick | Normal link Restore after inventory recovers |
//! | Known peer `AllowedIPs` mismatch | Owned link down before debounce/budget | Normal configuration Restore |
//! | Active exit MTU/keepalive mismatch | Default becomes unreachable on first sighting | Debounced configuration repair, then route promotion |
//!
//! Every forwarding enable has a conntrack flush immediately before it in the
//! same plan, including recovery after interruption. Only a gone namespace
//! inode prevents namespace steps; other escalations accompany normal planning.
//! A failed observation is never a placeholder success. On the first incomplete
//! tc/link inventory tick, an unidentifiable bypass may remain until the second
//! tick closes client ingress; [`safe`] does not certify that Unknown state.

mod desired;
mod model;
mod plan;
mod types;

pub use desired::Desired;
pub use model::{
    ForwardingGates, KernelLink, KernelModel, ObservationDetails, ObservationItem, safe,
};
pub use plan::{clear_latch, plan, replan_after_failure};
pub use types::*;
