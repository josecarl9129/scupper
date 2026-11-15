//! State readers copied from main 4442253 for binary rollback checks.
#![allow(dead_code)]
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// Expansion of text_type!(ExitId, ...) in that release's config/types.rs.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(transparent)]
pub struct ExitId(pub String);

/// Persisted operator selection, distinct from route intent and kernel state.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub enum Selection {
    /// Use the configured candidate order.
    #[default]
    Auto,
    /// Prefer an exit, permitting fallback in a future multi-exit release.
    Prefer(ExitId),
    /// Use only this exit.
    Pin(ExitId),
    /// Require observed closure before reporting an administrative disconnect.
    Disconnected,
}

/// Persisted safety latch; consumers must honor it before enabling forwarding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Quarantine {
    /// Why the repair budget was exhausted.
    pub reason: String,
    /// The object whose recurring drift triggered quarantine.
    pub object: String,
    /// Unix seconds when the latch was set.
    pub since_unix: u64,
}

/// On-disk state schema. Missing optional fields are refused, as are unknown fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    /// The supported state schema, currently 1.
    pub schema: u32,
    /// Last successfully applied immutable configuration version.
    #[serde(deserialize_with = "required_option")]
    pub applied_version: Option<u64>,
    /// Durable operator selection, including deliberate disconnection.
    pub selection: Selection,
    /// Persistent quarantine latch, cleared only by explicit administrative action.
    #[serde(deserialize_with = "required_option")]
    pub quarantine: Option<Quarantine>,
}
fn required_option<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    d: D,
) -> Result<Option<T>, D::Error> {
    Option::deserialize(d)
}
/// Numbered boot checkpoints from DESIGN §15.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum BootStep {
    /// 0: acquire the global writer lock, with a bounded wait.
    Lock = 0,
    /// 8: verify modules, loading missing ones only for a fresh namespace.
    Modules = 8,
    /// 1: resolve all inputs and open or create the foreign namespace.
    Inputs = 1,
    /// 2: close forwarding and verify hardening.
    Close = 2,
    /// 3: validate, load and canonically verify the ruleset.
    Ruleset = 3,
    /// 4: create host-born tunnels, move by descriptor and configure.
    Links = 4,
    /// 5: reassert the persisted default routes.
    Routes = 5,
    /// 6: enable forwarding only after verification, unless quarantined or Disconnected.
    Forwarding = 6,
    /// 7: durably publish the per-boot namespace identity and report.
    Record = 7,
}

/// A single step's outcome. Unrun steps do not appear in the report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepResult {
    /// Numbered operation.
    pub step: BootStep,
    /// Failure reason, with bounded diagnostics but never secret command output.
    pub error: Option<String>,
    /// This step needed no writes because the namespace was adopted.
    pub adopted: bool,
}

/// Per-boot namespace identity, never persisted across reboots.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NamespaceIdentity {
    /// Namespace filesystem device.
    pub dev: u64,
    /// Namespace inode.
    pub ino: u64,
}

/// Complete or stopped boot attempt; the first failed step ends the attempt.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct BootReport {
    /// Ordered attempted steps.
    pub steps: Vec<StepResult>,
    /// Applied immutable configuration, when input resolution succeeded.
    pub applied_version: Option<u64>,
    /// Held namespace identity, when opened.
    pub netns: Option<NamespaceIdentity>,
    /// Alert-worthy input loss and operational warnings.
    pub warnings: Vec<String>,
    /// Whether the namespace passed the verify-only adoption criteria.
    pub adopted: bool,
    /// Owned `WireGuard` names and ifindexes verified through the held namespace.
    #[serde(default)]
    pub owned_links: BTreeMap<String, u32>,
}
