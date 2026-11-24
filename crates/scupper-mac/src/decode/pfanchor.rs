//! Owned-anchor protocol and proposed per-build pfctl rows. No R7 row is reviewed.
//! Parser recognition is distinct from qualification; native callers must pass
//! the review gate even when the candidate text parses exactly.
use super::pftext::{self, Build};
use crate::platform::SysError;
use std::collections::BTreeSet;

pub(crate) const UNREVIEWED: SysError = SysError::Failed("pf anchor text unreviewed");
pub(crate) const SELECTIVE_UNQUALIFIED: SysError =
    SysError::Failed("interface state removal unqualified");

/// Immutable two-component namespace. Only `Paths` chooses the native value.
#[derive(Clone, Debug)]
pub struct AnchorPath(String);
impl AnchorPath {
    /// Validate a fixed anchor path without accepting pf wildcard syntax.
    ///
    /// # Errors
    /// Rejects anything except two nonempty safe components.
    pub fn new(path: &str) -> Result<Self, SysError> {
        let components: Vec<_> = path.split('/').collect();
        if components.len() != 2 || !components.iter().all(|s| component(s)) {
            return Err(SysError::Failed("invalid anchor path"));
        }
        Ok(Self(path.into()))
    }
    /// Exact path for every operation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
    fn parent(&self) -> &str {
        self.0.split_once('/').map_or("", |(p, _)| p)
    }
    fn child(&self) -> &str {
        self.0.split_once('/').map_or("", |(_, c)| c)
    }
}
fn component(s: &str) -> bool {
    !s.is_empty()
        && !matches!(s, "." | "..")
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

/// Sub-operation determines the entire allowed output grammar.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation {
    /// Load source on stdin.
    Load,
    /// Immediate children of the specified parent.
    Inventory,
    /// Filter rule text.
    Filter,
    /// Raw qualification syntax, never used by the native adapter.
    HarnessFilter,
    /// Translation rules, tables or descendant inventories, all required empty.
    Extra,
    /// Scoped rule flush.
    Rules,
    /// Scoped translation flush.
    Nat,
    /// Scoped table flush.
    Tables,
    /// Scoped dummynet rule flush (candidate output, unreviewed).
    Dummynet,
    /// Global state flush (irreversible ownership exception).
    States,
}
/// Parsed result; missing is available only from exact nonexistent-anchor text.
#[derive(Debug, PartialEq, Eq)]
pub enum Text {
    /// Fully delimited text (including the empty existing ruleset).
    Present(String),
    /// Exact nonexistent result, which alone never establishes absence.
    Missing,
    /// Exact named missing-parent diagnostic; must agree with the queried parent.
    MissingParent(String),
}
/// Source-derived candidates for owner review, never runner evidence.
pub const LOAD_WARNING: &[u8] = b"pfctl: Use of -f option, could result in flushing of rules\npresent in the main ruleset added by the system at startup.\nSee /etc/pf.conf for further details.\n";

/// Review status is keyed by build; neither build is qualified in pass 1.
#[must_use]
pub fn reviewed(build: &Build) -> bool {
    const ROWS: [(&str, bool); 2] = [("24H232", false), ("25G332", false)];
    ROWS.iter()
        .find(|(name, _)| *name == build.as_str())
        .is_some_and(|(_, reviewed)| *reviewed)
}
fn known(build: &Build) -> bool {
    pftext::BUILDS.contains(&build.as_str())
}
/// Parse a candidate row. Calling this is never qualification or permission to
/// report success. `qualified` is the adapter's only text-decision entry point.
///
/// # Errors
/// Unknown build, exit, diagnostic, malformed/truncated/extra line or foreign class.
pub fn proposed(
    build: &Build,
    op: Operation,
    rc: i32,
    stdout: &[u8],
    stderr: &[u8],
) -> Result<Text, SysError> {
    if !known(build) {
        return Err(SysError::Unknown);
    }
    let original_stderr = stderr;
    let stderr = pftext::stderr(build, stderr);
    // Source show helpers report errors but their caller ignores the return:
    // these proposed missing rows have rc 0. They remain unreviewed per build.
    if stdout.is_empty() && rc == 0 {
        if matches!(op, Operation::Filter | Operation::HarnessFilter)
            && stderr == b"pfctl: DIOCGETRULES: Invalid argument\n"
        {
            return Ok(Text::Missing);
        }
        if op == Operation::Inventory {
            for parent in ["com.apple", "scupper-qual"] {
                if stderr == format!("Anchor '{parent}' not found.\n").as_bytes() {
                    return Ok(Text::MissingParent(parent.into()));
                }
            }
        }
    }
    if rc != 0 {
        return Err(SysError::Unknown);
    }
    let accepted = match op {
        Operation::Load => {
            stdout.is_empty()
                && (original_stderr.is_empty()
                    || original_stderr == pftext::ALTQ_PREAMBLE
                    || original_stderr == LOAD_WARNING
                    || original_stderr.strip_prefix(LOAD_WARNING) == Some(pftext::ALTQ_PREAMBLE)
                    || original_stderr.strip_prefix(pftext::ALTQ_PREAMBLE) == Some(LOAD_WARNING))
        }
        Operation::Rules => stdout.is_empty() && stderr == b"rules cleared\n",
        Operation::Dummynet => stdout.is_empty() && stderr == b"dummynet cleared\n",
        Operation::Nat => stdout.is_empty() && stderr == b"nat cleared\n",
        Operation::Tables => stdout.is_empty() && numeric(stderr, b" tables deleted.\n"),
        Operation::States => stdout.is_empty() && numeric(stderr, b" states cleared\n"),
        Operation::Inventory | Operation::Filter | Operation::HarnessFilter | Operation::Extra => {
            stderr.is_empty()
        }
    };
    if !accepted {
        return Err(SysError::Unknown);
    }
    let text = std::str::from_utf8(stdout).map_err(|_| SysError::Unknown)?;
    if text.contains('\0') || (!text.is_empty() && !text.ends_with('\n')) {
        return Err(SysError::Unknown);
    }
    if op == Operation::Inventory {
        inventory(text)?;
    }
    if matches!(op, Operation::Filter | Operation::HarnessFilter) {
        if text.lines().any(str::is_empty) {
            return Err(SysError::Unknown);
        }
        for line in text.lines() {
            if op == Operation::HarnessFilter && line.starts_with("anchor ") {
                scupper_core::mac::parse::pf_rules(&format!("{line}\n"))
                    .map_err(|_| SysError::Unknown)?;
                continue;
            }
            if !["pass ", "block "]
                .iter()
                .any(|prefix| line.starts_with(prefix))
            {
                return Err(SysError::Unknown);
            }
            if op == Operation::Filter {
                scupper_core::mac::parse::pf_rules(&format!("{line}\n"))
                    .map_err(|_| SysError::Unknown)?;
                continue;
            }
            // Accept the exact harness-labelled floating-state row as well as
            // the policy subset. This is syntax validation only: never change
            // the text returned to the caller or claim semantic equivalence.
            let body = line.strip_suffix(" label \"scupper-qual\"").unwrap_or(line);
            let validation = body.strip_suffix(" keep state").map_or_else(
                || format!("{body}\n"),
                |prefix| format!("{prefix} keep state (if-bound)\n"),
            );
            scupper_core::mac::parse::pf_rules(&validation).map_err(|_| SysError::Unknown)?;
        }
    }
    if op == Operation::Extra && !text.is_empty() {
        return Err(SysError::Failed("foreign content in owned anchor"));
    }
    Ok(Text::Present(text.into()))
}
fn numeric(bytes: &[u8], suffix: &[u8]) -> bool {
    bytes.strip_suffix(suffix).is_some_and(|digits| {
        !digits.is_empty()
            && digits.len() <= 10
            && digits.iter().all(u8::is_ascii_digit)
            && std::str::from_utf8(digits)
                .ok()
                .and_then(|s| s.parse::<u32>().ok())
                .is_some()
    })
}
fn inventory(text: &str) -> Result<BTreeSet<&str>, SysError> {
    let mut names = BTreeSet::new();
    for line in text.lines() {
        // pfctl -sA prints two leading spaces per level, even without -v.
        let name = line.strip_prefix("  ").ok_or(SysError::Unknown)?;
        let components: Vec<_> = name.split('/').collect();
        if components.len() > 2
            || !components.iter().all(|part| component(part))
            || !names.insert(name)
        {
            return Err(SysError::Unknown);
        }
    }
    Ok(names)
}
fn inventory_at<'a>(text: &'a str, parent: &str) -> Result<BTreeSet<&'a str>, SysError> {
    let prefix = format!("{parent}/");
    inventory(text)?
        .into_iter()
        .map(|name| {
            let relative = if parent.is_empty() {
                name
            } else {
                name.strip_prefix(prefix.as_str())
                    .ok_or(SysError::Unknown)?
            };
            if !component(relative) {
                return Err(SysError::Unknown);
            }
            Ok(relative)
        })
        .collect()
}
/// Native review gate. Candidate matching never makes an unreviewed row succeed.
///
/// # Errors
/// All incomplete, unknown or unreviewed rows.
pub fn qualified(
    build: &Build,
    op: Operation,
    rc: i32,
    out: &[u8],
    err: &[u8],
) -> Result<Text, SysError> {
    if op == Operation::HarnessFilter {
        return Err(SysError::Unknown);
    }
    let result = proposed(build, op, rc, out, err)?;
    if !reviewed(build) {
        return Err(UNREVIEWED);
    }
    Ok(result)
}

/// Serialized command interface. One caller deadline must cover every subcall.
pub trait Commands {
    /// Execute through the bounded runner, check complete evidence and review gate.
    ///
    /// # Errors
    /// Unknown/incomplete/unreviewed results are never empty.
    fn call(&mut self, op: Operation, args: &[&str], input: &[u8]) -> Result<Text, SysError>;
}
/// Independent read using the parent inventory and corroborating rules read.
///
/// # Errors
/// Any incomplete or inconsistent result, including foreign content.
pub fn read(io: &mut impl Commands, path: &AnchorPath) -> Result<Option<String>, SysError> {
    let parent = io.call(Operation::Inventory, &["-a", path.parent(), "-sA"], &[])?;
    let present = match parent {
        Text::Present(text) => inventory_at(&text, path.parent())?.contains(path.child()),
        Text::MissingParent(parent) if parent == path.parent() => {
            let Text::Present(root) = io.call(Operation::Inventory, &["-sA"], &[])? else {
                return Err(SysError::Unknown);
            };
            if inventory_at(&root, "")?.contains(path.parent()) {
                return Err(SysError::Unknown);
            }
            false
        }
        _ => return Err(SysError::Unknown),
    };
    let filter = io.call(Operation::Filter, &["-a", path.as_str(), "-sr"], &[])?;
    match (present, filter) {
        (false, Text::Missing) => Ok(None),
        (true, Text::Present(text)) => {
            for flag in ["-sn", "-sT", "-sA", "-sd"] {
                let extra = io.call(Operation::Extra, &["-a", path.as_str(), flag], &[])?;
                if extra != Text::Present(String::new()) {
                    return Err(SysError::Failed("foreign content in owned anchor"));
                }
            }
            Ok(Some(text))
        }
        _ => Err(SysError::Unknown),
    }
}
/// Scoped removal; an existing empty child is not absent under the contract.
///
/// # Errors
/// Failed flush or any failure to confirm absence, including a persistent empty child.
pub fn remove(io: &mut impl Commands, path: &AnchorPath) -> Result<(), SysError> {
    if read(io, path)?.is_none() {
        return Ok(());
    }
    for (op, class) in [
        (Operation::Rules, "rules"),
        (Operation::Nat, "nat"),
        (Operation::Tables, "Tables"),
        (Operation::Dummynet, "dummynet"),
    ] {
        io.call(op, &["-a", path.as_str(), "-F", class], &[])?;
    }
    if read(io, path)?.is_some() {
        return Err(SysError::Failed("empty anchor persists"));
    }
    Ok(())
}
/// Sanity only: `AnchorText` remains constructible exclusively by its renderer.
///
/// # Errors
/// Embedded NUL or missing final newline.
pub fn source(text: &str) -> Result<(), SysError> {
    if text.contains('\0') || !text.ends_with('\n') {
        return Err(SysError::Failed("invalid anchor text"));
    }
    Ok(())
}
/// Selective state removal has no qualified native implementation.
///
/// # Errors
/// A nonempty set always returns the exact repair-triggering error, with no tool.
pub fn selective(empty: bool) -> Result<(), SysError> {
    if empty {
        Ok(())
    } else {
        Err(SELECTIVE_UNQUALIFIED)
    }
}

#[cfg(test)]
#[path = "pfanchor_tests.rs"]
mod tests;
