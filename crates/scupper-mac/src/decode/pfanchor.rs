//! Owned-anchor protocol; per-build rows reviewed against CI 45355500636.
//! Parser recognition is distinct from qualification; native callers must pass
//! the review gate even when the candidate text parses exactly.
use super::pftext::{self, Build};
use crate::platform::SysError;
use std::collections::BTreeSet;

pub(crate) const UNSUPPORTED_BUILD: SysError = SysError::Failed("unsupported pf anchor build");
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
    /// Filter and scrub rule text.
    Filter,
    /// Raw qualification syntax, never used by the native adapter.
    HarnessFilter,
    /// Translation rules, tables and unreviewed descendant inventories: empty only.
    Extra,
    /// Dummynet show, including its reviewed missing-anchor diagnostic.
    DummynetShow,
    /// Scoped rule flush.
    Rules,
    /// Scoped translation flush.
    Nat,
    /// Scoped table flush.
    Tables,
    /// Scoped dummynet rule flush.
    Dummynet,
    /// Global state flush (irreversible ownership exception).
    States,
}
/// Parsed result; missing is available only from exact nonexistent-anchor text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Text {
    /// Fully delimited text (including the empty existing ruleset).
    Present(String),
    /// Exact nonexistent result, which alone never establishes absence.
    Missing,
    /// Exact named missing-parent diagnostic; must agree with the queried parent.
    MissingParent(String),
}
/// Exact load warning preceding the ALTQ preamble on both reviewed builds.
pub const LOAD_WARNING: &[u8] = b"pfctl: Use of -f option, could result in flushing of rules\npresent in the main ruleset added by the system at startup.\nSee /etc/pf.conf for further details.\n\n";

/// Reviewed text and descendant coverage are separate per-build decisions.
struct Review {
    build: &'static str,
    descendants_reviewed: bool,
}
const REVIEWS: [Review; 2] = [
    Review {
        build: "24H232",
        descendants_reviewed: false,
    },
    Review {
        build: "25G332",
        descendants_reviewed: false,
    },
];
/// Text review status grants no enforcement qualification.
#[must_use]
pub fn reviewed(build: &Build) -> bool {
    REVIEWS.iter().any(|row| row.build == build.as_str())
}
pub(crate) fn descendants_reviewed(build: &Build) -> bool {
    REVIEWS
        .iter()
        .any(|row| row.build == build.as_str() && row.descendants_reviewed)
}
fn require_review(io: &impl Commands) -> Result<(), SysError> {
    if !reviewed(&io.build()?) {
        return Err(UNSUPPORTED_BUILD);
    }
    Ok(())
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
    let stderr = if op == Operation::Load {
        original_stderr
    } else {
        original_stderr
            .strip_prefix(pftext::ALTQ_PREAMBLE)
            .ok_or(SysError::Unknown)?
    };
    // Source show helpers report errors but their caller ignores the return:
    // these reviewed missing rows have rc 0, so status alone proves no success.
    if stdout.is_empty() && rc == 0 {
        if matches!(
            op,
            Operation::Filter | Operation::HarnessFilter | Operation::DummynetShow
        ) && stderr == b"pfctl: DIOCGETRULES: Invalid argument\n"
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
                && original_stderr.strip_prefix(LOAD_WARNING) == Some(pftext::ALTQ_PREAMBLE)
        }
        Operation::Rules => stdout.is_empty() && stderr == b"rules cleared\n",
        Operation::Dummynet => stdout.is_empty() && stderr == b"dummynet cleared\n",
        Operation::Nat => stdout.is_empty() && stderr == b"nat cleared\n",
        Operation::Tables => stdout.is_empty() && numeric(stderr, b" tables deleted.\n"),
        Operation::States => stdout.is_empty() && numeric(stderr, b" states cleared\n"),
        Operation::Inventory
        | Operation::Filter
        | Operation::HarnessFilter
        | Operation::Extra
        | Operation::DummynetShow => stderr.is_empty(),
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
            if op == Operation::Filter
                && (["scrub ", "scrub-anchor ", "anchor "]
                    .iter()
                    .any(|p| line.starts_with(p))
                    || line.contains('<'))
            {
                return Err(SysError::Failed("foreign content in owned anchor"));
            }
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
    if matches!(op, Operation::Extra | Operation::DummynetShow) && !text.is_empty() {
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
        if components.len() > 10
            || !components.iter().all(|part| component(part))
            || !names.insert(name)
        {
            return Err(SysError::Unknown);
        }
    }
    Ok(names)
}
pub(crate) fn inventory_at<'a>(text: &'a str, parent: &str) -> Result<BTreeSet<&'a str>, SysError> {
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
    /// Build identity, obtained without spawning pfctl.
    ///
    /// # Errors
    /// Missing or incomplete OS build identity.
    fn build(&self) -> Result<Build, SysError>;
    /// Separate coverage gate; test I/O can exercise a future reviewed row.
    ///
    /// # Errors
    /// Missing or incomplete OS build identity.
    fn descendants_reviewed(&self) -> Result<bool, SysError> {
        Ok(descendants_reviewed(&self.build()?))
    }

    /// Attempt emergency source load, returning only a diagnostic exit code.
    /// This is never qualification; the caller must validate the owned path and
    /// canonical Lockdown bytes first and must return Unknown even on rc 0.
    ///
    /// # Errors
    /// Failed or incomplete command evidence.
    fn emergency_load(&mut self, args: &[&str], input: &[u8]) -> Result<i32, SysError> {
        self.call(Operation::Load, args, input).map(|_| 0)
    }

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
            let mut count = 1;
            let recursive = io.descendants_reviewed()?;
            empty_classes(io, path.as_str(), 0, &mut count, recursive)?;
            Ok((!text.is_empty()).then_some(text))
        }
        _ => Err(SysError::Unknown),
    }
}
// Only immediate children with exact, strictly owned paths can be traversed.
fn empty_classes(
    io: &mut impl Commands,
    path: &str,
    depth: usize,
    count: &mut usize,
    recursive: bool,
) -> Result<(), SysError> {
    let mut children = BTreeSet::new();
    for flag in ["-sn", "-sT", "-sA", "-sd"] {
        let op = match flag {
            "-sd" => Operation::DummynetShow,
            "-sA" if recursive => Operation::Inventory,
            _ => Operation::Extra,
        };
        let extra = io.call(op, &["-a", path, flag], &[])?;
        if flag == "-sA" && recursive {
            let Text::Present(text) = extra else {
                return Err(SysError::Unknown);
            };
            children = inventory_at(&text, path)?
                .into_iter()
                .map(str::to_owned)
                .collect();
        } else if extra != Text::Present(String::new()) {
            return Err(SysError::Failed("foreign content in owned anchor"));
        }
    }
    for child in children {
        *count += 1;
        if depth >= 8 || *count > 64 {
            return Err(SysError::Failed("descendant bound exceeded"));
        }
        let child = format!("{path}/{child}");
        if io.call(Operation::Filter, &["-a", &child, "-sr"], &[])? != Text::Present(String::new())
        {
            return Err(SysError::Failed("foreign content in owned anchor"));
        }
        empty_classes(io, &child, depth + 1, count, recursive)?;
    }
    Ok(())
}
/// Reviewed loads may succeed. On other builds, only canonical Lockdown at an
/// owned native/qualification path is attempted, and its result remains Unknown.
///
/// # Errors
/// Unsupported build, invalid source or incomplete load.
pub fn load(io: &mut impl Commands, path: &AnchorPath, text: &str) -> Result<(), SysError> {
    if !reviewed(&io.build()?) {
        if text != scupper_core::mac::policy::render_lockdown().as_str()
            || !matches!(path.as_str(), "com.apple/scupper" | "scupper-qual/scupper")
        {
            return Err(UNSUPPORTED_BUILD);
        }
        let _attempt = io.emergency_load(&load_args(path), text.as_bytes());
        return Err(SysError::Unknown);
    }
    source(text)?;
    io.call(Operation::Load, &load_args(path), text.as_bytes())?;
    Ok(())
}
/// Remove active configuration; an empty listed namespace may persist.
///
/// # Errors
/// Unsupported build (before any command), failed flush or unconfirmed absence.
/// Descendant paths are never flushed; nonempty descendants make removal fail.
pub fn remove(io: &mut impl Commands, path: &AnchorPath) -> Result<(), SysError> {
    require_review(io)?;
    if read(io, path).is_ok_and(|text| text.is_none()) {
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
        return Err(SysError::Failed("anchor configuration persists"));
    }
    Ok(())
}
/// Fixed optimizer mode preserves rule order and prevents generated tables.
pub(crate) fn load_args(path: &AnchorPath) -> [&str; 6] {
    ["-o", "none", "-a", path.as_str(), "-f", "-"]
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
