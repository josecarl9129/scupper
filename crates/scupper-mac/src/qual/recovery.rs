//! Completion evidence for append-only fixture journals, never production state.
use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::{Evidence, journal::Entry, model::MAX_FINAL_RESTORE_SECONDS};

pub(super) fn final_restore_seconds(remaining: usize, anchors: usize) -> u64 {
    10_u64
        .saturating_add(
            u64::try_from(remaining)
                .unwrap_or(u64::MAX)
                .saturating_mul(2),
        )
        .saturating_add(u64::try_from(anchors).unwrap_or(u64::MAX).saturating_mul(3))
        .min(MAX_FINAL_RESTORE_SECONDS)
}

// The snapshot is unconditional, including when recovery fails. This boundary
// also makes the zero-work final restore observable in portable unit tests.
pub(super) fn recover_then_snapshot<R, S>(
    has_pending: bool,
    recover: impl FnOnce() -> R,
    snapshot: impl FnOnce() -> S,
) -> (Option<R>, S) {
    let recovered = has_pending.then(recover);
    (recovered, snapshot())
}

/// Try every independent recovery step and retain failures in execution order.
pub(super) fn run_steps<T, E: std::fmt::Display>(
    steps: impl IntoIterator<Item = T>,
    mut run: impl FnMut(T) -> Result<(), E>,
) -> Vec<String> {
    let mut failures = Vec::new();
    for step in steps {
        if let Err(error) = run(step) {
            failures.push(error.to_string());
        }
    }
    failures
}

// A diagnostic snapshot after failed cleanup cannot retroactively gain a fence
// merely because the remaining writer exits after that snapshot started.
pub(super) fn snapshot_can_complete<T, E>(cleanup: Option<&Result<T, E>>) -> bool {
    cleanup.is_none_or(Result::is_ok)
}
#[cfg(test)]
mod snapshot_fence_tests {
    #[test]
    fn late_writer_exit_does_not_authorize_a_prefence_snapshot() {
        let failed_cleanup: Option<Result<(), &str>> = Some(Err("group still alive"));
        let fence_at_read_start = super::snapshot_can_complete(failed_cleanup.as_ref());
        let writer_exited_after_read = true;
        assert!(!fence_at_read_start && writer_exited_after_read);
        assert!(super::snapshot_can_complete(Some(&Ok::<(), &str>(()))));
        assert!(super::snapshot_can_complete::<(), &str>(None));
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(super) struct Writer {
    pub pid: u32,
    pub start: String,
}

#[derive(Default, Serialize, Deserialize)]
pub(super) struct Completed {
    // Indices distinguish a new intent for the same key/path from an old one.
    pub entries: BTreeSet<usize>,
    pub writers: Vec<Writer>,
}

impl Completed {
    pub fn pending(&self, entries: Vec<Entry>) -> Vec<(usize, Entry)> {
        entries
            .into_iter()
            .enumerate()
            // Read-only census subprocesses journal their identity too; they
            // cannot own resources and need no recovery operation.
            .filter(|(index, entry)| {
                !matches!(entry.kind.as_str(), "inventory" | "detach-attempt")
                    && !self.entries.contains(index)
            })
            .collect()
    }

    pub fn writer_stopped(&mut self, writer: Writer, entries: &[Entry]) {
        self.entries
            .extend(entries.iter().enumerate().filter_map(|(index, e)| {
                (matches!(e.kind.as_str(), "probe" | "child")
                    && e.pid == writer.pid
                    && e.start == writer.start)
                    .then_some(index)
            }));
        if !self.writers.contains(&writer) {
            self.writers.push(writer);
        }
    }
}

// A failed identity read is not proof of absence. A complete, strictly parsed
// process census is; a truncated, failed or malformed census is never enough.
pub(super) fn process_absent(pid: u32, listing: &Evidence) -> bool {
    if !listing.complete() {
        return false;
    }
    let pids = listing
        .stdout
        .split_whitespace()
        .map(str::parse::<u32>)
        .collect::<Result<Vec<_>, _>>();
    pids.is_ok_and(|pids| !pids.is_empty() && !pids.contains(&0) && !pids.contains(&pid))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completed_entries_are_skipped_but_new_identical_intents_are_pending()
    -> Result<(), serde_json::Error> {
        let entries = super::super::journal::committed(
            "{\"kind\":\"token\",\"token\":7}\n{\"kind\":\"token\",\"token\":7}\n",
        )?;
        let mut completed = Completed::default();
        completed.entries.insert(0);
        let completed: Completed = serde_json::from_str(&serde_json::to_string(&completed)?)?;
        let pending = completed.pending(entries);
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].0, 1);
        Ok(())
    }

    #[test]
    fn stopped_writer_does_not_complete_its_token_acquisition() -> Result<(), serde_json::Error> {
        let entries = super::super::journal::committed(
            "{\"kind\":\"probe\",\"pid\":42,\"start\":\"1:2\"}\n{\"kind\":\"pf-acquire\",\"pid\":42,\"start\":\"1:2\"}\n",
        )?;
        let mut completed = Completed::default();
        completed.writer_stopped(
            Writer {
                pid: 42,
                start: "1:2".into(),
            },
            &entries,
        );
        assert_eq!(completed.entries, BTreeSet::from([0]));
        assert_eq!(completed.pending(entries)[0].1.kind, "pf-acquire");
        Ok(())
    }

    #[test]
    fn final_budget_is_sized_and_bounded() {
        assert_eq!(final_restore_seconds(0, 4), 22);
        assert_eq!(final_restore_seconds(64, 0), 138);
        assert_eq!(final_restore_seconds(115, 0), MAX_FINAL_RESTORE_SECONDS);
        assert_eq!(
            final_restore_seconds(usize::MAX, usize::MAX),
            MAX_FINAL_RESTORE_SECONDS
        );
    }

    #[test]
    fn final_restore_with_zero_incomplete_entries_only_calls_snapshot()
    -> Result<(), serde_json::Error> {
        let entries = super::super::journal::committed(concat!(
            "{\"kind\":\"token\",\"token\":7}\n",
            "{\"kind\":\"child\",\"pid\":42,\"start\":\"1:2\"}\n",
            "{\"kind\":\"key\",\"path\":\"State:/Network/Service/scupper-qual-test/DNS\"}\n",
            "{\"kind\":\"image\",\"path\":\"fixture.dmg\"}\n",
            "{\"kind\":\"mount\",\"path\":\"fixture-mount\"}\n",
            "{\"kind\":\"inventory\",\"pid\":43}\n",
        ))?;
        let completed = Completed {
            entries: BTreeSet::from([0, 1, 2, 3, 4]),
            writers: Vec::new(),
        };
        let calls = std::cell::RefCell::new(Vec::new());
        let (recovery, snapshot) = recover_then_snapshot(
            !completed.pending(entries).is_empty(),
            || calls.borrow_mut().push("cleanup tool"),
            || {
                calls.borrow_mut().push("snapshot");
                "post-state"
            },
        );
        assert!(recovery.is_none());
        assert_eq!(snapshot, "post-state");
        assert_eq!(*calls.borrow(), ["snapshot"]);
        Ok(())
    }

    #[test]
    fn failed_step_does_not_skip_remaining_restore_steps() {
        let mut called = Vec::new();
        let failures = run_steps(["jobs", "anchors", "tokens", "pf state"], |step| {
            called.push(step);
            match step {
                "jobs" | "tokens" => Err(step),
                _ => Ok(()),
            }
        });
        assert_eq!(called, ["jobs", "anchors", "tokens", "pf state"]);
        assert_eq!(failures, ["jobs", "tokens"]);
    }

    #[test]
    fn failed_recovery_still_takes_post_state_snapshot() {
        let calls = std::cell::RefCell::new(Vec::new());
        let (recovery, ()) = recover_then_snapshot(
            true,
            || {
                calls.borrow_mut().push("cleanup");
                Err::<(), _>("unavailable")
            },
            || calls.borrow_mut().push("snapshot"),
        );
        assert_eq!(recovery, Some(Err("unavailable")));
        assert_eq!(*calls.borrow(), ["cleanup", "snapshot"]);
    }

    #[test]
    fn process_absence_requires_a_complete_census() -> Result<(), serde_json::Error> {
        let mut listing: Evidence = serde_json::from_value(serde_json::json!({
            "command":[], "stdin":null,"pid":null,"exit_code":0,"started_unix_ms":0,
            "elapsed_ms":0,"timed_out":false,"truncated":false,
            "stdout":" 1\n 42\n", "stderr":""
        }))?;
        assert!(process_absent(99, &listing));
        assert!(!process_absent(42, &listing));
        listing.truncated = true;
        assert!(!process_absent(99, &listing));
        listing.truncated = false;
        for text in ["", "PID\n1\n", "0\n", "1\nbroken\n"] {
            listing.stdout = text.into();
            assert!(!process_absent(99, &listing));
        }
        listing.stdout = "1\n".into();
        listing.exit_code = Some(1);
        assert!(!process_absent(99, &listing));
        listing.exit_code = Some(0);
        listing.timed_out = true;
        assert!(!process_absent(99, &listing));
        Ok(())
    }
}

/// Shared journal undo scheduler: dependent mutations need fresh quiescence;
/// failures never skip independent steps or complete withheld journal entries.
pub(super) fn undo<E: std::fmt::Display>(
    mut quiescent: impl FnMut() -> Result<bool, E>,
    mut run: impl FnMut(&str) -> Result<(), E>,
) -> Vec<String> {
    let mut failures = Vec::new();
    for step in [
        "tools",
        "tokens",
        "anchors",
        "pf state",
        "keys",
        "resolver",
        "images",
        "store tree",
        "loopback",
        "sockets",
        "child staging",
        "feth",
        "completion",
    ] {
        let result = (|| -> Result<(), String> {
            if matches!(step, "tokens" | "anchors" | "pf state" | "completion")
                && !quiescent().map_err(|e| format!("{step}: quiescence unknown; withheld: {e}"))?
            {
                return Err(format!("{step}: writers/services not quiescent; withheld"));
            }
            run(step).map_err(|e| e.to_string())
        })();
        if let Err(error) = result {
            failures.push(error);
        }
    }
    failures
}

#[cfg(test)]
#[allow(clippy::expect_used)] // Literal fake journals are part of each test.
mod undo_tests {
    use super::*;

    #[test]
    fn fake_journal_undo_withholds_mutations_after_failed_job_stop() {
        let entries = super::super::journal::committed(concat!(
            "{\"kind\":\"r4-job\",\"path\":\"system/net.scupper.qual.r4-exit\"}\n",
            "{\"kind\":\"anchor\",\"path\":\"scupper-qual/scupper\"}\n",
            "{\"kind\":\"token\",\"token\":7}\n",
            "{\"kind\":\"r6-pf\"}\n",
        ))
        .expect("fake journal");
        // The fake stop failed, old writer identities/groups are already gone,
        // but the KeepAlive service remains: precisely the respawn gap.
        let stop_jobs = || Err::<(), _>("bootout failed");
        let mut report = vec![stop_jobs().expect_err("fake job stop must fail").to_owned()];
        let service: super::super::Evidence = serde_json::from_value(serde_json::json!({
            "command":["launchctl","print","system/net.scupper.qual.r4-exit"],
            "stdin":null,"pid":1,"exit_code":0,"started_unix_ms":0,"elapsed_ms":0,
            "timed_out":false,"truncated":false,"stdout":"state = running\n","stderr":""
        }))
        .expect("fake service evidence");
        let mut commands = Vec::new();
        let mut diagnostics = Vec::new();
        let failures = undo(
            || Ok::<_, &str>(super::super::jobs::absent(&service)),
            |step| {
                match step {
                    "anchors" => commands.push("pfctl -F rules"),
                    "tokens" => commands.push("pfctl -X 7"),
                    "pf state" => commands.push("pfctl -d"),
                    _ => diagnostics.push(step.to_owned()),
                }
                Ok::<_, &str>(())
            },
        );
        assert!(
            commands.is_empty(),
            "assertion failed: failed job stop must withhold all dependent mutations"
        );
        for step in ["anchors", "tokens", "pf state", "completion"] {
            assert!(
                failures
                    .iter()
                    .any(|s| s.starts_with(step) && s.contains("withheld"))
            );
        }
        report.extend(failures);
        assert!(report.iter().any(|s| s == "bootout failed"));
        assert!(diagnostics.contains(&"images".into()));
        assert_eq!(entries.len(), 4);
        let mut absent = service;
        absent.exit_code = Some(113);
        assert!(super::super::jobs::absent(&absent));
        absent.timed_out = true;
        assert!(!super::super::jobs::absent(&absent));
        absent.timed_out = false;
        absent.truncated = true;
        assert!(!super::super::jobs::absent(&absent));
    }

    #[test]
    fn fake_journal_undo_tools_failure_still_runs_anchors() {
        let entries = super::super::journal::committed(
            "{\"kind\":\"anchor\",\"path\":\"scupper-qual/scupper\"}\n",
        )
        .expect("fake journal");
        let mut visited = Vec::new();
        let failures = undo(
            || Ok::<_, &str>(true),
            |step| {
                visited.push(step.to_owned());
                if step == "tools" {
                    Err("tools failed")
                } else {
                    Ok(())
                }
            },
        );
        assert_eq!(entries[0].kind, "anchor");
        assert!(visited.contains(&"anchors".into()));
        assert!(visited.contains(&"completion".into()));
        assert_eq!(failures, ["tools failed"]);
    }
}

/// Keep independent allowances when another anchor read is incomplete.
#[derive(Default, serde::Serialize)]
pub(super) struct AnchorReads {
    pub empty_names: Vec<String>,
    pub incomplete_names: Vec<String>,
    pub violations: Vec<String>,
    pub inconclusive: Vec<String>,
}
/// Preserve the adapter error class alongside the failing descendant command.
pub(super) struct AnchorReadError {
    pub error: crate::platform::SysError,
    pub detail: String,
}
impl From<crate::platform::SysError> for AnchorReadError {
    fn from(error: crate::platform::SysError) -> Self {
        Self {
            detail: format!("{error:?}"),
            error,
        }
    }
}
impl std::fmt::Display for AnchorReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.detail)
    }
}
pub(super) fn read_anchors(
    paths: impl IntoIterator<Item = String>,
    mut read: impl FnMut(&str) -> Result<Option<Vec<String>>, AnchorReadError>,
) -> AnchorReads {
    let mut result = AnchorReads::default();
    for path in paths.into_iter().collect::<BTreeSet<_>>() {
        match read(&path) {
            Ok(None) => result
                .violations
                .push(format!("journaled anchor has configuration: {path}")),
            Ok(Some(names)) => result.empty_names.extend(names),
            Err(error) if matches!(error.error, crate::platform::SysError::Failed(_)) => {
                if error.error
                    == crate::platform::SysError::Failed("foreign content in owned anchor")
                {
                    result.violations.push(format!(
                        "journaled anchor has configuration: {path}: {error}"
                    ));
                } else {
                    result
                        .violations
                        .push(format!("journaled anchor read failed: {path}: {error}"));
                }
            }
            Err(error) => {
                result
                    .inconclusive
                    .push(format!("journaled anchor read incomplete: {path}: {error}"));
                result.incomplete_names.push(path);
            }
        }
    }
    result
}
#[cfg(test)]
mod anchor_read_tests {
    #[test]
    fn foreign_content_is_configuration_violation_with_descendant_path() {
        use crate::platform::SysError;
        let result = super::read_anchors(["scupper-qual/children".into()], |_| {
            Err(super::AnchorReadError {
                error: SysError::Failed("foreign content in owned anchor"),
                detail: "pfctl -a scupper-qual/children/X/_1 -sr: foreign content in owned anchor"
                    .into(),
            })
        });
        assert_eq!(result.inconclusive, [] as [String; 0]);
        assert_eq!(result.incomplete_names, [] as [String; 0]);
        assert_eq!(result.empty_names, [] as [String; 0]);
        assert_eq!(
            result.violations,
            [
                "journaled anchor has configuration: scupper-qual/children: pfctl -a scupper-qual/children/X/_1 -sr: foreign content in owned anchor"
            ]
        );
        for error in [SysError::TimedOut, SysError::Unknown] {
            let result = super::read_anchors(["a/b".into()], |_| Err(error.clone().into()));
            assert_eq!(result.incomplete_names, ["a/b"]);
            assert_eq!(result.violations, [] as [String; 0]);
            assert_eq!(result.inconclusive.len(), 1);
        }
    }
    #[test]
    fn duplicate_failed_read_is_inconclusive_and_keeps_other_allowances() {
        let mut calls = Vec::new();
        let result = super::read_anchors(["a", "b", "a", "c"].map(str::to_owned), |path| {
            calls.push(path.to_owned());
            match path {
                "a" => Ok(Some(vec![path.to_owned()])),
                "b" => Err(super::AnchorReadError {
                    error: crate::platform::SysError::TimedOut,
                    detail: "-sd timed out".into(),
                }),
                _ => Ok(None),
            }
        });
        assert_eq!(calls, ["a", "b", "c"]);
        assert_eq!(result.empty_names, ["a"]);
        assert_eq!(result.incomplete_names, ["b"]);
        assert_eq!(
            result.inconclusive,
            ["journaled anchor read incomplete: b: -sd timed out"]
        );
        assert_eq!(result.violations, ["journaled anchor has configuration: c"]);
        assert!(
            !result
                .violations
                .iter()
                .any(|s| s.contains("b:") || s.contains("not empty"))
        );
        assert_eq!(super::final_restore_seconds(0, 0), 10);
        assert_eq!(super::final_restore_seconds(0, 9), 37);
    }
}
