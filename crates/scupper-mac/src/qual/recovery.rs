//! Completion evidence for append-only fixture journals, never production state.
use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::{Evidence, journal::Entry, model::MAX_FINAL_RESTORE_SECONDS};

pub(super) fn final_restore_seconds(remaining: usize) -> u64 {
    10_u64
        .saturating_add(
            u64::try_from(remaining)
                .unwrap_or(u64::MAX)
                .saturating_mul(2),
        )
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
            .filter(|(index, entry)| entry.kind != "inventory" && !self.entries.contains(index))
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
        assert_eq!(final_restore_seconds(0), 10);
        assert_eq!(final_restore_seconds(64), 138);
        assert_eq!(final_restore_seconds(115), MAX_FINAL_RESTORE_SECONDS);
        assert_eq!(final_restore_seconds(usize::MAX), MAX_FINAL_RESTORE_SECONDS);
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
