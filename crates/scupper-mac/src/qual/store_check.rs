//! Portable Q-STORE phase accounting. Evidence is supplied by the host-side caller.
use serde_json::{Value, json};
use std::{
    error::Error,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

#[derive(Debug, thiserror::Error)]
#[error("phase {phase}: {source}")]
pub(super) struct PhaseError {
    phase: String,
    #[source]
    source: Box<dyn Error>,
}

/// Follow phase wrappers without losing the environment/contract distinction.
pub(super) fn caused_by<E: Error + 'static>(mut error: &(dyn Error + 'static)) -> bool {
    loop {
        if error.is::<E>() {
            return true;
        }
        let Some(source) = error.source() else {
            return false;
        };
        error = source;
    }
}

#[derive(Default)]
pub(super) struct Phases {
    pub(super) records: Vec<Value>,
}
impl Phases {
    /// Publish a start before doing work, then an end even when the work fails.
    /// The caller supplies an evidence writer outside both mounted images.
    pub(super) fn run<T>(
        &mut self,
        name: &str,
        publish: impl Fn(&Value) -> Result<()>,
        work: impl FnOnce(&mut Self) -> Result<T>,
    ) -> Result<T> {
        let wrap = |source| {
            Box::new(PhaseError {
                phase: name.into(),
                source,
            }) as Box<dyn Error>
        };
        let start_unix_seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| wrap(e.into()))?
            .as_secs_f64();
        let started = Instant::now();
        publish(&json!({"phase":name, "event":"start", "start_unix_seconds":start_unix_seconds}))
            .map_err(wrap)?;
        let result = work(self).map_err(wrap);
        let record = json!({"phase":name, "event":"end", "start_unix_seconds":start_unix_seconds,
            "end_unix_seconds":SystemTime::now().duration_since(UNIX_EPOCH).map_err(|e| wrap(e.into()))?.as_secs_f64(),
            "elapsed_seconds":started.elapsed().as_secs_f64(), "outcome":if result.is_ok() {"ok"} else {"error"},
            "error":result.as_ref().err().map(ToString::to_string)});
        self.records.push(record.clone());
        // Keep the original failure if publishing diagnostics also fails.
        let published = publish(&record).map_err(wrap);
        if let Err(error) = &published
            && let Some(record) = self.records.last_mut()
        {
            record["outcome"] = json!("error");
            record["evidence_error"] = json!(error.to_string());
        }
        match result {
            Err(error) => Err(error),
            Ok(value) => {
                published?;
                Ok(value)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[derive(Debug, thiserror::Error)]
    #[error("budget expired")]
    struct BudgetExpired;

    #[test]
    fn nested_phase_failure_preserves_cause_and_both_timings() {
        let events = std::cell::RefCell::new(Vec::new());
        let publish = |value: &Value| {
            events.borrow_mut().push(value.clone());
            Ok(())
        };
        let mut phases = Phases::default();
        let result: Result<()> = phases.run("full", publish, |phases| {
            phases.run("full/reset", publish, |_| Err(Box::new(BudgetExpired)))
        });
        let error = result.err().unwrap_or_else(|| unreachable!());
        assert!(caused_by::<BudgetExpired>(&*error));
        assert_eq!(
            error.to_string(),
            "phase full: phase full/reset: budget expired"
        );
        assert_eq!(events.borrow().len(), 4);
        assert_eq!(phases.records.len(), 2);
        for record in phases.records {
            assert_eq!(record["outcome"], "error");
            assert!(record["elapsed_seconds"].as_f64().is_some_and(|s| s >= 0.0));
            assert!(record["start_unix_seconds"].is_number());
            assert!(record["end_unix_seconds"].is_number());
        }
    }

    #[test]
    fn failed_end_publication_names_its_phase() {
        let mut phases = Phases::default();
        let result = phases.run(
            "evidence",
            |value| {
                if value["event"] == "end" {
                    Err("disk full".into())
                } else {
                    Ok(())
                }
            },
            |_| Ok(()),
        );
        assert_eq!(
            result.err().map(|e| e.to_string()).as_deref(),
            Some("phase evidence: disk full")
        );
        assert_eq!(phases.records.len(), 1);
        assert_eq!(phases.records[0]["outcome"], "error");
    }
}
