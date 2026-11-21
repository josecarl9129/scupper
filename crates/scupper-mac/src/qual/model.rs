use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

pub(super) const MAX_FINAL_RESTORE_SECONDS: u64 = 240;

/// A case result is evidence, not an automatic qualification promotion.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// An adapter or harness contract failed; the cell must fail.
    ContractViolation,
    /// The experiment confirmed its stated assumption.
    AssumptionHolds,
    /// The experiment refuted an assumption; retained for owner review.
    AssumptionRefuted,
    /// Missing or unsuitable environment; never qualifies a build.
    Inconclusive,
    /// Raw capability measurement; never supports qualification.
    Measurement,
}

/// Bounded, redacted raw command evidence.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Evidence {
    /// Executable followed by its exact arguments.
    pub command: Vec<String>,
    /// Fixed standard input, if supplied.
    pub stdin: Option<String>,
    /// Spawned child pid, absent when no child was started.
    pub pid: Option<u32>,
    /// Exit status, absent on signal or spawn failure.
    pub exit_code: Option<i32>,
    /// Wall-clock start in Unix milliseconds.
    pub started_unix_ms: u128,
    /// Elapsed monotonic milliseconds.
    pub elapsed_ms: u128,
    /// Deadline expired.
    pub timed_out: bool,
    /// Output exceeded the cap or a reader failed to complete.
    pub truncated: bool,
    /// Standard output, redacted before persistence.
    pub stdout: String,
    /// Standard error, redacted before persistence.
    pub stderr: String,
}

impl Evidence {
    #[cfg(any(target_os = "macos", test))]
    pub(super) fn complete(&self) -> bool {
        self.exit_code == Some(0) && !self.timed_out && !self.truncated
    }
}

/// Portable case verdict, written even when environment prerequisites fail.
#[derive(Debug, Deserialize, Serialize)]
pub struct CaseResult {
    /// Manifest case id.
    pub case: String,
    /// SHA256 of the root-owned harness executable producing this verdict.
    pub binary_sha256: String,
    /// Experiment outcome.
    pub verdict: Verdict,
    /// Number of completed iterations.
    pub iterations: u32,
    /// Human-readable reason and limitations.
    pub detail: String,
    /// Redacted command observations.
    pub evidence: Vec<Evidence>,
}

/// A manifest entry; budgets include case-specific capture time.
#[derive(Debug, Deserialize, Serialize)]
pub struct Case {
    /// Stable case identifier.
    pub id: String,
    /// Matrix group.
    pub group: String,
    /// Required iteration count.
    pub minimum_iterations: u32,
    /// Internal case deadline in minutes.
    pub budget_minutes: u32,
    /// Assumptions this case can eventually support.
    pub supported_assumptions: Vec<String>,
}

/// Qualification completeness and time budget skeleton.
#[derive(Debug, Deserialize, Serialize)]
pub struct Manifest {
    /// Schema version.
    pub schema: u32,
    /// Entire workflow cell budget.
    pub cell_budget_minutes: u32,
    /// Reserved checkout, build and restore budget.
    pub overhead_minutes: u32,
    /// Cases currently implemented.
    pub cases: Vec<Case>,
}

impl Manifest {
    /// Parse the checked-in qualification manifest.
    ///
    /// # Errors
    /// Returns a JSON error if the manifest is malformed.
    pub fn bundled() -> Result<Self, serde_json::Error> {
        serde_json::from_str(include_str!("../../qualification/manifest.json"))
    }

    /// Fit case slack and the bounded final restore within the harness budget.
    #[must_use]
    pub fn budgets_fit(&self) -> bool {
        let Some(available) = self.cell_budget_minutes.checked_sub(self.overhead_minutes) else {
            return false;
        };
        let mut groups = BTreeMap::<&str, u64>::new();
        for case in &self.cases {
            *groups.entry(&case.group).or_default() += u64::from(case.budget_minutes);
        }
        !groups.is_empty()
            && groups.values().all(|minutes| {
                minutes * 110 <= u64::from(available) * 100
                    && minutes * 60 + MAX_FINAL_RESTORE_SECONDS <= u64::from(available) * 60
            })
    }
}

/// Remove whole lines containing UAPI key assignments, including embedded
/// assignments in diagnostic prefixes. Apply before writing *any* evidence.
#[must_use]
pub fn redact(text: &str) -> String {
    text.split_inclusive('\n')
        .map(|line| {
            let lower = line.to_ascii_lowercase();
            if lower.contains("private_key=") || lower.contains("preshared_key=") {
                if line.ends_with('\n') {
                    "[redacted key material]\n"
                } else {
                    "[redacted key material]"
                }
            } else {
                line
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_has_room_for_restore_and_ten_percent_slack()
    -> Result<(), Box<dyn std::error::Error>> {
        let manifest = Manifest::bundled()?;
        assert!(manifest.budgets_fit());
        assert_eq!(manifest.cell_budget_minutes - manifest.overhead_minutes, 18);
        assert_eq!(MAX_FINAL_RESTORE_SECONDS, 240);
        assert_eq!(manifest.cases.len(), 14);
        assert!(
            manifest
                .cases
                .iter()
                .all(|case| case.minimum_iterations > 0)
        );
        // Fifteen case minutes fit the old 10% rule, but leave only three
        // minutes for final recovery instead of the required maximum of four.
        let mut over = Manifest::bundled()?;
        over.cases
            .iter_mut()
            .find(|case| case.group == "probe")
            .ok_or("missing probe case")?
            .budget_minutes += 1;
        assert!(!over.budgets_fit());
        let mut over = manifest;
        over.cases[0].budget_minutes = 18;
        assert!(!over.budgets_fit());
        Ok(())
    }

    #[test]
    fn redaction_removes_entire_key_lines_in_all_streams() -> Result<(), Box<dyn std::error::Error>>
    {
        let input = "ok\nprivate_key=fixture-private\r\ntrace: preshared_key=fixture-shared\nPUBLIC_KEY=public\nPRIVATE_KEY=fixture-final";
        let output = redact(input);
        assert!(!output.contains("fixture-"));
        assert!(!output.to_ascii_lowercase().contains("private_key="));
        assert!(!output.contains("preshared_key="));
        assert!(output.contains("PUBLIC_KEY=public"));
        assert_eq!(redact(&output), output);
        let serialized = serde_json::to_string(&CaseResult {
            case: "Q-CAPTURE".into(),
            binary_sha256: "0".repeat(64),
            verdict: Verdict::Inconclusive,
            iterations: 0,
            detail: output,
            evidence: Vec::new(),
        })?;
        assert!(!serialized.contains("fixture-"));
        Ok(())
    }

    #[test]
    fn verdict_spellings_are_stable() -> Result<(), serde_json::Error> {
        for (verdict, expected) in [
            (Verdict::ContractViolation, "contract_violation"),
            (Verdict::AssumptionHolds, "assumption_holds"),
            (Verdict::AssumptionRefuted, "assumption_refuted"),
            (Verdict::Inconclusive, "inconclusive"),
            (Verdict::Measurement, "measurement"),
        ] {
            assert_eq!(serde_json::to_string(&verdict)?, format!("\"{expected}\""));
        }
        Ok(())
    }
}
