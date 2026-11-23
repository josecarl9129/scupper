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
    /// Preserve exact pfctl bytes independently of the readable UTF-8 projection.
    #[cfg(any(target_os = "macos", test))]
    pub(crate) fn pf_text_capture(
        &self,
        build: &str,
        stdout: &[u8],
        stderr: &[u8],
    ) -> Result<serde_json::Value, serde_json::Error> {
        let mut capture = serde_json::to_value(self)?;
        capture["build"] = serde_json::json!(build);
        capture["stdout_bytes"] = serde_json::json!(stdout);
        capture["stderr_bytes"] = serde_json::json!(stderr);
        Ok(capture)
    }
    #[cfg(any(target_os = "macos", test))]
    pub(crate) fn complete(&self) -> bool {
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
    /// Case wall duration in milliseconds.
    #[serde(default)]
    pub elapsed_ms: u128,
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
    /// Separate CI budgets for groups that do not run in the ordinary cell.
    #[serde(default)]
    pub group_budgets: BTreeMap<String, GroupBudget>,
    /// Cases currently implemented.
    pub cases: Vec<Case>,
}

/// Dedicated CI group budget, including its own setup and recovery margin.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GroupBudget {
    /// Entire job timeout.
    pub cell_budget_minutes: u32,
    /// Setup and recovery reservation outside the experiments.
    pub overhead_minutes: u32,
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
            && groups.iter().all(|(group, minutes)| {
                let available = if let Some(budget) = self.group_budgets.get(*group) {
                    let Some(value) = budget
                        .cell_budget_minutes
                        .checked_sub(budget.overhead_minutes)
                    else {
                        return false;
                    };
                    value
                } else {
                    available
                };
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
    fn pf_text_capture_preserves_build_and_unexpected_bytes_before_verdict()
    -> Result<(), serde_json::Error> {
        for build in crate::decode::pftext::BUILDS {
            for flag in 0..4 {
                let evidence = Evidence {
                    command: vec!["/sbin/pfctl".into(), "-E".into()],
                    stdin: None,
                    pid: Some(123),
                    exit_code: if flag == 0 { None } else { Some(1) },
                    started_unix_ms: 0,
                    elapsed_ms: 0,
                    timed_out: flag == 1,
                    truncated: flag == 2,
                    stdout: "unexpected".into(),
                    stderr: "unexpected".into(),
                };
                let stdout = b"unexpected\xff\n";
                let stderr = [crate::decode::pftext::ALTQ_PREAMBLE, b"unknown\0\xfe"].concat();
                let serialized =
                    serde_json::to_vec(&evidence.pf_text_capture(build, stdout, &stderr)?)?;
                let saved: serde_json::Value = serde_json::from_slice(&serialized)?;
                assert_eq!(saved["build"], build);
                assert_eq!(saved["stdout_bytes"], serde_json::json!(stdout));
                assert_eq!(saved["stderr_bytes"], serde_json::json!(stderr));
                assert_eq!(saved["timed_out"], flag == 1);
                assert_eq!(saved["truncated"], flag == 2);
            }
        }
        Ok(())
    }
    #[test]
    fn manifest_has_room_for_restore_and_ten_percent_slack()
    -> Result<(), Box<dyn std::error::Error>> {
        let manifest = Manifest::bundled()?;
        assert!(manifest.budgets_fit());
        assert_eq!(manifest.cell_budget_minutes - manifest.overhead_minutes, 18);
        assert_eq!(MAX_FINAL_RESTORE_SECONDS, 240);
        assert_eq!(manifest.cases.len(), 25);
        let tools: Vec<_> = manifest
            .cases
            .iter()
            .filter(|case| case.group == "tool")
            .collect();
        assert_eq!(
            tools
                .iter()
                .map(|case| case.id.as_str())
                .collect::<Vec<_>>(),
            ["Q-TOOL", "Q-LAUNCHD", "Q-LOCK"]
        );
        assert!(tools.iter().map(|case| case.budget_minutes).sum::<u32>() * 110 <= 1000);
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
    fn store_cell_has_two_minute_setup_seven_minute_case_and_both_runners()
    -> Result<(), Box<dyn std::error::Error>> {
        let manifest = Manifest::bundled()?;
        let store: Vec<_> = manifest
            .cases
            .iter()
            .filter(|c| c.group == "store")
            .collect();
        assert_eq!(store.len(), 2);
        assert_eq!(
            (&store[0].id[..], store[0].budget_minutes),
            ("Q-STORE-SETUP", 2)
        );
        assert_eq!(
            (
                &store[1].id[..],
                store[1].budget_minutes,
                store[1].minimum_iterations
            ),
            ("Q-STORE", 7, 500)
        );
        assert!(manifest.budgets_fit());
        let workflow = include_str!("../../../../.github/workflows/ci.yml");
        assert!(workflow.contains("runner: [macos-15, macos-26]"));
        assert!(workflow.contains("tool-mutants, store, pf, pf-x, pf-x-stale, probe"));
        assert!(workflow.contains("matrix.group == 'store' && 10"));
        // Every group whose worker starts via launch_job needs the bootstrap helper.
        let helper = workflow
            .split("- name: Compile R4 harmless tool helper")
            .nth(1)
            .and_then(|rest| {
                rest.lines()
                    .find(|line| line.trim_start().starts_with("if:"))
            })
            .ok_or("helper compile step")?;
        let groups: Vec<_> = manifest
            .cases
            .iter()
            .map(|case| case.group.as_str())
            .filter(|group| {
                !matches!(*group, "smoke" | "base" | "store") && !group.starts_with("probe")
            })
            .collect();
        assert!(!groups.is_empty(), "no helper groups derived from manifest");
        for required in ["pf", "pf-x", "pf-x-stale"] {
            assert!(
                groups.contains(&required),
                "missing helper group {required}"
            );
        }
        for group in groups {
            assert!(
                helper.contains(&format!("matrix.group == '{group}'")),
                "{group}"
            );
        }
        Ok(())
    }

    #[test]
    fn reference_cells_fit_their_case_and_restore_budgets() -> Result<(), Box<dyn std::error::Error>>
    {
        let manifest = Manifest::bundled()?;
        for (id, group, iterations, minutes) in [
            ("Q-ENABLE", "pf", 50, 4),
            ("Q-EEXIST", "pf", 50, 3),
            ("Q-REFS", "pf", 2000, 15),
            ("Q-X", "pf-x", 3, 2),
            ("Q-X-STALE", "pf-x-stale", 1, 2),
        ] {
            let case = manifest
                .cases
                .iter()
                .find(|c| c.id == id)
                .ok_or("missing reference case")?;
            assert_eq!(
                (
                    &case.group[..],
                    case.minimum_iterations,
                    case.budget_minutes
                ),
                (group, iterations, minutes)
            );
        }
        assert!(manifest.budgets_fit());
        assert_eq!(
            manifest
                .cases
                .iter()
                .find(|c| c.id == "Q-X")
                .ok_or("missing Q-X")?
                .supported_assumptions,
            ["disable_voids_references"]
        );
        assert_eq!(
            manifest
                .cases
                .iter()
                .find(|c| c.id == "Q-X-STALE")
                .ok_or("missing Q-X-STALE")?
                .supported_assumptions,
            Vec::<String>::new()
        );
        assert!(!manifest.cases.iter().any(|c| c.id == "Q-FLUSH"));
        assert_eq!(
            manifest
                .cases
                .iter()
                .filter(|c| c.group == "pf")
                .map(|c| c.budget_minutes)
                .sum::<u32>(),
            22
        );
        const {
            assert!(super::super::guard::MAX_ARM_SECONDS >= 25 * 60);
        }
        let workflow = include_str!("../../../../.github/workflows/ci.yml");
        assert!(workflow.contains("then after=1500; fi"));
        assert!(workflow.contains("matrix.group == 'pf' && 25"));
        let launch = include_str!("tool.rs");
        assert!(launch.contains("\"pf\" => 24 * 60"));
        Ok(())
    }

    #[test]
    fn native_mutants_have_an_isolated_ci_budget() -> Result<(), Box<dyn std::error::Error>> {
        let manifest = Manifest::bundled()?;
        let budget = manifest
            .group_budgets
            .get("tool-mutants")
            .ok_or("mutation budget")?;
        let experiment = manifest
            .cases
            .iter()
            .find(|c| c.group == "tool-mutants")
            .ok_or("mutation case")?;
        assert_eq!(experiment.minimum_iterations, 5);
        let workflow = include_str!("../../../../.github/workflows/ci.yml");
        let native = workflow
            .split("  macos-native:")
            .nth(1)
            .ok_or("native CI job")?;
        assert!(native.contains("runner: [macos-15, macos-26]"));
        assert!(native.contains(
            "group: [smoke, base, tool, tool-mutants, store, pf, pf-x, pf-x-stale, probe, probe-hijack]"
        ));
        assert!(native.contains(&format!(
            "matrix.group == 'tool-mutants' && {} || matrix.group == 'pf' && 50 || 30",
            budget.cell_budget_minutes
        )));
        assert!(native.contains("continue-on-error: ${{ matrix.group == 'probe-hijack' }}"));
        let step = native
            .split("- name: Kill native R4")
            .nth(1)
            .ok_or("mutant step")?
            .split("- name: Preflight")
            .next()
            .ok_or("step boundary")?;
        assert!(step.contains("if: matrix.group == 'tool-mutants'"));
        assert!(step.contains(&format!("timeout-minutes: {}", experiment.budget_minutes)));
        let mut insufficient = Manifest::bundled()?;
        insufficient
            .group_budgets
            .get_mut("tool-mutants")
            .ok_or("mutation budget")?
            .cell_budget_minutes = budget.overhead_minutes + experiment.budget_minutes;
        assert!(
            !insufficient.budgets_fit(),
            "mutants need recovery margin too"
        );
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
            elapsed_ms: 0,
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
