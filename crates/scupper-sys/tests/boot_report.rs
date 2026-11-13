//! Upgrade handoffs use the exact report emitted by the pre-module boot writer.
#![allow(clippy::unwrap_used)]
use scupper_sys::boot::{BootReport, BootStep, StepResult};

const LEGACY: &str = include_str!("fixtures/boot-pre-modules.json");

#[test]
fn previous_release_boot_report_succeeds_without_changing_its_shape() {
    let report: BootReport = serde_json::from_str(LEGACY).unwrap();
    assert!(report.succeeded());
    assert_eq!(report.steps.len(), 8);
    assert_eq!(serde_json::to_string(&report).unwrap(), LEGACY);
}

#[test]
fn handoffs_require_complete_ordered_success_with_only_modules_optional() {
    let legacy: BootReport = serde_json::from_str(LEGACY).unwrap();
    let mut current = legacy.clone();
    current.steps.insert(
        1,
        StepResult {
            step: BootStep::Modules,
            error: None,
            adopted: false,
        },
    );
    assert!(current.succeeded());
    for report in [legacy, current] {
        for index in 0..report.steps.len() {
            let mut failed = report.clone();
            failed.steps[index].error = Some("failed checkpoint".into());
            assert!(!failed.succeeded(), "{failed:?}");

            let mut missing = report.clone();
            let removed = missing.steps.remove(index);
            assert_eq!(missing.succeeded(), removed.step == BootStep::Modules);

            let mut duplicate = report.clone();
            duplicate
                .steps
                .insert(index, duplicate.steps[index].clone());
            assert!(!duplicate.succeeded(), "{duplicate:?}");

            if index + 1 < report.steps.len() {
                let mut reordered = report.clone();
                reordered.steps.swap(index, index + 1);
                assert!(!reordered.succeeded(), "{reordered:?}");
            }
        }
    }
    assert!(!BootReport::default().succeeded());
}
