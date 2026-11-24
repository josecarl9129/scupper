//! One source for launchd setup and journal restoration.
pub(super) const MODES: &[&str] = &[
    "tools",
    "pf",
    "pf-x",
    "pf-x-stale",
    "bootout",
    "kill9",
    "group",
    "process",
    "real",
    "rosetta",
    "exit",
    "contracts",
];

pub(super) fn service(mode: &str) -> Option<String> {
    MODES
        .contains(&mode)
        .then(|| format!("system/net.scupper.qual.r4-{mode}"))
}

pub(super) fn restorable(path: &str) -> bool {
    path.strip_prefix("system/net.scupper.qual.r4-")
        .and_then(service)
        .is_some_and(|expected| expected == path)
}

pub(super) fn absent(evidence: &super::Evidence) -> bool {
    evidence.exit_code == Some(113) && !evidence.timed_out && !evidence.truncated
}

#[cfg(test)]
mod tests {
    #[test]
    fn every_journaled_job_is_restorable_including_contracts() {
        for mode in super::MODES.iter().copied().chain(["contracts"]) {
            let path = super::service(mode);
            assert!(
                path.is_some(),
                "assertion failed: every launchd mode must have a restorable label: {mode}"
            );
            let path = path.expect("asserted known launchd mode");
            let entries = super::super::journal::committed(&format!(
                "{{\"kind\":\"r4-job\",\"path\":\"{path}\"}}\n"
            ))
            .expect("journal fixture");
            assert!(entries.iter().all(|e| super::restorable(&e.path)));
        }
        for unknown in [
            "system/net.scupper.qual.r4-foreign",
            "net.scupper.qual.r4-contracts",
            "system/net.scupper.qual.r4-contracts/child",
        ] {
            assert!(!super::restorable(unknown));
        }
    }
}
