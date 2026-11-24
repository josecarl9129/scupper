use crate::platform::SysError;

pub(super) fn anchor_error_is_inconclusive(error: &SysError) -> bool {
    *error == crate::decode::pfanchor::UNREVIEWED
        || matches!(error, SysError::Failed("anchor readback unsupported"))
}

// Portable independent golden gate for the native contract harness.
use crate::platform::tests::{Readback, pretunnel_fixture};
use scupper_core::mac::policy::{self, AnchorText};

// Command bookkeeping changes on every read. Compare only complete command
// results when measuring a sentinel, never PID/start/elapsed metadata.
pub(super) fn sentinel_changed(before: &super::Evidence, after: &super::Evidence) -> Option<bool> {
    (before.complete() && after.complete() && before.command == after.command)
        .then(|| before.stdout != after.stdout || before.stderr != after.stderr)
}

// Inspect every write request, including one that failed after partially writing.
// Snapshots do not persist a Protected verdict: hold and absence of a child
// generation are durable join evidence; counted reference ownership is allowed.
pub(super) fn join_snapshot_writes_held(trace: &[String]) -> bool {
    let mut writes = 0;
    for line in trace
        .iter()
        .filter_map(|s| s.strip_prefix("snapshot_write:"))
    {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
            return false;
        };
        let snapshot = &value["snapshot"];
        if snapshot["machine"]["hold"] != true
            || !snapshot["machine"]
                .get("previous_generation")
                .is_some_and(serde_json::Value::is_null)
        {
            return false;
        }
        writes += 1;
    }
    writes != 0
}

pub(super) fn readback(build: &str, intended: &AnchorText, observed: &str) -> Readback {
    let (review, lockdown, pretunnel) = match build {
        "24H232" => (
            include_str!("../../qualification/goldens/24H232/review.json"),
            include_str!("../../qualification/goldens/24H232/lockdown.txt"),
            include_str!("../../qualification/goldens/24H232/pretunnel-fixture.txt"),
        ),
        "25G332" => (
            include_str!("../../qualification/goldens/25G332/review.json"),
            include_str!("../../qualification/goldens/25G332/lockdown.txt"),
            include_str!("../../qualification/goldens/25G332/pretunnel-fixture.txt"),
        ),
        _ => return Readback::Unsupported,
    };
    let reviewed = serde_json::from_str::<serde_json::Value>(review)
        .is_ok_and(|r| r["reviewed"] == true && r["build"] == build);
    if !reviewed {
        return Readback::Unsupported;
    }
    let golden = if intended == &policy::render_lockdown() {
        lockdown
    } else if pretunnel_fixture().is_ok_and(|text| text == *intended) {
        pretunnel
    } else {
        return Readback::Unsupported;
    };
    if observed == golden {
        Readback::Match
    } else {
        Readback::Mismatch
    }
}

#[cfg(test)]
use crate::platform::tests::LEFT_METHODS;

#[cfg(test)]
mod tests {
    #[test]
    fn anchor_errors_only_review_gaps_are_inconclusive() {
        use super::*;
        assert!(anchor_error_is_inconclusive(
            &crate::decode::pfanchor::UNREVIEWED
        ));
        assert!(anchor_error_is_inconclusive(&SysError::Failed(
            "anchor readback unsupported"
        )));
        for error in [
            SysError::Unknown,
            SysError::Failed("anchor missing after load"),
            SysError::Failed("foreign content in owned anchor"),
            SysError::Failed("empty anchor persists"),
        ] {
            assert!(!anchor_error_is_inconclusive(&error));
        }
    }

    use super::*;
    #[test]
    fn proposed_goldens_preserve_the_renderer_policy_without_qualifying_the_build() {
        use scupper_core::mac::parse::{Rule, pf_rules};
        let expanded = |text: &str| {
            pf_rules(text)
                .unwrap()
                .rules()
                .iter()
                .flat_map(|rule| match rule {
                    Rule::Pass(pass) => pass.expanded().into_iter().map(Rule::Pass).collect(),
                    other => vec![other.clone()],
                })
                .collect::<Vec<_>>()
        };
        for (build, lockdown, pretunnel) in [
            (
                "24H232",
                include_str!("../../qualification/goldens/24H232/lockdown.txt"),
                include_str!("../../qualification/goldens/24H232/pretunnel-fixture.txt"),
            ),
            (
                "25G332",
                include_str!("../../qualification/goldens/25G332/lockdown.txt"),
                include_str!("../../qualification/goldens/25G332/pretunnel-fixture.txt"),
            ),
        ] {
            assert_eq!(
                expanded(lockdown),
                expanded(policy::render_lockdown().as_str())
            );
            assert_eq!(
                expanded(pretunnel),
                expanded(pretunnel_fixture().unwrap().as_str())
            );
            assert_eq!(
                readback(build, &policy::render_lockdown(), lockdown),
                Readback::Unsupported
            );
        }
    }

    #[test]
    fn sentinel_comparison_ignores_metadata_but_not_content_or_incompleteness() {
        let mut before = super::super::Evidence {
            command: vec!["/sbin/pfctl".into(), "-sr".into()],
            stdin: None,
            pid: Some(42),
            exit_code: Some(0),
            started_unix_ms: 1,
            elapsed_ms: 2,
            timed_out: false,
            truncated: false,
            stdout: "block drop all\n".into(),
            stderr: String::new(),
        };
        let mut after = before.clone();
        after.pid = Some(43);
        after.started_unix_ms = 20;
        after.elapsed_ms = 3;
        assert_eq!(sentinel_changed(&before, &after), Some(false));
        after.stdout.clear();
        assert_eq!(sentinel_changed(&before, &after), Some(true));
        after.truncated = true;
        assert_eq!(sentinel_changed(&before, &after), None);
        after.truncated = false;
        before.exit_code = Some(1);
        assert_eq!(sentinel_changed(&before, &after), None);
    }

    #[test]
    fn join_checks_intermediate_writes_instead_of_only_the_final_pair() {
        let held = r#"snapshot_write:{"snapshot":{"machine":{"hold":true,"previous_generation":null,"pf_reference":null}}}"#
            .to_owned();
        assert!(join_snapshot_writes_held(std::slice::from_ref(&held)));
        assert!(!join_snapshot_writes_held(&[]));
        for bad in [
            held.replace("true", "false"),
            held.replace("\"previous_generation\":null", "\"previous_generation\":1"),
            "snapshot_write:null".into(),
            "snapshot_write:{}".into(),
            "snapshot_write:truncated".into(),
        ] {
            assert!(!join_snapshot_writes_held(&[
                held.clone(),
                bad,
                held.clone()
            ]));
        }
    }

    #[test]
    fn proposed_and_unknown_goldens_never_match_even_themselves() {
        for build in ["24H232", "25G332", "future"] {
            assert_eq!(
                readback(
                    build,
                    &policy::render_lockdown(),
                    include_str!("../../qualification/goldens/24H232/lockdown.txt")
                ),
                Readback::Unsupported
            );
            assert_eq!(
                readback(
                    build,
                    &pretunnel_fixture().unwrap(),
                    include_str!("../../qualification/goldens/24H232/pretunnel-fixture.txt")
                ),
                Readback::Unsupported
            );
        }
    }
    #[test]
    fn left_audit_contains_no_native_stub() {
        let source = include_str!("../native/mod.rs");
        for method in LEFT_METHODS {
            let body = source
                .split(&format!("    fn {method}("))
                .nth(1)
                .unwrap()
                .split("\n    fn ")
                .next()
                .unwrap();
            assert!(!body.contains("UNIMPLEMENTED"), "needs {method} (R8–R11)");
        }
    }
}
