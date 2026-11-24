use crate::platform::SysError;

pub(super) fn anchor_error_is_inconclusive(error: &SysError) -> bool {
    *error == crate::decode::pfanchor::UNREVIEWED
        || matches!(error, SysError::Failed("anchor readback unsupported"))
}

// Classify the first failed adapter row itself; later incomplete calls must not
// hide an earlier complete mismatch of a reviewed row.
pub(super) fn first_anchor_failure_complete(trace: &[String]) -> Option<bool> {
    let (index, row) = trace
        .iter()
        .enumerate()
        .find(|(_, row)| row.starts_with("anchor:") && row.contains(":Err("))?;
    let op = row.strip_prefix("anchor:")?.split_once(':')?.0;
    let prefix = format!("anchor_evidence:{op}:complete:");
    Some(
        trace[..index]
            .iter()
            .rev()
            .find_map(|s| s.strip_prefix(&prefix))
            == Some("true"),
    )
}

pub(super) fn startup_environment_failed(trace: &[String]) -> bool {
    trace
        .iter()
        .find(|row| row.starts_with("failed:"))
        .is_some_and(|row| {
            [
                "failed:check_pfctl:",
                "failed:acquire_instance_lock:",
                "failed:poll_copy:",
            ]
            .iter()
            .any(|prefix| row.starts_with(prefix))
        })
}

// The cleanup runs after every returned observation error, including a load
// whose post-call budget check failed after it changed the anchor.
pub(super) fn with_cleanup<I, T, C, E>(
    io: &mut I,
    observe: impl FnOnce(&mut I) -> Result<T, E>,
    cleanup: impl FnOnce(&mut I) -> C,
) -> (Result<T, E>, C) {
    let observation = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| observe(io)));
    let cleaned = cleanup(io);
    match observation {
        Ok(result) => (result, cleaned),
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

// Measurements accept any text, including nonempty foreign classes, but every
// nested command still needs complete streams and a successful exit.
pub(super) fn measurement_complete(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Object(fields) if fields.contains_key("command") => {
            serde_json::from_value::<super::Evidence>(value.clone()).is_ok_and(|e| e.complete())
        }
        serde_json::Value::Object(fields) => {
            fields.get("kernel_complete").is_none_or(|v| v == true)
                && fields.values().all(measurement_complete)
        }
        serde_json::Value::Array(values) => values.iter().all(measurement_complete),
        _ => true,
    }
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
        .is_ok_and(|r| r["reviewed"] == true && r["build"] == build && r["optimizer"] == "none");
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
    fn fixture_cleanup_runs_after_budget_and_capture_errors() {
        for failure in [
            "post-load budget exhausted",
            "inventory capture failed",
            "record failed",
        ] {
            let mut calls = Vec::new();
            let (observed, cleaned) = super::with_cleanup(
                &mut calls,
                |calls| {
                    calls.extend(["load", "record observation"]);
                    Err::<(), _>(failure)
                },
                |calls| {
                    calls.extend(["cleanup", "record cleanup"]);
                    "cleanup result"
                },
            );
            assert_eq!(observed, Err(failure));
            assert_eq!(cleaned, "cleanup result");
            assert_eq!(
                calls,
                ["load", "record observation", "cleanup", "record cleanup"]
            );
        }
    }

    #[test]
    fn fixture_cleanup_runs_before_resuming_an_observation_panic() {
        let mut cleaned = false;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            super::with_cleanup(
                &mut cleaned,
                |_| -> Result<(), ()> {
                    panic!("fixture observation");
                },
                |cleaned| *cleaned = true,
            )
        }));
        assert!(result.is_err());
        assert!(cleaned);
    }

    #[test]
    fn reviewed_failures_keep_complete_mismatches_distinct_from_incomplete_reads() {
        for complete in [false, true] {
            let mut trace = vec![
                format!("anchor_evidence:Load:complete:{complete}"),
                "anchor:Load:Err(Unknown)".into(),
            ];
            assert_eq!(super::first_anchor_failure_complete(&trace), Some(complete));
            trace.extend([
                "anchor_evidence:Filter:complete:false".into(),
                "anchor:Filter:Err(Unknown)".into(),
            ]);
            assert_eq!(super::first_anchor_failure_complete(&trace), Some(complete));
        }
        assert_eq!(super::first_anchor_failure_complete(&[]), None);
        assert_eq!(
            super::first_anchor_failure_complete(&["anchor:Load:Err(Unknown)".into()]),
            Some(false)
        );
        for row in [
            "failed:check_pfctl:unknown",
            "failed:acquire_instance_lock:busy",
            "failed:poll_copy:unreadable",
        ] {
            assert!(super::startup_environment_failed(&[row.into()]));
        }
        assert!(!super::startup_environment_failed(&[
            "failed:poll_install_record:install record: no writer before 5a3".into(),
            "failed:poll_copy:late failure".into(),
            "failed:check_pfctl:late failure".into(),
        ]));
    }

    #[test]
    fn nested_measurement_requires_every_stream_but_accepts_foreign_text() {
        let evidence = serde_json::json!({"command":["pfctl"],"stdin":null,"pid":1,"exit_code":0,
            "started_unix_ms":0,"elapsed_ms":0,"timed_out":false,"truncated":false,
            "stdout":"anchor \"child\"\n","stderr":"unreviewed spelling\n"});
        assert!(super::measurement_complete(
            &serde_json::json!({"classes":[evidence.clone()]})
        ));
        for (key, bad) in [
            ("timed_out", serde_json::json!(true)),
            ("truncated", serde_json::json!(true)),
            ("exit_code", serde_json::json!(1)),
            ("exit_code", serde_json::Value::Null),
        ] {
            let mut incomplete = evidence.clone();
            incomplete[key] = bad;
            assert!(!super::measurement_complete(
                &serde_json::json!({"before":[evidence.clone()],"after":[incomplete]})
            ));
        }
    }

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
            SysError::Failed("anchor configuration persists"),
        ] {
            assert!(!anchor_error_is_inconclusive(&error));
        }
    }

    use super::*;
    #[test]
    fn reviewed_optimizer_none_goldens_preserve_source_order() {
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
                Readback::Match
            );
            assert_eq!(
                readback(build, &pretunnel_fixture().unwrap(), pretunnel),
                Readback::Match
            );
            let mut rows: Vec<_> = pretunnel.lines().collect();
            rows.swap(1, 2);
            assert_eq!(
                readback(
                    build,
                    &pretunnel_fixture().unwrap(),
                    &(rows.join("\n") + "\n")
                ),
                Readback::Mismatch
            );
            for bad in [
                String::new(),
                format!("{lockdown}\n"),
                lockdown.replace("block drop", "block return"),
            ] {
                assert_eq!(
                    readback(build, &policy::render_lockdown(), &bad),
                    Readback::Mismatch
                );
            }
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
    fn unknown_goldens_never_match_even_themselves() {
        for build in ["future", "24H233", "25G333"] {
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

/// Pass-2 pinned userland rejections, reviewed for 24H232 and 25G332.
pub(super) fn descendant_rejection(build: &str, name: &str, load: &super::Evidence) -> bool {
    let diagnostic: &[u8] = match name {
        "underscore" => b"stdin:1: anchor names beginning with '_' are reserved for internal use\npfctl: Syntax error in config file: pf rules not loaded\n",
        "inline" => b"stdin:1: syntax error\npfctl: Syntax error in config file: pf rules not loaded\n",
        _ => return false,
    };
    matches!(build, "24H232" | "25G332")
        && load.exit_code == Some(1)
        && !load.timed_out
        && !load.truncated
        && load.stdout.is_empty()
        && load.stderr.as_bytes()
            == [
                crate::decode::pfanchor::LOAD_WARNING,
                crate::decode::pftext::ALTQ_PREAMBLE,
                diagnostic,
            ]
            .concat()
}
#[cfg(test)]
mod rejection_tests {
    use super::*;
    #[test]
    fn full_reviewed_rejection_rows_match_both_builds() {
        for review in [
            include_str!("../../qualification/goldens/24H232/measurement-review.json"),
            include_str!("../../qualification/goldens/25G332/measurement-review.json"),
        ] {
            let review: serde_json::Value = serde_json::from_str(review).unwrap();
            let build = review["build"].as_str().unwrap();
            for row in review["rejections"].as_array().unwrap() {
                let name = row["name"].as_str().unwrap();
                let mut load: super::super::Evidence = serde_json::from_value(serde_json::json!({
                    "command":row["command"],"stdin":row["stdin"],"pid":1,"exit_code":row["exit_code"],
                    "started_unix_ms":0,"elapsed_ms":0,"timed_out":false,"truncated":false,
                    "stdout":row["stdout"],"stderr":row["stderr"]
                })).unwrap();
                assert!(descendant_rejection(build, name, &load));
                load.truncated = true;
                assert!(!descendant_rejection(build, name, &load));
                load.truncated = false;
                load.stderr.push('x');
                assert!(!descendant_rejection(build, name, &load));
            }
        }
    }
    #[test]
    fn only_exact_pinned_rejections_count_as_completed_load_measurements() {
        let mut load: super::super::Evidence = serde_json::from_value(serde_json::json!({
            "command":[],"stdin":null,"pid":null,"exit_code":1,"started_unix_ms":0,"elapsed_ms":0,
            "timed_out":false,"truncated":false,"stdout":"","stderr":""
        }))
        .unwrap();
        load.stderr = String::from_utf8([crate::decode::pfanchor::LOAD_WARNING, crate::decode::pftext::ALTQ_PREAMBLE,
            b"stdin:1: anchor names beginning with '_' are reserved for internal use\npfctl: Syntax error in config file: pf rules not loaded\n"].concat()).unwrap();
        assert!(descendant_rejection("25G332", "underscore", &load));
        assert!(descendant_rejection("24H232", "underscore", &load));
        for build in ["24H232", "25G332"] {
            load.stderr = [
                crate::decode::pfanchor::LOAD_WARNING,
                crate::decode::pftext::ALTQ_PREAMBLE,
                b"stdin:1: syntax error\npfctl: Syntax error in config file: pf rules not loaded\n",
            ]
            .concat()
            .iter()
            .map(|b| char::from(*b))
            .collect();
            assert!(descendant_rejection(build, "inline", &load));
            assert!(!descendant_rejection(build, "inline-multiline", &load));
        }
        load.stderr.push('x');
        assert!(!descendant_rejection("25G332", "underscore", &load));
    }
}
