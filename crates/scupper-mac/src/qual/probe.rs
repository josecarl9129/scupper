//! Portable validation of throwaway C-probe output. Measurements never promote.
use serde_json::Value;

use super::Verdict;

pub(super) const NAMES: [&str; 9] = [
    "pf-starters",
    "pf-eexist",
    "proc-identity",
    "utun-handoff",
    "storage",
    "sc-session",
    "dns-keys",
    "dns-default",
    "dns-default-minimal",
];

pub(super) fn questions(value: &Value) -> Result<Vec<(String, Verdict, u32)>, &'static str> {
    let events = value["events"]
        .as_array()
        .ok_or("probe needs an events array")?;
    let mut questions = Vec::new();
    for event in events.iter().filter(|event| event["event"] == "question") {
        let id = event["question"].as_str().ok_or("missing question id")?;
        if !id.starts_with("Q-")
            || !id.bytes().all(|byte| {
                byte.is_ascii_uppercase()
                    || byte.is_ascii_digit()
                    || byte == b'-'
                    || byte.is_ascii_lowercase()
            })
            || questions.iter().any(|(old, _, _)| old == id)
        {
            return Err("invalid or duplicate question id");
        }
        let verdict: Verdict = serde_json::from_value(event["verdict"].clone())
            .map_err(|_| "invalid question verdict")?;
        if !matches!(
            verdict,
            Verdict::AssumptionHolds | Verdict::AssumptionRefuted | Verdict::Inconclusive
        ) {
            return Err("probe cannot assert a harness contract verdict");
        }
        let iterations = event["iterations"]
            .as_u64()
            .and_then(|n| u32::try_from(n).ok())
            .ok_or("invalid iteration count")?;
        if iterations == 0 && verdict != Verdict::Inconclusive {
            return Err("a zero-iteration question cannot hold or refute");
        }
        questions.push((id.into(), verdict, iterations));
    }
    Ok(questions)
}

pub(super) fn pf_read_count(value: &Value) -> u32 {
    value["events"].as_array().map_or(0, |events| {
        u32::try_from(
            events
                .iter()
                .filter(|event| event["event"] == "getstarters" && event["rc"] == 0)
                .count(),
        )
        .unwrap_or(u32::MAX)
    })
}

// Darwin errno values are part of the measured ABI, not the build host's libc.
pub(super) fn pf_contract_violation(value: &Value) -> bool {
    let mut readonly = true;
    value["events"].as_array().is_some_and(|events| {
        events.iter().any(|event| {
            if event["event"]
                .as_str()
                .is_some_and(|name| name.starts_with("open"))
            {
                readonly = event["mode"] == "rdonly";
            }
            event["errno"] == 19
                || (readonly && (event["rc"] == -1 || event["fd"] == -1) && event["errno"] == 13)
        })
    })
}

pub(super) fn pf_size_query(value: &Value) -> (Verdict, u32) {
    let Some(events) = value["events"].as_array() else {
        return (Verdict::Inconclusive, 0);
    };
    let mut count = 0;
    for event in events.iter().filter(|e| e["event"] == "size-query") {
        if event["rc"] != 0 {
            return (Verdict::Inconclusive, count);
        }
        count += 1;
        if event["capacity"] != 0
            || !event["returned_size"]
                .as_u64()
                .is_some_and(|size| size > 0 && size % 84 == 0)
            || !event["tokens"].as_array().is_some_and(Vec::is_empty)
        {
            return (Verdict::AssumptionRefuted, count);
        }
    }
    (
        if count == 5 {
            Verdict::AssumptionHolds
        } else {
            Verdict::Inconclusive
        },
        count,
    )
}

// Run every independent experiment and always execute the final recovery check.
pub(super) fn run_all<E: std::fmt::Display>(
    names: impl IntoIterator<Item = &'static str>,
    mut run: impl FnMut(&str) -> Result<(), E>,
    final_restore: impl FnOnce() -> Result<(), E>,
) -> Vec<String> {
    let mut failures = Vec::new();
    for name in names {
        if let Err(error) = run(name) {
            failures.push(format!("{name}: {error}"));
        }
    }
    if let Err(error) = final_restore() {
        failures.push(format!("final restore: {error}"));
    }
    failures
}

// Q-REFS tests the observed copy loop, including the deliberately unaligned
// capacities. This is measurement validation, not an adapter completeness rule.
pub(super) fn pf_layout(value: &Value) -> Verdict {
    if pf_contract_violation(value) {
        return Verdict::ContractViolation;
    }
    let Some(events) = value["events"].as_array() else {
        return Verdict::Inconclusive;
    };
    let Some(layout) = events.iter().find(|e| e["event"] == "layout") else {
        return Verdict::Inconclusive;
    };
    if layout["token_size"] != 84
        || layout["request_size"] != 16
        || layout["ioctl"] != 0xc010_4405_u64
    {
        return Verdict::AssumptionRefuted;
    }
    let mut order: Vec<u64> = Vec::new();
    let mut reads = 0;
    for event in events {
        if event["event"] == "series" {
            let Some(tokens) = event["acquisition_order"].as_array() else {
                return Verdict::Inconclusive;
            };
            let Some(tokens) = tokens.iter().map(Value::as_u64).collect::<Option<Vec<_>>>() else {
                return Verdict::Inconclusive;
            };
            if !matches!(tokens.len(), 1 | 2 | 3 | 8 | 64)
                || tokens.contains(&0)
                || tokens
                    .iter()
                    .collect::<std::collections::BTreeSet<_>>()
                    .len()
                    != tokens.len()
            {
                return Verdict::Inconclusive;
            }
            order = tokens.into_iter().rev().collect();
        }
        if event["event"] != "getstarters" {
            continue;
        }
        if event["rc"] != 0 {
            return Verdict::Inconclusive;
        }
        let Some(capacity) = event["capacity"].as_u64() else {
            return Verdict::Inconclusive;
        };
        let Some(tokens) = event["tokens"].as_array() else {
            return Verdict::Inconclusive;
        };
        if capacity == 0 {
            return Verdict::AssumptionRefuted;
        }
        let expected = order
            .len()
            .min(usize::try_from(capacity / 84).unwrap_or(usize::MAX));
        let returned = u64::try_from(expected)
            .unwrap_or(u64::MAX)
            .saturating_mul(84);
        if event["returned_size"] != returned
            || tokens.len() != expected
            || tokens.iter().zip(&order).any(|(a, b)| a["token"] != *b)
        {
            return Verdict::AssumptionRefuted;
        }
        reads += 1;
    }
    if reads == 35 {
        Verdict::AssumptionHolds
    } else {
        Verdict::Inconclusive
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn every_probe_has_a_bounded_measurement_manifest_entry() -> Result<(), serde_json::Error> {
        let manifest = super::super::Manifest::bundled()?;
        for name in NAMES {
            let case = manifest
                .cases
                .iter()
                .find(|case| case.id == format!("Q-PROBE-{}", name.to_ascii_uppercase()));
            assert!(case.is_some_and(|case| case.budget_minutes <= 2
                && case.supported_assumptions.is_empty()
                && case.group
                    == if name.starts_with("dns-default") {
                        "probe-hijack"
                    } else {
                        "probe"
                    }));
        }
        Ok(())
    }

    #[test]
    fn hijack_deadman_exceeds_cases_and_final_restore_budget()
    -> Result<(), Box<dyn std::error::Error>> {
        let manifest = super::super::Manifest::bundled()?;
        let case_seconds: u64 = manifest
            .cases
            .iter()
            .filter(|case| case.group == "probe-hijack")
            .map(|case| u64::from(case.budget_minutes) * 60)
            .sum();
        let workflow = include_str!("../../../../.github/workflows/ci.yml");
        let arm = workflow
            .split("- name: Arm independent launchd restore")
            .nth(1)
            .ok_or("missing arm step")?
            .split("- name: Run qualification cell")
            .next()
            .ok_or("missing run step boundary")?;
        let deadlines: Vec<u64> = arm
            .lines()
            .filter_map(|line| {
                line.trim()
                    .strip_prefix("after=")
                    .and_then(|value| value.parse().ok())
            })
            .collect();
        assert_eq!(
            deadlines.len(),
            1,
            "one shared arm deadline; no hijack override"
        );
        assert!(deadlines[0] >= 120);
        assert!(deadlines[0] > case_seconds + super::super::model::MAX_FINAL_RESTORE_SECONDS);
        // The largest probe group and the maximum final restore must also fit
        // before the shared dead-man fires (scoped recovery is in each case).
        let probe_seconds: u64 = manifest
            .cases
            .iter()
            .filter(|case| case.group == "probe")
            .map(|case| u64::from(case.budget_minutes) * 60)
            .sum();
        assert!(deadlines[0] >= probe_seconds + super::super::model::MAX_FINAL_RESTORE_SECONDS);
        let restore_minutes = workflow
            .split("- name: Restore and stop dead-man")
            .nth(1)
            .ok_or("missing always-step recovery")?
            .lines()
            .find_map(|line| line.trim().strip_prefix("timeout-minutes: "))
            .ok_or("missing always-step deadline")?
            .parse::<u64>()?;
        assert!(restore_minutes * 60 > super::super::model::MAX_FINAL_RESTORE_SECONDS);
        assert!(arm.contains("--after \"$after\""));
        let overrides: Vec<_> = arm
            .lines()
            .map(str::trim)
            .filter(|line| line.contains("then after="))
            .collect();
        assert_eq!(
            overrides,
            [r#"if [ "${{ matrix.group }}" = pf ]; then after=1500; fi"#]
        );
        assert_eq!(deadlines[0], 18 * 60);
        Ok(())
    }

    #[test]
    fn malformed_or_zero_iteration_answers_cannot_qualify() {
        assert!(questions(&json!({})).is_err());
        for verdict in [
            "measurement",
            "contract_violation",
            "assumption_holds",
            "assumption_refuted",
        ] {
            assert!(questions(&json!({"events":[{"event":"question", "question":"Q-X", "verdict":verdict, "iterations":0}]})).is_err());
        }
        assert_eq!(pf_layout(&json!({"events":[]})), Verdict::Inconclusive);
    }

    #[test]
    fn truncated_copy_and_wrong_order_refute_the_layout_hypothesis() {
        let mut events = vec![
            json!({"event":"layout", "token_size":84, "request_size":16, "ioctl":0xc010_4405_u64}),
        ];
        for n in [1_u64, 2, 3, 8, 64] {
            for c in [0, 83, 84, 85, 167, 168, n * 84, n * 84 + 84] {
                events.push(
                    json!({"event":"series", "acquisition_order":(1..=n).collect::<Vec<_>>()}),
                );
                let count = n.min(c / 84);
                events.push(json!({"event":if c == 0 { "size-query" } else { "getstarters" }, "capacity":c, "rc":0, "returned_size":if c==0 {n*84} else {count*84}, "tokens":(1..=n).rev().take(usize::try_from(count).unwrap_or(0)).map(|t| json!({"token":t})).collect::<Vec<_>>()}));
            }
        }
        let good = json!({"events":events});
        assert_eq!(pf_layout(&good), Verdict::AssumptionHolds);
        assert_eq!(pf_size_query(&good), (Verdict::AssumptionHolds, 5));
        assert_eq!(pf_read_count(&good), 35);
        let mut bad = good.clone();
        bad["events"][8]["tokens"][0]["token"] = json!(999);
        assert_eq!(pf_layout(&bad), Verdict::AssumptionRefuted);
        let mut query_bad = good.clone();
        query_bad["events"][2]["returned_size"] = json!(1);
        assert_eq!(pf_layout(&query_bad), Verdict::AssumptionHolds);
        assert_eq!(pf_size_query(&query_bad), (Verdict::AssumptionRefuted, 1));
        let mut short = good;
        short["events"].as_array_mut().map(Vec::pop);
        assert_eq!(pf_layout(&short), Verdict::Inconclusive);
        assert_eq!(pf_read_count(&short), 34);
    }
    #[test]
    fn wrong_command_and_readonly_denial_are_harness_failures() {
        for mode in ["rdonly", "rdwr"] {
            for errno in [1, 2, 13, 19] {
                let value = json!({"events":[
                    {"event":"open", "mode":mode, "errno":0},
                    {"event":"empty", "rc":-1, "errno":errno}
                ]});
                let violation = errno == 19 || (mode == "rdonly" && errno == 13);
                assert_eq!(pf_contract_violation(&value), violation);
                assert_eq!(
                    pf_layout(&value),
                    if violation {
                        Verdict::ContractViolation
                    } else {
                        Verdict::Inconclusive
                    }
                );
            }
        }
        assert!(pf_contract_violation(
            &json!({"events":[{"event":"open", "mode":"rdonly", "errno":19}]})
        ));
    }

    #[test]
    fn failed_probe_does_not_skip_later_probes_or_final_restore() {
        let calls = std::cell::RefCell::new(Vec::new());
        let failures = run_all(
            ["one", "two", "three"],
            |name| {
                calls.borrow_mut().push(name.to_owned());
                if name == "two" {
                    Ok(())
                } else {
                    Err("inventory unavailable")
                }
            },
            || {
                calls.borrow_mut().push("restore".into());
                Err("post-state mismatch")
            },
        );
        assert_eq!(*calls.borrow(), ["one", "two", "three", "restore"]);
        assert_eq!(
            failures,
            [
                "one: inventory unavailable",
                "three: inventory unavailable",
                "final restore: post-state mismatch"
            ]
        );
    }
}
