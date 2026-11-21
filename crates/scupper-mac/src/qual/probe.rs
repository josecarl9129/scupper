//! Portable validation of throwaway C-probe output. Measurements never promote.
use serde_json::Value;

use super::Verdict;

pub(super) const NAMES: [&str; 8] = [
    "pf-starters",
    "pf-eexist",
    "proc-identity",
    "utun-handoff",
    "storage",
    "sc-session",
    "dns-keys",
    "dns-default",
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

// Q-REFS tests the observed copy loop, including the deliberately unaligned
// capacities. This is measurement validation, not an adapter completeness rule.
pub(super) fn pf_layout(value: &Value) -> Verdict {
    let Some(events) = value["events"].as_array() else {
        return Verdict::Inconclusive;
    };
    let Some(layout) = events.iter().find(|e| e["event"] == "layout") else {
        return Verdict::Inconclusive;
    };
    if layout["token_size"] != 84
        || layout["request_size"] != 16
        || layout["ioctl"] != 0xc010_445b_u64
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
            if !matches!(tokens.len(), 1 | 2 | 3 | 8)
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
        let expected = if capacity == 0 {
            order.len()
        } else {
            order
                .len()
                .min(usize::try_from(capacity / 84).unwrap_or(usize::MAX))
        };
        let returned = u64::try_from(expected)
            .unwrap_or(u64::MAX)
            .saturating_mul(84);
        if event["returned_size"] != returned
            || (capacity != 0
                && (tokens.len() != expected
                    || tokens.iter().zip(&order).any(|(a, b)| a["token"] != *b)))
            || (capacity == 0 && !tokens.is_empty())
        {
            return Verdict::AssumptionRefuted;
        }
        reads += 1;
    }
    if reads == 32 {
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
                    == if name == "dns-default" {
                        "probe-hijack"
                    } else {
                        "probe"
                    }));
        }
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
            json!({"event":"layout", "token_size":84, "request_size":16, "ioctl":0xc010_445b_u64}),
        ];
        for n in [1_u64, 2, 3, 8] {
            for c in [0, 83, 84, 85, 167, 168, n * 84, n * 84 + 84] {
                events.push(
                    json!({"event":"series", "acquisition_order":(1..=n).collect::<Vec<_>>()}),
                );
                let count = n.min(c / 84);
                events.push(json!({"event":"getstarters", "capacity":c, "rc":0, "returned_size":if c==0 {n*84} else {count*84}, "tokens":(1..=n).rev().take(usize::try_from(count).unwrap_or(0)).map(|t| json!({"token":t})).collect::<Vec<_>>()}));
            }
        }
        let good = json!({"events":events});
        assert_eq!(pf_layout(&good), Verdict::AssumptionHolds);
        assert_eq!(pf_read_count(&good), 32);
        let mut bad = good.clone();
        bad["events"][8]["tokens"][0]["token"] = json!(999);
        assert_eq!(pf_layout(&bad), Verdict::AssumptionRefuted);
        let mut short = good;
        short["events"].as_array_mut().map(Vec::pop);
        assert_eq!(pf_layout(&short), Verdict::Inconclusive);
        assert_eq!(pf_read_count(&short), 31);
    }
}
