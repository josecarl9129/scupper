use std::collections::BTreeMap;

use serde::Serialize;

use super::Evidence;

const STATIC_OBSERVATIONS: [&str; 8] = [
    "pf-rules",
    "pf-anchors",
    "pf-apple-anchors",
    "pf-nat",
    "tool-sha256",
    "osversion",
    "kernel-uuid",
    "machine",
];

pub(super) struct RestoreEffects<'a> {
    pub already_restored: bool,
    pub network_mutations: &'a [String],
    pub writer_stop_count: usize,
    pub observations: &'a BTreeMap<String, Evidence>,
}

#[derive(Debug, Serialize)]
pub(super) struct Comparison {
    pub violations: Vec<String>,
    pub unavailable_observations: Vec<String>,
}

// Compare the second restore against an actual no-op, not just a marker file.
// Dynamic counters, timing and foreign routes/interfaces are intentionally absent.
pub(super) fn compare(first: &RestoreEffects<'_>, second: &RestoreEffects<'_>) -> Comparison {
    let mut result = Comparison {
        violations: Vec::new(),
        unavailable_observations: Vec::new(),
    };
    if !second.already_restored {
        result
            .violations
            .push("second restore did not observe the first restore marker".into());
    }
    if !first.network_mutations.is_empty() || !second.network_mutations.is_empty() {
        result
            .violations
            .push("bootstrap restore performed network actions".into());
    }
    if second.writer_stop_count != 0 {
        result
            .violations
            .push("second restore performed writer-stop actions".into());
    }
    for name in STATIC_OBSERVATIONS {
        match (first.observations.get(name), second.observations.get(name)) {
            (Some(old), Some(new)) if old.complete() && new.complete() => {
                if old.stdout != new.stdout
                    || old.stderr != new.stderr
                    || old.exit_code != new.exit_code
                {
                    result
                        .violations
                        .push(format!("second restore changed {name}"));
                }
            }
            _ => result.unavailable_observations.push(name.into()),
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observation() -> Evidence {
        Evidence {
            command: Vec::new(),
            stdin: None,
            pid: None,
            exit_code: Some(0),
            started_unix_ms: 0,
            elapsed_ms: 0,
            timed_out: false,
            truncated: false,
            stdout: "stable".into(),
            stderr: String::new(),
        }
    }

    #[test]
    fn second_restore_requires_no_actions_and_equal_static_observations() {
        let observations: BTreeMap<_, _> = STATIC_OBSERVATIONS
            .into_iter()
            .map(|name| (name.into(), observation()))
            .collect();
        let first = RestoreEffects {
            already_restored: false,
            network_mutations: &[],
            writer_stop_count: 1,
            observations: &observations,
        };
        let mut second = RestoreEffects {
            already_restored: true,
            network_mutations: &[],
            writer_stop_count: 0,
            observations: &observations,
        };
        let equal = compare(&first, &second);
        assert_eq!(equal.violations, Vec::<String>::new());
        assert_eq!(equal.unavailable_observations, Vec::<String>::new());
        second.already_restored = false;
        assert_ne!(compare(&first, &second).violations, Vec::<String>::new());
        second.already_restored = true;
        second.writer_stop_count = 1;
        assert!(
            compare(&first, &second)
                .violations
                .iter()
                .any(|reason| reason.contains("writer-stop"))
        );
        second.writer_stop_count = 0;
        let mutations = ["unexpected action".into()];
        second.network_mutations = &mutations;
        assert_ne!(compare(&first, &second).violations, Vec::<String>::new());
        second.network_mutations = &[];
        for name in STATIC_OBSERVATIONS {
            let mut changed = observations.clone();
            changed.get_mut(name).expect("fixture key").stdout = "drift".into();
            let drifted = RestoreEffects {
                observations: &changed,
                ..second
            };
            assert_eq!(
                compare(&first, &drifted).violations,
                [format!("second restore changed {name}")]
            );
        }
    }

    #[test]
    fn incomplete_observations_are_reported_and_dynamic_drift_is_ignored() {
        let first_observations = BTreeMap::new();
        let second_observations = BTreeMap::from([("routes".into(), observation())]);
        let first = RestoreEffects {
            already_restored: false,
            network_mutations: &[],
            writer_stop_count: 0,
            observations: &first_observations,
        };
        let second = RestoreEffects {
            already_restored: true,
            network_mutations: &[],
            writer_stop_count: 0,
            observations: &second_observations,
        };
        let result = compare(&first, &second);
        assert_eq!(result.violations, Vec::<String>::new());
        assert_eq!(
            result.unavailable_observations.len(),
            STATIC_OBSERVATIONS.len()
        );
    }
}
