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
// Compare normalized policy, names, addresses and routes; counters and timings
// are observations, not restorable configuration.
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
    if !second.network_mutations.is_empty() {
        result
            .violations
            .push("second restore performed network actions".into());
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

/// Observations that must be complete before a mutating probe may run.
pub(super) const REQUIRED: [&str; 10] = [
    "pf-info",
    "pf-references",
    "pf-rules",
    "pf-anchors",
    "pf-apple-anchors",
    "pf-nat",
    "scutil-keys",
    "routes",
    "interfaces",
    "machine",
];

pub(super) fn pf_status(observations: &BTreeMap<String, Evidence>) -> Option<bool> {
    let info = observations.get("pf-info")?;
    if !info.complete() {
        return None;
    }
    match info
        .stdout
        .lines()
        .find_map(|line| line.strip_prefix("Status: "))?
        .split_whitespace()
        .next()?
    {
        "Enabled" => Some(true),
        "Disabled" => Some(false),
        _ => None,
    }
}

pub(super) fn key_list(text: &str) -> Vec<String> {
    let mut keys: Vec<_> = text
        .lines()
        .filter_map(|line| line.split_once(" = ").map(|(_, key)| key.trim().to_owned()))
        .collect();
    keys.sort();
    keys
}

pub(super) fn valid_key_list(evidence: &Evidence) -> bool {
    evidence.complete()
        && evidence.stdout.lines().map(str::trim).all(|line| {
            line.is_empty()
                || (line.starts_with("subKey [")
                    && line
                        .split_once("] = ")
                        .is_some_and(|(_, key)| !key.is_empty()))
        })
}

fn normalized(name: &str, text: &str) -> Vec<String> {
    if name == "scutil-keys" {
        return key_list(text);
    }
    let mut netif = None;
    let mut lines: Vec<_> = text
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|line| {
            if name == "routes" {
                // netstat's Refs/Use/Expire are counters/timers. Preserve destination,
                // gateway, flags and interface regardless of optional counter columns.
                let fields: Vec<_> = line.split_whitespace().collect();
                if line.starts_with("Destination") {
                    netif = fields.iter().position(|field| *field == "Netif");
                }
                if fields.len() >= 4
                    && !line.starts_with("Destination")
                    && !line.starts_with("Routing")
                    && !line.ends_with(':')
                    && let Some(index) = netif.filter(|index| *index < fields.len())
                {
                    return format!(
                        "{} {} {} {}",
                        fields[0], fields[1], fields[2], fields[index]
                    );
                }
            }
            line.to_owned()
        })
        .collect();
    lines.sort();
    lines
}

pub(super) fn state_diff(
    before: &BTreeMap<String, Evidence>,
    after: &BTreeMap<String, Evidence>,
) -> Vec<String> {
    let mut changes = Vec::new();
    if !before.get("scutil-keys").is_some_and(valid_key_list)
        || !after.get("scutil-keys").is_some_and(valid_key_list)
    {
        changes.push("scutil key inventory malformed or unavailable".into());
    }
    if pf_status(before).is_none() || pf_status(before) != pf_status(after) {
        changes.push("pf enable status differs or unavailable".into());
    }
    for name in REQUIRED.into_iter().filter(|name| *name != "pf-info") {
        match (before.get(name), after.get(name)) {
            (Some(a), Some(b)) if a.complete() && b.complete() => {
                if normalized(name, &a.stdout) != normalized(name, &b.stdout)
                    || a.stderr != b.stderr
                {
                    changes.push(format!("{name}: post-state differs from preflight"));
                }
            }
            _ => changes.push(format!("{name}: baseline or post-state unavailable")),
        }
    }
    changes
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
    fn restore_requires_complete_equal_configuration_and_ignores_route_counters() {
        let mut before: BTreeMap<_, _> = REQUIRED
            .into_iter()
            .map(|name| (name.into(), observation()))
            .collect();
        if let Some(e) = before.get_mut("pf-info") {
            e.stdout = "Status: Disabled for 00:01".into();
        }
        if let Some(e) = before.get_mut("scutil-keys") {
            e.stdout = "subKey [0] = State:/one\nsubKey [1] = State:/two\n".into();
        }
        if let Some(e) = before.get_mut("routes") {
            e.stdout = "Destination Gateway Flags Refs Use Netif Expire\ndefault 192.0.2.1 UGSc 4 100 en0 50\n".into();
        }
        let mut after = before.clone();
        if let Some(e) = after.get_mut("pf-info") {
            e.stdout = "Status: Disabled for 00:02".into();
        }
        if let Some(e) = after.get_mut("scutil-keys") {
            e.stdout = "subKey [9] = State:/two\nsubKey [3] = State:/one\n".into();
        }
        if let Some(e) = after.get_mut("routes") {
            e.stdout = "Destination Gateway Flags Refs Use Netif Expire\ndefault 192.0.2.1 UGSc 8 900 en0 49\n".into();
        }
        assert_eq!(state_diff(&before, &after), Vec::<String>::new());
        for name in REQUIRED {
            let mut changed = after.clone();
            if let Some(e) = changed.get_mut(name) {
                e.stdout = "changed".into();
            }
            assert!(!state_diff(&before, &changed).is_empty(), "{name}");
            let mut missing = after.clone();
            missing.remove(name);
            assert!(!state_diff(&before, &missing).is_empty(), "{name}");
        }
        let mut malformed = observation();
        malformed.stdout = "Could not communicate with configd".into();
        assert!(!valid_key_list(&malformed));
    }

    #[test]
    fn second_restore_requires_no_actions_and_equal_static_observations() {
        let observations: BTreeMap<_, _> = STATIC_OBSERVATIONS
            .into_iter()
            .map(|name| (name.into(), observation()))
            .collect();
        let first = RestoreEffects {
            already_restored: false,
            network_mutations: &["fixture cleanup".into()],
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
