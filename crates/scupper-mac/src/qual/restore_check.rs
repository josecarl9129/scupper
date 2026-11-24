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
            (Some(old), Some(new))
                if old.complete()
                    && new.complete()
                    && (!name.starts_with("pf-")
                        || (super::guard::pf_read_complete(first.observations, name)
                            && super::guard::pf_read_complete(second.observations, name))) =>
            {
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
    match crate::decode::pftext::info(
        &super::guard::pf_build(observations)?,
        0,
        info.stdout.as_bytes(),
        info.stderr.as_bytes(),
    )
    .ok()?
    {
        crate::platform::PfInfo::Enabled => Some(true),
        crate::platform::PfInfo::Disabled => Some(false),
        crate::platform::PfInfo::Incomplete(_) => None,
    }
}

/// Decide whether the current state is known; Unknown also triggers harness disable.
/// Missing build/status is a visible restore failure, never a silent skip.
pub(super) fn restore_disable(
    observations: &BTreeMap<String, Evidence>,
) -> Result<bool, &'static str> {
    pf_status(observations).ok_or("restore pf status unknown (including OS build evidence)")
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

pub(super) fn resolver_clone(text: &str) -> bool {
    let mut netif = 3;
    text.lines().any(|line| {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.first() == Some(&"Destination") {
            netif = fields
                .iter()
                .position(|field| *field == "Netif")
                .unwrap_or(3);
        }
        fields.len() > netif
            && fields.len() >= 4
            && fields[0] == "127.0.0.53"
            && fields[1] == "127.0.0.1"
            && fields[2].contains('H')
            && fields[2].contains('W')
            && !fields[2].contains('S')
            && fields[netif] == "lo0"
    })
}

fn harness_key(key: &str, journaled: &[String]) -> bool {
    key.starts_with("State:/Network/Service/scupper-qual-")
        || key.contains("com.scupper.")
        || journaled.iter().any(|owned| owned == key)
}

#[derive(Debug, Default, Serialize)]
pub(super) struct StateChanges {
    pub violations: Vec<String>,
    pub os_drift: Vec<String>,
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
        .filter_map(|line| {
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
                    let gateway = fields[1];
                    let flags = fields[2];
                    let interface = fields[index];
                    let link_gateway = gateway.starts_with("link#")
                        || (gateway.split(':').count() == 6
                            && gateway.split(':').all(|part| {
                                !part.is_empty()
                                    && part.len() <= 2
                                    && part.bytes().all(|b| b.is_ascii_hexdigit())
                            }));
                    // Cache entries may appear/disappear between inventories.
                    // Keep all fixture/tunnel routes and network gateways.
                    let network_gateway = gateway
                        .split('%')
                        .next()
                        .is_some_and(|gateway| gateway.parse::<std::net::IpAddr>().is_ok());
                    if !network_gateway
                        && !interface.starts_with("utun")
                        && !interface.contains("scupper")
                        && (flags.contains('L') || (flags.contains('W') && link_gateway))
                    {
                        return None;
                    }
                    return Some(format!("{} {} {} {}", fields[0], gateway, flags, interface));
                }
            }
            Some(line.to_owned())
        })
        .collect();
    lines.sort();
    lines
}

#[cfg(test)]
pub(super) fn state_changes(
    before: &BTreeMap<String, Evidence>,
    after: &BTreeMap<String, Evidence>,
    journaled_keys: &[String],
    empty_anchor_names: &[String],
) -> StateChanges {
    state_changes_with_incomplete(before, after, journaled_keys, empty_anchor_names, &[])
}

pub(super) fn state_changes_with_incomplete(
    before: &BTreeMap<String, Evidence>,
    after: &BTreeMap<String, Evidence>,
    journaled_keys: &[String],
    empty_anchor_names: &[String],
    incomplete_anchor_names: &[String],
) -> StateChanges {
    let mut changes = Vec::new();
    let mut os_drift = Vec::new();
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
            (Some(a), Some(b))
                if a.complete()
                    && b.complete()
                    && (!name.starts_with("pf-")
                        || name == "pf-references"
                        || (super::guard::pf_read_complete(before, name)
                            && super::guard::pf_read_complete(after, name))) =>
            {
                let old = normalized(name, &a.stdout);
                let mut new = normalized(name, &b.stdout);
                if name == "scutil-keys" {
                    new.retain(|key| {
                        if !old.contains(key) && !harness_key(key, journaled_keys) {
                            os_drift.push(key.clone());
                            false
                        } else {
                            true
                        }
                    });
                }
                if matches!(name, "pf-anchors" | "pf-apple-anchors") {
                    new.retain(|line| {
                        old.contains(line)
                            || (!empty_anchor_names.contains(line)
                                && !incomplete_anchor_names.iter().any(|name| {
                                    line == name
                                        || (name != "scupper-qual"
                                            && line.starts_with(&format!("{name}/")))
                                }))
                    });
                }
                if old != new || a.stderr != b.stderr {
                    changes.push(format!("{name}: post-state differs from preflight"));
                }
            }
            _ => changes.push(format!("{name}: baseline or post-state unavailable")),
        }
    }
    StateChanges {
        violations: changes,
        os_drift,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Write as _;

    fn state_diff(
        before: &BTreeMap<String, Evidence>,
        after: &BTreeMap<String, Evidence>,
    ) -> Vec<String> {
        state_changes(before, after, &[], &[]).violations
    }

    #[test]
    fn post_state_only_allows_proven_empty_journaled_anchor_names() {
        let mut before = BTreeMap::from([
            (
                "osversion".into(),
                Evidence {
                    stdout: "25G332".into(),
                    ..observation()
                },
            ),
            (
                "pf-anchors".into(),
                Evidence {
                    stdout: String::new(),
                    stderr: String::from_utf8_lossy(crate::decode::pftext::ALTQ_PREAMBLE)
                        .into_owned(),
                    ..observation()
                },
            ),
        ]);
        let mut after = before.clone();
        after.get_mut("pf-anchors").unwrap().stdout =
            "  scupper-qual\n  scupper-qual/scupper\n".into();
        let allowed = vec!["scupper-qual".into(), "scupper-qual/scupper".into()];
        let baseline = state_changes(&before, &before, &[], &allowed).violations;
        assert_eq!(
            state_changes(&before, &after, &[], &allowed).violations,
            baseline
        );
        assert_ne!(
            state_changes(&before, &after, &[], &[]).violations,
            baseline
        );
        after
            .get_mut("pf-anchors")
            .unwrap()
            .stdout
            .push_str("  scupper-qual/foreign\n");
        assert_ne!(
            state_changes(&before, &after, &[], &allowed).violations,
            baseline
        );
        before.get_mut("pf-anchors").unwrap().stdout = "  removed-foreign\n".into();
        assert_ne!(
            state_changes(&before, &after, &[], &allowed).violations,
            baseline
        );
    }

    #[test]
    fn incomplete_anchor_read_keeps_other_allowances_and_does_not_hide_foreign_siblings() {
        let before = BTreeMap::from([
            (
                "osversion".into(),
                Evidence {
                    stdout: "25G332".into(),
                    ..observation()
                },
            ),
            (
                "pf-anchors".into(),
                Evidence {
                    stdout: String::new(),
                    stderr: String::from_utf8_lossy(crate::decode::pftext::ALTQ_PREAMBLE)
                        .into_owned(),
                    ..observation()
                },
            ),
        ]);
        let mut after = before.clone();
        after.get_mut("pf-anchors").unwrap().stdout =
            "scupper-qual\nscupper-qual/ok\nscupper-qual/unknown\n".into();
        let allowed = vec!["scupper-qual/ok".into()];
        let incomplete = vec!["scupper-qual".into(), "scupper-qual/unknown".into()];
        let baseline =
            state_changes_with_incomplete(&before, &before, &[], &allowed, &incomplete).violations;
        assert_eq!(
            state_changes_with_incomplete(&before, &after, &[], &allowed, &incomplete).violations,
            baseline
        );
        after
            .get_mut("pf-anchors")
            .unwrap()
            .stdout
            .push_str("scupper-qual/foreign\n");
        assert_ne!(
            state_changes_with_incomplete(&before, &after, &[], &allowed, &incomplete).violations,
            baseline
        );
    }

    #[test]
    fn restore_decision_requires_build_and_disables_enabled_pf() {
        let mut enabled = observation();
        enabled.stdout = "Status: Enabled\n".into();
        enabled.stderr = String::from_utf8_lossy(crate::decode::pftext::ALTQ_PREAMBLE).into_owned();
        let mut current = BTreeMap::from([("pf-info".into(), enabled)]);
        assert!(restore_disable(&current).is_err());
        for build in crate::decode::pftext::BUILDS {
            current.insert(
                "osversion".into(),
                Evidence {
                    stdout: build.into(),
                    ..observation()
                },
            );
            assert_eq!(restore_disable(&current), Ok(true), "must run pfctl -d");
            current.get_mut("pf-info").expect("fixture").stdout = "Status: Disabled\n".into();
            assert_eq!(restore_disable(&current), Ok(false));
            for text in [
                "Status: Disabled\nunknown\n",
                "Status: Disabled\nStatus: Enabled\n",
            ] {
                current.get_mut("pf-info").expect("fixture").stdout = text.into();
                assert!(restore_disable(&current).is_err());
            }
            current.get_mut("pf-info").expect("fixture").stdout = "Status: Enabled\n".into();
        }
        let resources = include_str!("resources.rs");
        assert!(
            resources.contains("(\"osversion\".into(), osversion)"),
            "assertion: restore must supply live osversion"
        );
        assert!(resources.contains("match restore_check::restore_disable(&current)"));
        assert!(resources.contains("undo_pf_state(out, deadline, &mut actions, &mut failures);"));
        let enabled = resources
            .split_once("Ok(true) => {")
            .expect("enabled restore branch")
            .1
            .split("Ok(false)")
            .next()
            .expect("enabled body");
        assert!(enabled.contains("action(out, \"/sbin/pfctl\", &[\"-d\"]"));
        let unknown = resources
            .split_once("Err(reason) => {")
            .expect("unknown restore branch")
            .1;
        assert!(unknown.contains("action(out, \"/sbin/pfctl\", &[\"-d\"]"));
        assert!(resources.contains("restore pf status capture failed"));
        let pf = include_str!("pf.rs");
        assert!(pf.contains("if status != PfInfo::Disabled {"));
        assert!(pf.contains("Err(error) if args == [\"-d\"] => {"));
        assert!(pf.contains("let _enabled_info = raw(out, p, &[\"-s\", \"info\"], end)?;"));
    }

    #[test]
    fn resolver_clone_is_exact_and_remains_a_restore_difference() {
        let line = "127.0.0.53 127.0.0.1 UHW3I lo0 3579";
        assert!(resolver_clone(line));
        assert!(resolver_clone(
            "Destination Gateway Flags Refs Use Netif Expire\n127.0.0.53 127.0.0.1 UHW3I 0 3 lo0 3579\n"
        ));
        for changed in [
            line.replace("127.0.0.53", "127.0.0.54"),
            line.replace("127.0.0.1 ", "127.0.0.2 "),
            line.replace("UHW3I", "UHSW"),
            line.replace("lo0", "en0"),
        ] {
            assert!(!resolver_clone(&changed));
        }
        let header = "Destination Gateway Flags Netif Expire\n";
        assert_ne!(
            normalized("routes", header),
            normalized("routes", &format!("{header}{line}\n"))
        );
    }

    #[test]
    fn lazy_os_keys_are_drift_but_removals_and_owned_additions_violate()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut before = BTreeMap::from([("scutil-keys".into(), observation())]);
        before
            .get_mut("scutil-keys")
            .ok_or("missing fixture keys")?
            .stdout = "subKey [0] = State:/original\n".into();
        let mut after = before.clone();
        after
            .get_mut("scutil-keys")
            .ok_or("missing fixture keys")?
            .stdout
            .push_str("subKey [1] = State:/Network/NetBIOS\n");
        let baseline = state_changes(&before, &before, &[], &[]).violations;
        let added = state_changes(&before, &after, &[], &[]);
        assert_eq!(added.violations, baseline);
        assert_eq!(added.os_drift, ["State:/Network/NetBIOS"]);
        for key in [
            "State:/Network/Service/scupper-qual-dns/DNS",
            "State:/Network/Service/com.scupper.tunnel/DNS",
            "State:/journaled",
        ] {
            let mut owned = after.clone();
            writeln!(
                owned
                    .get_mut("scutil-keys")
                    .ok_or("missing fixture keys")?
                    .stdout,
                "subKey [2] = {key}"
            )?;
            assert_ne!(
                state_changes(&before, &owned, &["State:/journaled".into()], &[]).violations,
                baseline
            );
        }
        after
            .get_mut("scutil-keys")
            .ok_or("missing fixture keys")?
            .stdout = "subKey [0] = State:/Network/NetBIOS\n".into();
        assert_ne!(
            state_changes(&before, &after, &[], &[]).violations,
            baseline
        );
        Ok(())
    }

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
    fn pf_status_and_anchor_evidence_reject_unqualified_or_extra_stderr() {
        for build in crate::decode::pftext::BUILDS {
            let mut os = observation();
            os.stdout = build.into();
            let mut info = observation();
            info.stdout = include_str!(
                "../../../scupper-core/tests/fixtures/mac/pf-info-disabled-24H232.txt"
            )
            .into();
            let mut observations = BTreeMap::from([
                ("osversion".into(), os),
                ("pf-info".into(), info),
                ("pf-anchors".into(), observation()),
            ]);
            for name in ["pf-info", "pf-anchors"] {
                observations.get_mut(name).expect("fixture").stderr =
                    String::from_utf8_lossy(crate::decode::pftext::ALTQ_PREAMBLE).into_owned();
            }
            assert_eq!(pf_status(&observations), Some(false));
            assert!(super::super::guard::pf_read_complete(
                &observations,
                "pf-anchors"
            ));
            observations.get_mut("osversion").expect("fixture").stdout = "unsupported".into();
            assert_eq!(pf_status(&observations), None);
            assert!(!super::super::guard::pf_read_complete(
                &observations,
                "pf-anchors"
            ));
            observations.get_mut("osversion").expect("fixture").stdout = build.into();
            for name in ["pf-info", "pf-anchors"] {
                observations
                    .get_mut(name)
                    .expect("fixture")
                    .stderr
                    .push_str("unexpected\n");
            }
            assert_eq!(pf_status(&observations), None);
            assert!(!super::super::guard::pf_read_complete(
                &observations,
                "pf-anchors"
            ));
        }
    }
    #[test]
    fn restore_requires_complete_equal_configuration_and_ignores_route_counters() {
        let mut before: BTreeMap<_, _> = REQUIRED
            .into_iter()
            .map(|name| (name.into(), observation()))
            .collect();
        before.insert(
            "osversion".into(),
            Evidence {
                stdout: "24H232".into(),
                ..observation()
            },
        );
        if let Some(e) = before.get_mut("pf-info") {
            e.stdout = "Status: Disabled for 0 days 00:00:01 Debug: Urgent".into();
        }
        if let Some(e) = before.get_mut("scutil-keys") {
            e.stdout = "subKey [0] = State:/one\nsubKey [1] = State:/two\n".into();
        }
        if let Some(e) = before.get_mut("routes") {
            e.stdout = "Destination Gateway Flags Refs Use Netif Expire\ndefault 192.0.2.1 UGSc 4 100 en0 50\n".into();
        }
        let mut after = before.clone();
        if let Some(e) = after.get_mut("pf-info") {
            e.stdout = "Status: Disabled for 0 days 00:00:02 Debug: Urgent".into();
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
    fn route_cache_expiry_and_aging_are_ignored_but_network_changes_are_detected() {
        let header = "Destination Gateway Flags Netif Expire\n";
        let arp = "192.168.64.1 12:34:56:78:9a:bc UHLWIir en0 1192\n";
        let aged_arp = "192.168.64.1 12:34:56:78:9a:bc UHLWIir en0 1169\n";
        let mdns = "224.0.0.251 1:0:5e:0:0:fb UHmLWI en0\n";
        let route = "default 192.168.64.1 UGSc en0 1192\n";
        assert_eq!(
            normalized("routes", &format!("{header}{arp}{mdns}{route}")),
            normalized("routes", &format!("{header}{aged_arp}{route}"))
        );
        assert_eq!(
            normalized("routes", &format!("{header}{route}")),
            normalized(
                "routes",
                &format!("{header}{}", route.replace("1192", "1169"))
            )
        );
        for extra in [
            "192.0.2/24 192.168.64.1 UGS en0",
            "192.0.2.1 192.168.64.1 UHW en0",
            "192.0.2.1 192.168.64.1 UHLW en0",
            "192.0.2/24 link#20 US utun7",
            "192.0.2.1 link#20 UHLW utun7",
            "192.0.2.1 link#21 UHLW scupper0",
            "2001:db8::/64 fe80::1%en0 UGS en0",
        ] {
            let baseline = format!("{header}{route}");
            let added = format!("{baseline}{extra}\n");
            assert_ne!(
                normalized("routes", &baseline),
                normalized("routes", &added),
                "{extra}"
            );
            let changed = added.replace("192.168.64.1", "192.168.64.2");
            assert_ne!(normalized("routes", &added), normalized("routes", &changed));
        }
        assert_eq!(
            normalized("routes", &format!("{header}192.0.2.1 link#4 UHW en0\n")),
            normalized("routes", header)
        );
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
