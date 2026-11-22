use serde::{Deserialize, Serialize};

pub(super) const MAX_ARM_SECONDS: u64 = 18 * 60;

/// The portable part of the accident guard. Inputs are observations, not trusted
/// authentication: a local administrator can spoof them.
pub(super) fn check_environment(
    github_actions: &str,
    runner_environment: &str,
    root: bool,
    disposable: bool,
) -> Result<(), &'static str> {
    if github_actions != "true" || runner_environment != "github-hosted" || !root || !disposable {
        return Err(
            "requires GITHUB_ACTIONS=true, RUNNER_ENVIRONMENT=github-hosted, euid 0 and --disposable-runner (accident guard, not a security property)",
        );
    }
    Ok(())
}

#[derive(Debug, Deserialize, Serialize)]
pub(super) struct Ack {
    pub pid: u32,
    pub start: String,
    pub pgid: u32,
    pub ppid: u32,
    pub armed_at: u64,
    pub fire_at: u64,
    pub boot_session: String,
    pub armed_monotonic: u64,
    pub fire_monotonic: u64,
}

impl Ack {
    pub fn fresh(&self, now: u64, boot_session: &str) -> bool {
        self.pid > 1
            && self.pgid == self.pid
            && self.ppid == 1
            && !self.start.is_empty()
            && self.armed_monotonic <= now
            && now < self.fire_monotonic
            && self.fire_monotonic - self.armed_monotonic <= MAX_ARM_SECONDS
            && self.boot_session == boot_session
    }
}

// A header-only or unknown response is not proof of zero references. Keep raw
// evidence so a newly encountered tool format can be reviewed without rerunning.
pub(super) fn no_foreign_references(
    build: &crate::decode::pftext::Build,
    stdout: &str,
    stderr: &str,
) -> bool {
    crate::decode::pftext::references_empty(build, stdout.as_bytes(), stderr.as_bytes())
}

/// A missing or incomplete build observation cannot qualify stderr normalization.
pub(super) fn pf_build(
    observations: &std::collections::BTreeMap<String, super::Evidence>,
) -> Option<crate::decode::pftext::Build> {
    crate::decode::pftext::Build::observed(observations)
}

pub(super) fn pf_read_complete(
    observations: &std::collections::BTreeMap<String, super::Evidence>,
    name: &str,
) -> bool {
    observations.get(name).is_some_and(|e| {
        e.complete()
            && pf_build(observations).is_some_and(|build| {
                crate::decode::pftext::read(&build, 0, e.stdout.as_bytes(), e.stderr.as_bytes())
                    .is_ok()
            })
    })
}

pub(super) fn preflight_conditions(
    observations: &std::collections::BTreeMap<String, super::Evidence>,
    binary_is_arm64: bool,
) -> Vec<String> {
    let mut inconclusive = Vec::new();
    // Optional inventory failures stay in raw evidence. Only prerequisites for
    // safe qualification gate a cell, including missing observations.
    for name in [
        "pf-references",
        "pf-anchors",
        "pf-apple-anchors",
        "translated",
        "binary-arch",
        "machine",
    ] {
        let Some(evidence) = observations.get(name) else {
            inconclusive.push(format!("{name}: observation missing"));
            continue;
        };
        // Native arm64 can omit this OID; accept only its exact unknown-OID error.
        let absent_translation_oid = name == "translated"
            && evidence.exit_code == Some(1)
            && evidence.stderr.trim() == "sysctl: unknown oid 'sysctl.proc_translated'"
            && !evidence.timed_out
            && !evidence.truncated;
        if (!evidence.complete()
            || (name.starts_with("pf-")
                && name != "pf-references"
                && !pf_read_complete(observations, name)))
            && !absent_translation_oid
        {
            inconclusive.push(format!(
                "{name}: command failed, timed out or was truncated"
            ));
        }
    }
    if observations.get("pf-references").is_none_or(|refs| {
        !pf_build(observations)
            .is_some_and(|build| no_foreign_references(&build, &refs.stdout, &refs.stderr))
    }) {
        inconclusive.push("foreign pf references present or reference text not recognized".into());
    }
    if observations
        .get("pf-anchors")
        .is_some_and(|e| e.stdout.contains("com.apple/scupper"))
        || observations.get("pf-apple-anchors").is_some_and(|e| {
            e.stdout
                .lines()
                .any(|line| line.trim().trim_matches('"') == "scupper")
        })
    {
        inconclusive.push("existing com.apple/scupper anchor".into());
    }
    match observations.get("translated") {
        Some(e) if e.stdout.trim() == "1" => inconclusive.push("sysctl.proc_translated=1".into()),
        Some(e) if e.complete() && e.stdout.trim() == "0" => {}
        Some(e)
            if e.exit_code == Some(1)
                && e.stderr.trim() == "sysctl: unknown oid 'sysctl.proc_translated'"
                && !e.timed_out
                && !e.truncated => {}
        _ => inconclusive.push("translation status not established".into()),
    }
    if !binary_is_arm64
        || observations
            .get("binary-arch")
            .is_none_or(|e| e.stdout.trim() != "arm64")
    {
        inconclusive.push("qualification binary is not native arm64".into());
    }
    if observations
        .get("machine")
        .is_none_or(|e| e.stdout.trim() != "arm64")
    {
        inconclusive.push("hw.machine is not arm64".into());
    }
    inconclusive
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observation(stdout: &str) -> super::super::Evidence {
        super::super::Evidence {
            command: Vec::new(),
            stdin: None,
            pid: None,
            exit_code: Some(0),
            started_unix_ms: 0,
            elapsed_ms: 0,
            timed_out: false,
            truncated: false,
            stdout: stdout.into(),
            stderr: String::new(),
        }
    }

    #[test]
    fn pf_build_requires_complete_nonempty_osversion() {
        let mut observations = std::collections::BTreeMap::new();
        assert!(pf_build(&observations).is_none());
        for text in ["", " \n", "24H232 extra"] {
            observations.insert("osversion".into(), observation(text));
            assert!(pf_build(&observations).is_none());
        }
        for build in crate::decode::pftext::BUILDS {
            let os = observation(&format!("{build}\n"));
            observations.insert("osversion".into(), os.clone());
            assert_eq!(
                pf_build(&observations).expect("complete build").as_str(),
                build
            );
            for failure in 0..4 {
                let mut incomplete = os.clone();
                match failure {
                    0 => incomplete.truncated = true,
                    1 => incomplete.timed_out = true,
                    2 => incomplete.exit_code = Some(1),
                    _ => incomplete.stderr = "unexpected".into(),
                }
                observations.insert("osversion".into(), incomplete);
                assert!(
                    pf_build(&observations).is_none(),
                    "assertion: incomplete osversion {failure}"
                );
            }
        }
    }

    #[test]
    fn preflight_classifies_environment_without_network_mutation() {
        let mut observations = std::collections::BTreeMap::from([
            (
                "pf-references".into(),
                observation("No pf starter references held"),
            ),
            ("osversion".into(), observation("24H232")),
            ("pf-anchors".into(), observation("com.apple")),
            ("pf-apple-anchors".into(), observation("")),
            ("translated".into(), observation("0")),
            ("binary-arch".into(), observation("arm64")),
            ("machine".into(), observation("arm64")),
        ]);
        assert_eq!(
            preflight_conditions(&observations, true),
            Vec::<String>::new()
        );
        assert_ne!(
            preflight_conditions(&observations, false),
            Vec::<String>::new()
        );
        for (key, value, reason) in [
            ("pf-references", "TOKENS: foreign", "foreign pf"),
            (
                "pf-anchors",
                "com.apple/scupper",
                "existing com.apple/scupper",
            ),
            (
                "pf-apple-anchors",
                "  scupper",
                "existing com.apple/scupper",
            ),
            ("translated", "1", "proc_translated=1"),
            ("binary-arch", "x86_64", "not native arm64"),
        ] {
            let old = observations
                .insert(key.into(), observation(value))
                .expect("fixture key");
            assert!(
                preflight_conditions(&observations, true)
                    .iter()
                    .any(|text| text.contains(reason))
            );
            observations.insert(key.into(), old);
        }
        observations
            .get_mut("translated")
            .expect("fixture key")
            .exit_code = Some(1);
        observations
            .get_mut("translated")
            .expect("fixture key")
            .stderr = "sysctl: unknown oid 'sysctl.proc_translated'".into();
        assert_eq!(
            preflight_conditions(&observations, true),
            Vec::<String>::new()
        );
        observations
            .get_mut("translated")
            .expect("fixture key")
            .stderr = "permission denied".into();
        assert_ne!(
            preflight_conditions(&observations, true),
            Vec::<String>::new()
        );
    }

    #[test]
    fn optional_observations_do_not_gate_but_missing_safety_observations_do() {
        let mut observations = std::collections::BTreeMap::from([
            (
                "pf-references".into(),
                observation("No pf starter references held"),
            ),
            ("osversion".into(), observation("24H232")),
            ("pf-anchors".into(), observation("com.apple")),
            ("pf-apple-anchors".into(), observation("")),
            ("translated".into(), observation("0")),
            ("binary-arch".into(), observation("arm64")),
            ("machine".into(), observation("arm64")),
        ]);
        for name in ["sdk", "tool-sha256", "scutil-keys"] {
            let mut failed = observation("");
            failed.timed_out = true;
            observations.insert(name.into(), failed);
        }
        assert_eq!(
            preflight_conditions(&observations, true),
            Vec::<String>::new()
        );
        observations.remove("pf-anchors");
        assert!(
            preflight_conditions(&observations, true)
                .iter()
                .any(|reason| reason.contains("pf-anchors"))
        );
    }

    #[test]
    fn guard_checks_every_condition_and_ack_cannot_cross_boots_or_expire() {
        assert!(check_environment("true", "github-hosted", true, true).is_ok());
        for values in [
            ("false", "github-hosted", true, true),
            ("true", "self-hosted", true, true),
            ("true", "github-hosted", false, true),
            ("true", "github-hosted", true, false),
        ] {
            assert!(check_environment(values.0, values.1, values.2, values.3).is_err());
        }
        let ack = Ack {
            pid: 42,
            start: "recorded start".into(),
            pgid: 42,
            ppid: 1,
            armed_at: 100,
            fire_at: 200,
            boot_session: "boot".into(),
            armed_monotonic: 100,
            fire_monotonic: 200,
        };
        assert!(ack.fresh(150, "boot"));
        assert!(!ack.fresh(99, "boot"));
        assert!(!ack.fresh(200, "boot"));
        assert!(!ack.fresh(150, "another boot"));
        // Wall-clock jumps do not change monotonic acknowledgement freshness.
        let jumped = Ack {
            armed_at: 999_999,
            fire_at: 1,
            ..ack
        };
        assert!(jumped.fresh(150, "boot"));
        let invalid = Ack {
            fire_monotonic: 100 + MAX_ARM_SECONDS + 1,
            ..jumped
        };
        assert!(!invalid.fresh(150, "boot"));
    }

    #[test]
    fn unknown_or_nonempty_references_never_establish_clean_preflight() {
        assert!(no_foreign_references(
            &crate::decode::pftext::Build::fixture("24H232"),
            "",
            "No ALTQ support in kernel\nALTQ related functions disabled\nNo pf starter references held\n"
        ));
        assert!(!no_foreign_references(
            &crate::decode::pftext::Build::fixture("24H232"),
            "TOKENS:\n",
            ""
        ));
        assert!(!no_foreign_references(
            &crate::decode::pftext::Build::fixture("24H232"),
            "TOKENS: foreign token\n",
            "No pf starter references held"
        ));
        assert!(!no_foreign_references(
            &crate::decode::pftext::Build::fixture("24H232"),
            "",
            "permission denied"
        ));
    }
}
