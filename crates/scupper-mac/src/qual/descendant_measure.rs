//! Disposable descendant fixture names and observational path-length probes.
use super::{Evidence, contract_check::with_cleanup, desc_inventory::ROOT};
use serde_json::{Value, json};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const FIXTURE_PATH_BOUND: usize = 48;
pub(super) const LENGTHS: [usize; 5] = [62, 63, 64, 65, 66];
const SAMPLE_MARGIN: Duration = Duration::from_secs(30);
const RULE: &str = "pass quick on lo0 all no state\n";

/// A fixed-width run token plus a shared hex counter keeps names short.
pub(super) struct FixtureNames {
    token: String,
    next: u32,
}
impl FixtureNames {
    pub fn new() -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        Self::from_run(nanos, std::process::id())
    }
    fn from_run(nanos: u128, pid: u32) -> Self {
        let mut value =
            u32::try_from((nanos ^ (u128::from(pid) << 32)) % 36_u128.pow(4)).unwrap_or_default();
        let mut token = ['0'; 4];
        for digit in token.iter_mut().rev() {
            *digit = char::from_digit(value % 36, 36).unwrap_or('0');
            value /= 36;
        }
        Self {
            token: token.iter().collect(),
            next: 0,
        }
    }
}

pub(super) fn fixture_parent(
    next: &mut FixtureNames,
    suffix_len: usize,
) -> Result<String, &'static str> {
    let parent = format!("{ROOT}/f{}{:x}", next.token, next.next);
    let target_length = parent
        .len()
        .checked_add(suffix_len)
        .ok_or("path length overflow")?;
    if target_length > FIXTURE_PATH_BOUND {
        return Err("descendant fixture exceeds path length bound");
    }
    next.next = next
        .next
        .checked_add(1)
        .ok_or("fixture counter exhausted")?;
    Ok(parent)
}

pub(super) struct LengthFixture {
    pub parent: String,
    pub target: String,
    pub child: Option<String>,
    pub length: usize,
}

pub(super) fn length_fixture(
    next: &mut FixtureNames,
    length: usize,
    nested: bool,
) -> Result<LengthFixture, &'static str> {
    let parent = fixture_parent(next, 0)?;
    let prefix = if nested {
        format!("{parent}/")
    } else {
        parent.clone()
    };
    let padding = length
        .checked_sub(prefix.len())
        .filter(|n| *n > 0)
        .ok_or("path-length sample too short")?;
    let target = format!("{prefix}{}", "x".repeat(padding));
    Ok(LengthFixture {
        parent: if nested { parent } else { target.clone() },
        child: nested.then(|| "x".repeat(padding)),
        target,
        length,
    })
}

pub(super) trait LengthIo {
    type Error;
    fn remaining(&self) -> Duration;
    fn fresh(&mut self, fixture: &LengthFixture) -> Result<(), Self::Error>;
    fn journal(&mut self, path: &str) -> Result<(), Self::Error>;
    fn load(&mut self, path: &str, source: &str) -> Result<Evidence, Self::Error>;
    fn cleanup(&mut self, fixture: &LengthFixture) -> Result<(), Self::Error>;
}

fn sample_budget(io: &impl LengthIo) -> bool {
    io.remaining() >= SAMPLE_MARGIN
}

pub(super) struct LengthOutcome<E> {
    pub observation: Result<Value, E>,
    pub cleanup: Result<(), E>,
}

/// Nonzero exits are retained as measurements, including unknown diagnostics.
/// Journaling precedes every load; cleanup runs even after capture errors/panics.
pub(super) fn length_sample<I: LengthIo>(
    io: &mut I,
    fixture: &LengthFixture,
) -> Result<Option<LengthOutcome<I::Error>>, I::Error> {
    if !sample_budget(io) {
        return Ok(None);
    }
    io.fresh(fixture)?;
    // Freshness reads consume budget too; stop before creating journal entries.
    if !sample_budget(io) {
        return Ok(None);
    }
    io.journal(&fixture.parent)?;
    if fixture.parent != fixture.target {
        io.journal(&fixture.target)?;
    }
    let (observation, cleanup) = with_cleanup(
        io,
        |io| {
            let setup_source = fixture
                .child
                .as_ref()
                .map(|child| format!("anchor \"{child}\"\n"));
            let setup = setup_source
                .as_ref()
                .map(|source| io.load(&fixture.parent, source))
                .transpose()?;
            // Attempt the child even when the parent call was rejected: both rows matter.
            let load = io.load(&fixture.target, RULE)?;
            let captured =
                |call: &Evidence| call.exit_code.is_some() && !call.timed_out && !call.truncated;
            let capture_complete = captured(&load) && setup.as_ref().is_none_or(captured);
            Ok(
                json!({"parent":fixture.parent,"target":fixture.target,"length":fixture.length,
            "nested":fixture.child.is_some(),"source":RULE,"setup_source":setup_source,
            "setup":setup,"load":load,"capture_complete":capture_complete,"measurement_only":true}),
            )
        },
        |io| io.cleanup(fixture),
    );
    Ok(Some(LengthOutcome {
        observation,
        cleanup,
    }))
}

/// Validate one complete set of class reads without recursively visiting names.
pub(super) fn sample_classes_absent(
    build: &crate::decode::pftext::Build,
    path: &str,
    calls: &[Evidence],
    own_child: Option<&str>,
) -> Result<bool, String> {
    use crate::decode::pftext::ALTQ_PREAMBLE;
    if !matches!(build.as_str(), "24H232" | "25G332") {
        return Err("sample class rows unreviewed for build".into());
    }
    if calls.len() != 5 || calls.iter().any(|call| !call.complete()) {
        return Err("sample class capture incomplete".into());
    }
    let mut missing_count = 0;
    for (call, flag) in calls.iter().zip(["-sr", "-sn", "-sT", "-sA", "-sd"]) {
        // Darwin retains committed empty children after both paths are flushed.
        let own_child_listing = flag == "-sA"
            && own_child.is_some_and(|child| call.stdout == format!("  {child}\n"))
            && call.stderr.as_bytes() == ALTQ_PREAMBLE;
        if (!call.stdout.is_empty() && !own_child_listing)
            || call.command.last().map(String::as_str) != Some(flag)
        {
            return Err(format!(
                "{path}: sample {flag} row is not empty or mismatched"
            ));
        }
        let diagnostic = call
            .stderr
            .as_bytes()
            .strip_prefix(ALTQ_PREAMBLE)
            .ok_or_else(|| format!("{path}: sample {flag} ALTQ preamble unpinned"))?;
        // Pass-4 captures, CI 45478867692: identical rows on both reviewed builds.
        let missing = match flag {
            "-sr" | "-sn" | "-sd" => "pfctl: DIOCGETRULES: Invalid argument\n".to_owned(),
            "-sT" => "pfctl: Anchor or Ruleset does not exist.\n".to_owned(),
            "-sA" => format!("Anchor '{path}' not found.\n"),
            _ => unreachable!(),
        };
        if diagnostic == missing.as_bytes() {
            missing_count += 1;
        } else if !diagnostic.is_empty() {
            return Err(format!(
                "{path}: sample {flag} missing/empty diagnostic unpinned"
            ));
        }
    }
    if missing_count > 0 && missing_count < calls.len() {
        return Err(format!(
            "{path}: sample class reads mix missing and present-empty rows"
        ));
    }
    Ok(missing_count != 0)
}

/// Cleanup never enumerates the shared tree. Each exact path gets one class read,
/// even after a census/flush failure; the whole-tree check belongs to Q-RESTORE.
pub(super) trait SampleCleanupIo {
    fn present(&mut self, path: &str) -> Result<bool, String>;
    fn flush(&mut self, path: &str, class: &str) -> Result<(), String>;
    fn read_absent(&mut self, path: &str, own_child: Option<&str>) -> Result<(), String>;
}
pub(super) fn cleanup_sample(
    io: &mut impl SampleCleanupIo,
    fixture: &LengthFixture,
) -> Result<(), String> {
    let mut failures = Vec::new();
    let mut paths = vec![fixture.target.as_str()];
    if fixture.parent != fixture.target {
        paths.push(&fixture.parent);
    }
    for path in paths {
        match io.present(path) {
            Ok(true) => {
                for class in ["rules", "nat", "Tables", "dummynet"] {
                    if let Err(error) = io.flush(path, class) {
                        failures.push(error);
                    }
                }
            }
            Ok(false) => (),
            Err(error) => failures.push(error),
        }
        let own_child =
            (path == fixture.parent && path != fixture.target).then_some(fixture.target.as_str());
        if let Err(error) = io.read_absent(path, own_child) {
            failures.push(error);
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; "))
    }
}

/// Describe sampled outcomes without claiming a universal kernel limit.
pub(super) fn length_detail(rows: &[Value]) -> String {
    let mut details = Vec::new();
    for nested in [false, true] {
        let mut successful = Vec::new();
        let mut failed = Vec::new();
        let mut incomplete = Vec::new();
        for row in rows.iter().filter(|row| row["nested"] == nested) {
            let mut calls = vec![&row["load"]];
            if nested {
                calls.push(&row["setup"]);
            }
            let calls = calls
                .into_iter()
                .map(|call| serde_json::from_value::<Evidence>(call.clone()))
                .collect::<Result<Vec<_>, _>>();
            let length = row["length"].as_u64().unwrap_or_default();
            match calls {
                Ok(calls) if calls.iter().all(Evidence::complete) => successful.push(length),
                Ok(calls)
                    if calls.iter().all(|call| {
                        call.exit_code.is_some() && !call.timed_out && !call.truncated
                    }) =>
                {
                    failed.push(length);
                }
                _ => incomplete.push(length),
            }
        }
        let mode = if nested {
            "nested setup/load"
        } else {
            "direct"
        };
        details.push(format!("{mode}: max successful={:?}, successful={successful:?}, failed={failed:?}, incomplete={incomplete:?}", successful.iter().max()));
    }
    format!(
        "path-length observed limit (sampled lengths only): {}",
        details.join("; ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn response(path: &str, source: &str, rc: i32) -> Evidence {
        serde_json::from_value(
            json!({"command":["/sbin/pfctl","-o","none","-a",path,"-f","-"],
            "stdin":source,"pid":1,"exit_code":rc,"started_unix_ms":0,"elapsed_ms":0,
            "timed_out":false,"truncated":false,"stdout":"captured stdout",
            "stderr":if rc == 0 { "" } else { "unknown refusal\n" }}),
        )
        .unwrap()
    }

    #[derive(Default)]
    #[allow(clippy::struct_excessive_bools)] // Independent capture, cleanup and freshness fault controls.
    struct FakePfctl {
        events: Vec<String>,
        remaining: Option<Duration>,
        preexisting: bool,
        exhaust_on_fresh: bool,
        rc: i32,
        capture_error: bool,
        truncated: bool,
        cleanup_error: bool,
    }
    impl LengthIo for FakePfctl {
        type Error = &'static str;
        fn remaining(&self) -> Duration {
            self.remaining.unwrap_or(Duration::from_secs(180))
        }
        fn fresh(&mut self, fixture: &LengthFixture) -> Result<(), Self::Error> {
            self.events.push(format!("fresh:{}", fixture.target));
            if self.preexisting {
                return Err("target already exists");
            }
            if self.exhaust_on_fresh {
                self.remaining = Some(Duration::from_secs(29));
            }
            Ok(())
        }
        fn journal(&mut self, path: &str) -> Result<(), Self::Error> {
            self.events.push(format!("journal:{path}"));
            Ok(())
        }
        fn load(&mut self, path: &str, source: &str) -> Result<Evidence, Self::Error> {
            self.events.push(format!("load:{path}:{source}"));
            if self.capture_error {
                Err("capture error")
            } else {
                let mut result = response(path, source, self.rc);
                result.truncated = self.truncated;
                Ok(result)
            }
        }
        fn cleanup(&mut self, fixture: &LengthFixture) -> Result<(), Self::Error> {
            self.events.push(format!("cleanup:{}", fixture.parent));
            if self.cleanup_error {
                Err("cleanup error")
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn short_fixture_parents_are_bounded_and_unique() {
        let mut next = FixtureNames::from_run(0, 0);
        let mut seen = BTreeSet::new();
        for _ in 0..4096 {
            let parent = fixture_parent(&mut next, "/empty/grandchild".len()).unwrap();
            assert!(parent.len() + "/empty/grandchild".len() <= FIXTURE_PATH_BOUND);
            assert!(seen.insert(parent));
        }
        let before = next.next;
        assert!(fixture_parent(&mut next, FIXTURE_PATH_BOUND).is_err());
        assert_eq!(next.next, before);
        assert!(fixture_parent(&mut next, usize::MAX).is_err());
        let mut exhausted = FixtureNames {
            token: "0000".into(),
            next: u32::MAX,
        };
        assert!(fixture_parent(&mut exhausted, 0).is_err());
    }

    #[test]
    fn path_length_samples_journal_load_capture_and_clean_every_variant() {
        let mut next = FixtureNames::from_run(0, 0);
        let mut seen = BTreeSet::new();
        let mut rows = Vec::new();
        for nested in [false, true] {
            for length in LENGTHS {
                let fixture = length_fixture(&mut next, length, nested).unwrap();
                assert_eq!(fixture.target.len(), length);
                assert!(fixture.target.starts_with(&format!("{ROOT}/")));
                assert!(seen.insert(fixture.target.clone()));
                let mut io = FakePfctl {
                    rc: i32::from(length >= 64),
                    ..FakePfctl::default()
                };
                let result = length_sample(&mut io, &fixture).unwrap().unwrap();
                assert_eq!(result.cleanup, Ok(()));
                let row = result.observation.unwrap();
                assert_eq!(row["load"]["exit_code"], io.rc);
                assert_eq!(row["load"]["stdout"], "captured stdout");
                assert_eq!(row["load"]["stdin"], RULE);
                assert_eq!(row["measurement_only"], true);
                assert_eq!(
                    super::super::desc_inventory::findings(&row),
                    Vec::<String>::new()
                );
                assert_eq!(row["capture_complete"], true);
                let mut expected = vec![
                    format!("fresh:{}", fixture.target),
                    format!("journal:{}", fixture.parent),
                ];
                if nested {
                    expected.push(format!("journal:{}", fixture.target));
                    let source = format!("anchor \"{}\"\n", fixture.child.as_ref().unwrap());
                    expected.push(format!("load:{}:{source}", fixture.parent));
                    assert_eq!(row["setup_source"], source);
                    assert_eq!(row["setup"]["exit_code"], io.rc);
                } else {
                    assert!(row["setup"].is_null());
                }
                expected.push(format!("load:{}:{RULE}", fixture.target));
                expected.push(format!("cleanup:{}", fixture.parent));
                assert_eq!(io.events, expected);
                if io.rc != 0 {
                    assert_eq!(row["load"]["stderr"], "unknown refusal\n");
                }
                rows.push(row);
            }
        }
        assert_eq!(rows.len(), 10);
        let detail = length_detail(&rows);
        assert_eq!(detail.matches("max successful=Some(63)").count(), 2);
        assert_eq!(detail.matches("failed=[64, 65, 66]").count(), 2);
        rows[0]["load"]["truncated"] = json!(true);
        assert!(length_detail(&rows).contains("incomplete=[62]"));
    }

    #[test]
    fn path_length_truncated_stream_is_incomplete_without_a_violation() {
        let fixture = length_fixture(&mut FixtureNames::from_run(0, 0), 66, false).unwrap();
        let mut io = FakePfctl {
            truncated: true,
            ..FakePfctl::default()
        };
        let result = length_sample(&mut io, &fixture).unwrap().unwrap();
        assert_eq!(result.cleanup, Ok(()));
        let row = result.observation.unwrap();
        assert_eq!(row["capture_complete"], false);
        assert!(length_detail(std::slice::from_ref(&row)).contains("incomplete=[66]"));
        assert_eq!(
            super::super::desc_inventory::findings(&row),
            Vec::<String>::new()
        );
    }

    #[test]
    fn path_length_capture_and_cleanup_errors_remain_explicit() {
        let fixture = length_fixture(&mut FixtureNames::from_run(0, 0), 64, true).unwrap();
        let mut io = FakePfctl {
            capture_error: true,
            cleanup_error: true,
            ..FakePfctl::default()
        };
        let result = length_sample(&mut io, &fixture).unwrap().unwrap();
        assert_eq!(result.observation, Err("capture error"));
        assert_eq!(result.cleanup, Err("cleanup error"));
        assert_eq!(
            io.events.last(),
            Some(&format!("cleanup:{}", fixture.parent))
        );
    }
    #[test]
    fn run_tokens_change_short_names_without_changing_the_bound() {
        let mut first = FixtureNames::from_run(100, 1);
        let mut later = FixtureNames::from_run(101, 1);
        let mut other_pid = FixtureNames::from_run(100, 2);
        let names =
            [&mut first, &mut later, &mut other_pid].map(|run| fixture_parent(run, 16).unwrap());
        assert_eq!(names.iter().collect::<BTreeSet<_>>().len(), 3);
        assert!(
            names
                .iter()
                .all(|name| name.len() + 16 <= FIXTURE_PATH_BOUND)
        );
        assert!(
            names
                .iter()
                .all(|name| name.rsplit('/').next().unwrap().len() == 6)
        );
        // Exercise the runtime source too; collision checks remain authoritative.
        let mut runtime = FixtureNames::new();
        assert!(fixture_parent(&mut runtime, 16).is_ok());
    }

    #[test]
    fn sample_budget_stops_before_any_journal_load_or_cleanup() {
        for nested in [false, true] {
            let fixture = length_fixture(&mut FixtureNames::from_run(0, 0), 64, nested).unwrap();
            for remaining in [
                Duration::ZERO,
                Duration::from_secs(29),
                Duration::from_millis(29_999),
            ] {
                let mut io = FakePfctl {
                    remaining: Some(remaining),
                    ..FakePfctl::default()
                };
                assert!(length_sample(&mut io, &fixture).unwrap().is_none());
                assert_eq!(io.events, Vec::<String>::new());
            }
            let mut io = FakePfctl {
                exhaust_on_fresh: true,
                ..FakePfctl::default()
            };
            assert!(length_sample(&mut io, &fixture).unwrap().is_none());
            assert_eq!(io.events, vec![format!("fresh:{}", fixture.target)]);
            let mut io = FakePfctl {
                remaining: Some(Duration::from_secs(30)),
                ..FakePfctl::default()
            };
            assert!(length_sample(&mut io, &fixture).unwrap().is_some());
        }
    }

    #[test]
    fn preexisting_length_sample_is_skipped_without_mutation() {
        for nested in [false, true] {
            let fixture = length_fixture(&mut FixtureNames::from_run(0, 0), 62, nested).unwrap();
            let mut io = FakePfctl {
                preexisting: true,
                ..FakePfctl::default()
            };
            assert!(length_sample(&mut io, &fixture).is_err());
            assert_eq!(io.events, vec![format!("fresh:{}", fixture.target)]);
        }
    }

    #[derive(Default)]
    struct CleanupCounter {
        reads: Vec<String>,
        flushes: Vec<String>,
        missing: bool,
        fail: bool,
    }
    impl SampleCleanupIo for CleanupCounter {
        fn present(&mut self, _: &str) -> Result<bool, String> {
            Ok(!self.missing)
        }
        fn flush(&mut self, path: &str, class: &str) -> Result<(), String> {
            self.flushes.push(format!("{path}:{class}"));
            if self.fail {
                Err("flush failed".into())
            } else {
                Ok(())
            }
        }
        fn read_absent(&mut self, path: &str, _: Option<&str>) -> Result<(), String> {
            self.reads.push(path.into());
            if self.fail {
                Err("read incomplete".into())
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn sample_cleanup_reads_only_its_own_paths_once() {
        for nested in [false, true] {
            for (missing, fail) in [(false, false), (true, false), (false, true)] {
                let fixture =
                    length_fixture(&mut FixtureNames::from_run(0, 0), 64, nested).unwrap();
                let mut io = CleanupCounter {
                    missing,
                    fail,
                    ..CleanupCounter::default()
                };
                assert_eq!(cleanup_sample(&mut io, &fixture).is_err(), fail);
                assert!(io.reads.iter().all(|path| path != ROOT));
                let mut expected = vec![fixture.target.clone()];
                if nested {
                    expected.push(fixture.parent.clone());
                }
                assert_eq!(io.reads, expected);
                assert_eq!(
                    io.flushes.len(),
                    if missing { 0 } else { expected.len() * 4 }
                );
            }
        }
    }

    // Exact pass-4 stderr bytes, independent of the classifier's row table.
    fn sample_reads(path: &str, missing: bool) -> Vec<Evidence> {
        [
            ("-sr", "pfctl: DIOCGETRULES: Invalid argument\n".to_owned()),
            ("-sn", "pfctl: DIOCGETRULES: Invalid argument\n".to_owned()),
            (
                "-sT",
                "pfctl: Anchor or Ruleset does not exist.\n".to_owned(),
            ),
            ("-sA", format!("Anchor '{path}' not found.\n")),
            ("-sd", "pfctl: DIOCGETRULES: Invalid argument\n".to_owned()),
        ]
        .into_iter()
        .map(|(flag, diagnostic)| {
            let mut call = response(path, "", 0);
            call.command = ["/sbin/pfctl", "-a", path, flag]
                .map(str::to_owned)
                .to_vec();
            call.stdout.clear();
            call.stderr = "No ALTQ support in kernel\nALTQ related functions disabled\n".into();
            if missing {
                call.stderr.push_str(&diagnostic);
            }
            call
        })
        .collect()
    }

    const PASS4_PARENT: &str = "scupper-qual/children/named-1795552631-8252-3366";
    const PASS4_CHILD: &str = "scupper-qual/children/named-1795552631-8252-3366/qchild";

    fn pass4_parent_reads() -> Vec<Evidence> {
        // children-classes-…-3441, CI 45478867692, identical on both builds.
        let mut calls = sample_reads(PASS4_PARENT, false);
        calls[3].stdout = "  scupper-qual/children/named-1795552631-8252-3366/qchild\n".into();
        calls
    }

    #[test]
    fn sample_classes_accept_exact_pass4_own_child_only_during_cleanup() {
        for name in ["24H232", "25G332"] {
            let build = crate::decode::pftext::Build::fixture(name);
            let calls = pass4_parent_reads();
            assert_eq!(
                sample_classes_absent(&build, PASS4_PARENT, &calls, Some(PASS4_CHILD)),
                Ok(false)
            );
            assert!(sample_classes_absent(&build, PASS4_PARENT, &calls, None).is_err());
            for missing in [false, true] {
                assert_eq!(
                    sample_classes_absent(
                        &build,
                        PASS4_PARENT,
                        &sample_reads(PASS4_PARENT, missing),
                        Some(PASS4_CHILD),
                    ),
                    Ok(missing)
                );
            }
            for index in 0..5 {
                let mut bad = calls.clone();
                bad[index].stderr.push_str("unknown diagnostic\n");
                assert!(
                    sample_classes_absent(&build, PASS4_PARENT, &bad, Some(PASS4_CHILD)).is_err()
                );
                let mut bad = calls.clone();
                bad[index].stdout = calls[3].stdout.clone();
                if index != 3 {
                    assert!(
                        sample_classes_absent(&build, PASS4_PARENT, &bad, Some(PASS4_CHILD))
                            .is_err()
                    );
                }
            }
            let mut missing_with_listing = sample_reads(PASS4_PARENT, true);
            missing_with_listing[3].stdout.clone_from(&calls[3].stdout);
            assert!(
                sample_classes_absent(
                    &build,
                    PASS4_PARENT,
                    &missing_with_listing,
                    Some(PASS4_CHILD),
                )
                .is_err()
            );
        }
    }

    #[test]
    fn sample_classes_reject_different_or_extra_child() {
        for name in ["24H232", "25G332"] {
            let build = crate::decode::pftext::Build::fixture(name);
            for stdout in [
                "  scupper-qual/children/named-1795552631-8252-3366/other\n".to_owned(),
                format!("  {PASS4_CHILD}\n  {PASS4_PARENT}/other\n"),
                format!("  {PASS4_CHILD}\n  {PASS4_CHILD}\n"),
                "  qchild\n".to_owned(),
                format!(" {PASS4_CHILD}\n"),
                format!("  {PASS4_CHILD}"),
                "arbitrary stdout\n".to_owned(),
            ] {
                let mut calls = pass4_parent_reads();
                calls[3].stdout = stdout;
                assert!(
                    sample_classes_absent(&build, PASS4_PARENT, &calls, Some(PASS4_CHILD)).is_err(),
                    "assertion failed: nested cleanup accepted a different or extra child"
                );
            }
            assert!(
                sample_classes_absent(
                    &build,
                    PASS4_PARENT,
                    &pass4_parent_reads(),
                    Some("scupper-qual/children/named-1795552631-8252-3366/other"),
                )
                .is_err(),
                "assertion failed: nested cleanup accepted another sample's child"
            );
        }
    }

    struct NestedCleanup {
        build: crate::decode::pftext::Build,
        events: Vec<String>,
        child_missing: bool,
    }

    impl SampleCleanupIo for NestedCleanup {
        fn present(&mut self, path: &str) -> Result<bool, String> {
            self.events.push(format!("present:{path}"));
            // The census precedes flushing; the child can disappear afterward.
            Ok(true)
        }
        fn flush(&mut self, path: &str, class: &str) -> Result<(), String> {
            self.events.push(format!("flush:{path}:{class}"));
            Ok(())
        }
        fn read_absent(&mut self, path: &str, own_child: Option<&str>) -> Result<(), String> {
            self.events.push(format!("read:{path}"));
            let calls = if path == PASS4_PARENT {
                assert_eq!(own_child, Some(PASS4_CHILD));
                pass4_parent_reads()
            } else {
                assert_eq!(path, PASS4_CHILD);
                assert_eq!(own_child, None);
                sample_reads(path, self.child_missing)
            };
            sample_classes_absent(&self.build, path, &calls, own_child).map(|_| ())
        }
    }

    #[test]
    fn nested_cleanup_flushes_both_paths_and_accepts_own_emptied_child() {
        let fixture = LengthFixture {
            parent: PASS4_PARENT.into(),
            target: PASS4_CHILD.into(),
            child: Some("qchild".into()),
            length: PASS4_CHILD.len(),
        };
        for name in ["24H232", "25G332"] {
            for child_missing in [false, true] {
                let mut io = NestedCleanup {
                    build: crate::decode::pftext::Build::fixture(name),
                    events: Vec::new(),
                    child_missing,
                };
                assert_eq!(cleanup_sample(&mut io, &fixture), Ok(()));
                let mut expected = Vec::new();
                for path in [PASS4_CHILD, PASS4_PARENT] {
                    expected.push(format!("present:{path}"));
                    for class in ["rules", "nat", "Tables", "dummynet"] {
                        expected.push(format!("flush:{path}:{class}"));
                    }
                    expected.push(format!("read:{path}"));
                }
                assert_eq!(io.events, expected);
            }
        }
    }

    #[test]
    fn sample_class_absence_needs_every_complete_class_and_exact_inventory() {
        let path = "scupper-qual/children/f00000";
        for name in ["24H232", "25G332"] {
            let build = crate::decode::pftext::Build::fixture(name);
            let missing = sample_reads(path, true);
            let empty = sample_reads(path, false);
            assert_eq!(
                sample_classes_absent(&build, path, &missing, None),
                Ok(true)
            );
            assert_eq!(sample_classes_absent(&build, path, &empty, None), Ok(false));
            for index in 0..5 {
                for rows in [&missing, &empty] {
                    for fault in 0..9 {
                        let mut bad = rows.clone();
                        match fault {
                            0 => bad[index].truncated = true,
                            1 => bad[index].timed_out = true,
                            2 => bad[index].exit_code = Some(1),
                            3 => bad[index].exit_code = None,
                            4 => bad[index].stdout = "unexpected configuration\n".into(),
                            5 => bad[index].stderr.push_str("unknown diagnostic\n"),
                            6 => {
                                bad[index].stderr.pop();
                            }
                            7 => {
                                bad[index].stderr = bad[index].stderr.replacen(
                                    "No ALTQ support in kernel\n",
                                    "",
                                    1,
                                );
                            }
                            _ => {
                                bad[index].command.pop();
                            }
                        }
                        assert!(sample_classes_absent(&build, path, &bad, None).is_err());
                    }
                }
            }
            assert!(sample_classes_absent(&build, path, &missing[..4], None).is_err());
            assert!(sample_classes_absent(&build, "other", &missing, None).is_err());
            for rows in [missing, empty] {
                assert!(
                    sample_classes_absent(
                        &crate::decode::pftext::Build::fixture("unknown"),
                        path,
                        &rows,
                        None,
                    )
                    .is_err()
                );
            }
        }
    }

    #[test]
    fn sample_classes_reject_altq_only_tables_among_missing_rows() {
        let path = "scupper-qual/children/f00000";
        for name in ["24H232", "25G332"] {
            let build = crate::decode::pftext::Build::fixture(name);
            let mut calls = sample_reads(path, true);
            calls[2] = sample_reads(path, false).remove(2);
            assert!(sample_classes_absent(&build, path, &calls, None).is_err());
        }
    }

    #[test]
    fn sample_classes_reject_every_mixed_missing_and_empty_set() {
        let path = "scupper-qual/children/f00000";
        for name in ["24H232", "25G332"] {
            let build = crate::decode::pftext::Build::fixture(name);
            let missing = sample_reads(path, true);
            let empty = sample_reads(path, false);
            for mask in 1..31 {
                let calls = (0..5)
                    .map(|index| {
                        if mask & (1 << index) != 0 {
                            missing[index].clone()
                        } else {
                            empty[index].clone()
                        }
                    })
                    .collect::<Vec<_>>();
                assert!(sample_classes_absent(&build, path, &calls, None).is_err());
            }
        }
    }

    struct RefusedSample {
        build: crate::decode::pftext::Build,
        events: Vec<String>,
    }
    impl LengthIo for RefusedSample {
        type Error = String;
        fn remaining(&self) -> Duration {
            Duration::from_secs(180)
        }
        fn fresh(&mut self, fixture: &LengthFixture) -> Result<(), String> {
            self.events.push("fresh".into());
            let absent = sample_classes_absent(
                &self.build,
                &fixture.target,
                &sample_reads(&fixture.target, true),
                None,
            )?;
            if absent {
                Ok(())
            } else {
                Err("path already exists".into())
            }
        }
        fn journal(&mut self, _: &str) -> Result<(), String> {
            self.events.push("journal".into());
            Ok(())
        }
        fn load(&mut self, path: &str, source: &str) -> Result<Evidence, String> {
            self.events.push("load refused".into());
            Ok(response(path, source, 1))
        }
        fn cleanup(&mut self, fixture: &LengthFixture) -> Result<(), String> {
            cleanup_sample(self, fixture)
        }
    }
    impl SampleCleanupIo for RefusedSample {
        fn present(&mut self, _: &str) -> Result<bool, String> {
            self.events.push("kernel absent".into());
            Ok(false)
        }
        fn flush(&mut self, _: &str, _: &str) -> Result<(), String> {
            self.events.push("flush".into());
            Ok(())
        }
        fn read_absent(&mut self, path: &str, own_child: Option<&str>) -> Result<(), String> {
            self.events.push("read classes".into());
            sample_classes_absent(&self.build, path, &sample_reads(path, true), own_child)
                .map(|_| ())
        }
    }

    #[test]
    fn refused_direct_load_on_fresh_missing_path_cleans_without_flush() {
        for name in ["24H232", "25G332"] {
            let fixture = length_fixture(&mut FixtureNames::from_run(0, 0), 64, false).unwrap();
            let mut io = RefusedSample {
                build: crate::decode::pftext::Build::fixture(name),
                events: Vec::new(),
            };
            let result = length_sample(&mut io, &fixture).unwrap().unwrap();
            assert_eq!(result.observation.unwrap()["load"]["exit_code"], 1);
            assert_eq!(result.cleanup, Ok(()));
            assert_eq!(
                io.events,
                [
                    "fresh",
                    "journal",
                    "load refused",
                    "kernel absent",
                    "read classes"
                ]
            );
        }
    }
}
