#!/usr/bin/env python3
"""R7 portable assertion mutants. Restores bytes even on timeout or failure."""
from pathlib import Path
import hashlib
import json
import os
import subprocess

ROOT = Path(__file__).resolve().parents[3]
ANCHOR = ROOT / "crates/scupper-mac/src/decode/pfanchor.rs"
CONTRACT = ROOT / "crates/scupper-mac/src/platform/tests.rs"
JOURNAL = ROOT / "crates/scupper-mac/src/qual/journal.rs"
DETACH = ROOT / "crates/scupper-mac/src/qual/detach.rs"
REFERENCE = ROOT / "crates/scupper-mac/src/engine/reference.rs"
CONTRACT_CHECK = ROOT / "crates/scupper-mac/src/qual/contract_check.rs"
NATIVE_CONTRACTS = ROOT / "crates/scupper-mac/src/qual/contracts.rs"
RECOVERY = ROOT / "crates/scupper-mac/src/qual/recovery.rs"
PROTOCOL = ROOT / "crates/scupper-mac/src/engine/protocol.rs"
REVIEW = ROOT / "crates/scupper-mac/qualification/goldens/24H232/review.json"
JOBS = ROOT / "crates/scupper-mac/src/qual/jobs.rs"
TRACE = ROOT / "crates/scupper-mac/src/decode/qualification_trace.rs"
RESOURCE_UNDO = ROOT / "crates/scupper-mac/src/qual/resources/undo.rs"
EVIDENCE_PATH = ROOT / "crates/scupper-mac/src/qual/evidence_path.rs"
STATE_MEASURE = ROOT / "crates/scupper-mac/src/qual/state_measure.rs"
RULESET_CENSUS = ROOT / "crates/scupper-darwin/src/pf_rulesets.rs"
DESC_INVENTORY = ROOT / "crates/scupper-mac/src/qual/desc_inventory.rs"
CHILD_STAGE = ROOT / "crates/scupper-mac/src/qual/child_stage.rs"
OUT = ROOT / "target/r7-mutants"
OUT.mkdir(parents=True, exist_ok=True)
MUTANTS = [
    ("state-issues-hide-removal-refutation", STATE_MEASURE,
     'if r.verdict != super::Verdict::AssumptionRefuted {', 'if true {',
     "qual::state_measure::tests::state_issues_preserve_removal_refutation_and_detail"),
    ("kernel-missing-anchor-EINVAL-to-ENOENT", RULESET_CENSUS,
     'Err(EINVAL) => return Ok(None),', 'Err(2 /* Darwin ENOENT */) => return Ok(None),',
     "qual::ruleset_census::tests::missing_anchor_errno_only_on_initial_count"),
    ("state-read-aborts-first-error", STATE_MEASURE,
     'next(read.map_err(|e| e.to_string()))', 'next(Ok(read?))',
     "qual::state_measure::tests::read_errors_do_not_abort_lifecycle_or_scope_measurements"),
    ("inventory-differences-ignored", DESC_INVENTORY,
     ['if !kernel_only.is_empty() {', 'if !text_only.is_empty() {'],
     ['if false && !kernel_only.is_empty() {', 'if false && !text_only.is_empty() {'],
     "qual::desc_inventory::tests::stable_inventory_differences_are_findings_and_mutation_is_inconclusive"),
    ("sweep-NotFound-fatal-again", EVIDENCE_PATH,
     'Err(error) if error.kind() == io::ErrorKind::NotFound => (),',
     'Err(error) if error.kind() == io::ErrorKind::NotFound => return Err(error),',
     "qual::evidence_path::tests::sweep_skips_vanished"),
    ("restore-failed-read-is-not-empty", RECOVERY,
     ['.inconclusive\n                    .push(format!("journaled anchor read incomplete: {path}: {error}"))',
      'journaled anchor read incomplete: {path}: {error}'],
     ['.violations\n                    .push(format!("journaled anchor read incomplete: {path}: {error}"))',
      'journaled anchor not empty: {path}: {error}'],
     "qual::recovery::anchor_read_tests::duplicate_failed_read"),
    ("state-parse-error-is-no-state", STATE_MEASURE,
     'let states = rows?;', 'let states = rows.unwrap_or_default();',
     "qual::state_measure::tests::parse_failure_is_explicit"),
    ("child-staging-overwrites-existing-entry", CHILD_STAGE,
     ['if !absent(target)? {', '.create_new(true)'],
     ['if false && !absent(target)? {', '.create(true).truncate(true)'],
     "qual::child_stage::tests::staging_never_overwrites"),
    ("child-staging-exclusive-create-lost", CHILD_STAGE,
     '.create_new(true)', '.create(true).truncate(true)',
     "qual::child_stage::tests::exclusive_create_closes"),
    ("shared-anchor-gates-core-and-Left-again", NATIVE_CONTRACTS,
     'results.push(case(out, id, |r| operation(out, r))?);',
     'results.push(case(out, id, |r| { if matches!(id, "Q-CONTRACTS" | "Q-E2E") { shared_anchor_clean(out)?; } operation(out, r) })?);',
     "python:ArtifactTests.test_shared_anchor_gate_only_blocks_anchor_work"),

    ("unreviewed-load-accepts-any-payload", ANCHOR,
     'if text != scupper_core::mac::policy::render_lockdown().as_str()',
     'if false && text != scupper_core::mac::policy::render_lockdown().as_str()',
     "decode::pfanchor::tests::unsupported_build_only"),
    ("unreviewed-load-returns-ok", ANCHOR,
     'let _attempt = io.emergency_load(&load_args(path), text.as_bytes());',
     'let _attempt = io.emergency_load(&load_args(path), text.as_bytes()); if _attempt == Ok(0) { return Ok(()); }',
     "decode::pfanchor::tests::unsupported_build_only"),
    ("drop-installed-protected-check", TRACE,
     '!trace.iter().any(|row| {', 'true || !trace.iter().any(|row| {',
     "engine::tests::r7::installed_protected_candidate"),
    ("drop-descendant-depth-bound", ANCHOR,
     'if depth >= 8 || *count > 64 {', 'if *count > 64 {',
     "decode::pfanchor::tests::descendant_depth_bound"),
    ("native-undo-quiescence-always-true", RESOURCE_UNDO,
     'Ok(campaign_quiescent()? && jobs_absent()? && writers_quiescent()?)',
     'Ok(true)',
     "qual::resources::tests::journal_undo_retains"),
    ("inventory-error-is-empty", ANCHOR,
     'let parent = io.call(Operation::Inventory, &["-a", path.parent(), "-sA"], &[])?;',
     'let parent = io.call(Operation::Inventory, &["-a", path.parent(), "-sA"], &[]).unwrap_or(Text::Present(String::new()));',
     "decode::pfanchor::tests::absence_needs_parent"),
    ("inventory-alone-proves-absence", ANCHOR,
     'let filter = io.call(Operation::Filter,',
     'if !present { return Ok(None); }\n    let filter = io.call(Operation::Filter,',
     "decode::pfanchor::tests::absence_needs_parent"),
    ("child-compared-with-root", ANCHOR,
     'let parent = io.call(Operation::Inventory, &["-a", path.parent(), "-sA"], &[])?;',
     'let parent = io.call(Operation::Inventory, &["-sA"], &[])?;',
     "decode::pfanchor::tests::absence_needs_parent"),
    ("ignore-nat-and-tables", ANCHOR,
     'for flag in ["-sn", "-sT", "-sA", "-sd"] {', 'for flag in ["-sA"] {',
     "decode::pfanchor::tests::present_empty"),
    ("remove-without-absence-read", ANCHOR,
     'if read(io, path)?.is_some() {', 'if false && read(io, path)?.is_some() {',
     "decode::pfanchor::tests::removal_uses"),
    ("F-all-instead-of-scoped", ANCHOR,
     '(Operation::Rules, "rules"),', '(Operation::Rules, "all"),',
     "decode::pfanchor::tests::removal_uses"),
    ("selective-nonempty-is-ok", ANCHOR,
     'if empty {\n        Ok(())', 'if empty || !empty {\n        Ok(())',
     "decode::pfanchor::tests::unknown_counts"),
    ("flush-accepts-unknown", ANCHOR,
     'Operation::States => stdout.is_empty() && numeric(stderr, b" states cleared\\n"),',
     'Operation::States => true,',
     "decode::pfanchor::tests::every_proposed_row"),
    ("unavailable-skips-none-assertion", CONTRACT,
     '&& mode == ExeIdentity::Unavailable', '&& mode == ExeIdentity::Required',
     "platform::tests::r7_hooks::unavailable"),
    ("unsupported-is-match", CONTRACT,
     'if actual == Readback::Unsupported {', 'if actual == Readback::Unsupported { return Ok(()); }\n    if actual == Readback::Unsupported {',
     "platform::tests::r7_hooks::unsupported"),
    ("journal-preexisting-anchor", JOURNAL,
     'Ok(None) => append(),', 'Ok(_) => append(),',
     "qual::journal::r7::preexisting"),
    ("detach-stops-before-thirty-seconds", DETACH,
     'let plain_end = start + available.min(Duration::from_secs(30));',
     'let plain_end = start + available.min(Duration::from_secs(3));',
     "qual::detach::tests::busy_gets_full"),
    ("H1-anonymous-only-on-install-failure", REFERENCE,
     ['if self.platform.boot_id().is_none() || self.mode == Mode::PersistBlocked {',
      'if self.platform.boot_id().is_none() {\n            // The reservation'],
     ['if self.install.is_none() || self.platform.boot_id().is_none() || self.mode == Mode::PersistBlocked {',
      'if self.install.is_none() || self.platform.boot_id().is_none() {\n            // The reservation'],
     "engine::tests::r7::r7_install_no_writer_selects_lockdown"),
    ("M1-anchor-errors-all-inconclusive", CONTRACT_CHECK,
     '*error == crate::decode::pfanchor::UNREVIEWED',
     'true || *error == crate::decode::pfanchor::UNREVIEWED',
     "qual::contract_check::tests::anchor_errors_only_review_gaps"),
    ("M2-qualification-production-paths", NATIVE_CONTRACTS,
     '    let adapter = p.remove_anchor(deadline());',
     '    let _production = NativePlatform::new(Paths::production())?;\n    let adapter = p.remove_anchor(deadline());',
     "python:ArtifactTests.test_qualification_never_uses_production_paths"),
    ("M3-ignore-dummynet", ANCHOR,
     'for flag in ["-sn", "-sT", "-sA", "-sd"] {',
     'for flag in ["-sn", "-sT", "-sA"] {',
     "decode::pfanchor::tests::present_empty"),
    ("empty-listed-anchor-is-Some", ANCHOR,
     'Ok((!text.is_empty()).then_some(text))', 'Ok(Some(text))',
     "decode::pfanchor::tests::present_empty"),
    ("empty-listed-anchor-is-Err", ANCHOR,
     'Ok((!text.is_empty()).then_some(text))', 'if text.is_empty() { return Err(SysError::Unknown); } Ok(Some(text))',
     "decode::pfanchor::tests::present_empty"),
    ("flush-on-first-read-absence", ANCHOR,
     'if read(io, path).is_ok_and(|text| text.is_none()) {',
     'if false && read(io, path).is_ok_and(|text| text.is_none()) {',
     "decode::pfanchor::tests::removal_skips_flush"),
    ("drop-optimizer-none", ANCHOR,
     ['pub(crate) fn load_args(path: &AnchorPath) -> [&str; 6]', '["-o", "none", "-a", path.as_str(), "-f", "-"]'],
     ['pub(crate) fn load_args(path: &AnchorPath) -> [&str; 4]', '["-a", path.as_str(), "-f", "-"]'],
     "decode::pfanchor::tests::load_requires"),
    ("restore-aborts-on-first-failed-step", RECOVERY,
     'failures.push(error.to_string());', 'failures.push(error.to_string()); break;',
     "qual::recovery::tests::failed_step_does_not_skip"),
    ("contracts-job-missing-from-allowlist", JOBS,
     '    "contracts",', '',
     "qual::jobs::tests::every_journaled_job"),
    ("golden-Mismatch-is-Inconclusive", CONTRACT_CHECK,
     '    } else {\n        Readback::Mismatch\n    }\n}', '    } else {\n        Readback::Unsupported\n    }\n}',
     "qual::contract_check::tests::reviewed_optimizer_none"),
    ("descendant-review-flag-ignored", ANCHOR,
     'let recursive = io.descendants_reviewed()?;', 'let recursive = true;',
     "decode::pfanchor::tests::descendant_absence"),
    ("nonempty-grandchild-accepted", ANCHOR,
     'if io.call(Operation::Filter, &["-a", &child, "-sr"], &[])? != Text::Present(String::new())',
     'if depth != 1 && io.call(Operation::Filter, &["-a", &child, "-sr"], &[])? != Text::Present(String::new())',
     "decode::pfanchor::tests::descendant_absence"),
    ("unsupported-build-spawns-pfctl", ANCHOR,
     'fn require_review(io: &impl Commands) -> Result<(), SysError> {\n    if !reviewed(&io.build()?) {',
     'fn require_review(io: &impl Commands) -> Result<(), SysError> {\n    if false && !reviewed(&io.build()?) {',
     "decode::pfanchor::tests::unsupported_build"),
    ("restore-without-writer-quiescence", RECOVERY,
     'if matches!(step, "tokens" | "anchors" | "pf state" | "completion")',
     'if false && matches!(step, "tokens" | "anchors" | "pf state" | "completion")',
     "qual::recovery::undo_tests::fake_journal_undo_withholds"),
    ("filter-foreign-becomes-unknown", ANCHOR,
     'if op == Operation::Filter\n                && (',
     'if false && op == Operation::Filter\n                && (',
     "decode::pfanchor::tests::filter_foreign_classes"),
    ("undo-aborts-after-tools-failure", RECOVERY,
     'failures.push(error);', 'failures.push(error); break;',
     "qual::recovery::undo_tests::fake_journal_undo_tools_failure"),
    ("review-golden-hash-drift", REVIEW,
     '8d88ce6bb28645b35bb0440868c44712057d98be24165187f343227b058923f8', '0' * 64,
     "python:ArtifactTests.test_review_sha256_matches_exact_golden_bytes"),
    ("clear-intent-whitespace-clears", PROTOCOL,
     'if self.platform.read_anchor(d)?.is_some() {',
     'if self.platform.read_anchor(d)?.is_some_and(|text| !text.trim().is_empty()) {',
     "engine::tests::r7::clear_intent_only_none"),
]
temporary = OUT / "tmp"
temporary.mkdir(exist_ok=True)
env = dict(os.environ, CARGO_BUILD_JOBS="2", RUST_TEST_THREADS="2", CARGO_NET_OFFLINE="true", TMPDIR=str(temporary))
originals = {path: path.read_bytes() for _, path, *_ in MUTANTS}
results = []
try:
    for name, path, old, new, test in MUTANTS:
        source = originals[path].decode()
        replacements = zip(old, new) if isinstance(old, list) else [(old, new)]
        for before, after in replacements:
            if source.count(before) != 1:
                raise RuntimeError(f"{name}: expected exactly one mutation site")
            source = source.replace(before, after, 1)
        path.write_text(source)
        try:
            command = (["python3", "crates/scupper-mac/qualification/test_artifacts.py", test.removeprefix("python:")]
                       if test.startswith("python:") else
                       ["cargo", "test", "-p", "scupper-mac", "--lib", "--all-features", test, "--", "--nocapture"])
            result = subprocess.run(command, cwd=ROOT, env=env,
                                    capture_output=True, text=True, timeout=300, check=False)
            output = result.stdout + result.stderr
            (OUT / f"{name}.log").write_text(output)
            killed = result.returncode != 0 and (
                ("test result: FAILED" in output and ("assertion" in output or "did not panic as expected" in output))
                or (test.startswith("python:") and "FAILED (failures=" in output and "AssertionError" in output))
            results.append(dict(mutant=name, killed_by_assertion=killed, returncode=result.returncode, test=test))
            print(json.dumps(results[-1]), flush=True)
            if not killed:
                raise RuntimeError(f"mutant not killed by a test assertion: {name}")
        finally:
            path.write_bytes(originals[path])
finally:
    for path, data in originals.items():
        path.write_bytes(data)
    restored = all(path.read_bytes() == data for path, data in originals.items())
    (OUT / "results.json").write_text(json.dumps(dict(results=results, restored=restored,
        source_sha256={str(path.relative_to(ROOT)): hashlib.sha256(data).hexdigest()
                       for path, data in originals.items()}), indent=2) + "\n")
