#!/usr/bin/env python3
"""R6 Linux mutants: require an assertion failure, restore exact bytes and retest.

All builds enable qualification. Native wiring is cross-linted separately; these
mutants exercise the actual portable protocols called by the Darwin boundary.
"""
from pathlib import Path
import hashlib
import json
import os
import subprocess

ROOT = Path(__file__).resolve().parents[3]
TOKEN = ROOT / 'crates/scupper-mac/src/decode/pftoken.rs'
TEXT = ROOT / 'crates/scupper-mac/src/decode/pftext.rs'
ENGINE = ROOT / 'crates/scupper-mac/src/engine/reference.rs'
RULES = ROOT / 'crates/scupper-darwin/src/rules.rs'
CORE = ROOT / 'crates/scupper-core/src/mac/parse.rs'
OUT = ROOT / 'target/r6-mutants'
ENV = dict(os.environ, CARGO_BUILD_JOBS='2', RUST_TEST_THREADS='2')
MUTANTS = [
    ('altq-strip-anywhere', TEXT,
     'bytes.strip_prefix(ALTQ_PREAMBLE).unwrap_or(bytes)',
     'bytes.windows(ALTQ_PREAMBLE.len()).position(|w| w == ALTQ_PREAMBLE).map_or(bytes, |offset| &bytes[offset + ALTQ_PREAMBLE.len()..])',
     'scupper-mac', 'altq_prefix_is_exact_once_build_qualified_for_every_row'),
    ('altq-strip-repeatedly', TEXT,
     'bytes.strip_prefix(ALTQ_PREAMBLE).unwrap_or(bytes)',
     '{ let mut tail = bytes; while let Some(rest) = tail.strip_prefix(ALTQ_PREAMBLE) { tail = rest; } tail }',
     'scupper-mac', 'altq_prefix_is_exact_once_build_qualified_for_every_row'),
    ('altq-accept-any-remainder', TEXT,
     'if rc != 0 || !self::stderr(build, stderr).is_empty() {',
     'if rc != 0 || (!stderr.starts_with(ALTQ_PREAMBLE) && !self::stderr(build, stderr).is_empty()) {',
     'scupper-mac', 'altq_prefix_is_exact_once_build_qualified_for_every_row'),
    ('altq-strip-unsupported-build', TEXT,
     '    if supported(build) {\n        bytes.strip_prefix',
     '    if true {\n        bytes.strip_prefix',
     'scupper-mac', 'altq_prefix_is_exact_once_build_qualified_for_every_row'),
    ('native-mapping-drops-stdout-truncation', TEXT,
     'stdout_truncated: stdout.truncated,', 'stdout_truncated: false,',
     'scupper-mac', 'native_output_mapping_preserves_each_stream_truncation_flag'),
    ('native-mapping-drops-stderr-truncation', TEXT,
     'stderr_truncated: stderr.truncated,', 'stderr_truncated: false,',
     'scupper-mac', 'native_output_mapping_preserves_each_stream_truncation_flag'),
    ('accept-full', TOKEN, 'returned <= capacity - stride', 'returned <= capacity',
     'scupper-mac', 'full_copy_and_subrecord_buffers_never_prove_absence'),
    ('use-allocation-capacity', TOKEN, 'let mut bytes = allocate(capacity);',
     'let mut bytes = allocate(capacity); bytes.resize(bytes.capacity(), 0);',
     'scupper-mac', 'allocation_capacity_is_never_the_ioctl_length'),
    ('zero-is-empty', TOKEN,
     '    if stride == 0 || returned > capacity || !returned.is_multiple_of(stride) {',
     '    if returned == 0 { return Classification::Complete; }\n'
     '    if stride == 0 || returned > capacity || !returned.is_multiple_of(stride) {',
     'scupper-mac', 'full_copy_and_subrecord_buffers_never_prove_absence'),
    ('unaligned-less-than-capacity', TOKEN, 'returned <= capacity - stride', 'returned < capacity',
     'scupper-mac', 'classify_matches_xnu_copy_loop'),
    ('stride-88', TOKEN, 'pub const STRIDE: usize = 84;', 'pub const STRIDE: usize = 88;',
     'scupper-mac', 'literal_two_record_fixture_pins_byte_84_boundary'),
    ('read-size-after-error', RULES, 'if success { Some(read()) } else { None }',
     'let size = read(); if success { Some(size) } else { None }',
     'scupper-darwin', 'failed_ioctl_never_reads_size'),
    ('ungated-eexist', TEXT,
     'if gates.eexist_establishes_anonymous == Assumption::Established =>', 'if true =>',
     'scupper-mac', 'every_build_row_and_eexist_gate'),
    ('no-fingerprint-match', ENGINE, 'if !qualification.fingerprints\n                || !e',
     'if !qualification.fingerprints\n                || false && !e',
     'scupper-mac', 'numeric_release_requires_qualified_matching_fingerprint'),
    ('unqualified-release', ENGINE, 'if !qualification.fingerprints\n                || !e', 'if !e',
     'scupper-mac', 'numeric_release_requires_qualified_matching_fingerprint'),
    ('unknown-x-is-invalid', TEXT,
     '        Err(SysError::Unknown)\n    }\n}\n/// Parse all pf-info',
     '        Ok(Release::TokenInvalid)\n    }\n}\n/// Parse all pf-info',
     'scupper-mac', 'unknown_text_status_streams_and_builds_grant_nothing'),
    ('acquire-unknown-notstarted', TEXT,
     '        Ok(token) => ToolOutcome::Ok((token, result.pid)),\n'
     '        Err(_) => ToolOutcome::Unknown {\n'
     '            reaped: result.reap.settled(),\n        },',
     '        Ok(token) => ToolOutcome::Ok((token, result.pid)),\n'
     '        Err(_) => ToolOutcome::NotStarted(SysError::Unknown),',
     'scupper-mac', 'portable_outcomes_require_complete_post_spawn_evidence'),
    ('status-ignores-truncation', TEXT, '        || result.stdout_truncated\n        || result.stderr_truncated\n', '',
     'scupper-mac', 'portable_outcomes_require_complete_post_spawn_evidence'),
    ('status-ignores-timeout', TEXT, 'result.timed_out\n        || result.io_failed', 'result.io_failed',
     'scupper-mac', 'portable_outcomes_require_complete_post_spawn_evidence'),
    ('qualification-drops-layout-fingerprints', TOKEN,
     'fingerprints: self.pf_token_layout == Assumption::Established\n                && self.fingerprints',
     'fingerprints: self.fingerprints',
     'scupper-mac', 'mixed_assumptions_require_layout_and_each_individual_gate'),
    ('qualification-drops-layout-disable', TOKEN,
     'disable_voids_references: self.pf_token_layout == Assumption::Established\n                && self.disable_voids_references',
     'disable_voids_references: self.disable_voids_references',
     'scupper-mac', 'mixed_assumptions_require_layout_and_each_individual_gate'),
    ('pf-starters-direct-size', RULES,
     'successful_size(success, read).ok_or(StarterSizeError::Ioctl)?', 'read()',
     'scupper-darwin', 'starter_decision_requires_success_and_valid_size'),
    ('duplicate-token-values', TOKEN, '!seen.insert(token)', '!seen.insert(token) && false',
     'scupper-mac', 'malformed_copy_replies_and_duplicates_never_complete'),
    ('copy-noent-empty', TOKEN,
     '        let Ok(returned) = read(&mut bytes) else {\n            continue;\n        };',
     '        let returned = match read(&mut bytes) { Ok(n) => n, '
     'Err(ReadError::Noent) => return Ok(vec![]), Err(_) => continue };',
     'scupper-mac', 'retry_errors_ignore_size_and_buffers_have_exact_initialized_length'),

    ('release-unknown-notstarted', TEXT,
     '        Ok(released) => ToolOutcome::Ok(released),\n'
     '        Err(_) => ToolOutcome::Unknown {\n'
     '            reaped: result.reap.settled(),\n        },',
     '        Ok(released) => ToolOutcome::Ok(released),\n'
     '        Err(_) => ToolOutcome::NotStarted(SysError::Unknown),',
     'scupper-mac', 'portable_outcomes_require_complete_post_spawn_evidence'),
    ('status-nochild-is-zero', TEXT, '        _ => Err(SysError::Unknown),\n    }\n}',
     '        Reap::NoChild => Ok(0),\n        _ => Err(SysError::Unknown),\n    }\n}',
     'scupper-mac', 'portable_outcomes_require_complete_post_spawn_evidence'),
    ('status-pending-is-zero', TEXT, '        _ => Err(SysError::Unknown),\n    }\n}',
     '        Reap::Pending => Ok(0),\n        _ => Err(SysError::Unknown),\n    }\n}',
     'scupper-mac', 'portable_outcomes_require_complete_post_spawn_evidence'),
    ('status-ignores-io-failure', TEXT, '        || result.io_failed\n', '',
     'scupper-mac', 'portable_outcomes_require_complete_post_spawn_evidence'),
    ('status-ignores-unsent-stdin', TEXT, '        || result.stdin_unsent != 0\n', '',
     'scupper-mac', 'portable_outcomes_require_complete_post_spawn_evidence'),
    ('status-ignores-stderr-truncation', TEXT, '        || result.stderr_truncated\n', '',
     'scupper-mac', 'portable_outcomes_require_complete_post_spawn_evidence'),
    ('debug-only-accepts-enabled', CORE, '!enabled && valid_debug_level(level)', 'valid_debug_level(level)',
     'scupper-core', 'source_derived_disabled_info_accepts_only_documented_debug_suffix'),
    ('debug-only-accepts-any-level', CORE, '!enabled && valid_debug_level(level)', '!enabled',
     'scupper-core', 'source_derived_disabled_info_accepts_only_documented_debug_suffix'),
    ('info-ignores-completeness', TEXT, 'info(build, status(&e)?, e.stdout, e.stderr)', 'info(build, 0, e.stdout, e.stderr)',
     'scupper-mac', 'info_outcome_requires_complete_evidence'),
    ('enumerate-ignores-spare', TOKEN,
     '        spare,\n        |classification|', '        16,\n        |classification|',
     'scupper-mac', 'small_spare_retries_full_copies_then_completes_without_losing_oldest'),
    ('retry-alone-claims-growth', TOKEN,
     '.is_some_and(|capacity| need > capacity)',
     '.is_some()',
     'scupper-mac', 'small_spare_retries_full_copies_then_completes_without_losing_oldest'),
    ('discard-release-reread', ENGINE,
     '            lines = match self.platform.references(d) {',
     '            let _discarded = match self.platform.references(d) {',
     'scupper-mac', 'each_numeric_release_requires_a_read_after_the_previous_release'),
    ('drop-release-reread', ENGINE,
     '            lines = match self.platform.references(d) {\n'
     '                Enumeration::Complete(lines) => lines,\n'
     '                Enumeration::Incomplete(error) => return Err(error),\n'
     '            };', '',
     'scupper-mac', 'each_numeric_release_requires_a_read_after_the_previous_release'),

]


def run(crate, test):
    target = ['--test', 'mac'] if crate == 'scupper-core' else ['--lib']
    return subprocess.run(['cargo', 'test', '--offline', '-p', crate, '--all-features', *target, test],
                          cwd=ROOT, env=ENV, capture_output=True, text=True, timeout=300)


if __name__ == '__main__':
    OUT.mkdir(parents=True, exist_ok=True)
    regression_root = ROOT / "crates/scupper-mac/proptest-regressions"
    regressions = {p: p.read_bytes() for p in regression_root.rglob("*") if p.is_file()}
    originals = {path: path.read_bytes() for path in [TOKEN, TEXT, ENGINE, RULES, CORE]}
    results = []
    try:
        for crate, test in [('scupper-mac', 'decode::pf'),
                            ('scupper-mac', 'numeric_release_requires_qualified_matching_fingerprint'),
                            ('scupper-mac', 'each_numeric_release_requires_a_read_after_the_previous_release'),
                            ('scupper-core', 'source_derived_disabled_info_accepts_only_documented_debug_suffix'),
                            ('scupper-darwin', 'failed_ioctl_never_reads_size')]:
            baseline = run(crate, test)
            (OUT / f'baseline-{test.replace(":", "-")}.log').write_text(baseline.stdout + baseline.stderr)
            assert baseline.returncode == 0, baseline.stdout + baseline.stderr
        for name, path, before, after, crate, test in MUTANTS:
            source = originals[path].decode()
            assert source.count(before) == 1, (name, 'mutation anchor not unique')
            path.write_text(source.replace(before, after))
            try:
                result = run(crate, test)
                output = result.stdout + result.stderr
                (OUT / f'{name}.log').write_text(output)
                killed = (result.returncode == 101 and 'test result: FAILED' in output
                          and ('assertion' in output or 'reference released without qualified matching fingerprint' in output)
                          and 'error[E' not in output)
                results.append(dict(mutant=name, test=test, killed_by_assertion=killed))
                assert killed, (name, output)
                print(f'KILLED by assertion: {name} / {test}', flush=True)
            finally:
                path.write_bytes(originals[path])
        for crate, test in [('scupper-mac', 'decode::pf'),
                            ('scupper-mac', 'numeric_release_requires_qualified_matching_fingerprint'),
                            ('scupper-mac', 'each_numeric_release_requires_a_read_after_the_previous_release'),
                            ('scupper-core', 'source_derived_disabled_info_accepts_only_documented_debug_suffix'),
                            ('scupper-darwin', 'failed_ioctl_never_reads_size')]:
            restored = run(crate, test)
            (OUT / f'restored-{test.replace(":", "-")}.log').write_text(restored.stdout + restored.stderr)
            assert restored.returncode == 0, restored.stdout + restored.stderr
    finally:
        # Mutant counterexamples are not baseline regressions. Preserve existing
        # files and remove only persistence files introduced by this campaign.
        for path in regression_root.rglob("*"):
            if path.is_file() and path not in regressions:
                path.unlink()
        for path, data in regressions.items():
            path.write_bytes(data)
        if regression_root.exists():
            for directory in sorted((p for p in regression_root.rglob("*") if p.is_dir()), reverse=True):
                if not any(directory.iterdir()):
                    directory.rmdir()
            if not any(regression_root.iterdir()):
                regression_root.rmdir()
        for path, original in originals.items():
            path.write_bytes(original)
        assert all(path.read_bytes() == original for path, original in originals.items())
        for path, original in originals.items():
            backup = OUT / ('original-' + path.parent.name + '-' + path.name)
            backup.write_bytes(original)
            diff = subprocess.run(['git', 'diff', '--no-index', '--', str(backup), str(path)],
                                  cwd=ROOT, capture_output=True, text=True)
            assert diff.returncode == 0, diff.stdout + diff.stderr
        diff = subprocess.run(['git', 'diff', '--', *map(str, originals)], cwd=ROOT,
                              capture_output=True, text=True, check=True)
        (OUT / 'restored.diff').write_text(diff.stdout)
        (OUT / 'results.json').write_text(json.dumps(dict(results=results,
            restored_sha256={str(p.relative_to(ROOT)): hashlib.sha256(b).hexdigest()
                             for p, b in originals.items()}), indent=2) + '\n')
    print('RESTORED: exact bytes, git diff comparisons and baseline assertions passed', flush=True)
