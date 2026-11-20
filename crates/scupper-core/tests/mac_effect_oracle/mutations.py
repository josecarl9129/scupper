"""Safety mutants. Run only after green gates, in a clean worktree.

An optional reviewed baseline patch is applied by this script itself and restored
on exit. All mutations and baseline edits restore exact bytes in finally and
verify SHA-256. A kill requires a named regression, never a compiler failure.
"""
from pathlib import Path
import os
import subprocess
import time
import argparse
import hashlib
import signal


def guarded_run(run, mutated_paths):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline-patch', type=Path,
                        help='Apply reviewed edits ourselves, only after a clean-target check; restore them on exit.')
    parser.add_argument('--resource-only', action='store_true', help='Core: run just R0 and expected-policy kind mutants.')
    parser.add_argument('--budget-seconds', type=float, default=900,
                        help='Separate wall-clock mutation budget (default: 900 seconds).')
    args = parser.parse_args()
    paths = set(mutated_paths)
    if args.baseline_patch:
        args.baseline_patch = args.baseline_patch.resolve()
        stat = subprocess.run(['git', 'apply', '--numstat', str(args.baseline_patch)],
                              check=True, capture_output=True, text=True).stdout
        for row in stat.splitlines():
            path = Path(row.split('\t', 2)[2])
            if path.is_absolute() or '..' in path.parts or '.git' in path.parts:
                raise SystemExit('Unsafe baseline patch path: ' + str(path))
            paths.add(path)
    dirty = subprocess.run(['git', 'status', '--porcelain', '--', *map(str, sorted(paths))],
                           check=True, capture_output=True, text=True).stdout
    if dirty:
        raise SystemExit('Refusing mutations: uncommitted changes not made by this script:\n' + dirty)
    originals = {path: path.read_bytes() if path.exists() else None for path in paths}

    def interrupted(signum, _frame):
        raise SystemExit('Mutation run interrupted by signal ' + str(signum))

    old_term = signal.signal(signal.SIGTERM, interrupted)
    try:
        if args.baseline_patch:
            subprocess.run(['git', 'apply', str(args.baseline_patch)], check=True)
        run(args)
    finally:
        for path, original in originals.items():
            if original is None:
                path.unlink(missing_ok=True)
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(original)
        for path, original in originals.items():
            if original is None:
                assert not path.exists(), 'Restore failed: ' + str(path)
            else:
                assert hashlib.sha256(path.read_bytes()).digest() == hashlib.sha256(original).digest(), 'Restore hash mismatch: ' + str(path)
        signal.signal(signal.SIGTERM, old_term)
        print('Original bytes restored; SHA-256 verified for every affected file.', flush=True)


def run_mutants(args):
    deadline = time.monotonic() + args.budget_seconds
    def run_command(*command_args, **kwargs):
        remaining = deadline - time.monotonic()
        if remaining < 5:
            raise SystemExit('Mutation budget exhausted; remaining mutants skipped.')
        kwargs['timeout'] = min(kwargs.get('timeout', 180), remaining)
        result = subprocess.run(*command_args, **kwargs)
        print('command=' + ' '.join(command_args[0]) + '; exit=' + str(result.returncode), flush=True)
        return result
    Path('target/run6-fix1/mutants').mkdir(parents=True, exist_ok=True)
    """Run from the worktree root; each mutation must fail with a finite counterexample.

Restores lifecycle source and regression seeds even if a mutation check fails.
"""

    source = Path('crates/scupper-core/src/mac/lifecycle.rs')
    seeds = Path('crates/scupper-core/tests/mac.proptest-regressions')
    original_bytes = source.read_bytes()
    original = original_bytes.decode()
    original_seeds = seeds.read_bytes()

    # Move the existing suffix wait ahead of the safety prefix (fix-4 regression).
    wait = '''        if let Some(delay) = self.rejoin_delay {
            self.pending.push(Step::Backoff {
                until: now.saturating_add(delay),
            });
        }
'''
    assert original.count(wait) == 1
    m4 = original.replace(wait, '')
    needle = '        if (self.durable.pf_reference.is_none() || self.references.needed)'
    assert m4.count(needle) == 1
    m4 = m4.replace(needle, wait + needle)

    # Remove the one-second wait following a Repair verification result (fix-5 B-1).
    needle = """                            if !held_background {
                                self.closing_wait(Step::VerifyPreTunnel, now);
                            }"""
    assert original.count(needle) == 1
    m5 = original.replace(needle, '')

    # Remove the round-7 acquisition observation boundary (direct context contract).
    needle = '        self.invalidate(false); // acquisition invalidates every round started before it\n'
    assert original.count(needle) == 1
    m7 = original.replace(needle, '').replace('        self.context.acquisition_revision += 1;\n', '')

    # Keep the suffix wait and add another wait ahead of the safety prefix. This
    # must fail on next-boundary effects, independently of exponential arithmetic.
    prefix = '        if (self.durable.pf_reference.is_none() || self.references.needed)'
    assert original.count(prefix) == 1
    m4_extra = original.replace(prefix, wait + prefix)

    # Restore the round-7 intent overload, including consumption by a late result.
    needle = '        if active && self.references.pf_disabled_seen.take().is_some() {\n            self.durable.reference_needs_reconcile = true;\n        }'
    assert original.count(needle) == 1
    m8_b1 = original.replace(needle, '        if self.references.pf_disabled_seen.take().is_some() {\n            self.durable.reference_intent = Some(ReferenceIntent::Release);\n            self.schedule_reference(now);\n        }')

    # Restore the covered gate: no completed prefix means every loss is absorbed.
    needle = '        let fresh_loss = action.is_some() || wake;'
    assert original.count(needle) == 1
    m8_s1 = original.replace(needle, '        let fresh_loss = (action.is_some() || wake)\n            && (!self.closing.active || self.closing.covered.is_some());')
    m8_s1 = m8_s1.replace('struct Closing {', 'struct Closing {\n    covered: Option<Context>,')
    m8_s1 = m8_s1.replace('                    if self.closing.active {\n                        self.invalidate(false);',
        '                    if self.closing.active {\n                        self.invalidate(false);\n                        self.closing.covered = Some(self.context);')

    needle = 'let maintenance = self.background_only()'
    assert original.count(needle) == 1
    maintenance = original.replace(needle, 'let maintenance = false && self.background_only()')

    # Resource model C1: independently restore each superseded Leave dependency.
    needle = "const CLEANUP: [Step; 5]"
    assert original.count(needle) == 1
    c1_cleanup = original.replace(needle, "const CLEANUP: [Step; 6]")
    needle = "    Step::RemoveAnchor,\n];"
    assert c1_cleanup.count(needle) == 1
    c1_cleanup = c1_cleanup.replace(needle, "    Step::RemoveAnchor,\n    Step::ReleaseReference,\n];")
    needle = "                        if !self.durable.pending_cleanup.is_empty() {"
    assert original.count(needle) == 1
    c1_clear = original.replace(needle, "                        if !self.durable.pending_cleanup.is_empty() || self.reference_slots() > 0 {")

    # C2: the reconciled-empty path incorrectly runs the acquisition prefix in Left.
    needle = "                    && self.durable.join_intended\n                    && self.reference_slots() < 2"
    assert original.count(needle) == 1
    c2 = original.replace(needle, "                    && self.reference_slots() < 2")

    # C2: every newly added not-joined guard must independently reach a regression.
    def remove_guard(start, end, guard):
        a = original.index(start)
        b = original.index(end, a)
        region = original[a:b]
        assert region.count(guard) == 1, (start, guard)
        return original[:a] + region.replace(guard, '') + original[b:]

    c2_guards = [
        ('C2 idle coalescing guard', remove_guard('    fn coalesce(', '        let (action, unknown)',
            '            || (!self.durable.join_intended && self.operation != Some(Operation::Join))\n')),

        ('C2 closing rerun guard', remove_guard('        if (boundary\n', '        next.schedule_state_recheck(now);',
            '            && next.durable.join_intended\n')),
        ('C2 fail guard', remove_guard('    fn fail(', '    fn apply(',
            'self.durable.join_intended\n                    && ')),
        ('C2 in-flight invalidation guard', remove_guard('            Event::InvalidateObservations { since } => {', '                self.mark_gap(since);',
            '                    && self.durable.join_intended\n')),
        ('C2 backoff invalidation guard', remove_guard('                self.mark_gap(since);\n                if matches!', '            Event::Completed(step) => {',
            '                    && self.durable.join_intended\n')),
        ('C2 Unknown recovery guard', remove_guard('                    Verdict::Unknown { since } => {', '                    Verdict::Repair(action) => {',
            '                            && self.durable.join_intended\n')),
        ('C2 Repair recovery guard', remove_guard('                    Verdict::Repair(action) => {', '                    Verdict::NeverVerified =>',
            '                            || !self.durable.join_intended\n')),
    ]

    # Run-1 follow-up guards: each mutant reaches a direct regression.
    h7_not_protected = remove_guard('                    Verdict::NotProtected(reason) => {',
        '                    Verdict::Unknown { since } => {',
        '                        if !self.durable.join_intended {\n                            return Ok(());\n                        }\n')
    h7_unknown = original.replace('if self.durable.join_intended && self.durable.last_error.is_none() {',
        'if self.durable.last_error.is_none() {')
    needle = '''                        if self.durable.pf_reference.is_none() && !self.durable.hold {
                            self.references.needed = true;
                            self.fail(Reason::Observation("unresolved acquisition debt"), now);
                            return Ok(());
                        }
'''
    assert original.count(needle) == 1
    h4 = original.replace(needle, '')
    needle = '                    return Err(Error("cannot settle active acquisition"));'
    assert original.count(needle) == 1
    h5 = original.replace(needle, '                    self.durable.reference_intent = None; true')

    # C3: settle an arbitrary uncertain slot instead of the exact sequence.
    needle = "                    self.durable.uncertain_acquires.remove(index);"
    assert original.count(needle) == 1
    c3 = original.replace(needle, "                    let _ = index;\n                    self.durable.uncertain_acquires.remove(0);")

    # C4 must stop at idle-held, and failed accounting must not park enforcement.
    needle = '        if self.durable.hold {\n            return;\n        }\n        if let Some(delay) = self.rejoin_delay {'
    assert original.count(needle) == 1
    hold_suffix = original.replace(needle, '        if let Some(delay) = self.rejoin_delay {')
    needle = '            self.reference_retry(now);\n            self.advance(now);\n            return;'
    assert original.count(needle) == 1
    hold_parks = original.replace(needle,
        '            self.reference_retry(now);\n            self.advance(now);\n'
        '            if self.durable.hold { self.pending.insert(0, Step::Backoff { until: now + 1 }); }\n            return;')

    # K1: drop reconciliation at the head of a fresh held closing prefix.
    needle = """        if self.durable.hold && self.references.needed && self.reference_slots() >= 2 {
            self.pending.push(Step::ReconcileReference);
        }
"""
    assert original.count(needle) == 1
    hold_no_head_reconcile = original.replace(needle, '')


    # R2f-S1: discard an already-dispatched hold cleanup head on invalidation.
    needle = '.filter(|step| !matches!(step, Step::Backoff { .. }));'
    assert original.count(needle) == 1
    hold_displaces_cleanup = original.replace(needle, '.filter(|step| *step == Step::ReconcileReference);')

    # A kept cleanup result must retain a separately requested repair at its boundary.
    needle = """            if Self::is_hold_cleanup(step) {
                self.abort_requested = false;
            }
"""
    assert original.count(needle) == 1
    hold_drops_deferred_repair = original.replace(needle, needle.replace(
        '                self.abort_requested = false;\n',
        '                self.abort_requested = false;\n                self.deferred_repair = None;\n'))

    # R2f-S2: accounting precedes safety even when it does not block acquisition.
    needle = 'if self.durable.hold && self.references.needed && self.reference_slots() >= 2 {'
    assert original.count(needle) == 1
    hold_broad_head = original.replace(needle,
        'if self.durable.hold && (self.reference_slots() >= 2 || self.reference_debt() && now >= self.references.retry_at) {')

    # R2f-S2 also requires accepting enabled-pf evidence in a held proof.
    needle = '''                        if self.durable.hold {
                            // A full held proof establishes that pf is enabled,
                            // even when another owner holds its only live token.
                            self.references.needed = false;
                        }
'''
    assert original.count(needle) == 1
    hold_still_needs_enable = original.replace(needle, '')

    # R2f-S3: accounting-only queues once again count as background only in hold.
    a = original.index('    fn background_only(')
    b = original.index('    fn held_background(', a)
    joined_background = original[:a] + original[a:b].replace('self.operation.is_none()',
        'self.durable.hold && self.operation.is_none()') + original[b:]

    # K1's independent guard: never insert an accounting timer inside a held prefix.
    hold_accounting_wait = remove_guard('    fn schedule_reference(', '    fn is_hold_cleanup(', """        if self.durable.hold
            && !self.pending.is_empty()
            && (!self.held_background() || !matches!(self.pending(), Some(Step::Backoff { .. })))
        {
            return;
        }
""")

    # K2: charge cleanup failure to enforcement and stop/restart the closing prefix.
    needle = '        if self.durable.hold\n            && self.operation != Some(Operation::Leave)\n            && let Some(step) = self.pending().filter(|step| Self::is_hold_cleanup(*step))'
    assert original.count(needle) == 1
    hold_cleanup_stops = original.replace(needle, needle.replace('if self.durable.hold', 'if false && self.durable.hold'))

    # K3: reject held Repair while accounting is queued or dispatched.
    needle = '(!self.pending.is_empty() && !self.held_background())'
    assert original.count(needle) == 1
    hold_rejects_repair = original.replace(needle, '!self.pending.is_empty()')

    # K5: schedule predecessor release before the replacement has a fresh proof.
    needle = """                && matches!(&self.enforcement, Verdict::Protected(proof)
                    if proof.form() == Form::Joined || self.durable.hold && !self.closing.active)"""
    assert original.count(needle) == 1
    early_predecessor = original.replace(needle, '')

    # K6: stop reporting held status as the mandatory untrusted-state error.
    needle = '        } else if self.durable.hold {\n            ConnectionStatus::NotProtected {'
    assert original.count(needle) == 1
    hold_status = original.replace(needle, needle.replace('if self.durable.hold', 'if false && self.durable.hold'))

    # R2f-N3: independently restore each smaller side effect.
    needle = '            self.pending.insert(0, retry.step);'
    assert original.count(needle) == 1
    cleanup_drops_accounting = original.replace(needle, '            self.pending = vec![retry.step];')
    needle = 'if !self.reference_debt() && self.durable.older_references.is_empty() {'
    assert original.count(needle) == 1
    invalidation_clears_debt_error = original.replace(needle, 'if !self.reference_debt() {')
    needle = """                    if self.durable.cleanup_errors.iter().any(|(failed, reason)| {
                        *failed == step && self.durable.last_error.as_ref() == Some(reason)
                    }) {
                        self.durable.last_error = None;
                    }
"""
    assert original.count(needle) == 1
    cleanup_keeps_last_error = original.replace(needle, '')

    # Optimize the full suites separately; selected mutation regressions compile faster at O0.
    env = dict(os.environ, CARGO_BUILD_JOBS='2', RUST_TEST_THREADS='2', PROPTEST_CASES='1', PROPTEST_MAX_SHRINK_ITERS='4096', CARGO_PROFILE_TEST_OPT_LEVEL='0')
    killed = 0
    if not args.resource_only:
        try:
            for label, mutated in [('fix4-backoff', m4), ('fix4-extra-prefix-wait', m4_extra), ('fix5-B1', m5), ('round7-B1', m7), ('round8-B1-intent', m8_b1), ('round8-S1-first-prefix', m8_s1)]:
                source.write_text(mutated)
                result = run_command(['cargo', 'test', '-p', 'scupper-core', '--test', 'mac',
                    'external_effects_obey_ownership_repair_and_pacing', '--', '--nocapture'],
                    env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=120)
                Path('target/round8-mutation-' + label + '.log').write_text(result.stdout)
                assert result.returncode != 0, label + ' unexpectedly survived'
                assert 'Test failed:' in result.stdout and 'minimal failing input:' in result.stdout, label + ' did not produce a counterexample'
                killed += 1
                print(label + ': killed by external_effects_obey_ownership_repair_and_pacing', flush=True)
                lines = result.stdout.splitlines()
                for index, line in enumerate(lines):
                    if 'Test failed:' in line or 'minimal failing input:' in line:
                        print('\n'.join(lines[index:index+4]), flush=True)
            source.write_text(maintenance)
            result = run_command(['cargo', 'test', '-p', 'scupper-core', '--test', 'mac',
                'idle_states_clean_maintenance_acceptance_is_bounded_by_epoch_time_and_mode'],
                env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=120)
            Path('target/core-mutation-idle-maintenance.log').write_text(result.stdout)
            assert result.returncode != 0 and 'test result: FAILED' in result.stdout, 'idle maintenance mutant survived or failed to compile'
            killed += 1
            print('idle-maintenance: killed by idle_states_clean_maintenance_acceptance_is_bounded_by_epoch_time_and_mode', flush=True)
            for label, mutated, test in [
                ('L1 drops deferred repair', hold_drops_deferred_repair, 'held_cleanup_retry_results_preserve_separately_requested_repairs'),
                ('L1 displace cleanup head', hold_displaces_cleanup, 'held_cleanup_retry_results_keep_their_head_across_every_invalidation'),
                ('L2 accounting before safety', hold_broad_head, 'held_lost_anchor_loads_before_failed_accounting_with_both_slots_uncertain'),
                ('L2 enabled proof leaves acquisition needed', hold_still_needs_enable, 'held_lost_anchor_loads_before_failed_accounting_with_both_slots_uncertain'),
                ('L3 hold-only background', joined_background, 'joined_retained_predecessor_accepts_maintenance_and_handshake_for_over_sixty_seconds'),
                ('K1 accounting wait in held prefix', hold_accounting_wait, 'held_accounting_backoff_never_precedes_safety_steps_except_a_closing_wait'),
                ('K2 cleanup stops prefix', hold_cleanup_stops, 'held_cleanup_failure_retries_only_that_step_and_does_not_starve_accounting'),
                ('K3 rejects held Repair', hold_rejects_repair, 'recovery_hold_accepts_every_repair_with_accounting_waiting_or_in_flight'),
                ('K5 releases predecessor before verification', early_predecessor, 'fresh_join_verification_schedules_retained_predecessor_for_exact_settlement'),
                ('K6 held status', hold_status, 'held_status_never_promises_rejoining_and_reports_only_fresh_blocking'),
                ('L5 cleanup drops accounting', cleanup_drops_accounting, 'held_cleanup_retry_preserves_queued_accounting_and_clears_its_last_error_on_success'),
                ('L5 invalidation clears debt error', invalidation_clears_debt_error, 'invalidation_preserves_predecessor_reference_and_cleanup_errors'),
                ('L5 successful cleanup keeps last error', cleanup_keeps_last_error, 'held_cleanup_retry_preserves_queued_accounting_and_clears_its_last_error_on_success'),
                ('H7 Left NotProtected guard', h7_not_protected, 'left_observations_preserve_reconcile_and_do_not_record_errors'),
                ('H7 Left Unknown error guard', h7_unknown, 'left_observations_preserve_reconcile_and_do_not_record_errors'),
                ('H4 Protected held-token guard', h4, 'protected_observation_with_two_uncertain_entries_cannot_publish_protected'),
                ('H5 active acquisition settlement rejection', h5, 'settlement_rejects_active_acquisition_and_does_not_confuse_token_and_sequence'),
                ('no reconcile at prefix head', hold_no_head_reconcile, 'held_disabled_pf_reconciles_full_slots_before_acquiring_and_verifying'),
                ('hold plans the suffix', hold_suffix, 'hold_restart_plans_accounting_prefix_and_cleanup_without_a_rejoin_suffix'),
                ('reconcile failure parks the prefix', hold_parks, 'hold_reconcile_failure_never_parks_the_closing_prefix'),
                ('C1 cleanup release', c1_cleanup, 'fresh_leave_cleanup_never_plans_reference_release'),
                ('C1 ClearIntent reference gate', c1_clear, 'leave_preserves_every_reference_field_and_finishes_before_idle_accounting'),
                ('C2 acquires when not joined', c2, 'idle_empty_reconciliation_never_acquires'),
                ('C3 settles the wrong entry', c3, 'settlement_removes_exactly_the_named_entry_for_every_disposition_and_mode'),
                *[(label, mutant, 'settlement_during_leave_never_restarts_a_join_after_clear_intent' if label == 'C2 closing rerun guard' else 'left_observations_preserve_reconcile_and_do_not_record_errors' if label == 'C2 idle coalescing guard' else 'idle_reference_events_never_start_recovery') for label, mutant in c2_guards],
            ]:
                source.write_text(mutated)
                result = run_command(['cargo', 'test', '-p', 'scupper-core', '--test', 'mac', test],
                    env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=120)
                Path('target/core-mutation-' + label.replace(' ', '-') + '.log').write_text(result.stdout)
                assert result.returncode != 0 and 'test result: FAILED' in result.stdout and ('test ' + test + ' ... FAILED') in result.stdout, label + ' survived or did not reach its regression'
                killed += 1
                print(label + ': killed by ' + test, flush=True)
            print(f'Mutation total: {killed} killed, 0 survived, 0 invalid', flush=True)
        finally:
            source.write_bytes(original_bytes)
            seeds.write_bytes(original_seeds)
            assert hashlib.sha256(source.read_bytes()).digest() == hashlib.sha256(original_bytes).digest()
            assert hashlib.sha256(seeds.read_bytes()).digest() == hashlib.sha256(original_seeds).digest()

    # Resource-model run 6: policy kinds and lockdown use independently checked guards.
    verify_source = Path('crates/scupper-core/src/mac/verify.rs')
    verify_original_bytes = verify_source.read_bytes()
    verify_original = verify_original_bytes.decode()
    kind_start = original.index('                            || proof.kind()')
    kind_end = original.index('                            || proof.form()', kind_start)
    any_kind = original[:kind_start] + original[kind_end:]
    needle = '''            Rule::Pass(pass) if pass.quick && !reached.contains(OWN) => {
                return Err(Reason::QuickPass);
            }'''
    assert verify_original.count(needle) == 1
    no_earlier_pass = verify_original.replace(needle, '''            Rule::Pass(pass) if pass.quick && !reached.contains(OWN) => {}''')
    some_kind = '.is_some_and(|b| b.kind() == self.pre_tunnel_policy())'
    no_kind = '.is_none_or(|b| b.kind() != self.pre_tunnel_policy())'
    assert original.count(some_kind) == 1 and original.count(no_kind) == 1
    form_rerun = original.replace(some_kind, '.is_some_and(|b| b.form() == Form::PreTunnel)')
    form_recheck = original.replace(no_kind, '.is_none_or(|b| b.form() != Form::PreTunnel)')
    start = original.index('                    Some(Step::VerifyReplacement(expected)) => {')
    end = original.index('                    _ => false,', start)
    form_replacement = original[:start] + '                    Some(Step::VerifyReplacement(expected)) => { baseline.kind() == super::policy::Kind::Installed(expected) }\n' + original[end:]
    try:
        for label, path, mutated, args, test in [
            ('R0 accept any proof kind', source, any_kind, ['--lib'], 'held_verify_requires_policy_kind_even_if_other_evidence_matches'),
            ('R0 ignore earlier anchor pass for lockdown', verify_source, no_earlier_pass, ['--test', 'mac'], 'lockdown_rejects_preceding_and_nested_anchor_pass_even_if_qualified'),
            ('S10 flush rerun compares form', source, form_rerun, ['--lib'], 'held_state_recheck_and_flush_rerun_require_expected_policy_kind'),
            ('S10 idle recheck compares form', source, form_recheck, ['--lib'], 'held_state_recheck_and_flush_rerun_require_expected_policy_kind'),
            ('S10 replacement assumes Installed', source, form_replacement, ['--lib'], 'held_replacement_readback_requires_expected_policy_kind'),
        ]:
            path.write_text(mutated)
            command = ['cargo', 'test', '-p', 'scupper-core', *args, test]
            result = run_command(command, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=180)
            Path('target/core-mutation-' + label.replace(' ', '-') + '.log').write_text(result.stdout)
            assert result.returncode != 0 and 'test result: FAILED' in result.stdout and test + ' ... FAILED' in result.stdout, label + ' survived or did not reach its regression'
            print(label + ': killed by ' + test + '; command=' + ' '.join(command) + '; exit=' + str(result.returncode), flush=True)
            source.write_bytes(original_bytes)
            verify_source.write_bytes(verify_original_bytes)
        print('Resource policy mutations: 5 killed, 0 survived, 0 invalid', flush=True)
    finally:
        source.write_bytes(original_bytes)
        verify_source.write_bytes(verify_original_bytes)
        assert hashlib.sha256(source.read_bytes()).digest() == hashlib.sha256(original_bytes).digest()
        assert hashlib.sha256(verify_source.read_bytes()).digest() == hashlib.sha256(verify_original_bytes).digest()


if __name__ == '__main__':
    guarded_run(run_mutants, [Path(path) for path in ['crates/scupper-core/src/mac/lifecycle.rs', 'crates/scupper-core/src/mac/verify.rs', 'crates/scupper-core/tests/mac.proptest-regressions']])
