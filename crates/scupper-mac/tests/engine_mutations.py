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
    parser.add_argument('--resource-only', action='store_true', help='Core: run just the two R0 policy mutants.')
    parser.add_argument('--only', action='append', default=[], help='Run only these exact engine mutant labels.')
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
        return subprocess.run(*command_args, **kwargs)
    Path('target/run6-fix1/mutants').mkdir(parents=True, exist_ok=True)
    """Run-6 safety mutants. Run from the worktree root; sources are always restored.

A kill requires a named assertion failure, never a build failure. Existing core
mutations, including the two new policy checks, run through the core script.
"""

    engine = Path('crates/scupper-mac/src/engine.rs')
    execute = engine.parent / 'engine/execute.rs'
    protocol = engine.parent / 'engine/protocol.rs'
    core = Path('crates/scupper-core/src/mac/lifecycle.rs')
    platform_source = Path('crates/scupper-mac/src/platform.rs')
    original_bytes = {path: path.read_bytes() for path in [engine, execute, protocol, core, platform_source]}
    originals = {path: data.decode() for path, data in original_bytes.items()}
    env = dict(os.environ, CARGO_BUILD_JOBS='2', RUST_TEST_THREADS='2')
    mutants = []

    def replace(path, needle, replacement):
        original = originals[path]
        assert original.count(needle) == 1, (path, needle)
        return original.replace(needle, replacement)

    mutants.append(('Leave waits on accounting', {protocol: replace(protocol,
        '        self.leave_item = Some("anchor");',
        '        if self.snapshot.references.iter().flatten().next().is_some() { return Err(SysError::Failed("reference debt")); }\n        self.leave_item = Some("anchor");')},
        'leave_does_not_wait_on_reference_debt_or_open_cleanup_family'))

    # Independently omit each required complete read or final fence predicate.
    markers = ['anchor', 'DNS key', 'owned process', 'split route', 'host route', 'fence open']
    text = originals[protocol]
    for index, marker in enumerate(markers):
        start = text.index('        self.leave_item = Some("' + marker + '");')
        end = text.index('        self.leave_item = Some("' + markers[index + 1] + '");', start) if index + 1 < len(markers) else text.index('        self.leave_item = None;', start)
        # Keep route inventory when testing only the split-route predicate, because
        # the following host-route predicate depends on that same complete read.
        if marker == 'split route':
            old = '        if routes.split_owned {\n            return Err(SysError::Failed("split route"));\n        }\n'
            mutant = replace(protocol, old, '')
        else:
            mutant = text[:start] + text[end:]
        mutants.append(('ClearIntent skips ' + marker, {protocol: mutant}, 'clear_intent_complete_reads_name_each_failure_then_recover'))

    # Defeat the scheduling and reserve-before-effect gates together. Removing only
    # one is redundant defense, so cannot actually expose the forbidden ioctl.
    a = originals[engine].index('                if self.waiting.is_some()')
    b = originals[engine].index('                if self.tool_blocked', a)
    scheduler = originals[engine][:a] + originals[engine][b:]
    a = originals[execute].index('        if step == Step::AcquireReference && !self.commit_if_changed()')
    b = originals[execute].index('        let Some(next)', a)
    acquire = originals[execute][:a] + originals[execute][b:]
    mutants.append(('Acquire in PersistBlocked', {engine: scheduler, execute: acquire}, 'persist_blocked_masks_protected_runs_n_work_and_never_acquires_disabled_pf'))

    start = originals[engine].index('    pub fn status(')
    status = originals[engine][:start] + originals[engine][start:].replace('} else if self.mode == Mode::PersistBlocked {', '} else if false && self.mode == Mode::PersistBlocked {', 1)
    assert status != originals[engine]
    mutants.append(('Expose Protected in PersistBlocked', {engine: status}, 'persist_blocked_masks_a_previously_protected_machine_and_join_ack'))
    mutants.append(('Hold plans CheckTools', {core: replace(core,
        '        if self.durable.hold {\n            return;\n        }\n        if let Some(delay) = self.rejoin_delay {',
        '        if self.durable.hold {\n            self.pending.push(Step::CheckTools);\n            return;\n        }\n        if let Some(delay) = self.rejoin_delay {')}, 'hold_table_repairs_refreshes_ignores_child_and_never_plans_suffix'))

    mutants.append(('Confirm cleanup while a late tool survives', {execute: replace(execute,
        '        if self.platform.fence() != super::Fence::Closed {',
        '        if false && self.platform.fence() != super::Fence::Closed {')}, 'leave_late_anchor_effect_is_reaped_before_immediate_cleanup_retry'))

    # Each restored gate has its own independent oracle.
    mutants.append(('M1 remove D wait only', {engine: scheduler}, 'persist_blocked_waiting_d_gate_does_not_redispatch_a_failed_commit'))
    mutants.append(('M1 remove reservation gate only', {execute: acquire}, 'acquire_dispatch_requires_committed_reservation_even_without_scheduler'))
    mutants.append(('M2 restart enters Stuck', {engine: replace(engine,
        '        self.mode = if self.storage_blocked {',
        '        if self.snapshot.internal_error.is_some() { self.enter_stuck(); return; }\n        self.mode = if self.storage_blocked {')},
        'timing_persisted_internal_error_restarts_in_verified_hold_and_leave_runs_normally'))
    mutants.append(('M3 no settled eviction', {protocol: replace(protocol,
        '        let oldest = requests.iter().position(|old| settled_request(old.kind));',
        '        let oldest: Option<usize> = None;')},
        'settled_requests_are_evicted_oldest_first_and_six_join_leave_cycles_reach_left'))
    mutants.append(('M3 Leave refuses full window', {protocol: replace(protocol,
        'oldest.or(leave.then_some(0))', 'oldest')},
        'full_unsettled_window_refuses_join_without_stuck_but_always_accepts_leave'))
    mutants.append(('S3 blocked equality skips write', {engine: replace(engine,
        '        if !self.storage_blocked && self.snapshot == self.committed {',
        '        if self.snapshot == self.committed {')},
        'storage_retry_rewrites_equal_snapshot_and_abandoned_newer_copy'))

    # Mutate the publication fence separately from the ClearIntent fence.
    mutants.append(('S9 Left publication ignores open fence', {engine: replace(engine,
        'if self.left_verified && mutation_fence != Fence::Closed {',
        'if false && self.left_verified && mutation_fence != Fence::Closed {')},
        'left_publication_rechecks_a_newly_opened_fence'))
    a = originals[engine].index('            match &enforcement {')
    b = originals[engine].index('\n        };\n        Status {', a)
    mutants.append(('S1 text ignores mask', {engine: originals[engine][:a] + '            self.machine.status_text_at(&clock)' + originals[engine][b:]},
        'persist_blocked_masks_a_previously_protected_machine_and_join_ack'))
    mutants.append(('S4 handshake does not supersede D wait', {protocol: replace(protocol,
        '        if self.machine.transition(event.clone(), &clock).is_err() {',
        '        if matches!(event, Event::Handshake { .. }) || self.machine.transition(event.clone(), &clock).is_err() {')},
        'persist_blocked_pf_and_handshake_observations_supersede_waiting_d_commit'))
    mutants.append(('S5 installed uses platform qualification', {execute: replace(execute,
        'self.install\n                .as_ref()\n                .map(|install| install.config.qualification.clone())',
        'self.platform.firewall_qualification()')},
        'installed_policy_uses_install_qualification_when_platform_has_none'))
    a = originals[protocol].index('        // A queued completion may carry')
    b = originals[protocol].index('        self.mode = Mode::Stuck;', a)
    mutants.append(('S7 Stuck strands queued completion', {protocol: originals[protocol][:a] + originals[protocol][b:]},
        'entering_stuck_retains_the_matching_queued_acquisition_completion'))
    a = originals[protocol].index('            self.stuck_leave = Some(VecDeque::from([Step::ClearIntent]));')
    b = originals[protocol].index('\n        }\n    }', a)
    mutants.append(('S6 Left commit has no backoff', {protocol: originals[protocol][:a] + '            self.stuck_leave = Some(VecDeque::from([Step::ClearIntent]));' + originals[protocol][b:]},
        'timing_stuck_left_commit_failure_backs_off_without_repeating_clear_intent_reads'))
    mutants.append(('S9 reload on every held gap', {core: replace(core,
        '        self.pending = vec![Step::FlushStates, Step::VerifyPreTunnel];',
        '        self.pending = vec![Step::LoadPreTunnel, Step::VerifyPreTunnelLoad, Step::FlushStates, Step::VerifyPreTunnel];')},
        'held_refresh_gap_and_expiry_do_not_reload_matching_policy'))
    mutants.append(('S8 ignore uncommitted pfctl orphan', {platform_source: replace(platform_source,
        '            if proc.ppid == 1 && owned && start_key(proc.start) < start_key(own.start) {',
        '            if proc.ppid == 1 && owned && proc.path.as_deref() != Some(Path::new("/sbin/pfctl")) && start_key(proc.start) < start_key(own.start) {')},
        'uncommitted_helper_tool_orphan_is_killed_by_next_start_fence_before_effects'))

    a = originals[engine].index('                if self\n                    .push_request(')
    b = originals[engine].index('                self.left_verified = false;', a)
    region = originals[engine][a:b]
    assert region.count('                    return;') == 1
    mutants.append(('M3 full Join enters Stuck', {engine: originals[engine][:a] + region.replace('                    return;', '                    self.enter_stuck();\n                    return;') + originals[engine][b:]},
        'full_unsettled_window_refuses_join_without_stuck_but_always_accepts_leave'))

    mutants.append(('S9 lose durable Leaving on restart', {engine: replace(engine,
        '        let next = if durable.hold && self.install.is_none() {',
        '        if durable.leaving { durable.leaving = false; durable.leave_requested = false; durable.pending_cleanup.clear(); durable.cleanup_errors.clear(); }\n        let next = if durable.hold && self.install.is_none() {')},
        'leave_crash_at_each_commit_resumes_cleanup_without_spawn'))
    if args.only:
        unknown = set(args.only) - {mutant[0] for mutant in mutants}
        assert not unknown, 'Unknown mutant labels: ' + repr(unknown)
        mutants = [mutant for mutant in mutants if mutant[0] in args.only]

    # Preserve the brief's priority order within the separate mutation budget.
    priority = ['M1 remove D wait only', 'M1 remove reservation gate only', 'M2 restart enters Stuck', 'M3 no settled eviction', 'M3 Leave refuses full window', 'M3 full Join enters Stuck', 'S1 text ignores mask', 'Expose Protected in PersistBlocked', 'S3 blocked equality skips write', 'S5 installed uses platform qualification', 'S6 Left commit has no backoff', 'S4 handshake does not supersede D wait', 'S7 Stuck strands queued completion', 'S8 ignore uncommitted pfctl orphan', 'S9 Left publication ignores open fence', 'S9 reload on every held gap']
    mutants.sort(key=lambda mutant: priority.index(mutant[0]) if mutant[0] in priority else len(priority))

    try:
        for label, changes, test in mutants:
            for path, text in changes.items():
                path.write_text(text)
            command = ['cargo', 'test', '-p', 'scupper-mac', '--lib', test]
            result = run_command(command, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=180)
            Path('target/run6-fix1/mutants/mutant-' + label.replace(' ', '-') + '.log').write_text(result.stdout)
            assert result.returncode != 0 and 'test result: FAILED' in result.stdout and test + ' ... FAILED' in result.stdout, label + ' survived or did not reach its regression'
            print(label + ': killed by ' + test + '; command=' + ' '.join(command) + '; exit=' + str(result.returncode), flush=True)
            for path in changes:
                path.write_bytes(original_bytes[path])
                assert hashlib.sha256(path.read_bytes()).digest() == hashlib.sha256(original_bytes[path]).digest()
        print(f'Engine mutations: {len(mutants)} killed, 0 survived, 0 invalid', flush=True)
    finally:
        for path, data in original_bytes.items():
            path.write_bytes(data)
            assert hashlib.sha256(path.read_bytes()).digest() == hashlib.sha256(data).digest()


if __name__ == '__main__':
    guarded_run(run_mutants, [Path(path) for path in ['crates/scupper-mac/src/engine.rs', 'crates/scupper-mac/src/engine/execute.rs', 'crates/scupper-mac/src/engine/protocol.rs', 'crates/scupper-mac/src/platform.rs', 'crates/scupper-core/src/mac/lifecycle.rs']])
