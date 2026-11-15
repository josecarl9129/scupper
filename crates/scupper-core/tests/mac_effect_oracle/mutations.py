"""Run from the worktree root; each mutation must fail with a finite counterexample.

Restores lifecycle source and regression seeds even if a mutation check fails.
"""
from pathlib import Path
import os
import subprocess

source = Path('crates/scupper-core/src/mac/lifecycle.rs')
seeds = Path('crates/scupper-core/tests/mac.proptest-regressions')
original = source.read_text()
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
needle = '''                            self.closing.retry = None;
                            self.begin(Operation::Recover, false, now);
                            self.closing_wait(Step::VerifyPreTunnel, now);'''
assert original.count(needle) == 1
m5 = original.replace(needle, needle.rsplit('\n', 1)[0])

# Remove the round-7 acquisition observation boundary (direct context contract).
needle = '        self.invalidate(false); // acquisition invalidates every round started before it\n'
assert original.count(needle) == 1
m7 = original.replace(needle, '')

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

env = dict(os.environ, PROPTEST_CASES='1', PROPTEST_MAX_SHRINK_ITERS='4096')
try:
    for label, mutated in [('fix4-backoff', m4), ('fix4-extra-prefix-wait', m4_extra), ('fix5-B1', m5), ('round7-B1', m7), ('round8-B1-intent', m8_b1), ('round8-S1-first-prefix', m8_s1)]:
        source.write_text(mutated)
        result = subprocess.run(['cargo', 'test', '-p', 'scupper-core', '--test', 'mac',
            'external_effects_obey_ownership_repair_and_pacing', '--', '--nocapture'],
            env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=120)
        Path('target/round8-mutation-' + label + '.log').write_text(result.stdout)
        assert result.returncode != 0, label + ' unexpectedly survived'
        assert 'Test failed:' in result.stdout and 'minimal failing input:' in result.stdout, label + ' did not produce a counterexample'
        print(label + ': killed with property counterexample', flush=True)
        lines = result.stdout.splitlines()
        for index, line in enumerate(lines):
            if 'Test failed:' in line or 'minimal failing input:' in line:
                print('\n'.join(lines[index:index+4]), flush=True)
finally:
    source.write_text(original)
    seeds.write_bytes(original_seeds)
