#!/usr/bin/env python3
"""Kill ten storage protocol mutants on Linux; restore every edited byte.

The fsync mutant adds a mock successful fsync operation after failed full-sync.
It tests the same protocol used by Darwin; it does not execute a Darwin syscall.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / 'crates/scupper-mac/src/platform/storage.rs'
TESTS = ROOT / 'crates/scupper-mac/src/platform/storage/tests.rs'
OUT = ROOT / 'target/r5-mutants'
OUT.mkdir(parents=True, exist_ok=True)
original = {path: path.read_bytes() for path in [SOURCE, TESTS]}
backups = {SOURCE: OUT / 'original-storage.rs', TESTS: OUT / 'original-tests.rs'}
for path, backup in backups.items():
    backup.write_bytes(original[path])
env = dict(os.environ, CARGO_BUILD_JOBS='2', RUST_TEST_THREADS='2')
command = ['cargo', 'test', '-p', 'scupper-mac', '--all-features', '--lib']
results = []


def replace(path, before, after):
    source = path.read_text()
    if source.count(before) != 1:
        raise AssertionError(f'mutation anchor not unique: {before!r}')
    path.write_text(source.replace(before, after))


def mutate(name):
    if name == 'fsync-fallback':
        replace(SOURCE, '    fn full_sync(&mut self, directory: bool) -> Result<(), SysError>;',
                '    fn full_sync(&mut self, directory: bool) -> Result<(), SysError>;\n'
                '    fn fsync(&mut self) -> Result<(), SysError> { Ok(()) }')
        replace(SOURCE, '    io.full_sync(false)?;',
                '    io.full_sync(false).or_else(|_| io.fsync())?;')
    elif name == 'preallocation-is-length':
        replace(SOURCE, '    if !valid_copy(final_meta) || final_meta.size != COPY_BYTES as u64 {',
                '    if false && (!valid_copy(final_meta) || final_meta.size != COPY_BYTES as u64) {')
    elif name == 'accept-short-pwrite':
        replace(SOURCE, '    if io.pwrite(bytes)? != COPY_BYTES {',
                '    if { let _ = io.pwrite(bytes)?; false } {')
    elif name == 'accept-two-links':
        replace(SOURCE, ' && m.nlink == 1', '')
    elif name == 'consume-abandoned':
        replace(SOURCE, '    pub fn abandon(&mut self) {\n        self.read = None;\n    }',
                '    pub fn abandon(&mut self) {}')
    elif name == 'no-stub-cleanup':
        replace(SOURCE, '                io.cleanup_failed_create();', '')
    elif name == 'short-is-unreadable':
        replace(SOURCE, 'valid_created(m) && m.size <= COPY_BYTES as u64',
                'valid_created(m) && m.size == COPY_BYTES as u64')
    elif name == 'credit-unreached':
        replace(SOURCE, '*iterations += u32::from(reached);', '*iterations += 1;')
    elif name == 'skip-repair-directory-sync':
        replace(SOURCE, '    if create || meta.size < COPY_BYTES as u64 {',
                '    if create {')
    elif name == 'skip-directory-sync':
        replace(SOURCE, '        io.full_sync(true)?;', '')
    else:
        raise AssertionError(name)


try:
    baseline = subprocess.run(command + ['platform::storage::tests'], cwd=ROOT,
                              env=env, capture_output=True, text=True, timeout=300)
    (OUT / 'baseline.log').write_text(baseline.stdout + baseline.stderr)
    assert baseline.returncode == 0, 'baseline did not pass'
    for name, test in [
        ('fsync-fallback', 'full_sync_failure_never_falls_back_or_returns_synced'),
        ('preallocation-is-length', 'preallocation_is_not_length_and_short_pwrite_is_failed_without_sync'),
        ('accept-short-pwrite', 'preallocation_is_not_length_and_short_pwrite_is_failed_without_sync'),
        ('accept-two-links', 'hard_linked_copy_returns_no_bytes_and_starts_no_pread'),
        ('consume-abandoned', 'abandoned_same_copy_result_is_never_consumed_by_the_next_read'),
        ('skip-directory-sync', 'create_requires_both_checked_syncs_in_order'),
        ('skip-repair-directory-sync', 'short_repair_requires_both_checked_syncs_in_order'),
        ('no-stub-cleanup', 'failed_create_cleans_its_stub_but_never_an_existing_file'),
        ('short-is-unreadable', 'short_stub_is_zero_padded_and_repairable_but_long_files_are_unreadable'),
        ('credit-unreached', 'unreached_hook_iterations_earn_no_credit'),
    ]:
        try:
            mutate(name)
            run = subprocess.run(command + [test], cwd=ROOT, env=env,
                                 capture_output=True, text=True, timeout=300)
            output = run.stdout + run.stderr
            (OUT / (name + '.log')).write_text(output)
            killed = (run.returncode == 101 and 'test result: FAILED' in output
                      and 'assertion' in output and 'error[E' not in output)
            results.append(dict(mutant=name, test=test, killed_by_assertion=killed))
            assert killed, f'{name} survived or failed compilation; inspect {OUT}'
        finally:
            for path, data in original.items():
                path.write_bytes(data)
    restored = subprocess.run(command + ['platform::storage::tests'], cwd=ROOT,
                              env=env, capture_output=True, text=True, timeout=300)
    (OUT / 'restored.log').write_text(restored.stdout + restored.stderr)
    assert restored.returncode == 0, 'restored baseline did not pass'
finally:
    for path, data in original.items():
        path.write_bytes(data)
    assert all(path.read_bytes() == data for path, data in original.items())
    diff = subprocess.run(['git', 'diff', '--', str(SOURCE.relative_to(ROOT)), str(TESTS.relative_to(ROOT))],
                          cwd=ROOT, capture_output=True, text=True, check=True)
    (OUT / 'restored.diff').write_text(diff.stdout)
    # These new files can still be untracked. Compare their complete contents,
    # rather than treating an empty tracked-only diff as restoration evidence.
    for path, backup in backups.items():
        exact = subprocess.run(['git', 'diff', '--no-index', '--', str(backup), str(path)],
                               cwd=ROOT, capture_output=True, text=True)
        assert exact.returncode == 0, exact.stdout + exact.stderr
    (OUT / 'results.json').write_text(json.dumps(dict(results=results,
        restored_sha256={str(path.relative_to(ROOT)):hashlib.sha256(data).hexdigest()
                         for path,data in original.items()}), indent=2) + '\n')
print(json.dumps(results, indent=2))
