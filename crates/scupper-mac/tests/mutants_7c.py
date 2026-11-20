#!/usr/bin/env python3
"""Run 7c mutants only in a clean, explicitly pinned disposable git worktree.

Example (after the coordinator commits the reviewed implementation elsewhere):
  python3 mutants_7c.py --root /disposable/tree --expected-head <40-hex-commit> --control
  python3 mutants_7c.py --root /disposable/tree --expected-head <40-hex-commit>

--validate-only performs byte validation alone and may inspect a dirty worktree.
No mutation is executed by validation. Normal runs always run clean controls first.
POSIX watchdog workers restore on controller SIGKILL/EOF; a durable recovery journal
also restores after simultaneous worker/controller death on the next invocation.
After an abnormal stop, re-invoke immediately to recover and stop orphaned sessions.
Never reuse a disposable tree for gates without checking a clean git status.
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import math
import os
from pathlib import Path
import re
import select
import signal
import shutil
import shlex
import tempfile
import subprocess
import sys
import time

SOURCE_FILES = {
    'crates/scupper-mac/src/engine.rs',
    'crates/scupper-mac/src/platform.rs',
    'crates/scupper-core/src/mac/lifecycle.rs',
    *('crates/scupper-mac/src/engine/' + name + '.rs'
      for name in ('lockless', 'emergency', 'reference', 'execute', 'protocol')),
}
ENV = dict(os.environ, CARGO_BUILD_JOBS='2', RUST_TEST_THREADS='2', CARGO_TERM_COLOR='never')
for flag in list(ENV):
    if flag in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'CARGO_BUILD_RUSTFLAGS') or (
            flag.startswith('CARGO_TARGET_') and flag.endswith('_RUSTFLAGS')):
        ENV.pop(flag)
ACTIVE_CHILD = None


def sha(data):
    return hashlib.sha256(data).hexdigest()


def git(root, *args):
    return subprocess.check_output(['git', '-C', str(root), *args], text=True).strip()


def atomic_bytes(path, data):
    fd, name = tempfile.mkstemp(prefix='.mut-tmp-' + path.name + '.', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as output:
            os.fchmod(output.fileno(), path.stat().st_mode & 0o7777)
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(name, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        Path(name).unlink(missing_ok=True)


def atomic_json(path, data):
    temp = path.with_suffix('.tmp')
    with temp.open('w') as output:
        json.dump(data, output)
        output.flush()
        os.fsync(output.fileno())
    temp.replace(path)
    fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def source_path(root, name):
    if name not in SOURCE_FILES:
        raise ValueError('Mutation outside allowed source files: ' + name)
    path = root / name
    if path.is_symlink() or root not in path.resolve().parents:
        raise ValueError('Source escapes root: ' + name)
    return path


def validate_mutation_keys(mutants):
    seen = {}
    for mutant in mutants:
        key = (mutant['file'], mutant['old'], mutant['new'])
        if key in seen:
            raise ValueError(f"Duplicate mutation rows: {seen[key]} and {mutant['id']}")
        seen[key] = mutant['id']


def validate_review_classification(mutant):
    for field in ('equivalent', 'untestable'):
        if field in mutant and not isinstance(mutant[field], bool):
            raise ValueError(mutant['id'] + ': ' + field + ' must be boolean')
    if mutant.get('equivalent') and mutant.get('untestable'):
        raise ValueError(mutant['id'] + ': equivalent and untestable are exclusive')
    if mutant.get('equivalent') or mutant.get('untestable'):
        if not isinstance(mutant.get('reason'), str) or not mutant['reason'].strip():
            raise ValueError(mutant['id'] + ': classification requires a reason')


def validate(root, mutants):
    validate_mutation_keys(mutants)
    ids = set()
    for mutant in mutants:
        if mutant['id'] in ids or not re.fullmatch(r'[a-z0-9_-]+', mutant['id']):
            raise ValueError('Duplicate/unsafe id: ' + mutant['id'])
        ids.add(mutant['id'])
        data = source_path(root, mutant['file']).read_bytes()
        old, new = mutant['old'].encode(), mutant['new'].encode()
        if not old or data.count(old) != 1:
            raise ValueError(f"{mutant['id']}: old snippet occurs {data.count(old)} times")
        changed = data.replace(old, new, 1)
        if changed == data:
            raise ValueError(mutant['id'] + ': unchanged bytes')
        line = data[:data.index(old)].count(b'\n') + 1
        if mutant['line'] != line:
            raise ValueError(f"{mutant['id']}: stale line {mutant['line']} (actual {line})")
        if not mutant['tests'] or not all('::' in test for test in mutant['tests']):
            raise ValueError(mutant['id'] + ': full test paths required')
        validate_review_classification(mutant)
    equivalent = sum(bool(m.get('equivalent')) for m in mutants)
    untestable = sum(bool(m.get('untestable')) for m in mutants)
    print(f'Validated {len(mutants)} mutants: unique mutation triples and old snippets, changed bytes, current lines, full test paths. '
          f'Review summary: {len(mutants) - equivalent - untestable} test candidates, '
          f'{equivalent} equivalent, {untestable} untestable.', flush=True)


def stop_child(child):
    if child is not None:
        # Cargo and all descendants have their own session/process group.
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        child.wait()


def process_identity(pid):
    # A PID alone is not authority to kill a process after recovery/reuse.
    stat = Path('/proc') / str(pid) / 'stat'
    try:
        return stat.read_text().rsplit(')', 1)[1].split()[19]
    except (FileNotFoundError, IndexError):
        # macOS has no /proc. Use the process birth stamp and group identity.
        result = subprocess.run(['ps', '-p', str(pid), '-o', 'lstart=', '-o', 'pgid='],
                                capture_output=True, text=True, check=False)
        return result.stdout.strip() or None


def cleanup_core_dumps(root):
    # Dumps land in package cwd. Inspect only directories in the tracked tree,
    # without descending into target, untracked trees, or symlink directories.
    tracked = subprocess.check_output(['git', '-C', str(root), 'ls-files', '-z'])
    directories = {root}
    for name in tracked.decode().split('\0'):
        relative = Path(name)
        if not name or 'target' in relative.parts:
            continue
        directories.update((root / relative).parents)
    for directory in sorted(directories):
        if directory != root and root not in directory.parents:
            continue
        if any(part.is_symlink() for part in (directory, *directory.parents) if part == root or root in part.parents):
            continue
        if not directory.is_dir():
            continue
        for path in directory.glob('core*'):
            if re.fullmatch(r'core(?:\.\d+)?', path.name) and not path.is_symlink() and path.is_file():
                with path.open('rb') as stream:
                    is_dump = stream.read(4) == b'\x7fELF'
                if is_dump:
                    path.unlink()


def recover_temps(root):
    for name in SOURCE_FILES:
        path = source_path(root, name)
        for stray in path.parent.glob('.mut-tmp-' + path.name + '.*'):
            stray.unlink()
    cleanup_core_dumps(root)


def recover(root, journal):
    if not journal.exists():
        recover_temps(root)
        return
    record = json.loads(journal.read_text())
    if record['root'] != str(root) or record['head'] != git(root, 'rev-parse', 'HEAD'):
        raise ValueError('Recovery root/HEAD mismatch; refusing to touch source')
    worker = record['worker']
    if process_identity(worker) == record['worker_identity']:
        raise ValueError('Recovery worker is still alive; allow its watchdog to finish')
    child = record.get('child')
    if child and record.get('child_identity'):
        if process_identity(child) == record['child_identity']:
            try:
                os.killpg(child, signal.SIGKILL)
            except ProcessLookupError:
                pass
    path = source_path(root, record['file'])
    original = bytes.fromhex(record['original_hex'])
    committed = subprocess.check_output(['git', '-C', str(root), 'show',
                                         record['head'] + ':' + record['file']])
    if sha(original) != record['original_sha256'] or original != committed:
        raise ValueError('Recovery journal does not match the pinned committed source')
    if sha(path.read_bytes()) not in (record['original_sha256'], record['mutated_sha256']):
        raise ValueError('Source changed outside harness; refusing recovery overwrite')
    atomic_bytes(path, original)
    if sha(path.read_bytes()) != record['original_sha256']:
        raise ValueError('Recovery SHA-256 mismatch')
    journal.unlink()
    recover_temps(root)
    print('Recovered interrupted mutation; original SHA-256 verified.', flush=True)


def guard(root, expected, inventory, journal):
    if not re.fullmatch(r'[0-9a-f]{40}', expected or ''):
        raise ValueError('--expected-head must be the full reviewed 40-hex commit')
    if Path(git(root, 'rev-parse', '--show-toplevel')).resolve() != root:
        raise ValueError('--root must be the git repository root')
    if git(root, 'rev-parse', 'HEAD') != expected:
        raise ValueError('HEAD does not equal --expected-head')
    recover(root, journal)
    dirty = git(root, 'status', '--porcelain', '--untracked-files=all')
    if dirty:
        raise ValueError('Tree must be clean:\n' + dirty)


def classify(output, returncode, tests, *, timed_out=False, build=False, full_suite=False):
    """Use cargo's build/run boundaries and libtest records, never panic wording."""
    if timed_out:
        return 'killed-timeout', None, ('full-suite timeout (flagged)' if full_suite
                                        else 'per-test timeout (flagged)')
    ran = bool(re.search(r'^\s*Running ', output, re.M))
    if (build and returncode) or (not build and not ran):
        return 'compile-error', None, 'build failed or no test binary ran; not counted as killed'
    if build:
        return 'built', None, 'test binaries built'
    tests = [test.removeprefix('core-mac::') for test in tests if test is not None]
    failed = re.findall(r'^test (\S+) \.\.\. FAILED\s*$', output, re.M)
    if full_suite and failed:
        return 'killed', ', '.join(failed), 'full-suite FAILED tests'
    expected = next((test for test in failed if test in tests), None)
    if expected:
        return 'killed', expected, 'expected test FAILED'
    if failed:
        return 'killed-other', ', '.join(failed), 'unexpected FAILED test (flagged)'
    # Allocation aborts have no FAILED record; panic text alone never overrides
    # a structured test failure. Cargo and rustc are outside the memory limit.
    if re.search(r'^memory allocation of \d+ bytes failed\s*$|Cannot allocate memory', output, re.M | re.I):
        return 'killed-oom', None, 'test binary exhausted memory (flagged)'
    if returncode:
        return 'killed-crash', None, 'test binary ran then crashed/aborted (flagged)'
    if re.search(r'^running 0 tests\s*$', output, re.M):
        return 'test-error', None, 'no tests executed; not counted as killed or survived'
    if full_suite and re.search(r'^test result: ok\. [1-9]\d* passed;', output, re.M):
        return 'survived', None, 'all suite tests passed'
    if not full_suite and all(re.search(r'^test ' + re.escape(test) + r' \.\.\. ok\s*$', output, re.M) for test in tests):
        return 'survived', None, 'all named tests passed'
    return 'test-error', None, 'named control/test did not execute'


def self_test():
    row = dict(id='first', file='engine.rs', old='before', new='after')
    validate_mutation_keys([row, dict(row, id='distinct', new='other')])
    try:
        validate_mutation_keys([row, dict(row, id='duplicate')])
    except ValueError as error:
        assert str(error) == 'Duplicate mutation rows: first and duplicate'
    else:
        raise AssertionError('duplicate mutation triple accepted')
    for options in ({}, {'equivalent': True, 'reason': 'invariant'},
                    {'untestable': True, 'reason': 'fake cannot model timing'}):
        validate_review_classification(dict(row, **options))
    for options in ({'equivalent': True}, {'untestable': True, 'reason': ' '},
                    {'untestable': 'timing'}, {'equivalent': 1},
                    {'equivalent': True, 'untestable': True, 'reason': 'both'}):
        try:
            validate_review_classification(dict(row, **options))
        except ValueError:
            pass
        else:
            raise AssertionError('invalid review classification accepted: ' + str(options))
    test = 'engine::tests::witness'
    running = '     Running unittests src/lib.rs (target/debug/deps/scupper_mac-test)\n'
    for cause in ('assertion failed', 'explicit panic', 'called unwrap on Err', 'abort', 'Cannot allocate memory'):
        output = running + f'test {test} ... FAILED\n{cause}\nerror: test failed\n'
        assert classify(output, 101, [test])[0] == 'killed', cause
    cases = [
        ('error[E0308]: mismatched types\nerror: could not compile', 101, {}, 'compile-error'),
        (running, 0, {'timed_out': True}, 'killed-timeout'),
        (running + 'test unrelated::test ... FAILED\nerror: test failed', 101, {}, 'killed-other'),
        (running + f'test {test} ... ok\n', 0, {}, 'survived'),
        (running + 'running 0 tests\ntest result: ok. 0 passed; 0 failed;', 0, {}, 'test-error'),
        (running + 'test unrelated::test ... FAILED\n', 101, {'full_suite': True}, 'killed'),
        (running + 'test result: ok. 2 passed; 0 failed;', 0, {'full_suite': True}, 'survived'),
        (running + 'process exited: signal: 6, SIGABRT: process abort signal', 101, {}, 'killed-crash'),
        (running + 'memory allocation of 4096 bytes failed', 101, {}, 'killed-oom'),
        ('', 0, {}, 'compile-error'),
        (running, 101, {'build': True}, 'compile-error'),
        ('Finished test profile', 0, {'build': True}, 'built'),
    ]
    for output, code, options, expected in cases:
        actual = classify(output, code, [test], **options)[0]
        assert actual == expected, (actual, expected)
    assert all(flag not in ENV for flag in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'CARGO_BUILD_RUSTFLAGS'))
    assert not any(flag.startswith('CARGO_TARGET_') and flag.endswith('_RUSTFLAGS') for flag in ENV)
    suite = test_command(None, ['million_idle_ticks', 'another_filter'])
    assert suite[-4:] == ['--skip', 'million_idle_ticks', '--skip', 'another_filter']
    assert '--exact' not in suite
    assert test_command(test)[-3:] == [test, '--', '--exact']
    assert test_command('core-mac::clearing') == ['cargo', 'test', '-p', 'scupper-core', '--test', 'mac', '--locked', 'clearing', '--', '--exact']
    assert classify(running + 'test clearing ... ok\n', 0, ['core-mac::clearing'])[0] == 'survived'
    mutant = dict(id='fake', file='crates/scupper-core/src/mac/lifecycle.rs')
    for outcomes, expected in [(['survived', 'survived'], 'killed'),
                               (['killed', 'survived'], 'killed'),
                               (['survived', 'killed'], 'killed'),
                               (['killed', 'killed'], 'killed-flaky'),
                               (['compile-error', 'survived'], 'killed'),
                               (['killed', 'compile-error'], 'test-error'),
                               (['compile-error', 'compile-error'], 'test-error')]:
        calls = []
        def fake_run(root, tests, timeout, log):
            calls.extend(tests)
            return outcomes[len(calls) - 1], None, 'synthetic clean rerun'
        result = dict(status='killed', killer='first, second', note='full-suite FAILED tests')
        rerun_full_suite_failure(Path('.'), mutant, result, 1, Path('target'), run=fake_run)
        assert result['status'] == expected, result
        assert calls == ['core-mac::first', 'core-mac::second'], calls
    # Use only scratch paths beneath the invocation directory. Supply a tracked
    # directory listing without touching git metadata or real repository dumps.
    with tempfile.TemporaryDirectory(prefix='.mut-self-test-', dir=Path.cwd()) as scratch:
        root = Path(scratch)
        for name in ('crates/pkg/src', 'target/nested', 'untracked/private'):
            (root / name).mkdir(parents=True)
        removed = [root / 'core', root / 'crates/pkg/core.123']
        retained = [root / 'target/nested/core', root / 'untracked/private/core',
                    root / 'crates/pkg/src/core.txt']
        for path in [*removed, *retained]:
            path.write_bytes(b'\x7fELFsynthetic dump')
        (root / 'crates/linked').symlink_to(root / 'untracked/private', target_is_directory=True)
        (root / 'core.999').symlink_to(root / 'untracked/private/core')
        original_output = subprocess.check_output
        try:
            def tracked_output(command, **options):
                assert command == ['git', '-C', str(root), 'ls-files', '-z'], command
                return b'README.md\0crates/pkg/src/lib.rs\0crates/linked/lib.rs\0target/nested/retained\0'
            subprocess.check_output = tracked_output
            cleanup_core_dumps(root)
        finally:
            subprocess.check_output = original_output
        assert all(not path.exists() for path in removed)
        assert all(path.exists() for path in retained)
        assert (root / 'core.999').is_symlink()
    print('Classifier self-test passed (failures, crashes, OOM, zero tests, full suite, skips, environment).')


def configure_runner(memory_limit):
    if not shutil.which('prlimit'):
        raise ValueError('prlimit is required for test-binary memory limits')
    info = subprocess.check_output(['rustc', '-vV'], text=True, env=ENV)
    host = next(line.removeprefix('host: ') for line in info.splitlines() if line.startswith('host: '))
    # Force the host target so Cargo uses this runner even if a config has build.target.
    ENV['CARGO_BUILD_TARGET'] = host
    key = 'CARGO_TARGET_' + host.upper().replace('-', '_') + '_RUNNER'
    ENV[key] = shlex.join(['prlimit', f'--as={memory_limit}', '--core=0', '--'])


def test_command(test, skips=()):
    package = 'scupper-core' if test and test.startswith('core-mac::') else 'scupper-mac'
    if package == 'scupper-core':
        return ['cargo', 'test', '-p', package, '--test', 'mac', '--locked', test.removeprefix('core-mac::'), '--', '--exact']
    if test is None:
        return ['cargo', 'test', '-p', 'scupper-mac', '--lib', '--locked', '--',
                *(arg for skip in skips for arg in ('--skip', skip))]
    return ['cargo', 'test', '-p', 'scupper-mac', '--lib', '--locked', test, '--', '--exact']


def run_tests(root, tests, timeout, log_path, parent_fd=None, journal=None, record=None, *, build=False, full_suite=False, skips=(), core_suite=False):
    global ACTIVE_CHILD
    for test in ([None] if full_suite and not build else tests):
        deadline = time.monotonic() + timeout
        with log_path.open('ab') as log:
            command = (['cargo', 'test', '-p', 'scupper-mac', '--lib', '--locked', '--no-run']
                       if build else test_command(test, skips))
            if core_suite and (build or full_suite):
                command = ['cargo', 'test', '-p', 'scupper-core', '--test', 'mac', '--locked',
                           *(['--no-run'] if build else ['--', *(arg for skip in skips for arg in ('--skip', skip))])]
            log.write(('\n$ ' + ' '.join(command) + '\n').encode())
            log.flush()
            start = log.tell()
            # The exec gate prevents cargo starting before its process identity
            # is durably journalled. If this worker dies in the spawn/journal gap,
            # EOF makes the trampoline exit without executing cargo.
            gate_read, gate_write = os.pipe()
            trampoline = (
                'import os,sys,signal,resource; '
                'resource.setrlimit(resource.RLIMIT_CORE,(0,0)); '
                '[signal.signal(sig,signal.SIG_DFL) for sig in '
                '(signal.SIGHUP,signal.SIGINT,signal.SIGTERM)]; '
                'fd=int(sys.argv[1]); token=os.read(fd,1); '
                'os.close(fd); '
                'os.execvpe(sys.argv[2],sys.argv[2:],os.environ) if token==b"x" else sys.exit(1)'
            )
            child = None
            try:
                child = subprocess.Popen([sys.executable, '-c', trampoline, str(gate_read), *command],
                                         cwd=root, env=ENV, stdout=log, stderr=subprocess.STDOUT,
                                         start_new_session=True, pass_fds=(gate_read,))
                ACTIVE_CHILD = child
                if journal:
                    record.update(child=child.pid, child_identity=process_identity(child.pid))
                    if record['child_identity'] is None:
                        raise RuntimeError('Cannot journal cargo process birth identity')
                    atomic_json(journal, record)
                os.write(gate_write, b'x')
            except BaseException:
                stop_child(child)
                raise
            finally:
                os.close(gate_read)
                os.close(gate_write)
            try:
                while child.poll() is None:
                    if time.monotonic() >= deadline:
                        stop_child(child)
                        return classify('', 0, tests, timed_out=True, full_suite=full_suite)
                    if parent_fd is not None:
                        ready, _, _ = select.select([parent_fd], [], [], 0.1)
                        if ready and not os.read(parent_fd, 1):
                            raise SystemExit('controller exited; watchdog restoring')
                    else:
                        time.sleep(0.1)
                output = log_path.read_bytes()[start:].decode(errors='replace')
            finally:
                stop_child(child)
                ACTIVE_CHILD = None
                cleanup_core_dumps(root)
        result = classify(output, child.returncode, tests if full_suite else [test],
                          build=build, full_suite=full_suite)
        if build or result[0] != 'survived' or result[2] not in ('all named tests passed', 'all suite tests passed'):
            return result
    return 'survived', None, 'all suite tests passed' if full_suite else 'all named tests passed'


def rerun_full_suite_failure(root, mutant, result, timeout, work, run=run_tests):
    """Source has already been restored and checked by the controller."""
    core = mutant['file'].startswith('crates/scupper-core/')
    clean_passes = []
    clean_failures = []
    inconclusive = []
    for index, name in enumerate(result['killer'].split(', ')):
        test = ('core-mac::' + name) if core else name
        clean, _, note = run(root, [test], timeout,
                             work / (mutant['id'] + f'-clean-rerun-{index}.log'))
        if clean == 'killed' or clean.startswith('killed-'):
            clean_failures.append(name)
        elif clean == 'survived':
            clean_passes.append(name)
        else:
            inconclusive.append(name + ': ' + clean + ': ' + note)
    if clean_failures:
        result['note'] += '; clean test also FAILED: ' + ', '.join(clean_failures)
    if inconclusive:
        result['note'] += '; clean rerun inconclusive: ' + ', '.join(inconclusive)
    if clean_passes:
        result['status'] = 'killed'
        result['note'] += '; failing tests passed once on clean tree: ' + ', '.join(clean_passes)
    elif inconclusive:
        result['status'] = 'test-error'
    else:
        result['status'] = 'killed-flaky'


def mutate_worker(root, mutant, timeout, work, read_fd, expected, full_suite=False, skips=()):
    path = source_path(root, mutant['file'])
    original = path.read_bytes()
    changed = original.replace(mutant['old'].encode(), mutant['new'].encode(), 1)
    journal = work / 'recovery.json'
    record = dict(root=str(root), head=expected, worker=os.getpid(),
                  worker_identity=process_identity(os.getpid()), file=mutant['file'],
                  original_hex=original.hex(), original_sha256=sha(original), mutated_sha256=sha(changed))
    if record['worker_identity'] is None:
        raise RuntimeError('Cannot journal watchdog process birth identity')
    started = time.monotonic()
    try:
        atomic_json(journal, record)
        atomic_bytes(path, changed)
        outcome, killer, note = run_tests(root, mutant['tests'], timeout,
                                        work / (mutant['id'] + '.log'), read_fd, journal, record,
                                        full_suite=full_suite, skips=skips,
                                        core_suite=mutant['file'].startswith('crates/scupper-core/'))
        if mutant.get('equivalent'):
            note += '; known equivalent: ' + mutant['reason']
        result = dict(id=mutant['id'], status=outcome, killer=killer, note=note,
                      seconds=round(time.monotonic() - started, 2), head=expected,
                      equivalent=mutant.get('equivalent', False),
                      untestable=mutant.get('untestable', False))
    finally:
        stop_child(ACTIVE_CHILD)
        atomic_bytes(path, original)
        if sha(path.read_bytes()) != sha(original):
            raise RuntimeError('FATAL: restore SHA-256 mismatch: ' + str(path))
        journal.unlink(missing_ok=True)
    result['restore_sha256'] = sha(original)
    atomic_json(work / 'worker-result.json', result)


def execute_mutant(root, mutant, args, work):
    read_fd, write_fd = os.pipe()
    result_path = work / 'worker-result.json'
    result_path.unlink(missing_ok=True)
    worker = os.fork()
    if worker == 0:
        for sig in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, signal.SIG_IGN)
        os.close(write_fd)
        code = 0
        try:
            mutate_worker(root, mutant, args.timeout, work, read_fd, args.expected_head, args.full_suite, args.skip)
        except BaseException as error:
            print(str(error), file=sys.stderr, flush=True)
            code = 1
        finally:
            os.close(read_fd)
        os._exit(code)
    os.close(read_fd)
    try:
        _, status = os.waitpid(worker, 0)
    finally:
        # On HUP/TERM/INT or controller death the worker sees EOF, kills its
        # cargo session and restores before exiting. SIGKILL needs no handler.
        os.close(write_fd)
    if status != 0 or not result_path.exists():
        raise RuntimeError('Worker interrupted; inspect/recover journal before resuming')
    return json.loads(result_path.read_text())


def summary(results, path):
    counts = collections.Counter(result['status'] for result in results)
    lines = ['| Result | Count |', '| --- | ---: |']
    for name in ('killed', 'killed-other', 'killed-crash', 'killed-timeout', 'killed-oom', 'killed-flaky', 'compile-error', 'test-error', 'survived'):
        lines.append(f'| {name} | {counts[name]} |')
    total_killed = sum(count for name, count in counts.items() if name == 'killed' or (name.startswith('killed-') and name != 'killed-flaky'))
    lines.append(f'| total killed | {total_killed} |')
    lines += ['', 'Flagged killed-* statuses count as killed except killed-flaky; mixed results count as killed when any failing test passes clean. Core lifecycle full-suite scope is scupper-core --test mac only; it excludes core unit/other integration suites and scupper-mac lib tests. The scupper-mac full-suite scope is --lib only and excludes its integration tests. Both scopes can under-count kills.', '',
              '| Mutant | Result | Killer / note |', '| --- | --- | --- |']
    for result in results:
        lines.append(f"| {result['id']} | {result['status']} | {(result.get('killer') or '') + ': ' + result['note']} |")
    path.write_text('\n'.join(lines) + '\n')
    print('\n'.join(lines[:11]), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path)
    parser.add_argument('--self-test', action='store_true', help='classify canned evidence without cargo or mutations')
    parser.add_argument('--memory-limit', type=int, default=4 * 1024**3, help='test binary address-space limit in bytes (default 4 GiB)')
    parser.add_argument('--expected-head')
    parser.add_argument('--data', type=Path, default=Path(__file__).with_suffix('.json'))
    parser.add_argument('--validate-only', action='store_true')
    parser.add_argument('--control', action='store_true', help='run only clean controls, each distinct full test filter once')
    parser.add_argument('--timeout', type=float, default=600, help='seconds per witness or full suite, excluding pre-build (default 600)')
    parser.add_argument('--full-suite', action='store_true', help='run the entire lib suite per mutant')
    parser.add_argument('--skip', action='append', default=None, help='full-suite skip filter; repeatable (default million_idle_ticks)')
    parser.add_argument('--only', action='append', default=[], help='exact ids; repeatable')
    parser.add_argument('--results', type=Path, help='JSONL path under root/target (default target/mutants-7c/results.jsonl)')
    args = parser.parse_args()
    if args.skip is None:
        args.skip = ['million_idle_ticks']
    if args.self_test:
        self_test()
        return
    if args.root is None:
        parser.error('--root is required except with --self-test')
    if args.memory_limit <= 0:
        parser.error('--memory-limit must be positive')
    root = args.root.resolve(strict=True)
    inventory = json.loads(args.data.read_text())
    mutants = inventory['mutants']
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        parser.error('--timeout must be positive')
    validate(root, mutants) if args.validate_only else None
    if args.validate_only:
        return
    if os.name != 'posix':
        parser.error('execution requires POSIX process groups and watchdogs')
    configure_runner(args.memory_limit)
    work = root / 'target/mutants-7c'
    journal = work / 'recovery.json'
    if root not in work.resolve().parents:
        parser.error('target/work directory escapes --root')
    guard(root, args.expected_head, inventory, journal)
    validate(root, mutants)
    work.mkdir(parents=True, exist_ok=True)
    import fcntl  # POSIX execution only; validation remains platform independent.
    lock = (work / 'controller.lock').open('a')
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        raise ValueError('Another controller/watchdog owns this worktree') from None
    # Workers inherit the lock, retaining it through restoration after a killed
    # controller. Recheck after acquisition to close the concurrent-start race.
    guard(root, args.expected_head, inventory, journal)
    results_path = (args.results or work / 'results.jsonl').resolve()
    if (root / 'target').resolve() not in results_path.parents:
        parser.error('--results must be under --root/target')
    results_path.parent.mkdir(parents=True, exist_ok=True)
    fingerprint = sha(json.dumps(inventory, sort_keys=True).encode())
    metadata = results_path.with_suffix('.metadata.json')
    identity = dict(root=str(root), head=args.expected_head, inventory_sha256=fingerprint, memory_limit=args.memory_limit, classifier_version=4, full_suite=args.full_suite, skips=args.skip if args.full_suite else [])
    if metadata.exists() and json.loads(metadata.read_text()) != identity:
        parser.error('results belong to another root/HEAD/inventory')
    atomic_json(metadata, identity)
    results = []
    if results_path.exists():
        data = results_path.read_bytes()
        complete = 0
        for line in data.splitlines(keepends=True):
            try:
                result = json.loads(line)
            except json.JSONDecodeError:
                if complete + len(line) != len(data) or line.endswith(b'\n'):
                    raise ValueError('Corrupt results JSONL before final interrupted append') from None
                # A controller killed in append may leave one incomplete tail.
                with results_path.open('r+b') as output:
                    output.truncate(complete)
                print('Discarded interrupted final JSONL append.', flush=True)
                break
            results.append(result)
            complete += len(line)
        if data and complete == len(data) and not data.endswith(b'\n'):
            with results_path.open('ab') as output:
                output.write(b'\n')
    selected = [mutant for mutant in mutants if not args.only or mutant['id'] in args.only]
    if set(args.only) - {mutant['id'] for mutant in mutants}:
        parser.error('unknown --only id')
    tests = ([None] if args.full_suite else
             sorted({test for mutant in selected for test in mutant['tests']}))
    # Exclude the cold build from individual control/test deadlines.
    outcome, _, note = run_tests(root, ['build'], max(3600, args.timeout), work / 'build.log', build=True)
    if outcome != 'built':
        raise RuntimeError(f'Pre-build failed: {outcome}: {note}')
    if any(mutant['file'].startswith('crates/scupper-core/') for mutant in selected):
        outcome, _, note = run_tests(root, ['build'], max(3600, args.timeout), work / 'core-build.log',
                                    build=True, core_suite=True)
        if outcome != 'built':
            raise RuntimeError(f'Core pre-build failed: {outcome}: {note}')
        if args.full_suite:
            outcome, _, note = run_tests(root, [None], args.timeout, work / 'core-control.log',
                                        full_suite=True, core_suite=True, skips=args.skip)
            if outcome != 'survived':
                raise RuntimeError(f'Clean core control failed: {outcome}: {note}')
    # An unmutated oracle pre-run is mandatory even when resuming.
    for index, test in enumerate(tests):
        outcome, _, note = run_tests(root, [test], args.timeout, work / f'control-{index}.log',
                                     full_suite=args.full_suite, skips=args.skip)
        if outcome != 'survived' or note not in ('all named tests passed', 'all suite tests passed'):
            raise RuntimeError(f'Clean control failed: {test}: {outcome}: {note}')
        print('Control passed: ' + (test or 'full lib suite'), flush=True)
    if args.control:
        print(f'All {len(tests)} distinct clean controls passed.', flush=True)
        return
    finished = {result['id'] for result in results}
    try:
        for mutant in selected:
            if mutant['id'] in finished:
                continue
            # Re-check the full tree after every restoration, before another mutation.
            guard(root, args.expected_head, inventory, journal)
            result = execute_mutant(root, mutant, args, work)
            if args.full_suite and result['status'] == 'killed':
                guard(root, args.expected_head, inventory, journal)
                rerun_full_suite_failure(root, mutant, result, args.timeout, work)
            with results_path.open('a') as output:
                output.write(json.dumps(result, sort_keys=True) + '\n')
                output.flush()
                os.fsync(output.fileno())
            results.append(result)
            print(f"{result['id']}: {result['status']} (restore SHA-256 verified)", flush=True)
    finally:
        summary(results, results_path.with_suffix('.summary.md'))


def interrupted(signum, _frame):
    raise SystemExit('Interrupted by signal ' + str(signum))


if __name__ == '__main__':
    for sig in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, interrupted)
    try:
        main()
    except (ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        raise SystemExit(str(error)) from error
