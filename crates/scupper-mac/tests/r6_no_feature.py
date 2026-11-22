#!/usr/bin/env python3
"""Compile-time proof: assumption and spare-slot overrides are absent in production."""
from pathlib import Path
import json
import os
import subprocess

ROOT = Path(__file__).resolve().parents[3]
OUT = ROOT / 'target/r6-no-feature'
ENV = dict(os.environ, CARGO_BUILD_JOBS='2', RUST_TEST_THREADS='2')
TARGET = 'aarch64-apple-darwin'

if __name__ == '__main__':
    OUT.mkdir(parents=True, exist_ok=True)
    checked = subprocess.run(['cargo', 'check', '--offline', '--target', TARGET, '-p', 'scupper-mac',
                              '--lib', '--no-default-features', '--message-format=json'],
                             cwd=ROOT, env=ENV, capture_output=True, text=True, check=True)
    metadata = []
    for line in checked.stdout.splitlines():
        item = json.loads(line)
        if item.get('reason') == 'compiler-artifact' and item['target']['name'] == 'scupper_mac':
            metadata.extend(p for p in item['filenames'] if p.endswith('.rmeta'))
    assert len(metadata) == 1, metadata
    for name, source in [
        ('method', 'pub fn probe(p: &mut scupper_mac::native::NativePlatform) { '
                   'p.reference_assumptions(Default::default()); }'),
        ('spare_method', 'pub fn probe(p: &mut scupper_mac::native::NativePlatform) { '
                          'p.reference_spare_slots(0); }'),
        ('spare_function', 'pub fn probe() { let _ = '
                          'scupper_mac::decode::pftoken::enumerate_with_spare; }'),
        ('variant', 'pub fn probe() { let _ = scupper_mac::decode::pftoken::Override::'
                    'Qualification(Default::default()); }'),
    ]:
        path = OUT / f'{name}.rs'
        path.write_text(source + '\n')
        result = subprocess.run(['rustc', '--edition=2024', '--target', TARGET, '--crate-type=lib',
                                 '--emit=metadata', '--extern', 'scupper_mac=' + metadata[0],
                                 '-L', 'dependency=' + str(ROOT / 'target' / TARGET / 'debug/deps'),
                                 '-L', 'dependency=' + str(ROOT / 'target/debug/deps'),
                                 str(path), '-o', str(OUT / f'{name}.rmeta')], cwd=ROOT,
                                env=ENV, capture_output=True, text=True)
        (OUT / f'{name}.log').write_text(result.stdout + result.stderr)
        assert result.returncode != 0 and ('E0425' if name == 'spare_function' else 'E0599') in result.stderr, result.stderr
        assert dict(method='reference_assumptions', variant='Qualification', spare_method='reference_spare_slots', spare_function='enumerate_with_spare')[name] in result.stderr
        print(f'PROVED absent in no-feature Darwin build: {name}', flush=True)
