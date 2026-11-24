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
OUT = ROOT / "target/r7-mutants"
OUT.mkdir(parents=True, exist_ok=True)
MUTANTS = [
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
]
temporary = OUT / "tmp"
temporary.mkdir(exist_ok=True)
env = dict(os.environ, CARGO_BUILD_JOBS="2", RUST_TEST_THREADS="2", TMPDIR=str(temporary))
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
