#!/usr/bin/env python3
"""R4 portable mutations: require a failing assertion, then restore exact bytes."""
from pathlib import Path
import os
import subprocess

ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / "crates/scupper-mac/src/platform/runtime.rs"
LOGS = ROOT / "target/r4-validation"
# The utun cross-check is exercised by native wiring mutants; mutating the
# portable boolean passthrough cannot establish that the wiring is used.
MUTANTS = [
    ("accept-self-dup", "    source >= 0 && target >= 0 && source != target\n}",
     "    source >= 0 && target >= 0\n}", "self_dup_is_rejected"),
    ("reaped-without-syscall", "matches!(self, Self::Status(_) | Self::NoChild)",
     "matches!(self, Self::Pending | Self::Status(_) | Self::NoChild)",
     "only_reap_evidence_closes_fences_and_families_are_separate"),
    ("child-reaper-consumes-tool", "self.children.retain_mut(|r| !reap(r).settled());",
     "self.tools.retain_mut(|(_, r)| !reap(r).settled());\n        self.children.retain_mut(|r| !reap(r).settled());",
     "only_reap_evidence_closes_fences_and_families_are_separate"),
    ("skip-start-recheck", "p.start != start || pgid.is_some_and(|g| p.pgid != g)",
     "pgid.is_some_and(|g| p.pgid != g)", "wrong_start_prevents_signal_and_partial_spawn_keeps_image"),
    ("accept-two-links", " && nlink == 1", "", "lock_rejects_extra_links_and_permissions"),
    ("omit-partial-image", "child.image = observed.image.or(retained);", "",
     "wrong_start_prevents_signal_and_partial_spawn_keeps_image"),
]

def run(test):
    return subprocess.run(["cargo", "test", "-p", "scupper-mac", "--all-features", "--lib",
                           "platform::runtime::tests::" + test], cwd=ROOT,
                          env=dict(os.environ, CARGO_BUILD_JOBS="2", RUST_TEST_THREADS="2"),
                          capture_output=True, text=True, check=False)

RULES = ROOT / "crates/scupper-darwin/src/rules.rs"
original_rules = RULES.read_bytes()
original = SOURCE.read_bytes()
LOGS.mkdir(parents=True, exist_ok=True)
try:
    for name, before, after, test in MUTANTS:
        text = original.decode()
        assert text.count(before) == 1, (name, "mutation anchor not unique")
        SOURCE.write_text(text.replace(before, after, 1))
        result = run(test)
        output = result.stdout + result.stderr
        (LOGS / f"mutant-{name}.log").write_text(output)
        assert result.returncode == 101 and "panicked at" in output and "test result: FAILED" in output, (name, output)
        print(f"KILLED by assertion: {name} / {test}", flush=True)
        SOURCE.write_bytes(original)
    before = "default_handler && !no_child_wait"
    assert original_rules.decode().count(before) == 1
    RULES.write_text(original_rules.decode().replace(before, "true || (default_handler && !no_child_wait)"))
    result = subprocess.run(["cargo", "test", "-p", "scupper-darwin", "--lib", "rules::tests::sigchld_requires_default_and_waitable_children"], cwd=ROOT,
        env=dict(os.environ, CARGO_BUILD_JOBS="2", RUST_TEST_THREADS="2"), capture_output=True,text=True,check=False)
    output = result.stdout + result.stderr
    (LOGS / "mutant-omit-sigchld-policy.log").write_text(output)
    assert result.returncode == 101 and "panicked at" in output and "test result: FAILED" in output, output
    print("KILLED by assertion: omit-sigchld-policy", flush=True)
finally:
    SOURCE.write_bytes(original)
    RULES.write_bytes(original_rules)
assert SOURCE.read_bytes() == original
baseline = run("")
(LOGS / "mutant-restored-baseline.log").write_text(baseline.stdout + baseline.stderr)
assert baseline.returncode == 0, baseline.stdout + baseline.stderr
print("RESTORED: exact original source; all portable runtime tests pass", flush=True)

assert RULES.read_bytes() == original_rules
