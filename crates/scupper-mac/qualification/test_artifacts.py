"""Portable executable-identity and redaction regression checks."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

CHECKER = Path(__file__).with_name("check-artifacts.py").resolve()
REPO = CHECKER.parents[3]
SHA256 = "a" * 64


class ArtifactTests(unittest.TestCase):
    def setUp(self):
        # Keep all test writes in the worktree, including temporary evidence.
        self.temporary = tempfile.TemporaryDirectory(prefix=".qual-test-", dir=REPO)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.write_json("preflight.json", {"binary_sha256": SHA256})
        for name in ["built-harness-sha256.txt", "executed-harness-sha256.txt"]:
            (self.root / name).write_text(f"{SHA256}  harness\n")
        self.result = {"case": "Q-SMOKE", "binary_sha256": SHA256,
                       "verdict": "assumption_holds", "iterations": 1000,
                       "detail": "fixture"}
        self.write_json("Q-SMOKE.json", self.result)
        self.write_json("verdicts.json", [self.result])

    def write_json(self, name, value):
        (self.root / name).write_text(json.dumps(value))

    def check(self, *arguments, env=None):
        return subprocess.run([sys.executable, str(CHECKER), str(self.root), *arguments],
                              capture_output=True, text=True, env=env, check=False)

    def test_matching_identity_passes_and_summary_names_hash(self):
        self.assertEqual(self.check().returncode, 0)
        summary = self.root / "summary.txt"
        env = dict(os.environ, GITHUB_STEP_SUMMARY=str(summary),
                   QUAL_RUNNER="fixture", QUAL_GROUP="smoke")
        self.assertEqual(self.check("--summary", env=env).returncode, 0)
        self.assertIn(SHA256, summary.read_text())

    def test_stale_build_or_stage_or_preflight_quarantines_verdicts(self):
        for filename in ["built-harness-sha256.txt", "executed-harness-sha256.txt",
                         "preflight.json"]:
            with self.subTest(filename=filename):
                original = (self.root / filename).read_text()
                (self.root / filename).write_text(original.replace(SHA256, "b" * 64))
                self.write_json("Q-SMOKE.json", self.result)
                self.write_json("verdicts.json", [self.result])
                self.assertEqual(self.check().returncode, 1)
                self.assertIn("quarantined", (self.root / "Q-SMOKE.json").read_text())
                self.assertIn("quarantined", (self.root / "verdicts.json").read_text())
                (self.root / filename).write_text(original)

    def test_stale_verdict_in_each_location_is_rejected(self):
        stale = dict(self.result, binary_sha256="b" * 64)
        for filename, value in [("Q-SMOKE.json", stale), ("verdicts.json", [stale])]:
            with self.subTest(filename=filename):
                self.write_json("Q-SMOKE.json", self.result)
                self.write_json("verdicts.json", [self.result])
                self.write_json(filename, value)
                self.assertEqual(self.check().returncode, 1)

    def test_missing_identity_and_verdict_without_preflight_fail_closed(self):
        (self.root / "built-harness-sha256.txt").unlink()
        self.assertEqual(self.check().returncode, 1)
        (self.root / "preflight.json").unlink()
        self.assertEqual(self.check().returncode, 1)

    def test_redaction_quarantines_text_and_probe_is_not_uploaded(self):
        (self.root / "abi-probe").write_bytes(b"fixture executable")
        (self.root / "command.json").write_text("private_key=fixture-only\n")
        self.assertEqual(self.check().returncode, 1)
        self.assertFalse((self.root / "abi-probe").exists())
        self.assertNotIn("fixture-only", (self.root / "command.json").read_text())

    def test_nested_probe_output_is_redacted_and_all_executables_are_removed(self):
        for name in ["probe-pf-starters", "probe-dns-default", "wireguard-go", "storage.dmg"]:
            (self.root / name).write_bytes(b"fixture executable")
        self.write_json("probe.json", {"stdout": '{"reply":"trace: preshared_key=fixture-shared"}'})
        self.assertEqual(self.check().returncode, 1)
        self.assertNotIn("fixture-shared", (self.root / "probe.json").read_text())
        for name in ["probe-pf-starters", "probe-dns-default", "wireguard-go", "storage.dmg"]:
            self.assertFalse((self.root / name).exists())

    def test_unicode_escaped_assignments_inside_embedded_json_are_quarantined(self):
        escaped = '{"reply":"private\\u005fkey\\u003dfixture-escaped"}'
        self.write_json("escaped.json", {"stdout": escaped})
        self.assertEqual(self.check().returncode, 1)
        self.assertNotIn("fixture-escaped", (self.root / "escaped.json").read_text())

    def test_capability_evidence_must_match_the_built_staged_and_executed_hashes(self):
        for name in ["built-capability-sha256.txt", "executed-capability-sha256.txt"]:
            (self.root / name).write_text(f"{SHA256}  /fixture/probe-pf-starters\n")
        (self.root / "wireguard-sha256.txt").write_text(f"{SHA256}  /fixture/wireguard-go\n")
        with (self.root / "executed-capability-sha256.txt").open("a") as staged:
            staged.write(f"{SHA256}  /fixture/wireguard-go\n")
        self.write_json("probe-identity-pf-starters.json", {"name":"pf-starters", "sha256":SHA256})
        self.assertEqual(self.check().returncode, 0)
        self.write_json("probe-identity-pf-starters.json", {"name":"pf-starters", "sha256":"b" * 64})
        self.assertEqual(self.check().returncode, 1)
        self.assertIn("quarantined", (self.root / "Q-SMOKE.json").read_text())


if __name__ == "__main__":
    unittest.main()
