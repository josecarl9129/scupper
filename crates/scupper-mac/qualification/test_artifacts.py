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


if __name__ == "__main__":
    unittest.main()
