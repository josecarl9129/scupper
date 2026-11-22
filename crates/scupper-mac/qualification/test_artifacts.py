"""Portable executable-identity and redaction regression checks."""
import json
import os
import re
import runpy
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
        for name in ["built-abi-sha256.txt", "executed-probe-sha256.txt"]:
            (self.root / name).write_text(f"{SHA256}  abi-probe\n")
        for name in ["built-binaries-sha256.txt", "executed-binaries-sha256.txt"]:
            (self.root / name).write_text(f"{SHA256}  harness\n{SHA256}  abi-probe\n")
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

    def test_pf_contract_and_stale_measurement_have_separate_artifacts(self):
        manifest = json.loads((REPO / "crates/scupper-mac/qualification/manifest.json").read_text())
        cases = {case["id"]: case for case in manifest["cases"]}
        self.assertEqual(cases["Q-X"]["supported_assumptions"], ["disable_voids_references"])
        self.assertEqual(cases["Q-X-STALE"]["supported_assumptions"], [])
        self.assertEqual(cases["Q-X"]["group"], "pf-x")
        self.assertEqual(cases["Q-X-STALE"]["group"], "pf-x-stale")
        workflow = (REPO / ".github/workflows/ci.yml").read_text()
        self.assertIn("pf, pf-x, pf-x-stale, probe", workflow)
        contract = dict(self.result, case="Q-X", verdict="assumption_holds", iterations=3)
        stale = dict(self.result, case="Q-X-STALE", verdict="measurement", iterations=1)
        self.write_json("Q-X.json", contract)
        self.write_json("Q-X-STALE.json", stale)
        self.write_json("verdicts.json", [contract, stale])
        self.assertEqual(self.check().returncode, 0)
        summary = self.root / "pf-summary.txt"
        env = dict(os.environ, GITHUB_STEP_SUMMARY=str(summary), QUAL_RUNNER="fixture", QUAL_GROUP="pf-x")
        self.assertEqual(self.check("--summary", env=env).returncode, 0)
        self.assertIn("Q-X: **assumption_holds**", summary.read_text())
        self.assertIn("Q-X-STALE: **measurement**", summary.read_text())

    def test_missing_both_complete_manifests_rejects_verdicts(self):
        for name in ["built-binaries-sha256.txt", "executed-binaries-sha256.txt"]:
            (self.root / name).unlink()
        result = self.check()
        self.assertEqual(result.returncode, 1)
        self.assertIn("incomplete staged binary manifest", result.stderr)

    def test_native_full_sync_checks_fcntl_without_fallback(self):
        darwin = REPO / "crates/scupper-darwin/src"
        source = (darwin / "sys.rs").read_text()
        body = source.split("pub fn full_sync(", 1)[1]
        self.assertIn("libc::fcntl(fd.as_fd().as_raw_fd(), libc::F_FULLFSYNC)", body)
        self.assertIn("if rc == -1 { Err(last_errno()) } else { Ok(()) }", body)
        self.assertIn("pub const FULLFSYNC_COMMAND: i32 = libc::F_FULLFSYNC;", source)
        self.assertIn("const _: () = assert!(libc::F_FULLFSYNC == 51);", source)
        storage = REPO / "crates/scupper-mac/src/platform/storage.rs"
        for path in [*darwin.rglob("*.rs"), storage, storage.with_suffix("") / "darwin.rs"]:
            self.assertNotIn("fsync(", path.read_text(), str(path))
        probe = (REPO / "crates/scupper-darwin/probe/abi.c").read_text()
        self.assertIn('_Static_assert(F_FULLFSYNC == 51, "full-sync command")', probe)
        self.assertIn('printf("{\\"F_FULLFSYNC\\":%d,", F_FULLFSYNC)', probe)
        qualification = (REPO / "crates/scupper-mac/src/qual/store.rs").read_text()
        self.assertIn('abi["F_FULLFSYNC"].as_i64() == Some(i64::from(scupper_darwin::FULLFSYNC_COMMAND))', qualification)

    def test_store_full_path_never_reclaims_before_detach(self):
        source = (REPO / "crates/scupper-mac/src/qual/store.rs").read_text()
        # Path checks may resize short fixtures on the unfilled image only.
        full_path = source.split("fn fixtures(", 1)[1].split("fn path_checks(", 1)[0]
        self.assertNotIn("set_len(", full_path)
        self.assertNotIn("fs::rename(", full_path)
        self.assertNotIn('remove_file(root.join("filler"))', source)
        for removed in ["reclaim_for_concurrency", "RECLAIM_RETRIES", "reclaim-slack",
                        "reserved-b", "full/concurrency_reset", "store-full-concurrency.json"]:
            self.assertNotIn(removed, source)
        fixtures = full_path.split("fn full_race(", 1)[0]
        self.assertIn("synced(&mut p, root, Copy::A, old, true, end)", fixtures)
        # B stays absent: creating it would force an unlink on the full image.
        self.assertNotIn("Copy::B", fixtures)
        self.assertIn("racing_valid_reads", source)
        loops = source.split("fn fault_loops(", 1)[1].split("fn ordinary(", 1)[0]
        self.assertLess(loops.index('"full/fill"'), loops.index('"full/race"'))
        self.assertLess(loops.index('"full/race"'), loops.index('"{label}/fault_loop"'))
        self.assertRegex(loops, r'if !full \{\s*phase\(phases, out, "unfilled/concurrency"')
        restore = source.split("pub(super) fn restore_tree(", 1)[1]
        self.assertIn("after all fixture images were detached", source)
        self.assertIn("fs::remove_dir_all(&entry.path)", restore)

    def test_native_mutation_worker_record_is_checked_before_parsing(self):
        driver = runpy.run_path(str(REPO / "crates/scupper-mac/tests/r4_native_mutations.py"))
        parse = driver["parse_worker_record"]
        diagnostics = "worker stderr: died\nlaunchd job status: last exit code = 9"
        for code, text in [(1, ""), (0, ""), (0, " \n"), (1, '{"error":"expected"}')]:
            with self.subTest(returncode=code, stdout=text):
                failure = subprocess.CompletedProcess([], code, stdout=text)
                with self.assertRaises(AssertionError) as error:
                    parse("omit-sigchld-check", failure, diagnostics)
                message = str(error.exception)
                self.assertIn("worker record missing, empty or unreadable", message)
                self.assertIn("omit-sigchld-check", message)
                self.assertIn(diagnostics, message)
        failure = subprocess.CompletedProcess([], 0, stdout='{"error":"expected"}')
        self.assertEqual(parse("fixture", failure, diagnostics), {"error": "expected"})

    def test_abi_probe_stringifies_member_before_macro_expansion(self):
        source = (REPO / "crates/scupper-darwin/probe/abi.c").read_text()
        macros = "\n".join(line for line in source.splitlines()
                           if line.startswith(("#define FIELD(", "#define NEXT_FIELD(")))
        shim = (macros + "\n#define p_starttime p_un.__p_starttime\n"
                "NEXT_FIELD(kinfo_proc, kp_proc.p_starttime);\n"
                "NEXT_FIELD(kinfo_proc, kp_proc.p_starttime.tv_sec);\n"
                "NEXT_FIELD(kinfo_proc, kp_proc.p_starttime.tv_usec);\n")
        result = subprocess.run(["cc", "-E", "-P", "-x", "c", "-"], input=shim,
                                capture_output=True, text=True, check=True)
        for member in ["kp_proc.p_starttime", "kp_proc.p_starttime.tv_sec",
                       "kp_proc.p_starttime.tv_usec"]:
            self.assertIn('"' + member + '"', result.stdout)
        self.assertNotIn('"kp_proc.p_un.__p_starttime', result.stdout)
        self.assertIn("offsetof(struct kinfo_proc, kp_proc.p_un.__p_starttime)",
                      result.stdout)

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

    def test_scoped_recovery_exports_only_text(self):
        scope = self.root / "scope-storage"
        scope.mkdir()
        for name in ["storage.dmg", "scratch-sleep", "renamed-sleep", "hard-sleep"]:
            (scope / name).write_bytes(b"fixture binary")
        (scope / "resources.jsonl").write_text('{"kind":"image","path":"fixture"}\n')
        self.assertEqual(self.check().returncode, 0)
        self.assertEqual([path.name for path in scope.iterdir()], ["resources.jsonl"])

    def test_magic_removes_unknown_probes_before_redaction(self):
        scope = self.root / "nested"
        scope.mkdir()
        names = []
        for index, magic in enumerate(["cf fa ed fe", "ce fa ed fe", "fe ed fa cf",
                                       "fe ed fa ce", "ca fe ba be", "be ba fe ca"]):
            path = scope / ("probe-dns-default-minimal" if index == 0 else f"unknown-{index}")
            path.write_bytes(bytes.fromhex(magic) + b"private_key=compiled literal")
            names.append(path)
        for name in ["unknown.dmg", "other.DMG", "scratch.sparseimage", "optical.iso"]:
            path = scope / name
            path.write_bytes(b"preshared_key=image fixture")
            names.append(path)
        text = scope / "keep.json"
        text.write_text('{"fixture":"retained"}\n')
        (scope / "short.txt").write_bytes(b"\xcf\xfa\xed")
        result = self.check()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(all(not path.exists() for path in names))
        self.assertEqual(text.read_text(), '{"fixture":"retained"}\n')
        self.assertTrue((scope / "short.txt").exists())

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


    def test_built_capabilities_and_qproc_require_executed_manifest(self):
        for name in ["built-capability-sha256.txt", "wireguard-sha256.txt",
                     "base-churn-sha256.txt", "base-image-sha256.txt", "Q-PROC.json",
                     "base-processes.json", "base-pin-images.json", "base-stopped-inventory.json",
                     "base-images.json", "proc-churn.json"]:
            with self.subTest(name=name):
                path = self.root / name
                path.write_text(f"{SHA256}  /fixture/base-churn\n")
                result = self.check()
                self.assertEqual(result.returncode, 1)
                self.assertIn("executed-capability-sha256.txt", result.stderr)
                path.unlink()

    def test_staged_base_churn_counts_as_built_capability(self):
        (self.root / "built-capability-sha256.txt").write_text(f"{SHA256}  qual-out/probe-pf-starters\n")
        (self.root / "wireguard-sha256.txt").write_text(f"{SHA256}  qual-out/wireguard-go\n")
        (self.root / "executed-capability-sha256.txt").write_text(
            f"{SHA256}  /private/var/db/scupper-qual/probe-pf-starters\n"
            f"{SHA256}  /private/var/db/scupper-qual/wireguard-go\n"
            f"{SHA256}  /private/var/db/scupper-qual/base-churn\n")
        self.write_json("probe-identity-pf-starters.json", {"name":"pf-starters", "sha256":SHA256})
        self.assertEqual(self.check().returncode, 1)
        (self.root / "Q-SMOKE.json").write_text(json.dumps(self.result))
        self.write_json("verdicts.json", [self.result])
        (self.root / "base-churn-sha256.txt").write_text(f"{SHA256}  qual-out/base-churn\n")
        self.assertEqual(self.check().returncode, 0)
        (self.root / "base-churn-sha256.txt").write_text(f"{'b' * 64}  qual-out/base-churn\n")
        self.assertEqual(self.check().returncode, 1)

    def test_staged_base_images_require_matching_built_hashes(self):
        (self.root / "built-capability-sha256.txt").write_text(f"{SHA256}  qual-out/probe-pf-starters\n")
        (self.root / "wireguard-sha256.txt").write_text(f"{SHA256}  qual-out/wireguard-go\n")
        (self.root / "executed-capability-sha256.txt").write_text(
            "".join(f"{SHA256}  /fixture/{name}\n" for name in
                    ["probe-pf-starters", "wireguard-go", "base-image-a", "base-image-b"]))
        self.write_json("probe-identity-pf-starters.json", {"name":"pf-starters", "sha256":SHA256})
        self.assertEqual(self.check().returncode, 1)
        self.write_json("Q-SMOKE.json", self.result)
        self.write_json("verdicts.json", [self.result])
        (self.root / "base-image-sha256.txt").write_text(
            "".join(f"{SHA256}  qual-out/base-image-{name}\n" for name in ["a", "b"]))
        self.assertEqual(self.check().returncode, 0)
        (self.root / "base-image-sha256.txt").write_text(f"{SHA256}  qual-out/base-image-a\n")
        self.assertEqual(self.check().returncode, 1)

    def test_base_cell_hashes_are_checked_without_probe_identity(self):
        (self.root / "executed-capability-sha256.txt").write_text(f"{SHA256}  /fixture/base-image-a\n")
        (self.root / "base-image-sha256.txt").write_text(f"{SHA256}  /fixture/base-image-a\n")
        self.assertEqual(self.check().returncode, 0)
        (self.root / "base-image-sha256.txt").write_text(f"{'b' * 64}  /fixture/base-image-a\n")
        self.assertEqual(self.check().returncode, 1)

    def test_abi_probe_built_hash_is_required_and_matches_stage(self):
        (self.root / "built-abi-sha256.txt").unlink()
        self.assertEqual(self.check().returncode, 1)
        (self.root / "built-abi-sha256.txt").write_text(f"{'b' * 64}  abi-probe\n")
        self.assertEqual(self.check().returncode, 1)

    def test_tool_helper_manifest_is_required_and_checked(self):
        (self.root / "executed-capability-sha256.txt").write_text(f"{SHA256}  /fixture/tool-child\n")
        self.assertEqual(self.check().returncode, 1)
        (self.root / "tool-sha256.txt").write_text(f"{SHA256}  qual-out/tool-child\n")
        self.write_json("Q-SMOKE.json", self.result)
        self.write_json("verdicts.json", [self.result])
        self.assertEqual(self.check().returncode, 0)
        (self.root / "tool-sha256.txt").write_text(f"{'b' * 64}  qual-out/tool-child\n")
        self.assertEqual(self.check().returncode, 1)

    def test_rosetta_helper_digest_is_required_and_matches_stage(self):
        (self.root / "executed-capability-sha256.txt").write_text(
            f"{SHA256}  /fixture/tool-child\n{'c' * 64}  /fixture/tool-child-x86_64\n")
        (self.root / "tool-sha256.txt").write_text(f"{SHA256}  qual-out/tool-child\n")
        self.assertEqual(self.check().returncode, 1)
        (self.root / "tool-sha256.txt").write_text(
            f"{SHA256}  qual-out/tool-child\n{'c' * 64}  qual-out/tool-child-x86_64\n")
        self.write_json("Q-SMOKE.json", self.result)
        self.write_json("verdicts.json", [self.result])
        self.assertEqual(self.check().returncode, 0)
        (self.root / "tool-sha256.txt").write_text(
            f"{SHA256}  qual-out/tool-child\n{'d' * 64}  qual-out/tool-child-x86_64\n")
        self.assertEqual(self.check().returncode, 1)

    def test_store_evidence_requires_built_and_staged_manifests(self):
        self.write_json("Q-STORE.json", dict(self.result, case="Q-STORE"))
        result = self.check()
        self.assertEqual(result.returncode, 1)
        self.assertIn("executed-capability-sha256.txt", result.stderr)

    def test_every_staged_helper_has_a_checked_built_hash(self):
        manifests = {
            "base-churn-sha256.txt": ["base-churn"],
            "base-image-sha256.txt": ["base-image-a", "base-image-b"],
            "wireguard-sha256.txt": ["wireguard-go"],
            "tool-sha256.txt": ["tool-child", "tool-child-x86_64", "tool-child-utun", "tool-child-utun-stale"],
            "built-capability-sha256.txt": ["probe-" + path.stem for path in
                sorted((REPO / "crates/scupper-mac/qualification/probes").glob("*.c"))],
        }
        for name, binaries in manifests.items():
            (self.root / name).write_text("".join(f"{SHA256}  qual-out/{binary}\n" for binary in binaries))
        (self.root / "executed-capability-sha256.txt").write_text("".join(
            f"{SHA256}  /fixture/{binary}\n" for binaries in manifests.values() for binary in binaries))
        self.assertEqual(self.check().returncode, 0)
        for name, binaries in manifests.items():
            for binary in binaries:
                with self.subTest(binary=binary):
                    path = self.root / name
                    original = path.read_text()
                    path.write_text(original.replace(f"{SHA256}  qual-out/{binary}\n", f"{'b' * 64}  qual-out/{binary}\n"))
                    self.write_json("Q-SMOKE.json", self.result)
                    self.write_json("verdicts.json", [self.result])
                    self.assertEqual(self.check().returncode, 1)
                    path.write_text(original)

    def test_duplicate_binary_across_built_manifests_is_rejected(self):
        for name in ["base-churn-sha256.txt", "tool-sha256.txt", "executed-capability-sha256.txt"]:
            (self.root / name).write_text(f"{SHA256}  /fixture/base-churn\n")
        self.assertEqual(self.check().returncode, 1)

    def test_complete_staging_manifest_including_nested_experiments(self):
        for directory in [self.root, self.root / "mutations" / "experiment"]:
            directory.mkdir(parents=True, exist_ok=True)
            built = directory / "built-binaries-sha256.txt"
            staged = directory / "executed-binaries-sha256.txt"
            manifest = f"{SHA256}  harness\n{'b' * 64}  abi-probe\n"
            built.write_text(manifest)
            staged.write_text(manifest)
            self.write_json("Q-SMOKE.json", self.result)
            self.write_json("verdicts.json", [self.result])
            self.assertEqual(self.check().returncode, 0)
            for wrong in [f"{SHA256}  harness\n", manifest.replace('b' * 64, 'c' * 64), manifest + f"{SHA256}  extra\n"]:
                staged.write_text(wrong)
                self.assertEqual(self.check().returncode, 1)
            staged.write_text(manifest)
            built.unlink()
            self.assertEqual(self.check().returncode, 1)
            built.write_text(manifest)
            staged.write_text(manifest)


if __name__ == "__main__":
    unittest.main()
