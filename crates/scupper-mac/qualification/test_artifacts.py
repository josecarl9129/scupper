"""Portable executable-identity and redaction regression checks."""
import json
import hashlib
import os
import re
import ast
from pathlib import Path
import subprocess
import shlex
import sys
import tempfile
import unittest

CHECKER = Path(__file__).with_name("check-artifacts.py").resolve()
REPO = CHECKER.parents[3]
SHA256 = "a" * 64


class ArtifactTests(unittest.TestCase):
    def setUp(self):
        target_tmp = os.environ.get("CARGO_TARGET_TMPDIR")
        if target_tmp is None and os.environ.get("CARGO_TARGET_DIR"):
            target_tmp = str(Path(os.environ["CARGO_TARGET_DIR"]) / "tmp")
        if target_tmp is not None:
            Path(target_tmp).mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix=".qual-test-", dir=target_tmp)
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

    def test_flush_selectors_use_retaining_measurement_loop(self):
        contracts = (REPO / "crates/scupper-mac/src/qual/contracts.rs").read_text()
        flush = contracts[contracts.index("fn flush_measurement("):]
        self.assertEqual(flush.count("super::super::state_measure::selector_measurements("), 1)
        self.assertNotIn("drop(fresh)", flush)
        helper = (REPO / "crates/scupper-mac/src/qual/state_measure.rs").read_text()
        helper = helper[helper.index("pub(super) fn selector_measurements<"):]
        helper = helper[:helper.index("/// A state read")]
        self.assertEqual(helper.count("connections.push(fresh);"), 1)
        self.assertIn("with_cleanup(", helper)
        self.assertIn("Vec::clear", helper)

    def test_descendant_count_tracks_load_attempts_and_names_reviewed_skip(self):
        contracts = (REPO / "crates/scupper-mac/src/qual/contracts.rs").read_text()
        descendants = contracts[contracts.index("fn descendants("):contracts.index("fn anchor_lifecycle(")]
        self.assertNotIn("r.iterations = 9", descendants)
        self.assertNotIn("all descendant", descendants)
        measurements = contracts[contracts.index("fn descendant_measurements("):contracts.index("fn kernel_comparison(")]
        self.assertEqual(measurements.count("r.iterations += 1;"), 1)
        self.assertIn("r.iterations += 1;\n                    let load = raw(", measurements)
        self.assertLess(measurements.index("continue;"), measurements.index("r.iterations += 1;"))
        self.assertIn("skipped.push(name);", measurements)
        self.assertIn('"inline-multiline"', measurements)
        self.assertIn('skipped fixtures: {skipped:?}', measurements)
        self.assertIn('r.iterations = 0;', measurements)

    def test_review_sha256_matches_exact_golden_bytes(self):
        goldens = REPO / "crates/scupper-mac/qualification/goldens"
        for build in ["24H232", "25G332"]:
            review = json.loads((goldens / build / "review.json").read_text())
            self.assertEqual(set(review["sha256"]), {"lockdown.txt", "pretunnel-fixture.txt"})
            for name, expected in review["sha256"].items():
                self.assertEqual(hashlib.sha256((goldens / build / name).read_bytes()).hexdigest(), expected,
                                 f"{build}/{name} golden drift")

    def test_measurement_reviews_pin_udp_tcp_multiline_and_full_rejections(self):
        goldens = REPO / "crates/scupper-mac/qualification/goldens"
        for build in ["24H232", "25G332"]:
            review = json.loads((goldens / build / "measurement-review.json").read_text())
            self.assertEqual(review["build"], build)
            self.assertIs(review["states_v_reviewed"], True)
            self.assertEqual(review["protocol_allowlist"], ["udp", "tcp"])
            self.assertIs(review["states_vv_reviewed"], False)
            self.assertIs(review["descendants_reviewed"], False)
            self.assertTrue(review["inline_multiline_reviewed"])
            self.assertIn(f"{build}/anchor-children-inline-multiline.json", review["inline_multiline"]["provenance"])
            self.assertEqual(len(review["inline_multiline"]["facts"]), 3)
            observations = review["inline_multiline"]["normalized_observations"]
            self.assertEqual(observations["load"]["exit_code"], 0)
            self.assertEqual(observations["load"]["stdout"], "")
            self.assertEqual(observations["source"], "anchor {\n pass quick on lo0 all no state\n}\n")
            self.assertEqual(observations["parent_filter_stdout"], "anchor all {\n  pass quick on lo0 all no state\n}\n")
            self.assertEqual(observations["inventory_agreement"], "K=T at every level before and after")
            self.assertTrue(observations["after_parent_flush"]["rule_bearing_child_survives"])
            self.assertFalse(observations["after_parent_flush"]["empty_doubled_leaf_survives"])
            tcp = review["states_v_tcp"]
            self.assertEqual(hashlib.sha256((goldens / build / tcp["fixture"]).read_bytes()).hexdigest(), tcp["sha256"])
            text = (goldens / build / tcp["fixture"]).read_text()
            self.assertEqual(text.count("ALL tcp "), 5)
            self.assertEqual(text.count("ESTABLISHED:ESTABLISHED"), 5)
            refusal = review["underscore_flush_refusal"]
            self.assertTrue(refusal["reviewed"])
            self.assertEqual(refusal["classes"], ["rules", "nat", "Tables", "dummynet"])
            self.assertEqual(refusal["exit_code"], 1)
            self.assertEqual(refusal["stdout"], "")
            self.assertEqual(refusal["stderr"], "No ALTQ support in kernel\nALTQ related functions disabled\npfctl: anchor names beginning with '_' cannot be modified from the command line\n")
            self.assertEqual(hashlib.sha256((goldens / build / "states-v.txt").read_bytes()).hexdigest(),
                             review["states_v_sha256"])
            self.assertEqual({row["name"] for row in review["rejections"]}, {"underscore", "inline", "direct-underscore", "direct-grandchild-underscore"})
            for row in review["rejections"]:
                self.assertTrue(row["reviewed"])
                direct = row["name"].startswith("direct-")
                suffix = ("/f00003/_x" if row["name"] == "direct-underscore" else "/f00004/qchild/_x") if direct else ""
                self.assertEqual(row["command"], ["/sbin/pfctl", "-o", "none", "-a", "scupper-qual/children" + suffix, "-f", "-"])
                self.assertEqual(row["exit_code"], 1)
                self.assertEqual(row["stdout"], "")
                if direct:
                    self.assertEqual(row["stdin"], "pass quick on lo0 all no state\n")
                    self.assertIn("CI 45478867692", row["provenance"])
                    self.assertEqual(row["stderr"], "pfctl: Use of -f option, could result in flushing of rules\npresent in the main ruleset added by the system at startup.\nSee /etc/pf.conf for further details.\n\nNo ALTQ support in kernel\nALTQ related functions disabled\npfctl: anchor names beginning with '_' cannot be modified from the command line\n")
                else:
                    self.assertTrue(row["stderr"].endswith("pfctl: Syntax error in config file: pf rules not loaded\n"))
        a = json.loads((goldens / "24H232/measurement-review.json").read_text())["rejections"]
        b = json.loads((goldens / "25G332/measurement-review.json").read_text())["rejections"]
        self.assertEqual(a, b)

    def test_fix8_mutants_have_exactly_one_source_site(self):
        # Inspect the literal assignments only: never import/run the mutation driver.
        tree = ast.parse((REPO / "crates/scupper-mac/tests/r7_mutations.py").read_text())
        paths = {}
        mutants_node = None
        for node in tree.body:
            if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name):
                name = node.targets[0].id
                if (isinstance(node.value, ast.BinOp) and isinstance(node.value.left, ast.Name)
                        and node.value.left.id == "ROOT" and isinstance(node.value.right, ast.Constant)):
                    paths[name] = REPO / node.value.right.value
                if name == "MUTANTS":
                    mutants_node = node.value
        expected = {"underscore-refusal-is-success", "foreign-content-labelled-incomplete",
                    "process-sweep-retries-own-pid", "non-established-tcp-accepted",
                    "direct-underscore-refusal-accepts-any-stderr", "descendant-fixture-ignores-path-length-bound",
                    "path-length-cleanup-rereads-whole-tree", "path-length-budget-guard-ignored",
                    "path-length-altq-only-tables-is-missing", "path-length-mixed-classes-is-absent"}
        found = set()
        for row in mutants_node.elts:
            name = ast.literal_eval(row.elts[0])
            if name not in expected:
                continue
            found.add(name)
            path = paths[row.elts[1].id]
            site = ast.literal_eval(row.elts[2])
            self.assertEqual(path.read_text().count(site), 1, name)
        self.assertEqual(found, expected)

    def test_pass3_descendant_order_skip_and_read_only_flushes(self):
        native = (REPO / "crates/scupper-mac/src/qual/contracts.rs").read_text()
        start = native.index("for (name, source, suffix) in [")
        end = native.index("let parent = super::super::descendant_measure::fixture_parent(", start)
        campaign = native[start:end]
        names = ["named-inline", "wildcard", "grandchild", "direct-underscore",
                 "direct-grandchild-underscore", "named", "underscore", "inline", "inline-multiline"]
        positions = [campaign.index(f'"{name}"') for name in names]
        self.assertEqual(positions, sorted(positions))
        self.assertIn('inline_multiline_reviewed', campaign)
        self.assertIn('continue;', campaign)
        self.assertIn('"fixture_loaded":false', campaign)
        # Pass-4 direct creation refusals are now pinned reviewed rejections.
        for build in ["24H232", "25G332"]:
            review = json.loads((REPO / f"crates/scupper-mac/qualification/goldens/{build}/measurement-review.json").read_text())
            self.assertEqual({row["name"] for row in review["rejections"] if row["name"].startswith("direct-")},
                             {"direct-underscore", "direct-grandchild-underscore"})
        resources = (REPO / "crates/scupper-mac/src/qual/resources.rs").read_text()
        self.assertIn('skip_unmodifiable(&mut io, target, &mut failures)', resources)
        self.assertIn('skip_unmodifiable(&mut io, path, &mut failures)', resources)
        self.assertIn('read_only_underscore', resources)
        self.assertIn('flush-vv-identity-measurement.json', native)
        self.assertIn('vv_stability(&vv_before)', native)
        self.assertIn('vv_stability(&vv_reused)', native)
        self.assertIn('let reuse_attempt = udp.send_ten()', native)

    def test_path_length_measurements_follow_fixtures_and_remain_observational(self):
        native = (REPO / "crates/scupper-mac/src/qual/contracts.rs").read_text()
        campaign = native[native.index("fn descendant_measurements("):native.index("struct PathLengthIo")]
        self.assertLess(campaign.index("inventory_findings\n"), campaign.index("path_length_measurements(out,"))
        self.assertIn("&mut next_parent", campaign)
        helper = native[native.index("fn path_length_measurements("):native.index("fn kernel_comparison(")]
        self.assertIn("for nested in [false, true]", helper)
        self.assertIn("for length in LENGTHS", helper)
        self.assertIn("measurement_attempt(", helper)
        self.assertIn("cleanup_failure", helper)
        self.assertNotIn(".complete()", helper)
        self.assertNotIn("ContractViolation", helper)
        self.assertIn("anchor-children-path-length-summary.json", helper)
        self.assertIn("{length_detail}", campaign)

    def test_path_length_cleanup_is_scoped_and_freshness_is_complete(self):
        native = (REPO / "crates/scupper-mac/src/qual/contracts.rs").read_text()
        io = native[native.index("struct PathLengthIo"):native.index("fn path_length_measurements(")]
        self.assertIn("cleanup_length_sample", io)
        self.assertNotIn("cleanup_measurement(", io)
        resources = (REPO / "crates/scupper-mac/src/qual/resources.rs").read_text()
        helper = resources[resources.index("pub(super) fn cleanup_length_sample("):resources.index("pub(super) fn anchor_read(")]
        self.assertIn("cleanup_sample(", helper)
        self.assertIn("sample_classes_absent(self.io.out, path, self.io.deadline, own_child)", helper)
        self.assertNotIn("pfanchor::read", helper)
        self.assertNotIn("measurement_paths", helper)
        fresh = resources[resources.index("pub(super) fn fresh_length_sample("):resources.index("pub(super) fn cleanup_length_sample(")]
        self.assertEqual(fresh.count("qual_pf_rulesets(path)"), 2)
        self.assertIn("sample_classes_absent(out, path, deadline, None)", fresh)
        sweep = native[native.index("fn path_length_measurements("):native.index("fn kernel_comparison(")]
        self.assertIn('"skipped":skipped', sweep)
        self.assertIn('row["elapsed_before_evidence_write_ms"]', sweep)
        self.assertIn("excludes sample-row evidence write", sweep)
        self.assertIn("per-sample cost", sweep)

    def test_ruleset_probe_falls_back_and_records_header_provenance(self):
        header = REPO / "crates/scupper-darwin/probe/pf-rulesets-layout.h"
        # Select the absent branch in a copy without redefining compiler builtins.
        missing_header = self.root / "missing-layout.h"
        text = header.read_text()
        self.assertEqual(text.count("#if __has_include(<net/pfvar.h>)"), 1)
        missing_header.write_text(text.replace("#if __has_include(<net/pfvar.h>)", "#if 0", 1))
        net = self.root / "net"
        net.mkdir()
        synthetic = ("struct pfioc_ruleset { uint32_t nr; char path[1024]; char name[64]; };\n"
                     "#define DIOCGETRULESETS 0xC444443AUL\n#define DIOCGETRULESET 0xC444443BUL\n")
        pfvar = net / "pfvar.h"
        pfvar.write_text(synthetic)
        for present in [False, True]:
            with self.subTest(from_sdk_header=present):
                # BSD ioctl encoding for this portable synthetic-header test only.
                # This is not a compile against a macOS SDK.
                source = ('#include <stdint.h>\n#include <stddef.h>\n#include <stdio.h>\n#include <sys/ioctl.h>\n'
                          '#if !defined(__APPLE__)\n#undef _IOWR\n'
                          '#define _IOWR(g,n,t) (0xC0000000UL | (sizeof(t) << 16) | ((g) << 8) | (n))\n#endif\n'
                          '#include "' + str(header if present else missing_header) + '"\n'
                          'int main(void) { ruleset_layout(); return 0; }\n')
                c_file = self.root / "probe.c"
                c_file.write_text(source)
                binary = self.root / "probe"
                log = self.root / "abi-build.log"
                command = [os.environ.get("CC", "cc"), "-std=c11", "-Wall", "-Wextra", "-Werror", "-v", "-I", str(self.root),
                           str(c_file), "-o", str(binary)]
                compiled = subprocess.run(["bash", "-eo", "pipefail", "-c",
                                           shlex.join(command) + " 2>&1 | tee " + shlex.quote(str(log))],
                                          capture_output=True, text=True, check=False)
                self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
                self.assertIn("checking XNU-published layout pins" if present else
                              "XNU-published layout pin, not SDK-verified", log.read_text())
                measured = subprocess.run([str(binary)], capture_output=True, text=True, check=True)
                layout = json.loads("{" + measured.stdout.rstrip(",") + "}")
                self.assertIs(layout["pfioc_ruleset"]["from_sdk_header"], present)
                self.assertEqual(layout["pfioc_ruleset"]["layout_source"],
                                 "sdk-header" if present else "xnu-published-pin")
                self.assertEqual(layout["pfioc_ruleset"]["size"], 1092)
                self.assertEqual(layout["pfioc_ruleset"]["fields"], {"nr": 0, "path": 4, "name": 1028})
                self.assertEqual(layout["DIOCGETRULESETS"], 0xC444443A)
                self.assertEqual(layout["DIOCGETRULESET"], 0xC444443B)
        for broken in [synthetic.replace("#define DIOCGETRULESETS 0xC444443AUL", ""),
                       synthetic.replace("#define DIOCGETRULESET 0xC444443BUL", ""),
                       synthetic.replace("path[1024]", "path[1023]"),
                       synthetic.replace("0xC444443AUL", "0xC444443CUL")]:
            pfvar.write_text(broken)
            compiled = subprocess.run(command, capture_output=True, text=True, check=False)
            self.assertNotEqual(compiled.returncode, 0)
        native = (REPO / "crates/scupper-mac/src/qual/contracts.rs").read_text()
        self.assertNotIn('layout["pfioc_ruleset"]["from_sdk_header"] == true', native)
        self.assertIn('let from_sdk_header = layout["pfioc_ruleset"]["from_sdk_header"]', native)
        self.assertIn('from_sdk_header={from_sdk_header}', native)
        self.assertIn('XNU-published layout pin, not SDK-verified', native)
        if sys.platform == "darwin":
            # On macOS also compile the entire probe using the CI flags/pipeline.
            full_command = ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-v",
                            str(REPO / "crates/scupper-darwin/probe/abi.c"), "-o", str(binary)]
            full = subprocess.run(["bash", "-eo", "pipefail", "-c", shlex.join(full_command) +
                                   " 2>&1 | tee " + shlex.quote(str(log))],
                                  capture_output=True, text=True, check=False)
            self.assertEqual(full.returncode, 0, full.stdout + full.stderr)
            measured = subprocess.run([str(binary)], capture_output=True, text=True, check=True)
            self.assertIsInstance(json.loads(measured.stdout)["pfioc_ruleset"]["from_sdk_header"], bool)

    def test_anchor_state_issues_cannot_bypass_continuation_or_verdict_guard(self):
        source = (REPO / "crates/scupper-mac/src/qual/contracts.rs").read_text()
        lifecycle = source[source.index("fn anchor_lifecycle("):source.index("fn adapter_measurement_complete(")]
        scope = source[source.index("fn fall_scope("):source.index("fn flush(")]
        self.assertIn("state_measure::finish_anchor(r, &state_issues, env)", lifecycle)
        self.assertIn("states_every_time &= state_issues.is_empty()", lifecycle)
        self.assertEqual(lifecycle.count("state_measure::continue_after_read("), 1)
        self.assertEqual(scope.count("state_measure::continue_after_read("), 2)
        self.assertNotRegex(lifecycle + scope, r"known_id\([^;]*?\)\?")
        self.assertNotIn("state_ids(&states_after)?", scope)

    def test_inventory_findings_reach_case_verdict_and_restore_census_continues(self):
        source = (REPO / "crates/scupper-mac/src/qual/contracts.rs").read_text()
        campaign = source[source.index("fn descendant_measurements("):source.index("fn kernel_comparison(")]
        self.assertRegex(campaign, r"findings\.extend\(\s*inventory_findings\s*\.into_iter\(\)\s*\.map\(\|finding\| \(true, finding\)\),?\s*\)")
        case = source[source.index("fn descendants("):source.index("fn anchor_lifecycle(")]
        self.assertIn("desc_inventory::verdict(&findings)", case)
        self.assertLess(case.index("verdict != Verdict::ContractViolation"), case.index("r.verdict = verdict"))
        restore = (REPO / "crates/scupper-mac/src/qual/resources.rs").read_text()
        targets = restore[restore.index("for target in targets.iter().rev()"):restore.index('"pf state" =>')]
        self.assertNotIn("qual_pf_rulesets(target)?", targets)
        self.assertIn("anchor restore census: {target}: {error}", targets)
        self.assertIn("continue;", targets)

    def test_anchor_campaign_orders_and_isolates_descendants(self):
        source = (REPO / "crates/scupper-mac/src/qual/contracts.rs").read_text()
        campaign = source[source.index("fn anchors("):source.index("fn descendants(")]
        self.assertNotIn("optimizer_controls(", campaign)
        worker = source[source.index("pub(super) fn worker("):source.index("struct Harness")]
        self.assertLess(worker.index('("Q-FLUSH", flush)'), worker.index('("Q-DESCENDANTS", descendants)'))
        campaign = source[source.index("fn descendants("):source.index("fn anchor_lifecycle(")]
        self.assertLess(campaign.index("optimizer_controls("), campaign.index("foreign_fixtures("))
        self.assertLess(campaign.index("foreign_fixtures("), campaign.index("descendant_measurements("))
        foreign = source[source.index("fn foreign_fixtures("):source.index("fn descendant_measurements(")]
        self.assertNotIn('anchor \"', foreign)
        self.assertIn("read.is_err()", foreign)
        self.assertIn('const ROOT: &str = "scupper-qual/children"', source)
        self.assertIn('"measurement_only":true', source)
        recovery = (REPO / "crates/scupper-mac/src/qual/resources.rs").read_text()
        self.assertIn("super::super::resources::undo(", recovery)
        self.assertIn("|| super::tool::jobs_absent(out, deadline)", recovery)

    def test_qualification_never_uses_production_paths(self):
        paths = list((REPO / "crates/scupper-mac/src/qual").rglob("*.rs"))
        paths += [REPO / "crates/scupper-mac/src/platform/tests.rs",
                  REPO / "crates/scupper-mac/src/decode/qualification_trace.rs"]
        for path in paths:
            self.assertNotRegex(path.read_text(), r"Paths\s*::\s*production", str(path))
        native = (REPO / "crates/scupper-mac/src/native/mod.rs").read_text()
        self.assertIn('cfg(all(feature = "qualification", not(test)))', native)
        self.assertIn('paths.anchor_path() == "com.apple/scupper"', native)
        self.assertIn("paths.root.starts_with(PRODUCTION_ROOT)", native)
        self.assertIn("paths.lock == Path::new(PRODUCTION_LOCK)", native)
        self.assertIn("paths.control == Path::new(PRODUCTION_CONTROL)", native)
        stage = REPO / "crates/scupper-mac/src/qual/child_stage.rs"
        self.assertIn('const CHILD: &str = "/opt/scupper/wireguard-go"', stage.read_text())
        for path in paths:
            if path != stage and path.parent.name == "qual":
                self.assertNotIn('"/opt/scupper', path.read_text(), str(path))
                if path.name != "contracts.rs":
                    self.assertNotIn("child_stage::stage(", path.read_text(), str(path))
            self.assertNotRegex(path.read_text(), r'["\']/private/var/db/scupper(?:/|["\'])', str(path))
        contracts = (REPO / "crates/scupper-mac/src/qual/contracts.rs").read_text()
        self.assertIn("Path::new(super::super::child_stage::CHILD)", contracts)
        body = contracts[contracts.index("fn e2e("):contracts.index("fn e2e_scenarios(")]
        self.assertIn("child_stage::stage(&bytes", body)
        self.assertEqual(contracts.count("child_stage::stage("), 1)

    def test_shared_anchor_gate_only_blocks_anchor_work(self):
        source = (REPO / "crates/scupper-mac/src/qual/contracts.rs").read_text()
        worker = source[source.index("pub(super) fn worker("):source.index("struct Harness")]
        self.assertNotIn("shared_anchor_clean(out)?", worker)
        contracts = source[source.index("fn contracts("):source.index("fn seed(")]
        self.assertLess(contracts.index('"Q-CONTRACTS-core"'), contracts.index('"Q-CONTRACTS-anchor"'))
        self.assertGreater(contracts.index("shared_anchor_clean(out)?"), contracts.index('"Q-CONTRACTS-anchor"'))
        e2e = source[source.index("fn e2e_scenarios("):source.index("fn inventory(")]
        self.assertLess(e2e.index('"e2e-left.json"'), e2e.index("shared_anchor_clean(out)?"))
        self.assertLess(e2e.index("shared_anchor_clean(out)?"), e2e.index('"engine-join"'))

    def test_deep_descendant_targets_keep_the_adapter_namespace_fixed(self):
        source = (REPO / "crates/scupper-mac/src/qual/contracts.rs").read_text()
        campaign = source[source.index("fn descendant_measurements("):source.index("fn kernel_comparison(")]
        self.assertIn("journal_measurement_target(out, &parent)", campaign)
        self.assertIn("journal_measurement_target(out, &target)", campaign)
        self.assertNotIn("journal_anchor(out, &parent", campaign)
        self.assertNotIn("journal_anchor(out, &target", campaign)
        adapter = (REPO / "crates/scupper-mac/src/decode/pfanchor.rs").read_text()
        self.assertIn("components.len() != 2", adapter)

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
        # Extract only the pure function: never execute a mutation driver's module.
        path = REPO / "crates/scupper-mac/tests/r4_native_mutations.py"
        tree = ast.parse(path.read_text(), filename=str(path))
        function = next(node for node in tree.body
                        if isinstance(node, ast.FunctionDef) and node.name == "parse_worker_record")
        namespace = {"json": json}
        exec(compile(ast.Module(body=[function], type_ignores=[]), str(path), "exec"), namespace)
        parse = namespace["parse_worker_record"]
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

    def test_contract_scratch_copy_requires_the_built_source_digest(self):
        built = self.root / "built-binaries-sha256.txt"
        staged = self.root / "executed-binaries-sha256.txt"
        for manifest in [built, staged]:
            with manifest.open("a") as output:
                output.write(SHA256 + "  /fixture/wireguard-go\n")
        copied = dict(source_name="wireguard-go", source_sha256=SHA256, copy_sha256=SHA256)
        self.write_json("contract-copy-identities.json", copied)
        self.assertEqual(self.check().returncode, 0)
        for field in ["source_sha256", "copy_sha256"]:
            with self.subTest(field=field):
                self.write_json("contract-copy-identities.json", dict(copied, **{field: "b" * 64}))
                self.assertEqual(self.check().returncode, 1)
                self.write_json("contract-copy-identities.json", copied)
                self.write_json("Q-SMOKE.json", self.result)
                self.write_json("verdicts.json", [self.result])

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
