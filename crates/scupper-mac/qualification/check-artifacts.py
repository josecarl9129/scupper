#!/usr/bin/env python3
"""Check persisted text evidence; print all case verdicts in the Actions summary."""
import json
import os
from pathlib import Path
import re
import sys

root = Path(sys.argv[1])
# Native executables contain the redactor's literals; only text is publishable
# evidence. Do not upload executables as part of the qualification record.
if "--summary" in sys.argv:
    results = []
    unreadable = []
    for path in sorted(root.glob("Q-*.json")):
        try:
            results.append(json.loads(path.read_text()))
        except (ValueError, OSError):
            unreadable.append(path.name)
    with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as summary:
        summary.write(f"### Native macOS: {os.environ['QUAL_RUNNER']} / {os.environ['QUAL_GROUP']}\n\n")
        if not results:
            summary.write("No verdicts produced; inspect build, preflight and dead-man diagnostics.\n")
        for name in unreadable:
            summary.write(f"- {name}: unreadable or quarantined; inspect redaction diagnostics.\n")
        for result in results:
            summary.write(f"- {result['case']}: **{result['verdict']}**, SHA256 `{result.get('binary_sha256', 'missing')}`, {result['iterations']} iterations — {result['detail']}\n")
            if result["verdict"] == "inconclusive":
                print(f"::warning::{result['case']} inconclusive: {result['detail']}")
else:
    # The probe is needed until run completes. Remove it before artifact upload;
    # layout JSON and compiler evidence are retained.
    (root / "abi-probe").unlink(missing_ok=True)
    bad = []
    for path in sorted(root.rglob("*")):
        if path.is_file() and re.search(rb"(?:private_key|preshared_key)=", path.read_bytes(), re.I):
            bad.append(str(path))
            # Do not let always-upload publish a file that fails the check.
            path.write_text("[artifact quarantined: unredacted key assignment]\n")
    # Bind all verdicts to the just-built and actually executed harness. A
    # matching commit label alone does not establish executable identity.
    identity_errors = []
    if (root / "preflight.json").exists():
        try:
            built = (root / "built-harness-sha256.txt").read_text().split()[0]
            executed = (root / "executed-harness-sha256.txt").read_text().split()[0]
            preflight = json.loads((root / "preflight.json").read_text())["binary_sha256"]
            if not re.fullmatch(r"[0-9a-f]{64}", built) or built != executed or built != preflight:
                identity_errors.append("built, staged and preflight harness SHA256s differ")
            verdicts = [json.loads(path.read_text()) for path in sorted(root.glob("Q-*.json"))]
            if (root / "verdicts.json").exists():
                verdicts.extend(json.loads((root / "verdicts.json").read_text()))
            for result in verdicts:
                if result.get("binary_sha256") != built:
                    identity_errors.append(f"{result.get('case', 'unknown case')}: harness SHA256 mismatch")
        except (OSError, ValueError, KeyError, IndexError, TypeError, AttributeError) as error:
            identity_errors.append(f"missing or invalid executable identity evidence: {error}")
    elif list(root.glob("Q-*.json")) or (root / "verdicts.json").exists():
        identity_errors.append("verdicts exist without preflight executable identity evidence")
    if identity_errors:
        # Always-upload must never publish a stale verdict as valid evidence.
        for path in [*root.glob("Q-*.json"), root / "verdicts.json"]:
            if path.exists():
                path.write_text("[artifact quarantined: executable identity mismatch]\n")
        print(*identity_errors, sep="\n", file=sys.stderr)
    if bad:
        print("Unredacted key assignments found; files quarantined:", *bad, sep="\n", file=sys.stderr)
    if bad or identity_errors:
        sys.exit(1)
