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
            summary.write(f"- {result['case']}: **{result['verdict']}**, {result['iterations']} iterations — {result['detail']}\n")
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
    if bad:
        print("Unredacted key assignments found; files quarantined:", *bad, sep="\n", file=sys.stderr)
        sys.exit(1)
