#!/usr/bin/env python3
"""Check persisted text evidence; print all case verdicts in the Actions summary."""
import json
import os
from pathlib import Path
import re
import sys

root = Path(sys.argv[1])

ASSIGNMENT = re.compile(r"(?:private_key|preshared_key)=", re.I)
MACH_MAGICS = {bytes.fromhex(magic) for magic in (
    "cf fa ed fe", "ce fa ed fe", "fe ed fa cf", "fe ed fa ce",
    "ca fe ba be", "be ba fe ca",
)}


def contains_assignment(value, depth=0):
    """Inspect decoded JSON as well as its serialized/embedded text."""
    if depth > 8:
        return False
    if isinstance(value, str):
        if ASSIGNMENT.search(value):
            return True
        try:
            nested = json.loads(value)
        except (ValueError, TypeError):
            return False
        return contains_assignment(nested, depth + 1) if nested != value else False
    if isinstance(value, dict):
        return any(contains_assignment(k, depth + 1) or contains_assignment(v, depth + 1)
                   for k, v in value.items())
    if isinstance(value, list):
        return any(contains_assignment(v, depth + 1) for v in value)
    return False


def unsafe_text(data):
    text = data.decode("utf-8", errors="replace")
    if contains_assignment(text):
        return True
    return any(contains_assignment(line) for line in text.splitlines())

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
    binaries = ["abi-probe", "wireguard-go", "scratch-sleep", "renamed-sleep", "hard-sleep", "storage.dmg"]
    binaries += ["probe-" + name for name in ["pf-starters", "pf-eexist", "proc-identity", "utun-handoff", "storage", "sc-session", "dns-keys", "dns-default"]]
    for name in binaries:
        for path in root.rglob(name):
            if path.is_file() or path.is_symlink():
                path.unlink()
    for path in root.rglob("*"):
        if path.is_file() and not path.is_symlink():
            with path.open("rb") as artifact:
                magic = artifact.read(4)
            if magic in MACH_MAGICS or path.suffix.lower() in {".dmg", ".sparseimage", ".sparsebundle", ".iso", ".cdr", ".img"}:
                path.unlink()
    bad = []
    for path in sorted(root.rglob("*")):
        if path.is_file() and unsafe_text(path.read_bytes()):
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
            built_abi = (root / "built-abi-sha256.txt").read_text().split()[0]
            staged_abi = (root / "executed-probe-sha256.txt").read_text().split()[0]
            if not re.fullmatch(r"[0-9a-f]{64}", built_abi) or built_abi != staged_abi:
                identity_errors.append("built and staged ABI probe hashes differ")
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
    def hash_map(path):
        values = {}
        for line in path.read_text().splitlines():
            digest, filename = line.split(maxsplit=1)
            name = Path(filename.strip()).name
            if not re.fullmatch(r"[0-9a-f]{64}", digest) or name in values:
                raise ValueError("invalid or duplicate capability hash")
            values[name] = digest
        return values

    # Every staging loop emits a complete manifest, including isolated mutants.
    # Visit nested experiment records even when they have no exported verdict.
    manifest_dirs = {path.parent for pattern in ["built-binaries-sha256.txt", "executed-binaries-sha256.txt"]
                     for path in root.rglob(pattern)}
    for directory in sorted(manifest_dirs):
        try:
            built_all = hash_map(directory / "built-binaries-sha256.txt")
            staged_all = hash_map(directory / "executed-binaries-sha256.txt")
            if not built_all or built_all != staged_all:
                identity_errors.append(f"{directory.name}: complete built/staged binary manifests differ")
        except (OSError, ValueError) as error:
            identity_errors.append(f"incomplete staged binary manifest: {error}")

    identities = sorted(root.glob("probe-identity-*.json"))
    qproc_patterns = ["Q-STORE*", "store-*.json", "Q-TOOL*", "Q-LAUNCHD*", "Q-LOCK*", "tool-*.json", "Q-PROC*", "base-proc*", "proc-churn.json", "base-oracle.json",
                      "oracle-*.log", "base-stopped*", "base-unlinked*", "base-paths.json",
                      "base-image*.json", "base-pin-images.json", "base-initial-snapshot.*",
                      "path-oracle.log", "pathless-census.json"]
    if (identities or (root / "executed-capability-sha256.txt").exists()
            or any(any(root.glob(pattern)) for pattern in qproc_patterns)
            or any((root / name).exists() for name in [
                "built-capability-sha256.txt", "wireguard-sha256.txt",
                "base-churn-sha256.txt", "base-image-sha256.txt", "tool-sha256.txt"])):
        try:
            built_probes = {}
            def merge_built(path):
                values = hash_map(path)
                if built_probes.keys() & values.keys():
                    raise ValueError("duplicate binary across built manifests")
                built_probes.update(values)
            for name in ["built-capability-sha256.txt", "wireguard-sha256.txt"]:
                if identities or (root / name).exists():
                    merge_built(root / name)
            # Every cell stages the base churn helper next to the probes.
            base_churn = root / "base-churn-sha256.txt"
            if base_churn.exists():
                merge_built(base_churn)
            base_images = root / "base-image-sha256.txt"
            if base_images.exists():
                merge_built(base_images)
            tool_helpers = root / "tool-sha256.txt"
            if tool_helpers.exists():
                merge_built(tool_helpers)
            staged_probes = hash_map(root / "executed-capability-sha256.txt")
            if built_probes != staged_probes:
                identity_errors.append("built and staged capability hashes differ")
            for path in identities:
                entry = json.loads(path.read_text())
                if entry["sha256"] != staged_probes.get("probe-" + entry["name"]):
                    identity_errors.append("executed probe hash differs from stage")
                if entry.get("wireguard_sha256") is not None and entry["wireguard_sha256"] != staged_probes.get("wireguard-go"):
                    identity_errors.append("executed wireguard-go hash differs from stage")
        except (OSError, ValueError, KeyError, TypeError) as error:
            identity_errors.append(f"invalid capability identity evidence: {error}")
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
