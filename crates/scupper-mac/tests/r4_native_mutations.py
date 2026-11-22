#!/usr/bin/env python3
"""Native R4 mutation assertions, on disposable root-staged macOS runners only.

Run as the runner user after staging /private/var/db/scupper-qual, in the dedicated tool-mutants CI group. Each experiment has its own preflight, binary identity,
fsynced resource journal and independently armed restore. Never run cargo as root.
"""
from pathlib import Path
import hashlib
import json
import os
import platform
import subprocess
import time

ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / "crates/scupper-darwin/src/sys.rs"
NATIVE = ROOT / "crates/scupper-mac/src/native/mod.rs"
STAGE = Path("/private/var/db/scupper-qual")
LOGS = ROOT / "qual-out/r4-native-mutations"
ENV = dict(os.environ, CARGO_BUILD_JOBS="2", RUST_TEST_THREADS="2")
SUDO = ["/usr/bin/sudo", "--preserve-env=GITHUB_ACTIONS,RUNNER_ENVIRONMENT"]
MUTANTS = [
    ("omit-sigchld-check", SOURCE, "    check_sigchld()?;\n", "",
     "SIGCHLD unsafe disposition allowed spawn"),
    ("omit-cloexec-default", SOURCE, "            | libc::POSIX_SPAWN_CLOEXEC_DEFAULT", "",
     "CLOEXEC_DEFAULT assertion: raw/tool/NativePlatform inherited planted fd or lock dup"),
    ("omit-utun-crosscheck", NATIVE,
     "if crate::platform::runtime::utun_crosscheck(protected_socket).is_err() {",
     "if false && crate::platform::runtime::utun_crosscheck(protected_socket).is_err() {",
     "utun cross-check assertion: uncorroborated control-unit name accepted"),
    ("accept-socket-without-child-listener", NATIVE,
     "let child_listening = !listeners.is_empty() && listeners.iter().all(|path| *path == socket);",
     "let child_listening = true;",
     "utun cross-check assertion: socket without child listener accepted"),
]


def command(args, *, check=True):
    return subprocess.run(args, cwd=ROOT, env=ENV, check=check,
                          capture_output=True, text=True)


def privileged(args, *, check=True):
    return command(SUDO + args, check=check)


def experiment(name, expected):
    started = time.monotonic()
    build = command(["cargo", "build", "-p", "scupper-mac", "--bin",
                     "scupper-mac-qual", "--features", "qualification", "--locked"])
    (LOGS / f"{name}-build.log").write_text(build.stdout + build.stderr)
    stage = STAGE / f"mutation-{name}"
    # install -d must never follow an existing or planted path.
    assert privileged(["/bin/test", "-e", str(stage)], check=False).returncode != 0
    assert privileged(["/bin/test", "-L", str(stage)], check=False).returncode != 0
    privileged(["/usr/bin/install", "-d", "-o", "root", "-g", "wheel", "-m", "0700", str(stage)])
    manifests = LOGS / name
    manifests.mkdir()
    built = []
    executed = []
    # Helper provenance comes from the top-level built-binaries manifest covering
    # qual-out; these experiment manifests additionally prove each installed copy.
    for binary in [ROOT / "target/debug/scupper-mac-qual", ROOT / "qual-out/abi-probe", ROOT / "qual-out/tool-child", ROOT / "qual-out/tool-child-utun", ROOT / "qual-out/tool-child-utun-stale"]:
        digest = hashlib.sha256(binary.read_bytes()).hexdigest()
        built.append(f"{digest}  {binary.name}\n")
        (manifests / "built-binaries-sha256.txt").write_text("".join(built))
        privileged(["/usr/bin/install", "-o", "root", "-g", "wheel", "-m", "0755", str(binary), str(stage / binary.name)])
        staged = privileged(["/usr/bin/shasum", "-a", "256", str(stage / binary.name)]).stdout
        executed.append(staged)
        (manifests / "executed-binaries-sha256.txt").write_text("".join(executed))
        assert staged.split()[0] == digest, (name, binary.name, "built/staged hash mismatch")
    command(["python3", "crates/scupper-mac/qualification/check-artifacts.py", str(manifests)])
    executable = str(stage / "scupper-mac-qual")
    out = stage / "evidence"
    args = ["--out", str(out), "--disposable-runner"]
    try:
        privileged([executable, "preflight", *args])
        privileged([executable, "arm", "--after", "600", *args])
        result = privileged([executable, "r4-tools", *args], check=False)
        stderr = privileged(["/bin/cat", str(out / "tool-worker-tools.stderr.log")], check=False)
        failure = privileged(["/bin/cat", str(out / "tool-worker-tools.json")], check=False)
        (LOGS / f"{name}-assertion.log").write_text(result.stdout + result.stderr + stderr.stdout + failure.stdout)
        if expected is None:
            assert result.returncode == 0, result.stderr + stderr.stdout
        else:
            record = json.loads(failure.stdout)
            assert result.returncode != 0 and expected in record.get("error", ""), (name, result.stderr, record)
            if name == "omit-cloexec-default":
                # Each path must independently detect BOTH deliberately inheritable
                # descriptors. Do not credit an earlier raw-spawn failure alone.
                observed = privileged(["/bin/cat", str(out / "tool-fd-isolation.json")])
                (LOGS / f"{name}-tables.json").write_text(observed.stdout)
                tables = json.loads(observed.stdout)
                for family in ["raw", "tool", "native"]:
                    assert not tables[f"{family}_isolated"], (family, tables)
                    assert all(fd in tables[family] for fd in tables["planted"]), (family, tables)
            print(f"KILLED by native qualification assertion: {name}", flush=True)
    finally:
        restored = privileged([executable, "restore", *args], check=False)
        (LOGS / f"{name}-restore.log").write_text(restored.stdout + restored.stderr)
        elapsed = time.monotonic() - started
        (LOGS / f"{name}-timing.json").write_text(json.dumps({"experiment": name, "wall_seconds": elapsed}) + "\n")
        print(f"TIMING {name}: {elapsed:.3f} s (build/preflight/arm/assertion/restore)", flush=True)
        # Preserve independent recovery until restore has succeeded.
        assert restored.returncode == 0, restored.stdout + restored.stderr
        service = f"system/net.scupper.qual.restore-mutation-{name}"
        privileged(["/bin/launchctl", "bootout", service], check=False)
        assert privileged(["/bin/launchctl", "print", service], check=False).returncode != 0
        # Retain protected experiment evidence for inspection; only the
        # journaled fixture tree is removed by restore, never recursive shell rm.


if __name__ == "__main__":
    assert platform.system() == "Darwin", "native mutations require macOS"
    assert ENV.get("GITHUB_ACTIONS") == "true" and ENV.get("RUNNER_ENVIRONMENT") == "github-hosted"
    LOGS.mkdir(parents=True, exist_ok=True)
    originals = {path: path.read_bytes() for path in [SOURCE, NATIVE]}
    try:
        for name, path, before, after, expected in MUTANTS:
            source = originals[path].decode()
            assert source.count(before) == 1, (name, "mutation anchor not unique")
            path.write_text(source.replace(before, after))
            try:
                experiment(name, expected)
            finally:
                path.write_bytes(originals[path])
    finally:
        for path, original in originals.items():
            path.write_bytes(original)
    assert all(path.read_bytes() == original for path, original in originals.items())
    experiment("restored-baseline", None)
    print("RESTORED: exact native/sys.rs bytes; native raw/tool/spawn baseline passed", flush=True)
