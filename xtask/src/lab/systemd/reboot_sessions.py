"""Observe fresh-device readiness without resetting the client's old session."""
import json
import subprocess
import sys
import time
from pathlib import Path

cli, log_path, started_path, reset_seen_path, client_key, budget = sys.argv[1:]
budget = int(budget)
start = time.monotonic()
transport_seen = False
saw_session_reset = False


def output(args):
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=6, check=False)
        return result.returncode, result.stdout
    except subprocess.TimeoutExpired:
        return None, "timeout"


def receipt():
    _, handshakes = output(["ip", "netns", "exec", "scupper", "wg", "show", "wg0", "latest-handshakes"])
    _, transfers = output(["ip", "netns", "exec", "scupper", "wg", "show", "wg0", "transfer"])
    epochs = {row[0]: int(row[1]) for line in handshakes.splitlines()
              if len(row := line.split()) == 2 and row[1].isdigit()}
    # Same conservative receipt rule as round 5. Repeated 92-byte gateway
    # handshake responses are not recovery. Only client1 participates here.
    return any(epochs.get(row[0], 0) > 0 and int(row[1]) > 92
               and int(row[1]) % 92 != 0
               for line in transfers.splitlines()
               if len(row := line.split()) == 3 and row[0] == client_key and row[1].isdigit())


with open(log_path, "w", encoding="utf-8") as log:
    Path(started_path).touch()
    while time.monotonic() - start < budget:
        # Bracket check: authentication arriving during its observations can
        # legitimately clear readiness. Record both sides to avoid a false
        # failure from the observer's own sampling race. Residual: authentication
        # just after check can still bracket a false 0 (documented in DESIGN §12).
        before = transport_seen or receipt()
        code, text = output([cli, "check", "--json"])
        transport_seen = before or receipt()
        try:
            verdict = json.loads(text).get("verdict", {})
        except (json.JSONDecodeError, AttributeError):
            verdict = {}
        if not before and verdict == {"Degraded": "ClientSessionsReset"}:
            saw_session_reset = True
            Path(reset_seen_path).touch()
        row = {"elapsed_ms": int((time.monotonic() - start) * 1000),
               "check_exit": code, "authenticated_before_check": before,
               "authenticated_current_generation": transport_seen,
               "session_reset_observed": saw_session_reset, "check": text}
        log.write(json.dumps(row) + "\n")
        log.flush()
        if time.monotonic() - start >= budget:
            raise SystemExit(f"reboot recovery exceeded {budget} s budget")
        if code == 0:
            if not transport_seen:
                raise SystemExit("check returned 0 before new authenticated client transport")
            if not saw_session_reset:
                raise SystemExit("reboot window never observed Degraded/ClientSessionsReset")
            break
        time.sleep(0.1)
    else:
        raise SystemExit(f"reboot recovery exceeded {budget} s budget")
