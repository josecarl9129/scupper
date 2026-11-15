"""Observe fresh-device readiness without resetting the client's old session."""
import json
import subprocess
import sys
import time
from pathlib import Path


def output(args):
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=6, check=False)
        return result.returncode, result.stdout
    except subprocess.TimeoutExpired:
        return None, "timeout"


def receipt_state(handshake, rx):
    # Repeated 92-byte gateway handshake responses are not recovery. A multiple
    # can also include real client data, so it needs another independent sample.
    if handshake == 0 or rx <= 92:
        return "absent"
    return "ambiguous" if rx % 92 == 0 else "transport"


def dump_receipt(dump, client_key):
    for line in dump.splitlines():
        row = line.split()
        # Peer dump columns: key, psk, endpoint, allowed-ips, handshake, rx, tx, keepalive.
        if len(row) == 8 and row[0] == client_key and all(v.isdigit() for v in row[4:6]):
            return int(row[4]), int(row[5])
    return 0, 0


def evidence(sample):
    handshake, rx = sample
    return {"handshake": handshake, "rx": rx,
            "ambiguous": receipt_state(handshake, rx) == "ambiguous"}


def resolve_ambiguous(sample, sample_again, pause=time.sleep):
    """Require real transport within four retries in the original handshake."""
    epoch = sample[0]
    samples = []
    for _ in range(4):
        pause(0.05)
        sample = sample_again()
        samples.append(evidence(sample))
        if sample[0] != epoch or receipt_state(*sample) == "absent":
            return sample, False, samples
        if receipt_state(*sample) == "transport":
            return sample, True, samples
    return sample, False, samples


def main():
    cli, log_path, started_path, reset_seen_path, client_key, budget = sys.argv[1:]
    budget = int(budget)
    start = time.monotonic()
    transport_seen = False
    saw_session_reset = False

    def receipt():
        code, dump = output(["ip", "netns", "exec", "scupper", "wg", "show", "wg0", "dump"])
        return dump_receipt(dump, client_key) if code == 0 else (0, 0)

    with open(log_path, "w", encoding="utf-8") as log:
        Path(started_path).touch()
        while time.monotonic() - start < budget:
            # Bracket check: authentication arriving during its observations can
            # legitimately clear readiness. Residual: post-check authentication
            # can bracket a false 0 (DESIGN §12); ambiguous retries add at most 200 ms
            # of sampling delay, plus the bounded wg subprocess time.
            before_sample = receipt()
            before = transport_seen or receipt_state(*before_sample) == "transport"
            code, text = output([cli, "check", "--json"])
            sample = receipt()
            after = receipt_state(*sample) == "transport"
            resamples = []
            ambiguous_rejected = False
            initial_sample = sample
            if code == 0 and receipt_state(*sample) == "ambiguous":
                sample, after, resamples = resolve_ambiguous(sample, receipt)
                ambiguous_rejected = not after
            transport_seen = before or after
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
                   "session_reset_observed": saw_session_reset, "check": text,
                   **evidence(sample), "before_sample": evidence(before_sample),
                   "after_check_sample": evidence(initial_sample), "resamples": resamples}
            log.write(json.dumps(row) + "\n")
            log.flush()
            if time.monotonic() - start >= budget:
                raise SystemExit(f"reboot recovery exceeded {budget} s budget")
            if code == 0:
                if not transport_seen or ambiguous_rejected:
                    raise SystemExit("check returned 0 before new authenticated client transport")
                if not saw_session_reset:
                    raise SystemExit("reboot window never observed Degraded/ClientSessionsReset")
                break
            time.sleep(0.1)
        else:
            raise SystemExit(f"reboot recovery exceeded {budget} s budget")


if __name__ == "__main__":
    main()
