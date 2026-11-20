# Native macOS qualification bootstrap

Build `scupper-mac-qual` with `--features qualification`. The only implemented
group is `smoke`. It observes pf, network configuration and system identity;
it never loads pf rules, acquires references, changes pf enablement, or changes
routes or DNS. It does not qualify production enforcement.

The supported qualification targets are Apple Silicon macOS 15 and 26, using
pinned GitHub-hosted runner labels. Environment variables, root and the
`--disposable-runner` flag form an **accident guard, not a security property**.
They are spoofable and do not authorize execution on another machine.

The workflow builds the Rust binary and `crates/scupper-darwin/probe/abi.c` as the runner user. All
commands use one fresh `--out DIR`, retained as the cell's artifact:

1. `preflight --out DIR --disposable-runner` records read-only state. Foreign
   references, an existing `com.apple/scupper` anchor, translation, a non-arm64
   binary, and failed or unknown observations make the campaign inconclusive.
   Missing `sysctl.proc_translated` is permitted only for its specific unknown-OID
   response on native arm64; the raw error is retained.
2. `arm --after 1080 --out DIR --disposable-runner` bootstraps the independent
   `system/net.scupper.qual.restore` launchd service. The worker acknowledges its
   own pid, microsecond start identity, group, parent, boot session and fire time.
   The ABI probe's harness-only identity mode supplies these start identities;
   it is not a production process adapter.
3. `run --group smoke --out DIR --disposable-runner` requires a live, unexpired
   acknowledgement. It captures SDK ABI JSON, verifies guard refusal, exercises
   restore twice, and records 1000 equal valid boot-session UUID reads.
   `capture --out DIR --disposable-runner` can also collect the read-only
   inventory separately while the acknowledgement remains fresh.
4. `restore --out DIR --disposable-runner` remains available after expiry. It
   first checks registered controllers by pid and microsecond start before
   signalling them, then records post-state and a diff against preflight.
   In-process smoke restore excludes its own controller. There are no network
   writers or owned network resources in this bootstrap, so both restores are
   network no-ops; the second records `already_restored: true`. No foreign
   drift is undone. Future mutation groups must add their resource restoration
   and child-writer registration before they can run.

Preflight and arm necessarily cannot require the acknowledgement they create;
restore must also remain usable after it expires. They still require every
other accident-guard condition. The worker is an independent launchd child and
group leader, so cleanup of the controller's group cannot remove the timer.
The workflow always restores again, records launchd status, and boots out the
worker before checking and uploading artifacts.

Each case writes a verdict JSON. Only `contract_violation` fails qualification;
`assumption_refuted` and `inconclusive` preserve evidence without qualifying a
build. There are no automatic retries or record promotions. The manifest's case
budgets plus ten percent must fit the 18-minute harness allocation inside a
30-minute cell.

Evidence includes exact executable/arguments/stdin, pid, exit code, timestamps,
elapsed time, timeout/truncation flags, and redacted stdout/stderr (256 KiB cap
per pipe). Pipes keep draining after the cap. Command observations are saved as
they complete. `boot-reads.jsonl` includes each attempted read before the syscall,
so a stalled read is identifiable even if the cell is interrupted. Restore
snapshots include dynamic state; differences in counters or foreign network
state are recorded, not attributed to this harness.

The artifacts include `preflight.json`, `ack.json`, `deadman-*.json` and logs,
`abi.json`, SDK/compiler logs, `smoke-restore-{first,second}.json`,
`restore-*.json`, `boot-reads.json{,l}`, `sysctl-strings.json`, `capture.json`,
`Q-SMOKE.json`, `Q-CAPTURE.json` and `verdicts.json`. ABI comparisons against Rust
layout constants are deferred until those bindings exist. Tool hashes, runner
image metadata, architecture and translation evidence are retained. The artifact
checker rejects and quarantines files containing UAPI key assignments before
upload; it removes the temporary probe executable after final restore.
