# Native macOS qualification

Build `scupper-mac-qual` with `--features qualification`. The `smoke`, `probe`,
and isolated `probe-hijack` groups run only on disposable Apple Silicon
GitHub-hosted macOS 15 and 26 runners. None qualifies production enforcement.
The capability experiments are self-contained C programs in [`probes/`](probes/).

Root, `GITHUB_ACTIONS=true`, `RUNNER_ENVIRONMENT=github-hosted`, and
`--disposable-runner` are an **accident guard, not authentication**. The workflow
builds as the runner user, then installs the harness, SDK ABI probe, capability
probes and pinned wireguard-go as root-owned executables under the fresh,
root-owned `0700` directory `/private/var/db/scupper-qual`. Privileged invocations
always execute these staged copies. Protected paths reject symlinks and writable
ancestors. A fixture APFS mountpoint is allowed to have filesystem-selected
metadata; its parent remains protected and recovery matches its image path.

Use one fresh absolute `--out DIR` under that protected directory:

1. `preflight --out DIR --disposable-runner` saves pf status, references, rules,
   anchors, SystemConfiguration keys, routes, interfaces, system identity and
   tool digests. Foreign pf references, a pre-existing production anchor,
   translation or an unsupported architecture make the campaign inconclusive.
   Mutating probes additionally require complete restorable baseline inventories
   and no pre-existing harness keys. Missing translation OIDs are accepted only
   for the exact native-arm64 unknown-OID response.
2. `arm --after 1080 --out DIR --disposable-runner` starts the independent
   `system/net.scupper.qual.restore` launchd worker. It acknowledges its own pid,
   microsecond start, process group, parent, boot session and monotonic deadline.
   A live, independent worker must acknowledge before any experiment starts.
3. `run --group smoke|probe|probe-hijack --out DIR --disposable-runner` runs the
   selected cell. Alternatively, `probe --name pf-starters --out DIR
   --disposable-runner` runs one experiment. `dns-default` additionally requires
   `--group probe-hijack`. Each named probe may run only once in an evidence
   directory; reruns use a new directory. `capture` remains a guarded read-only
   inventory command.
4. `restore --out DIR --disposable-runner` remains available after ack expiry.
   It serializes recovery, stops the controller and probe processes, then their
   children, checking each pid against its microsecond start before signalling.
   Zombies are treated as stopped writers. It releases live journaled pf tokens,
   flushes journaled fixture anchors, restores initial Disabled pf state with
   `pfctl -d` if necessary, removes fixture keys, closes utuns by killing their
   holders, detaches fixture disk images, and removes owned loopback aliases and
   stale UAPI sockets. It saves a post-state diff and `Q-RESTORE.json`.

Every mutating child waits on an exec grant until its identity/resource intent
is durably journaled. A parent dying before granting closes the pipe, so the
sentinel exits and closes inherited fds. A completed pf acquisition also journals
its token. Recovery handles death before that token append using the earlier
pfctl acquisition pid/time intent and a bounded raw token inventory. A partial
final journal append is preserved separately before truncation, after writers
stop. There remains a pid-reuse window between identity lookup and signalling;
these fixture checks do not make `kill` atomic.

After each probe, restore runs twice. The second must perform no network or
writer-stop actions. Both post-states must match preflight for pf enablement,
references, anchors/rules/NAT, keys, routes and interfaces. Route counters and
expiry, pf uptime/counters and scutil list indices are retained raw but are not
configuration equality fields. Missing observations or configuration drift cause
`contract_violation`. Restore never removes a foreign token or guesses a disk
number. No R2 probe loads any pf rules or anchors.

Each C program emits one JSON event stream. The harness retains bounded,
redacted stdout/stderr and writes a `measurement` aggregate plus separate named
hypothesis verdicts. `assumption_refuted` and `inconclusive` retain evidence and
pass the cell; `contract_violation` fails it. Measurements and these R2 manifest
entries cannot promote an assumption. There are no automatic retries.

The manifest reserves 12 of each 30-minute cell's minutes for setup and restore.
Seven non-hijack probes have two-minute budgets: 14 minutes plus 10% fits the
18-minute harness allocation. The hijack cell has a one-minute budget including
recovery, with a nine-second C lifetime and a ten-second outer command deadline.
Its temporary SystemConfiguration session also removes the hijack keys on death.
The cell is `continue-on-error` on both pinned runners; its independent dead-man
is armed for ten seconds instead of the normal 1080.

Compiler output is retained in full on native build failures. Artifact checks
remove executables/images and quarantine any remaining UAPI key assignments.
They bind the harness and executed capability binaries to their built and staged
SHA256s. The always-step restores again, stops the dead-man, then exports evidence
through an unprivileged writer, excluding disk images and mount contents.
