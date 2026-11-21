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
   `--group probe-hijack`, as does the separate `dns-default-minimal` probe. Each named probe may run only once in an evidence
   directory; reruns use a new directory. `capture` remains a guarded read-only
   inventory command.
4. `restore --out DIR --disposable-runner` remains available after ack expiry.
   It serializes recovery, stops the controller and probe processes, then their
   children, checking each pid against its microsecond start before signalling.
   Zombies are treated as stopped writers. It releases live journaled pf tokens,
   flushes journaled fixture anchors, restores initial Disabled pf state with
   `pfctl -d` if necessary, removes fixture keys, closes utuns by killing their
   holders, detaches fixture disk images, and removes owned loopback aliases and
   stale UAPI sockets. It deletes the journaled resolver host clone only when
   destination is 127.0.0.53, gateway is 127.0.0.1, interface is lo0, flags include
   H/W and exclude S, and the clone was absent from preflight. It saves a post-state diff and `Q-RESTORE.json`.

Every mutating child waits on an exec grant until its identity/resource intent
is durably journaled. A parent dying before granting closes the pipe, so the
sentinel exits and closes inherited fds. A completed pf acquisition also journals
its token. Recovery handles death before that token append using the earlier
pfctl acquisition pid/time intent and a bounded raw token inventory. Recovery
uses the ioctl inventory when complete, then falls back to the
`pfctl -s References` PID/process/token/elapsed-age table. If both inventories fail, it
still attempts `pfctl -X` for every durably recorded token and continues the
remaining cleanup, retaining the named inventory failure. A partial
final journal append is preserved separately before truncation, after writers
stop. There remains a pid-reuse window between identity lookup and signalling;
these fixture checks do not make `kill` atomic.

Each probe has its own `scope-NAME/` directory and resource journal. After each
probe, scoped restore runs twice, including after execution or classification
failure. The cell retains each failure and continues with the next probe. Final
restore and comparison run after all selected probes; final and dead-man recovery
visit every scope after stopping all writers. The second restore must perform no
network or writer-stop actions. Both post-states must match preflight for pf enablement,
references, anchors/rules/NAT, keys, routes and interfaces. Route counters and
expiry, link-layer/cloned route cache entries, pf uptime/counters and scutil list
indices are retained raw but are not configuration equality fields. Added SC
keys outside the harness namespaces and explicit key journals are recorded as
`os_drift`; removed preflight keys and added harness keys remain violations. The
journaled resolver clone remains a comparison field until explicitly removed. Network
gateways and tunnel/harness routes remain comparison fields. Missing observations
or configuration drift cause
`contract_violation`. Restore never removes a foreign token or guesses a disk
number. No R2 probe loads any pf rules or anchors.

`DIOCGETSTARTERS` uses Darwin `_IOWR('D', 5, 16)` (`0xC0104405`), with
84-byte packed token records and a 16-byte request. An O_RDONLY EACCES or any
ENODEV is a probe contract violation. Zero-capacity size queries are separate
from copy observations and have their own `Q-REFS-size-query` artifact.

Each C program emits one JSON event stream. The harness retains bounded,
redacted stdout/stderr and writes a `measurement` aggregate plus separate named
hypothesis verdicts. `assumption_refuted` and `inconclusive` retain evidence and
pass the cell; `contract_violation` fails it. Measurements and these R2 manifest
entries cannot promote an assumption. There are no automatic probe reruns.

The manifest reserves 12 of each 30-minute cell's minutes for setup and restore.
Seven non-hijack probes have two-minute budgets: 14 minutes plus 10% fits the
18-minute harness allocation, as do the cases plus final restore's four-minute
maximum. The hijack cell has two one-minute cases including
recovery. `dns-default` runs the DNS-only, OverridePrimary-only and full utun
phases; `dns-default-minimal` runs the no-Router and no-OverridePrimary phases.
Each has a nine-second alarm while keys are owned and a ten-second outer command
deadline. A gated undo sentinel removes both keys on SIGALRM notification,
unexpected parent EOF or its 8.5-second deadline, in addition to temporary-session
teardown. The cell is `continue-on-error` on both pinned runners; the independent
dead-man uses the same 1080 seconds as other groups. The timing regression test
requires this deadline to exceed both hijack case budgets plus final restore's
240-second maximum, and to cover the larger probe group plus that maximum.
Final recovery gets its own budget: 10 seconds plus two seconds per incomplete
journal entry or controller, capped at 240 seconds. Verified completed entries
are skipped, including identities of stopped writers; every restore still takes
a post-state snapshot and compares it with preflight. The always-step allows five
minutes for recovery and stopping the dead-man.

Compiler output is retained in full on native build failures. Artifact checks
remove executables/images and quarantine any remaining UAPI key assignments.
They bind the harness and executed capability binaries to their built and staged
SHA256s. The always-step restores again, stops the dead-man, then exports evidence
through an unprivileged writer, excluding disk images and mount contents.

The handoff probes use Darwin `<fcntl.h>` F_DUPFD_CLOEXEC to keep spawn sources
at fd >=10; `<spawn.h>` actions duplicate them onto targets 0..4. The trampoline
records fd 3's F_GETFD result before exec. Verbose child stdout/stderr are piped,
bounded and redacted, and wait events retain raw status, exit code and signal.
UAPI `get=1` checks `<sys/un.h>` SOL_LOCAL/LOCAL_PEERPID against the child pid;
`<sys/proc_info.h>` supplies socket identity (unit and soi_so). The process probe
compares live p_uuid with both the built file's LC_UUID and the R2 UUID
D4946FC0-C4E2-3F64-A76D-F48900B81CE7. Its private flavor-17 layout remains
explicitly local and size-asserted.

The pinned source confirms the name-file distinction:
[main.go lines 114–134](https://github.com/WireGuard/wireguard-go/blob/f333402bd9cbe0f3eeb02507bd14e23d7d639280/main.go#L114-L134)
uses CreateTUNFromFile directly for WG_TUN_FD;
[tun_darwin.go lines 123–135](https://github.com/WireGuard/wireguard-go/blob/f333402bd9cbe0f3eeb02507bd14e23d7d639280/tun/tun_darwin.go#L123-L135)
only writes WG_TUN_NAME_FILE from CreateTUN("utun"). Handoff identity therefore
uses the helper-known UTUN_OPT_IFNAME name, with no name-file prerequisite.

DNS phase-network events retain State:/Network/Global/IPv4 values and bracket
`netstat -rn`, `scutil --nwi` and `scutil --dns` observations. Completed lookups
with zero responder queries refute the effect hypothesis. DNS dictionaries set
SupplementalMatchDomainsNoSearch=1. Storage fullness is ENOSPC on a fresh 4096-byte
append after filling, independent of APFS free-block counters; top-up bytes and
f_bavail are retained. Detach gets 30 seconds and then a forced detach attempt.

SC teardown retains the original 100 ready and 100 pre-add kills, plus 20
AddTemporaryValue/SetValue-update kills. The kill-window polling target is 5 ms;
the ten-second reappearance tail polls every 50 ms. `key-polls.samples` contains
[start_ms, completed_ms, registered_key_count, presence_hex] for every poll, so
actual scheduling/IPC delays remain visible. The bounded command capture is
1 MiB per stream to hold this census without truncation. PF starter series now
include n=64, and pf-eexist records a deliberately stale release against an
otherwise harness-owned live token, including reissued-value effects and text.

R4 native mutation experiments run only in the `tool-mutants` matrix group on
both runners, with `continue-on-error: false`. Its job timeout is 60 minutes;
the mutation step has 18 minutes. The manifest reserves 36 minutes outside the
experiments for setup, builds, lint/tests and recovery. The review estimated
6–10 minutes for four experiments; scaling to five gives 7.5–12.5 minutes before
crediting the removed 45-second failure polls. Eighteen minutes adds margin;
the first runner timings must be used to revise this provisional budget.
Each experiment logs build/preflight/arm/assertion/restore wall time, has its own
restore service, and stops that service only after successful restore. The
ordinary `tool` cell has its own fresh preflight and never runs these mutants.

The utun cross-check is qualification-only provisional corroboration. It requires
a protected root-owned runtime directory, a root-owned single-link socket, a live
interface index and exactly one matching AF_UNIX stream listener in the owned
child's fd table. SDK layout evidence includes the UNIX bound address and
SO_ACCEPTCONN option. Absent and stale socket fixtures require the specific
cross-check refusal. R8 replaces this with the OD5 fd handoff; no production
assumption is promoted here. The portable boolean-passthrough utun mutant was
dropped because only native wiring mutations exercise these observations.

Q-LOCK also records every ancestor of both `/Library/Application Support` and
`/private/var/db` and whether a hypothetical root:wheel 0755 child beneath each
would pass the strict ancestor check. These are read-only measurements; modeled
directories are created only inside the journaled scratch tree. The provisional
run path does not settle the 5a3 layout, user traversal or reset/removal policy.
The existing `macos` job's `Clippy portable CLI and release tooling` step already
runs clippy without features, including the adapter and its Darwin dependency.
