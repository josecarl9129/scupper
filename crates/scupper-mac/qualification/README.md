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

R5 adds `run --group store` on both native runners. Image setup has two minutes
for a 256 MiB unfilled image and a 4 MiB full image; Q-STORE has seven minutes,
including setup. Image sizes and the off-image evidence check are recorded.
The cell selects each of five create faults 100 times unfilled and 50 times full,
plus three overwrite faults at the same counts, classifies both copies after every
operation, and separately checks full-volume create/overwrite, exact fstat size,
directory F_FULLFSYNC errno, root/copy rejection, read/write races, outstanding
write Busy/TimedOut/wait, and the two-reader/abandon limit. Full means ENOSPC on a
16 KiB block write. Full-volume create failures can precede the selected hook;
that is recorded rather than credited as reaching the hook. Every failure may
leave partial bytes. Synced requires the complete applicable write/sync protocol.
The full-image ordinary overwrite may also fail; it is recorded, with no Synced
credit. Before filling, fixtures allocate and sync a 256 KiB slack file outside
the copy namespace. After full-volume checks, reclaim truncates and syncs the
held slack fd, then truncates and syncs the held filler fd before dropping and
unlinking it, removing B and renaming reserved B for deterministic concurrency
fixtures. Each reclaim step has a named phase (`reclaim/truncate_slack`,
`reclaim/sync_slack`, `reclaim/truncate_filler`, `reclaim/sync_filler`,
`reclaim/unlink_filler`, `reclaim/remove_b`, `reclaim/rename_reserved_b`).
The phase evidence also records a `full/concurrency_reset` configuration event
with `slack_bytes`, `enospc_retries` and `retry_delay_ms`. ENOSPC gets at most five
retries spaced 200 ms apart, within the existing case budget; reclaim failure
is environment Inconclusive and names the step. Concurrency evidence names the
reclaimed image state. No harness evidence is written onto
either image. Every phase writes start/end timestamps, elapsed seconds and
outcome to `store-phases.jsonl`, with completed timings in
`store-hook-counts.json`; unexpected errors name their phase. Budget expiry is
an environment Inconclusive. Both create and Short-copy repair require file then
directory F_FULLFSYNC before Synced. These are **error handling checks only;
crash and power-loss durability are not established**.

The R5 tree, images and mounts have write-ahead journal intents. Image tools
wait on an exec gate until their PID/start identity is journaled and synced;
controller death before the grant closes the gate without executing hdiutil. Recovery stops
writers, detaches each image with a 30-second deadline and then a forced retry,
and removes the exact fixture tree only after an attached-image inventory proves
all images absent. R5 reserves the full 240-second final restore allowance for
two images plus post-state capture. Evidence export excludes the fixture tree.
All staged binaries, including isolated R4 mutation builds, have complete built
and executed SHA256 manifests checked recursively by `check-artifacts.py`.
Linux runs `tests/r5_storage_mutations.py` and an exhaustive no-feature fault-enum
compile test. The fallback mutant uses a mock successful fsync after a failed
full-sync; actual Darwin syscall behavior remains a native-runner observation.

R6 adds `pf` (Q-ENABLE 2 minutes, Q-EEXIST 2 minutes, Q-REFS 8 minutes)
`pf-x` (Q-X 2 minutes) and `pf-x-stale` (Q-X-STALE 2 minutes) on both pinned runners. These cells require pf
Disabled and no starter references at preflight. They journal global-state
intent before mutation and run all pf tools and four churn workers inside a
journaled launchd process group. The existing dead-man/always restore stops
that group before harness-only `pfctl -d` restores the disabled baseline.
The adapter never globally disables pf. Q-FLUSH belongs to R7.

Q-ENABLE writes full stdout/stderr/status to `pf-text-*.json`; review those
captures per build against `decode/pftext.rs` before promoting its provisional
acquisition/release templates. Q-REFS writes raw capacities/copied records,
500 acquisition fingerprints and value-reuse counts, and 2000 churn reads with
eight long-lived references including the oldest. Workers acquire bursts of four.
The 2000 reads comprise 1000 with the default 16 spare slots and 500 each with
qualification-only spare 0 and 1. `pf-churn.json` records each sub-run's internal
Retry count and complete/incomplete observations. Each small-spare sub-run requires
Retry > 0 and Complete > 0; missing coverage is Inconclusive. Production always
uses 16 spares; the override method and portable entry point compile only with
`qualification`, with their absence checked by `r6_no_feature.py`.
Q-X checks X1, X1-anonymous and X2, saves `pf-x-contract.json`, and returns
`assumption_holds` or `contract_violation` (incomplete evidence is Inconclusive).
It alone supports `disable_voids_references`. Q-X-STALE records up to 200
enabled-pf recurrence trials in `pf-x-observations.json`; successful trials always
return `measurement` and support no assumptions. A missing recurrence is a
measurement limit, never evidence that values are unique.
The harness executable remains covered by the complete built/staged manifests;
R6 introduces no additional staged executable.

Linux regression commands (all mutate only the current worktree and restore
source bytes) are `python3 crates/scupper-mac/tests/r6_reference_mutations.py`
and `python3 crates/scupper-mac/tests/r6_no_feature.py`. The latter requires the
Darwin Rust target and proves the qualification override API is absent without
features. Neither Linux checks nor a successful cross-lint substitutes for the
native campaigns or establishes a production assumption record.

The no-uptime `Status: Disabled` + `Debug:` row is source-derived, not a native
capture. Upstream pfctl's
[`print_status` at 855d4e8](https://github.com/openbsd/src/blob/855d4e832803330fc45a64539854bf8d27180600/sbin/pfctl/pfctl_parser.c)
omits uptime when `since` is zero, then prints the Debug column with one of
None/Urgent/Misc/Loud. The core fixture `pf-info-disabled-source.txt` pins that
form; unknown debug levels/suffixes still fail closed. Real disabled info and
exact acquisition/release captures on both campaign builds remain pending.
Q-ENABLE's two-minute budget is unchanged until native timing evidence arrives.
