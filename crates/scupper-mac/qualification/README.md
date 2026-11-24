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
   Use `--after 1500` for the expanded `pf` group.
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
dead-man uses 1080 seconds, as do the other groups except `pf` (1500 seconds). The timing regression test
requires this deadline to exceed both hijack case budgets plus final restore's
240-second maximum, and to cover the larger probe group plus that maximum.
Final recovery gets its own budget: 10 seconds plus two seconds per incomplete
journal entry or controller plus three seconds per distinct journaled anchor
(counted independently in each scope), capped at 240 seconds. Verified completed entries
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
credit. The comprehensive concurrency suite (Busy/TimedOut/wait, racing reads,
worker capacity and abandon-discard) runs only on the unfilled image. The full
image performs no reclaim: no slack file, filler truncation/unlink or reserved-B
rename. A is valid and synced before filling; B stays absent on both images (the
fault loops need it absent, and unlinking it on the full image could fail with
ENOSPC). Immediately after the
ENOSPC fill and before destructive faults, `full/race` gates one overwrite of A,
checks Busy and a short wait timeout, starts a racing reader, then releases the
write and makes bounded reads. Valid reads must equal the exact old or new bytes;
Synced must leave exact new bytes. The number of racing reads classified valid
is recorded (`racing_valid_reads`; zero is a recorded coverage gap). The real settled outcome, syscall errno,
post-read bytes and duration are recorded in `store-full-race.json` and phase
evidence. If the race did not fail with ENOSPC, verdict detail records
`"enospc_failure_race":"not exercised"` as a coverage gap. Fault loops continue
from the bytes the race left, without resetting A or freeing the filler. The
`image_state` and `full_concurrency` evidence distinguish this targeted full-state
probe from the unfilled comprehensive suite. The full image remains filled until
detach. No harness evidence is written onto
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

R6 adds `pf` (Q-ENABLE 4 minutes, Q-EEXIST 3 minutes, Q-REFS 15 minutes)
`pf-x` (Q-X 2 minutes) and `pf-x-stale` (Q-X-STALE 2 minutes) on both pinned runners. These cells require pf
Disabled and no starter references at preflight. They journal global-state
intent before mutation and run all pf tools and four churn workers inside a
journaled launchd process group. The existing dead-man/always restore stops
that group before harness-only `pfctl -d` restores the disabled baseline.
The adapter never globally disables pf. Q-FLUSH belongs to R7.

Q-ENABLE writes full stdout/stderr/status to `pf-text-*.json`, with `build`,
`stdout_bytes` and `stderr_bytes` preserving exact per-build bytes (including
non-UTF-8 diagnostics). Raw harness calls and native adapter mutator attempts
are saved before text parsing or an Inconclusive verdict; review those
captures per build against `decode/pftext.rs` before promoting its provisional
acquisition/release templates. Q-REFS writes raw capacities/copied records,
500 acquisition fingerprints and value-reuse counts, and 2000 churn reads with
eight long-lived references including the oldest. Workers acquire bursts of four.
The 2000 reads comprise 1000 with the default 16 spare slots and 500 each with
qualification-only spare 0 and 1. `pf-churn.json` records each sub-run's internal
Retry count, complete/incomplete observations, and `growth_past_copy_capacity` events
(the next size query exceeds the previous copy capacity). This soak is measurement only; spawn latency does not reliably hit the
size/copy window. A Complete missing a continuously held fingerprint still fails.
`pf-injection.json` instead asserts deterministic boundary coverage: with eight
held fingerprints, spare in {0,1,16}, inject each distinct k in
{0, spare-1 when nonnegative, spare, spare+1, spare+2, 2*spare+3}. A one-shot
qualification hook fixes capacity before acquiring k references with ordinary
native -E, journals each immediately and holds them through enumeration. The
adapter records actual first-copy capacity and contents. k < spare must first
Complete; k >= spare must Retry; k > spare must omit the oldest held fingerprint
in the first copy and observe growth past capacity. The final Complete must
contain every held/injected fingerprint. Checked releases and independent reads
follow enumeration, in acquisition order. Incomplete evidence remains Unknown;
failed/unfinished injection writers require group restore before global reset. Production always
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

CI 45050965328 on 723dbda captured identical never-started, disabled info on
24H232 (macos-15) and 25G332 (macos-26), arm64. The primary core fixtures
`pf-info-disabled-24H232.txt` and `pf-info-disabled-25G332.txt` pin that stdout,
including Apple's `dummynet` and `invalid-port` non-policy counters. Enabled
status with Debug but no uptime and unknown counters still fail closed.
All observed read-only pfctl commands exited zero with the exact stderr prefix
`No ALTQ support in kernel\nALTQ related functions disabled\n`.
`decode/pftext.rs` strips this exact prefix once, only for those two builds;
all existing remainder rules still apply. Later mutator captures are pinned in
`decode/pftext.rs`, including the sole-reference row from CI 45079241070.

Original source note: upstream pfctl's
[`print_status` at 855d4e8](https://github.com/openbsd/src/blob/855d4e832803330fc45a64539854bf8d27180600/sbin/pfctl/pfctl_parser.c)
omits uptime when `since` is zero, then prints the Debug column with one of
None/Urgent/Misc/Loud. `pf-info-disabled-source.txt` retains that earlier evidence.
CI 45079241070 measured 49 Q-ENABLE Started captures spanning 119 seconds on
24H232 (about 2.4 s/iteration). Q-ENABLE now has 240 s (50*2.4=120 s,
100% headroom); Q-EEXIST has 180 s using the same conservative 120 s work
allowance (50% headroom). Q-REFS has 900 s: the previous conservative 480 s
work allowance plus 118 injected acquire/release pairs at 0.8 s = 574.4 s;
1.5*574.4=861.6 s fits. Native elapsed_ms records will refine that allowance.
The pf launchd wait is 24 minutes for 22 minutes of cases plus setup/cleanup;
the run step and pf dead-man are 25 minutes (other groups remain at 18);
the CI cell is 50 minutes with 20 minutes overhead,
leaving room for 10% case slack and the 240 s final restore. Deadlines with less
than one whole second left are environment errors; adapter timeouts retain the
actual error instead of becoming text mismatches.

CI 45079241070 also pins the SoleReleased row independently for both builds:
rc 0, empty stdout and exact preamble + `pf disabled\n` stderr. Text is only
an acknowledgement of our exact -X invocation. Qualified matching pre-call
fingerprint and a fresh complete post-read proving its absence are mandatory.
Later pf-info is diagnostic only; isolated qualification additionally requires
Disabled and empty inventory. `pf-last-reference-*.json` is saved before verdict.
Every pf case JSON includes elapsed_ms. Q-REFS resets on exit; incomplete
injection writers defer reset to the journaled group restore.


R7 uses the `contracts` group on both runners, with a 16-minute run step,
15-minute launchd worker budget, and 1500-second independent dead-man. Its
40-minute job reserves setup and final restoration time. It runs Q-ANCHOR,
Q-CONTRACTS (core and anchor verdicts separately), Q-E2E, Q-FLUSH and then
Q-DESCENDANTS. All cases use the root-owned harness covered by complete built/staged hash manifests;
`contract-copy-identities.json` binds the scratch executable to staged wireguard-go.

CI 45355500636 pass-1 evidence is reviewed for 24H232 and 25G332. Both builds
have identical load, show, inventory, missing-anchor/parent and scoped/global
flush text rows. Every accepted operation requires rc 0 and its exact stderr:
show commands require the ALTQ preamble; load requires the warning block,
including its blank line, before ALTQ; flushes require ALTQ followed by the exact
class message (decimal counts for tables and states). Missing-anchor `-sr` and
`-sd` also return rc 0, with ALTQ plus DIOCGETRULES Invalid argument. That result
is distinct from an empty existing ruleset. Extra/unknown lines, missing ALTQ,
unknown builds and incomplete evidence remain errors. R6 enable/token rows
remain unchanged. Reviewing text does not qualify production enforcement.

`read_anchor` returns `None` for absence of active configuration: either a
complete parent inventory lacks the owned child and agrees with the pinned
missing-anchor filter result (a missing parent also requires a complete root
inventory lacking that parent), or all configuration classes are completely
empty. Listed descendants remain foreign content on 24H232 and 25G332: both
reviewed rows explicitly set `descendants_reviewed = false`. With a future true
row, every exact descendant must have complete, empty `-sr`, `-sn`, `-sd`, `-sT`
and recursively checked `-sA` classes. Paths must stay strictly below the owned
root plus `/`; depth is bounded at 8 below the root and count at 64 including
that root. Existing time/output bounds and the shared deadline still apply.
Exceeded bounds, incomplete reads, unexpected text and any nonempty descendant
class return Err. `Some(own_policy)` requires the same empty descendant proof.
`Some("")` never occurs. Configuration absence does not prove namespace
reclamation or absence of runtime states or src nodes. Empty anchor names,
including the qualification parent, can remain until reboot on both builds.

On builds outside the reviewed table, `load_anchor` attempts only byte-exact
canonical Lockdown at the owned `com.apple/scupper` (or qualification
`scupper-qual/scupper`) path, using `pfctl -o none -a PATH -f -`. It returns
`Unknown` regardless of exit status or stderr, including rc 0. Every other
payload/path and every `remove_anchor` is refused before spawning with
`Failed("unsupported pf anchor build")`. On reviewed builds, removal first reads
independently. Complete `None` returns success without any flush, since flushing
a missing anchor creates it. Otherwise it
flushes only the owned path's rules, nat, Tables and dummynet, and succeeds only
after a complete final `None`. An incomplete or foreign first read cannot take
the shortcut. It never flushes descendant paths; a nonempty descendant makes
removal fail. Leave removes configuration, without reclaiming the namespace or
asserting runtime-state absence. The owner accepts fix 2's ClearIntent change:
only `None` clears; even a nonconforming adapter's `Some("")` or `Some(" \n")`
must refuse to clear. All other engine absence branches retain their behavior.

Native loads use `pfctl -o none -a PATH -f -`. Both A (Lockdown) and B goldens
are reviewed expectations re-derived for this mode: source order, address-list
expansion in source order, ICMPv6 names routersol/routeradv/neighbrsol/neighbradv,
implicit TCP `flags S/SA`, and numeric `port = 51820`. The re-derived text equals
the previous proposed text; review metadata records optimizer mode and hashes.
These are not new optimizer-none runner captures. The next native run must
confirm them; Mismatch is always contract_violation, never Inconclusive.
Unsupported builds remain Inconclusive. Journal-authority failures are harness
preconditions and Inconclusive consistently in all three anchor campaigns.

`Paths::qualification` fixes the unhooked `scupper-qual/scupper`. Q-ANCHOR
runs lifecycle iterations, hooked removals and F-all measurements within its
180-second budget. Q-DESCENDANTS runs after Q-FLUSH, with a separate 180-second
budget for optimizer controls, foreign fixtures and descendant measurements.
These limits use the pass-1 lifecycle durations (90.8–96.0 seconds) and observed
roughly 75 ms per captured pfctl call as the sizing evidence; the new split still
requires native timing confirmation. Each case records its measured `elapsed_ms`.
Each control/fixture records observations, always attempts cleanup outside the
case budget using independent adapter deadlines, and records the cleanup result,
including after budget exhaustion or capture errors. Cleanup failure withholds
later users of that shared anchor as Inconclusive with the recorded reason.
At the end, any contract violation wins; otherwise rejected spellings/environment
issues are Inconclusive. Every shared-anchor raw load still requires the original
absence journal.

Optimizer controls load ten destination addresses with `-o basic` and `-o none`,
recording generated tables and source-order expansion. The overlapping TCP
no-state/state fixture records exact text and source order. These unreviewed
text expectations are measurements: mismatches are recorded as Inconclusive,
never contract violations. Reviewed A/B goldens remain violations on mismatch.

Foreign fixtures cover scrub, nat, rdr, binat, nat64, dummynet, an empty persistent
table and a referenced table. None creates a child in the shared anchor. The
fixture artifacts together record exact source, streams/status for every class,
exact adapter error, removal and final read. Load notices are measurements, not reviewed A/B
load-row assertions. Accepted foreign fixtures must yield any Err before removal;
an unknown grammar is still fail-closed. Removal Ok followed by a complete Some is a contract violation. An incomplete
final read is an environment Inconclusive. Removal Err is an Inconclusive Leave-coverage finding,
with cleanup failure recorded even if an observation also failed. Every rejected
spelling is recorded and makes the aggregate Inconclusive.

The independent, journaled `scupper-qual/children` subtree measures each spelling
in a uniquely named disposable parent, refused if that namespace already exists:
named-inline, wildcard, nonempty grandchild, direct-path `_x` and `qchild/_x`
loads first, followed by named, quoted underscore and one-line anonymous controls.
Pass-4 CI 45478867692 pins both direct `_x` creation refusals for 24H232 and
25G332: rc 1, empty stdout and exactly LOAD_WARNING + ALTQ + the command-line
underscore refusal. These complete as reviewed rejection measurements only when
the remaining class, inventory and flush evidence completes. Other diagnostics
remain Inconclusive. Fixture parents use a short run token and hexadecimal counter under
`scupper-qual/children`; the longest ordinary target is bounded to 48 bytes.
The original root absence authority and individual target journals are retained.
Reviewed builds never load the multiline anonymous fixture; its pass-3 evidence
is pinned in each build's measurement review (facts 1, 2 and 4 from
`anchor-children-inline-multiline.json`). On an unreviewed build it runs last;
any residue is recorded as a declared restore failure. Every ancestor inventory and direct target class
read is retained, including the root ruleset inventory. Bounded qualification-only
DIOCGETRULESETS/DIOCGETRULESET reads
are compared with text inventories at every measured level; exact text-only and
kernel-only differences are saved and the union is traversed. Existence disagreement
is also a contract finding, including when both child-name sets are empty. Only
an initial count-query EINVAL means a missing parent; every later error and every other
first-call errno (including ENOENT) stays incomplete. This is the pass-2 Darwin
fact cross-checked by pfctl's rc-0 `Anchor '<path>' not found.` row.
Qualification absence checks also traverse the union before journaling or granting
restore allowances, so kernel-only configured children cannot authorize cleanup.
The absence merge requires a matching named text missing-parent result exactly
when the kernel reports None; an empty present listing cannot substitute for it.
Deep fixture targets use bounded `anchor-target` journal rows under the original
root absence authority; the production adapter path remains exactly two components.
Fixture cleanup skips kernel-proven missing targets and verifies the entire disposable root.
Length-sample cleanup reads only its exact paths; Q-RESTORE verifies the whole tree.
The restore budget counts these distinct targets as well as adapter-anchor rows.
The Rust ruleset ABI check is a layout pin against XNU-published constants:
size 1092, nr/path/name offsets 0/4/1028, and ioctl numbers
0xC444443A / 0xC444443B. It is not independent SDK verification. The C probe
uses `net/pfvar.h` when available and otherwise compiles an explicitly labelled
in-tree mirror of the XNU-published layout. Both branches assert the size, field
offsets, alignment and ioctl numbers above. A present header with missing ioctls
or a contradictory layout still fails compilation. The CI `cc -std=c11 -Wall
-Wextra -Werror -v ... 2>&1 | tee ...` pipeline can therefore compile with public
SDKs that omit this private header.
`descendant-abi.json` retains `from_sdk_header:true|false` and `layout_source`.
Q-DESCENDANTS records the flag in its successful detail instead of requiring true.
The false branch is an "XNU-published layout pin, not SDK-verified"; compiling the
mirror never establishes SDK verification.
Every discovered path gets class reads before and after each scoped flush.
Paths with any `_`-prefixed component are read but never flushed by the harness.
Configured underscore paths report `unremovable _-anchor content: <path>`.
The reviewed rc-1 refusal is a distinct adapter error,
`pfctl refuses _-anchor modification`, never success. Cleanup
uses an independent 30-second deadline, attempts explicit journaled targets even
if enumeration fails, and retains cleanup failures. A failure withholds later
descendant fixtures. Only this disposable subtree permits recursive harness cleanup;
both native descendant coverage flags remain false.

The supplied pass-2 25G332 facts are pinned in `goldens/25G332/pass2-facts.json`.
Each build's `measurement-review.json` reviews its exact UDP state golden and the
full underscore and one-line anonymous inline rejection command/stdin/rc/stdout/
stderr rows. The 24H232 pin uses CI 45397408312 attempt 2 supplied in the fix 6
brief; the rejection rows are byte-identical across both builds. Pass-3 multiline
acceptance and residue are reviewed measurements, not rejection rows. Exact reviewed parser rejections are
complete measurements when the remaining inventory/flush evidence completes.
Other failed fixture command rows remain Inconclusive.

After the descendant fixtures, a measurement-only sweep loads one loopback pass
rule at total anchor-path lengths 62, 63, 64, 65 and 66 bytes, both directly
and through a parent containing `anchor "<child>"`. Only the final component is
padded. Fixture parents use `f<four base36 run characters><hex counter>` (for
example `f00003`); time and PID supply the run token, and explicit fixture paths
remain within 48 bytes. Collisions remain possible with a short token and are
rejected by freshness reads. Before loading a length sample, complete class reads
and bracketing kernel censuses must show its target (and nested parent) absent.
On reviewed builds 24H232 and 25G332, absence requires all five rc-0 reads
with empty stdout and the exact pass-4 stderr (CI 45478867692): the ALTQ preamble
followed by `pfctl: DIOCGETRULES: Invalid argument\n` for `-sr`, `-sn` and `-sd`,
`pfctl: Anchor or Ruleset does not exist.\n` for `-sT`, and
`Anchor '<exact path>' not found.\n` for `-sA`. Five ALTQ-only empty reads mean
present-empty. Any mixed set or unpinned text is an environment issue.
A preexisting name or incomplete read skips that sample as an environment issue.
Every parent/target is journaled before loading. Each sample flushes only its
kernel-present target and, in nested mode, parent, then reads each path's classes
once to confirm missing or present-empty status. Only the nested parent's cleanup
read also accepts `-sA` stdout exactly `  <target full path>\n` with ALTQ-only
stderr, because Darwin retains its own emptied child. Empty stdout remains valid;
a different child, extra lines, or any other class content is an environment issue.
Freshness and the child's cleanup read retain the strict empty-stdout rule.
A refused direct load that leaves
its target absent needs no flush; the five exact missing rows complete cleanup.
No sample cleanup walks the shared tree; Q-RESTORE retains whole-tree verification.
Before freshness reads and again before journaling, a 30-second remaining-case
margin gates samples. Falling below the margin stops the sweep and records all
remaining mode/length pairs as skipped measurements, without a violation.
The ten samples add at most 15 names; the reviewed eight-fixture layout has 18
names, giving 34 nodes including ROOT after a full sweep on a fresh machine,
below the 64-node traversal bound. Persistent names from reused machines still
count toward that bound. Nonzero exits, including unknown stderr, are retained as
measurements without contract violations. Capture and cleanup errors remain
explicit environment findings; cleanup failure withholds subsequent samples.
`anchor-children-path-length-{direct,nested}-<length>.json` retains setup/load
status and streams plus cleanup outcome and `elapsed_before_evidence_write_ms`
(freshness, load and cleanup, excluding the sample-row JSON evidence write);
`anchor-children-path-length-summary.json`
and the case detail report successful, failed and incomplete sampled lengths and
the maximum successful length separately for each mode, skipped lengths, and measured
per-sample costs with that same exclusion. This describes the
observed boundary for these samples, without asserting a universal path limit.

Per parent, normalized kernel set K and text set T are compared without ordering.
K minus T produces a contract finding "text inventory incomplete"; T minus K
produces "inventory disagreement". Kernel censuses bracket the text/class read;
enumeration failure or a detected change is Inconclusive. Traversal within the
disposable subtree covers the union of observed text and kernel names, including
incomplete comparisons. Ancestor inventories are compared without traversing
foreign subtrees.
Q-DESCENDANTS is assumption_holds only if every attempted optimizer, foreign-fixture
and descendant measurement completed with no findings (budget-skipped length
samples are listed as measurements); any inventory finding makes
it contract_violation. Neither verdict promotes native descendant coverage.
Persistent empty namespace names are allowed only after complete
configuration-absence reads. Restore deduplicates journal paths, reuses those
post-state reads for completion, and retains each independently established
allowance. A complete read finding foreign content is a configuration-present violation,
including the descendant command/path. Other explicit Failed errors are violations.
"Read incomplete" is reserved for timeout, unknown or truncated observations;
added names for that incomplete path remain unresolved, while new
foreign siblings and removed baseline names remain comparison violations.

Twenty unhooked lifecycle iterations and twenty hooked removals (with states
and after global state flush) remain. Raw harness measurements use journaled
`com.apple/scupper` and sentinel `com.apple/scupper-qual`, without constructing
a production-path adapter. The explicit F-all experiment alone uses `-F all`;
ordinary cleanup uses the four scoped classes. No main ruleset, parent ruleset or pf.conf is changed. Wildcard calls occur only
inside the disposable descendant measurement subtree. Global state flush destroys foreign states
irreversibly; restoration cannot return them. The sentinel persistent table and
narrow rule, and the three ephemeral-port Q-FLUSH passes, remain the previously
recorded harness-only scope deviations. Foreign tokens still withhold destructive
cleanup and record failure.

Q-E2E retains the exact Left method audit, committed incarnation, zero pf
mutations/spawn and a complete owned-process census. Join observes at least
sixty seconds with input-free Lockdown, durable hold, no child generation, no
spawn, no Protected status and no Installed-form Protected candidate, including
candidates that disappear within a tick. Trace lines include the verification
form. Both qualified and unqualified fake firewalls exercise install failure;
a qualified PreTunnel Lockdown candidate may be Protected while hold masks
status. Native collection stubs remain unqualified.
Trace requests include write/create/wait outcomes, returned token/PID and complete
reference reads. AcquireReference is reached only after a reservation is Synced
on both copies or an acquire boundary call occurs. Merely planned but uncommitted
acquisition is environmental and names `join.machine().pending()`. Acquisition-
independent violation checks precede the acquisition environment checks.
Each reservation permits one counted `-E`; matching complete reference reads and
recorded fingerprints precede settlement/release. Unresolved debt remains durable.
Returned tokens are journaled immediately; the effect-to-journal gap still relies
only on runner exclusivity and restoring baseline pf state. Trace overflow is
Inconclusive; production builds do not format or hash qualification traces.

Restoration derives launchd setup and its allowlist from `qual/jobs.rs`, including
`system/net.scupper.qual.r4-contracts`. Tests require every journaled mode to be
restorable. A failed stop/cleanup step is recorded while subsequent independent
steps and journals are attempted. Before each dependent cleanup step, fresh
`launchctl print <service>` evidence must show every journaled service absent,
and journaled writers/groups must be gone across all scopes. Otherwise anchor
cleanup, token release, pf-state restoration and completion are `withheld`,
their journal entries remain pending and restore fails. Independent diagnostics
continue. Exec gates alone never establish this dependency. Each anchor first
receives the same complete configuration-absence check,
so an already-empty or missing anchor is never flushed. Recovery attempts all four
classes even if one flush fails, then requires complete configuration absence.
The dummynet row is now reviewed on both builds; its failure is therefore a restore
failure rather than the old unreviewed-row Inconclusive note. Post-state comparison
allows only independently proven empty journaled anchor names and their empty
created qualification parent. Any nonempty class, removed baseline anchor or
un-journaled new sibling/name still fails comparison. The second restore must
remain a measured no-op. Production ancestor measurements share native path
constants, and qualification constructors reject the production anchor outside
native unit tests; the source guard also scans the shared suite and trace module.

Q-FLUSH requires known UDP/TCP IPv4/IPv6 loopback and feth tuples immediately
before the adapter call. The supplied 24H232 and 25G332 `-v` grammar is reviewed
for UDP and TCP tuple measurement. UDP permits `SINGLE:NO_TRAFFIC` and
`NO_TRAFFIC:SINGLE`. TCP requires exactly `ESTABLISHED:ESTABLISHED` and
`   [<u32> + <u32>] wscale <0..14>  [<u32> + <u32>] wscale <0..14>`.
Headers use seven spaces before the status. TCP records are ordered header,
sequence, then age/expiry/counters/anchor/rule/flowhash detail; numbers are bounded.
Any other variant, unknown line, malformed record, duplicate tuple or truncation
invalidates the whole listing as unsupported, never an empty or absent result.
Fixtures copy both supplied pass-3 listings verbatim, including UDP rows.
Tuple identity remains the verdict key. Q-FLUSH separately takes three repeated
`-vv` dumps before deletion and three after attempting UDP reuse on the same
sockets, retaining per-tuple `(id, creatorid)` stability and the post-deletion
observation. Missing/unparsed observations remain explicit. This is measurement
only; it does not promote `-vv` identities into verdicts.
Q-ANCHOR records
state read/parse errors per hooked iteration and in the `-F all` scope check,
continues the remaining lifecycle steps, and aggregates these measurement
issues as Inconclusive. Its repeated socket tuple measures presence, not identity.
A tuple present after Q-FLUSH is likewise Inconclusive because it may recur.
Unknown text, missing tuples, stock skip or unavailable feth is Inconclusive. Accepted TCP sockets are explicitly blocking with a read timeout.
Q-FLUSH attempts anchor and feth cleanup after errors and observation panics.
Interface/address selectors remain raw measurements; selective removal is unqualified.

Q-E2E alone stages the pinned child at `/opt/scupper/wireguard-go`. Any existing
entry, including a dangling symlink, refuses staging. Inspection errors are not
absence. Parents must be root-owned and not group/other-writable; absent parents
are created with protected modes. Write-ahead intents precede mkdir and exclusive
file creation, and successful creations record device/inode identity. The file
uses O_CREAT|O_EXCL with no replacement or rename-over. Cleanup removes only
matching created objects, directories only when empty; unresolved intents and
changed identities are retained as restore issues. The named path-absence precheck
and both executable_id/image_uuid results precede scenario counts. No process-name
or unreadable-identity exceptions are added. Production root, lock, control and
anchor remain refused by qualification constructors. Shared-anchor contamination
gates Q-CONTRACTS-anchor and Join, after core contracts and Left have run.

Run `python3 crates/scupper-mac/tests/r7_mutations.py` for portable assertion
mutants. They include listed-empty absence, no flush after a complete first None,
optimizer mode, restore continuation, the contracts job label, golden mismatch
classification, vanished evidence entries, incomplete anchor reads, parse errors,
exclusive child staging, the anchor-only gate, initial missing-anchor EINVAL,
non-aborting state errors and inventory-difference verdicts. Original source bytes
are restored on every exit; evidence is
kept under target/r7-mutants until the required final target cleanup.

R7 verification traces record `verification_kind:Lockdown` or
`verification_kind:Installed(PreTunnel)` / `Installed(Joined)`, followed by
`:verification_protected:true` or `false`. Q-E2E rejects every Installed Protected
candidate, including one masked before the end of a tick; Lockdown Protected
candidates remain distinguishable. Only the first failed stub is eligible for
startup tool/lock/storage environment classification; a later failure cannot hide
an earlier install refusal or subsequent contract checks.

Restore samples each journaled launchd service up to five times within a
five-second settle window and the caller deadline, saving every status. Only the
shared complete exit-113 predicate establishes absence. Native pass-2 review must
record the observed statuses, including whether 113 was reached after settling.
Anchor snapshot completion requires the same campaign quiescence fence as pf
group/state completion. Incomplete or out-of-bounds descendant inventory records
a per-entry restore failure and does not skip later journaled anchors.

Pass-3 review: TCP `-v` is pinned for both builds under the restrictions above.
Descendant coverage remains unreviewed on both builds. Multiline `_N` content is
visible but pfctl cannot modify it; foreign inline content in the owned anchor
cannot be removed through the adapter's currently qualified operations. Absolute-call
reachability of an orphan `_N` remains unmeasured.

Core process contracts allow at most three sweeps, one second apart, within the
original call deadline. Only Incomplete with a named foreign pid is retryable;
own-pid, spawned scratch-child, unnamed and final failures remain violations.
Every failed attempt is retained in the core verdict detail. Complete own records are checked field by
field. Kill confirmation retries every Incomplete, including own-pid and unnamed
failures, until its original overall deadline. Image-transition traces include
listed and re-looked-up `(name, ppid, pgid)`.
