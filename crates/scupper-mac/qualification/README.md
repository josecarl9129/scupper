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


R7 adds the `contracts` group on both runners, with a 15-minute run step,
14-minute launchd worker budget, and 1500-second independent dead-man. Its
40-minute job reserves 15 minutes for setup/overhead; the remaining 25 minutes
cover the dead-man, and exceed the 15-minute run plus four-minute final restore. It runs
Q-CONTRACTS, Q-ANCHOR (20 unhooked lifecycle iterations and 20 hooked removals
with states and after global state flush), Q-E2E and Q-FLUSH. Every case uses the
same root-owned harness covered by the complete built/staged hash manifests.
The disposable scratch executable is a copy of that staged `wireguard-go`;
`contract-copy-identities.json` is checked against its original build digest.

Pass 1 deliberately cannot qualify the new adapter operations. Candidate pfctl
rows in `decode/pfanchor.rs` and both builds' `goldens/*/review.json` are marked
unreviewed. An exact candidate match still returns an error from the adapter;
readback returns Unsupported. Raw measurements save exact bytes before any
interpretation. Unknown raw measurement text is inconclusive, never an
automatically learned success. Core storage/reference/process contracts
run first and have a separate verdict even if anchor journaling fails. Only
unreviewed anchor text or Unsupported readback is inconclusive in the anchor
block; other errors and panics are contract_violation. The owner must review
runner captures and independently pin text and goldens before pass 2.

`Paths::qualification` fixes `scupper-qual/scupper`, which is unhooked. Its
Lockdown loads prove no reachability, blocking or evaluation ordering. Harness
raw measurements alone use the journaled stock-hook child `com.apple/scupper`
and a separate rule/table sentinel `com.apple/scupper-qual`. No main ruleset,
parent anchor, pf.conf, or wildcard is changed. Only the explicit F-all raw
scope experiment uses `-F all`; the adapter and restore use scoped
rules/nat/Tables/dummynet flushes. Hooked removal uses raw commands and raw reads
only, with no production-path adapter and no adapter_ok claim.
Global state flush is irreversible and destroys foreign traffic state. Restore
can return pf enablement and fixture resources, but cannot return those states.

Q-E2E's exact fake method audit covers Left startup through incarnation commit;
none of those native methods is a remaining stub. Actual native incompleteness
still yields inconclusive. Install refusal retains the base engine reference
protocol: counted `-E` is correct when a fresh Acquire(sequence) reservation has
reached Synced on both snapshot copies. A reservation permits at most one `-E`.
The ordered platform trace records both write_copy and create_copy requests,
their outcomes (including waits), returned token/pfctl PID and complete reference
reads. Settlement requires a matching complete token/PID read and recorded
fingerprint; otherwise Acquire debt must remain in both final snapshots. Every
engine `-X` must target an engine-recorded fingerprint. Without a committable
reservation only anonymous `-e` is allowed in this fresh-state experiment.
Once acquisition is reached with known boot and healthy storage, at least one
reserved `-E` is required. Stopping earlier, for example at unreviewed D-3
containment text, is inconclusive naming that step, never assumption_holds.
Join runs at least sixty seconds of ticks and checks Lockdown load/read outcomes,
no spawn and no Protected after every tick and across every snapshot write
request. A diagnostic engine hook, compiled only for qualification/tests, also
records every full verification result offered for publication. A successful
verification candidate is distinct from an actual Protected status; the latter
is forbidden, while the engine may mask/reject the former under hold. Durable
writes must retain hold and no child generation; a recorded
pf reference is permitted. Transient startup census/ownership failures are
classified before the expected first-install-failure assertion. Evidence uses
worker-measured ppid and process group identity.

Returned `-E` tokens are journaled immediately. The interval from `-E` effect to
returned-token journaling is covered **only by disposable-runner exclusivity
and restoring the preflight pf state**; the journal cannot close that gap.
Raw acquire captures aid restore accounting but do not remove this limitation.
The call trace omits now/pause/fence, hashes stdin and caps entries at 16,384
(plus one explicit overflow marker), with a 32 KiB per-entry cap. Overflow makes
the case inconclusive. Native pf-text capture retains R6's original mutation-only
selection (-e/-E/-X/-d); reads are not added to R6 capture/failure accounting.
The contracts cell explicitly opts in to full R7 adapter text captures.
Acquire captures have a separate filename prefix for restore scans.

Q-ANCHOR has a 180-second per-case deadline, clipped command deadlines and an
elapsed_ms measurement in its saved verdict, including failures and pass 1.
The unhooked namespace supplies no ordering, reachability or blocking evidence.

Q-FLUSH requires every UDP/TCP IPv4/IPv6 loopback and feth flow to have a printed
state id/creatorid just before the adapter call. TCP traffic uses quiescent
sockets; the qualification-only Darwin IP_BOUND_IF wrapper forces the feth
client onto feth0. Unknown state text, stock loopback skip, unavailable feth or
missing state identities is inconclusive. Interface and address state selectors
are raw measurements only; a fresh state with the floating `all` header must
be positively identified before either selector. The adapter rejects nonempty
selective removal. The F-all scope case first loads an existing target, captures
foreign rule and table entries, and compares complete outputs without command
PID/timing metadata; an unknown result is never treated as an unchanged sentinel.

Run `python3 crates/scupper-mac/tests/r7_mutations.py` for the sixteen portable
assertion mutants. It restores original bytes on every exit and saves outcomes
under target/r7-mutants until the task's required final target cleanup.

The proposed absence/inventory rows follow upstream `pfctl_show_anchors` and
its main dispatch at [855d4e8](https://github.com/openbsd/src/blob/855d4e832803330fc45a64539854bf8d27180600/sbin/pfctl/pfctl.c): immediate children are printed as full paths with two leading
spaces; a missing parent has a named diagnostic, and ignored show-helper return
values can leave exit zero. The proposal binds the named diagnostic to the
queried parent and still requires a complete root inventory and corroborating
missing-filter result. Apple's exact build output remains a runner question.
[XNU pf_ioctl](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/net/pf_ioctl.c)
returns EINVAL for missing rulesets, compares state selectors against the state
kif, and truncates the cleared-state count through `sa_family_t`. These source
facts support proposed shapes and the selective-removal refusal; none pins the
userland output for a runner build. Renderer-derived goldens likewise remain
proposals (including numeric/named service ports and normalization spelling).

R7 fix 1 caveats and owner questions:

- Dummynet is a fourth required-empty class (`-a PATH -sd`), and removal and
  restore add `-a PATH -F dummynet` before absence reads. Pass 1 retains those raw
  show/flush results. These are proposed, unreviewed command/output rows: Apple's
  released XNU sources expose separate scrub/filter/dummynet classes, but the
  Apple PacketFilter userland source was not available in the public distribution
  inspected. Thus exact `-s`/`-F` spelling and whether Apple's `-sr` includes scrub
  could not be source-confirmed. This is a source/qualification blind spot, not a
  claim that no command exists. Unknown output fails closed; no row is promoted.
  Actual scrub rows are rejected by the production filter grammar. Runner review
  must resolve this coverage question before authorizing support.
- Production filter grammar accepts only renderer syntax. Harness labels,
  floating keep-state normalization and anchor declarations have a separate raw
  harness parser, which the native qualified entry point refuses.
- Owner question (L6): removal still stops without flushing when readback finds
  foreign content, including dummynet. Leave can remain stuck. This is the chosen
  fail-closed behavior; broadening cleanup authority needs an owner decision.
- Deviation (L8): hooked sentinel measurements exceed the brief's exactly-one-rule
  limit. The F-all experiment uses a persistent table containing only 192.0.2.123
  plus its narrow block rule. Q-FLUSH uses three pass-quick rules constrained to
  ephemeral TCP listener ports on IPv4/IPv6 loopback and the feth0 pair. These
  rules remain harness-only, absence-journaled and scoped; this deviation is not
  production policy qualification.
- Restore (L11) withholds even our own journaled anchor flushes and feth destroy
  while foreign tokens exist. It records failure and can leave harness rules
  loaded until the disposable runner is discarded.
