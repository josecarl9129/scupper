# Decisions

## 2026-11-13 — Client-link bounce resets WireGuard sessions

Keep immediate D2 LinkDown when bypass-relevant inventory is Unknown. Once down,
keep it down until inventory is known and all existing reopening gates pass.

Implement A: after each client LinkUp, attempt one fixed UDP probe per configured
client, using its device host /32, namespace-held execution, interface and gateway
source bindings, fixed port and payload, and the planner's verified output/config
proof. Failures log and fall back to client retry. Add no firewall exception and
no temporary keepalive override.

Implement B: retain per-peer reset generations and full-resolution netlink
baselines captured while down in run state. Recently active clients (handshake
within 180 seconds preceding reset) keep check at exit 3 ClientSessionsReset
until post-reset authenticated transport or a newer client-initiated handshake
is evidenced. Gateway handshake completion alone cannot clear the generation.
Idle peers warn; time alone never clears an active reset. Containment, latch and
administrative disconnect keep precedence. DESIGN §12 defines the service gate.

Remove the L44 positive TCP retry. Add daemon-L54 for one Unknown tick, no false
OK during session loss, client-side handshake evidence and a first-attempt TCP
canary within five seconds after recovery. Keep captures through service checks.

## 2026-11-14: Gateway session history, fix round 8

New provisioning commits incarnation-bound EMPTY/never-served history. Boot/check
never create it; first daemon/sampler start consumes EMPTY durably before clients
serve. Only the sampler may reconstruct unavailable history after 180 seconds of
complete observations, without a handshake shortcut. Sampling has its own 5 s
cadence and lock, with 10 s slack (15 s freshness); overruns remain gaps through
180 s of resumed sampling, including without rebuild (N1 retained).

Planned client-device teardown quiesces traffic, commits a final complete sample,
confirms destruction, then writes a device/incarnation/sample-bound single-use
clean-stop marker. Next start consumes it durably and judges freshness at stop;
leases age in wall time and any backwards clock invalidates history. Ordinary
daemon restart with a live link uses normal freshness. Abandoned reset intents
require verified live identity, UP state and continuous counters before clearing.

Connect accepts protection/exit success with an honest session-only degraded
verdict. The original heartbeat 600 s session-only grace is superseded by the
2026-11-19 decision below. Status exposes the session reason. Five-second durable
renewals intentionally accept their fsync cost; root snapshot rollback remains
undetectable. The check-only lab provisions explicitly and uses the product sampler.

### Round 9r: latch crash safety without delaying forwarding closure

Latching containment creates the presence-means-latched /run marker synchronously,
closes forwarding, persists the latch within a bounded budget, finishes tightening,
then emits planned events. Marker failure is recorded without blocking containment.
A failed forwarding write moves the storage wait after the remaining tightening.
Startup honors the marker even after the bypass disappears. Remove it only after
confirmed durable persistence or explicit admin clearance. Timeout and an already
pending write recreate it on the caller. This avoids the former storage-dependent
leak window while preserving the administrative latch across a crash.

Ingress quarantine resolves only after a verified lift with client output available;
disconnect and exit unavailability deliberately keep it active, including after a
restart. Stop-time alerts remain journaled for the next daemon process to deliver.

### Round 9s: finish containment before durable latch storage

This user-approved order supersedes the 9r order above: synchronously create the
/run latch-uncertain marker (record failure and continue), close forwarding,
complete every remaining containment operation, persist the latch within its
bounded budget, then publish events before restoring anything. Forwarding zero
does not stop tc mirred redirects. No durable latch-storage wait may delay tc
removal, foreign-link closure, containment LinkDown or conntrack flushing. Restore-group
hardening stays with its create/reconfigure operation, and a ruleset load must
repeat the earlier conntrack flush because it invalidates that proof. This applies
to durable latch storage: client-LinkDown session hooks retain bounded storage
waits (about 150 ms before down, up to about five seconds for tracking after down),
which can delay later containment such as conntrack flushing. Round 9t qualifies
this residual rather than moving the lifecycle fences. Duplicate planned
containment LinkDowns are coalesced with the failed-forwarding fallback.

The 9r claim that its ordering removed the storage-dependent leak window was
incorrect for tc redirects and foreign-link bypasses; 9s removes that window.
The /run marker covers process crashes, including before the durable write, but
does not survive reboot. Crash plus reboot before durability remains a known gap.

The earlier ingress-lift and stop-delivery descriptions record existing product
behavior, not fresh user approval in this round. Strict client-output proof can
leave an ingress incident active throughout disconnect or exit unavailability;
this prevents a false resolve but delays recovery notification. Journaling stop
alerts for the next process preserves them across restart but delays delivery
indefinitely after a final stop. Reconsidering those tradeoffs is deferred; 9s
preserves the existing gates and alert delivery behavior.


## 2026-11-19: Neutral heartbeat logs for verified session readiness

Replaces the 2026-11-18 reset-only exemption and supersedes the 2026-11-14
heartbeat grace decision. A fresh 0 sends success. A fresh session-only 3 uses
`<url>/log` in `status_code` mode only when `Report::session_readiness_log()`
classifies it as `ClientSessionsReset` or `HistoryReconstructing`.
Protection and exit verification must pass, and telemetry must be valid and
current; verdict ordering (`ClientSessionTelemetryUnknown` wins before session
readiness) plus the warning allow-list enforce this. Reset allows only
`ClientHandshakesStale`, `IdleClientSessionsReset` and `ClientSessionsPending`
warnings. History reconstruction after a start or an observation gap requires
`ClientSessionsUnknown` and the explicit `ClientSessionHistoryUnavailable`
warning, allowing only that warning plus `ClientHandshakesStale`,
`IdleClientSessionsReset` and `ClientSessionsPending`. The sampler needs roughly
180 s of complete samples to reconstruct history. This is not a local heartbeat
timer. Missing peers, expired-unconfirmed sessions, unknown/currently unavailable
telemetry, other Unknown causes, and unrelated warnings never qualify.

The sampler does not distinguish starts from runtime observation gaps (stalls,
missed cadence slots, writer contention, quarantined records, open barriers or
durable-write fallback). We accept the same exemption for both, without adding
provenance state. A persistent runtime history fault, including durable-write
failure, is paged only by the monitor timeout, not immediately by `/3`. The
on-host `client-session-history-alert` event still fires. `ok_only` never pages
immediately anyway. The timeout bounds the continuous absence of success;
short recoveries to 0 can reset it repeatedly. A real serving failure visible
only as stale client handshakes remains exit 0 after reconstruction: the existing
Protected-with-stale policy is unchanged.

Compared with 0.1.3, the reset exemption is deliberately narrower to enforce the
sole-cause rule. Reset combined with peer-missing, expired-unconfirmed,
telemetry-unavailable or history-unavailable warnings now receives ordinary
failure reporting (`/3` in `status_code`, withheld in `ok_only`).

Both causes use the fixed plain-text body
`code=3 reason=ClientSessionsPending` (with a trailing newline), which names their
shared readiness condition without mislabeling history reconstruction as reset.
It signals neither success nor failure. `ok_only` withholds every nonzero verdict.
All other nonzero results retain their ordinary status-code behavior. Never
send `/0` for a degraded verdict (I3); `/3` immediately fails a healthchecks check
and would page on every restart if used for history reconstruction.

There is no local reset grace, escalation timer, or durable grace update. Old
grace files and their writer lock are deleted best-effort when heartbeat checks
first start; corruption or cleanup failure cannot affect eligibility. The monitor's
timeout (period plus grace since the last success) bounds the continuous absence
of success, including across daemon restarts and repeated resets that never reach
0. A log ping consumes the ordinary send interval and retains the existing
monotonic freshness/deadline gates. Start with a monitor
grace of at least 10 minutes to cover ordinary sleep/wake resets, then tune it to
observed recovery times: a longer grace avoids transient pages but delays dead
or persistently reset gateway alerts. The monitor grace alone supplies this reset
allowance. Only delivered success-class pings advance local last-success status;
`/log` and nonzero status deliveries do not. Stored URLs keep the 0.1.2 two-byte
suffix reserve; if `/log` cannot fit, that ping falls back to ordinary `/3`.

Fresh nonzero check results enter the bounded event log as
`HeartbeatCheckVerdict` with code, a closed value-free reason, the
heartbeat action (`Success`, `Log`, `Status`, `Withheld`), and a cumulative count
per (code, reason) key, including suppressed observations. A fixed-size table
allows each key to emit immediately on its first observation, then at most once
per 600 seconds, even when other reasons or zero intervene. Recovery transitions
emit `HeartbeatCheckRecovered` with their own cumulative transition count and
the same 600-second debounce. A suppressed recovery is held until the first
healthy check at or after the previous recovery event plus 600 seconds, and
emits once with suppressed transitions included. A newly logged failure clears
the pending recovery; a later recovery starts a new pending transition. Flush-only
healthy checks do not increment the count; other consecutive zeros emit nothing.
State is per daemon process:
`DaemonStarted` is the boundary, and a failure spanning restart does not promise
a recovery event unless observed again in the new process. The action describes
only the emitting observation; intervening actions can differ. For a log decision,
the worker reports the first attempted request class before the event is written:
a `/log` to `/3` fallback records `Status`. Preparation failure or timeout before
an attempt records `Withheld`. Waiting preserves heartbeat-event order without
delaying protection-verdict events. `Withheld` also
covers alerts-only checks with no heartbeat configured. Fresh protection changes
are recorded even if a delivery is in flight. Events use the existing bounded
asynchronous writer and retention limits, never raw diagnostics, addresses or the
secret monitor URL.


### Mac 5a2a round 2: durable session history and checked Recovery exit

Historical rules for the removed session markers, effect history, Recovery slot
and bounded history store (superseded by the resource-model engine, see DESIGN §14).

D1: the helper atomically writes a root-owned session-latch and checks full file
and directory durability before accepting Join intent or exposing a join effect.
It also writes an installation-lifetime joined-once marker, never deleted. Failed
or uncertain durability aborts Join. Only a durably committed clean Left permits
clearing the latch. Startup retries transient reads up to three times, each with a
bounded five-second deadline and a 100 ms pause after an early failure (inside that
attempt budget). Five readers with three attempts each have an approximately
75-second worst-case startup read budget. A valid journal with its expected latch and installation history
uses the normal restart path: load and verify pre-tunnel policy, kill states,
never adopt a surviving interface or child, recreate, and rejoin only after
verified enforcement. A valid clean Left starts without blocking. Recovery is
reserved for missing expected, unreadable, corrupt or unknown-version journal,
latch, joined-once or installation evidence. A verifiably absent latch establishes
clean Left: an unreadable journal is a degraded error, imposes no blocking and
writes no latch. Join is refused until a readable restart or an explicit Leave
rewrites a fresh Left from a valid install record. Recovery entry never writes a
new latch. Main missing with JoinedOnce true and an absent latch is explicitly
classified as degraded Left: the independently absent latch takes priority over
missing-while-expected main. Fixed-name discovery must still rule out leftover
helper anchor/DNS resources; discovery failure or presence reports degraded.

Each Recovery generation has a stable independent 128-bit random/UUID id; losing
readable journal counters cannot reuse an old receipt. At every start its ledger, children and
dispatch high-water are durably imported with a receipt into the selected journal,
including Normal and degraded Left. Continuing in the same Recovery slot keeps its
generation and commits the receipt there. A transfer to main retires the source
only after the destination commit; retirement does not certify cleanup. Receipt
replay never imports settled debts again. Imported Left debt stops repairs and
runs attributable Leave cleanup without acquiring or loading a safety anchor.
Only verified cleanup and a durable Left commit permit Left. If import cannot
commit, idempotent attributable cleanup remains available; the source is preserved,
and acknowledgement waits for the final durable commit. Undecodable/unreadable or
missing Recovery storage with an absent latch requires fixed-name discovery.
Leave can remove that anchor and DNS key while retaining an honest unresolved
token-cleanup error. Boot identity is the boot-session id, with unknown treated as
same boot; only verified previous-boot token/child obligations are void.

D2: Recovery cannot respawn. Only an authorized Recovery Leave can exit: discover
attributable resources using the fixed helper anchor name and DNS key plus recorded
process/utun and same-boot pf identities; stop/reap children, clean
routes/DNS/artifacts, reach quiescence, and remove protection last. Each outcome
must be checked; independently verified absence counts. Potentially owned,
unattributable resources retain Recovery. References positively attributed to
other products are excluded from our inventory and never released. Then atomically
commit a fresh current-version main journal in Left with the independently
validated install owner, and clear the latch last. This checked replacement also
applies to corrupt and unknown-version main bytes. There is no force reset.

D3: emergency blocking requires loading and reading back the pre-tunnel anchor,
an acquired pf enable reference, a checked flush and a fresh complete verifier
observation including reachability, precedence and both address families. Until
verification it is unprotected. Recovery Leave may clean only attributable
resources after the checked prefix even if surrounding pf qualification refuses a
Protected proof. Load, readback, acquire and flush failures retry every second. Only a verification
or qualification refusal while another verified block remains effective can back
off, doubling to 60 seconds. A verified block and every mode transition reset the
delay. After its safety prefix Recovery runs the same cadence of cheap pf-enabled
and anchor-present/reachable checks, including with uncertain ownership. Drift or
failed verification invalidates the blocking claim and reasserts emergency policy.
A Leave that has begun cleanup does not reinstall the removed anchor.
Keep same-boot tokens in memory and the ledger when storage permits, bound
acquisitions, and retain the acquisition/result-recording crash window as Unknown.
Release only positively attributable references; never globally disable pf.
Unreadable install metadata uses a deny-all anchor and cannot claim verification
without qualified inputs. An emergency token can become the reconciled current
reference, with the previous machine token released as predecessor; both count
toward the two-reference bound until checked release or voidness. Before every new acquisition, independently reconcile existing obligations; with
two ledger obligations, independently reconcile their disposition and release
only a checked predecessor while another valid reference remains. An accepted
Recovery Leave survives restoration of readable main storage: resume it in Normal,
retain its ownership evidence, and still require fresh empty attributable inventory
and the checked Left/latch commit before acknowledgement.

D4: the journal is a bounded snapshot committed only on state/ledger changes.
Compact settled receipts (including ownerless unsolicited diagnostics), completed
requests and gone generations; retain every active obligation and resource-bearing
ambiguous outcome. Ownerless state-flush and reference-reconciliation Unknowns
are excluded by construction from dispatch, Leave acknowledgement, Recovery exit
and the unresolved-operation limit. Every reference reconciliation is ownerless;
token ownership remains in acquire entries, including while releasing a
predecessor. An uncertain flush prevents Protected until a later successful flush.
Ownerless Unknowns never gate dispatch: a complete observation
or successful reissue records them as resolved-ambiguous, without retroactively
asserting a successful flush or satisfying the verifier's clean-epoch rule.
Enforce a symmetric 16 MiB read/write cap. New resource creation stops at the
conservative entry, generation, unresolved-operation and 8 MiB thresholds; safety
loads and single-anchor replacements for every purpose, Leave and cleanup use a separate reserve up to the full byte cap. A semantically verified
anchor load prunes debts against its exact rendered generation, using the existing
readback normalization. Only one unresolved replacement can exist for the fixed
anchor; it must be reconciled or superseded by verified loading before another.
Replacement is one load, never flush then load. The 16 MiB hard cap refuses with a
NotProtected alert without recursively attempting emergency dispatch.
Successful periodic full walks and state flushes update only volatile evidence.
Bounds never authorize discarding cleanup debt.

Implementation boundaries (N3–N7, N9): preservation of corrupt/unknown main bytes
until checked replacement applies to Recovery. An explicit degraded-Left Leave
may replace them without an archival copy after attributable cleanup. Periodic
maintenance FlushStates is the single ownerless mutation exception to durable
dispatch-before-exposure: it bypasses ledger, dispatch gate and queue admission,
and uses the current next_dispatch without consuming an id. The dispatch-intent
mutant covers ordinary lifecycle effects, not this exception. Maintenance still
requires checked success for a clean state epoch. With unreadable install metadata
Recovery's lockdown prefix cannot set recovery_safety_done or start Recovery Leave
until a validated install read succeeds. Drivers must yield to an event or the
next cadence/retry deadline after each bounded run; is_quiescent=false is not a
license to spin (a resumed Recovery Leave may wait indefinitely on inventory).
Degraded-Left retry shares retry_at/retry_delay with persistence retry. A latch
that becomes present in that state retains the degraded metadata diagnostic until
explicit Leave; it never silently authorizes Join.

5a2c qualification obligations: live `pfctl -s References` pid/name evidence must
positively distinguish foreign references from ours; a numeric token alone never
establishes attribution. The fake's delayed anchor producer remains observable
across helper restart in its kernel model; the real adapter must record/revalidate
producer identity or conservatively retain uncertainty until producer quiescence
can be established. This fake capability does not qualify real process discovery.

## 2026-11-17 — 5a2 restart after Stuck and tools before the helper commit

Stuck is an in-process state that preserves the current anchor. It does not
survive a helper restart or reboot: when Join or Leaving was committed, a
persisted `internal_error` instead starts the core held plan, loading and
verifying Installed PreTunnel when the install
record is readable, or Lockdown otherwise. Join is refused; Leave follows the
normal cleanup protocol and clears the error with ClearIntent. Until then the
persisted error remains available for status.

After the native start fence closes, a failed helper commit enters PersistBlocked
and permits the restart plan's N-class work, including tool children. Therefore
a tool may belong to a helper incarnation that never committed. Before any new ordinary
effect, the next start fence kills every older orphan of a pinned tool, regardless
of which helper identity survived on disk. The committed-helper requirement still
applies to foreground tunnel spawn and D-class reservations.

Leave is never refused because the replay window is full. Evict the oldest
settled request first (JoinDone, LeaveDone, JoinCancelled, JoinDoneCancelled).
When every slot is pending, Leave may overwrite the oldest id, deliberately
losing replay of that id; a full window refuses Join without entering Stuck.
Leave deliberately preempts queued work synchronously at submit; a queued Join
that it supersedes receives a cancelled record within the bounded replay window.
Insert Leave before the queued cancellation records so that its insertion cannot
evict the cancellation it just created. Eviction of settled ids also means that a
stale retry outside the eight-slot replay window may act again.

The resource-model Recovery/both-copies-missing hold decision supersedes the
old unreadable-Left-journal availability rule: an unreadable pair cannot attest
that the user had Left. It requires conservative held enforcement and checked
Leave, even if the old journal implementation would have stayed unblocked.

A startup process-group/launchd-parent invariant failure is different from an
ordinary in-process Stuck. It has no closed start fence, so the fixed Leave
routine remains unavailable: signalling a shared/incorrect helper group could
kill unrelated processes, and the child/orphan boundary has not been established.
Native enumeration and status continue; supervisor correction and a fresh valid
helper are required. No tools or cleanup effects run under that invalid identity.

If an internal mismatch produces more than two distinct accounting keys, the
frozen snapshot schema cannot encode their union. Checked cleanup still publishes
Left (not durable); every key is kept in memory with token release authority
removed, retries use the Leave back-off, and Exit0 is withheld. This is an
accounting persistence limitation, never a dependency of connectivity cleanup.
The helper stays Stuck and rechecks ClearIntent at intervals up to 60 seconds;
restart uses the old committed Joined snapshot and enters the held plan.

## 2026-11-17 — 5a2 internal error: hold only when join was intended; Stuck without enforcement restarts

The hold-only-when-joined rule remains current. The pre-fence `internal_error`
commit and Restart outcome are historical (superseded by the resource-model
engine, see DESIGN §14). The later emergency and ownership decisions replace
those paragraphs; the speculative-commit safety rule remains applicable.

Restart with `internal_error` enters hold only when the committed snapshot had
`join_intended` or `leaving`. A Left or never-joined snapshot restarts Left,
installs no enforcement and has no hold. Retain the error for status and refuse
Join until the user runs Leave, which clears it. This also covers the startup
invariant Stuck (helper not a group leader or not a launchd child): commit
`internal_error` before the fence, but run no tools or cleanup effects under the
invalid identity (review 05a2r6-fix1 M-A). Status instructs the user to run Leave.

When Stuck would be entered while Join is intended and this incarnation has
never had a verified pre-tunnel or joined proof, commit `internal_error` if
storage allows and return the explicit Restart outcome. The caller exits
non-zero so launchd restarts the helper into the verified hold above; the engine
never calls `process::exit`. Keep Stuck in process after this incarnation has
verified blocking, and for Left without Join intent. Launchd's throttle bounds
restart loops; each iteration starts the blocking plan before any rejoin
(review 05a2r6-fix1 S-A).

Only a waiting speculative D commit may be superseded by an accepted
observation. A superseded PersistIntent must re-plan the admitted Join and
commit its intent before exposing any later D effect. Failed Stuck ClearIntent
rechecks revoke Left publication and name the remaining cleanup item.

Mutants never run in the implementation checkout. Run mutation scripts only in
a disposable copy (a separate git checkout at the same commit), so a killed
script cannot leave a mutant in code that will be committed (review
05a2r6-fix1 S-E, run 6 M-1).

## 5a2 Stuck while join is intended: emergency lockdown in process, no Restart (2026-11-17)

Historical pre-fence containment refusal and unresolved writer-lock requirement
(superseded by the resource-model engine, see DESIGN §14). The later stateless
containment and instance-lock decisions apply; in-process Stuck remains current.

Supersedes the "Stuck before enforcement" / Restart paragraph of the preceding
entry. Restart could repeat a startup invariant, snapshot validation, encoding,
sequence or settlement failure forever without loading any blocking policy.
There is no Restart outcome or self-restart because blocking is unverified.
An unrelated restart still uses the M-A/M-2 durable hold path.

Every Stuck entry, including an unrepresentable startup selection, uses the same
in-process decision. When join is intended and blocking is not currently believed
installed, an independent emergency loop loads the input-free core Lockdown
policy. It requires no core completion, snapshot encoding, sequence allocation or
successful commit. Persisting internal_error is attempted but never gates blocking.
A closed start fence is required; an open fence keeps sweeping with Recovery's
unknown-previous-helper rules. The startup ownership invariant is never waived
for lockdown: a failed invariant reports NotProtected("internal: not blocking")
and loads nothing. This unblocked state is an explicit residual.

One bounded load-and-global-verification attempt runs at a time, using platform
tool deadlines and reaping, with a one-second retry after completion. Emergency
pf enablement follows the reference decision recorded below. Leave removes the
anchor and does not disable global pf. Full R0 verification includes global hooks, traversal, tool
integrity and state evidence. Pf-off, anchor loss and readback drift revoke the
evidence and reload. Stuck always publishes NotProtected("internal"), with a
separate emergency_blocking_verified field, and never Protected.

Leave revokes emergency retries first, then cancels and reaps outstanding tools,
then runs the fixed cleanup and removes the same anchor. A late completion cannot
reinstall it. Leave also runs when already Stuck or after an earlier Exit0, and a
Leave queued before Stuck is retained. Cleanup still requires a closed fence and
valid startup ownership. Fixed Leave is refused under a failed ownership
invariant, as recorded in the preceding entry.

Verified blocking means currently believed installed: RemoveAnchor, ClearIntent,
pf-disabled, anchor-loss and definite policy/readback-drift observations clear it.
Tunnel-only RecreateChild and Rerender repairs during emergency reverification do
not clear installation knowledge. One-off Unknown and read failures preserve it;
sustained missing fresh proof beyond max_age (15 seconds) revokes it and installs
Lockdown. Stuck uses one-second cheap checks and five-second full walks. Published
proofs expire without driving the engine; cheap positive checks never extend them.

During Leave admission, eviction prefers settled records from before that
operation, then pending Leaves, preserving multiple newly created queued-Join
cancellations. Join admission reserves one of the eight replay slots for Leave;
at most seven unsettled/queued Join admissions can coexist.

SF-6 is deferred to run 7: a stray helper with an invalid identity can still
attempt the internal_error commit without an exclusive single-instance lock.
Concurrent incarnations can interfere with the snapshot pair. Run 7 must cover
two writers and decide the lock/commit ownership boundary. No mutation scripts
were run in this checkout or in this round.

## 5a2 emergency lockdown: pf enable and unreserved references; Leave under a failed invariant (2026-11-17)

Historical read-back-mismatch veto on enablement (superseded by the resource-model engine, see DESIGN §14).
The later always-enable-after-own-load decision applies. The unreserved
acquisition residual remains implemented.

- **Enabling pf when verification is impossible.** After a successful load of the input-free Lockdown, the emergency
  loop enables pf and flushes, even if qualification or read-back parsing fails because the pf output cannot be
  interpreted. It does **not** proceed when a read-back is parsed and shows a different policy or target; that
  failure retries the load. `emergency_blocking_verified` stays false until full verification passes. Enabling pf
  can activate other products' rules, so this is not "harmless"; it is chosen because privacy takes priority over
  availability.
- **References.**
  - If pf is already enabled (by us or anyone), emergency acquires no reference.
  - Otherwise it uses the normal reserve-before-effect path when a commit succeeds.
  - If storage is failing, one unreserved emergency acquisition is allowed per helper incarnation. The allowance is
    marked consumed before `pfctl -E`. A timeout, lost output or unparsable token counts as possibly acquired and is
    never retried.
  - Leave releases only tokens it knows it owns.
  - Residual (accepted): a crash loop under failing storage can accumulate up to one unaccounted reference per
    incarnation. They keep pf enabled until reboot or manual release, and never weaken blocking.
- **Leave under a failed startup invariant is refused** (the earlier decision is restored; review 05a2r6-fix3 S-4).
  Running the fixed cleanup from a stray, non-launchd instance could kill the live helper's child and undo its
  state. Status names the misconfiguration; 5a3 setup checks launchd ownership.


## 5a2 emergency lockdown: reference-free enable fallback (2026-11-17)

Historical semantic-mismatch veto and storage-wait description
(superseded by the resource-model engine, see DESIGN §14). Later decisions
require enablement after our own load and sliced storage waits.

Amends "emergency lockdown: pf enable and unreserved references" (review 05a2r6-fix4 M-1).
- A definite NotStarted (pfctl never ran) consumes nothing.
- The reserved path keeps its normal accounting.
- When no accounted `-E` is allowed (the allowance is used, the cap is full, or the outcome is ambiguous), the
  emergency loop enables pf with `pfctl -e`, which takes no token, retried at the closing cadence.

`-e` is idempotent and takes pf's single anonymous enable reference without a token,
so retries cannot accumulate references. That is the concern the earlier
critique raised about blind `-E` retries. pf then stays enabled until reboot or someone else disables it. scupper
never disables pf globally, including on Leave. This is the same accepted cost as a leaked reference, and privacy
over availability decides it.

An incomplete pf-info read never authorizes acquisition: the loop uses the reference-free fallback instead.
Committed ambiguous acquisitions keep their durable reservations, and the two-key cap never permits an
unreserved acquisition. Definite NotStarted settles its reservation and restores an unreserved allowance.
Only a definite parsed policy/target mismatch (including missing final block, unexpected statement, or empty
policy) refuses emergency enablement. Normalization and qualification errors enable and flush without a claim.

An installed Lockdown is reloaded only on observed absence or definite parsed policy mismatch. While verification
is unavailable, state flushes back off from one second, doubling to 60 seconds; a new load or observed disabled-to-enabled
transition or fresh verified block resets this delay. Flush failures also back off while the installed blocking policy remains present.
The engine still checks enablement and retries needed enables at the one-second closing cadence, and reaps tunnel
children in join-intended Stuck. A fresh full verification remains necessary for any published blocking proof.

The reserve-before-effect commit writes both snapshot copies between load and `-E`. Under hanging storage this
can add two write deadlines before enablement. Leave removes the anchor but conservatively retains emergency
reference ownership for reconciliation by the next incarnation; known tokens are released there, while foreign
and ambiguous tokens are never released without the existing ownership evidence.

## 5a2 emergency lockdown: always enable after our own load (2026-11-17)

Amends “emergency lockdown: pf enable and unreserved references” (review
05a2r6-fix5 D-1).

After our own successful `load_anchor`, the emergency path always enables pf:
reserved `-E`, otherwise the reference-free `-e` fallback. A read-back that parses
as a different policy, is empty, absent, or unreadable drives the next reload and
withholds verification. Disabled pf passes everything; enabling after our load
cannot admit more traffic than disabled pf. Activating other products’ rules is
an accepted availability cost: privacy over availability.

Skip a reload only on positive evidence: the normalized current read-back must
be byte-equal to the read-back captured immediately after our own load. A definite
semantic mismatch still requires reload even if its printed text is stable.
Different, missing, or unreadable output retries with 1 s, doubling to 60 s,
independently of flush backoff. Stable unsupported output retains installation
knowledge without claiming verification. A definite `NotStarted` acquisition
settles its reservation, uses `-e`, and backs off further reserved attempts with
the same 1–60 s schedule to bound snapshot writes if both commands keep failing.

Run 7a covers these decisions, typed capture errors, generated emergency and Stuck
fault tables, and Leave/reference rows. Crash boundaries, two-incarnation and
single-instance behavior, and post-exit requests are run 7b. Mutants run only in
the coordinator’s disposable run-7c checkout. Real-adapter contracts (EEXIST,
NotStarted versus Unknown, and tool pinning across OS updates) remain run 8/5a2c.

## 5a2 emergency reload recovery and known storage failure (2026-11-17)

Historical reservation timing and post-load acceptance details
(superseded by the resource-model engine, see DESIGN §14). Later storage-slicing
and guarded read-back rules apply; known-storage-failure fallback remains current.

Amends the run-7a reload and reservation rules (review 05a2r7a, fix 1).
Reload backoff covers present but unequal or unreadable observations after a
successful own load. Positive absence from either cheap checks or read-back
resets it to one second, measured from the last load attempt; repeated absence
cannot create a load storm. Before any own load succeeds, failures retry every
second. Observation drift never delays recovery from known absence.

On a qualified OS, post-load text is retained as our text only if baseline
capture succeeds. Foreign or unsupported text arriving between load and read-back
therefore retries with drift backoff. An unqualified OS retains the prior
record-any-text behavior, without claiming verification. A garbled successful
read revokes a previously verified Joined policy immediately and can replace it
with Lockdown; this privacy-favoring rule is intentional.

Known blocked storage, or any failed emergency commit earlier in this episode,
skips reservation entirely. The existing cap/counter limits and one unreserved
`-E` allowance still apply; otherwise use reference-free `-e`. No storage write
precedes that enable effect. Successful `-E` resets its retry backoff.

Storage whose failure is not yet known still uses reserve-before-effect. The
reservation budget is `2 × command_deadline + 1 closing cadence` (11 seconds
with production timings), plus a command deadline if acquisition itself hangs
(16 seconds total). This replaces the earlier “two write deadlines” description;
the commit has one overall budget shared by both copies. The run-7a model
measured 5 seconds for the first storage hang (11 seconds was the conservative
bound). This historical budget is superseded by the decision below. Always
enabling with `-e` before `-E` would change the reference model.


## 5a2 emergency reservation deadline; single-instance lock (2026-11-17)

Historical one-second total reservation budget, structural-lock refusal and
unqualified post-load acceptance (superseded by the resource-model engine, see DESIGN §14).
Later decisions retain total storage budgets with one-second maintenance slices
and permit stateless containment on structural lock failure.

- **Emergency reservation deadline** (review 05a2r7a-fix1 F3 and D-1). The emergency path's reservation commit gets
  a short deadline of 1 s, used only there.
  - On timeout it takes the existing failed-commit path: the unreserved or `-e` enable.
  - Reserve-before-effect is kept, and the first unknown storage hang costs about 1 s, not 5 to 16 s.
  - "`-e` first" was not adopted, because it would change the reference model.
- **Post-load text** (L-1, L-2). Our post-load text is accepted only after two identical read-backs taken right after
  our own load. Any raw change after that reloads within 1 s.
- **Single-instance lock.**
  - Before reading the install record or the snapshot, the helper takes `flock(LOCK_EX|LOCK_NB)` on a lock file
    outside the removable state, in a root-owned directory whose ancestors are checked. The file is opened `O_RDWR`,
    `O_CREAT`, `O_CLOEXEC` and `O_NOFOLLOW`. `fstat` must show a regular file, owner root, mode 0600 and one link.
  - The lock file is never unlinked or replaced.
  - The fd is held for the whole process life, through shutdown cleanup. Children never inherit it, and the child
    never calls `LOCK_UN`.
  - On contention the instance exits at once with a distinct status. It does no snapshot read or write, no sweep, no
    tools and no anchor, and it does not create or unlink the control socket. Any other lock error also fails
    closed, with its own status.
  - The control socket is created, and a stale path unlinked, only while the lock is held.
  - Startup invariant failure, now checked after the lock, logs and exits without any shared-state write. This
    supersedes "commits `internal_error`" for that cause.
  - Uninstall (5a3) must stop the job and take the lock before removing state.
  - Real multi-process macOS tests go to 5a2c: crash, fork/exec inheritance, replacement and uninstall.

At production tool deadlines, the deterministic entry-to-enable rows measure
1 second for the first unknown reservation-storage hang, 6 seconds when that
hang is followed by an `-E` hang, and 5 seconds for an `-E` hang under already
blocked storage (5-second tool timeout, then immediate reference-free `-e` under F6).
Known blocked storage with a working toolchain enables immediately; no storage
write precedes that enable effect. These bounds assume successful subsequent
enablement and exclude persistent tool failure or an open mutation fence.
Normal commits retain their existing overall budget. While emergency enablement
is pending after an ambiguous `-E`, internal-error persistence and storage
retries yield to the next emergency cadence. Otherwise a fresh storage hang
could delay the reference-free fallback beyond the six-second bound. F6 now attempts that fallback immediately after
the ambiguous outcome rather than waiting for another cadence.

Post-load acceptance records raw bytes separately from verifier qualification.
Two immediate identical observations allow stale qualification or unsupported
output to remain stable without weakening proof publication. A writer changing
text between the reads is rejected; any later raw change overrides reload
backoff, at most one attempt per second. A writer racing both observations with
the same foreign text remains observationally indistinguishable; acceptance of
raw text grants no verification. Persistent cheap absence (including hook loss)
causes at most one reload and one state flush each second. A missing main hook
still prevents anchor enforcement; hook repair/qualification remains for run 8.
Repeated external pf disable under blocked storage consumes at most the one
unreserved `-E` allowance in an incarnation and uses reference-free `-e` thereafter.

Crash-prefix tests distinguish same-boot helper death (page cache and kernel
references survive) from reboot (pending bytes and old-boot references vanish).
Durable internal error with Join/Leave intent rebuilds blocking under hold;
Retained reference accounting never grants authority to release an unrecorded token. Reload,
failed-commit and unreserved-allowance flags are intentionally incarnation-local.
The fake models lock contention, storage sharing and process-lifetime release;
fd flags, filesystem validation and real process inheritance remain adapter
contracts to be qualified on macOS in 5a2c.


The crash matrix also covers a held restart with durable internal error and two
uncertain acquisition reservations. Neither reservation may be freed on the same
boot. If that debt keeps the reducer ahead of its blocking prefix, the engine
runs independent Lockdown, using the existing full-cap `-e` fallback. It retains
both debts, allocates no new reference and spawns no child. The held reducer
parks while independent Lockdown owns the anchor, until Leave resumes cleanup;
its incompatible policy prefix must not replace that anchor. Independent global
verification is published as emergency blocking, while hold still refuses Join.
Leave revokes that loop and proof before any removal; a later admitted Join can
arm emergency protection again. Ordinary Recovery's core prefix is unchanged.

## 5a2 lock failure other than contention: best-effort lockless lockdown (2026-11-17)

Problem (review 05a2r7b H1 and the open lock question): when the lock fails for a
non-contention reason, no instance can ever lock, so a join-intended Mac would
never block. This supersedes the earlier refusal on structural lock errors.

Decision (best-effort mitigation, not a guarantee):

- **Intent.** Read both snapshot copies read-only, with no repair. Left is trusted
  only when both copies are valid and agree. Joined, Leaving, a conflict, stale
  state or unreadable state all count as block.
- **Blocking.** Use stateless Lockdown without storage writes, sweeps, kills, the
  tunnel, pf references or the control socket. Check pinned pfctl, load the
  input-free Lockdown anchor, enable pf with `pfctl -e`, and flush states with
  backoff. Perform the full global Lockdown verification and log its verdict;
  publish no Protected claim. Reload within 1 s when the anchor is absent or
  changed.
- **The lock.** Retry EINTR immediately. Retry structural errors every 1 to 5 s.
  Never replace the lock file. Contention still exits immediately.
- **When the lock is taken.** Continue in process with the lock retained: stop
  fallback dispatch, drain and reap our own tool children, then run normal
  startup, which loads its own policy. No delayed fallback effect may cross that
  normal policy load. If the locked reread finds Left after fallback may have
  loaded Lockdown, stage normal Leave cleanup to remove that fallback policy;
  ownership and the start fence still precede every shared-state write.
- **The control socket.** It is independent of safety in the locked path too.
  Report creation failures and retry at 1 Hz while Lockdown, reference-free `-e`,
  flush and full verification proceed. Without transport, Leave is unavailable;
  uninstall still takes the lock.
- **Deferred ownership.** In Stuck, decide startup ownership even without join
  intent. A definite failure exits without shared-state writes, releasing the
  lock on process teardown.
- **Internal error persistence.** Pending enablement defers the annotation for
  at most the next emergency cadence, measured after the first attempt returns.
  Thereafter storage retries follow their own cadence even if `-e` keeps failing.
- **Held reducer.** Park only when blocking is unverified and the next core step
  is outside the blocking prefix; once independent Lockdown owns the anchor,
  maintain it until revocation. This applies to all reference shapes. Revocation
  stops parking immediately.

Residuals: traffic can escape before the first lockdown at boot or during a
failed flush. The earlier before-networking boot requirement is narrowed by the
2026-11-20 resource-model decision: best-effort early load, measured boot gap,
no Mac first-packet guarantee. Apple treats PF as an unsupported API, so version-specific behaviour
needs qualification. Run 8 qualification must confirm that two consecutive
`pfctl -sr -a` reads of our own load are byte-identical on every supported build,
without verbose counters or nondeterministic ordering.

## 5a2 locked emergency: stateless lockdown before the start fence (2026-11-17)

Problem (review 05a2r7b-fix1 N1): the locked emergency needed a complete inventory,
a closed start fence and closed reaping before it loaded Lockdown. It therefore
blocked less than the lockless fallback.

Decision (D-3, best-effort containment):

- **Allowed before the fence closes,** and explicitly exempted from it in the
  platform contract: fixed-argument pinned-pfctl commands that load the Lockdown
  anchor, `pfctl -e`, verification, and a narrowly specified state flush. Old
  states bypass rule evaluation, so the flush is not deferred. No rule or anchor
  flush is exempted.
- **Still gated:** `-E` and reference bookkeeping and release, ordinary policy
  changes, tunnel starts, and Leave's `RemoveAnchor`. Leave also needs an
  authorized Leave, reconciled ownership and the termination and reaping of
  emergency writers, so that a delayed Lockdown cannot undo cleanup.
- **Continue while the fence is open:** sweeps and reaping, since they are what
  closes the fence. Emergency children are included in the eventual quiescence
  proof.
- **Repair** after a stale write or drift means reload, then verify with pf
  enabled, then flush states. A reload alone is not a repair.
- **Status** reads "containment attempted; safety unproven" until a full
  verification passes. A reload within 1 s is not a leakage bound.

This supersedes "never load with the fence open" from the Stuck-emergency entry,
for these commands only. A definite startup ownership failure still refuses
shared-state writes and signalling and exits; undecided ownership must not
withhold stateless containment. Preliminary stateless containment may already
have run before a complete inventory establishes refusal.

Reference-free `-e` is used for lockless and D-3 containment, recorded control
socket failure, incomplete pf status, and when the existing reservation model
cannot acquire now: blocked storage/failed reservation with the one unreserved
allowance consumed, a full cap, sequence exhaustion, or acquisition retry
backoff after a failed/ambiguous tool outcome. Socket failure remains a separate
explicit exception because transport recovery must not precede containment;
"not created yet" grants no exception. Retry backoff uses `-e` to enable filtering
without repeatedly exposing `-E`; it owns no token. Known Enabled skips `-e`.
Healthy held Normal-mode emergencies follow reservation-before-`-E` after the
fences close, using the independent accounting path already used in Stuck.
When pre-fence `-e` enabled pf, the closed-fence path still obtains its reserved
reference when the cap and storage budget permit, rather than treating that
enable as reference ownership. Before authorized Leave resumes a parked held
reducer, transfer the current durable reference accounting back to it; cancel only
its never-dispatched speculative acquisition. This prevents stale reducer
accounting from resurrecting settled entries or losing emergency references.

Handoff preserves a durable Leaving cleanup plan, appending RemoveAnchor only
if absent. Plain Left stages only fallback-policy removal. With the lock held,
our tools get the normal tool deadline to drain, then exact live identities are
killed and reaped; stateless maintenance runs before each drain attempt. On
contention, only a bounded own-tool reap is permitted before the exit outcome;
an unkillable writer can still outlive process exit (fail-closed availability
residual). The production caller must exit on InstanceContended. Immediate EINTR
retries are capped at eight, then follow structural-error backoff.

N11 sweep provenance: the emergency fence retains a checksum-selected helper
record even when the durable machine fails semantic validation. It is a prior
incarnation hint under the existing guarded group/start rules, not a fresh
ownership proof. Pinned orphan tools remain independently targeted. Helperless
Recovery/hold keeps Unknown and its ambiguous-process rule. A surviving unowned
child cannot override Lockdown; the narrower hint avoids treating every invalid
machine as authority to broaden ambiguous targeting.

N7 availability residual: if lockless uncertain intent installed Lockdown and
both copies later agree on Left, the fallback stops maintaining it but cannot
remove the anchor while the lock remains broken. Removal waits for locked,
fenced Leave cleanup; a read-only Left observation grants no removal authority.

## 5a2 locked start: 1 s intent probe before storage reads (2026-11-18)

Problem (review 05a2r7b-fix2 F1): under the lock, the full A/B storage reads can
spend about 37 s before containment, while the lockless path decides within 1 s.

Decision: apply the lockless intent rule immediately after taking the lock.
Read both copies read-only with one shared 1 s total budget, before reading the
install record. Join intended, Leaving, conflicting, unreadable or undecided
intent triggers D-3 stateless containment immediately, then normal full reads,
classification and startup. Two valid, equal Left copies trigger no containment.
If full startup establishes Left, stage fenced Leave removal of that containment
anchor, preserving any durable Leaving cleanup. Leave pf as it is; scupper never
disables pf globally.

D-3 maintenance has its own 1 s cadence before inventory and drainage. Startup
sweeps poll without sleeping; emergency sweep, kill and reap share a 1 s slice.
A tick never performs a second startup sweep. These bounds assume working pfctl;
tool failures retain their bounded tool deadlines and no proof is published.

F8 clarification: D-3 deliberately overrides a previously verified Joined anchor
while ownership or writer quiescence is undecided, including a same-boot locked
restart. This can briefly interrupt connectivity. Fresh containment is preferred
to trusting proof that may overlap a stale writer; reference reconciliation must
retain continuous pf enablement through the subsequent normal start.

F5/F6 clarification: after D-3's reference-free enable, known Enabled only permits
`-E` with a committed reservation. Blocked storage or a full cap preserves the
unreserved allowance. A failed or ambiguous acquisition starts acquisition
backoff and immediately attempts reference-free `-e` if not known Enabled. This
keeps DECISIONS' existing backoff rule and avoids waiting for the cap to fill.

F3 refinement: structural lock failure still grants no authority to sweep or
signal foreign processes. It permits guarded timeout cancellation and reaping
of exact own tool children, confirmed parented to this incarnation in its group.
Tool calls have already spent their normal deadline before exposing an unreaped
child. Stateless maintenance precedes a shared 1 s cancellation/reap slice. This
supersedes the earlier blanket prohibition on lockless kills for own children
only; contention still performs only bounded reap before exit.

Probe-only cleanup over trusted Left does not authorize clearing a durable
internal error or acknowledging Leave requests. It removes the containment
anchor and preserves that error until an explicit Leave, so a pending Join
cannot be replayed merely because the probe needed containment.

## 5a2 residual containment and availability (2026-11-18)

Locked-start install/copy reads retain their original total budgets (5 s for
the install record, up to three command-deadline attempts per copy). After an
intent probe requests containment, each attempt waits on the same operation in
at most one-second slices, with containment between slices. Commits retain their
original total budget (normally 10 s, at most one command deadline per copy),
including emergency reference reservations. Timed-out writes are polled, never
restarted within a slice. A total timeout still leaves a write outstanding under
the storage fence; read results are abandoned at the original total deadline.
Slow storage within those budgets therefore completes without a helper restart.

The slice cap applies in Starting, Stuck and PersistBlocked, or any mode with
lockless fallback or emergency containment loaded, only while join is intended,
revocation/ownership refusal is absent. A fresh verified Joined or PreTunnel proof
of this incarnation exempts policy replacement only when no own Pfctl tool is
unreaped; an outstanding MTU tool cannot overwrite pf, but an outstanding Pfctl can.
Even under this exemption, waits remain sliced and cheap checks observe pf enablement
and anchor presence between slices. A negative check immediately drops the exemption
and contains; positive checks never extend the proof's 15-second lifetime.
The negative observation also invalidates reducer observations without a recursive
storage commit, so returning to Normal cannot publish the earlier Joined proof.
Saved reducers also inherit observations made during storage at completion/retry
handoffs, including a failed retry, before they can replace the current reducer.
Failure to reap a non-Pfctl tool alone also preserves this current proof internally;
status publication still masks protection while the general tool fence is open.
This exemption checks the tools present now, not tool history. A current proof
requires a closed fence at verification; every reducer pfctl writer invalidates
that proof before starting, and emergency load/flush/enable writers are blocking.
Thus a current proof implies no own asynchronous pfctl writer has started since
verification. A hung read-only cheap check enters the Pfctl fence and drops the
exemption on the next slice: conservative Lockdown can cost availability.
During an outstanding storage wait, maintenance uses the stateless path. An explicit
stateful-emergency frame guard prevents re-entry into load_emergency during load,
enablement and reservation commits. Lockdown is already loaded in that frame:
maintenance uses reference-free -e and checks anchor presence and readback.
Frame-scoped reload_pending and flush_pending latches retain repair intent across
storage slices. Missing, mismatched, unknown or failed anchor readback sets both
latches and marks the frame disturbed. Only an own Lockdown load followed by two
matching, semantically verified Lockdown readbacks clears reload_pending; foreign
or unsupported post-load text is never adopted as the guarded reference. Merely
observing Lockdown again cannot discharge a pending own reload.
Each slice re-enables pf if necessary, attempts a pending reload when its gate is
open, then attempts one pending reference-free state flush. Every guarded reload
and re-enable sets flush_pending. Only a successful flush clears it. Capacity
refusal, pin-check failure and tool failures retain pending work for later slices.
Guarded reloads and flushes each run at most once per calendar second (the clock
uses floor seconds, so attempts across a boundary may be less than 1000 ms apart);
the reload gate also respects the outer load's second. The guard uses this
one-second retry gate, not the outer path's doubling observation backoff.
Unknown or unsupported readback
therefore retries at this bounded cadence until verified success. A disturbed
frame resets the outer observation backoff to 1 s unconditionally, including when
both repair latches are already clear. Every disturbed frame discards its comparison
readback, so this reset restores observation of later raw changes even when no
storage guard runs in the next frame. It also carries unfinished repair forward.
The next reload is due no later than 1 s after the last own load. This can add one
outer reload and flush after each disturbed storage-wait frame, including on hosts
whose readback never verifies; reloads remain bounded by the last-own-load gate.
The next undisturbed frame can still establish fresh proof if verification succeeds.
Guarded flushes never create clean-state proof evidence. A frame that ever sets
either latch remains disturbed even after both repairs succeed: the outer frame
discards its earlier readback, baseline and proof and forces an additional flush.
The guard also disturbs a frame when it performs that frame's own pending enable.
This deliberately delays proof until the next fresh frame, an availability cost
of treating every guarded re-enable as flush debt and disturbance.
Only a subsequent fresh verification may publish protection. Capacity recovery and
working pfctl bound containment; an unreapable capacity backlog can defer repair.
Maintenance never replaces reservation/accounting state; a pf disable marks
reference reconciliation necessary, including after acquisition.
Enablement is re-read after reservation storage, before spending an unreserved
acquisition allowance.
Total budgets include the time spent on maintenance; slow or failed
pfctl retains its own command deadline and can still prevent storage completion.
Held emergencies own their drain slice instead of waiting for generic reaping.
Socket-failure startup gives own-tool drainage a fresh one-second slice after
inventory and the stateless pre-step.

Emergency pfctl spawning stops while two own pfctl children remain unreaped,
including lockless maintenance, and emits a SafetyEvent. Cancellation/reaping
continues. An unkillable kernel ioctl can therefore prevent further repair;
working pfctl remains the assumption behind the containment cadence.

Deliberate R4 availability residual: an uncertain Left intent probe may install
Lockdown before startup discovers a definite launchd-ownership failure. Startup
then refuses shared-state writes and Leave, so there is no automatic remover.
While the installation/ownership issue persists, an administrator can recover
connectivity with `pfctl -a com.apple/scupper -F all` for the fixed scupper anchor
(DESIGN §14 / ADR 0021). This removes that anchor's policy; pf stays enabled.
After ownership is corrected, restarting the helper also removes probe-only
containment when full locked startup establishes Left. Manual removal is needed
while the ownership problem persists; DESIGN §14 also documents the same
administrator escape while Starting or structural lock failure prevents Leave.

The 7c mutation harness classifies build failure separately from running test
binaries. Any expected libtest FAILED record is a kill regardless of panic cause;
unexpected FAILED names, crashes, timeouts and memory exhaustion are separately
flagged kill categories. Every test binary runs through a host-target Cargo
runner using `prlimit --as` (4 GiB by default, configurable in bytes). Cargo and
rustc are outside that test-only limit. Controls pre-build with `--locked`, and
each named test has its own timeout. After an abnormal stop, re-invoke the harness
immediately to recover its journal and stop orphaned sessions; confirm a clean
checkout before using a disposable tree for gates. Simultaneous SIGKILL of both
controller and watchdog still needs that recovery, although binary memory remains
bounded by the runner.

A read longer than the install record's full 5-second budget still latches the
install record to None for the rest of the process. Recovery of that record needs
a helper restart; a later read is not attempted in the same session. Storage reads
run in abandonable workers independent of the single write fence. Abandonment
invalidates the result. At most two read workers (active plus abandoned) may
remain alive; at capacity further reads return Busy/Unreadable without starting a
worker until one exits. Writes use
their independent fence and remain available. A hung worker therefore bounds thread
use while two hung workers make reads unavailable until one exits. One abandoned
intent probe still permits install/full-copy reads in the remaining worker slot.

## 5a2 post-Joined reference reconciliation error (2026-11-18)

A reconciliation failure after the Joined proof is established records both a
reference error and the last status error. Successful reconciliation with no debt
or predecessor now clears that same last error along with the reference error,
while preserving a different last error. Mirror matching is by value, so identical
reasons share the mirror; clearing it restores any unresolved enforcement_error.
The shared clearing call at successful reconciliation additionally requires
!reference_debt(): during Leave a held current token retains the reference and
ReconcileReference cleanup errors until release. Previously a successful retry left a
stale failure visible indefinitely despite Joined protection and settled ownership.
This is a status/availability reporting defect, not a packet leak or lost reference.
The deterministic 24-completion recovery case and saved proptest seed cover it.

## 5a2 run 7c-b mutation harness (2026-11-18)

Rust flags environment variables, including CARGO_TARGET_*_RUSTFLAGS, are removed.
Core dumps are inspected only in tracked-tree directories outside target, with
symlink directories excluded. A full-suite FAILED test is rerun once after verified
source restoration. Only when every failing test also fails clean is the result
killed-flaky and excluded from the kill total. Any failing test that passes clean
makes the result killed; flaky test names remain in the note. Inconclusive reruns
without a clean pass are test-error. Validation/self-test do not run mutants.
Core lifecycle mutations use an explicit core-mac:: witness selector for the mac
integration suite. Full-suite mode for these rows runs only scupper-core --test mac,
excluding core unit/other integration suites and scupper-mac lib tests; this can
under-count kills. The two individual frame-guard removals are equivalent because
either wrapper sets the same guard before storage. A shared-predicate mutant
removes both effects together, reached by the slow stateful-commit test.

## 5a2 run 7c-c1 equivalent guards (2026-11-18)

`l-035-intent-86`: CopyClass::V.bytes contains the entire authenticated input including the little-endian sequence at bytes 12..20. Equal bytes imply equal decoded sequences, so a == b implies a_seq == b_seq. Check classify_copy sequence extraction and returned bytes.

`l-038-intent-89`: Every CopyClass::V snapshot passed validate_durable, which rejects leaving && !leave_requested. The still-required !leave_requested therefore implies !leaving. Check classify_copy -> Snapshot::validate -> DurableRecord::to_core -> validate_durable.

`l-040-intent-91`: validate_durable rejects hold && !join_intended && !leaving. The intent guard already requires !join_intended and !leaving, so any validated snapshot reaching the hold conjunct has hold=false. Check that invariant in validate_durable and the remaining intent conjuncts.

`p-017-stuck-leave-ready`: ready is check_startup_invariant() && close_emergency_fence(). If ownership definitely fails, reaped is false via !startup_invariant_failed. If inventory is unknown, check_startup_invariant leaves the start fence open. If close_emergency_fence returns false, the start fence is open. cancel_emergency_tools never changes start_fence, and the immediately following start_fence != Closed guard returns in both open cases. Thus removing !ready cannot reach cleanup. Check these three functions and the following guard in run_stuck_leave.

`f-011-fence-target-216`: An owned process satisfying the ambiguous arm's remaining ppid==1 and start<own.start conditions has already matched the preceding owned-orphan arm and returned Target::Process. Removing !owned cannot change the selected target. Check the immediately preceding if in start_fence_inner.

`f-012-fence-target-217`: The ambiguous arm requires ppid==1. Zombies matching it are excluded from sweep_matching survivors by state!=Zombie || ppid==own.pid (a helper has pid>1). qualify_pathless also explicitly ignores zombies. They are never signalled or included in closure evidence; removing the target-state condition changes no observation. Check start_fence_inner, qualify_pathless and the survivor filter in sweep_matching.

## 5a2 l-033 probe containment before PersistLeaving (2026-11-18)

When a startup probe installs Lockdown over a snapshot with leave_requested but
without leaving or join intent, stage leaving and the cleanup plan using the
core's PersistLeaving transition before appending RemoveAnchor. Preserve the
snapshot's reference accounting while deriving that plan. Reference-bearing
snapshots need the full core cleanup sequence; reference-free snapshots still
need RemoveAnchor to remove the probe's policy. Deferring all staging to the
restarted core loses that removal because its volatile installed policy is empty.
An explicit Leave must finish with a removed anchor, durable Left, LeaveDone, and
no internal error, without entering Stuck.

`l-033-resume-locked-start` is equivalent after this repair: trusted and Recovery
snapshots validate, pre-PersistLeaving staging uses the core transition, existing
cleanup gains only the last ordered step, and probe-only cleanup sets both Leave
flags. The validation guard therefore remains defensive. Its former witness
asserted the defective path and has been replaced with completion regressions.

Stuck Leave also retains trusted snapshot references when startup still has a
placeholder core machine. A validated snapshot preserves its existing
release authority. The evidence union reconstructs missing annotations with
release_unknown and reference_needs_reconcile rather than losing keys or
granting new numeric release authority. A direct placeholder regression covers
this case alongside the ordinary reference-bearing Leave regression.

The placeholder is identified by an explicit `adopted` flag, set only once the
engine installs an adopted reducer. A default-valued adopted reducer is still
adopted; structural equality with a fresh machine is not an ownership signal.

After Stuck Leave returns `Outcome::Exit0`, no anchor remains, while retained
accounting or anonymous enable can keep pf enabled. The next start attempts
reconciliation of validated snapshot entries, subject to boot, presence and
fingerprint gates; release is not guaranteed. Anonymous enable persists until
reboot or foreign global disable even after all tokens settle. The combined
staging-failure → Stuck → Stuck Leave → restart regression covers a releasable
token, including preservation of the pre-PersistLeaving reference entries.

**Installer requirement:** install launchd with unconditional `KeepAlive = true`,
including restart after successful exit. A `KeepAlive` dictionary with
`SuccessfulExit = false` is insufficient: Exit0 would leave pf enabled with our
token and no anchor without attempted reconciliation. Anonymous enable remains
independently until reboot or foreign global disable. The installer must check
this restart policy when its launchd plist is added. No plist exists in the
current resource-model implementation; the restart contract is required of
packaging, and is not enforced by the engine itself.

## Run 7c-c2: surviving-mutant equivalence review

These are source equivalence arguments, not measured survivor results. No mutants
were applied or executed in this run. The inventory in
`crates/scupper-mac/tests/mutants_7c.json` links the witnesses for the other
requested ids.

- **m-014 / m-015 (held parking):** `snapshot::validate_durable` requires a held
  machine without join intent to be Leaving, and Leaving requires no join intent.
  Core PersistLeaving and ClearIntent preserve those implications. In
  `held_emergency_due`, `!hold || !join_intended || leaving` therefore has redundant
  join-intent and Leaving terms individually: if the removed term would refuse,
  one of the remaining terms already refuses. Inspect the validator and the core
  Leave/ClearIntent transitions; this does not assume all independent booleans
  are freely reachable.
- **m-019 (stateless lockless term):** `start_selected_inner` initializes ownership
  unchecked. While a fallback exists, dispatch prioritizes `run_lockless`, whose
  read-only probes, load/enable path and cancellation never check startup
  ownership. The fallback is removed before `resume_locked_start` / `finish_start`
  checks ownership. Thus `lockless.is_some()` implies the later
  `!startup_invariant_checked` stateless disjunct. Inspect those methods and the
  sole assignment of the checked flag in `check_startup_invariant`.
- **m-046 (stable readback equality):** in `load_emergency_inner`, an unequal
  positive raw read first calls `reset_reload_after_absence`, clearing
  `emergency_readback`. At the later `stable` expression, a surviving
  `Some(loaded)` necessarily equals the current text. The outer `is_some_and`
  remains in both versions, so replacing its equality by true changes nothing.
- **m-057 (two capture reads):** the relaxed arm could only retain the first of
  two unequal successful Some reads. The immediately following inequality test
  unconditionally clears that value through `reset_reload_after_absence` before
  returning the unchanged second read. Inspect the entire capture method,
  including the reset after the assignment.
- **r-024 (accounting validation, reclassified as test in fix 1):** all five
  production callers preserve bounded keys, matching evidence and lifecycle
  invariants. Direct engine tests now also exercise the private staging helper
  with three keys and mismatched evidence, requiring refusal and an unchanged
  snapshot. The inventory therefore treats this defensive guard as testable
  instead of relying on the cross-site equivalence argument.
- **r-027 (in-flight test):** the earlier `in_flight.is_some()` return guarantees
  `is_none()` at the changed expression; no intervening operation changes it.
- **h3-r1-lockless (storage protection term):** a fallback begins in Starting;
  normal dispatch never runs while it remains, and the fallback is removed before
  the handoff can adopt Normal mode. Storage failure preserves Starting/Stuck.
  Thus a present fallback already satisfies the preceding Starting/Stuck mode
  alternative in this predicate.
- **h3-r1-next-emergency (deadline minimum):** integer seconds make
  `now + min(budget, 1)` at most `now + 1`, with saturating arithmetic. A future
  next-emergency deadline is at least `now + 1`; the other branch is exactly that
  bound. The final minimum is redundant even for zero budget or saturation.
- **l-033 after P1:** trusted/recovery snapshots validate, successful pre-Leave
  staging derives Leaving and cleanup from the core, and anchor-only staging sets
  Leaving/leave_requested together. Failed staging now skips cleanup append and
  is rejected separately by `staging_failed` after the common resets. Dropping
  only the snapshot-validation term leaves that failure refusal intact. Inspect
  `resume_locked_start` and its dedicated staging-failure regressions through
  lock-failure/probe handoff (including an old-boot reference); the inventory row
  is reanchored to the new combined guard.

- **h3-r1-slice-budget (one-second clamp):** inspect every production assignment
  of `next_emergency` in engine.rs, lockless.rs, emergency.rs and protocol.rs.
  Initial zero, reset zero, current/past now, and now+1 are the only values.
  `Platform::now` is monotonic within this incarnation, so this timer can never
  be more than one second in the future. The remaining final minimum therefore
  already clamps every positive integer budget to now+1; zero budget and
  saturation are unchanged. Removing `budget.min(1)` alone is equivalent under
  this timer invariant. `safety_storage_deadline` now asserts
  `next_emergency <= now.saturating_add(1)` immediately before using the bound.
  The deadline witnesses use a reachable now+1 timer, rather than an artificial
  MAX value that would break the invariant.


## Mac helper: resource-model engine replaces the executor and journal (2026-11-20)

Context: the previous Mac integration kept effect history, reference accounting,
Recovery-slot imports and session markers in overlapping records. Crash recovery
and cleanup depended on those records agreeing. The replacement keeps only
unobservable obligations durably and rediscovers exclusively owned resources
through complete reads and guarded process enumeration. DESIGN §14 consolidates
the current rules and supersedes the earlier resource-model specification's
whole-group ordinary sweep, unchanged-anchor/no-emergency-loop, emergency
refusal without reservation and Recovery-creates-files wording.

Decision:

- The core lifecycle machine owns ordinary planning and reference accounting.
  One bounded snapshot holds durable state and matching reference evidence,
  endpoint, owner, helper incarnation, replay records and internal error. Commit
  A then B; both checked syncs precede ordinary dependent effects. Startup
  classifies both copies, checks ownership, creates the control socket, repairs
  a trusted pair or writes Recovery, and closes the start fence. Recovery never
  creates files: a missing copy with no valid mate stays PersistBlocked until
  safe setup repair. Only both missing set the enforcement reason `storage
  missing: reinstall`; other such pairs use `storage failing`. Recovery hold
  makes text read `state untrusted: run leave` (or `containment attempted;
  safety unproven`), so reinstall guidance currently lives only in the
  enforcement field.
- Ordinary counted acquisition reserves before effect and requires known current
  boot identity before reservation and dispatch; later reads never fill unknown
  reservation provenance. Numeric release durably pre-marks `release_unknown`.
  Ambiguity retains an entry. Apart from confirmed release, definite
  never-started acquisition (settled only with freeing fences closed), and a
  never-dispatched reservation, free only by two known differing boot ids,
  complete post-fence token absence, or qualified pf-disabled evidence (the
  pf-disable invalidation assumption [X], rule 3, default off). Token absence
  never frees an uncertain acquisition. Numeric release requires a held token
  with `release_unknown` false, two known equal boots, complete post-fence
  presence and matching fingerprints where qualified. The snapshot has two
  slots. Unknown-boot Recovery acquisitions remain unresolved across later
  known boots/reboots until qualified freeing or safe setup reset. Reconciliation
  is an attempt, not a promise of release at the next start.
- The start fence closes over eligible previous-group processes and older
  launchd-orphaned (`ppid 1`) pinned tools, whatever their owner: a foreign
  launchd job running a pinned tool directly can be killed (accepted residual).
  Ordinary sweeps kill individuals and preserve group peers. Recheck and kill
  are not atomic: PID reuse between them remains an accepted residual except
  for own unreaped children. Unknown boot can select a reused previous group
  whose leader has exited. Attribution is a qualification assumption, not proof.
  The tool fence retains unreaped producers. Ordinary reconciliation requires
  committed helper identity, closed start/tool fences and no unconfirmed sweep;
  independent emergency accounting can settle absent tokens with closed
  start/tool fences without the helper commit or no-unconfirmed-sweep gate.
- Storage has its own outstanding-write fence. The late-write superset property
  assumes a single writer ([W]), that fence and reserve-before-effect. Whole
  snapshots are not monotone; a late write can restore an earlier, more
  restrictive intent, including Joined after nondurable Leave. Owned anchor,
  DNS, processes, endpoint route and managed artifacts are removed by live
  observation, without durable mutation history. A pre-existing static host route
  to the endpoint is treated as ours and is not restored.
- Starting queues Leave until ownership, the control socket and start fence
  are established; Join is refused until Normal admission. Stateless containment
  may precede those gates. Normal runs the core; Recovery is durable hold, refusing Join and the
  rejoin suffix. PersistBlocked pauses dependent D-class work while N-class
  safety and Leave continue after Starting (never StartChild without its
  committed generation and a confirmed sweep). Stuck freezes the core reducer,
  not independent emergency accounting, which may reserve, record or settle its
  entries by complete post-fence token absence. It retains matching queued
  acquisition results and runs no in-process restart-resync.
- In every mode after Starting, accepted Leave revokes containment and invalidates
  protection caches before cancellation, bookkeeping or storage waits. Only a
  newly admitted Join rearms containment. Leave cancels rejoin and attempts every connectivity cleanup without waiting for
  reference settlement; if in-flight accounting must merge first, the request
  and revocation are retained and automatically retried. While Starting persists
  or the instance lock is structurally unavailable (no socket), Leave cannot
  run. The administrator escape is `pfctl -a com.apple/scupper -F all`; pf stays
  enabled. This does not persist Leave, and continuing containment can reload the
  anchor. ClearIntent independently verifies anchor/DNS absence, complete owned
  process absence, complete empty managed-artifact inventory, no owned split or
  endpoint host route, and closed start/tool fences before and after reads.
  Artifacts exclude the lifetime lock/control socket. Recreated artifacts require
  removal and a fresh check. An undeletable or unknown managed entry can keep
  `leaving: artifacts` pending and prevent Left/re-Join indefinitely; a terminal
  operator workflow remains required.
- Failed Leave persistence reports `left (not durable)` and retries; it is never
  durable Left. When the endpoint is unknown, durable cleanup uses the distinct
  `left (endpoint route not checked)` text and `endpoint_unknown` status field;
  only a later process with readable install data can remove that caveat.
  Accounting survives Left. Stuck Leave commits the conservative evidence union
  and returns Exit0. Snapshot evidence wins for shared keys, missing metadata
  grants no release authority and mismatches mark tokens `release_unknown`.
  An unencodable union stays only in this process (no Exit0, no numeric release)
  and cannot shrink here because Stuck runs no reconciliation. A crash restarts
  from the last committed snapshot, which holds every reserved obligation;
  only unreserved emergency acquisitions can be lost (accepted).
- When join is intended, pf is observed disabled (or the helper has no confirmed
  enable reference), and a counted `-E` cannot be reserved because storage is
  failing, both slots are occupied or current boot is unknown, attempt Lockdown
  preparation then plain `pfctl -e` in the same step, retrying failed enablement
  every second while no ordinary pre-tunnel load is pending (a pending load
  blocked by an unreaped own pfctl also defers it). This replaces the earlier
  specification choice to report NotProtected while leaving pf disabled when no
  counted reference could be reserved. Preparation attempts load/read-back, invocation verification and state
  flushing when disabled; failure never gates enablement. Trusted pfctl, tool
  capacity and containment authority remain gates. Already-enabled pf skips
  preparation. With healthy storage, closed fences and known boot, missing
  ownership instead takes a durably reserved counted reference. Keep
  NotProtected until full verification; held/blocked/Stuck modes remain masked.
- Emergency containment explicitly amends the earlier resource-model ordinary
  reserve-before-effect and emergency-refusal rules for the emergency path. It
  consolidates the November 17 decisions on unreserved pf acquisition,
  token-free enable fallback, in-process Stuck Lockdown, enablement after an own
  load and stateless containment before the start fence. Pinned Lockdown loads,
  token-free enable, reads and state-only flushes may precede quiescence.
  Stateless commands can race stale writers and are reasserted every second;
  no blocking claim is made until the start fence closes over earlier writers
  and own tools are reaped. The interval is not a leakage bound. A recent
  pre-fence load can be reused only with fresh post-fence read-back and full
  verification. With closed fences and known boot, failing persistence in Stuck
  permits one unreserved counted acquisition per incarnation (PersistBlocked uses
  only the anonymous enable), refunded only for definite
  NotStarted. Lost unreserved `-E` tokens can accumulate across crashes, at most
  one per incarnation until reboot; two durable slots are not an all-mode bound.
- Token-free `pfctl -e` takes pf's single anonymous enable reference, without a
  token. No token release removes it; pf stays enabled until reboot or foreign
  `pfctl -d`, also after Left. It does not accumulate; the helper never globally
  disables pf. The platform contract maps DIOCSTART success and EEXIST to Started
  and AlreadyRunning (native mapping qualified in 5a2c); both confirm this
  effect, independently of protection. Anonymous enable consumes no counted slot
  and settles no entry. It can activate other products' rules. A foreign
  disable/enable pair entirely between checks can leave confirmation stale; a
  later foreign last-token release can disable pf until the next check. The
  platform lacks enabled-since identity; this remains accepted polling drift.
- Protected requires a fresh full proof in the current context, including state
  cleanliness, and is masked in hold, PersistBlocked, Stuck, Starting/uncommitted
  helper, on open fences or survivors, internal error and queue overflow
  (DESIGN §14). Stuck's enforcement reason is `internal`, with
  containment/untrusted text precedence; independent emergency blocking is a
  separate expiring field. Retain durable connection failure/retry count until
  Protected(Joined); any accepted proof clears enforcement error and reference
  errors settle independently. Core Protected/progress text still appends
  `; pf ownership cleanup debt: <Debug reason>` when a reference error remains.

Consequences: no separate session latch, import receipts, per-effect resource
history or restart-resync remains. Plain observations and successful maintenance
flushes do not write snapshots. Automatic Leave, reference and storage retries
replace manual retries. Left verifies removal of this helper's restrictions and
routing; other products' filtering and retained pf accounting are separate.
Fixed-size copies bound logical storage, not future APFS write success. Root
rollback of both copies is undetectable; complete process discovery and bounded
termination remain assumptions. The Platform contract and fake are implemented;
native macOS adapter and packaging still need qualification.

The Mac claim is the narrowed one in DESIGN §1/§14: no first-packet guarantee at
boot and no maximum detection/recovery bound between checks. Early helper/anchor
load is best effort; measure the boot gap in 5a2c native qualification and the 5a4 lab
qualification and retain it as a residual. First-packet protection requires
an optional separate default-deny network device in front of the Mac (the user's choice, not the scupper gateway); a Network Extension
backend is the roadmap. The gateway boot requirement is unchanged. Lockless and
emergency Lockdown are recovery, not continuous protection. Arbitrary foreign
policy changes can admit packets between checks; status can remain Protected
until detection or proof expiry. Stale producers can undo pre-quiescence
containment. After flush failures grow the backoff, stale states can survive
disable/re-enable even once the flush fault heals, while the next retry waits up
to 60 seconds. Continued flush failure has no recovery bound. Protected and
emergency-verified blocking stay withheld with unproven cleanliness.

Carried to 5a2c/5a3 (DESIGN §14 has the native qualification rows):

- Qualify anonymous `-e` through owned/foreign last-token releases, helper restart,
  repeated calls and persistent DIOCSTART EEXIST; foreign `-d`/reboot must clear
  anonymous ownership and invalidate counted tokens. Qualify [X] separately per
  release (default off) and pid/timestamp fingerprints. Prove reference ioctl
  completeness under buffer boundaries/concurrent churn: XNU silently truncates
  and drops oldest tokens. A larger buffer with returned size below capacity
  plus retries, or an equivalent qualified method, is required; `ENOENT` is a
  complete empty list. Parsed text and exit zero alone are insufficient.
- Qualify reliable boot-session UUID reads during startup/reservation/commit
  waits, `proc_pidpath`, complete process enumeration, vnode identity, guarded
  signalling, tool deadlines/cancellation/reaping, launchd cleanup, instance-lock
  rules and APFS ENOSPC sync behavior. Prove configd cannot apply queued scutil
  DNS changes after final read-back following reaping, or supply a stronger
  adapter fence before Left; also qualify resolver restoration. Measure polling
  drift and stale-state survival, and check cheap-check/pf-info failure consistency.
- Implement/qualify the native adapter, align `/opt/scupper/wireguard-go` with
  packaged `bin/`, and use only
  `State:/Network/Service/com.scupper.tunnel/DNS`. Surface the reinstall reason
  despite status-text precedence, map `endpoint_unknown` to a distinct CLI
  exit/state, replace the cleanup-debt/Debug suffix, and define the terminal
  managed-artifact diagnostic/recovery workflow.
- Setup, refresh, repair and uninstall boot out launchd, take the instance lock
  before storage access and confirm child absence. Never overwrite snapshots
  while helper/child may live. Setup never overwrites checksum-valid or
  unknown-format copies; it creates only missing files (both missing: fresh
  pair; one missing: pair repair). Refresh/upgrade retain snapshots. Uninstall
  requires full Leave checks including managed artifacts, the lock and confirmed
  child absence; report remaining reference counts/uncertainties with "pf may
  stay enabled until reboot", then delete storage. Safe setup reset requires
  the same cleanup/reporting, not silent accounting loss. Endpoint changes need
  verified Leave or retention of the old endpoint until its route is absent.
- Install unconditional `KeepAlive = true`, not `SuccessfulExit = false`:
  successful Stuck Leave must restart for attempted reconciliation, not promised
  release. Ambiguous releases and uncertain acquisitions can remain until known
  boot change or qualified [X]; unknown-boot acquisitions cannot use boot change.
  Anonymous enable persists independently. Qualify launchd respawn throttling
  after Exit0; shutdown/SIGTERM must not be treated as Leave.


## 2026-11-20 — Confined Darwin FFI boundary

Accept [ADR 0034](docs/adr/0034-darwin-ffi-boundary.md): first-party unsafe code
is permitted only in the private `sys` module of `scupper-darwin`, behind typed,
owned results and strict unsafe lints. Other crates retain `forbid(unsafe_code)`.
Packed and variable-length data is decoded by safe portable code. SDK ABI
observations, cross-target checking and native qualification are separate gates.

## 2026-11-20 — Supported macOS releases and qualification venue

Support and qualify macOS 15 and 26 on Apple Silicon using the pinned
`macos-15` and `macos-26` GitHub runner labels. macOS 14 is unsupported; its
GitHub runner image was retired on 2026-11-02. Never select `macos-latest` for
qualification. Runner evidence applies only to the exact observed build and
architecture; it does not automatically qualify another Mac. With the maintainer's
consent and timing, later on-device qualification may collect a separate record
under the dead-man restore, using inert test anchors for non-network groups.


## 2026-11-24 — 5a2c R7: fix 3 binding decisions

The maintainer accepts fix 2's `engine/protocol.rs` ClearIntent change: only `None`
clears anchor intent. `Some("")` and `Some(" \n")` from a nonconforming adapter
must refuse to clear. Keep the `.is_some()` check; do not restore whitespace
normalization in the engine.

Descendant absence is separately gated per reviewed build. Both 24H232 and
25G332 retain `descendants_reviewed = false`: every listed child remains foreign
content. A future reviewed true row requires complete empty classes at every
exact descendant path, strict owned-subtree containment, depth at most 8 and at
most 64 anchors including the owned root. This also applies to `Some(own_policy)`;
removal never flushes descendant paths. Unknown/unreviewed builds reject load
and removal with a distinct unsupported-build error before any pfctl spawn.

Q-ANCHOR runs lifecycle, hooked removals and F-all first, optimizer controls next,
foreign fixtures next and descendant coverage measurements last. Descendant
fixtures use only the independently journaled `scupper-qual/children` subtree.
Unreviewed optimizer/overlap text and descendant spellings are measurements;
reviewed A/B golden mismatches remain violations. Every control/fixture records
its outcome and continues; violations take precedence over Inconclusive issues.
Qualification restore may clean and prove emptiness recursively in that disposable
measurement subtree; this never promotes native descendant coverage.

Anchor cleanup, token release and pf-state restoration require proven writer
quiescence. This implementation takes fresh launchctl absence evidence for every
journaled service and checks writers/groups across all campaign scopes before
each dependent step. Otherwise those steps and completion are withheld, journal
entries remain pending, independent diagnostics continue and restore fails.

Under install-failure hold, neither qualified nor unqualified firewalls may
publish Protected status or an Installed-form Protected candidate. Qualified
PreTunnel Lockdown verification may be Protected while status remains masked.


## 2026-11-24 — 5a2c R7: emergency containment and deferred flush obligation

This entry supersedes fix 3's unsupported-build load refusal. Outside the
reviewed build table, the adapter attempts only the byte-exact canonical Lockdown
rendering at its owned anchor, using `pfctl -o none -a <anchor> -f -`. Its result is
always Unknown, regardless of rc or stderr; rc 0 never establishes success.
Every other payload/path and removal remain refused before spawning with the
distinct unsupported-build error. Emergency guard reloads retain best-effort
containment without claiming verification. No engine logic changes are required.

The global `flush_states` operation remains unchanged in this slice. Its flush
obligation stays unresolved across repeated Unknown results and guard reloads.
A later slice will add bounded backoff instead of per-tick retries; suppressing
a retry never clears the obligation or enables Protected. A one-shot cap was
rejected because states created before a later successful Lockdown would survive.
Unsupported-build state flushes remain an unresolved review/gating gap; the later
slice must address that gap together with bounded retries.

Q-ANCHOR retains 180 seconds for lifecycle, hooked removals and F-all.
Q-DESCENDANTS runs after Q-FLUSH with its own 180-second budget for descendant
coverage, optimizer controls and foreign fixtures. Case durations are recorded;
native pass-2 timing must confirm the split against the pass-1 sizing evidence.
Cleanup runs independently of case budgets. Failed cleanup retains journal
obligations and withholds later dependent uses with its recorded reason.

## 2026-11-24 — 5a2c R7 fix 6: adopted measurement pins and inventory verdict

The fix 6 plan adopts the 24H232 UDP `pfctl -s states -v` bytes from
CI 45397408312 attempt 2 and the byte-identical full underscore and one-line
inline rejection rows on 24H232 and 25G332. Each build's measurement review pins
its own state golden. Only UDP is reviewed; the parser must consume the entire
listing and reject any other protocol, extra/unknown line, malformed record or
truncation with an explicit measurement error. A state read/parse error records
an Inconclusive issue and does not stop Q-ANCHOR's remaining lifecycle/scope
steps. `-vv` and TCP remain capture-only; Q-FLUSH Inconclusive is expected in
pass 3 pending review of the TCP captures. Tuples do not establish identity.
Both builds retain `descendants_reviewed = false`.

Per parent, compare normalized order-insensitive kernel K and text T sets.
K minus T is a contract finding "text inventory incomplete"; T minus K is
"inventory disagreement". Enumeration failure or detected concurrent mutation
is Inconclusive, and traversal covers the observed union. Q-DESCENDANTS cannot
be assumption_holds with any finding. Multi-line inline rejections remain
unpinned. These are adopted maintainer decisions, so no further pin approval is
required in this checkout.

## 2026-11-24 — 5a2c R7 fix 7: private-header ABI fallback

The probe uses `net/pfvar.h` when present. When public SDKs omit this private
header, an in-tree mirror pins the XNU-published ruleset size 1092, offsets
0/4/1028 and ioctl numbers 0xC444443A / 0xC444443B. This supersedes the earlier
requirement to fail compilation when the header is absent. Missing ruleset ioctls
in a present header, or a contradiction with the pins, still fail compilation.
Evidence records `from_sdk_header:true|false` and `layout_source`; false means
"XNU-published layout pin, not SDK-verified" and cannot claim SDK verification.
Q-DESCENDANTS records this provenance and checks the pins without requiring true.

Q-ANCHOR preserves AssumptionRefuted when removal fails despite state measurement
issues, retaining those issues in its detail. Stable K/T existence disagreements
are contract findings even if both child-name sets are empty. These measurements
do not promote production descendant coverage flags.
