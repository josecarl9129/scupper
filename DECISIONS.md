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
brief recoveries to 0 can reset it repeatedly. A real serving failure visible
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
