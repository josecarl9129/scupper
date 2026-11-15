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
verdict. Heartbeat accepts session-only 3 for a durable, nonrenewable 600 s grace
since the first such 3 after the last 0; all diagnoses participate in classification.
Only 0 resets grace. Status exposes the session reason. Five-second durable
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
