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
