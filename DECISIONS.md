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
