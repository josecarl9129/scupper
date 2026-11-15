# 0004. Process model: boot unit, synchronous root daemon, unprivileged edge in the namespace

Status: accepted, 2026-11-08. Design: [DESIGN.md](../DESIGN.md).

## Context

Client-facing services (DNS, API, metrics) must be unable to touch the uplink. The supervisor needs root and must keep working when services fail. Privilege separation is useful, but each extra component adds IPC, units and states to test.

## Decision

Three gateway units: `scupper-net` (oneshot `scupper boot`), `scupperd` (root, host namespace, no network listener, synchronous single reconciler thread) and `scupper-edge` (user `scupper-edge`, only `CAP_NET_BIND_SERVICE`, whole process placed in the namespace by systemd's `NetworkNamespacePath=`). Probes and alert/heartbeat deliveries run as short-lived children: probe children enter the namespace and create sockets as root while single-threaded, then drop to `scupper-probe`; delivery children start as `scupper-alert`. No TLS or HTTP is parsed as root. Edge uses tokio; scupperd does not. Edge reaches scupperd only through its own socket `/run/scupper/edge.sock` with a fixed operation set, sees an empty `/run` apart from that socket (so host resolver and D-Bus sockets are out of reach), and dumps no core.

## Alternatives considered

- Six components (supervisor, privileged kernel worker, API worker, resolver, probe worker, alert worker) with a typed operation protocol: sound, but triples IPC and unit surface for no gain in I1-I7.
- One process using `setns` per socket: correct only by code review, and `setns` is per thread, which conflicts with async runtimes.
- tokio in the root daemon: nothing to gain in an exec-driven 2 s loop.

## Consequences

- The kernel guarantees edge cannot listen on or send via the uplink.
- DNS keeps working while scupperd restarts or hangs.
- scupperd is deterministic and testable with a fake clock.
- Edge authenticates tunnel principals (ADR 0007); scupperd authorizes them (ADR 0029).
- `BindsTo=` ties edge to the namespace *unit*, not the namespace object; scupperd checks edge's namespace inode every tick and restarts edge after a rebuild.

The fresh heartbeat and pending-verification checks are concurrent exceptions to
single-threaded reconciliation. They can commit client session confirmations
under the session writer lock, with a 500 ms deadline and epoch fences, but never
write reconciler intent. A detached worker whose filesystem operation is blocked
can keep that lock; sampling skips contention, lifecycle hooks remain bounded,
and clean stop waits up to three seconds without invalidating on contention.
Confirmation writes never renew sampler freshness or publish cached readiness.

Daemon-only stop uses `KillMode=mixed`: systemd sends TERM only to the main PID.
There is no daemon `ExecStop`; the signal handler requests synchronous graceful
shutdown. The main process closes helper admission and drains/reaps all owned
execs, including timeout reapers, before it exits. Unknown shutdown safety gets
one two-second re-observation after draining; known unsafe or still unknown safety
is contained at complete operation boundaries. `TimeoutStopSec=240s` budgets the
current operation, collection/drain, re-observation, 120-second containment prefix,
30-second final closure and final audit/session work (see DESIGN). systemd sends
SIGKILL to remaining processes only at that final timeout, including the main PID
if it is still waiting for an unreapable child.
