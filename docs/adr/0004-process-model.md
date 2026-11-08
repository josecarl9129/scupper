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
