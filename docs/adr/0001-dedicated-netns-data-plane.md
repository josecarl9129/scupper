# 0001. Dedicated network namespace for the data plane

Status: accepted, 2026-11-08. Design: [DESIGN.md](../DESIGN.md).

## Context

v1 runs in the host namespace and keeps client traffic off the uplink with a policy rule (`iif wg0 lookup 51820`) and an nftables table. Three of four historical bugs came from sharing that namespace: with the gateway's own traffic (bug 1), with kernel-generated packets (bug 3) and with systemd-networkd, which deleted the policy rule (bug 4). A foreign table using `dup to … device eth0` could also copy client packets out before the forward drop. WireGuard keeps an interface's UDP socket in the namespace where the interface was created, even after the interface is moved.

## Decision

From milestone 2 all plaintext client traffic lives in netns `scupper`, which contains only `lo`, `wg0` and the exit tunnels. WireGuard links are created in the host namespace and then moved, so encrypted transport uses the host uplink and plaintext never exists there. The topology is the kill switch; nftables in the namespace is a second layer. M1 keeps the v1 layout (ADR 0015); no repair code is ever written for the v1 layout.

## Alternatives considered

- v1 layout plus more watchers: detection is not prevention, and every watcher re-creates the shared-state problem.
- VRF/l3mdev: still init-namespace rules that networkd and others can delete.
- systemd-networkd `.netdev` ownership: not cloud-agnostic, no namespace placement.

## Consequences

- No route, rule or nft verdict in the namespace can reach the uplink because the uplink is not there; bug 4 disappears as a class.
- Every client-facing socket (DNS, API, probes) lives in the namespace; the kernel, not code review, keeps them off the uplink.
- `ssh` to the tunnel address stops working (ADR 0008); debugging needs `ip netns exec`/`ip -n`.
- Migration risk is handled by building a fresh host (ADR 0014).
