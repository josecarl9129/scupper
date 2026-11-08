# 0020. Probes resolve names through the exit they test

Status: accepted, 2026-11-08. Design: [DESIGN.md](../DESIGN.md).

## Context

Inside the namespace the host resolver is unreachable (`/etc/resolv.conf` points at `127.0.0.53`, which does not exist there; `NetworkNamespacePath=` gives no resolv.conf overlay). Pinning probe target IPs breaks when CDNs move.

## Decision

Probe targets are hostnames (default `ifconfig.me`, `icanhazip.com`). The probe resolves the name itself with a DNS query to the exit's provider DNS through that exit (which is also the path probe), then connects to the resolved IP with SNI. Edge never resolves names. If every exit fails its probes at once, the target is blamed, not the exits (common-mode rule).

## Alternatives considered

- HTTPS URLs via the host resolver: broken in the namespace.
- Literal IPs with TLS names: drift.

## Consequences

- No host resolver and no pinned addresses.
- A provider DNS outage on all exits shows as common-mode degradation, not failover.
