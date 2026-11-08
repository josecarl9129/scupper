# 0015. Milestone 1 is a pure v1 parity port

Status: accepted, 2026-11-08. Design: [DESIGN.md](../DESIGN.md).

## Context

The namespace layout is a large change. Starting with it would mix a language port with an architecture change, so a failing test could not tell which one broke. A parity port first proves the Rust code against v1's golden file and test tables.

## Decision

M1 ports v1 to Rust in the v1 layout: the same six commands, exit codes 0-4 and verdict order, the byte-exact golden ruleset, the route probe, and two strengthenings: exact comparison of the whole host ruleset (ADR 0013) and `nft -c` validation before `apply` renames a file into place. It is built and tested in a lab namespace and a VM, not deployed; the existing gateway stays on v1 until it is replaced by a freshly built M2 host. The namespace layout starts M2, before any repair code. The v1 renderer and golden stay until the last v1-layout gateway is retired and are deleted together.

## Alternatives considered

- Namespace isolation already in M1: higher risk now, no gain.
- Build M2 daemon watchers for the v1 layout: throwaway work.

## Consequences

- M1 proves the port (golden, verdict and parser parity) before the layout changes. The v1 layout keeps its dependency on `nftables.service` (DESIGN §3): with the stock unit a stop flushes the only barrier between the client tunnel and the uplink while the exit is down. M1 is therefore a lab milestone only (DESIGN §3, §19 D-1): it is built and tested in a lab namespace and a VM, never deployed to a gateway carrying traffic. The first deployment is M2 on a freshly built host.
- The leak-test harness starts with the namespace layout in M2; M1 relies on unit, golden and property tests, lab-only negative tests (L40) and a self-restoring check on the gateway.
