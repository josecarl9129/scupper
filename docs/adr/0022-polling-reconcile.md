# 0022. Level-triggered polling reconcile loop

Status: accepted, 2026-11-08. Design: [DESIGN.md](../DESIGN.md).

## Context

The daemon must notice drift and converge without trusting its memory of past actions.

## Decision

Every 2 s observe the full state and compare it to the desired state; probes on their own cadence. The systemd watchdog is fed only after a complete iteration. Safety observations run first in each tick with a bounded budget; probes run in children and event fsync on a writer thread, so neither can delay a safety action. `ip monitor`/`nft monitor` may later be added as wake-up hints without changing the logic.

## Alternatives considered

- Netlink and nft monitor events plus periodic snapshots: faster detection, more code paths, events can be lost anyway.

## Consequences

- A crash between action and bookkeeping is harmless.
- Detection latency up to one tick plus the bounded safety group (bounds the I7 gap after a ruleset flush); measured numbers are quoted, not derived.
