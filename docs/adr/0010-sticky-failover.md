# 0010. Sticky failover by default

Status: accepted, 2026-11-08. Design: [DESIGN.md](../DESIGN.md).

## Context

After a failover the preferred exit may recover. Every switch resets all client flows (conntrack flush) and changes the public IP; switching back gains no safety.

## Decision

Default `policy.failback = "manual"`: the gateway stays on the working exit until an admin runs `scupper exit use`/`exit auto` or the active exit fails. `failback = "auto"` is a config option: switch back when the preferred exit has been healthy for `failback_hold` (10 min) and at least `min_dwell` (120 s) since the last switch; more than 4 switches in 30 min suppresses failback for an hour. Intent (`Auto`, `Prefer`, `Pin`, `Disconnected`) is persisted separately from state. Holds, dwell and flap suppression use the monotonic clock, so clock steps cannot shorten or stall them.

## Alternatives considered

- Automatic failback after 10 min by default, with flap damping: more states and tests, more disruptive.

## Consequences

- Fewer switches, fewer states to test.
- The active exit may not be the configured first choice; `status` shows it.
