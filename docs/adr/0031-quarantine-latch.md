# 0031. Persisted quarantine latch after an exhausted repair budget

Status: accepted, 2026-11-08. Design: [DESIGN.md](../DESIGN.md) §2, §7.

## Context

When safety drift (ruleset, foreign link, tc hook) keeps returning, the repair budget runs out and the gateway closes with forwarding 0. As first specified, that state lived only in memory, and the ordinary repair "forwarding 0 with a verified ruleset → forwarding 1" would raise forwarding again on the next tick whenever the ruleset itself was exact, for example with a recurring foreign link. A restart or reboot also forgot the budget, and boot enables forwarding.

## Decision

Exhausting a budget for safety drift sets a **quarantine latch** `quarantine {reason, object, since}` in `state.json`, written durably before anything else. While it is set, no repair, planner step or boot step may raise forwarding; `check` reports 4 `Quarantined`. Only `scupper repair clear` or a verified full `scupper apply` clears it, with an `AdminAction` event. If the latch cannot be persisted it holds in memory and `PersistenceFailed` is raised.

## Alternatives considered

- In-memory suppression: lost on restart and overridden by the forwarding repair.
- Clearing automatically after a quiet period: loosens policy without a human decision (I4).

## Consequences

- A property test checks that no step sequence raises forwarding while the latch is set; L43 covers restart and reboot.
- An operator's deliberate stop now has a durable form: setting the latch.
