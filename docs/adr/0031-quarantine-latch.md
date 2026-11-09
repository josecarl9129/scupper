# 0031. Persisted quarantine latch after an exhausted repair budget

Status: accepted, 2026-11-08; amended 2026-11-09 (write order, per-class budgets). Design: [DESIGN.md](../DESIGN.md) §2, §7.

## Context

When safety drift (ruleset, foreign link, tc hook) keeps returning, the repair budget runs out and the gateway closes with forwarding 0. As first specified, that state lived only in memory, and the ordinary repair "forwarding 0 with a verified ruleset → forwarding 1" would raise forwarding again on the next tick whenever the ruleset itself was exact, for example with a recurring foreign link. A restart or reboot also forgot the budget, and boot enables forwarding.

## Decision

Exhausting a budget for safety drift sets a **quarantine latch** `quarantine {reason, object, since}`. The daemon holds it in memory before its first step, sets forwarding 0, removes the drift (tightening is never budgeted), and then writes it durably to `state.json`. Forwarding goes to 0 before the write so that a slow or failing disk can never keep forwarding open; a crash before the write is safe because the drift is seen again and re-latches. Safety budgets count per drift class (ruleset, foreign link, tc hook), not per object, so a fighter cannot escape by changing names or handles. While it is set, no repair, planner step or boot step may raise forwarding; `check` reports 4 `Quarantined`. Only `scupper repair clear` or a verified full `scupper apply` clears it, with an `AdminAction` event. If the latch cannot be persisted it holds in memory and `PersistenceFailed` is raised.

## Alternatives considered

- In-memory suppression: lost on restart and overridden by the forwarding repair.
- Clearing automatically after a quiet period: loosens policy without a human decision (I4).

## Consequences

- A property test checks that no step sequence raises forwarding while the latch is set; L43 covers restart and reboot.
- An operator's deliberate stop now has a durable form: setting the latch.
- Accepted bound: with per-class budgets, a fighter alternating all three safety classes gets at most 3 reopen windows per class (9 in total) per 10 minutes before the latch; each reopen is only after the drift was removed and the ruleset verified.
- Only safety suppression closes the gateway. A non-safety repair whose budget runs out simply stops being repaired and raises `RepairSuppressed`.
