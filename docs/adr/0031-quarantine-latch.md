# 0031. Persisted quarantine latch after an exhausted repair budget

Status: accepted, 2026-11-08; amended 2026-11-09 (write order, per-class budgets). Design: [DESIGN.md](../DESIGN.md) §2, §7.

## Context

When safety drift (ruleset, foreign link, tc hook) keeps returning, the repair budget runs out and the gateway closes with forwarding 0. As first specified, that state lived only in memory, and the ordinary repair "forwarding 0 with a verified ruleset → forwarding 1" would raise forwarding again on the next tick whenever the ruleset itself was exact, for example with a recurring foreign link. A restart or reboot also forgot the budget, and boot enables forwarding.

## Decision

Exhausting a budget for safety drift sets a **quarantine latch** `quarantine {reason, object, since}`. The daemon holds it in memory before its first step, sets forwarding 0, removes the drift (tightening is never budgeted), and then writes it durably to `state.json`. Forwarding goes to 0 before the write so that a slow or failing disk can never keep forwarding open; a write-ahead repair checkpoint preserves uncertainty and repair counts across a crash before the main state write (see DESIGN §7). Safety budgets count per drift class (ruleset, foreign link, tc hook), not per object, so a fighter cannot escape by changing names or handles. While it is set, no repair, planner step or boot step may raise forwarding; `check` reports 4 `Quarantined`. An ordinary, durably recorded safety-budget latch requires `scupper repair clear` or a verified full `scupper apply`, with an `AdminAction` event. `scupper connect` may also clear a latch marked with the typed `uncertain` flag: unreadable checkpoint evidence, a runtime uncertainty marker, or failed latch persistence (including a safety-budget latch whose write failed). Reason text never grants clearance. If the latch cannot be persisted it holds in memory and `PersistenceFailed` is raised.

## Alternatives considered

- In-memory suppression: lost on restart and overridden by the forwarding repair.
- Clearing automatically after a quiet period: loosens policy without a human decision (I4).

## Consequences

- A property test checks that no step sequence raises forwarding while the latch is set; L43 covers restart and reboot.
- An operator's deliberate stop now has a durable form: setting the latch.
- Accepted bound: with per-class budgets, a fighter alternating all three safety classes gets at most 3 reopen windows per class (9 in total) per 10 minutes before the latch; each reopen is only after the drift was removed and the ruleset verified.
- Only safety suppression closes the gateway. A non-safety repair whose budget runs out simply stops being repaired and raises `RepairSuppressed`.

Amendment (2026-11-13): failed latch persistence also writes a
best-effort `/run/scupper/latch-uncertain` marker. Durable `repair-state.json`
records the latch before main-state replacement and reserves safety repair counts
before mutation. The in-flight flag covers one restore's execution and verified
completion; it is cleared when that restore ends, including a failed restore.
Neither an in-flight flag nor three successful repairs constitutes a latch at
startup or in `check`. Each attempt retains its Unix timestamp. At restart,
attempts at least ten minutes old expire; future timestamps clamp to now, and legacy count-only
entries expire. Live attempts retain only their remaining window, so the next
refused safety restore latches without granting a fresh repair budget.
Other restores checkpoint best effort and never depend on state-disk fsync.

A missing checkpoint means no record, including on upgrade from the previous
release. Under the writer lock, daemon initialization and boot create an empty legacy checkpoint
only beside readable state with an applied version and no runtime uncertainty
marker, and emit `RepairCheckpointCreated` once. Existing `state.quarantine` is
preserved byte for byte. Unreadable or corrupt checkpoints, recorded quarantine,
and runtime uncertainty still fail closed across restart. `connect` clears only
typed uncertainty; ordinary durable safety latches require `repair clear` or apply.

The migration audit is best effort: a failed event logs a warning and raises a
persistence alert without aborting startup. Daemon rebuild, apply and rollback
reuse the daemon's audit sender; only standalone boot opens an audit writer.
For binary rollback compatibility, `state.json` retains the previous release's
strict latch schema. Typed uncertainty and attempt timestamps are written only
to `repair-state.json`, which that release never reads. An older binary still
honors a main-state latch and its existing administrative clearance paths.
