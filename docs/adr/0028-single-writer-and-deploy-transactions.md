# 0028. One writer lock; deploys as serialized transactions

Status: accepted, 2026-11-08. Design: [DESIGN.md](../DESIGN.md) §7, §15.

## Context

Several actors can mutate kernel or persistent state: the boot unit, scupperd's tick and its boot retry, a manual restart of `scupper-net`, a local `apply` while scupperd is down, the deploy rollback timer and the guard unit. The "every prefix of every plan is safe" property is proved for one writer. Interleaved writers can leave a host-side link behind, race `ip netns add`, or converge toward different versions. Deploys share recovery material, and a confirmation can race a rollback executor that has already started; disarming a timer does not stop a running executor.

## Decision

- Every code path that mutates kernel or persistent state holds the exclusive lock `/run/scupper/writer.lock` (`flock`) for its whole step sequence.
- A deploy is a transaction with its own directory `deploy/<id>/` (new files, snapshot of every touched file, `pending.json`). Only one deploy may be pending; a second is refused.
- `pending.json` has a phase: `pending` → `confirmed` or `pending` → `rolling-back` → `rolled-back`. Both transitions are made durably under the deploy lock, and every executor re-checks the deploy id and phase before it mutates anything. Exactly one of confirmation and rollback can win.
- While a deploy is pending, config commits are refused except revocations, which are recorded and re-applied on top of the rollback target.
- A reboot while a deploy is pending always rolls back.

## Alternatives considered

- Rely on systemd ordering alone: does not cover manual restarts, local CLI mutations or timers.
- Shared `scupper.prev` and `pending.json`: a second deploy overwrites the first one's recovery material.
- Allow config changes during the window and restore the old version on rollback: resurrects revoked devices and tokens.

## Consequences

- Concurrency is a tested case (L44, L51), not an assumption.
- A deploy blocks ordinary config changes for its confirmation window (default 3 min).
- The rollback executor's input format is kept stable across releases.
