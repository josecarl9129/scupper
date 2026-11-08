# 0026. Confirm-or-rollback deploys

Status: accepted, 2026-11-08. Design: [DESIGN.md](../DESIGN.md) §15.

## Context

A new binary or config can break the client tunnel, the API or `check`. If
that happens on the operator's only gateway, the operator may lose the path
needed to fix it. Rollback must not depend on the code under test, and it
must stay fail-closed (I1, I2).

## Decision

`scupper deploy` (and `scupper upgrade`, which first downloads and verifies
a release) runs from the Mac over break-glass SSH: select the artefact for
the gateway's architecture, copy, verify sha256, show the `install` plan and
confirm unless `--yes`. Deploys are serialized transactions (ADR 0028):
one at a time under a lock, each with its own directory. Before switching,
the gateway snapshots every file the plan touches (binaries, units,
sysctl.d, state files) and the current rollback executor, records
`deploy/<id>/pending.json` (phase, monotonic deadline, boot id, previous
applied version), then arms a rollback timer (default 3 min) as a systemd
transient timer that runs the **previous** executor. A guard unit ordered
before the boot procedure rolls back any deploy still pending after a
reboot. While pending, config commits are refused except revocations, which
are re-applied on top of the rollback target. The Mac reconnects through the
tunnel and confirms only when the gateway's `check` is 0 **and** its own
checks pass (exit IP through the tunnel differs from the gateway's and the
Mac's uplink addresses; a random name resolves through the gateway), so the
decision does not rest on the code under test. Confirmation and rollback
are mutually exclusive phase transitions. Without confirmation the gateway
rolls back by itself: stop daemons (data path unchanged), restore the
snapshot and `daemon-reload`, commit the previous revision's content plus
the revocations as a new version, converge with the ordered planner, emit
`DeployRolledBack`.

## Alternatives considered

- Manual rollback over SSH: fails exactly when the operator cannot reach the
  gateway or is not watching.
- Rollback executed by the new binary: trusts the code under test.
- Confirmation over SSH: proves SSH works, not the client path.

## Consequences

- A bad deploy costs at most the confirmation timeout, during which clients
  are protected or blocked, never leaking.
- Needs the tunnel API for confirmation, so the full flow lands in M6; M2
  has a basic deploy without the timer (used for a fresh host, where the old
  host is the rollback).
- First deploys to a fresh host have nothing to roll back to.
- A reboot during the window always rolls back, because elapsed time across a reboot is not known reliably.
- The rollback executor's input format (pending.json schema 1, snapshot layout) is kept stable across releases.
