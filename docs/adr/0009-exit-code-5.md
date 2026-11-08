# 0009. Exit code 5: protected but unsupervised

Status: accepted, 2026-11-08. Design: [DESIGN.md](../DESIGN.md).

## Context

The `check` exit-code contract (0 protected, 1 error, 2 unprotected, 3 degraded, 4 fail closed) may be extended, not broken. With the daemon dead the data path still works but nothing fails over, repairs or alerts; without a distinct code `check` would report 0 until the active exit dies, which violates truthful health (I3).

## Decision

Add code 5: every data-path stage verified as for 0, but scupperd does not answer a control-socket ping within 2 s or its last complete iteration is older than 30 s. Checked last, and only when `health.require_daemon = true` (default from M2). `check` performs all probes itself, so it works with the daemon dead. Via the tunnel API a dead scupperd gives `503 supervisor_unavailable` and the CLI falls back to SSH, which runs the local check.

## Alternatives considered

- Report a dead daemon as 3: conflates "path broken" with "path fine, supervision missing".
- Warning only, exit 0: a script cannot see it.
- Have `check` served by the daemon: it cannot report its own death.

## Consequences

- Scripts that page on any non-zero code now page on a dead daemon; intended and noted in release notes.
- M1 keeps 0-4 only.
