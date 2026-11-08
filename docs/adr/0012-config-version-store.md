# 0012. The config version store is the source of truth

Status: accepted, 2026-11-08. Design: [DESIGN.md](../DESIGN.md).

## Context

The configuration must be declarative, versioned, with history and rollback, and every change must be attributable ("who did what"). A root-editable file that is silently accepted makes the actor unknowable.

## Decision

Immutable versions in `/var/lib/scupper/config/versions/`, each with meta (`parent`, sha256, actor, time, reason), and an atomically renamed `head`. Every change creates version N+1 with compare-and-swap on the parent. Rollback creates a new version with old content. `/etc/scupper/scupper.toml` is a read-only mirror; hand edits are detected, ignored and alerted, and `scupper config load` turns a file into a version deliberately. R2 sections are rejected, never ignored. Commits are durable in a fixed order (file fsync, rename, directory fsync; version, meta, head). Changes are risk-classified (ADR 0029).

## Alternatives considered

- `/etc/scupper/config.toml` authoritative, hand edits accepted after a stable valid read: simple for root, but changes are unattributed.
- SQLite store: unnecessary for a few small files.

## Consequences

- Linear, auditable history; bundles for rebuild are just the version directory.
- Operators who edit files must run one extra command.
