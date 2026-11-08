# 0019. JSON Lines event log

Status: accepted, 2026-11-08. Design: [DESIGN.md](../DESIGN.md).

## Context

Events form the audit record and the source of alerts. Volume is a few events per day.

## Decision

Append-only JSON Lines per month in `/var/lib/scupper/events/`, fsync per event, monotonic `seq`, a cursor file per alert sink. Retention 13 months or 100 MB. Event types have no destination or domain fields.

## Alternatives considered

- SQLite with WAL and a transactional outbox: a C dependency for a tiny volume.
- A hash-chained log: not tamper-proof against root, so of little value.

## Consequences

- Readable with `jq`; no database.
- Revisit for an R2 dashboard.
