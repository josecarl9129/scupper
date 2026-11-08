# 0014. Migration by building a fresh host

Status: accepted, 2026-11-08. Design: [DESIGN.md](../DESIGN.md).

## Context

The live v1 gateway is the operator's internet path. Converting it in place to the namespace layout means stopping its tunnels and rebuilding them under scupper while the operator may depend on it, with rollback depending on the conversion itself.

## Decision

Build a second small cloud VM with `scupper install`, enrol the Mac with a second profile, verify, and keep the old gateway untouched for about one week as rollback (rejoin the old profile), then delete it. The migration is also the first exercise of the rebuild runbook (ADR 0025).

## Alternatives considered

- In-place migration with a scripted rollback: no overlap cost, but the lifeline is modified mid-migration and an in-place migration path has to be built and tested.

## Consequences

- A few currency units of overlap; the installer is tested on a fresh host for free.
- Provider sessions of both gateways count against the session limit during the overlap.
- The in-place v1 migration is not built in R1, and `install` refuses a host with the v1 layout.
