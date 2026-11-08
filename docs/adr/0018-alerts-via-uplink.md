# 0018. Alerts and heartbeat leave via the host uplink

Status: accepted, 2026-11-08. Design: [DESIGN.md](../DESIGN.md).

## Context

The most important alert is "all exits down, failing closed". If alerts could only use the VPN, that alert would be undeliverable exactly when it matters.

## Decision

Alert sinks and the external heartbeat are delivered from the host namespace through the uplink, by unprivileged delivery children started by scupperd. They carry only typed operational fields, never client data. Delivery is at least once per sink, in order, from fsynced events with a cursor per sink, backoff, coalescing and rate limits.

## Alternatives considered

- VPN-only alert egress: undeliverable fail-closed alerts.

## Consequences

- The alert provider sees the gateway's public address, which is public anyway.
- Gateway-own traffic on the uplink remains legitimate, as in v1.
