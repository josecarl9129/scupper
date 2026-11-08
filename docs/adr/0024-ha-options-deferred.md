# 0024. High availability options, deferred

Status: accepted, 2026-11-08. Design: [DESIGN.md](../DESIGN.md).

## Context

A lost gateway host leaves clients failed closed (safe, but no service). Two high-availability designs are viable and neither is chosen yet.

## Decision

R1 implements neither and ships fast rebuild plus an external heartbeat (ADR 0025). Both options stay open, and the R1 data model must allow them: several `gateways.*` sections, client-facing `identities.*` that several gateways can reference, a list of gateways per device. R1 validation rejects more than one gateway and shared identities.
- **(a) Server-side active/standby** in one region behind a cloud floating/reserved IP moved via the cloud provider's API. Both hosts use the same client-facing `wg0` identity (a deliberate, documented exception to I6 for that one key), each gateway holds a cloud API token, and each host has its own provider exits.
- **(b) Client-side switching:** the Mac agent holds one profile per gateway and switches when the active gateway's handshake is stale. Works across regions and home + cloud; phones switch manually.
In both, the client stays fail-closed during a switch.

## Alternatives considered

- Build (a) or (b) in R1: premature before single-gateway operation is proven.
- Load sharing across gateways: incompatible with a single client tunnel without multipath; R2 uses a per-device primary gateway instead.

## Consequences

- R1 recovery is a rebuild of about 10 minutes.
- Choosing (a) later requires an I6 exception note and cloud credentials on the gateways; (b) requires Mac agent work only.
