# 0029. Risk-classified mutations: high-risk changes only over the local socket

Status: accepted, 2026-11-08. Design: [DESIGN.md](../DESIGN.md) §8, §10.

## Context

The tunnel API authenticates a request by the device's tunnel source address and a bearer token (ADR 0007). The token is a file readable by any process of the Mac user, and edge, which parses DNS and HTTP from clients, may assert any device principal. If `POST /v1/config` accepted any valid version, one stolen token or one edge compromise could add a device with an attacker's WireGuard key and token, or point an exit's endpoint and peer key at an attacker's server while reusing the existing private-key ref. No secret crosses the API in either case, so "no secrets via the API" does not prevent it.

## Decision

- scupperd classifies every change by its diff from head. **High-risk:** `devices`, `users`, `identities`; an exit's `endpoint`, `peer_public_key` or any `*_ref`; adding an exit or adding exits to `policy.exits`; alert sinks and heartbeat settings. **Low-risk:** exit order, enable/disable, names, tags, failback and standby settings, health timings.
- High-risk changes are accepted only over the local socket (root or `scupper-admin` on the gateway, which from the Mac means break-glass SSH). The CLI sends them over SSH by itself, so they still work the same from the Mac.
- Tunnel principals get the operational set only: status, check, events, metrics, connect, disconnect, exit selection, apply of head, low-risk changes, deploy confirmation. scupperd enforces this whatever edge asserts.
- `config rollback` is classified by its diff like any other change.

## Alternatives considered

- Accept any valid version from the API: one token gives lasting control (new device, exit replacement).
- A second admin token on the Mac readable only by root: protects against user-level malware, but adds a credential and a sudo path for little gain over SSH, which already exists as break-glass.
- Device-signed requests with replay protection: strongest against an edge compromise, but key handling on the Mac and in edge; an R2 option.
- Separate processes for DNS and the API: narrows edge compromise further; an R2 option.

## Consequences

- A stolen token or a compromised edge can disrupt service or choose among configured exits, but cannot add a device, change an exit's endpoint or keys, or redirect alerts.
- Administrative changes from the Mac need working SSH to the gateway's public address.
