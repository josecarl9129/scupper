# 0007. API authentication: WireGuard identity plus device token, plain HTTP

Status: accepted, 2026-11-08. Design: [DESIGN.md](../DESIGN.md).

## Context

The API listens on the tunnel address inside the namespace. WireGuard already provides confidentiality and peer authentication. The remaining threat is a web page in the Mac's browser sending requests to the gateway address (CSRF, DNS rebinding).

## Decision

Plain HTTP/1.1 served by edge. A request is authenticated when (1) its source address belongs to exactly one configured device (WireGuard binds sources to peer keys) and (2) it carries `Authorization: Bearer <token>`, a 32-byte token generated on the device of which the gateway stores only the sha256 (constant-time compare). `Host` must be the literal tunnel address; no CORS headers; preflights refused. Edge asserts the principal to scupperd, which accepts assertions only on the edge socket and decides itself which operations a tunnel principal may perform (ADR 0029). `GET /v1/health` needs no token and returns only `ok`.

## Alternatives considered

- WireGuard identity alone: open to browser-originated requests.
- Mutual TLS with a private CA: certificate issuance, rotation and revocation plus several crates, for little protection beyond WireGuard.

## Consequences

- No CA or certificates to manage.
- A leaked token is usable only from the device's tunnel address, so it needs code running on the device or the device's WireGuard key. The token file is readable by any process of the Mac user, so that is a real case; ADR 0029 limits it to the operational API set.
- A compromised edge can assert any device principal, but only for the operational set that scupperd enforces; edge is unprivileged, holds no keys and sees only its own socket in `/run`.
