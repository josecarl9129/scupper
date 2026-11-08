# 0006. Block DNS over TLS instead of intercepting it

Status: accepted, 2026-11-08. Design: [DESIGN.md](../DESIGN.md).

## Context

The requirement asked that all client DNS, including DoT on 853, be forced to the gateway resolver. TLS interception cannot work for third-party resolvers whose certificate the gateway does not hold. DoH on 443 cannot be told apart from HTTPS.

## Decision

Reject client TCP/853 with a TCP reset and UDP/853 with ICMP port-unreachable, so clients fall back to port 53 immediately, where all queries are redirected to the forwarder. The requirement is restated as: **plain DNS forced, DoT blocked, DoH not controllable.**

## Alternatives considered

- Redirect TCP/853 to a gateway TLS resolver with its own certificate: needs certificate issuance and rotation, still fails for third-party DoT, and adds nothing inside WireGuard.
- Silently drop 853: clients hang until timeout before falling back.

## Consequences

- DoT clients fall back quickly; strict DoT clients fail closed.
- DoH bypasses the gateway resolver but still leaves only through the VPN (I1 unaffected).
