# 0011. Hot standby with two exits

Status: accepted, 2026-11-08. Design: [DESIGN.md](../DESIGN.md).

## Context

Failover needs to know whether a standby works before switching to it. A standby that is down until needed must first handshake and qualify, which costs about a minute. Each exit kept up costs one provider session, and the provider's limit on simultaneous sessions sharing `10.2.0.2` is not yet verified.

## Decision

`policy.standby = "hot"` keeps the active exit and the next candidate up and probed (any number of exits may be configured; at most two are hot, the rest are cold candidates); a switch is one route replace, about 15 s after a failure. Hot standby is relied on only after the provider account is confirmed to allow two simultaneous WireGuard sessions (verification task V-09); otherwise `standby = "cold"` brings the next candidate up on demand.

## Alternatives considered

- Cold standby only: no extra session, about 30-60 s outage per failover.
- More than two hot exits: more sessions for little gain in R1.

## Consequences

- Standby health is always known; standby probes use `SO_BINDTODEVICE`, require `rp_filter=0` in the namespace and run over IPv4 only (bound IPv6 sockets have no route while the v6 default is elsewhere).
- When no comparison is available (cold standbys, or the hot standby is down), sustained probe failure of the active exit brings up a cold candidate as a qualifier, so "handshake works, payload fails" still leads to failover (DESIGN §6).
- During migration overlap the session limit includes the old gateway's exit.
