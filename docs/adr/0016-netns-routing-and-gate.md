# 0016. Single default route in the namespace; forwarding as the emergency gate

Status: accepted, 2026-11-08. Design: [DESIGN.md](../DESIGN.md).

## Context

Inside a namespace whose only non-loopback links are tunnels, the routing must pick the active exit and fail closed when none is healthy. Policy routing (RPDB rules, per-exit tables, marks) reintroduces the mechanism behind bugs 1 and 4. The ruleset drift case needs a gate that works even when the ruleset itself is gone.

## Decision

No policy rules in the namespace. Per family the main table holds one default route: `dev <active exit>` or `unreachable` (an ICMP error, so applications fail fast). Failover is one `route replace` per family, then a conntrack flush. Forward accepts client→any configured exit; the route chooses. The emergency gate for ruleset drift is namespace forwarding 0; every forwarding change is followed by re-applying and reading back the hardening sysctls (writing `ip_forward` rewrites per-device forwarding and `accept_redirects`), including `rp_filter=0`.

## Alternatives considered

- RPDB with `iif wg0` rules, uid and fwmark rules, per-exit tables and blackholes: a dozen objects to watch, marks need privilege, no I1 gain.
- An nft "active exit" set as the gate: depends on the ruleset being present, which is exactly the case it would need to cover.
- `blackhole` defaults: silent drops make applications hang.

## Consequences

- Every intermediate failover state routes to an exit or `unreachable`.
- Standby probes must use `SO_BINDTODEVICE`.
- Toggling forwarding requires the sysctl re-apply step.
- Standby probes are IPv4 only.
- Raising forwarding is refused while the quarantine latch is set (ADR 0031).
- The gate does not stop a tc `mirred` action on a foreign link; foreign links and tc hooks are acted on in the first tick (DESIGN §2, §7).
