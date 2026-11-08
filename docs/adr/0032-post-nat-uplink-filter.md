# 0032. Drop exit-sourced uplink packets after NAT

Status: accepted, 2026-11-08. Design: [DESIGN.md](../DESIGN.md) §2, §5.1, §5.2, §17.

## Context

The M1 lab's `config-disagreement` case exposed a leak: when a reply via `proton0` could not be delivered on `wg0`, the gateway generated an ICMP host-unreachable error and routed it through the main table to `eth0`. Conntrack applied the related client flow's NAT at postrouting, changing the source to `10.2.0.2` after the output hook. The output-chain exit-source drop could not see that final address. Frag-needed and other gateway-generated ICMP errors about NATed client flows can take the same path, violating I1.

## Decision

Keep the output-chain rule and add an `egress` filter chain at the postrouting hook with priority 110 and policy accept. After source NAT at priority 100, drop packets whose output interface is `V1Config.uplink_iface` and whose source is `V1Config.exit_addr`. Render the chain after `output` and update the byte-exact golden. Require zero uplink packets in the lab's `config-disagreement` case, and track this post-NAT property as L55 for M1 (lab) and M2.

## Alternatives considered

- Rely on the output rule: it runs before the related flow's NAT and misses the observed leak.
- Remove the output rule in favour of the new chain: retain the existing guard for locally generated packets that do not pass through NAT.
- Filter only ICMP host-unreachable: frag-needed and other related errors need the same protection; matching the final source covers them together.

## Consequences

- This deliberately diverges from v1's byte-for-byte ruleset parity (ADR 0015) to close the leak. The v1 `rulesetMatchesPolicy` substring check still passes because all its expected rules remain.
- Other host traffic remains permitted; the new rule only drops exit-sourced packets on the configured uplink after NAT.
- M2 must hold the same property: nothing with an exit address or client address on the uplink, checked after NAT, including gateway-generated ICMP errors. The namespace topology remains the primary barrier.
- Captured lab fixtures predate this chain; comparing captured live JSON against captured wanted JSON remains valid. Recapturing them is separate work.
