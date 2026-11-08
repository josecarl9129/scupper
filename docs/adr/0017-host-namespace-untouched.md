# 0017. scupper owns the namespace and nothing in the host

Status: accepted, 2026-11-08. Design: [DESIGN.md](../DESIGN.md).

## Context

Any host state scupper owns is state shared with other daemons. Ubuntu's stock `/etc/nftables.conf` starts with `flush ruleset`, so a host guard table would be wiped by any `nftables.service` reload: the bug-4 pattern again.

## Decision

Inside netns `scupper` scupper owns everything and loads its ruleset with `flush ruleset`; anything foreign there is drift. In the host it owns only its files and units: no host table, no host routes or rules, no forced sysctls, and never `flush ruleset` in the host (M1 keeps v1's ownership of `/etc/nftables.conf` as the one inherited exception, which shares the host ruleset with `nftables.service`; see ADR 0015). `install` may write `/etc/sysctl.d/90-scupper.conf` with host `ip_forward=0` on a dedicated host; `check` reports drift as a warning and never repairs it.

## Alternatives considered

- A host `inet scupper_guard` table, forced host `ip_forward=0` with restoration, networkd drop-ins and an initramfs guard: defense in depth that the topology already provides, with new shared state and much complexity.

## Consequences

- Host daemons cannot affect containment. They can affect availability of the client tunnel (host firewall, the `wg0` listen port), which `check` watches as client-side health without owning it.
- The host's own forwarding configuration is the operator's business.
