# 0005. Built-in DNS forwarder

Status: accepted, 2026-11-08. Design: [DESIGN.md](../DESIGN.md).

## Context

Clients need a resolver on the gateway that forwards only through the active exit to that exit's DNS, keeps the provider's filtering, writes no query logs and later feeds per-domain routing. In every option, DNS leak safety comes from the topology, not the resolver.

## Decision

A small forwarder inside `scupper-edge`: UDP/TCP relay to the active exit's provider DNS, in-memory cache flushed on failover, `hickory-proto` for parsing only, no recursion, no DNSSEC validation, no query logging code path. Upstream sockets follow the namespace route. dnsmasq in the namespace is the documented fallback if the forwarder slips.

## Alternatives considered

- Unbound (forward-only, DNSSEC): mature, but an extra unit and rendered config, restart on every failover, DNSSEC conflicts with filtered provider answers (bogus → SERVFAIL), inside the namespace trust-anchor updates would need the VPN path, which is closed at boot, no native nft-set support.
- dnsmasq: good fallback; a second config to render and reload on failover.
- A full Rust resolver: more than needed.

## Consequences

- About 300 lines in a process that already exists in the namespace.
- Direct path to R2 per-domain nft sets.
- No DNSSEC validation on the gateway; clients may validate themselves.
- The forwarder's response matching (RFC 5452), generation tagging of upstream queries, TTL ageing, truncation fallback to TCP and EDNS/DNSSEC-bit pass-through are specified and unit-tested (DESIGN §9), since parsing with `hickory-proto` alone does not provide them.
- The Firefox DoH canary `use-application-dns.net` is answered locally with NXDOMAIN, so Firefox keeps using the gateway resolver unless a user enabled DoH explicitly.
