# 0003. Exec system tools instead of netlink crates

Status: accepted, 2026-11-08. Design: [DESIGN.md](../DESIGN.md).

## Context

scupper must read and write links, addresses, routes, rules, WireGuard peers, nftables, tc and conntrack. Netlink crates give structured access but are async-only, add audit surface and change frequently. The requirements ask for minimal dependencies.

## Decision

Exec `ip -j`, `nft -j`, `wg`, `tc -j`, `conntrack` and `sysctl` by absolute path, with a hard timeout per call (3 s, probes 8 s) and an explicit allow-list of invocations: everything not listed is refused, which includes `wg showconf`, `show … dump`, `show … private-key` and `show … preshared-keys` because they print keys. Parse JSON output where available. Parsers are tested against captured output from Ubuntu 22.04, Ubuntu 24.04 and Debian 12.

## Alternatives considered

- `rtnetlink`, `genetlink`, `netlink-packet-wireguard`: faster change detection, more structure; the gain is availability, not safety. Revisit if polling cost or parsing fragility shows up.
- A custom nft netlink encoder: large and risky; `nft -f` is already transactional.

## Consequences

- Every action in a log can be reproduced by hand by an operator.
- Output-format drift across tool versions is a risk, mitigated by JSON and fixtures.
- A hung tool is bounded by the timeout and counted as a failure.
