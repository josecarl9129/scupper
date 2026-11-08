# 0013. Exact ruleset comparison by kernel canonicalization

Status: accepted, 2026-11-08. Design: [DESIGN.md](../DESIGN.md).

## Context

`nft` normalizes text (e.g. `priority 0` prints as `priority filter`), so live and rendered text differ. v1 therefore checked that a few required substrings occur, which still "matched" when extra permissive rules (an `eth0` accept, an unconstrained `ct state established,related accept`) were present.

## Decision

Load the rendered file into an anonymous network namespace (`unshare --net`; the loader aborts if its namespace is the host's, so a failed switch can never load into the host), list it with `nft -j`, strip handles, counter values and metainfo, and compare the resulting JSON with the equally stripped live listing (M1: the whole host ruleset, which M1 owns through `flush ruleset`, so foreign tables, netdev chains and `dup`/`fwd` statements are differences; M2+: the whole namespace ruleset). Any difference is a violation (exit 2). The canonical form is cached per (rendered sha256, nft version and binary identity, kernel release), and a difference is confirmed with a fresh canonicalization before it is reported. Elements of sets the renderer marks dynamic (R2 per-domain routing) are excluded from the comparison; their declarations are not. Renderer constraint: match interfaces by name everywhere except `lo`, so the file loads where our links do not exist. This replaces v1's check already in M1.

## Alternatives considered

- Keep the substring check: misses extra rules.
- A hand-written normalizer of nft JSON: must track nft versions; easy to get subtly wrong.

## Consequences

- Correct across nft versions with no normalizer to maintain.
- Needs root and an anonymous namespace per cache miss; nothing persists after a crash.
- An nft upgrade without reboot cannot turn a stale cache into a violation.
