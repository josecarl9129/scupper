# 0021. Mac: wg-quick, pf sub-anchor, fingerprint-based auto-join

Status: accepted, 2026-11-08. Design: [DESIGN.md](../DESIGN.md).

## Context

The Mac needs a tunnel, a kill switch while joined and auto-join on untrusted networks, preferably without FFI or unsafe code.

## Decision

`wg-quick` drives the tunnel, run by a minimal root helper from root-owned copies of the tools (ADR 0030); a per-user agent does everything else. pf rules live in the sub-anchor `com.apple/scupper`, reached by the stock `anchor "com.apple/*"`, so `/etc/pf.conf` is never edited; pf is enabled with a reference token (`pfctl -E`/`-X`, never `-d`). Join persists the join intent, loads a pre-tunnel anchor first, flushes existing states ("existing connections are reset when you join"), verifies the whole evaluation path (pf enabled, the `com.apple/*` hook present, no skip flags, the anchor by read-back), then brings the tunnel up. States are interface-bound; DHCP passes are limited to physical interfaces and DHCP destinations; DNS to the local network is blocked while joined. After any detected loss of protection the helper loads the pre-tunnel anchor, flushes states and rejoins; at boot it restores a persisted join. Auto-join fingerprints (interface, gateway IP, gateway MAC) as a convenience hint, not an authenticated identity; the trusted list is empty by default, unknown networks are untrusted, and there is no auto-leave.

## Alternatives considered

- An own helper driving `wireguard-go` with its own routes and DNS: reimplements wg-quick.
- A root anchor added to `/etc/pf.conf`: edits a file macOS updates may rewrite.
- SystemConfiguration/CoreWLAN with SSIDs: needs FFI and location permission.
- Network Extension (packet tunnel with OS-enforced routing): stronger, continuous enforcement, but needs a signed and notarized app, Swift/FFI and a different WireGuard integration. Not in R1; re-evaluated for R2 from the V-05 and V-20 measurements (DESIGN §19, D-2).

## Consequences

- Exec-only Mac code.
- The guarantee is enforcement while pf evaluates the anchor, with removals detected within 5 s and repaired; the gaps and the boot window are measured (V-05), not assumed zero.
- Auto-join is not zero-gap.
