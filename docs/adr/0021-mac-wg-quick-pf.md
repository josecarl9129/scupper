# 0021. Mac: wg-quick, pf sub-anchor, fingerprint-based auto-join

Status: accepted, 2026-11-08. Design: [DESIGN.md](../DESIGN.md).

Amended by [0033](0033-mac-own-tunnel-driver.md) (2026-11-13) for the tunnel
driver. The pf policy, DHCP/ND lifecycle, verifier and hook-loss contracts below
are specified by DESIGN §14.

## Context

The Mac needs a tunnel, a kill switch while joined and auto-join on untrusted networks, preferably without FFI or unsafe code.

## Decision

The minimal root helper drives its own pinned, supervised `wireguard-go -f` child over UAPI and owns addresses, routes, DNS and MTU (ADR 0033); the full per-user agent is M5b. pf rules live in the sub-anchor `com.apple/scupper`, reached by the stock `anchor "com.apple/*"`, so `/etc/pf.conf` is never edited; pf is enabled with a reference token (`pfctl -E`/`-X`, never `-d`). Join persists the join intent, loads a pre-tunnel anchor first, flushes existing states ("existing connections are reset when you join"), verifies the qualified evaluation path (pf enabled, the `com.apple/*` hook present, no non-loopback skip flags or bypassing quick passes, qualified surrounding rules and the anchor by read-back), then brings the tunnel up. Stateful passes are interface-bound and every pass has explicit state options; DHCPv4 has acquiring/rebinding rules on every physical interface before a lease exists, then lease-server-only bound rules per interface; multiple leases alone are supported, with endpoint-path selection details to be fixed in 5a2. The underlay permits only the numeric IPv4 UDP endpoint, TCP 22 to that same gateway endpoint IP on the selected physical interface, DHCPv4 and the explicit link-local ND matrix; no DHCPv6 exception exists. The CLI pins the SSH host key; any local app can send bytes to the endpoint UDP/TCP IP:port exceptions outside WireGuard (DESIGN §14, ADR 0008 unchanged). Stock siblings are accepted only when no contained rule can match our traffic; any quick pass that could match produces `NotProtected`. Anchor verification renders, loads, reads back once, semantically checks the normalized pfctl form and stores its text/hash; later reads compare with that baseline, never renderer text. DNS to the local network is blocked while joined. Repairable failures trigger checked pre-tunnel enforcement, state flushing and rejoin only after verified enforcement; missing hooks, foreign bypass rules or unsupported configurations produce `NotProtected` without editing the main ruleset. On hook loss, nothing of ours is evaluated; only routing still prefers the tunnel, so treat it as unprotected. A durable leaving phase completes leave on restart rather than rejoining. Otherwise, at boot, persisted join intent requires verified pre-tunnel enforcement and state flushing before tool-integrity checks or child recreation. Join, leave and repair are serialized (DESIGN §14). Auto-join (M5b) fingerprints (interface, gateway IP, gateway MAC) as a convenience hint, not an authenticated identity; the trusted list is empty by default, unknown networks are untrusted, and there is no auto-leave.

## Alternatives considered

- An own helper driving `wireguard-go` with its own routes and DNS: originally rejected as reimplementing wg-quick; accepted by ADR 0033.
- A root anchor added to `/etc/pf.conf`: edits a file macOS updates may rewrite.
- SystemConfiguration/CoreWLAN with SSIDs: needs FFI and location permission.
- Network Extension (packet tunnel with OS-enforced routing): stronger, continuous enforcement, but needs a signed and notarized app, Swift/FFI and a different WireGuard integration. Not in R1; re-evaluated for R2 from the V-05 and V-20 measurements (DESIGN §19, D-2).

## Consequences

- Exec-based system integration and a bounded UAPI client; scupper has no unsafe code, while wireguard-go uses unsafe internally.
- On qualified configurations, effective pf policy blocks traffic outside documented exceptions. Checks target 1 s/5 s while the helper runs, with no guaranteed maximum detection/recovery duration; transient changes or admitted states may escape detection. Stale observations yield `Unknown`; status shows the last full verification time. Boot before enforcement is unprotected; V-05 reports gap distributions, not a bound (DESIGN §14).
- M5b moves routine admin to the tunnel API and makes public SSH an explicit,
  expiring break-glass switch. High-risk changes and deploy/rollback still use
  SSH (ADR 0029/0026) with the switch open; closing/expiry removes the pass and
  its admitted states, as specified in DESIGN §14.
- Auto-join is not zero-gap.
