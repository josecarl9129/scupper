# 0033. Mac: scupper drives its own pinned wireguard-go, without wg-quick or Homebrew

Status: accepted, 2026-11-13. Amends [0021](0021-mac-wg-quick-pf.md) (tunnel driver) and
[0030](0030-mac-root-helper.md) (tool copies). Design: [DESIGN.md](../DESIGN.md) §14.

## Context

ADR 0030 originally made the root helper run root-owned copies of Homebrew's
`wg`, `wireguard-go`, `wg-quick` and `bash`, with recorded hashes. The copies are
independent of Homebrew, so a `brew upgrade` does not break them; instead they go
stale and miss WireGuard fixes until the user re-runs setup by hand. Operations
must need no manual steps after setup, and the update path must be scupper's own.
`wg-quick` is also a bash script run as root. Unattended provision/upgrade is M6a;
M5a establishes the tunnel driver and user-run setup first.

## Decision

- The scupper release for macOS contains a `wireguard-go` built in CI from a
  pinned upstream tag with a pinned Go toolchain, with its sha256 in the release
  checksums. `scupper mac setup` installs it root-owned next to the helper. No
  Homebrew package supplies the privileged tunnel tools.
- The helper replaces `wg` and `wg-quick`: it starts `wireguard-go -f utun` with a
  kernel-assigned interface number as its supervised foreground child, configures the device over the WireGuard
  UAPI socket (`set=1` key/value protocol), and sets addresses, routes (the /1
  split routes for v4 and v6 and the numeric IPv4 endpoint host route via the
  selected physical gateway), DNS (`scutil`) and MTU itself, using absolute
  paths to macOS system tools. No shell script runs as root.
- UAPI use is bounded, deadline-limited, read back, and never logs keys. The
  helper configuration lives in root-owned 0700 directories. The helper covers
  the darwin tunnel lifecycle: endpoint route refresh on network change,
  recursion and missing-gateway checks, simultaneous uplinks, MTU default 1280
  with override, DNS ownership/reconciliation and route cleanup. Exact DNS
  dictionary and other open implementation details are to be fixed in 5a2 as
  specified in DESIGN §14; cleanup removes only the helper's own DNS key.
- Recorded-hash checks remain tamper detection: installed files change only
  when scupper replaces them. With persisted join intent, the helper loads and
  verifies the pre-tunnel anchor and kills states before checking tool hashes
  and ownership. A mismatch then refuses join and reports failure. It must not
  exit on a tool mismatch before attempting and verifying protection; a failed
  policy load is reported as `NotProtected`, never assumed safe. Without join
  intent it installs no enforcement. A replaced helper is outside the claim.
- Join, leave and repair, and later update activation, share one serialized
  state machine. Planned teardown loads and verifies pre-tunnel enforcement,
  kills states, then releases the interface. Child death/helper restart does
  the same before recreation, never adopting a surviving utun or a previous
  generation's name-file/socket. The current-generation identity mechanism,
  startup readiness and stale socket/name-file rejection are **to be fixed in
  5a2**; a name alone is not identity. The death-to-reuse race remains a limitation.
  On restart, a durable leaving phase completes leave before considering join
  intent; it does not recreate a tunnel during an interrupted leave.
- The helper's socket authorizes the enrolled owner's uid with `LOCAL_PEERCRED`;
  in M5a this is the uid that ran setup, recorded before elevation.
  Any process running as this user can request leave; CLI confirmation prevents
  accidents, not malicious same-user requests.
- The pf claim is the qualified-configuration claim in DESIGN §14, with
  1 s/5 s check targets and no maximum detection/recovery duration. Hook loss
  and unsupported surrounding configurations produce `NotProtected`; with hook
  loss nothing of ours is evaluated and only routing still prefers the tunnel.
  Treat this as unprotected. The helper
  never rebuilds the main ruleset. Stale observations yield `Unknown`, with the
  last full verification time shown separately from tunnel health. V-05/V-20/
  V-21 are macOS-helper release gates per OS build and artifact; gaps are
  measured distributions, not bounds.
- DESIGN §14 specifies the bounded UDP endpoint and TCP 22 destination bypasses:
  any local app can send bytes to that IP:port outside WireGuard. TCP 22 goes
  only to the gateway endpoint IP on the selected physical interface with
  `keep state (if-bound)`; the CLI pins the host key. ADR 0008 stands unchanged.
  M5b moves routine admin to the tunnel API and turns public SSH into an
  explicit, expiring break-glass switch. High-risk changes, deploy/rollback and
  API-unavailable fallback still use SSH with that switch open (ADR 0029/0026,
  DESIGN §10/§15); closing or expiry removes the pass and its admitted states
  through the serialized state machine. An uncertain expiry must not reopen it.
  A closed-by-default switch conflicts with ADR 0008 (break-glass independent of every scupper
  component) and the §10 SSH fallback, so M5b must amend ADR 0008 and §10 first, including how the user recovers
  when the helper is hung (it can then neither open the switch nor leave).
- In M5a, user-run `scupper mac setup` (one admin prompt) is the only installer
  and refresh path. It imports the existing `~/.scupper/scupper0.conf` through
  the user-run CLI as validated typed data (device key, peer key, addresses and
  numeric endpoint); the helper uses the root-owned copy. The user copy remains
  for app binding, so its private key remains readable by that user. Enrolment
  stays M5b. It installs from the release archive verified by the user's
  own `scupper` using GitHub TLS and release checksums. R1 is not notarized;
  authenticated release metadata is R2, and signing/notarization accompanies
  the later Network Extension milestone.
- M6a adds unattended provisioning/upgrades: the helper takes only a release
  identifier, downloads from the fixed GitHub URL over TLS into root-owned
  staging, verifies the release itself and activates atomically with a durable
  rollback record. It accepts no caller-staged executables, archives or checksums
  as privileged activation authority. Activation maintains verified pre-tunnel
  enforcement when joined and rolls back on failure. The user agent is not a
  trusted privileged staging source.
- wireguard-go uses `unsafe` internally; the no-unsafe rule covers scupper's
  own code only.

## Alternatives considered

- Keep Homebrew tools and have the user agent re-run the copy after an upgrade:
  needs root again (a password prompt) and can leave stale tools or a refused join.
- Follow Homebrew's binaries without hashes: gives root to whoever can write
  the Homebrew prefix (ADR 0030's reason).

## Consequences

- More helper code (address, route, DNS and MTU management), with tests against
  the macOS route table and fault injection after privileged steps.
- WireGuard fixes reach the Mac through scupper releases; CI watches for new
  upstream wireguard-go tags. M5a refresh remains user-run until M6a provides
  unattended activation with the privileged-download requirements above.
- The wg-quick alternative rejected in ADR 0021 ("reimplements wg-quick") is
  accepted for these reasons.
