# 0030. Mac: a minimal root helper with root-owned tools, a user agent for the rest

Status: accepted, 2026-11-08. Design: [DESIGN.md](../DESIGN.md) §4, §14.

Amended by [0033](0033-mac-own-tunnel-driver.md) (2026-11-13).

## Context

The Mac needs root for pf and the tunnel. A single root LaunchDaemon with Homebrew in `PATH` would execute programs from a prefix the installing account can write, read a tunnel config from a user-writable directory (wg-quick runs hook commands from its config), parse HTTP and JSON from the gateway, and run user-defined secret backends. Compromise of the user account would then become persistent root and control over the kill switch.

## Decision

- **Root helper** (LaunchDaemon `net.scupper.helper`): pf, the persisted join intent, supervised `wireguard-go -f`, UAPI, addresses, routes, DNS and MTU (ADR 0033). It executes the root-owned, release-bundled pinned `wireguard-go` in `/Library/Application Support/net.scupper/bin/` and macOS system tools by absolute path, with a fixed minimal environment. User-run `scupper mac setup` installs the helper and child with recorded sha256; no Homebrew tools or shell scripts run as root. The tunnel config lives in a root-owned 0700 directory. It accepts typed commands over a root-owned local socket, authorizes `LOCAL_PEERCRED` against the enrolled owner's uid only (the uid that ran setup in M5a), parses no gateway HTTP/JSON (the M6a release-download exception is specified in DESIGN §14), reads no user config and resolves no secrets. Any process running as this user can request leave; the CLI asks for confirmation to prevent accidents. M5a setup imports validated data from the existing `~/.scupper/scupper0.conf` into the root-owned configuration through the user-run CLI; it retains the user copy for app binding, including its user-readable private key (DESIGN §14). Enrolment stays M5b. M5a also records durable errors and sends minimal failure notifications using `launchctl asuser <uid> sudo -u <user> /usr/bin/osascript …` (absolute system-tool paths): `asuser` selects the session, and `sudo -u` drops to the recorded non-root owner before the interpreter starts. The fixed script takes a bounded, validated message argument rather than interpolated source; the child has a deadline, and notification failure never affects enforcement.
- **User agent** (LaunchAgent `net.scupper.agent`, M5b): network fingerprint and join requests, gateway events, notifications, bundle copies, the API token, secret references. It requests leave only on an explicit user command; this convention is not an authorization boundary against another process of the enrolled uid.

## Alternatives considered

- One root daemon using Homebrew tools: trusts the Homebrew prefix owner with root.
- A signed privileged helper via SMAppService: the native mechanism, but needs a signed app; possible later together with a Network Extension.

## Consequences

- WireGuard fixes reach the helper through scupper releases: user-run `mac setup` in M5a, unattended helper-owned download/verification and atomic activation with rollback in M6a (ADR 0033). A durable leaving phase completes leave on restart. Otherwise, with persisted join intent, the helper loads and verifies pre-tunnel enforcement and kills states before tool checks; a hash/ownership mismatch then refuses join and reports `NotProtected`. Without join intent it installs no enforcement. A replaced helper is outside the claim; failed policy loads must be reported, never described as protected.
- Gateway-supplied data never reaches a root parser on the Mac.
