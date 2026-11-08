# 0030. Mac: a minimal root helper with root-owned tools, a user agent for the rest

Status: accepted, 2026-11-08. Design: [DESIGN.md](../DESIGN.md) §4, §14.

## Context

The Mac needs root for pf and the tunnel. A single root LaunchDaemon with Homebrew in `PATH` would execute programs from a prefix the installing account can write, read a tunnel config from a user-writable directory (wg-quick runs hook commands from its config), parse HTTP and JSON from the gateway, and run user-defined secret backends. Compromise of the user account would then become persistent root and control over the kill switch.

## Decision

- **Root helper** (LaunchDaemon `net.scupper.helper`): pf, wg-quick, the persisted join intent, nothing else. It executes only root-owned copies of its tools (`wg`, `wireguard-go`, `wg-quick`, `bash`) in `/Library/Application Support/net.scupper/bin/`, made by `scupper mac helper install` with recorded sha256, by absolute path, with a fixed `PATH` and an otherwise empty environment. The tunnel config lives in a root-owned 0700 directory. It accepts typed commands (join, leave, status) over a root-owned local socket, parses no HTTP, reads no user config and resolves no secrets.
- **User agent** (LaunchAgent `net.scupper.agent`): network fingerprint and join requests, gateway events, notifications, bundle copies, the API token, secret references. It can request a leave only on an explicit user command.

## Alternatives considered

- One root daemon using Homebrew tools: trusts the Homebrew prefix owner with root.
- A signed privileged helper via SMAppService: the native mechanism, but needs a signed app; possible later together with a Network Extension.

## Consequences

- Homebrew upgrades of WireGuard tools reach the helper only after `helper install` is re-run; the helper refuses to start on a hash or ownership mismatch, which fails closed.
- Gateway-supplied data never reaches a root parser on the Mac.
