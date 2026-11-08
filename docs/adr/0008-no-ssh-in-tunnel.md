# 0008. No SSH inside the tunnel; break-glass SSH to the public address

Status: accepted, 2026-11-08. Design: [DESIGN.md](../DESIGN.md).

## Context

In v1 the CLI wrapper ran commands over SSH to the gateway's tunnel address. In the namespace layout sshd stays in the host namespace, so the tunnel address no longer reaches it. Break-glass access must work when the tunnel or the daemons are broken.

## Decision

No sshd in the namespace. The CLI talks to the tunnel API. Break-glass SSH goes directly to the gateway's public address; the Mac's pf anchor has exactly one exception for it: TCP 22 to the gateway endpoint address (wg-quick's endpoint host route sends it via the physical interface). The CLI falls back to SSH only when the API is unavailable, never on an authentication failure, and reports the transport used.

## Alternatives considered

- An sshd socket unit inside the namespace on the tunnel address: a second sshd configuration and another listener in the client-facing namespace.
- No SSH exception in pf: a joined Mac would have no path to its own gateway when the API is down.

## Consequences

- `ssh <tunnel address>` stops working after migration; documented.
- Break-glass is independent of every scupper component and of the provider.
