# 0027. Gateway creation from the Mac with a client-only cloud token

Status: accepted, 2026-11-08. Design: [DESIGN.md](../DESIGN.md) §15.

## Context

Rebuilding or adding a gateway should take minutes and few manual steps.
Creating a VM needs a cloud API token, which can create, destroy and bill
resources: it must be protected like a key (I6).

## Decision

`scupper gateway create --provider digitalocean [--region --size --name]`
runs on the Mac: resolve the token from an operator-side secret reference
(ADR 0023), register the Mac's SSH public key, create the VM with a bootstrap host key
generated on the Mac and passed in the cloud-init user data over the
authenticated API, connect with that key pinned, have the VM replace it
with freshly generated host keys over that session and pin those, then run
`deploy` and the guided `install`. The documented token is custom-scoped
without delete; `delete_host` touches only hosts tagged by the same
invocation and never a configured gateway; the token is stripped from every
child environment. The token is used only on the Mac for the duration of the
command and is never stored in config, events, logs, child process
arguments or on the gateway. Cloud access sits behind a small
`CloudProvider` trait (`ensure_ssh_key`, `create_host`, `wait_ready`,
`delete_host`); R1 implements DigitalOcean and tests it against a local fake
API server.

## Alternatives considered

- Terraform as the R1 path: an extra tool and state file for one VM; kept as
  an R2 example.
- Storing the token on the gateway: only needed for R2 HA option (a), and
  then as a documented, separate decision (ADR 0024).
- Manual VM creation only: slower rebuilds, more runbook steps.

## Consequences

- Rebuild (ADR 0025) becomes `gateway create` + `install --bundle` +
  `mac enroll`.
- No trust on first use: the first contact is authenticated by the bootstrap host key, which is replaced before any secret is uploaded (the cloud metadata service keeps serving the user data, so the bootstrap key must not stay in use).
- Other clouds need only a trait implementation.
