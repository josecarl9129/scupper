# 0023. Secret references: gateway files by name, operator secrets resolved just in time

Status: accepted, 2026-11-08. Design: [DESIGN.md](../DESIGN.md) §8.

## Context

Config must never contain key material (I6) and must stay portable across
gateways for R2 config push. Operators also supply secrets from the Mac
(cloud API tokens, credential URLs) that must not end up in files, logs,
process arguments or on the gateway.

## Decision

- **Gateway side:** config fields are `*_ref` names; the secret is the file
  `/etc/scupper/secrets/<kind>/<ref>` (root, 0600; directories 0700). Refs
  are basenames matching `[a-z0-9][a-z0-9-]{0,62}`; the kind follows from
  the field, so a URL field cannot name a key file; files are opened
  relative to a directory descriptor without following symlinks and checked
  for type, owner and mode; content is validated per kind and never appears
  in errors. The schema has
  no key-typed field; a lint rejects key-shaped strings elsewhere.
  Credential-bearing URLs (ntfy topic, webhook, heartbeat) are secrets too.
- **Operator side:** every secret input is a reference `scheme:rest`
  resolved just in time through a registry of `SecretBackend`s, one per
  scheme. Built-in backends: `pass://vault/item/field` (Proton Pass
  `pass-cli`, the primary documented source; pinned minimum version,
  `PROTON_PASS_AGENT_REASON` set to the scupper command), `keychain:`,
  `env:`, `file:` (caller-owned, mode 0600), and no reference, which means a
  hidden prompt on a TTY and refusal otherwise.
- **Extensible:** any other store (1Password, Bitwarden, gopass, Vault, a
  script) is added as a command-defined backend in the Mac-side config: an
  argv template with `{ref}` substituted as one argument, no shell, a
  timeout, stdout as the value, a minimal environment. New built-ins are one new trait
  implementation. Built-in schemes cannot be overridden.
- **Never as root:** secret resolution refuses to run with euid 0, and no
  root process reads the user's Mac-side config.
- Reference strings are not secret and may be stored in Mac-side config.
  Values live only in memory (`Zeroizing`), never in config, events, logs,
  process arguments or on the gateway. A reference resolves only through its
  own backend: a missing or logged-out `pass-cli` fails with "run
  `pass-cli login`" and never falls back to another backend. A fake backend
  serves tests; cloud clients are tested against a local fake API, so
  development and CI need no real token.

## Alternatives considered

- Absolute `*_file` paths in config: machine-specific paths in a shared file.
- Names mapped to files by a separate node file: a second file to keep in sync.
- Tokens as plain command-line flags or config values: leak via shell
  history, process listings and files.
- A closed enum of sources: every new store needs a release.
- A plugin ABI (dynamic libraries): unsafe, platform-specific, unneeded when
  a command template covers every store with a CLI.
- Keychain through the Security framework from Rust: needs FFI; an unsigned
  CLI still gets the legacy "allow" dialog, not per-use Touch ID (that needs
  a signed app with entitlements).

## Consequences

- The same site file is valid on every gateway; each resolves refs locally.
- Bundles and pushes cannot carry secrets.
- Silent fallback between sources is excluded: it would read a different
  secret than the one named.
- Operators choose their store (Proton Pass, Keychain, environment, file,
  or any store with a CLI via a command backend) without scupper ever
  persisting a value.
- Command backends run operator-configured programs; they are as trusted as
  the operator's own shell config, run only on the operator's machine,
  never as root, and get a minimal environment (no cloud tokens). They ship
  in R1 (DESIGN §19, D-3).
