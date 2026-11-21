# 0034. Mac: a confined, typed Darwin FFI boundary

Status: accepted, 2026-11-20. Amends [0021](0021-mac-wg-quick-pf.md) and
[0033](0033-mac-own-tunnel-driver.md) (the first-party no-unsafe rule).
Design: [DESIGN.md](../DESIGN.md) §14.

## Context

The native helper needs kernel interfaces that command output cannot establish:
complete pf reference enumeration, precise process start identities and Darwin
spawn isolation. Exec-only integration cannot implement those contracts. Moving
all layouts into byte offsets would move the same risk into decoders rather
than remove it.

## Decision

- `scupper-darwin` is the only first-party crate permitted to contain unsafe
  code. It is empty outside macOS. Every other crate retains the workspace's
  `forbid(unsafe_code)` policy.
- Its Cargo lints copy the workspace table, changing `unsafe_code` to `deny`.
  Only its private `sys` module allows that lint. `unsafe_op_in_unsafe_fn`,
  `clippy::undocumented_unsafe_blocks`, `clippy::multiple_unsafe_ops_per_block`
  and `clippy::missing_safety_doc` are denied. These constraints must not be
  relaxed as the boundary grows.
- The boundary uses the already locked `libc` and `rustix` dependencies. Use
  safe rustix APIs when they provide the exact operation. `nix` is unnecessary:
  its spawn interface lacks Apple's `POSIX_SPAWN_CLOEXEC_DEFAULT`, introduces
  another build dependency, and does not encode the helper's timeout and
  child-recording contract.
- Public results are typed and owned. Fixed-layout records use SDK-compatible
  types and initialised typed buffers; no padding is exposed. File descriptors
  and other resources use RAII ownership. A worker owns its buffers and
  resources until the foreign call returns, even if its caller times out.
  Packed or variable-length records are returned as initialised bytes and
  decoded by safe, portable, Linux-tested code in `scupper-mac::decode`.
- Each unsafe block documents pointer lifetime, alignment, initialisation,
  returned-length validation and timeout ownership as applicable. A compiler
  lint boundary, rather than a literal-token search, enforces confinement.
- An SDK C probe records sizes and field offsets on each native runner. Binding
  additions must compare those observations against Rust layouts. The bootstrap
  records ABI evidence only; it introduces no process or pf record bindings.
  Darwin ioctl encoding is portable and tested independently of the host OS.
- Cross-target clippy for `aarch64-apple-darwin` is a required local and Linux CI
  check. Native linking, SDK layout evidence and runtime qualification remain
  separate checks on pinned macOS 15 and 26 Apple Silicon runners.

## Alternatives considered

- Exec-only integration: cannot establish the kernel reference and process
  contracts or the exact spawn attributes.
- Raw bytes for every interface: makes fixed C layouts less explicit and pushes
  layout mistakes into hand-written offsets.
- Unsafe code throughout the helper: unnecessarily expands the review boundary.

## Consequences

The no-unsafe statements in the earlier decisions and DESIGN §14 now have one
explicit exception. The engine and Platform contract remain safe Rust. The
bootstrap qualification harness observes state only; it cannot establish native
firewall enforcement or authorize production protection claims. Native adapter
operations and their qualification are added separately, with the constructor
remaining gated by the `qualification` feature during adapter development.

## Base binding failure inventory

The infallible `now`/raw-clock and `incarnation` operations abort on an OS
failure or an invalid value rather than invent time or a process identity.
Abort skips Rust destructors, including the qualification harness's supervised
child cleanup. The independent dead-man restores journaled children by their
recorded `(pid, start)` identities.

Base read-only children are journaled after spawn and identity lookup, without
an exec gate. A controller death before journal sync can leave an unjournaled
sleep (at most 360 seconds) or churn process (at most 180 seconds). This bounded
residual is a deliberate difference from the capability probes' exec-gated
journal discipline; these children make no network or firewall mutations.
