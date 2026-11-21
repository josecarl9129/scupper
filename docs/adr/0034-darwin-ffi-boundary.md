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

## OD4 B-neg: negative-only main-image evidence (R3b)

macOS continues to return `ProcInfo.exe = None` (OD4 A). For ENOENT from
`proc_pidpath`, read flavor 17 `proc_uniqidentifierinfo`, then re-lookup
`KERN_PROC_PID` for the enumeration's exact `(pid, start)`, then repeat flavor
17. Require identical nonzero UUID, uniqueid and exec-sensitive idversion.
Any failed/short read or bracket mismatch is Incomplete with the live PID;
confirmed vanishing and zombies retain the existing rules. `p_idversion` is
in the flavor-17 API record at offset 32; neither public `proc_bsdinfo` nor
`extern_proc` exposes it. The C probe and Rust const assertions pin this
[XNU API wire declaration](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/proc_info_private.h).
The SDK omits that private header, so the probe declares the wire record just
as the existing R2 identity probe does; this is not an independent SDK oracle.

Ownership and ambiguity rules run first. A remaining pathless live process is
provably foreign only if its validated UUID differs from every UUID in known
durable spawned-image history for the current boot and every current pin UUID,
and its known kernel name is not `wireguard-go`. Unknown history, unknown boot,
unknown pin UUID, missing image or name, and UUID equality withhold completeness
with the PID. UUID equality never selects or signals a process. A foreign
pathless process sharing a recorded or pinned build UUID blocks until it exits.
A translated foreign process is compared by its own main-image UUID only.

Snapshot family/format 2 adds boot-scoped spawned-image history, bounded to eight
distinct UUIDs. Missing, unreadable, corrupt and format-1 history is unknown,
never empty. Overflow marks the boot unknown and never evicts a UUID silently.
Only proof of a different boot resets it to empty-known. Unavailable or disagreeing
copies revoke history certainty even when the lifecycle start table can trust one
copy. Current tool pins also participate in negative comparisons during ordinary
sweeps and Leave; they gain no new ownership matches. Before spawn the engine
commits the pin UUID; write failure forbids spawn. An unexpected post-spawn UUID
is recorded durably, the exact child is killed, and spawn fails. R4 must report
the child's observed main-image identity and reject translated (Rosetta) owned
children via `proc_translated`/`P_TRANSLATED`. The read-only pin parser supports
thin arm64/arm64e and accepts fat files only when all native arm64 slices agree.
