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
17. Require identical nonzero UUID, uniqueid and exec-sensitive idversion, and
require the re-lookup name, pgid and ppid to equal the listed fields.
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

Snapshot family/format 2 adds boot-scoped spawned-image history, bounded to
eight distinct UUIDs. Missing, unreadable, corrupt and format-1 history is
unknown, never empty. Overflow marks the boot unknown and never evicts a UUID
silently. An independently proven fresh installation may write
`Snapshot::initial(owner_uid, boot)` as known-empty for a proven boot. Only the
installer may write it, after proving no existing storage or install record; it
writes both copies with identical bytes, and durable initialisation completes
before enabling the helper. Retries preserve existing state and never overwrite
it with `initial`. Owned children exec `/opt/scupper/wireguard-go`, `p_comm`
cannot be changed by the process, and wireguard-go never execs: the name guard
is a load-bearing backstop if the fresh-install proof or a mismatch-history
commit fails.

After Recovery, a torn pre-spawn commit (disagreeing or unreadable copies), or a
format-1 upgrade, history is unknown on the currently observed boot (the
uncertainty epoch). Sweeps stay Incomplete until reboot while any foreign
pathless process exists; there is no same-boot reset. An unreadable boot revokes
certainty and clears the epoch; a later readable boot establishes an unknown
epoch without resetting history. StartChild refuses to spawn while the boot is
unreadable, before the pre-spawn history commit. A helper record's boot cannot
supply this epoch: Recovery can prefer an older valid copy's helper, so that
provenance can roll back. Only a later different proven boot resets unknown
history to known-empty. On rollback, a format-1 helper reads v2 copies as
invalid and enters Recovery (L10). Unavailable copies or unequal image histories
revoke history certainty and clear the epoch even when the lifecycle start table
can trust one copy. Equal image histories in two valid copies retain certainty
at any sequences: a spawn happens only after a full A+B commit containing its
UUID, histories only grow within a boot, and a boot reset makes them unequal, so
equal histories at different sequences contain every spawned UUID of their boot.
Current tool pins also participate in negative comparisons during ordinary
sweeps and Leave; they gain no new ownership matches. Before spawn the engine
commits the pin UUID; write failure forbids spawn. An unexpected post-spawn UUID
is recorded durably, the exact child is killed, and spawn fails. A failed commit
enters the normal PersistBlocked/Stuck path; an unconfirmed kill retains the
child and requires a sweep. Failed or timed-out spawn also re-reads the child
pin and durably records the pin UUID as it is at re-read time (or revokes
certainty if unreadable) before trusting another sweep. An intermediate pin
replacement racing the spawn is covered only by the name guard. If this history
commit fails, the last sweep is marked Incomplete before returning. Pin reads
use O_NONBLOCK, O_NOFOLLOW and bounded preads: fat header/table, each native
slice header, then at most 1 MiB of load commands total across all slices,
checking the deadline between reads. A single blocking pread on a hung volume
can outlast the deadline; pins are root-owned and local. Fat arm64 slices must
still agree; no implicit arm64e subtype preference is introduced. R4 must report
the child's observed main-image identity even on partial failure and reject
translated (Rosetta) owned children via `proc_translated`/`P_TRANSLATED`. The
read-only pin parser supports thin arm64/arm64e and accepts fat files only when
all native arm64 slices agree.

## R5 snapshot storage: error handling qualification

The provisional two-copy namespace is `Paths::production().root` with fixed
`snapshot-a` and `snapshot-b` names, pending 5a3's installer layout. The adapter
never creates or relaxes that root. An fd-relative `O_DIRECTORY|O_NOFOLLOW` walk
checks the root and every ancestor for root ownership and no group/world write.
Only ENOENT opening a copy relative to that checked root establishes Missing.
Copies require regular/root/0600/single-link metadata and size at most 16384
bytes before read bytes or an existing-copy write are allowed. Short files return
zero-padded bytes with explicit `CopyRead::Short` provenance and always classify
as torn, so the engine repairs them. Provenance is necessary: a truncated suffix
can consist entirely of format padding, making padded bytes alone look valid.
Long files remain Unreadable. A write must leave exactly 16384 bytes before sync.

A persistent single storage thread owns writes and their buffers through timeout.
Busy starts nothing until the prior result is consumed by `wait_write`; reads
have an independent bound of two live workers including abandoned workers.
Abandon drops the receiver and never transfers an old result to a later read.
A copy read performs one bounded pread matching fstat length; unexpected short
reads fail closed. Write opens include O_NONBLOCK to reject FIFOs without hanging.
A panicking storage worker fails its outstanding call and is replaced on retry.
Deadlines bound
waiting, not a kernel call on a hung volume; an abandoned worker retains its fd
and capacity slot until return. There is no cancellation or rollback claim.

`create_copy` exclusively creates and preallocates, checks the full pwrite count
and final fstat length, then checks file and directory `F_FULLFSYNC` in order.
Creation explicitly checks fchown and fchmod(0600), independent of umask.
On a failed create, cleanup compares fstat(fd) with fd-relative nofollow lstat;
only matching dev/ino may be unlinked, followed by directory F_FULLFSYNC.
Cleanup is best effort and never changes Failed to Synced. A crash or failed
cleanup can retain a short stub, which the normal repair path can overwrite.
The checked root is private; this check is not an atomic conditional unlink
against a concurrently malicious root process.
Preallocation reserves blocks and does not set length. `write_copy` never creates
and checks its full pwrite count and file `F_FULLFSYNC`. When the initial fstat
is short, repair also requires storage-root directory `F_FULLFSYNC` after the
file sync. A failed create's surviving name may never have been synced; file
sync alone cannot certify that repair as Synced. A directory sync failure keeps
the repair Failed without unlinking the existing copy. The portable model tests
both sync failures and ordering, and a skip-repair-directory-sync mutant must
fail. The fake can retain or lose a failed create's name across reboot, and
startup repairs Short with `write_copy` and Missing with `create_copy`.
There is no fsync fallback.
Failed writes, failed syncs and timed-out writes may leave partial bytes, or the
complete old/new snapshot. A successful sync after a failed write proves nothing
about content. Only a complete protocol can return Synced.

Q-STORE injects per-call failures in qualification builds only and observes APFS
unfilled/full images; full means ENOSPC on a block write, not zero free blocks.
Full-volume operations may fail before the selected injection stage. Only the
matching per-stage injected marker earns an iteration. Unfilled runs require
all hooks to fire and check create size/bytes before cleanup (0/0/8192/16384/16384
bytes, with Short provenance before the full length). Final create post-state is
Missing after cleanup, and failed
overwrite bytes must match the completed stage. Evidence records reached and
unreached counts; the 500 minimum applies only to reached operations. The SDK
probe pins the local fstore_t binding and F_FULLFSYNC command (51), compared to
the Rust libc constant before storage operations. Source regression checks pin
the fcntl call, checked -1 result and absence of fsync fallback. These checks do
not execute Darwin sync on Linux or prove kernel/media durability.
Q-STORE's 420-second deadline starts at run entry, includes its at-most-120-second
setup, and fits in the 600-second CI step with 180 seconds for startup, ABI probe
and verdict saving (the in-run probe also consumes the case budget). Expiry is
an environment Inconclusive, including through nested phase errors. Every phase
journals start/end timestamps, elapsed seconds and outcome outside the images;
completed timings are also included in the hook counts. The unfilled image is
256 MiB (recorded in image-size evidence), allowing headroom for reset writes
and APFS CoW metadata; the full image remains 4 MiB. After full-volume checks,
the harness reclaims filler space before restoring the reserved B name and
running deterministic concurrency resets. A rename on a full APFS image may
itself return ENOSPC; a prior file allocation does not reserve rename metadata.
Concurrency evidence explicitly identifies the reclaimed image state. The journal
and independent dead-man own
image detachment (30 seconds, then a forced retry), mountpoints and fixture files.
Image create/attach tools wait on an exec gate until their PID/start identity is
synced in the resource journal; EOF before a grant starts no mutator. Recovery
stops those exact writers before inventorying or detaching images.
The claim is **error handling only; crash and power-loss durability are not
established**. Neither these observations nor F_FULLFSYNC's successful return
establish that residual. Native construction remains qualification-only. The
install-record format/writer belongs to 5a3, so both install reads still fail
closed and tool digests still come only from qualification-supplied pins.

5a3 must prevent building the production helper with `qualification` enabled,
using a production-bin compile_error or a release-binary CI guard. Hook exclusion
in no-feature library builds alone is not a production-binary guard. R4 native
mutations install helpers from qual-out: the top-level built-binaries manifest
provides their build provenance, while experiment manifests prove installed copies.

## R6 native pf references and assumption gates

The helper's only global enable is pinned `/sbin/pfctl -e`, through the bounded
mutating tool runner. It takes one anonymous reference, including qualified
EEXIST; repeated calls do not accumulate references. Numeric release cannot
remove it. It persists after Leave until reboot or a foreign global disable.
The adapter never runs `pfctl -d`; only disposable qualification/restore does.

Starter enumeration opens `/dev/pf` read-only with close-on-exec and uses
DIOCGETSTARTERS `0xC0104405`. The request is 16 bytes; records are packed 84-byte
little-endian `(token, calendar timestamp, pid, proc_name)` values. Rust const
assertions and the C probe pin sizes and offsets. The private wire declaration
is shared XNU evidence, not an independent public-SDK layout oracle. Failed
ioctls expose no returned size. An ENOENT size query means empty; other query
errors are incomplete. Successful sizes must be divisible by 84. Copy capacity
starts at `(need/84 + 16)*84`, using zeroed buffer length, never allocation
capacity. Copy errors restart the query. Returned lengths must be aligned and
within the buffer. Complete requires at least one whole spare slot; a full copy
retries with doubled slots, for at most eight attempts. Sub-record buffers
returning zero prove no absence. Duplicate token values are a layout error.
A 16 MiB allocation bound fails closed. One abandonable worker owns its fd and
buffer until return; timeout retains its slot and another read reports busy.

Numeric token values recur. The engine may call numeric release only with
`ReferenceQualification.fingerprints == true`, a recorded fingerprint, and a
complete read begun after both fences closed matching that token's PID and
calendar timestamp. Unqualified or mismatching presence never authorizes
release. Without qualified fingerprints the token remains accounting debt until
qualified absence, a qualified disable observation, or reboot settles it. This
accepted availability residual prevents release based on a reused number alone;
it does not claim timestamp monotonicity or uniqueness. The read-to-release race
is not atomic: concurrent foreign disable/reacquisition can still replace a
holder after the read, and PID/calendar-second fingerprints are not globally
unique identifiers. Accepted residual: -X matches only the number. A foreign
root actor could remove our reference and the kernel could reissue its number
between the fingerprint read and -X, causing our call to drop a foreign
reference. A post-read that loses a foreign fingerprint present before the call
records a safety event; it cannot retrospectively prevent that race.

Each kernel assumption is Unknown, Established or Refuted. Production defaults
are all Unknown: enumeration remains incomplete, EEXIST is Unknown, and both
optional qualifications are false. Only the `qualification` feature exposes a
per-instance override; its variant and native setter are absent in no-feature
builds. A no-feature exhaustive match and negative Darwin compilation checks
pin that exclusion. The protected record format, build match key and
SOURCES_DIGEST remain R11/promotion work. Exact enable rows cover 24H232 and
25G332. CI 45067680869 captured the real acquisition and non-last release rows
on both builds. Only rc 0 with the exact stderr row `disable request successful.
N more pf enable reference(s) remaining, pf still enabled.\n`, after the qualified
ALTQ preamble, acknowledges a request. N is decimal, has no leading zero and
is at least 1; it is never compared with the inventory. The engine settles
Released only after a complete reference read begun after that call and fence
closure shows the owned `(token, pid, timestamp)` fingerprint absent. Missing,
incomplete or contradictory evidence records Unknown and forbids a retry. A
different fingerprint with the same number is another reference; old authority
cannot be reused. The last-reference row is capture-only and always Unknown;
no wording is extrapolated. The old unobserved `Token : N revoked.` rows are
removed. Unknown text/builds remain Unknown. No
TokenInvalid text row is promoted: disabled-pf and stale-value replies cannot
establish safe numeric-release absence against a re-issued holder.

The dedicated pf/pf-x cells require disabled/no-reference preflight and journal
global-state intent before mutation. All adapter tools and churn processes stay
inside a journaled launchd group with AbandonProcessGroup=false; independent
restore stops that group and requires a complete census with no remaining
group members before restoring pf state and checking the preflight snapshot.
Q-EEXIST stops on refutation (OD10). Q-X's enabled-pf stale-value
experiment records recurrence and whether a re-issued holder was released as a
measurement, without promoting an invalid-token rule. Q-FLUSH remains R7.
