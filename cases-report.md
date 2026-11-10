# M2 leak cases

## Inventory (code reviewed before changes)

| DESIGN row | Existing implementation and assertions | Supervision before this task |
|---|---|---|
| L1 | `baseline`: provider-NAT TCP/UDP receipts and strict uplink allow-list; not a named M2 trial | No |
| L2 | No gateway-local reply/service isolation trial | Missing |
| L3 | `daemon-L3`: established TCP/UDP, WAN exit drop, stale handshake → check 4, recovery | Yes |
| L4 | `daemon-L4`: delete owned exit, remote sender and dead NAT flows, recreate/restart | Yes |
| L5 | No host rule/route flush trial | Missing |
| L6 | `daemon-L6`: remove namespace default, check 3, watchdog/tick and route repair events | Yes |
| L7 | `daemon-L7`: flush namespace nft, measured closure ≤2s, exact restore/conntrack event | Yes |
| L8 | No hostile host nft/dup trial | Missing |
| L9/L9b | `boot_kill`: kill real boot at fresh/live prefixes, forwarding/rules checks, canaries and retry | No |
| L10 | `daemon-L10`: SIGKILL/SIGSTOP, traffic continuity, check 5, restart | Yes |
| L11 | No second client or provider port isolation trial | Missing |
| L12 | No IPv4 WireGuard/antispoof two-stage forgery trial | Missing |
| L13 | `daemon-L13`: foreign veth and tc redirect, check 2, measured detection window | Yes |
| L14 | `daemon-L14`: disconnect/reboot/connect and effective closure; also `L14-boot` | Yes (daemon variant) |
| L15 | No fake exit-IP target returning an uplink address | Missing |
| L16 | `daemon-L16`: single-exit loss and autonomous recovery with checks 4/0 | Yes |
| L17 | `daemon-L17-V14`: held namespace re-mount/inode/traffic; `boot_kill` covers no-holder rebuild | Partial |
| L18 | `boot_inheritance`/`boot_sysctls`: hostile inherited host sysctls; `daemon-V03` verifies toggle reapplication | Partial |
| L19 | Mutation/bridged meta suite reserved for part 2 (existing bridge controls retained) | Deferred |
| L20 | No bidirectional MTU/PMTU trial | Missing |

Additional existing supervised cases: L43 quarantine budget/latch across restart/reboot;
L44 writer contention and ordered control mutations; L50 persisted disconnect crash;
L52/L52b extra IPv4/IPv6 routes. Existing auxiliary cases include check-v2 stage
faults, unprivileged probe confinement, IPv6 drop and bridge/uplink leak controls.

## Completed items

1. Inventoried each M2 row against implementation and assertions (above).
2. Added supervised `daemon-L1`, `L2`, `L5`, `L8`, `L11`, `L12`, `L15`, `L20`.
   Every trial has hard deadlines, required-supervisor checks and provider-NAT
   service controls before/after, strict uplink classification, capture loss
   checks and saved diagnostics. L2 includes a real DNS question. L11 uses live
   listeners, loopback controls, ingress scan manifests and destination captures.
   L12 requires both WireGuard rejection and traced antispoof drops, plus a fresh
   `PeerDiffers` check with exit 2. L15 checks a real local HTTPS response changing
   from healthy to the host uplink address and back. L20 checks v4/v6, both
   directions, exact quoted tuples, advertised MTU and absence at the receiver.
3. Added a separate `client2` underlay, WireGuard identity and 10.99.0.3/32 peer.
   Its configuration is assembled at runtime to preserve shared single-peer
   fake-kernel fixtures. Its transport pair is allow-listed on the uplink without
   making idle-client traffic mandatory in unrelated cases.
4. Added supervised `daemon-L9`, `L9b`, `L9-host-link`, `L17-rebuild`, `L18`.
   The real daemon executes boot and is SIGKILLed at each boot checkpoint; fresh
   daemons verify service before each crash and rebuild/adopt after it. No-holder
   namespace loss and sysctl inheritance/toggle reapplication are separate trials.
   Existing L3/L4/L6/L7/L10/L13/L14/L16/L17-V14/L43/L44/L50/L52/L52b/V03 are retained.
5. Added case-level selection, stable id tie-breaking and duration balancing,
   root-free `--list` and `--shard I/N`. Tests cover deterministic assignment,
   input-order independence, completeness, disjointness, balance, invalid shards
   and actual CLI listing without topology/artifact creation.
6. Added decrypted-path oracle regressions: missing gateway replies, wrong
   interface, unexpected service replies, blind isolation controls, forbidden
   delivery, v4/v6 PMTU wrong sender/router/type/code/MTU/quoted address/ports,
   missing errors, and rejection of plaintext PMTU evidence on the uplink.
7. Each daemon guard restores applied configuration, MTUs, peer AllowedIPs,
   optional v6 addresses, fault nft tables and host sysctls. Failed restoration
   skips later trials with a cause. Setup failures fill every selected case row.
   Final teardown reruns preflight to verify owned names/accounts/paths are gone.
   Top-level results use passed/failed/skipped, elapsed_ms and diagnostic causes.
8. CI uses four shards with fail-fast disabled, 35-minute job and 30-minute lab
   timeouts, per-shard artifacts, ubuntu-24.04 on lab/** and both existing runners
   elsewhere. Each shard owns its topology and teardown.

## Sharding layout

Generated from `xtask leaktest --list`; all durations below are estimates in
seconds, including the known 3–4 minute L3/L16 windows. Each shard reserves another
300 seconds for setup/fixtures. Individual cases retain hard deadlines (including
extra recovery allowance); cleanup has its own bounded deadline. Unsharded runs
select all cases and derive a larger whole-run budget from the same catalog.

| Shard | Expected cases | Cases + setup | Case layout (expected seconds) |
|---|---:|---:|---|
| 1/4 | 9 | 900s + 300s = 20.0 min | `daemon-L5` (60), `daemon-L9` (360), `daemon-L11` (120), `daemon-L17-rebuild` (60), `daemon-L7` (60), `daemon-L13` (60), `client-v6-dropped` (60), `bridged-real-ruleset` (60), `positive-control-uplink` (60) |
| 2/4 | 9 | 900s + 300s = 20.0 min | `daemon-L1` (60), `daemon-L8` (60), `daemon-L9b` (270), `daemon-L18` (60), `daemon-L20` (120), `daemon-L52` (60), `daemon-L14` (60), `daemon-L43` (150), `probe-child` (60) |
| 3/4 | 8 | 840s + 300s = 19.0 min | `daemon-L2` (60), `daemon-L15` (60), `daemon-L16` (240), `daemon-L52b` (60), `daemon-V03` (60), `daemon-L10` (60), `daemon-L44` (180), `daemon-L9-host-link` (120) |
| 4/4 | 9 | 840s + 300s = 19.0 min | `daemon-L12` (60), `daemon-L6` (60), `daemon-L17-V14` (60), `daemon-L3` (240), `daemon-L4` (60), `daemon-L50` (180), `baseline` (60), `check-v2` (60), `positive-control-permissive` (60) |

The maximum estimate remains below 25 minutes. Last-green results.tsv artifacts
were unavailable in the worktree, so these are conservative estimates rather
than claimed measurements; new results preserve elapsed_ms for future tuning.

## Deviations

- L2/L11 use the M2 service policy: client echo allowed, gateway DNS/API queries
  denied. DESIGN §5.2 defers listeners on 53/7380 to M4. L11 installs real test
  listeners behind this policy and verifies them via loopback before scanning.
- L5 records networkd restart as inapplicable: the isolated `gwhost` namespace
  has no systemd/networkd instance. It preserves connected kernel routes and
  the host default (removing those would be L46).
- L20 adds a temporary v6 tunnel path and widens only the renderer's empty
  client_nets6/exit_ifaces_v6 sets while scupperd is stopped for injection;
  it resumes after restoring exact M2 state. M2's validator rejects v6 config.
  IPv4 uses the same bounded fault window. Real checks are 0 before/after.
- L9 prefixes are independent simulated boots. Lab-private boot-attempt budgets
  are saved/reset so previous prefixes cannot consume the next trial's retry
  budget; production retry limits are exercised unchanged within each trial.
- L15 adds a testing-feature-only extra CA root (normal TLS name/signature
  checks stay enabled). Certificates/keys are generated per run, kept private,
  and removed at teardown; only public observations are saved as artifacts.
- Last-green results.tsv artifacts were unavailable in the worktree. Durations
  are explicit conservative estimates (L3/L16 240s), not claimed measurements.

L19 remains part 2 as requested. Namespace lab execution is unavailable locally.

## Verification

All required gates passed, each with `timeout 600`:

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`
- `cargo test --workspace --all-features --locked`
- `RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps --locked`
- `cargo deny check` (advisories, bans, licenses and sources all OK)

Workspace tests used `CARGO_TARGET_TMPDIR` under this worktree's `target/tmp`.
The final PMTU tests require observing the oversized datagram as well as the
correct return error and reject unrelated informational ICMP too. Targeted xtask
and actual `--list` CLI tests passed. `git diff --check` passed. Build/test logs
remain under `target/`. `cargo fmt --all` was run last.

Namespace lab cases were not executed locally, as requested; CI must validate
kernel behavior and replace duration estimates with measured results. No commit
was created.
