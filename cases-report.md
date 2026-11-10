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
   fake-kernel fixtures. Its transport pair is allow-listed only during L11, with both peers
   required to show increasing receive/transmit counters in that trial.
4. Added supervised `daemon-L9`, `L9b`, `L9-host-link`, `L17-rebuild`, `L18`.
   The real daemon executes boot and is SIGKILLed at each boot checkpoint; fresh
   daemons verify one initial service control and rebuild/adopt after every crash. No-holder
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
8. CI uses four shards with fail-fast disabled, 100-minute job and 60-minute lab
   timeouts, per-shard artifacts, ubuntu-24.04 on lab/** and both existing runners
   elsewhere. Each shard owns its topology and teardown.

## Sharding layout

`xtask leaktest --list` is the authoritative four-shard layout. L9 now
estimates 900 seconds for both CLI and daemon fresh prefixes, L9b 720 seconds
for both live prefix sets, and L9-host-link 240 seconds. The unit test checks
that each default shard's estimated cases plus 300 seconds remain ≤25 minutes.
Whole-run deadlines reserve twice the selected duration plus 600 seconds;
individual hard case deadlines remain independent. CI allows 3600 seconds for
the lab and 100 minutes for installation, both builds and artifact handling.

`--durations <shared-results.tsv>` balances using successful previous rows,
including the old elapsed_ms-in-detail format. All shards must use the same
input. `xtask/lab/results.tsv` is read automatically when present. Recorded
cases receive 25% plus five seconds of scheduling allowance. Failed/skipped
rows cannot replace estimates with the time at which a trial aborted. New
results have a dedicated elapsed_ms column and retain measurement details.

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
  IPv4 remains supervised through both MTU faults and subsequent ticks/checks.
  IPv6 is labeled "renderer chain property, unsupervised" in the case detail.
- L9 prefixes are independent simulated boots. Lab-private boot-attempt budgets
  are saved/reset so previous prefixes cannot consume the next trial's retry
  budget; production retry limits are exercised unchanged within each trial.
- L15 adds a testing-feature-only extra CA root (normal TLS name/signature
  checks stay enabled). Certificates/keys are generated per run, kept private,
  and removed at teardown; only public observations are saved as artifacts.
- Last-green results.tsv artifacts were unavailable in the worktree. Durations
  are explicit conservative estimates (L3/L16 240s), not claimed measurements.

L19 remains part 2 as requested. Namespace lab execution is unavailable locally.

## Verification before Fix round 1

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

## Fix round 1

| Item | Change | Case / test / evidence |
|---|---|---|
| H1 | Restore a catalogued supervised L14-boot; check both exit and verdict reason; save/require both unreachable defaults and exit-down after every administrative closure, including reboot/restart. | daemon-L14, daemon-L14-boot, L43, L44, L50; closed-for-wrong-reason unit regression |
| H2 | Guarded init_net injection with complete IPv4 conf restoration (ip_forward changes other knobs); create an independent namespace from gwhost and require hostile values before real boot. | L18-pre-boot.json; daemon-L18 hardening readback; restore on normal/error cleanup |
| H3 | Flush a verified sentinel; install ip and inet dup on all five hooks, permissive forwarding and client/exit masquerade; require forwarding=1 and nonzero WireGuard-UDP counters on ingress/input/output/postrouting. | daemon-L8; L8-host-ruleset.json; strict uplink oracle includes ciphertext copies |
| H4 / M4 | Kill both real scupper boot CLI and daemon boot at every prefix; fsync exact reached-point evidence before SIGKILL; check expected namespace existence and closed prefix before supervised recovery. | L9, L9b, L9-host-link; checkpoint persistence test; per-prefix reached.txt and path captures |
| M1 | Restore host RPDB before boot, rebuild before namespace-dependent network reset; audit host routing rules in the clean baseline. | DaemonGuard cleanup; L5 interrupted-flush recovery; missing namespace recovery |
| M2 | Route provider traffic to client subnet; TCP/UDP probes to gateway/client addresses; client isolation in both directions; capture protected destinations. | daemon-L11 scan manifest, wg0/exit/client/client2 captures |
| M3 / Low L10 | Allow client2 only in L11 and its deliberate capture control; require both clients' rx/tx transfer growth during L11. | exact endpoint policy unit test; L11-transfers.json |
| M5 / Low L5 | Keep the supervisor process/scheduler alive during namespace loss. A testing-only release checkpoint closes forwarding and relinquishes retained holders before deletion; require no remaining holders, ongoing gap canaries, next-tick rebuild, recovered Boot event and a fresh namespace-local alias marker. Do not require a different recyclable inode. | daemon-L17-rebuild; gap/events/identity artifacts; existing held-namespace L17-V14 retained |
| M6 | Remove duplicated before-recovery; expand crash budgets for both executables; use a shared recorded-duration input and generous whole-run margin. | shard duration-ingestion/determinism/balance tests; --list |
| M7 / reviewer 2 item 1 | Keep IPv4 PMTU faults supervised, require a completed tick and check 0; isolate and label unsupported IPv6 fixture. | daemon-L20 per-family artifacts and row detail |
| M8 | Return the selected trial observation to the result row, including L7's I7 and L13's detection/packet windows. | results.tsv elapsed_ms and detail |
| Reviewer 2 item 2 | Reject oversized receiver delivery using the receiver's NAT-adjusted flow in both families (including first fragments), in addition to requiring correct sender PMTU errors and rejecting receiver ICMP. | IPv4/IPv6 PMTU negative oracle regressions |
| Lab: blind captures | Use immediate, packet-buffered capture; drain before graceful INT and wait/reap before reading statistics/pcap; explicitly diagnose received>0/captured=0. | capture shutdown-statistics regression; L1/L9/L9b/host-link and L12 reuse lifecycle |
| Lab: L17 cascade / L18 | Restore missing namespace in the correct order, avoid inode reuse failures, restore init_net before continuing, and force a fresh client handshake after rebuild. | guarded cleanup; L17-rebuild/L18 |
| Lab: L12 | Retain sender ingress/drop evidence and add a gateway underlay capture of the forged-size WireGuard data message plus peer receive growth with an authenticated echo control. | L12-cipher-ingress.pcap; L12-wireguard-rx.json |
| Lab: permissive control | Explicitly configure bridge IPv6 forwarding and sink return routes, cleaning them afterwards; retain literal v6 delivery and output-marker assertions. Kernel rerun still required. | positive-control-permissive; bridge captures/route diagnostics |
| Lab: shard summary | Move setup and nested checkpoint observations to setup-results.json; results.tsv lists catalogued case outcomes only. | result serialization/setup partition tests |
| Low L1 | Require injected pref-100 rule and route to be absent after flush; record networkd/udev as unavailable in gwhost for L5 and L9. | daemon-L5 readback; L9 deviation below |
| Low L2 / L3 | Add query and full raw-datagram markers to uplink canary matching; require all gateway-local queries at wg0. Preserve original uplink minimum-packet and expected-class checks. | daemon-L2/L11/L12/L20; path::attempted |
| Low L4 | Require physical receive evidence and authenticated gateway peer rx growth alongside the forged-source drop. | daemon-L12 |
| Low L6 | Reject unknown daemon case selections. | daemon_case selection validation |
| Low L7 / L8 | Check default list against the CI matrix/count; extend job/lab timeouts with installation/build allowance. | ci_matrix_covers_the_default_list_exactly |
| Low L9 | Build release CLI/daemon without testing and assert env-driven/crash/release-checkpoint strings absent; apply the same assertion to musl release artifacts. | production and musl CI jobs; local release verification below |

L9 simulates independent boots in a disposable namespace; gwhost has no udev
or networkd service to observe them. L17's release checkpoint exists only in
testing builds so the live supervisor can exercise a loss with no retained
holder; it does not restart the process. Temporary lab data is under
CARGO_TARGET_TMPDIR; short descriptor-based notification addresses avoid Unix
socket path-length limits in long worktree paths.

Fix-round verification passed (each gate used `timeout 600`):

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`
- `cargo test --workspace --all-features --locked`
- `RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps --locked`
- `cargo deny check`

The final PMTU/NAT and recorded-duration changes were also verified with
`timeout 600 cargo test -p xtask --all-features --locked`: 49 library tests
passed, plus the oracle, probe, flow and two root-free shard CLI tests.
The boot checkpoint persistence regression passed in the workspace suite.
`timeout 600 cargo build -p scupper -p scupperd --release --locked` passed;
both native binaries were checked for absence of testing hook strings.
Musl artifact checks are configured in CI and were not run locally.
`git diff --check` passed. Logs are under `target/tmp/`; all temporary test
paths used CARGO_TARGET_TMPDIR. `cargo fmt --all` was run last. No commit.

Privileged namespace trials cannot run in this unprivileged worktree environment;
no kernel/lab pass is claimed here. The appended first-run artifacts were used
as read-only diagnostics; the IPv6 permissive-control correction still needs
a fresh kernel run, alongside the other restored and strengthened lab cases.
