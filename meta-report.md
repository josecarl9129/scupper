# M2-2q part 2: L19 meta-tests

## Mutations and expected catches

`lab-mutation` propagates through core, sys, CLI, daemon and xtask. Only feature-enabled code reads `SCUPPER_LAB_MUTATION`; builds without debug assertions reject the feature. Production rendering and checking retain their existing behavior without it.

| Mutation | Historical change | L19 subtrial | Required catch |
| --- | --- | --- | --- |
| M-src | Bug-1 symptom oracle control (lab layout), not product code | L2-provenance | GatewayLocalOnExit: decoded gateway echo reply takes the exit |
| M-ct | Forward established/related accept loses its direction constraints | L3-established-bridge | ForbiddenAddress on the foreign path, with the established canary tuple and payload |
| M-out | Output containment chain is omitted | L4-local-output-bridge | ForbiddenAddress on the foreign path, with the exit-sourced local canary |
| M-probe | Only client-route observations are forged; HTTPS exit probe becomes device-bound | L6-route-stage | RouteStageMissed: Protected with live ingress-unreachable policy and intact main default |

Four golden diffs cover the policy-rule arguments, both nft changes, and the observed/skipped client-route stage plus changed probe binding; default inventory stays observed. Unit tests cover correct catch, all-pass, wrong reason/case, harness failure, and restoration/finalization failure. Default-feature CLI tests reject mutation selection even with the environment set.

`xtask leaktest --mutation M-* --artifacts <directory>` runs a separate unmutated L19 control, then the selected mutant subtrial. A catch is published only after trial restoration, baseline verification, global cleanup and artifact finalization succeed. Reports record the mutation, selected L19 case, named subtrial and violation; raw captures, oracle reports, route readbacks and check JSON remain available. Existing artifact directories are refused to prevent stale catches. L6 independently verifies that the real bound HTTPS probe succeeds with the ingress policy fault live.

## Bridged topology and catalog

The existing `bridged-real-ruleset` already supplies L19b: preferred IPv4/IPv6 routes through a namespace-to-wan veth bypass routing isolation. Route lookups, ARP and both echo exchanges prove path liveness. Client markers and local output remain contained by nft. Existing `positive-control-permissive` uses the same topology and requires client delivery without NAT, proving that the path can leak. `positive-control-uplink` retains its exact injection/reason checks.

L19 additionally exercises established forwarding and exit-sourced local output over a preferred veth path. L19 is now included in the case catalog and DESIGN completeness test, including the legacy-case count assertion.

## CI

The `mutations` job has four mutation matrix entries, Ubuntu 24.04 on lab/** branches and both 24.04/22.04 on main and pull requests, matching leaktest. It uses debug lab binaries, `fail-fast: false`, a cached build and 40-minute job limit, and separate artifacts per runner/mutation. Both release-binary marker greps include the mutation selector. No dependencies were added.

## Deviations

R1 has no production client policy rule. M-src therefore replays the historical layout in lab-only policy table 191: correct `iif wg0` in the control, `from 10.99.0.0/24` under mutation. L19 contains focused extensions of L2/L3/L4/L6; its L3/L4 subtrials deliberately bypass topology isolation so nft faults are observable. The L3 extension uses a bidirectional established UDP flow; the original long-lived TCP daemon-L3 remains in the normal suite. The preinstalled ingress policy fault is caught by topology inventory, as the fake-system regression test proves. An xtask-only System wrapper instead injects the fault at the first forwarding read, after topology/default inventory; all collected observations are real. This tests policy drift between stages. Only the feature-selected M-probe forges client-route results. These deviations are recorded in DESIGN.

## Verification

The original implementation passed these commands. Fix round 1 verification is recorded below; each gate is wrapped in `timeout 600`:

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`
- `cargo test --workspace --all-features --locked`
- `RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps --locked`
- `cargo deny check`

Also passed: default-feature mutation CLI tests (including an environment-selected mutation being rejected), the intended release-feature compile rejection, and `git diff --check`. The full suite verifies all four goldens, strict inversion/finalization behavior, and catalog completeness including L19. Final `cargo fmt --all` is run after the checks.

The first suite run exposed the old eight-case assertion, which was updated for L19. A subsequent cold build/test run reached its 600-second timeout during existing long-running tests without reporting a test failure. Prebuilding the final test binaries completed in 3m 37s; the subsequent complete required test command passed within its own 600-second timeout. The final fixture suppresses incidental multicast consistently with the existing bridge fixture; observation copying occurs only for selected M-probe runs.

Privileged lab cases and actual mutation catches could not run locally. CI executes them with the self-checking controls and diagnostics above. No commit was created.

## Fix round 1

- B1 → M-probe now forges routes only. The xtask-only wrapper injects live `iif wg0 unreachable` policy after topology/default inventory; main default remains intact, the control requires client IPv4 `RouteWrong(Unreachable)` / exit 3, and the mutant requires Protected / exit 0. Live policy, default readback, independent real forwarded lookup and bound HTTPS probe are required. Tests: earlier policy rejection fake test, real-driver subprocess pair and route-stage golden passed in the workspace run. Privileged L19 remains for CI.
- M2 → live nft JSON is compared to an independently parsed control plus exactly the reviewed golden diff; policy fixture readback and observed packet/check evidence accompany catches. Tests: golden patch exactness and inversion rejection without evidence passed in focused tests; workspace assertions and all five final focused mutation tests passed. Live policy comparison normalizes numeric table spelling, split src/srclen prefixes and implicit origin metadata while retaining every packet selector; extra/unknown selector regression tests passed.
- M3 → stop errors are collected and every cleanup action runs; bridge restoration flushes conntrack and resets sysctls. Meta now also reaches the shared rules/conntrack/sysctl restoration; its early return previously skipped it. Test: cleanup continuation/error aggregation and typed-catch invalidation passed.
- M4 → L4 requires EPERM in the control and delivery in M-out; L3 requires a live fwd_dropped increase; gateway oracle requires the exact gateway source. Test: renderer/runtime checks passed; live EPERM/drop-counter acceptances require privileged CI.
- M1 → moved policy fixture to xtask; M-src is the bug-1 symptom oracle control (lab layout), not a product mutation. Added product route argument and boot trace invariants. Tests: policy golden, renderer checks and the boot trace invariant passed in the workspace run.
- M5 → production CI runs default xtask and scupper integration fencing plus the release-feature rejection. Tests: default xtask/scupper CLI subprocesses and default-engine route verdicts passed; release-feature build failed with the intended debug-only diagnostic.
- M6 → DESIGN explains R1 isolation and L19-only bug-2/3 detection; catalog test requires L19 in regular shards. Test: catalog completeness and regular-shard detector assertion passed.
- M7 → subprocess tests exercise the real CLI renderer, staged driver and bound-probe hook. Tests: default and feature scupper rules subprocesses and feature real-driver/binding subprocesses passed. Default-engine subprocesses additionally require the unchanged RouteWrong verdict under M-ct/M-probe; production CI runs them explicitly.
- M8/M9 → cached mutation builds and increased job budget; both artifact destinations are refused before running controls. Tests: default CLI and git diff checks passed; feature stale-artifact test passed sequentially.

Fix-round gate status: format check, final strict clippy, strict rustdoc and cargo-deny passed under `timeout 600`. Default CLI and engine subprocess checks passed; release-feature rejection matched its intended compile diagnostic. The sequential complete all-feature workspace run passed; the five focused mutation tests also passed after the final policy-format normalization change. Privileged namespace runs are unavailable locally (`ip`/`nft` absent); no live catch is claimed from local execution.

The first all-feature run passed the new golden, runtime-hook, boot, cleanup and inversion tests. Its late xtask integration test found a default-feature executable because a concurrent default-feature cargo test replaced `target/debug/xtask`. The sequential feature CLI test and complete workspace gate then passed. Default and feature CLI checks must remain serialized when sharing one target directory.

Final verification for Fix round 1:

- `timeout 600 cargo fmt --all -- --check` — passed.
- `timeout 600 cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` — passed.
- `timeout 600 cargo test --workspace --all-features --locked` — passed sequentially; final focused mutation tests also passed (5 tests).
- `RUSTDOCFLAGS='-D warnings' timeout 600 cargo doc --workspace --no-deps --locked` — passed.
- `timeout 600 cargo deny check` — passed.
- Default scupper/xtask CLI integration tests and default-engine M-ct/M-probe subprocess checks — passed, under `timeout 600`.
- Release plus lab-mutation — rejected with the intended debug-only compile diagnostic, under `timeout 600`.
- CI YAML parsing and `git diff --check` — passed.

Final `cargo fmt --all` runs after these checks. No commit is created. Live namespace fault catches and nft counter/EPERM acceptances remain for privileged CI; local fake-system and subprocess results do not claim those live outcomes.

## Fix round 2

- Lab run 1: the saved L19-L4 lookup already selected `lab-bridge`, but the UDP sender forced every explicit source onto `wg0`. Device binding now applies only to scoped IPv6 link-local sources; the exit-sourced IPv4 canary follows the preferred bridge route. L3/L4 assert and save UDP route lookups before measurement. ENOKEY remains a harness error and now identifies the WireGuard route/device mismatch. Added a real source-bound UDP echo regression and ENOKEY classification checks.
- L3: nft counter reads now surround both send-count reads. Window arithmetic has boundary, delayed-counter and saturation coverage; drop artifacts record sends, drops and the required count.
- N1: both exit-status-only subprocess parents now require fresh completion sentinels written after the child assertions, under `env!("CARGO_TARGET_TMPDIR")`.
- N6: control and mutant subprocesses each receive a separate 600-second timeout; the matrix shares one build-cache key. Release rejection requires exit 101 and the exact debug-only compile diagnostic.
- DESIGN §17 states the during-check limit of M-probe: R1 inventories detect steady-state policy/route drift first.
- N7/N8: the boot guard accepts only exact IPv4/IPv6 rule-inventory commands and requires both families. The L19 control and subprocess control already assert the client address and `got = Unreachable` exactly; those assertions are retained.

Final verification for Fix round 2:

- `timeout 600 cargo fmt --all -- --check` — passed.
- `timeout 600 cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` — passed.
- `timeout 600 cargo test --workspace --all-features --locked` — passed, including the UDP source-binding regression, ENOKEY classification, window arithmetic, both rule inventories and feature subprocess sentinels.
- `RUSTDOCFLAGS='-D warnings' timeout 600 cargo doc --workspace --no-deps --locked` — passed.
- `timeout 600 cargo deny check` — passed.
- Default-feature core `verdict_v2` / `default_build`, xtask mutation integration and scupper mutation integration tests — passed sequentially, each under `timeout 600`; the default-engine sentinels and exact RouteWrong assertions passed.
- Release-feature rejection — passed under `timeout 600`, requiring exit 101 and `error: lab-mutation is restricted to debug lab builds`.
- CI YAML, all workflow shell scripts, the matrix-independent cache key and `git diff --check` — passed.

Final `timeout 600 cargo fmt --all` runs last. No commit is created. Privileged lab execution is unavailable locally (`ip`/`nft` absent); the supplied 24.04 failure artifacts were inspected, but no live containment or mutation catch is claimed.
