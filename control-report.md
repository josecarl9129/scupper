# Control plane review

## Fix round 1

- H1 → supervised checks use the real completed-iteration age (missing means Dead); Ping carries the held namespace identity. Tests: `supervised_check_uses_real_age_and_held_namespace`, `stage_eight_socket_age_table_uses_the_strict_thirty_second_boundary`, `socket_check_with_stale_age_returns_five` (the age table also checks wrong inode).
- H2 → added lifetime supervisor lease before socket binding; fallback only on missing/refused socket and successful lease acquisition; local initialization, intent, planner, apply and repair retain one writer capability. Tests: `live_supervisor_lease_refuses_fallback_without_changing_state`, `local_mutation_refuses_another_writer_before_loading_or_changing_intent`, `timed_out_ping_with_live_lease_never_runs_local_mutation`.
- H3 → drain up to four control requests on every scheduler iteration, including back-to-back slow ticks. Test: `control_requests_are_serviced_without_scheduler_sleep`.
- R2-P1 → split durable intent from synchronous ticks; pending connect can adopt a newly ready candidate from fresh normal-tick observations during its ten-second deadline (pending dispatcher tracked with M1). Test: `pending_connect_allows_ticks_to_qualify`.
- R2-P2 → local dry-run runs the same fresh planner preview and returns repair and target boot operations separately. Test: `local_dry_run_includes_hardening_repair_preview`.
- M1 → fresh checks run on independent read-only workers; Connect/Disconnect persist intent then wait asynchronously while ordinary ticks and watchdog notifications continue. Tests: `pending_connect_allows_ticks_to_qualify`, `pending_verification_does_not_wait_for_probe_worker`.
- M2 → accept errors retry with backoff and emit a control-plane drift event; scheduler monitors listener liveness and rebinds a dead listener. Test: `accept_errors_retry_until_shutdown`.
- M3 → bounded operation-aware dedupe rejects mismatched reuse, excludes unexecuted timeout/unavailable outcomes, and labels replays with original observation time; request ids include pid and random bits; client validates result kind. Tests: `dedupe_conflict_timeout_retry_and_capacity`, `dedupe_success_failure_and_ten_minute_expiry`, `generated_request_ids_are_valid_unique_and_bounded`.
- M4 → real apply executes only the full boot, holds one writer capability across head resolution, boot and reinitialization, abandons old probes first, and sends periodic service timeout extensions. Test: `control_commit_and_apply_use_one_writer_and_end_version_changes_in_full_boot`, `apply_extends_service_timeout_and_feeds_watchdog`.
- M5 → verified apply can open despite durable quarantine; quarantine is cleared and LatchCleared emitted only after the opening boot succeeds. Persistence failure re-closes forwarding. Test: `control_apply_keeps_quarantine_on_failure_and_clears_only_after_full_verification`.
- M6 → socket binding runs on a retry worker; bind failure leaves reconciliation running, and lease exclusion remains in force. Test: `bind_failure_does_not_prevent_scheduler_ticks`.
- M7 → SO_PEERCRED is checked on the accept thread before allocating an authorized peer slot or reading request bytes. Test: `unauthorized_peers_are_rejected_without_reading_or_using_slots`.
- M8 → status consistently uses the existing local staged observation renderer, including when the daemon is unavailable or uninitialized; its informational exit code stays zero. Tests: `m2_check_codes_and_json_work_without_a_tty`, `status_with_responsive_uninitialized_socket_keeps_local_schema`.
- L1 → validate a held run-directory fd (root, no group/other writes), bind and set ownership/mode inside a private 0700 staging directory, publish by rename and verify the socket inode. Test: `unsafe_control_directory_is_refused`.
- L2 → distinguish completed reconciliation from bounded scheduler work; rebuild retries feed the watchdog without refreshing last_complete. Test: `rebuild_pending_scheduler_feeds_watchdog_while_retry_is_spaced`.
- L3 → uninitialized supervisors can persist disconnect/connect/repair-clear intent themselves under the writer lock; pending requests still require closure/readiness verification before success. Test: `uninitialized_supervisor_persists_recovery_intent`.
- L4 → invalid exits return InvalidRequest; latched connect returns Quarantined immediately. Test: `connect_rejects_unconfigured_exit_and_quarantine`.
- L5 → RepairStatus returns the actual latch reason; RepairClear carries bounded operator context and stores it durably in state. Tests: `repair_clear_retains_operator_context_and_actual_latch_reason`, protocol argument validation.
- L6 → local startup failures map to Internal; a verified local apply returns success directly without an unrelated reattachment failure. Tests: local lock-refusal regression and full-apply verification tests.
- L7 → head resolution happens under the retained writer lock; repair previews and target boot operations have separate fields and rendering. Tests: `control_commit_and_apply_use_one_writer_and_end_version_changes_in_full_boot`, `local_dry_run_includes_hardening_repair_preview`.
- T1 → L14 requires socket transport and asserts both unreachable defaults and a down exit from the command's immediate snapshot.
- T2 → L44 pauses socket apply until explicit release, refuses a competing local mutation against the held lease, and samples before and after release; every open sample requires check=0.
- T3 → L50 asserts DisconnectNotEffective for intent-only state and exercises the real pending socket disconnect failure and recovery.
- T4 → L10 includes a responsive stale supervisor; L43 requires socket repair-clear transport.
- T5 → added age, lease refusal, pending readiness, read-worker timeout, accept retry, peer admission, dedupe collision/retry/capacity, durable clear and bind-failure scheduler regressions; `admin_check_independently_proves_disconnect` exercises the actual admin check and staged driver.
- T6 → claims now reflect lifetime lease exclusion and one writer capability across each local sequence; unknown delivery refuses fallback. Lab cases are self-checking and require the privileged lab runner; not executed locally.

### Verification

All five gates passed, each invoked under `timeout 600`:

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`
- `cargo test --workspace --all-features --locked`
- `RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps --locked`
- `cargo deny check`

The full test suite includes the delayed-handshake, stale socket check, lease refusal, operation-aware dedupe, unauthorized-peer slot flood, opening-boot failure, and durable repair-context regressions. Test temporary paths were kept inside the worktree for the final gates. `git diff --check` passed.

Lab cases L10, L14, L43, L44 and L50 were updated and compiled, but not run locally. No third-party crates were added. No commit was created.

## Fix round 2

- Decisions / H3 / R2-1 / N3 → Ping is answered directly from a shared iteration snapshot without a writer capability; queue budget is 180 s, response budget 240 s, Ping remains 2 s. Socket Check errors fall back to local observations. Tests: `ping_snapshot_does_not_wait_for_dispatch`, `socket_check_error_uses_local_observations`.
- Decision / R2-2 → supervised workers read the live last-complete instant at evaluation time. Test: `supervised_check_reads_live_completion`.
- N1 → CLI boot retains the supervisor lease for its full lifetime and refuses contention before kernel calls. Test: `boot_refuses_live_supervisor_before_kernel_calls`.
- N2 → startup retries lease contention for 60 s with STATUS notices; unit restarts every 2 s with no start-rate limit and a 90 s startup window. Test: `supervisor_lease_waits_for_release`.
- N4 → apply watchdog feeding stops after a hard 120 s budget. Test: `apply_keepalive_stops_at_budget`.
- N9 decision → schema 1 stays strict and unchanged: free-text repair context is written only to AdminAction audit events, never state.json. Old schema-1 readers can read all newly written safety state; a round-1 file containing the extra field is refused rather than silently discarding safety data. Test: `repair_clear_retains_operator_context_and_actual_latch_reason`, `uninitialized_supervisor_persists_recovery_intent`.
- N5 → apply and reinitialization invalidate workers from the old namespace; pending Checks receive a retryable unavailable response, mutations spawn fresh verification. Test: `dispatcher_pending_across_apply`.
- N6 → same-intent requests attach with independently correlated response ids; only different intent supersedes. Test: `dispatcher_same_intent_and_supersession`.
- N7 → errors before intent persistence are not cached. Test: `dispatcher_expiry_and_unexecuted_retry`.
- N8 → uncertain-delivery diagnostics now advise inspecting status before retrying; no unsupported request-id advice. Test: CLI diagnostics in full suite.
- N10 → local refusal identifies the unavailable control socket and gives `systemctl stop scupperd` as the recovery path; lease contention names scupperd.lock. Test: lease refusal regressions.
- N12 → Ping and RepairStatus avoid writer.lock; explicit versions resolve without reading head; failed applies retain the current attachment and last-complete timestamp. Tests: `read_only_admin_ignores_writer_contention`, `explicit_apply_version_does_not_verify_unrelated_head`.
- Lab L14 → disconnected reboot previously rejected adoption solely because the exit was deliberately down, causing a full rebuild that reset client peers and sessions. Adoption now accepts down exits only for Disconnected intent after all public configuration checks. Stage 4 returns ClientSideBroken/NoHandshake when no client session has ever been established; L14 now runs real service canaries immediately after socket connect. Tests: `disconnected_reboot_preserves_client_sessions`, `clients_without_established_session_are_not_protected`. Saved run-2 evidence: L14-reboot had adopted=false and L14-connected was Protected with ClientHandshakesStale; privileged confirmation still required.
- Lab L43 → each injected incident now waits for reopening, matching the per-class three-reopening/600 s budget. RouteDelete accepts a vanished route only after a successful full-family inventory proves the exact entry absent. Test: `route_delete_requires_observed_absence`; privileged L43 pending.
- T-b / L50 → reconnect and prove healthy routes before the second disconnect, so the closure snapshot tests reply ordering. Lab case compiled; privileged execution pending.
- N11 → persistent accept/bind failures produce at most one audit summary per minute, with accumulated error count. Test: `control_failures_are_counted_once_per_minute`.
- T-a / L44 → sample until apply exits, require an open sample, reject check codes 1/2/3, and require unreachable defaults for code 4; competing boot refuses the retained lease while Ping remains responsive. Lab case compiled; privileged execution pending.
- Lab L10 → notify capture also retries Interrupted reads and survives timeout/STOP/CONT/KILL gaps; test `notify_capture_survives_idle_and_sender_restart` covers idle gaps and replaced senders. Direct lab daemon execution does not exercise systemd watchdog kills; bounded feeder is verified independently.
- Lab isolation → clear the prior event directory only after the preceding stopped daemon's evidence is saved; later cases are explicitly skipped if baseline restoration fails. Lab cases compiled; privileged execution pending.
- T-c → production Runtime now drains through the factored Dispatcher, using an injected intent/worker backend and explicit monotonic time. Tests: `dispatcher_same_intent_and_supersession`, `dispatcher_same_intent_success_correlates_every_id`, `dispatcher_expiry_and_unexecuted_retry`, `dispatcher_pending_across_apply`.
- T-d → bind ownership is injectable only through the private bind implementation. Mode rejection uses the actual test owner; publication, stale-socket removal, live-socket refusal, inode-preserving cleanup and rebind run without root on filesystems supporting socket chmod. This worktree filesystem returns EINVAL for socket chmod, so the local test explicitly proves fail-closed refusal and defers the complete publication branch to supporting CI filesystems. Tests: `unsafe_control_directory_is_refused`, `bind_publication_stale_removal_replacement_and_rebind`.
- T-e → added `boot_refuses_live_supervisor_before_kernel_calls`, `supervisor_lease_waits_for_release` (real three-second contention and bounded timeout), and `apply_keepalive_stops_at_budget` (feeder exits while owner retains the guard).
- Test scratch paths → legacy scratch directories now use CARGO_TARGET_TMPDIR (unit-test fallback target/tmp); CI exports it explicitly. Long socket paths use directory capabilities or a relative path within that root.

### Round 2 verification

All five gates passed, each under `timeout 600`:

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`
- `cargo test --workspace --all-features --locked --no-fail-fast`
- `RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps --locked`
- `cargo deny check`

The full run passed 845 tests, with 8 existing subprocess fixtures ignored. Test scratch directories used CARGO_TARGET_TMPDIR under the worktree. `git diff --check` passed. No third-party crates or commits were added.

Privileged lab cases and real-systemd watchdog fault runs were compiled but not executed locally. L14's session-reset diagnosis is supported by the saved boot trace and the new adoption/verdict regressions; actual canary recovery still needs the privileged lab. The bind test explicitly verifies fail-closed refusal on this filesystem's unsupported socket chmod (EINVAL); its full publication/rebind branch requires a supporting filesystem.

Final scratch-path audit: the CLI harness, probe wiring, namespace restore, lab registry, oracle and lab test helper all use CARGO_TARGET_TMPDIR. The final xtask-only run passed 106 tests after its last scratch-path changes. No crate-local target directories were recreated; all changed files are within the authorized source/CI paths and this report.

## Fix round 3

- F1 decision → stale and Never client handshakes warn only; stages 5–8 still run. Tests: `client_handshakes_stale_is_warning_only`, `clients_without_established_session_do_not_mask_later_stages`.
- F2 decision → full boot preserves configured client peers in place and keeps wg0 up, while removing unknown peers and updating AllowedIPs/keepalive. Test: `full_boot_updates_client_peers_without_resetting_sessions`; lab canary assertions tracked below.
- F3 decision / N12 / T-5 → failed target boot durably restores the previous applied version, emits ApplyFailed, and boots the previous configuration under the same writer guard before reattachment. Failed rollback persistence drops the running attachment and keeps gates closed. Test: `failed_apply_restores_version_without_drift_budget_or_latch_and_restart_boots_previous` (added below).
- F10 / F12 → removed invalidation of the taken dispatcher; publish namespace snapshots immediately after initialization and rebuild. Tests: dispatcher apply regressions and initialization tests.
- T-2 → disconnected adoption now asserts both unreachable defaults, down exits, unchanged forwarding and check=4; an up-exit/foreign-default boot must close routes. Tests: `disconnected_reboot_preserves_client_sessions`, `disconnected_boot_closes_an_up_exit_and_foreign_default`.
- F5 decision → RouteDelete absence compares table/family/destination/type/source/device/gateway/metric identity; flags, preferred source, protocol and scope cannot disguise a surviving route. Test: `route_delete_requires_observed_absence` (includes changed linkdown).
- F6 decision → a boot under a live supervisor lease exits 0 with an explicit namespace-ownership notice, so manual scupper-net restarts succeed without resetting sessions. Filesystem/lease errors still fail. Test: `boot_defers_to_live_supervisor_before_kernel_calls`.
- F10 → explicit bind group avoids reading /etc/group. Test: `bind_publication_stale_removal_replacement_and_rebind`.
- T-1 → unsupported chmod must yield InvalidInput/Unsupported, leave no staging directories, and fails the test if CI is set. Test: `bind_publication_stale_removal_replacement_and_rebind`.
- F11 → lease wait notices fire immediately then at most every five seconds. Tests: `supervisor_lease_waits_for_release`, production startup regression tracked below.
- F9 decision → retain the Ubuntu 22.04-compatible fixed RestartSec=2s backoff; emit DaemonStarted once only after READY so deterministic startup failures do not flood audit history. Tests: daemon scheduler/startup tests and unit golden.
- F4 / F7 / lab L6 → stale or missing Ping completion age skips queued Check and retains Alive/stale for local observations; socket Check has a 60 s deadline and retries SupervisorUnavailable once after fresh Ping. Queued requests from disconnected peers are discarded, and peer slots release promptly on hangup. L6 artifacts show a 15 s external timeout killing the queued check before output; lab Check now allows its 60 s deadline plus local observation margin (90 s). Tests: stale-Ping, retry and abandoned-peer regressions added below; existing JSON/fallback tests.
- F2 / lab L14 / L44 → require adopted=true for the disconnected simulated reboot, observe a client handshake before canaries, apply an exit-only keepalive version, assert the existing client session remains established and immediately deliver service canaries. Privileged execution pending.
- Lab L43 → after clear wait for all forwarding gates (including both defaults and wg0) to read 1 before check=0, then require client delivery; healthy routes alone were already present and did not prove reopening. Forwarding defaults are now classified as gates rather than hardening warnings. Tests: clear/reopen regression and collector tests; privileged lab pending.
- T-4 → L44 additionally queues disconnect during a second paused apply, proves no early reply, releases apply, requires both commands to succeed, then asserts unreachable defaults and check=4 before reconnecting. Privileged execution pending.
- T-6 → L14 now deletes the namespace with the daemon stopped, boots disconnected/check=4, reconnects, and requires an ordinary client handshake and service delivery within 20 s, retaining the uplink capture oracle. Privileged execution pending.
- T-3 / T-5 partial coverage → production run delegates to the same injectable notification entry after parsing its socket address. Test `daemon_run_waits_for_lease_and_sends_status_before_reading_config` holds the real lease, receives STATUS, proves run stays pending without notification flooding, releases it and proves config reading resumes. The supplied 24.04 artifacts skipped L44 and contain no 22.04 READY-timeout evidence, so that historical timeout remains unassigned.
- F4 abandoned calls → `dispatcher_drops_mutation_after_peer_hangup` proves a disconnected queued mutation cannot persist intent.
- F4 / F7 regression tests → `stale_ping_skips_socket_check_and_preserves_stale_supervision` covers None/30/100 s ages with typed JSON/stale verdict; `check_retries_once_after_apply_invalidates_worker` covers Ping → unavailable Check → fresh Ping → successful Check.
- Lab L14 / T-2 evidence → L14-reboot.calls.json completes topology/adoption checks, then reads ip_forward and immediately starts Close. The daemon's effective disconnect had already closed global gates, but adoption demanded forwarding=1. Disconnected adoption now accepts a fully verified closed sysctl set as well as the verified open set, preserving the gate state and client sessions. Test: `disconnected_reboot_preserves_client_sessions` now models the daemon's closed gates.
- F3 rollback failure → `failed_apply_with_undurable_rollback_keeps_forwarding_closed` prevents state publication after the target ruleset step and requires PersistenceUnavailable, both global gates closed and a failed boot handoff.
- L43 recovery verification → `repair_clear_reopens_forwarding_after_quarantined_restart` passes with both global gates, both default gates and wg0 forwarding restored after normal debounce/ticks.
- F4 deadline → the optional Check retry shares the original 60 s deadline rather than extending it.
- F8 scope exception pending → the stated edit scope excludes `docs/DESIGN.md` and `tests/golden/units/scupperd.service`. Those files remain unchanged pending the requested exception. The replacement unit golden and DESIGN changes (unit settings and daemon-owned manual boot behavior) are prepared under `CARGO_TARGET_TMPDIR/round3`; switching the unit test back and deleting the adjacent copy will accompany that exception. Current test: `render::units::tests::m2_goldens` still uses the adjacent copy, so F8 remains open.

### Round 3 verification

All five gates passed, each invoked under `timeout 600`:

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`
- `cargo test --workspace --all-features --locked --no-fail-fast`
- `RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps --locked`
- `cargo deny check`

The final full workspace run passed with no failing targets. The prior broad run exposed a fixture error: its unknown peer reused the configured client's key and overwrote the test's roamed endpoint; the fixture now uses a distinct key. The final run includes the disconnected closed-gate adoption, configured-peer/session retention, rollback/restart, rollback-persistence refusal, stale-Ping/retry, abandoned-client, startup STATUS and quarantine-clear reopening regressions. `git diff --check` and the edit-scope audit passed.

Privileged L10/L14/L43/L44/L50 and real-systemd watchdog runs were compiled but not executed. The supplied read-only artifacts cover 24.04; the historical 22.04 READY timeout cannot be assigned a cause from them. All scratch files are under CARGO_TARGET_TMPDIR in this worktree. No new crates or commits.
