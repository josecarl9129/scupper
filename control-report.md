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
