# M2-2r external heartbeat

Implementation and required verification complete. No commits or new third-party packages.

1. **Pure core:** deterministic monotonic decision function with complete/fresh-check gating, interval throttling by attempts, healthy-only reporting, status suffixes `/0`–`/4`, rejection of code 5, and deadline fixed at verdict time +30 seconds. Table and property tests cover all branches.
2. **Delivery child:** hidden `scupper deliver heartbeat`; URL and absolute CLOCK_MONOTONIC nanoseconds travel only on stdin. Uses HTTPS **GET**, the existing rustls/webpki client and its hostname/443/IPv4 target support, without redirects. The parent resolves the dedicated `scupper-alert` uid/gid and applies them at exec in the host namespace. Child core dumps are disabled and no-new-privileges is set. Resolver waits, connection, TLS and reads are bounded; expiry is checked before connect and before GET. Parent uses bounded nonblocking stdin, kill/reap and output limits. URL-bearing types format as redacted; errors/events contain closed reasons only. Child statuses: 0 = delivered 2xx, 20 = HTTP non-2xx, 21 = timeout/deadline, 22 = internal/protocol/transport failure.
3. **Daemon:** fresh staged checks and delivery waits run outside the watchdog loop. Only completed scheduler work can consume a fresh verdict and start delivery. A check exceeding its own 20-second budget is ineligible, including after SIGSTOP/resume. Configuration/namespace generations are checked. Failed jobs retry once within the original deadline, then emit the existing `HeartbeatFailed` event and warning. Status exposes monotonic age of the last successful delivery.
4. **Secret references:** reuse confined SecretFile reads under `/etc/scupper/secrets/url/<ref>`: root ownership, 0600 regular file, 0700 secret directories, no symlinks, bounded contents and HTTPS validation. Config validation rejects URL literals as refs. Missing/unreadable/unsafe/invalid refs produce a typed heartbeat-secret failure without crashing; no URL is copied to argv, environment, errors or events.
5. **Lab:** added sharded L53 and heartbeat cases, and extended L10. The TCP-only sink observes ClientHello without a TLS test CA. The oracle allows only the configured HTTPS destination and host uplink source. L53 verifies an actual host-namespace child survives daemon death during a delayed uplink and rejects ClientHello timestamps beyond the original deadline. L10 checks incomplete/stopped/killed daemon silence and resumed heartbeats. Healthy controls, failing `ok_only`, status `/0` and `/4`, and rejection of `/5` are checked with wire observations and a test-only suffix/deadline trace. Core tests cover every status 0–4.

The four existing shards remain. New mandatory deadline waits require a 30-minute tested shard allowance, including 300 seconds setup slack; the whole-lab deadline increased from 1600 to 1900 seconds. Maximum estimated case work is 1320 seconds (27 minutes with setup). Existing CI outer limits already cover this.

## Verification

Passed, each under `timeout 600`:

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`
- `cargo clippy --workspace --all-targets --locked -- -D warnings`
- `cargo test --workspace --all-features --locked`
- `RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps --locked`
- `cargo deny check`

The final full workspace run passed with the bounded resolver and suspension guards. Coverage includes real hidden-child stdin/expiry, deadline guards before connect and after handshake, blocked resolution, redaction properties, secret ownership/modes, bounded pipe/group timeout, retry-then-event, last-success status, FakeKernel scheduler gating, endpoint-only oracle and shard-budget checks. Tests use `env!("CARGO_TARGET_TMPDIR")`. The only dependency-list change reuses the workspace's existing proptest package.

Privileged namespace cases could not execute here: uid 1000; ip, nft, tc and tcpdump are unavailable. The cases compile and their oracle/shard tests run in the workspace suite.

Read DESIGN sections 4/5, 12/13, L10/L53 and ADRs 0018/0025. `dev/design/M2-plan.md` is absent; the brief supplies Q5/Q8. No real heartbeat endpoints were used. Final operation after verification: `timeout 600 cargo fmt --all`.
