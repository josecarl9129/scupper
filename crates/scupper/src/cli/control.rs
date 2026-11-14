//! CLI control operations and bounded, single-writer local fallback.
use super::{BootNamespaces, Dependencies, output_error, require_root};
use clap::Subcommand;
use scupper_proto::{Op, OpResult, Response, Schema, VerdictCode};
use scupper_sys::daemon::{
    admin,
    control::{self, ClientError},
};
use std::{
    io::Write,
    time::{Duration, Instant},
};

#[derive(Clone, Subcommand)]
pub(super) enum RepairCommand {
    /// Show persisted quarantine.
    Status,
    /// Clear quarantine and reset repair budgets.
    Clear {
        /// Operator context; audit records use the bounded Operator reason.
        #[arg(long)]
        reason: Option<String>,
    },
}

pub(super) fn connect(deps: &Dependencies<'_>, name: Option<String>) -> Result<Op, String> {
    let Some(name) = name else {
        return Ok(Op::Connect { exit: None });
    };
    let config = super::m2_config(deps)?.ok_or("no applied configuration")?;
    let gateway = config
        .site
        .gateway(&config.gateway)
        .ok_or("unknown gateway")?;
    let candidates: Vec<_> = gateway
        .exits()
        .iter()
        .map(|e| (e.id().as_str(), e.name().as_str()))
        .collect();
    let id = match_exit(&name, &candidates, deps.prompt.is_terminal())?;
    Ok(Op::Connect {
        exit: Some(scupper_proto::Identifier::try_from(id).map_err(str::to_owned)?),
    })
}

pub(super) fn match_exit(
    name: &str,
    candidates: &[(&str, &str)],
    tty: bool,
) -> Result<String, String> {
    if name.is_empty() {
        return Err("exit must not be empty".into());
    }
    let name = name.to_lowercase();
    let exact: Vec<_> = candidates
        .iter()
        .filter(|(id, label)| id.to_lowercase() == name || label.to_lowercase() == name)
        .collect();
    let found = if exact.is_empty() && tty {
        candidates
            .iter()
            .filter(|(id, label)| {
                id.to_lowercase().starts_with(&name) || label.to_lowercase().starts_with(&name)
            })
            .collect()
    } else {
        exact
    };
    match found.as_slice() {
        [(id, _)] => Ok((*id).to_owned()),
        [] => Err("no matching exit (without a TTY use an exact id or name)".into()),
        _ => Err(format!(
            "ambiguous exit: {}",
            found
                .iter()
                .map(|(id, label)| format!("{label} [{id}]"))
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}

pub(super) fn repair(
    deps: &Dependencies<'_>,
    command: RepairCommand,
    json: bool,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<u8, String> {
    let op = match command {
        RepairCommand::Status => Op::RepairStatus {},
        RepairCommand::Clear { reason } => {
            if reason
                .as_ref()
                .is_some_and(|text| text.len() > 1024 || text.contains(['\n', '\r']))
            {
                return Err("repair reason must be one line, at most 1024 bytes".into());
            }
            Op::RepairClear { reason }
        }
    };
    mutation(deps, op, json, out, err)
}

pub(super) fn mutation(
    deps: &Dependencies<'_>,
    op: Op,
    json: bool,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<u8, String> {
    require_root(deps, "control operation")?;
    let request = control::request(op.clone());
    let ping = control::call(
        deps.writer_root,
        &control::request(Op::Ping {}),
        Duration::from_secs(2),
    );
    let delivery = match ping {
        Ok(_) => control::call(deps.writer_root, &request, control::RESPONSE_TIMEOUT),
        Err(ClientError::Unavailable(error))
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
            ) =>
        {
            Err(ClientError::Unavailable(error))
        }
        Err(_) => return Err("scupperd is alive but unresponsive".into()),
    };
    let response = match delivery {
        Ok(response) => {
            writeln!(err, "transport: local socket").map_err(output_error)?;
            response
        }
        Err(ClientError::Unavailable(error))
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
            ) =>
        {
            writeln!(err, "transport: local writer").map_err(output_error)?;
            let result = admin::local(
                scupper_sys::boot::BootDeps {
                    system: deps.system,
                    namespace: &BootNamespaces(deps.namespaces),
                    state_root: deps.state_root,
                    config_root: deps.config_root,
                    run_root: deps.writer_root,
                    #[cfg(feature = "testing")]
                    hook: None,
                    #[cfg(feature = "testing")]
                    secret_owner: rustix::process::geteuid().as_raw(),
                },
                deps.probe_exec,
                op,
                0,
            );
            let result = match result {
                Ok(result) => Ok(result),
                Err(admin::LocalError::Api(error)) => Err(error),
                Err(admin::LocalError::Startup(message)) => {
                    writeln!(err, "scupper: {message}").map_err(output_error)?;
                    Err(scupper_proto::ApiError {
                        code: scupper_proto::ApiErrorCode::Internal,
                        observation: None,
                    })
                }
            };
            Response {
                request_id: request.request_id,
                schema: Schema,
                replayed: false,
                observed_at: None,
                result,
            }
        }
        Err(ClientError::Unavailable(_) | ClientError::OutcomeUnknown(_)) => {
            return Err(format!(
                "scupperd is alive but unresponsive; control outcome unknown for {}; inspect scupper status before retrying",
                String::from(request.request_id)
            ));
        }
    };
    render(response, json, out, err)
}

pub(super) enum ReadOutcome {
    Rendered(u8),
    Local(LocalRead),
}

pub(super) struct LocalRead {
    pub supervisor: scupper_core::verdict::v2::Supervisor,
    pub version: Option<u64>,
    // Namespace retries share one allowance for the post-observation Ping.
    transition_deadline: Option<Instant>,
}

// Each fallback phase may spend at most 500 ms beyond the shared Check budget.
const PING_ALLOWANCE: Duration = Duration::from_millis(500);

trait ReadClient {
    fn now(&self) -> Instant;
    fn call(
        &self,
        root: &std::path::Path,
        op: Op,
        deadline: Instant,
    ) -> Result<Response, ClientError>;
}

struct SocketClient;
impl ReadClient for SocketClient {
    fn now(&self) -> Instant {
        Instant::now()
    }
    fn call(
        &self,
        root: &std::path::Path,
        op: Op,
        deadline: Instant,
    ) -> Result<Response, ClientError> {
        control::call_until(root, &control::request(op), deadline)
    }
}

struct PingObservation {
    supervisor: scupper_core::verdict::v2::Supervisor,
    busy_age: Option<u64>,
    operation: Option<scupper_proto::OperationProgress>,
    version: u64,
}
fn ping_supervisor(
    deps: &Dependencies<'_>,
    deadline: Instant,
    client: &impl ReadClient,
) -> Option<PingObservation> {
    use scupper_core::verdict::v2::Supervisor;
    let response = client
        .call(
            deps.writer_root,
            Op::Ping {},
            deadline.min(client.now() + Duration::from_secs(2)),
        )
        .ok()?;
    let Ok(OpResult::Ping {
        last_complete_iteration_age,
        current_iteration_age,
        operation,
        netns,
        version,
        ..
    }) = response.result
    else {
        return None;
    };
    Some(PingObservation {
        supervisor: Supervisor::Alive {
            netns,
            iteration_age: Duration::from_secs(last_complete_iteration_age.unwrap_or(30)),
        },
        busy_age: current_iteration_age,
        operation,
        version,
    })
}

pub(super) fn read(
    deps: &Dependencies<'_>,
    status: bool,
    json: bool,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<ReadOutcome, String> {
    read_with(deps, status, json, out, err, &SocketClient)
}

#[allow(clippy::too_many_lines)] // Keep the shared deadline and target-context fallback in one sequence.
fn read_with(
    deps: &Dependencies<'_>,
    status: bool,
    json: bool,
    out: &mut dyn Write,
    err: &mut dyn Write,
    client: &impl ReadClient,
) -> Result<ReadOutcome, String> {
    use scupper_core::verdict::v2::Supervisor;
    let deadline = client.now() + control::CHECK_TIMEOUT;
    let mut local = |err: &mut dyn Write, supervisor, mut version: Option<u64>| {
        if let Some(operation) =
            version.and_then(|from| version_transition(from, applied_version(deps)))
        {
            if target_context_exists(deps, operation.to) {
                version = Some(operation.to);
            } else {
                return operation_report(&operation, json, out, err);
            }
        }
        writeln!(err, "transport: local observations").map_err(output_error)?;
        Ok(ReadOutcome::Local(LocalRead {
            supervisor,
            version,
            transition_deadline: None,
        }))
    };
    if status {
        return local(err, Supervisor::Dead, None);
    }
    let mut observed = client.now();
    let Some(PingObservation {
        mut supervisor,
        busy_age,
        operation,
        version,
    }) = ping_supervisor(deps, deadline, client)
    else {
        return local(err, Supervisor::Dead, None);
    };
    let mut version = Some(version);
    if let Some(operation) = operation {
        if let Some(current) = operation_context(deps, &operation) {
            // The target is safe to compare only after its verified boot completed.
            return local(err, supervisor, Some(current));
        }
        return operation_report(&operation, json, out, err);
    }
    if busy_age.is_some_and(|age| age >= 5)
        || matches!(supervisor, Supervisor::Alive {iteration_age, ..} if iteration_age >= Duration::from_secs(30))
    {
        return local(err, supervisor, version);
    }
    for attempt in 0..2 {
        let response = client.call(deps.writer_root, Op::Check {}, deadline);
        match response {
            Ok(response) if response.result.is_ok() => {
                writeln!(err, "transport: local socket").map_err(output_error)?;
                return render(response, json, out, err).map(ReadOutcome::Rendered);
            }
            Err(ClientError::OutcomeUnknown(error))
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) =>
            {
                // Only a timed-out Check may retain the preceding Ping's age.
                break;
            }
            other => {
                observed = client.now();
                let fresh = ping_supervisor(deps, observed + PING_ALLOWANCE, client);
                if let Some(PingObservation {
                    operation: Some(operation),
                    ..
                }) = fresh.as_ref()
                {
                    if let Some(current) = operation_context(deps, operation) {
                        return local(
                            err,
                            fresh
                                .as_ref()
                                .map_or(Supervisor::Dead, |ping| ping.supervisor),
                            Some(current),
                        );
                    }
                    return operation_report(operation, json, out, err);
                }
                version = fresh.as_ref().map(|ping| ping.version);
                supervisor = fresh.map_or(Supervisor::Dead, |ping| ping.supervisor);
                let unavailable = matches!(
                    other,
                    Ok(Response {
                        result: Err(scupper_proto::ApiError {
                            code: scupper_proto::ApiErrorCode::SupervisorUnavailable,
                            ..
                        }),
                        ..
                    })
                );
                if attempt != 0
                    || client.now() >= deadline
                    || !unavailable
                    || !matches!(supervisor, Supervisor::Alive {iteration_age, ..} if iteration_age < Duration::from_secs(30))
                {
                    return local(err, supervisor, version);
                }
            }
        }
    }
    let supervisor = match supervisor {
        Supervisor::Alive {
            netns,
            iteration_age,
        } => Supervisor::Alive {
            netns,
            iteration_age: iteration_age + client.now().saturating_duration_since(observed),
        },
        other => other,
    };
    local(err, supervisor, version)
}

pub(super) fn transition_after_observation(
    deps: &Dependencies<'_>,
    version: u64,
    local: &LocalRead,
    json: bool,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<Option<ReadOutcome>, String> {
    let deadline = local
        .transition_deadline
        .unwrap_or_else(|| Instant::now() + PING_ALLOWANCE);
    let ping = ping_supervisor(deps, deadline, &SocketClient);
    let state_version = applied_version(deps);
    if let Some(ping) = ping.as_ref() {
        if let Some(operation) = &ping.operation {
            if let Some(current) = operation_context(deps, operation) {
                return Ok(
                    (version != current).then_some(ReadOutcome::Local(LocalRead {
                        supervisor: ping.supervisor,
                        version: Some(current),
                        transition_deadline: Some(deadline),
                    })),
                );
            }
            return operation_report(operation, json, out, err).map(Some);
        }
        let identity = |supervisor| match supervisor {
            scupper_core::verdict::v2::Supervisor::Alive { netns, .. } => Some(netns),
            _ => None,
        };
        let current = state_version
            .filter(|version| target_context_exists(deps, *version))
            .unwrap_or(ping.version);
        if current != version || identity(ping.supervisor) != identity(local.supervisor) {
            return Ok(Some(ReadOutcome::Local(LocalRead {
                supervisor: ping.supervisor,
                version: Some(current),
                transition_deadline: Some(deadline),
            })));
        }
    }
    if let Some(operation) = version_transition(version, state_version) {
        if target_context_exists(deps, operation.to) {
            return Ok(Some(ReadOutcome::Local(LocalRead {
                supervisor: ping
                    .as_ref()
                    .map_or(local.supervisor, |ping| ping.supervisor),
                version: Some(operation.to),
                transition_deadline: Some(deadline),
            })));
        }
        return operation_report(&operation, json, out, err).map(Some);
    }
    Ok(None)
}

fn operation_context(
    deps: &Dependencies<'_>,
    operation: &scupper_proto::OperationProgress,
) -> Option<u64> {
    (operation.kind == scupper_proto::OperationKind::Apply)
        .then(|| applied_version(deps))
        .flatten()
        .filter(|version| *version == operation.to && target_context_exists(deps, *version))
}

fn target_context_exists(deps: &Dependencies<'_>, version: u64) -> bool {
    let succeeded = (|| -> Option<bool> {
        let report: scupper_sys::boot::BootReport = serde_json::from_str(
            &std::fs::read_to_string(deps.writer_root.join("boot.json")).ok()?,
        )
        .ok()?;
        let namespace = deps.namespaces.open_gateway().ok()??;
        Some(
            report.succeeded()
                && report.applied_version == Some(version)
                && report
                    .netns
                    .is_some_and(|id| namespace.identity() == (id.dev, id.ino)),
        )
    })()
    .unwrap_or(false);
    succeeded
        && scupper_sys::store::VersionStore::read_only(deps.state_root, deps.config_root)
            .read(version)
            .is_ok()
}

fn applied_version(deps: &Dependencies<'_>) -> Option<u64> {
    let scupper_sys::state::StateRead::Present(state) =
        scupper_sys::state::StateFile::open(deps.state_root, None)
            .and_then(|file| file.read())
            .ok()?
    else {
        return None;
    };
    state.applied_version
}
fn version_transition(from: u64, target: Option<u64>) -> Option<scupper_proto::OperationProgress> {
    target
        .filter(|to| *to != from)
        .map(|to| scupper_proto::OperationProgress {
            kind: scupper_proto::OperationKind::Apply,
            from,
            to,
            age: 0,
        })
}

fn operation_report(
    operation: &scupper_proto::OperationProgress,
    json: bool,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<ReadOutcome, String> {
    let message = format!(
        "{} in progress (from {} to {}, {} s)",
        match operation.kind {
            scupper_proto::OperationKind::Apply => "apply",
            scupper_proto::OperationKind::Rebuild => "rebuild",
        },
        operation.from,
        operation.to,
        operation.age
    );
    writeln!(err, "{message}").map_err(output_error)?;
    let report = scupper_core::verdict::v2::Report {
        verdict: scupper_core::verdict::v2::Verdict::Degraded(
            scupper_core::verdict::v2::Degraded::OperationInProgress {
                from: operation.from,
                to: operation.to,
            },
        ),
        warnings: Vec::new(),
        at: unix_seconds(),
        config_version: operation.from,
    };
    if json {
        serde_json::to_writer(&mut *out, &report).map_err(|error| error.to_string())?;
        writeln!(out).map_err(output_error)?;
    } else {
        super::view::check(
            out,
            &serde_json::to_value(&report).map_err(|e| e.to_string())?,
        )?;
    }
    Ok(ReadOutcome::Rendered(3))
}
fn unix_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn render(
    response: Response,
    json: bool,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<u8, String> {
    let code = match &response.result {
        Ok(OpResult::Check { health, .. }) => verdict_code(health.verdict),
        Err(error)
            if error.code == scupper_proto::ApiErrorCode::NotReady
                || error.code == scupper_proto::ApiErrorCode::DisconnectNotEffective =>
        {
            3
        }
        Err(_) => 1,
        _ => 0,
    };
    if response.replayed
        && !json
        && let Ok(OpResult::Check { health, .. }) = &response.result
    {
        let at = response.observed_at.unwrap_or(health.at).0;
        writeln!(err, "(replayed result observed at {at})").map_err(output_error)?;
    }
    if response.replayed && !json && !matches!(response.result, Ok(OpResult::Check { .. })) {
        writeln!(
            out,
            "replayed outcome observed at {:?}: {:?}",
            response.observed_at, response.result
        )
        .map_err(output_error)?;
        return Ok(code);
    }
    if json {
        // Keep check's established full Report wire format for local and socket runs.
        if let Ok(OpResult::Check { report, .. }) = &response.result {
            serde_json::to_writer(&mut *out, report)
        } else {
            serde_json::to_writer(&mut *out, &response)
        }
        .map_err(|e| e.to_string())?;
        writeln!(out).map_err(output_error)?;
    } else {
        match response.result {
            Ok(OpResult::Check { report, .. }) => return super::view::check(out, &report).map(|()| code),
            Ok(OpResult::Disconnect {}) => writeln!(out, "traffic is now blocked"),
            Ok(OpResult::Connect { exit, report }) => {
                if let Some(exit) = exit { writeln!(out, "exit connected via {}; verdict: {}", String::from(exit), report["verdict"]) }
                else { writeln!(out, "exit connected; client session readiness {}; verdict: {}",
                    if report["verdict"]["Degraded"] == "ClientSessionsReset" { "pending" } else { "unknown" }, report["verdict"]) }
            },
            Ok(OpResult::Apply { version, dry_run, repair_plan, plan, warnings }) => {
                for warning in warnings { writeln!(out, "Warning: {warning}").map_err(output_error)?; }
                writeln!(out, "version {version}; dry run: {dry_run}\nPreflight: passed\nRepair preview: {repair_plan:?}\nTarget boot: {plan:?}")
            },
            Ok(result) => writeln!(out, "{result:?}"),
            Err(error) => writeln!(out, "{error}"),
        }
        .map_err(output_error)?;
    }
    Ok(code)
}
fn verdict_code(verdict: VerdictCode) -> u8 {
    match verdict {
        VerdictCode::Protected => 0,
        VerdictCode::ObservationError => 1,
        VerdictCode::Unprotected => 2,
        VerdictCode::Degraded => 3,
        VerdictCode::FailClosed => 4,
        VerdictCode::Unsupervised => 5,
    }
}

#[cfg(all(test, feature = "testing"))]
#[path = "../../../scupper-sys/tests/support/v2.rs"]
mod test_support;

#[cfg(test)]
mod tests {
    use super::*;
    use scupper_core::verdict::v2::{NetnsIdentity, Selection, Supervisor};
    use std::cell::{Cell, RefCell};
    use std::collections::VecDeque;

    #[test]
    #[allow(clippy::unwrap_used)]
    fn socket_check_uses_human_report_and_preserves_verdict_codes() {
        use scupper_core::{
            config::ExitId,
            verdict::v2::{FailClosed, NonEmpty, Report, Verdict, Violation, Warning},
        };
        for verdict in [
            Verdict::Protected {
                exit: ExitId("ch1".into()),
                exit_ip: "37.120.137.232".parse().unwrap(),
            },
            Verdict::Unprotected(NonEmpty::new(Violation::ForeignLink("eth0".into()))),
            Verdict::FailClosed(FailClosed::AdminDisconnected),
        ] {
            let report = Report {
                verdict,
                warnings: vec![Warning::ClockSkew],
                at: 1000,
                config_version: 2,
            };
            for replayed in [false, true] {
                let response = Response {
                    request_id: scupper_proto::Identifier::try_from("test-check".to_owned())
                        .unwrap(),
                    schema: Schema,
                    replayed,
                    observed_at: Some(scupper_proto::UnixSeconds(1001)),
                    result: Ok(OpResult::Check {
                        health: (&report).into(),
                        report: serde_json::to_value(&report).unwrap(),
                    }),
                };
                let mut out = Vec::new();
                let mut err = Vec::new();
                assert_eq!(
                    render(response.clone(), false, &mut out, &mut err).unwrap(),
                    report.verdict.exit_code()
                );
                assert_eq!(
                    String::from_utf8(err).unwrap(),
                    if replayed {
                        "(replayed result observed at 1001)\n"
                    } else {
                        ""
                    }
                );
                let text = String::from_utf8(out).unwrap();
                assert!(text.contains("config v2, 1 warning\nwarning: clock skew\n"));
                for debug in [
                    "Check {",
                    "HealthSummary {",
                    "Report {",
                    "ClockSkew",
                    "ForeignLink(",
                ] {
                    assert!(!text.contains(debug), "{text}");
                }
                let mut out = Vec::new();
                let mut err = Vec::new();
                assert_eq!(
                    render(response, true, &mut out, &mut err).unwrap(),
                    report.verdict.exit_code()
                );
                assert_eq!(err, Vec::<u8>::new());
                assert_eq!(
                    serde_json::from_slice::<serde_json::Value>(&out).unwrap(),
                    serde_json::to_value(&report).unwrap()
                );
            }
        }
    }
    type Reply = Result<Result<OpResult, scupper_proto::ApiError>, std::io::ErrorKind>;
    struct RecordedClient {
        now: Cell<Instant>,
        replies: RefCell<VecDeque<(Duration, Reply)>>,
        calls: RefCell<Vec<(Op, Instant, Instant)>>,
    }
    #[allow(clippy::unwrap_used)]
    impl ReadClient for RecordedClient {
        fn now(&self) -> Instant {
            self.now.get()
        }
        fn call(
            &self,
            _: &std::path::Path,
            op: Op,
            deadline: Instant,
        ) -> Result<Response, ClientError> {
            self.calls.borrow_mut().push((op, self.now(), deadline));
            let (elapsed, reply) = self.replies.borrow_mut().pop_front().unwrap();
            self.now.set(self.now() + elapsed);
            reply
                .map(|result| Response {
                    request_id: control::request(Op::Ping {}).request_id,
                    schema: Schema,
                    replayed: false,
                    observed_at: None,
                    result,
                })
                .map_err(|kind| ClientError::OutcomeUnknown(std::io::Error::from(kind)))
        }
    }
    fn live_ping() -> OpResult {
        OpResult::Ping {
            last_complete_iteration_age: Some(0),
            current_iteration_age: None,
            operation: None,
            netns: NetnsIdentity {
                device: 1,
                inode: 2,
            },
            version: 1,
            quarantined: false,
            selection: Selection::Auto,
        }
    }
    #[allow(clippy::unwrap_used)]
    fn local_read(client: &RecordedClient) -> LocalRead {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let system = scupper_sys::system::RealSystem::default();
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/tmp")
            .join(format!(
                "control-no-state-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
        std::fs::create_dir_all(root.parent().unwrap()).unwrap();
        std::fs::create_dir(&root).unwrap();
        let deps = Dependencies {
            state_root: &root,
            config_root: &root,
            writer_root: &root,
            probe_exec: &system,
            system: &system,
            namespaces: &super::super::ProcNamespaces,
            privilege: &super::super::EffectiveUid,
            prompt: &super::super::TerminalPrompt,
        };
        let outcome = read_with(&deps, false, true, &mut Vec::new(), &mut Vec::new(), client);
        std::fs::remove_dir(&root).unwrap();
        let outcome = outcome.unwrap();
        let ReadOutcome::Local(local) = outcome else {
            unreachable!("expected local observations")
        };
        assert!(client.replies.borrow().is_empty());
        local
    }

    #[test]
    fn initial_ping_and_hung_check_share_one_deadline() {
        let start = Instant::now();
        let client = RecordedClient {
            now: Cell::new(start),
            replies: RefCell::new(VecDeque::from([
                (Duration::from_millis(1500), Ok(Ok(live_ping()))),
                (
                    Duration::from_millis(3500),
                    Err(std::io::ErrorKind::TimedOut),
                ),
            ])),
            calls: RefCell::default(),
        };
        let local = local_read(&client);
        assert!(
            matches!(local.supervisor, Supervisor::Alive { iteration_age, .. }
            if iteration_age == control::CHECK_TIMEOUT)
        );
        assert_eq!(
            *client.calls.borrow(),
            [
                (Op::Ping {}, start, start + Duration::from_secs(2)),
                (
                    Op::Check {},
                    start + Duration::from_millis(1500),
                    start + control::CHECK_TIMEOUT
                ),
            ]
        );
    }

    #[test]
    fn check_error_near_or_after_deadline_refreshes_live_supervisor() {
        // Advancing an injected clock proves the allowance even after expiry,
        // without requiring a server to wake inside a narrow wall-clock window.
        for elapsed in [Duration::from_millis(4999), Duration::from_millis(5100)] {
            for code in [
                scupper_proto::ApiErrorCode::Internal,
                scupper_proto::ApiErrorCode::SupervisorUnavailable,
            ] {
                let start = Instant::now();
                let client = RecordedClient {
                    now: Cell::new(start),
                    replies: RefCell::new(VecDeque::from([
                        (Duration::ZERO, Ok(Ok(live_ping()))),
                        (
                            elapsed,
                            Ok(Err(scupper_proto::ApiError {
                                code,
                                observation: None,
                            })),
                        ),
                        (Duration::from_millis(200), Ok(Ok(live_ping()))),
                    ])),
                    calls: RefCell::default(),
                };
                let local = local_read(&client);
                assert!(matches!(local.supervisor, Supervisor::Alive { .. }));
                assert_eq!(local.version, Some(1));
                assert_eq!(
                    *client.calls.borrow(),
                    [
                        (Op::Ping {}, start, start + Duration::from_secs(2)),
                        (Op::Check {}, start, start + control::CHECK_TIMEOUT),
                        (
                            Op::Ping {},
                            start + elapsed,
                            start + elapsed + PING_ALLOWANCE
                        ),
                    ]
                );
            }
        }
    }

    #[cfg(feature = "testing")]
    #[test]
    #[allow(clippy::unwrap_used)]
    fn near_deadline_check_error_with_live_daemon_renders_protected() {
        use super::test_support::{Root, Script, fresh};
        struct Namespaces;
        impl super::super::NamespaceReader for Namespaces {
            fn read_namespace(&self, _: &std::path::Path) -> std::io::Result<std::path::PathBuf> {
                unreachable!("not used by the local check")
            }
            fn open_gateway(&self) -> Result<Option<scupper_sys::netns::NetnsHandle>, String> {
                Ok(Some(scupper_sys::netns::testing::handle().unwrap()))
            }
        }
        let sys = Script::new("ubuntu-24.04");
        fresh(&sys);
        let held = scupper_sys::netns::testing::handle().unwrap();
        let text = test_support::site_text(&sys.runner)
            .replace("require_daemon = false", "require_daemon = true");
        let root = Root::with_text(&text, &held);
        let deps = Dependencies {
            state_root: &root.path,
            config_root: &root.path,
            writer_root: &root.path,
            system: &sys,
            probe_exec: &sys,
            namespaces: &Namespaces,
            privilege: &super::super::EffectiveUid,
            prompt: &super::super::TerminalPrompt,
        };
        let (device, inode) = held.identity();
        let ping = || {
            Ok(Ok(OpResult::Ping {
                last_complete_iteration_age: Some(0),
                current_iteration_age: None,
                operation: None,
                netns: NetnsIdentity { device, inode },
                version: 1,
                quarantined: false,
                selection: Selection::Auto,
            }))
        };
        let client = RecordedClient {
            now: Cell::new(Instant::now()),
            replies: RefCell::new(VecDeque::from([
                (Duration::ZERO, ping()),
                (
                    Duration::from_millis(4999),
                    Ok(Err(scupper_proto::ApiError {
                        code: scupper_proto::ApiErrorCode::SupervisorUnavailable,
                        observation: None,
                    })),
                ),
                (Duration::from_millis(200), ping()),
            ])),
            calls: RefCell::default(),
        };
        let mut out = Vec::new();
        let mut err = Vec::new();
        let ReadOutcome::Local(local) =
            read_with(&deps, false, true, &mut out, &mut err, &client).unwrap()
        else {
            unreachable!("expected local fallback")
        };
        let config = super::super::m2_config(&deps).unwrap().unwrap();
        let code =
            super::super::m2_check(&deps, &config, false, true, local, &mut out, &mut err).unwrap();
        assert_eq!(code, 0, "{}", String::from_utf8_lossy(&out));
        assert!(String::from_utf8_lossy(&out).contains("Protected"));
        assert!(client.replies.borrow().is_empty());
    }

    #[cfg(feature = "testing")]
    #[test]
    #[allow(clippy::unwrap_used)]
    #[allow(clippy::too_many_lines)] // Both operation snapshots and a Ping racing publication must reach the real driver.
    fn apply_tail_uses_target_context_and_detects_kernel_violation() {
        use super::test_support::{Root, Script, fresh};
        struct Namespaces;
        impl super::super::NamespaceReader for Namespaces {
            fn read_namespace(&self, _: &std::path::Path) -> std::io::Result<std::path::PathBuf> {
                unreachable!("not used by the local check")
            }
            fn open_gateway(&self) -> Result<Option<scupper_sys::netns::NetnsHandle>, String> {
                Ok(Some(scupper_sys::netns::testing::handle().unwrap()))
            }
        }
        for (with_operation, boot_state) in [true, false].into_iter().flat_map(|operation| {
            ["previous", "in_progress", "succeeded", "wrong_inode"].map(|state| (operation, state))
        }) {
            let sys = Script::new("ubuntu-24.04");
            fresh(&sys);
            sys.replace("scupper-nft-ruleset.json", r#"{"nftables":[]}"#);
            let held = scupper_sys::netns::testing::handle().unwrap();
            let text = test_support::site_text(&sys.runner)
                .replace("require_daemon = false", "require_daemon = true");
            let root = Root::with_text(&text, &held);
            let path = root.path.join("boot.json");
            let (dev, ino) = held.identity();
            let mut boot = scupper_sys::boot::BootReport {
                steps: scupper_sys::boot::BootStep::ALL
                    .iter()
                    .map(|step| scupper_sys::boot::StepResult {
                        step: *step,
                        error: None,
                        adopted: true,
                    })
                    .collect(),
                applied_version: Some(1),
                netns: Some(scupper_sys::boot::NamespaceIdentity { dev, ino }),
                ..Default::default()
            };
            match boot_state {
                "previous" => boot.applied_version = Some(0),
                "in_progress" => {
                    boot.steps.pop();
                }
                "wrong_inode" => {
                    boot.netns.as_mut().unwrap().ino += 1;
                }
                _ => {}
            }
            std::fs::write(path, serde_json::to_vec(&boot).unwrap()).unwrap();
            let guard = scupper_sys::lock::WriterLock::acquire(&root.path).unwrap();
            scupper_sys::state::StateFile::open(&root.path, Some(&guard))
                .unwrap()
                .write(
                    &guard,
                    &scupper_sys::state::State {
                        applied_version: Some(1),
                        ..Default::default()
                    },
                )
                .unwrap();
            let deps = Dependencies {
                state_root: &root.path,
                config_root: &root.path,
                writer_root: &root.path,
                system: &sys,
                probe_exec: &sys,
                namespaces: &Namespaces,
                privilege: &super::super::EffectiveUid,
                prompt: &super::super::TerminalPrompt,
            };
            let (device, inode) = held.identity();
            let ping = || {
                Ok(Ok(OpResult::Ping {
                    last_complete_iteration_age: Some(0),
                    current_iteration_age: None,
                    operation: with_operation.then_some(scupper_proto::OperationProgress {
                        kind: scupper_proto::OperationKind::Apply,
                        from: 0,
                        to: 1,
                        age: 8,
                    }),
                    netns: NetnsIdentity { device, inode },
                    version: 0,
                    quarantined: false,
                    selection: Selection::Auto,
                }))
            };
            let mut replies = VecDeque::from([(Duration::ZERO, ping())]);
            if !with_operation {
                replies.push_back((control::CHECK_TIMEOUT, Err(std::io::ErrorKind::TimedOut)));
            }
            let client = RecordedClient {
                now: Cell::new(Instant::now()),
                replies: RefCell::new(replies),
                calls: RefCell::default(),
            };
            let mut out = Vec::new();
            let mut err = Vec::new();
            let outcome = read_with(&deps, false, true, &mut out, &mut err, &client).unwrap();
            if boot_state != "succeeded" {
                assert!(
                    matches!(outcome, ReadOutcome::Rendered(3)),
                    "{}",
                    String::from_utf8_lossy(&out)
                );
                assert!(String::from_utf8_lossy(&out).contains("OperationInProgress"));
                continue;
            }
            let ReadOutcome::Local(local) = outcome else {
                unreachable!("expected local fallback")
            };
            assert_eq!(local.version, Some(1));
            let config = super::super::m2_config_at(&deps, local.version)
                .unwrap()
                .unwrap();
            let code =
                super::super::m2_check(&deps, &config, false, true, local, &mut out, &mut err)
                    .unwrap();
            assert_eq!(code, 2, "{}", String::from_utf8_lossy(&out));
            assert!(String::from_utf8_lossy(&out).contains("Unprotected"));
            assert!(client.replies.borrow().is_empty());
        }
    }

    #[test]
    fn exit_matching_table() {
        let exits = [("ch1", "Zurich"), ("ch2", "Zug")];
        for (name, tty, expected) in [
            ("CH1", false, Some("ch1")),
            ("zURICH", false, Some("ch1")),
            ("Zuri", true, Some("ch1")),
            ("Zuri", false, None),
            ("Z", true, None),
            ("missing", true, None),
        ] {
            assert_eq!(match_exit(name, &exits, tty).ok().as_deref(), expected);
        }
    }
}
