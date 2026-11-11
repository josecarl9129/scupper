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

fn match_exit(name: &str, candidates: &[(&str, &str)], tty: bool) -> Result<String, String> {
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
                    secret_owner: 0,
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
    render(response, json, out)
}

pub(super) enum ReadOutcome {
    Rendered(u8),
    Local(LocalRead),
}

pub(super) struct LocalRead {
    pub supervisor: scupper_core::verdict::v2::Supervisor,
    pub version: Option<u64>,
    // The same deadline survives local observations and namespace retries.
    deadline: Instant,
}

struct PingObservation {
    supervisor: scupper_core::verdict::v2::Supervisor,
    busy_age: Option<u64>,
    operation: Option<scupper_proto::OperationProgress>,
    version: u64,
}
fn ping_supervisor(deps: &Dependencies<'_>, deadline: Instant) -> Option<PingObservation> {
    use scupper_core::verdict::v2::Supervisor;
    let response = control::call_until(
        deps.writer_root,
        &control::request(Op::Ping {}),
        deadline.min(Instant::now() + Duration::from_secs(2)),
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
    use scupper_core::verdict::v2::Supervisor;
    let deadline = Instant::now() + control::CHECK_TIMEOUT;
    let mut local = |err: &mut dyn Write, supervisor, version: Option<u64>| {
        if let Some(operation) =
            version.and_then(|from| version_transition(from, applied_version(deps)))
        {
            return operation_report(&operation, json, out, err);
        }
        writeln!(err, "transport: local observations").map_err(output_error)?;
        Ok(ReadOutcome::Local(LocalRead {
            supervisor,
            version,
            deadline,
        }))
    };
    if status {
        return local(err, Supervisor::Dead, None);
    }
    let mut observed = Instant::now();
    let Some(PingObservation {
        mut supervisor,
        busy_age,
        operation,
        version,
    }) = ping_supervisor(deps, deadline)
    else {
        return local(err, Supervisor::Dead, None);
    };
    let mut version = Some(version);
    if let Some(operation) = operation {
        return operation_report(&operation, json, out, err);
    }
    if busy_age.is_some_and(|age| age >= 5)
        || matches!(supervisor, Supervisor::Alive {iteration_age, ..} if iteration_age >= Duration::from_secs(30))
    {
        return local(err, supervisor, version);
    }
    for attempt in 0..2 {
        let response =
            control::call_until(deps.writer_root, &control::request(Op::Check {}), deadline);
        match response {
            Ok(response) if response.result.is_ok() => {
                writeln!(err, "transport: local socket").map_err(output_error)?;
                return render(response, json, out).map(ReadOutcome::Rendered);
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
                let fresh = ping_supervisor(deps, deadline);
                if let Some(PingObservation {
                    operation: Some(operation),
                    ..
                }) = fresh.as_ref()
                {
                    return operation_report(operation, json, out, err);
                }
                version = fresh.as_ref().map(|ping| ping.version);
                supervisor = fresh.map_or(Supervisor::Dead, |ping| ping.supervisor);
                observed = Instant::now();
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
            iteration_age: iteration_age + observed.elapsed(),
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
    let ping = ping_supervisor(deps, local.deadline);
    let state_version = applied_version(deps);
    if let Some(ping) = ping.as_ref() {
        if let Some(operation) = &ping.operation {
            return operation_report(operation, json, out, err).map(Some);
        }
        let identity = |supervisor| match supervisor {
            scupper_core::verdict::v2::Supervisor::Alive { netns, .. } => Some(netns),
            _ => None,
        };
        if ping.version != version || identity(ping.supervisor) != identity(local.supervisor) {
            return Ok(Some(ReadOutcome::Local(LocalRead {
                supervisor: ping.supervisor,
                version: Some(ping.version),
                deadline: local.deadline,
            })));
        }
    }
    if let Some(operation) = version_transition(version, state_version) {
        return operation_report(&operation, json, out, err).map(Some);
    }
    Ok(None)
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
    if json {
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
        serde_json::to_writer(&mut *out, &report).map_err(|error| error.to_string())?;
        writeln!(out).map_err(output_error)?;
    } else {
        writeln!(out, "{message}").map_err(output_error)?;
    }
    Ok(ReadOutcome::Rendered(3))
}
fn unix_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn render(response: Response, json: bool, out: &mut dyn Write) -> Result<u8, String> {
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
    if response.replayed && !json {
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
            Ok(OpResult::Disconnect {}) => writeln!(out, "traffic is now blocked"),
            Ok(OpResult::Connect { exit }) => writeln!(out, "connected via {}", String::from(exit)),
            Ok(OpResult::Apply { version, dry_run, repair_plan, plan }) => writeln!(out, "version {version}; dry run: {dry_run}\nRepair preview: {repair_plan:?}\nTarget boot: {plan:?}"),
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

#[cfg(test)]
mod tests {
    use super::*;
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
