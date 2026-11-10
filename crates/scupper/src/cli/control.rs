//! CLI control operations and bounded, single-writer local fallback.
use super::{BootNamespaces, Dependencies, output_error, require_root};
use clap::Subcommand;
use scupper_proto::{Op, OpResult, Response, Schema, VerdictCode};
use scupper_sys::daemon::{
    admin,
    control::{self, ClientError},
};
use std::{io::Write, time::Duration};

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

pub(super) fn read(
    deps: &Dependencies<'_>,
    status: bool,
    json: bool,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<Option<u8>, String> {
    if status {
        writeln!(err, "transport: local observations").map_err(output_error)?;
        return Ok(None);
    }
    let request = control::request(Op::Check {});
    let ping = control::call(
        deps.writer_root,
        &control::request(Op::Ping {}),
        Duration::from_secs(2),
    );
    if matches!(
        ping,
        Err(_)
            | Ok(Response {
                result: Err(scupper_proto::ApiError {
                    code: scupper_proto::ApiErrorCode::SupervisorUnavailable,
                    ..
                }),
                ..
            })
    ) {
        writeln!(err, "transport: local observations").map_err(output_error)?;
        return Ok(None);
    }
    if let Ok(response) = control::call(deps.writer_root, &request, control::RESPONSE_TIMEOUT)
        && response.result.is_ok()
    {
        writeln!(err, "transport: local socket").map_err(output_error)?;
        render(response, json, out).map(Some)
    } else {
        writeln!(err, "transport: local observations").map_err(output_error)?;
        Ok(None)
    }
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
