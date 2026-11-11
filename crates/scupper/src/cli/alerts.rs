//! Alert inspection and explicit delivery tests, without resolving URL secrets.
use super::{Dependencies, m2_config, output_error, require_root};
use clap::Subcommand;
use std::{io::Write, time::Duration};
#[derive(Clone, Subcommand)]
pub(super) enum AlertsCommand {
    /// List configured sinks and their durable delivery status.
    List,
    /// Queue one Info test through a running daemon's real delivery worker.
    Test { sink: Option<String> },
}
pub(super) fn run(
    command: AlertsCommand,
    deps: &Dependencies<'_>,
    json: bool,
    out: &mut dyn Write,
) -> Result<u8, String> {
    let config = m2_config(deps)?.ok_or("no applied configuration")?;
    let sinks = config.site.sinks();
    match command {
        AlertsCommand::List => {
            let mut rows = Vec::new();
            for (name, settings) in sinks {
                let (status, unavailable) = match scupper_sys::alerts::status(deps.state_root, name)
                {
                    Ok(status) => (status, false),
                    Err(_) => (scupper_sys::alerts::Status::default(), true),
                };
                let (kind, preset) = match settings {
                    scupper_core::config::AlertSink::Ntfy { .. } => ("ntfy", None),
                    scupper_core::config::AlertSink::Webhook { preset, .. } => {
                        ("webhook", Some(preset))
                    }
                };
                rows.push(serde_json::json!({"sink":name,"kind":kind,"preset":preset,"min_severity":settings.min_severity(),"cursor":status.cursor,"last_success":status.last_success,"last_failure":status.last_failure,"unavailable":unavailable}));
            }
            if json {
                serde_json::to_writer(&mut *out, &serde_json::json!({"schema":1,"sinks":rows}))
                    .map_err(|e| e.to_string())?;
                writeln!(out).map_err(output_error)?;
            } else {
                for row in rows {
                    writeln!(
                        out,
                        "{} {} preset={} min={} cursor={} success={} failure={} unavailable={}",
                        row["sink"].as_str().unwrap_or_default(),
                        row["kind"].as_str().unwrap_or_default(),
                        row["preset"],
                        row["min_severity"],
                        row["cursor"],
                        row["last_success"],
                        row["last_failure"],
                        row["unavailable"]
                    )
                    .map_err(output_error)?;
                }
            }
        }
        AlertsCommand::Test { sink } => {
            require_root(deps, "alerts test")?;
            let name = if let Some(name) = sink {
                name
            } else {
                if !deps.prompt.is_terminal() {
                    return Err("alerts test requires SINK without a TTY".into());
                }
                let names: Vec<_> = sinks.keys().map(String::as_str).collect();
                deps.prompt
                    .choose(&names)
                    .map_err(|_| "sink picker failed")?
            };
            if !sinks.contains_key(&name) {
                return Err("unknown alert sink".into());
            }
            let ping = scupper_sys::daemon::control::call(
                deps.writer_root,
                &scupper_sys::daemon::control::request(scupper_proto::Op::Ping {}),
                Duration::from_secs(2),
            )
            .map_err(|_| "alerts test requires a running scupperd")?;
            if ping.result.is_err() {
                return Err("alerts test requires a ready scupperd".into());
            }
            let id = scupper_sys::alerts::request_test(deps.state_root, &name)
                .map_err(|_| "could not queue alert test")?;
            let deadline = std::time::Instant::now() + Duration::from_secs(60);
            let outcome = loop {
                if let Some(outcome) =
                    scupper_sys::alerts::test_outcome(deps.state_root, &name, &id)
                        .map_err(|_| "alert test receipt unavailable")?
                {
                    let _ = scupper_sys::alerts::finish_test(deps.state_root, &name, &id);
                    break outcome;
                }
                if std::time::Instant::now() >= deadline {
                    break "timeout".into();
                }
                std::thread::sleep(Duration::from_millis(100));
            };
            if json {
                serde_json::to_writer(
                    &mut *out,
                    &serde_json::json!({"schema":1,"sink":name,"outcome":outcome}),
                )
                .map_err(|e| e.to_string())?;
                writeln!(out).map_err(output_error)?;
            } else {
                writeln!(out, "{name}: {outcome}").map_err(output_error)?;
            }
            return Ok(u8::from(outcome != "delivered"));
        }
    }
    Ok(0)
}
