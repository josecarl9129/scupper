//! Journal-backed undo boundary shared with the native resource adapter.
use super::{journal, recovery};
use std::{error::Error, fs, path::Path};
type Result<T> = std::result::Result<T, Box<dyn Error>>;

pub(crate) fn undo(
    out: &Path,
    mut campaign_quiescent: impl FnMut() -> Result<bool>,
    mut jobs_absent: impl FnMut() -> Result<bool>,
    mut writers_quiescent: impl FnMut() -> Result<bool>,
    mut run: impl FnMut(&str, &[(usize, journal::Entry)]) -> Result<()>,
) -> Result<Vec<String>> {
    let journal_path = out.join("resources.jsonl");
    let entries = if journal_path.exists() {
        journal::committed(&fs::read_to_string(journal_path)?)?
    } else {
        Vec::new()
    };
    let path = out.join("completed-resources.json");
    let completed: recovery::Completed = if path.exists() {
        serde_json::from_slice(&fs::read(path)?)?
    } else {
        recovery::Completed::default()
    };
    let pending = completed.pending(entries);
    Ok(recovery::undo(
        || -> Result<bool> { Ok(campaign_quiescent()? && jobs_absent()? && writers_quiescent()?) },
        |step| run(step, &pending),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    #[test]
    fn journal_undo_retains_entries_when_restartable_job_remains() -> Result<()> {
        let out = std::env::current_dir()?.join("target").join(format!(
            "resource-undo-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&out)?;
        let result = (|| -> Result<()> {
            let journal = concat!(
                "{\"kind\":\"r4-job\",\"path\":\"system/net.scupper.qual.r4-exit\"}\n",
                "{\"kind\":\"anchor\",\"path\":\"scupper-qual/scupper\"}\n",
                "{\"kind\":\"token\",\"token\":7}\n",
                "{\"kind\":\"r6-pf\"}\n"
            );
            fs::write(out.join("resources.jsonl"), journal)?;
            fs::write(
                out.join("completed-resources.json"),
                b"{\"entries\":[],\"writers\":[]}",
            )?;
            let completion_before = fs::read(out.join("completed-resources.json"))?;
            let status: super::super::Evidence = serde_json::from_value(serde_json::json!({
                "command":["launchctl","print"],"stdin":null,"pid":1,"exit_code":0,
                "started_unix_ms":0,"elapsed_ms":0,"timed_out":false,"truncated":false,
                "stdout":"state = running\n","stderr":""}))?;
            let mut commands = Vec::new();
            let mut visited = Vec::new();
            let failures = undo(
                &out,
                || Ok(true),
                || Ok(super::super::jobs::absent(&status)),
                || Ok(true),
                |step, pending| {
                    visited.push(step.to_owned());
                    match step {
                        "tools" => return Err("bootout failed".into()),
                        "tokens" | "anchors" | "pf state" => commands.push(step.to_owned()),
                        "completion" => fs::write(
                            out.join("completed-resources.json"),
                            serde_json::to_vec(&recovery::Completed {
                                entries: pending.iter().map(|(index, _)| *index).collect(),
                                writers: Vec::new(),
                            })?,
                        )?,
                        _ => {}
                    }
                    Ok(())
                },
            )?;
            assert!(
                commands.is_empty(),
                "assertion failed: dependent mutation escaped job absence gate"
            );
            assert!(visited.iter().any(|s| s == "images"));
            assert!(failures.iter().any(|s| s == "bootout failed"));
            for step in ["tokens", "anchors", "pf state", "completion"] {
                assert!(
                    failures
                        .iter()
                        .any(|s| s.starts_with(step) && s.contains("withheld"))
                );
            }
            assert_eq!(fs::read_to_string(out.join("resources.jsonl"))?, journal);
            assert_eq!(
                fs::read(out.join("completed-resources.json"))?,
                completion_before
            );
            let completed: recovery::Completed =
                serde_json::from_slice(&fs::read(out.join("completed-resources.json"))?)?;
            assert_eq!(
                completed
                    .pending(journal::committed(&fs::read_to_string(
                        out.join("resources.jsonl")
                    )?)?)
                    .len(),
                4
            );
            Ok(())
        })();
        fs::remove_dir_all(out)?;
        result
    }
}
