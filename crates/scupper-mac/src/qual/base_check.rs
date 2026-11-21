//! Portable evidence checks shared by the native base and smoke cells.
use crate::snapshot::{BootId, ImageHistory};
use crate::{
    decode::proc,
    platform::{Enumeration, ProcInfo, ProcState, ProcessError, SysError},
};
use serde_json::Value;

// Classification uses the engine's predicate; these labels only explain a
// withheld result under the explicitly synthetic fresh-install history.
// The caller must establish its current boot before collecting any census.
pub(super) fn census_classification(
    proc: &crate::platform::ProcInfo,
    history: &ImageHistory,
    boot: Option<&BootId>,
    pins: &[(String, [u8; 16])],
    pin_uuids: Option<&[[u8; 16]]>,
) -> String {
    debug_assert!(
        history.known_on(boot),
        "census requires a proven current boot"
    );
    if crate::platform::provably_foreign(proc, history, boot, pin_uuids) {
        return "foreign (synthetic empty history)".into();
    }
    let Some(image) = proc.image.filter(|i| i.uuid != [0; 16] && i.uniqueid != 0) else {
        return "withheld: image unknown".into();
    };
    if pin_uuids.is_none() {
        return "withheld: pins unknown".into();
    }
    if let Some((path, _)) = pins.iter().find(|(_, uuid)| *uuid == image.uuid) {
        return format!("withheld: equals pin {path}");
    }
    if history.uuids.contains(&image.uuid) {
        return "withheld: equals history".into();
    }
    if proc.name.is_none() {
        return "withheld: name unknown".into();
    }
    if !history.known_on(boot) {
        return "withheld: history unknown".into();
    }
    "withheld: name".into()
}

pub(super) fn withheld_persistent_pathless(census: &[Value], complete: usize) -> Vec<String> {
    let mut withheld = Vec::new();
    let mut persistent = std::collections::BTreeMap::<String, (usize, bool)>::new();
    for entry in census {
        if entry["source"] != "complete_inventory" {
            continue;
        }
        let key = format!("{}:{}", entry["pid"], entry["start"]);
        let (count, foreign) = persistent.entry(key).or_insert((0, true));
        *count += 1;
        *foreign &= entry["classification"] == "foreign (synthetic empty history)";
    }
    for (identity, (count, foreign)) in persistent {
        if count * 10 >= complete * 9 && !foreign {
            withheld.push(format!(
                "persistent pathless {identity} withheld ({count}/{complete} Complete inventories)"
            ));
        }
    }
    withheld
}

pub(super) fn compare_process_layout(
    abi: &Value,
    rust_fields: &[(&str, usize)],
    rust_size: usize,
    rust_maxcomlen: usize,
) -> Result<(), String> {
    let mut missing = Vec::new();
    for key in ["/kinfo_proc/size", "/MAXCOMLEN"] {
        if abi.pointer(key).is_none() {
            missing.push(key.to_owned());
        }
    }
    for (field, _) in rust_fields.iter().chain(proc::FIELDS.iter()) {
        let key = format!("/kinfo_proc/fields/{field}");
        if abi.pointer(&key).is_none() && !missing.contains(&key) {
            missing.push(key);
        }
    }
    if !missing.is_empty() {
        return Err(format!(
            "SDK ABI missing expected keys: {}",
            missing.join(", ")
        ));
    }
    if rust_size != proc::RECORD_BYTES
        || rust_maxcomlen != proc::MAXCOMLEN
        || abi["kinfo_proc"]["size"].as_u64() != Some(rust_size as u64)
        || abi["MAXCOMLEN"].as_u64() != Some(rust_maxcomlen as u64)
    {
        return Err("SDK/Rust process size or MAXCOMLEN mismatch".into());
    }
    for (field, offset) in rust_fields.iter().chain(proc::FIELDS.iter()) {
        if abi["kinfo_proc"]["fields"][field].as_u64() != Some(*offset as u64) {
            return Err(format!(
                "SDK/Rust/decoder kinfo_proc offset mismatch: {field}"
            ));
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
pub(super) enum Oracle {
    Stopped(u32),
    Pathless(u32),
}

// False means retry: incomplete evidence never establishes an oracle check.
pub(super) fn inventory(
    inventory: &Enumeration<Vec<ProcInfo>, ProcessError>,
    oracle: Oracle,
) -> Result<bool, String> {
    match inventory {
        Enumeration::Incomplete(error) => {
            if matches!(
                error.error,
                SysError::Failed(
                    "native: process layout"
                        | "native: invalid pid"
                        | "native: invalid ppid"
                        | "native: invalid pgid"
                )
            ) {
                return Err(format!("adapter process contract breach: {error:?}"));
            }
            Ok(false)
        }
        Enumeration::Complete(list) => match oracle {
            Oracle::Stopped(pid) => {
                if list
                    .iter()
                    .any(|p| p.pid == pid && p.state == ProcState::Stopped)
                {
                    Ok(true)
                } else {
                    Err("native inventory omitted or misclassified stopped oracle".into())
                }
            }
            Oracle::Pathless(pid) => {
                if list.iter().any(|p| {
                    p.pid == pid
                        && p.path.is_none()
                        && p.image
                            .is_some_and(|image| image.uuid != [0; 16] && image.uniqueid != 0)
                }) {
                    Ok(true)
                } else {
                    Err("Complete inventory missing validated pathless oracle".into())
                }
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn abi() -> Value {
        let fields = proc::FIELDS
            .iter()
            .map(|(key, offset)| ((*key).to_owned(), json!(offset)))
            .collect::<serde_json::Map<_, _>>();
        json!({"MAXCOMLEN": proc::MAXCOMLEN, "kinfo_proc": {"size": proc::RECORD_BYTES, "fields": fields}})
    }

    #[test]
    fn layout_checks_missing_macro_keys_and_decoder_offsets() -> Result<(), String> {
        let mut sdk = abi();
        compare_process_layout(&sdk, &proc::FIELDS, proc::RECORD_BYTES, proc::MAXCOMLEN)?;
        let fields = sdk["kinfo_proc"]["fields"]
            .as_object_mut()
            .ok_or("fields")?;
        fields.remove("kp_proc.p_starttime.tv_sec");
        fields.remove("kp_proc.p_starttime.tv_usec");
        fields.insert("kp_proc.p_un.__p_starttime.tv_sec".into(), json!(0));
        let error =
            compare_process_layout(&sdk, &proc::FIELDS, proc::RECORD_BYTES, proc::MAXCOMLEN)
                .err()
                .ok_or("missing keys accepted")?;
        assert!(error.contains("missing expected keys"));
        assert!(error.contains("kp_proc.p_starttime.tv_sec"));
        assert!(error.contains("kp_proc.p_starttime.tv_usec"));
        let mut sdk = abi();
        sdk["kinfo_proc"]["fields"]["kp_proc.p_comm"] = json!(244);
        // Even if the typed Rust layout followed the SDK, the decoder must agree.
        let mut rust = proc::FIELDS;
        rust[4].1 = 244;
        assert!(compare_process_layout(&sdk, &rust, proc::RECORD_BYTES, proc::MAXCOMLEN).is_err());
        Ok(())
    }

    #[test]
    fn incomplete_never_vacuously_qualifies_stopped_or_unrelated_pathless() -> Result<(), String> {
        let incomplete = |pid, error| Enumeration::Incomplete(ProcessError { pid, error });
        let unrelated = incomplete(Some(99), SysError::Failed("native: live pathless process"));
        assert!(!inventory(&unrelated, Oracle::Stopped(123))?);
        assert!(!inventory(&unrelated, Oracle::Pathless(123))?);
        let expected = incomplete(Some(123), SysError::Failed("native: live pathless process"));
        assert!(!inventory(&expected, Oracle::Pathless(123))?);
        let layout = incomplete(None, SysError::Failed("native: process layout"));
        assert!(inventory(&layout, Oracle::Stopped(123)).is_err());
        assert!(inventory(&layout, Oracle::Pathless(123)).is_err());
        let mut list = proc::records(include_bytes!(
            "../../tests/fixtures/macos/layout/kinfo_proc.bin"
        ))
        .map_err(|e| e.to_string())?;
        assert!(inventory(
            &Enumeration::Complete(list.clone()),
            Oracle::Stopped(123)
        )?);
        assert!(inventory(&Enumeration::Complete(list.clone()), Oracle::Pathless(123)).is_err());
        list[0].state = ProcState::Running;
        assert!(inventory(&Enumeration::Complete(list), Oracle::Stopped(123)).is_err());
        assert!(inventory(&Enumeration::Complete(Vec::new()), Oracle::Stopped(123)).is_err());
        Ok(())
    }
    #[test]
    fn census_labels_use_engine_foreign_predicate() -> Result<(), Box<dyn std::error::Error>> {
        let boot = BootId::try_from("01234567-89AB-CDEF-0123-456789ABCDEF")?;
        let mut history = ImageHistory::empty_for_boot(boot.clone());
        let mut proc = proc::records(include_bytes!(
            "../../tests/fixtures/macos/layout/kinfo_proc.bin"
        ))?
        .remove(0);
        proc.image = Some(crate::platform::ImageId {
            uuid: [3; 16],
            uniqueid: 42,
        });
        proc.name = Some("foreign".into());
        let pins = [("/sbin/pfctl".into(), [2; 16])];
        let label = |p: &ProcInfo, h: &ImageHistory| {
            census_classification(p, h, Some(&boot), &pins, Some(&[[2; 16]]))
        };
        assert_eq!(label(&proc, &history), "foreign (synthetic empty history)");
        assert_eq!(
            census_classification(&proc, &history, Some(&boot), &pins, None),
            "withheld: pins unknown"
        );
        history.record([3; 16]);
        assert_eq!(label(&proc, &history), "withheld: equals history");
        history = ImageHistory::empty_for_boot(boot.clone());
        proc.name = None;
        assert_eq!(label(&proc, &history), "withheld: name unknown");
        // The production caller requires known history; release builds still
        // explain uncertainty if that precondition is ever violated.
        if !cfg!(debug_assertions) {
            history.known = false;
            proc.name = Some("foreign".into());
            assert_eq!(label(&proc, &history), "withheld: history unknown");
            history.known = true;
        }
        proc.name = Some("wireguard-go".into());
        assert_eq!(label(&proc, &history), "withheld: name");
        proc.image.as_mut().ok_or("image absent")?.uuid = [2; 16];
        assert_eq!(label(&proc, &history), "withheld: equals pin /sbin/pfctl");
        proc.image = None;
        assert_eq!(label(&proc, &history), "withheld: image unknown");
        Ok(())
    }

    #[test]
    fn persistent_pathless_threshold_counts_complete_inventories_and_exact_identity() {
        let entries = |count, start, classification| {
            (0..count)
                .map(|iteration| {
                    json!({"source": "complete_inventory", "pid": 777, "start": [start, 0],
                "iteration": iteration, "classification": classification})
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(
            withheld_persistent_pathless(&entries(44, 1, "withheld: name"), 50),
            Vec::<String>::new()
        );
        assert_eq!(
            withheld_persistent_pathless(&entries(45, 1, "withheld: name"), 50).len(),
            1
        );
        assert_eq!(
            withheld_persistent_pathless(&entries(50, 1, "foreign (synthetic empty history)"), 50),
            Vec::<String>::new()
        );
        let mut changed = entries(30, 1, "withheld: name");
        changed.extend(entries(30, 2, "withheld: name"));
        assert_eq!(
            withheld_persistent_pathless(&changed, 50),
            Vec::<String>::new()
        );
        for entry in &mut changed {
            entry["source"] = json!("independent_census");
        }
        assert_eq!(
            withheld_persistent_pathless(&changed, 50),
            Vec::<String>::new()
        );
        let mut mixed = entries(50, 1, "foreign (synthetic empty history)");
        mixed[0]["classification"] = json!("withheld: pins unknown");
        assert_eq!(withheld_persistent_pathless(&mixed, 50).len(), 1);
    }
}
