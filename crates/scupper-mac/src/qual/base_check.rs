//! Portable evidence checks shared by the native base and smoke cells.
use crate::{
    decode::proc,
    platform::{Enumeration, ProcInfo, ProcState, ProcessError, SysError},
};
use serde_json::Value;

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
}
