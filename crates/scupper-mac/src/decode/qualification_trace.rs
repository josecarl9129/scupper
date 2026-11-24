//! Bounded qualification evidence; shared by the native and fake boundaries.
#![cfg_attr(not(any(test, target_os = "macos")), allow(dead_code))]
use crate::{
    platform::{RefLine, WriteOutcome},
    snapshot::{COPY_BYTES, Copy, CopyClass, CopyRead, Snapshot},
};
use scupper_core::mac::lifecycle::ReferenceEntry;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};

pub(crate) const OVERFLOW: &str = "trace_overflow";
pub(crate) fn record(trace: &mut Vec<String>, call: &str) {
    if matches!(call, "now" | "pause" | "fence") || trace.last().is_some_and(|s| s == OVERFLOW) {
        return;
    }
    if trace.len() >= 16_384 || call.len() > 32_768 {
        trace.push(OVERFLOW.into());
    } else {
        trace.push(call.into());
    }
}
pub(crate) fn write_request(copy: Copy, bytes: &[u8; COPY_BYTES]) -> String {
    let snapshot = match crate::snapshot::classify_copy(CopyRead::Bytes(bytes.to_vec())) {
        CopyClass::V { snapshot, .. } => Some(snapshot),
        _ => None,
    };
    format!(
        "snapshot_write:{}",
        json!({"copy":format!("{copy:?}"),"snapshot":snapshot})
    )
}
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn write_result(result: &WriteOutcome) -> String {
    format!("snapshot_result:{result:?}")
}
pub(crate) fn refs_result(lines: &[RefLine]) -> String {
    format!(
        "references_result:{}",
        json!(
            lines
                .iter()
                .map(|r| json!({"token":r.token,"pid":r.pid,"timestamp":r.timestamp}))
                .collect::<Vec<_>>()
        )
    )
}
fn reservations(s: &Snapshot) -> BTreeSet<u64> {
    s.references
        .iter()
        .flatten()
        .filter_map(|r| match r.key {
            ReferenceEntry::Acquire(sequence) => Some(sequence),
            ReferenceEntry::Token(_) => None,
        })
        .collect()
}

/// Validate reservation-before-dispatch, independent matching before settlement,
/// durable unresolved debt and recorded fingerprints before every release.
#[allow(clippy::too_many_lines)] // Keep the ordered evidence state machine in one auditable pass.
pub(crate) fn acquisitions(trace: &[String], final_pair: &[Snapshot; 2]) -> Result<usize, String> {
    let mut request = None;
    let mut outstanding = None;
    let mut synced: [Option<Snapshot>; 2] = [None, None];
    let mut used = BTreeSet::new();
    let mut outcomes = BTreeMap::<u64, Option<(u64, u32)>>::new();
    let mut confirmed = BTreeMap::<u64, (u64, u32, u64)>::new();
    let mut active = None;
    let mut settled = BTreeSet::new();
    for line in trace {
        if line == OVERFLOW {
            return Err("trace overflow".into());
        }
        if let Some(body) = line.strip_prefix("snapshot_write:") {
            let v: serde_json::Value =
                serde_json::from_str(body).map_err(|_| "invalid snapshot request")?;
            let snapshot: Snapshot =
                serde_json::from_value(v["snapshot"].clone()).map_err(|_| "invalid snapshot")?;
            snapshot
                .validate()
                .map_err(|_| "invalid snapshot invariants")?;
            // Check even failed/partial publication requests, before sync.
            for sequence in &used {
                if !settled.contains(sequence) && !reservations(&snapshot).contains(sequence) {
                    let Some((token, pid, timestamp)) = confirmed.get(sequence) else {
                        return Err(format!(
                            "Acquire({sequence}) settled without complete matching references read"
                        ));
                    };
                    if !snapshot.references.iter().flatten().any(|r| {
                        r.key == ReferenceEntry::Token(*token)
                            && r.fingerprint
                                .is_some_and(|f| f.pid == *pid && f.timestamp == *timestamp)
                    }) {
                        return Err("settlement omitted recorded fingerprint".into());
                    }
                    settled.insert(*sequence);
                }
            }
            let index = match v["copy"].as_str() {
                Some("A") => 0,
                Some("B") => 1,
                _ => return Err("unknown copy".into()),
            };
            request = Some((index, snapshot));
        } else if line == "snapshot_result:Synced" {
            if let Some((index, snapshot)) = request.take().or_else(|| outstanding.take()) {
                synced[index] = Some(snapshot);
            }
        } else if line == "snapshot_result:TimedOut" {
            if let Some((index, snapshot)) = request.take() {
                synced[index] = None;
                outstanding = Some((index, snapshot));
            }
        } else if line.starts_with("snapshot_result:") {
            if let Some((index, _)) = request.take() {
                if !line.starts_with("snapshot_result:Busy")
                    && !line.starts_with("snapshot_result:NotStarted")
                {
                    synced[index] = None;
                }
            } else if let Some((index, _)) = outstanding.take() {
                synced[index] = None;
            }
        } else if line.starts_with("pfctl:")
            && line.split(":stdin_sha256=").next() == Some("pfctl:/sbin/pfctl -E")
        {
            if request.is_some() || outstanding.is_some() {
                return Err("-E while reservation write unresolved".into());
            }
            let (Some(a), Some(b)) = (&synced[0], &synced[1]) else {
                return Err("-E before both copies Synced".into());
            };
            let common: Vec<_> = reservations(a)
                .intersection(&reservations(b))
                .copied()
                .filter(|s| !used.contains(s))
                .collect();
            if common.len() != 1 {
                return Err("-E without one fresh durable reservation".into());
            }
            let sequence = common[0];
            let boot = |s: &Snapshot| {
                s.references
                    .iter()
                    .flatten()
                    .find(|r| r.key == ReferenceEntry::Acquire(sequence))
                    .and_then(|r| r.boot.clone())
            };
            if boot(a).is_none() || boot(a) != boot(b) {
                return Err("-E reservation has no matching known boot".into());
            }
            used.insert(sequence);
            outcomes.insert(sequence, None);
            active = Some(sequence);
        } else if let Some(body) = line.strip_prefix("acquire_result:") {
            let pair: Option<(u64, u32)> =
                serde_json::from_str(body).map_err(|_| "invalid acquisition result")?;
            if pair.is_some_and(|(token, pid)| token == 0 || pid == 0) {
                return Err("zero acquisition identity".into());
            }
            if let Some(sequence) = active.take() {
                outcomes.insert(sequence, pair);
            }
        } else if let Some(body) = line.strip_prefix("references_result:") {
            let rows: Vec<serde_json::Value> =
                serde_json::from_str(body).map_err(|_| "invalid references result")?;
            for (sequence, outcome) in &outcomes {
                if let Some((token, pid)) = outcome {
                    for row in &rows {
                        if row["token"].as_u64() == Some(*token)
                            && row["pid"].as_u64() == Some(u64::from(*pid))
                        {
                            let timestamp = row["timestamp"]
                                .as_u64()
                                .ok_or("missing fingerprint timestamp")?;
                            confirmed.insert(*sequence, (*token, *pid, timestamp));
                        }
                    }
                }
            }
        } else if let Some(command) = line.strip_prefix("pfctl:/sbin/pfctl -X ") {
            let token: u64 = command
                .split(':')
                .next()
                .ok_or("missing release token")?
                .parse()
                .map_err(|_| "invalid release token")?;
            if !synced.iter().flatten().any(|s| {
                s.references
                    .iter()
                    .flatten()
                    .any(|r| r.key == ReferenceEntry::Token(token) && r.fingerprint.is_some())
            }) {
                return Err("-X without engine-recorded fingerprint".into());
            }
        }
    }
    for sequence in &used {
        if !confirmed.contains_key(sequence)
            && !final_pair
                .iter()
                .all(|s| reservations(s).contains(sequence))
        {
            return Err("unsettled acquisition lost durable debt".into());
        }
    }
    Ok(used.len())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::snapshot::{RefEvidence, RefFingerprint};
    fn reserved() -> Snapshot {
        let boot = crate::platform::fake::FakePlatform::new().unwrap().boot;
        let mut s = Snapshot::initial(Some(501), boot.clone());
        s.machine.hold = true;
        s.machine.join_intended = true;
        s.machine.reference_sequence = 1;
        s.machine.reference_intent = Some((true, 1));
        s.references[0] = Some(RefEvidence {
            key: ReferenceEntry::Acquire(1),
            boot,
            release_unknown: false,
            fingerprint: None,
        });
        s.validate().unwrap();
        s
    }
    fn settled(s: &Snapshot) -> Snapshot {
        let mut s = s.clone();
        s.machine.reference_intent = None;
        s.machine.pf_reference = Some(42);
        let r = s.references[0].as_mut().unwrap();
        r.key = ReferenceEntry::Token(42);
        r.fingerprint = Some(RefFingerprint {
            pid: 123,
            timestamp: 999,
        });
        s.validate().unwrap();
        s
    }
    fn write(trace: &mut Vec<String>, copy: Copy, snapshot: &Snapshot, result: &WriteOutcome) {
        trace.push(write_request(
            copy,
            &crate::snapshot::encode(2, snapshot).unwrap(),
        ));
        trace.push(write_result(result));
    }
    fn dispatched() -> (Snapshot, Vec<String>) {
        let s = reserved();
        let mut trace = vec![];
        for copy in [Copy::A, Copy::B] {
            write(&mut trace, copy, &s, &WriteOutcome::Synced);
        }
        trace.push("pfctl:/sbin/pfctl -E:stdin_sha256=".into());
        trace.push("acquire_result:[42,123]".into());
        (s, trace)
    }
    #[test]
    fn acquisition_requires_two_syncs_and_consumes_reservation_once() {
        let (s, trace) = dispatched();
        assert_eq!(acquisitions(&trace, &[s.clone(), s.clone()]), Ok(1));
        for index in [1, 3] {
            let mut broken = trace.clone();
            broken[index] = "snapshot_result:TimedOut".into();
            assert!(acquisitions(&broken, &[s.clone(), s.clone()]).is_err());
        }
        let mut duplicate = trace;
        duplicate.push("pfctl:/sbin/pfctl -E:stdin_sha256=".into());
        assert!(acquisitions(&duplicate, &[s.clone(), s]).is_err());
    }
    #[test]
    fn settlement_needs_complete_matching_token_pid_and_records_fingerprint() {
        for rows in [
            None,
            Some(vec![RefLine {
                token: 42,
                pid: 124,
                timestamp: 999,
            }]),
            Some(vec![RefLine {
                token: 43,
                pid: 123,
                timestamp: 999,
            }]),
            Some(vec![RefLine {
                token: 42,
                pid: 123,
                timestamp: 999,
            }]),
        ] {
            let (s, mut trace) = dispatched();
            let matched = rows
                .as_ref()
                .is_some_and(|r| r[0].token == 42 && r[0].pid == 123);
            if let Some(rows) = rows {
                trace.push(refs_result(&rows));
            }
            let token = settled(&s);
            for copy in [Copy::A, Copy::B] {
                write(&mut trace, copy, &token, &WriteOutcome::Synced);
            }
            assert_eq!(
                acquisitions(&trace, &[token.clone(), token]).is_ok(),
                matched
            );
        }
    }
    #[test]
    fn unresolved_debt_must_survive_and_foreign_release_is_rejected() {
        let (s, mut trace) = dispatched();
        assert!(acquisitions(&trace, &[s.clone(), settled(&s)]).is_err());
        trace.push("pfctl:/sbin/pfctl -X 42:stdin_sha256=".into());
        assert!(acquisitions(&trace, &[s.clone(), s]).is_err());
    }
    #[test]
    fn busy_request_cannot_replace_outstanding_write_evidence() {
        let s = reserved();
        let mut trace = vec![];
        write(&mut trace, Copy::A, &s, &WriteOutcome::TimedOut);
        write(&mut trace, Copy::B, &s, &WriteOutcome::Busy);
        trace.push(write_result(&WriteOutcome::Synced));
        trace.push("pfctl:/sbin/pfctl -E:stdin_sha256=".into());
        assert!(acquisitions(&trace, &[s.clone(), s]).is_err());
    }

    #[test]
    fn failed_rewrite_invalidates_previous_sync_authority() {
        let s = reserved();
        let mut trace = vec![];
        for copy in [Copy::A, Copy::B] {
            write(&mut trace, copy, &s, &WriteOutcome::Synced);
        }
        write(
            &mut trace,
            Copy::B,
            &s,
            &WriteOutcome::Failed(crate::platform::SysError::Unknown),
        );
        trace.push("pfctl:/sbin/pfctl -E:stdin_sha256=".into());
        assert!(acquisitions(&trace, &[s.clone(), s]).is_err());
    }
    #[test]
    fn release_requires_a_recorded_settlement_fingerprint() {
        let (s, mut trace) = dispatched();
        trace.push(refs_result(&[RefLine {
            token: 42,
            pid: 123,
            timestamp: 999,
        }]));
        let token = settled(&s);
        for copy in [Copy::A, Copy::B] {
            write(&mut trace, copy, &token, &WriteOutcome::Synced);
        }
        trace.push("pfctl:/sbin/pfctl -X 42:stdin_sha256=".into());
        assert_eq!(acquisitions(&trace, &[token.clone(), token.clone()]), Ok(1));
        trace.push("pfctl:/sbin/pfctl -X 999:stdin_sha256=".into());
        assert!(acquisitions(&trace, &[token.clone(), token]).is_err());
    }
    #[test]
    fn trace_is_bounded_and_omits_hot_calls() {
        let mut trace = vec![];
        for c in ["now", "pause", "fence"] {
            record(&mut trace, c);
        }
        assert_eq!(trace, Vec::<String>::new());
        for _ in 0..20_000 {
            record(&mut trace, "call");
        }
        assert_eq!(trace.len(), 16_385);
        assert_eq!(trace.last().map(String::as_str), Some(OVERFLOW));
    }
}
