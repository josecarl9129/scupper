//! Portable assertions shared with the disposable native pf campaign.
use crate::{
    decode::pftoken::{Classification, EnumerationEvent, STRIDE},
    platform::{RefLine, SysError},
};
use std::time::Duration;

pub(super) fn deadline_seconds(left: Duration) -> Result<u64, &'static str> {
    if left.as_secs() == 0 {
        return Err("pf case deadline expired");
    }
    Ok(left.as_secs().min(8))
}

pub(super) fn enable_result(
    actual: &Result<crate::platform::PfEnable, SysError>,
    expected: crate::platform::PfEnable,
) -> Result<(), String> {
    if actual == &Err(SysError::TimedOut) {
        return Err(format!("pf case deadline expired: {actual:?}"));
    }
    if actual != &Ok(expected) {
        return Err(format!("enable expected {expected:?}, actual {actual:?}"));
    }
    Ok(())
}

pub(super) fn worker_error(count: &serde_json::Value) -> Result<(), (bool, String)> {
    if count["error"].is_null() {
        return Ok(());
    }
    Err((
        count["environment_error"] == true,
        format!("churn worker: {}", count["error"]),
    ))
}

// Release is deliberately outside the enumerate closure: even the first copy
// must still see every injected reference held. On errors journaled restore owns
// cleanup, since a timed-out reader might still be acquiring references.
pub(super) fn injection_trial<T, E>(
    enumerate: impl FnOnce() -> Result<T, E>,
    release: impl FnOnce() -> Result<(), E>,
) -> Result<T, E> {
    let result = enumerate()?;
    release()?;
    Ok(result)
}

pub(super) fn check_injection(
    spare: usize,
    k: usize,
    held: &[RefLine],
    injected: &[RefLine],
    events: &[EnumerationEvent],
    complete: &[RefLine],
) -> Result<(), &'static str> {
    let require = |ok, error| if ok { Ok(()) } else { Err(error) };
    require(injected.len() == k, "injection acquisition count")?;
    require(held.len() == 8, "eight long-lived fingerprints required")?;
    let first = events.iter().find_map(|e| {
        if let EnumerationEvent::Copy(c) = e {
            Some(*c)
        } else {
            None
        }
    });
    let expected = if k < spare {
        Classification::Complete
    } else {
        Classification::Retry
    };
    require(first == Some(expected), "first copy classification")?;
    let (capacity, records) = events
        .iter()
        .find_map(|e| {
            if let EnumerationEvent::FirstCopy { capacity, records } = e {
                Some((*capacity, records))
            } else {
                None
            }
        })
        .ok_or("first copy evidence missing")?;
    require(
        capacity == (held.len() + spare) * STRIDE && capacity.is_multiple_of(STRIDE),
        "fixed aligned first copy capacity",
    )?;
    require(
        records.len() == (held.len() + k).min(capacity / STRIDE)
            && records.iter().all(|r| complete.contains(r)),
        "first copy contents/count",
    )?;
    if k <= spare {
        require(
            held.iter().chain(injected).all(|r| records.contains(r)),
            "first copy unexpectedly truncated",
        )?;
    }
    if k > spare {
        require(
            !records.contains(&held[0]),
            "first copy must omit oldest held fingerprint",
        )?;
        require(
            events.contains(&EnumerationEvent::GrowthPastCopyCapacity),
            "growth past copy capacity missing",
        )?;
    }
    require(
        held.iter().chain(injected).all(|r| complete.contains(r)),
        "Complete omitted a held or injected fingerprint",
    )?;
    require(
        events.contains(&EnumerationEvent::Copy(Classification::Complete)),
        "final copy not Complete",
    )
}

pub(super) fn scenarios(spare: usize) -> Vec<usize> {
    let mut ks = vec![0, spare, spare + 1, spare + 2, 2 * spare + 3];
    if let Some(k) = spare.checked_sub(1) {
        ks.push(k);
    }
    ks.sort_unstable();
    ks.dedup();
    ks
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn deadline_never_hands_out_expired_seconds_and_timeout_keeps_detail() {
        for ms in [0, 1, 999] {
            assert_eq!(
                deadline_seconds(Duration::from_millis(ms)),
                Err("pf case deadline expired")
            );
        }
        assert_eq!(deadline_seconds(Duration::from_secs(1)), Ok(1));
        assert_eq!(deadline_seconds(Duration::from_secs(20)), Ok(8));
        assert!(
            enable_result(&Err(SysError::TimedOut), crate::platform::PfEnable::Started)
                .unwrap_err()
                .contains("pf case deadline expired")
        );
        assert!(
            enable_result(
                &Err(SysError::Unknown),
                crate::platform::PfEnable::AlreadyRunning
            )
            .unwrap_err()
            .contains("Err(Unknown)")
        );
    }
    #[test]
    fn injected_references_are_released_after_enumeration_returns() {
        let returned = std::cell::Cell::new(false);
        let released = std::cell::Cell::new(false);
        let result = injection_trial(
            || {
                assert!(!released.get());
                returned.set(true);
                Ok::<_, ()>(42)
            },
            || {
                assert!(
                    returned.get(),
                    "assertion: release before enumeration returned"
                );
                released.set(true);
                Ok(())
            },
        );
        assert_eq!(result, Ok(42));
        assert!(released.get());
        let result = injection_trial(
            || Err::<(), _>("incomplete"),
            || -> Result<(), &str> { panic!("unknown worker must remain journaled") },
        );
        assert_eq!(result, Err("incomplete"));
    }
    #[test]
    fn injection_checks_require_actual_oldest_omission() {
        let held: Vec<_> = (1..=8)
            .map(|token| RefLine {
                token,
                pid: 42,
                timestamp: 1,
            })
            .collect();
        let injected = vec![RefLine {
            token: 9,
            pid: 42,
            timestamp: 1,
        }];
        let complete: Vec<_> = held.iter().chain(&injected).cloned().collect();
        let mut events = vec![
            EnumerationEvent::Copy(Classification::Retry),
            EnumerationEvent::FirstCopy {
                capacity: 8 * STRIDE,
                records: complete[1..].to_vec(),
            },
            EnumerationEvent::GrowthPastCopyCapacity,
            EnumerationEvent::Copy(Classification::Complete),
        ];
        assert_eq!(
            check_injection(0, 1, &held, &injected, &events, &complete),
            Ok(())
        );
        events[1] = EnumerationEvent::FirstCopy {
            capacity: 8 * STRIDE,
            records: held.clone(),
        };
        assert_eq!(
            check_injection(0, 1, &held, &injected, &events, &complete),
            Err("first copy must omit oldest held fingerprint")
        );
    }
    #[test]
    fn worker_environment_errors_keep_inconclusive_classification() {
        use serde_json::json;
        assert_eq!(worker_error(&json!({"error":null})), Ok(()));
        for environment in [true, false] {
            let (actual, detail) = worker_error(
                &json!({"error":"references incomplete", "environment_error":environment}),
            )
            .unwrap_err();
            assert_eq!(actual, environment);
            assert!(detail.contains("references incomplete"));
        }
    }
    #[test]
    fn native_qualification_wires_real_injection_and_budget_checks() {
        let native = include_str!("../native/pf.rs");
        assert!(native.contains("pftoken::enumerate_with_injection("));
        assert!(native.contains("injection.map_or(Ok(()), |inject| inject())"));
        let campaign = include_str!("pf.rs");
        assert!(campaign.contains("pf_check::deadline_seconds(left)"));
        assert!(campaign.contains("p.reference_injection(Box::new(move ||"));
        assert!(campaign.contains("injector.acquire(deadline(end)?)"));
        assert!(campaign.contains("pf_check::check_injection("));
        assert!(campaign.contains("pf_check::injection_trial("));
        assert!(!campaign.contains("coverage_missing"));
        assert!(campaign.contains("let cleanup = reset(out, p,"));
    }

    fn packed(r: &RefLine) -> Vec<u8> {
        let mut bytes = vec![0; STRIDE];
        bytes[..8].copy_from_slice(&r.token.to_le_bytes());
        bytes[8..16].copy_from_slice(&r.timestamp.to_le_bytes());
        bytes[16..20].copy_from_slice(&r.pid.to_le_bytes());
        bytes
    }
    #[test]
    fn scripted_same_table_injection_covers_every_spare_boundary() {
        use crate::decode::pftoken;
        use std::{cell::RefCell, rc::Rc};
        // Acquisition sequence deliberately differs from numeric token order.
        let held: Vec<_> = [81, 2, 73, 4, 65, 6, 57, 8]
            .into_iter()
            .map(|token| RefLine {
                token,
                pid: 42,
                timestamp: 123,
            })
            .collect();
        for spare in [0, 1, 16] {
            for k in scenarios(spare) {
                let table = Rc::new(RefCell::new(held.iter().rev().cloned().collect::<Vec<_>>()));
                let writer = table.clone();
                let injected = RefCell::new(Vec::new());
                let mut events = Vec::new();
                let mut calls = 0;
                let result = pftoken::enumerate_with_injection(
                    |bytes| {
                        assert!(bytes.len().is_multiple_of(STRIDE));
                        let table = table.borrow();
                        if bytes.is_empty() {
                            return Ok(table.len() * STRIDE);
                        }
                        let records = table.len().min(bytes.len() / STRIDE);
                        for (chunk, r) in bytes
                            .as_chunks_mut::<STRIDE>()
                            .0
                            .iter_mut()
                            .zip(table.iter())
                        {
                            chunk.copy_from_slice(&packed(r));
                        }
                        Ok(records * STRIDE)
                    },
                    || false,
                    spare,
                    |e| events.push(e),
                    || {
                        calls += 1;
                        for i in 0..k {
                            let r = RefLine {
                                token: 100 + u64::try_from(i).unwrap(),
                                pid: 42,
                                timestamp: 123,
                            };
                            injected.borrow_mut().push(r.clone());
                            writer.borrow_mut().insert(0, r);
                        }
                        Ok(())
                    },
                )
                .unwrap();
                assert_eq!(calls, 1);
                assert_eq!(injected.borrow().len(), k);
                assert_eq!(
                    check_injection(spare, k, &held, &injected.borrow(), &events, &result),
                    Ok(()),
                    "spare={spare} k={k}"
                );
                assert_eq!(result, *table.borrow());
            }
        }
    }
    #[test]
    fn persistent_same_table_growth_is_bounded_churn_never_complete() {
        use crate::decode::pftoken;
        let mut count = 8;
        let mut copies = 0;
        let result = pftoken::enumerate_with_spare(
            |bytes| {
                assert!(bytes.len().is_multiple_of(STRIDE));
                if bytes.is_empty() {
                    return Ok(count * STRIDE);
                }
                count = bytes.len() / STRIDE + 1;
                copies += 1;
                for (i, chunk) in bytes.as_chunks_mut::<STRIDE>().0.iter_mut().enumerate() {
                    chunk.copy_from_slice(&packed(&RefLine {
                        token: u64::try_from(count - i).unwrap(),
                        pid: 42,
                        timestamp: 123,
                    }));
                }
                Ok(bytes.len())
            },
            || false,
            1,
            |_| {},
        );
        assert_eq!(result, Err(SysError::Failed("churn")));
        assert_eq!(copies, 8);
    }
}
