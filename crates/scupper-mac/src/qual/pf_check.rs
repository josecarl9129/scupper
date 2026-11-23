//! Portable assertions shared with the disposable native pf campaign.
use crate::{
    decode::pftoken::{Classification, EnumerationEvent, STRIDE},
    platform::{RefLine, SysError},
};
use std::time::Duration;

pub(super) fn deadline_seconds(left: Duration) -> Result<u64, &'static str> {
    if left.as_secs() < 2 {
        return Err("pf case deadline expired");
    }
    Ok(left.as_secs().min(8))
}

// Includes the ordinary read allowance plus half a second per acquisition.
pub(super) fn injection_seconds(left: Duration, k: usize) -> Result<u64, &'static str> {
    deadline_seconds(left)?;
    Ok(left
        .as_secs()
        .min(8 + u64::try_from(k).unwrap_or(u64::MAX - 16).div_ceil(2)))
}

pub(super) fn references_result(
    result: crate::platform::Enumeration<Vec<RefLine>>,
    timeout_label: &str,
) -> Result<Vec<RefLine>, String> {
    match result {
        crate::platform::Enumeration::Complete(lines) => Ok(lines),
        crate::platform::Enumeration::Incomplete(SysError::TimedOut) => {
            Err(format!("{timeout_label}: references TimedOut"))
        }
        crate::platform::Enumeration::Incomplete(e) => Err(format!("references incomplete: {e:?}")),
    }
}

pub(super) fn sole_release_text(
    build: &crate::decode::pftext::Build,
    rc: i32,
    stdout: &[u8],
    stderr: &[u8],
    token: u64,
) -> bool {
    use crate::{decode::pftext, platform::Release};
    stdout.is_empty()
        && stderr == [pftext::ALTQ_PREAMBLE, b"pf disabled\n"].concat()
        && pftext::release(build, rc, stdout, stderr, token) == Ok(Release::Requested)
}

// true denotes environmental text drift; false is a model contradiction.
pub(super) fn release_result(acknowledged: bool, absent: bool) -> Result<(), (bool, &'static str)> {
    if !acknowledged {
        return Err((true, "release text unrecognized"));
    }
    if !absent {
        return Err((
            false,
            "acknowledged release fingerprint/inventory contradiction",
        ));
    }
    Ok(())
}

// The cleanup runs even if deadline construction fails before enumeration starts.
pub(super) fn injection_scope<T, R>(
    state: &mut T,
    run: impl FnOnce(&mut T) -> R,
    disarm: impl FnOnce(&mut T),
) -> R {
    struct Guard<'a, T, F: FnOnce(&mut T)> {
        state: &'a mut T,
        disarm: Option<F>,
    }
    impl<T, F: FnOnce(&mut T)> Drop for Guard<'_, T, F> {
        fn drop(&mut self) {
            if let Some(disarm) = self.disarm.take() {
                disarm(self.state);
            }
        }
    }
    let guard = Guard {
        state,
        disarm: Some(disarm),
    };
    run(guard.state)
}

pub(super) fn enable_result(
    actual: &Result<crate::platform::PfEnable, SysError>,
    expected: crate::platform::PfEnable,
    timed_out: bool,
) -> Result<(), String> {
    if timed_out || actual == &Err(SysError::TimedOut) {
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

pub(super) fn first_copy_result(events: &[EnumerationEvent]) -> Result<(), &'static str> {
    if events.contains(&EnumerationEvent::FirstCopyFailed) {
        Err("first copy ioctl failed; injection evidence unavailable")
    } else {
        Ok(())
    }
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
        for ms in [0, 1, 999, 1000, 1001, 1500, 1999] {
            assert_eq!(
                deadline_seconds(Duration::from_millis(ms)),
                Err("pf case deadline expired")
            );
        }
        assert_eq!(deadline_seconds(Duration::from_secs(2)), Ok(2));
        assert_eq!(deadline_seconds(Duration::from_secs(20)), Ok(8));
        assert!(
            enable_result(
                &Err(SysError::TimedOut),
                crate::platform::PfEnable::Started,
                false
            )
            .unwrap_err()
            .contains("pf case deadline expired")
        );
        assert!(
            enable_result(
                &Err(SysError::Unknown),
                crate::platform::PfEnable::AlreadyRunning,
                false
            )
            .unwrap_err()
            .contains("Err(Unknown)")
        );
    }
    #[test]
    fn injection_windows_scale_cap_and_fit_q_refs() {
        let left = Duration::from_mins(15);
        assert_eq!(injection_seconds(left, 0), Ok(8));
        assert_eq!(injection_seconds(left, 35), Ok(26));
        assert_eq!(injection_seconds(Duration::from_secs(12), 35), Ok(12));
        assert!(injection_seconds(Duration::from_millis(1999), 35).is_err());
        let mut windows = 0;
        let mut acquisitions = 0;
        let mut count = 0;
        for spare in [0, 1, 16] {
            for k in scenarios(spare) {
                count += 1;
                acquisitions += k;
                windows += injection_seconds(left, k).unwrap();
            }
        }
        assert_eq!((count, acquisitions, windows), (15, 118, 183));
        let manifest = super::super::Manifest::bundled().unwrap();
        let budget = manifest
            .cases
            .iter()
            .find(|c| c.id == "Q-REFS")
            .unwrap()
            .budget_minutes
            * 60;
        // Existing allowance: 500 fingerprint pairs at .8s, 120s churn/raw,
        // plus .4s per independent injected release and 60s cleanup/slack.
        assert!(
            400 + 120 + windows + (u64::try_from(acquisitions).unwrap() * 2).div_ceil(5) + 60
                < u64::from(budget)
        );
        assert_eq!(
            references_result(
                crate::platform::Enumeration::Incomplete(SysError::TimedOut),
                "injection window exceeded read deadline"
            )
            .unwrap_err(),
            "injection window exceeded read deadline: references TimedOut"
        );
    }

    #[test]
    fn unreaped_enable_timeout_retains_deadline_detail_in_qualification() {
        let detail = enable_result(
            &Err(SysError::Unknown),
            crate::platform::PfEnable::Started,
            true,
        )
        .unwrap_err();
        assert_eq!(detail, "pf case deadline expired: Err(Unknown)");
    }

    #[test]
    fn sole_runner_requires_exact_bytes_and_inventory_contradictions_are_contract_errors() {
        use crate::decode::pftext::{self, Build};
        let build = Build::fixture("24H232");
        let row = [pftext::ALTQ_PREAMBLE, b"pf disabled\n"].concat();
        assert!(sole_release_text(&build, 0, b"", &row, 42));
        let other = [pftext::ALTQ_PREAMBLE, b"disable request successful. 1 more pf enable reference(s) remaining, pf still enabled.\n"].concat();
        assert_eq!(
            pftext::release(&build, 0, b"", &other, 42),
            Ok(crate::platform::Release::Requested)
        );
        assert!(!sole_release_text(&build, 0, b"", &other, 42));
        assert!(!sole_release_text(&build, 0, b"unexpected", &row, 42));
        assert_eq!(release_result(true, true), Ok(()));
        assert_eq!(
            release_result(true, false),
            Err((
                false,
                "acknowledged release fingerprint/inventory contradiction"
            ))
        );
        assert_eq!(
            release_result(false, true),
            Err((true, "release text unrecognized"))
        );
        let campaign = include_str!("pf.rs");
        assert!(campaign.contains("check_release(acknowledged, !after.contains(&before))"));
        assert!(campaign.contains("pf_check::sole_release_text("));
        assert!(campaign.contains("if environment {"));
    }

    #[test]
    fn unfired_injection_disarms_on_deadline_error_and_scope_exit() {
        for fail in [true, false] {
            let mut armed = Some(42);
            let result = injection_scope(
                &mut armed,
                |slot| {
                    assert_eq!(*slot, Some(42));
                    if fail {
                        deadline_seconds(Duration::ZERO)?;
                    }
                    *slot = None; // a fired hook was consumed
                    Ok::<_, &str>(())
                },
                |slot| {
                    slot.take();
                },
            );
            assert_eq!(result.is_err(), fail);
            assert!(armed.is_none());
        }
    }

    #[test]
    fn first_copy_failure_never_reports_later_resized_copy_as_first() {
        use crate::decode::pftoken::{self, ReadError};
        let mut copies = 0;
        let mut events = vec![];
        let result = pftoken::enumerate_with_injection(
            |bytes| {
                if bytes.is_empty() {
                    return Ok(STRIDE);
                }
                copies += 1;
                if copies == 1 {
                    return Err(ReadError::Other);
                }
                bytes[..STRIDE].copy_from_slice(&packed(&RefLine {
                    token: 1,
                    pid: 42,
                    timestamp: 1,
                }));
                Ok(STRIDE)
            },
            || false,
            1,
            |e| events.push(e),
            || Ok(()),
        );
        assert!(result.is_ok());
        assert!(events.contains(&EnumerationEvent::FirstCopyFailed));
        assert!(
            !events
                .iter()
                .any(|e| matches!(e, EnumerationEvent::FirstCopy { .. }))
        );
        assert_eq!(
            first_copy_result(&events),
            Err("first copy ioctl failed; injection evidence unavailable")
        );
        assert!(include_str!("pf.rs").contains("pf_check::first_copy_result(&events)"));
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
        assert!(native.contains("if self.pf_reference_injection.take().is_some()"));
        assert!(native.contains(".store(true, std::sync::atomic::Ordering::Release)"));
        let campaign = include_str!("pf.rs");
        assert!(campaign.contains("pf_check::deadline_seconds(left)"));
        assert!(campaign.contains("pf_check::injection_seconds(left, k)"));
        assert!(campaign.contains("pf_check::injection_scope("));
        assert!(campaign.contains("NativePlatform::disarm_reference_injection"));
        assert!(campaign.contains("enable_pf_observed"));
        assert!(native.contains("attempt.as_ref().is_ok_and(|(_, result)| result.timed_out)"));
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
