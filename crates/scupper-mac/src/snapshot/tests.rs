#![allow(clippy::unwrap_used, clippy::panic)] // Test fixtures must fail loudly.
use super::*;
use proptest::prelude::*;
use scupper_core::mac::{
    DhcpPhase, HopLimitPolicy, Inputs, Tunnel,
    lifecycle::{Event, Machine, ReferenceEntry, ReferenceSettlement},
    parse, policy,
    verify::{
        self, AnchorObservation, Expected, IdentityEvidence, LiveTree, Normalization, Observations,
        Qualification, SelectedPath, SleepCountingClock, StateEvidence, StepOutcome, ToolIntegrity,
        Transport, Verdict,
    },
};
use serde_json::json;
use std::{cell::Cell, collections::BTreeMap};

fn boot() -> BootId {
    "01234567-89AB-CDEF-0123-456789ABCDEF".try_into().unwrap()
}
fn helper(pid: u32) -> HelperIncarnation {
    HelperIncarnation {
        pid,
        start: StartTime {
            seconds: u64::MAX,
            microseconds: 999_999,
        },
        pgid: u32::MAX,
        boot: Some(boot()),
    }
}
fn evidence(key: ReferenceEntry) -> RefEvidence {
    RefEvidence {
        key,
        boot: Some(boot()),
        release_unknown: false,
        fingerprint: None,
    }
}
// Bypass encoder validation to exercise authenticated but invalid bodies.
fn raw(seq: u64, body: &[u8]) -> Vec<u8> {
    assert!(body.len() <= BODY_MAX);
    let mut bytes = vec![0; COPY_BYTES];
    bytes[..8].copy_from_slice(&MAGIC);
    bytes[8..12].copy_from_slice(&FORMAT.to_le_bytes());
    bytes[12..20].copy_from_slice(&seq.to_le_bytes());
    bytes[20..24].copy_from_slice(&u32::try_from(body.len()).unwrap().to_le_bytes());
    let end = 24 + body.len();
    bytes[24..end].copy_from_slice(body);
    let digest = Sha256::digest(&bytes[..end]);
    bytes[end..end + 32].copy_from_slice(&digest);
    bytes
}
fn class(seq: u64, snapshot: &Snapshot) -> CopyClass {
    classify_copy(CopyRead::Bytes(encode(seq, snapshot).unwrap().to_vec()))
}
fn initial_class(seq: u64) -> CopyClass {
    class(seq, &Snapshot::initial(None))
}
fn is_invalid(bytes: Vec<u8>) {
    assert!(matches!(
        classify_copy(CopyRead::Bytes(bytes)),
        CopyClass::I { .. }
    ));
}
fn is_recovery(a: CopyClass, b: CopyClass, seq: u64) {
    assert!(matches!(decide(a, b), StartDecision::Recovery { seq: found, .. } if found == seq));
}
fn assert_trust(a: CopyClass, b: CopyClass, source: Copy, seq: u64, repair: Option<Copy>) {
    assert_eq!(
        decide(a, b),
        StartDecision::Trust {
            source,
            seq,
            snapshot: Snapshot::initial(None),
            repair
        }
    );
}

#[test]
fn initial_and_recovery_are_valid_and_restart_with_hold() {
    let initial = Snapshot::initial(Some(42));
    assert_eq!(initial.validate().unwrap(), Durable::default());
    let recovery = Snapshot::recovery(
        Some(boot()),
        Some("255.255.255.255:65535".parse().unwrap()),
        Some(u32::MAX),
        Some(helper(100)),
    );
    let d = recovery.validate().unwrap();
    assert!(d.join_intended && d.hold);
    assert_eq!(d.uncertain_acquires, [1, 2]);
    assert_eq!(d.reference_sequence, 2);
    let restarted = Machine::restart(d.clone());
    assert!(restarted.durable().hold);
    assert_eq!(restarted.durable().uncertain_acquires, [1, 2]);
    assert_eq!(
        recovery.references,
        [1, 2].map(|s| Some(evidence(ReferenceEntry::Acquire(s))))
    );
    assert!(recovery.requests.is_empty());
    assert!(recovery.internal_error.is_none());
    assert_eq!(recovery.validate().unwrap(), d);
    assert!(matches!(class(1, &recovery), CopyClass::V { snapshot, .. } if snapshot == recovery));
}

#[test]
fn boot_start_time_unknown_fields_and_request_states() {
    assert!(BootId::try_from("01234567-89ab-cdef-0123-456789abcdef").is_err());
    assert!(BootId::try_from("01234567_89AB-CDEF-0123-456789ABCDEF").is_err());
    assert!(BootId::try_from("01234567-89AB-CDEF-0123-456789ABCDE").is_err());
    assert!(
        serde_json::from_value::<StartTime>(json!({"seconds": 0, "microseconds": 1_000_000}))
            .is_err()
    );
    for kind in [
        RequestKind::Join,
        RequestKind::Leave,
        RequestKind::JoinDone,
        RequestKind::LeaveDone,
        RequestKind::JoinCancelled,
        RequestKind::JoinDoneCancelled,
    ] {
        let request = RequestRecord {
            id: COUNTER_MAX - 1,
            kind,
        };
        assert_eq!(
            serde_json::from_slice::<RequestRecord>(&serde_json::to_vec(&request).unwrap())
                .unwrap(),
            request
        );
    }
    let mut values = vec![
        serde_json::to_value(Snapshot::initial(None)).unwrap(),
        serde_json::to_value(DurableRecord::default()).unwrap(),
        serde_json::to_value(evidence(ReferenceEntry::Token(1))).unwrap(),
        serde_json::to_value(helper(1)).unwrap(),
        serde_json::to_value(StartTime {
            seconds: 0,
            microseconds: 0,
        })
        .unwrap(),
        serde_json::to_value(RefFingerprint {
            pid: 1,
            timestamp: 0,
        })
        .unwrap(),
        serde_json::to_value(RequestRecord {
            id: 1,
            kind: RequestKind::Join,
        })
        .unwrap(),
        serde_json::to_value(StepRecord::from(Step::StopChild)).unwrap(),
        serde_json::to_value(ReasonRecord::try_from(&Reason::HookMissing).unwrap()).unwrap(),
    ];
    for v in &mut values {
        v["unknown"] = json!(true);
    }
    assert!(serde_json::from_value::<Snapshot>(values[0].clone()).is_err());
    assert!(serde_json::from_value::<DurableRecord>(values[1].clone()).is_err());
    assert!(serde_json::from_value::<RefEvidence>(values[2].clone()).is_err());
    assert!(serde_json::from_value::<HelperIncarnation>(values[3].clone()).is_err());
    assert!(serde_json::from_value::<StartTime>(values[4].clone()).is_err());
    assert!(serde_json::from_value::<RefFingerprint>(values[5].clone()).is_err());
    assert!(serde_json::from_value::<RequestRecord>(values[6].clone()).is_err());
    assert!(serde_json::from_value::<StepRecord>(values[7].clone()).is_err());
    assert!(serde_json::from_value::<ReasonRecord>(values[8].clone()).is_err());
}

#[test]
fn bounded_decode_and_counter_limits() {
    let original = serde_json::to_value(Snapshot::initial(None)).unwrap();
    let bad_fields = [
        ("older_references", json!([1, 2])),
        ("uncertain_acquires", json!([1, 2, 3])),
        (
            "pending_cleanup",
            json!(vec![StepRecord::from(Step::StopChild); 7]),
        ),
        (
            "cleanup_errors",
            json!(vec![
                (
                    StepRecord::from(Step::StopChild),
                    ReasonRecord::try_from(&Reason::HookMissing).unwrap()
                );
                9
            ]),
        ),
        ("reference_sequence", json!(COUNTER_MAX)),
        ("previous_generation", json!(COUNTER_MAX)),
        (
            "last_error",
            json!({"kind":5,"text":"x".repeat(257),"argument":0}),
        ),
        ("last_error", json!({"kind":5,"text":"bad!","argument":0})),
        ("unknown", json!(false)),
    ];
    for (field, value) in bad_fields {
        let mut v = original.clone();
        v["machine"][field] = value;
        let body = serde_json::to_vec(&v).unwrap();
        assert!(
            serde_json::from_slice::<Snapshot>(&body).is_err(),
            "{field}"
        );
        is_invalid(raw(1, &body));
    }
    let mut requests = original.clone();
    requests["requests"] = json!(vec![
        RequestRecord {
            id: 1,
            kind: RequestKind::Join
        };
        9
    ]);
    assert!(serde_json::from_value::<Snapshot>(requests).is_err());
    let mut requests = original;
    requests["requests"] = json!([{"id": COUNTER_MAX, "kind": "Join"}]);
    assert!(serde_json::from_value::<Snapshot>(requests).is_err());
    let mut trailing = serde_json::to_vec(&Snapshot::initial(None)).unwrap();
    trailing.extend_from_slice(b" {}");
    is_invalid(raw(1, &trailing));
    is_invalid(raw(
        COUNTER_MAX,
        &serde_json::to_vec(&Snapshot::initial(None)).unwrap(),
    ));
    assert_eq!(
        encode(COUNTER_MAX, &Snapshot::initial(None)),
        Err(SnapshotError::Counter)
    );
    assert!(
        serde_json::from_str::<BoundedText<256>>(&format!("\"{}\"", "x".repeat(1_000_000)))
            .is_err()
    );
    assert!(serde_json::from_str::<BoundedText<256>>(r#""escaped\u0021""#).is_err());
    assert!(serde_json::from_str::<BoundedText<256>>(r#""é""#).is_err());
}

thread_local! { static ELEMENTS: Cell<usize> = const { Cell::new(0) }; }
#[derive(Debug)]
struct Counted;
impl<'de> Deserialize<'de> for Counted {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        ELEMENTS.with(|n| n.set(n.get() + 1));
        u8::deserialize(d)?;
        Ok(Self)
    }
}
#[test]
fn million_element_array_rejects_before_deserializing_or_allocating_element_n_plus_one() {
    let input = format!("[{}0]", "0,".repeat(999_999));
    ELEMENTS.with(|n| n.set(0));
    assert!(serde_json::from_str::<BoundedVec<Counted, 6>>(&input).is_err());
    ELEMENTS.with(|n| assert_eq!(n.get(), 6));
    let mut values = BoundedVec::<u8, 6>::default();
    for i in 0..6 {
        values.try_push(i).unwrap();
        assert!(values.0.capacity() <= 6);
    }
    assert_eq!(values.try_push(7), Err(SnapshotError::Bound));
    assert_eq!(values.0.capacity(), 6);
    assert!(serde_json::from_str::<BoundedVec<u8, 0>>("[]").is_ok());
    assert!(serde_json::from_str::<BoundedVec<u8, 0>>("[0]").is_err());
}

#[test]
fn classification_v() {
    assert!(matches!(initial_class(1), CopyClass::V { seq: 1, .. }));
}
#[test]
fn classification_i() {
    is_invalid(raw(3, b"{}"));
}
#[test]
fn classification_x() {
    let mut unknown = encode(5, &Snapshot::initial(None)).unwrap().to_vec();
    unknown[8..12].copy_from_slice(&2_u32.to_le_bytes());
    unknown[12..20].copy_from_slice(&u64::MAX.to_le_bytes());
    assert_eq!(classify_copy(CopyRead::Bytes(unknown)), CopyClass::X);
}
#[test]
fn classification_m() {
    assert_eq!(classify_copy(CopyRead::Missing), CopyClass::M);
}
#[test]
fn classification_u() {
    assert_eq!(classify_copy(CopyRead::Unreadable), CopyClass::U);
}
#[test]
fn classification_t_wrong_length() {
    for len in [0, 8, COPY_BYTES - 1, COPY_BYTES + 1] {
        assert_eq!(classify_copy(CopyRead::Bytes(vec![0; len])), CopyClass::T);
    }
}
#[test]
fn classification_t_bad_magic() {
    let mut bytes = encode(1, &Snapshot::initial(None)).unwrap().to_vec();
    bytes[0] ^= 1;
    assert_eq!(classify_copy(CopyRead::Bytes(bytes)), CopyClass::T);
}
#[test]
fn classification_t_body_len() {
    let mut bytes = encode(1, &Snapshot::initial(None)).unwrap().to_vec();
    bytes[20..24].copy_from_slice(&u32::try_from(BODY_MAX + 1).unwrap().to_le_bytes());
    assert_eq!(classify_copy(CopyRead::Bytes(bytes)), CopyClass::T);
}
#[test]
fn classification_t_checksum() {
    let original = encode(1, &Snapshot::initial(None)).unwrap().to_vec();
    let end = 24 + serde_json::to_vec(&Snapshot::initial(None)).unwrap().len();
    for pos in [12, 24, end] {
        let mut bytes = original.clone();
        bytes[pos] ^= 1;
        assert_eq!(
            classify_copy(CopyRead::Bytes(bytes)),
            CopyClass::T,
            "byte {pos}"
        );
    }
}
#[test]
fn nonzero_padding_is_i_and_not_t() {
    let mut bytes = encode(1, &Snapshot::initial(None)).unwrap().to_vec();
    bytes[COPY_BYTES - 1] = 1;
    is_invalid(bytes);
}

#[test]
fn all_36_start_table_pairs() {
    // Rows/columns V, I, X, T, M, U. Equal V copies are identical here.
    // R = Recovery, A/B = trusted source with repair except equal V/V.
    let expected = [
        ['A', 'R', 'A', 'A', 'A', 'A'],
        ['R', 'R', 'R', 'R', 'R', 'R'],
        ['R', 'R', 'R', 'R', 'R', 'R'],
        ['B', 'R', 'R', 'R', 'R', 'R'],
        ['B', 'R', 'R', 'R', 'R', 'R'],
        ['B', 'R', 'R', 'R', 'R', 'R'],
    ];
    let classes = [
        initial_class(5),
        CopyClass::I {
            seq: 5,
            helper: None,
        },
        CopyClass::X,
        CopyClass::T,
        CopyClass::M,
        CopyClass::U,
    ];
    for (i, a) in classes.iter().enumerate() {
        for (j, b) in classes.iter().enumerate() {
            let decision = decide(a.clone(), b.clone());
            match expected[i][j] {
                'A' => assert_eq!(
                    decision,
                    StartDecision::Trust {
                        source: Copy::A,
                        seq: 5,
                        snapshot: Snapshot::initial(None),
                        repair: (j != 0).then_some(Copy::B),
                    }
                ),
                'B' => assert_eq!(
                    decision,
                    StartDecision::Trust {
                        source: Copy::B,
                        seq: 5,
                        snapshot: Snapshot::initial(None),
                        repair: Some(Copy::A),
                    }
                ),
                'R' => assert_eq!(
                    decision,
                    StartDecision::Recovery {
                        seq: if i < 2 || j < 2 { 6 } else { 1 },
                        helper: None
                    }
                ),
                _ => unreachable!(),
            }
        }
    }
}
#[test]
fn start_ordering_equal_sequence_divergence_and_full_copy_comparison() {
    assert_trust(
        initial_class(5),
        initial_class(4),
        Copy::A,
        5,
        Some(Copy::B),
    );
    assert_trust(
        initial_class(5),
        CopyClass::I {
            seq: 4,
            helper: None,
        },
        Copy::A,
        5,
        Some(Copy::B),
    );
    is_recovery(initial_class(4), initial_class(5), 6);
    is_recovery(
        initial_class(4),
        CopyClass::I {
            seq: 5,
            helper: None,
        },
        6,
    );
    is_recovery(initial_class(5), class(5, &Snapshot::initial(Some(1))), 6);
    // A checksum does not make a noncanonical spelling valid.
    let body = format!(
        "{} ",
        serde_json::to_string(&Snapshot::initial(None)).unwrap()
    );
    let different_bytes = classify_copy(CopyRead::Bytes(raw(5, body.as_bytes())));
    assert!(matches!(different_bytes, CopyClass::I { .. }));
    is_recovery(initial_class(5), different_bytes, 6);
    assert_trust(CopyClass::T, initial_class(5), Copy::B, 5, Some(Copy::A));
    is_recovery(CopyClass::X, initial_class(5), 6);
}
#[test]
fn recovery_sequence_only_uses_authenticated_known_format_headers() {
    is_recovery(CopyClass::M, CopyClass::U, 1);
    is_recovery(
        CopyClass::I {
            seq: 100,
            helper: None,
        },
        initial_class(99),
        101,
    );
    for seq in [COUNTER_MAX - 1, COUNTER_MAX, u64::MAX] {
        is_recovery(CopyClass::I { seq, helper: None }, CopyClass::M, 1);
    }
    is_recovery(CopyClass::X, initial_class(COUNTER_MAX - 1), 1);
    is_recovery(
        CopyClass::X,
        initial_class(COUNTER_MAX - 2),
        COUNTER_MAX - 1,
    );
    let mut torn = encode(1, &Snapshot::initial(None)).unwrap().to_vec();
    torn[12..20].copy_from_slice(&1_000_000_000_u64.to_le_bytes());
    let torn = classify_copy(CopyRead::Bytes(torn));
    assert_eq!(torn, CopyClass::T);
    is_recovery(
        CopyClass::I {
            seq: 7,
            helper: None,
        },
        torn.clone(),
        8,
    );
    is_recovery(torn, CopyClass::M, 1);
    let mut unknown = raw(u64::MAX, b"{}");
    unknown[8..12].copy_from_slice(&2_u32.to_le_bytes());
    is_recovery(classify_copy(CopyRead::Bytes(unknown)), CopyClass::M, 1);
}
#[test]
#[allow(clippy::too_many_lines)] // Keep the helper preference and salvage matrix together.
fn recovery_helper_prefers_v_then_highest_sequence_and_salvages_i_object_only() {
    let mut a = Snapshot::initial(None);
    a.helper = Some(helper(1));
    let mut b = Snapshot::initial(None);
    b.helper = Some(helper(2));
    assert_eq!(
        decide(class(1, &a), class(2, &b)),
        StartDecision::Recovery {
            seq: 3,
            helper: Some(helper(2))
        }
    );
    assert_eq!(
        decide(
            CopyClass::I {
                seq: 100,
                helper: Some(helper(2))
            },
            class(1, &a)
        ),
        StartDecision::Recovery {
            seq: 101,
            helper: Some(helper(1))
        }
    );
    let partial = json!({"helper": helper(7), "machine": "broken", "arbitrary": [1, 2]});
    let invalid = classify_copy(CopyRead::Bytes(raw(
        9,
        &serde_json::to_vec(&partial).unwrap(),
    )));
    assert_eq!(
        invalid,
        CopyClass::I {
            seq: 9,
            helper: Some(helper(7))
        }
    );
    assert_eq!(
        decide(invalid.clone(), CopyClass::M),
        StartDecision::Recovery {
            seq: 10,
            helper: Some(helper(7))
        }
    );
    assert_eq!(
        decide(
            CopyClass::I {
                seq: 1,
                helper: Some(helper(1))
            },
            invalid.clone()
        ),
        StartDecision::Recovery {
            seq: 10,
            helper: Some(helper(7))
        }
    );
    assert_eq!(
        decide(
            CopyClass::I {
                seq: 20,
                helper: Some(helper(2))
            },
            invalid
        ),
        StartDecision::Recovery {
            seq: 21,
            helper: Some(helper(2))
        }
    );
    let bad_helper = json!({"helper": {"pid": 1, "pgid": 1, "start": {"seconds": 1,"microseconds": 1_000_000}, "boot": null}});
    for v in [
        bad_helper,
        json!([{"helper": helper(1)}]),
        json!({"helper": null}),
    ] {
        assert_eq!(
            classify_copy(CopyRead::Bytes(raw(1, &serde_json::to_vec(&v).unwrap()))),
            CopyClass::I {
                seq: 1,
                helper: None
            }
        );
    }
    let mut malformed = serde_json::to_vec(&partial).unwrap();
    malformed.push(b'!');
    assert_eq!(
        classify_copy(CopyRead::Bytes(raw(1, &malformed))),
        CopyClass::I {
            seq: 1,
            helper: None
        }
    );
    // A V without a helper does not hide a usable helper in I.
    assert_eq!(
        decide(
            CopyClass::I {
                seq: 3,
                helper: Some(helper(9))
            },
            initial_class(4)
        ),
        StartDecision::Recovery {
            seq: 5,
            helper: Some(helper(9))
        }
    );
}

#[test]
fn canonical_reference_validation_and_encoder_rejection() {
    let valid = Snapshot::recovery(None, None, None, None);
    let mut cases = Vec::new();
    let mut s = valid.clone();
    s.references[0] = None;
    cases.push(s);
    let mut s = valid.clone();
    s.references.swap(0, 1);
    cases.push(s);
    let mut s = valid.clone();
    s.references[1] = s.references[0].clone();
    cases.push(s);
    let mut s = valid.clone();
    s.machine.uncertain_acquires = vec![1, 1].try_into().unwrap();
    cases.push(s);
    let mut s = valid.clone();
    s.references[0].as_mut().unwrap().release_unknown = true;
    cases.push(s);
    let mut s = valid.clone();
    s.references[0].as_mut().unwrap().fingerprint = Some(RefFingerprint {
        pid: 1,
        timestamp: 1,
    });
    cases.push(s);
    let mut s = valid.clone();
    s.machine.reference_sequence = 1;
    cases.push(s);
    let mut s = valid.clone();
    s.machine.uncertain_acquires = vec![0, 2].try_into().unwrap();
    s.references[0].as_mut().unwrap().key = ReferenceEntry::Acquire(0);
    cases.push(s);
    let mut s = Snapshot::initial(None);
    s.references[1] = Some(evidence(ReferenceEntry::Token(10)));
    cases.push(s);
    let mut s = Snapshot::initial(None);
    s.machine.pf_reference = Some(0);
    s.references[0] = Some(evidence(ReferenceEntry::Token(0)));
    cases.push(s);
    let mut s = Snapshot::initial(None);
    s.machine.pf_reference = Some(7);
    s.machine.older_references = vec![7].try_into().unwrap();
    s.references = [
        Some(evidence(ReferenceEntry::Token(7))),
        Some(evidence(ReferenceEntry::Token(7))),
    ];
    cases.push(s);
    let mut s = Snapshot::initial(None);
    s.machine.hold = true;
    cases.push(s);
    let mut s = Snapshot::initial(None);
    s.machine.pending_cleanup = vec![StepRecord::from(Step::ReleaseReference)]
        .try_into()
        .unwrap();
    cases.push(s);
    let mut s = valid;
    s.machine.reference_intent = Some((true, 2));
    cases.push(s);
    for s in cases {
        assert!(s.validate().is_err(), "{s:?}");
        assert!(encode(1, &s).is_err());
        is_invalid(raw(1, &serde_json::to_vec(&s).unwrap()));
    }
    let mut transient = Snapshot::initial(None);
    transient.machine.reference_sequence = COUNTER_MAX - 1;
    transient.machine.reference_intent = Some((true, COUNTER_MAX - 1));
    transient.references[0] = Some(evidence(ReferenceEntry::Acquire(COUNTER_MAX - 1)));
    assert!(transient.validate().is_ok());
    let restarted = Machine::restart(transient.validate().unwrap());
    assert_eq!(restarted.durable().uncertain_acquires, [COUNTER_MAX - 1]);
    // Equal numbers in different key namespaces are distinct entries.
    transient.machine.pf_reference = Some(COUNTER_MAX - 1);
    transient.references = [
        Some(evidence(ReferenceEntry::Token(COUNTER_MAX - 1))),
        Some(evidence(ReferenceEntry::Acquire(COUNTER_MAX - 1))),
    ];
    assert!(transient.validate().is_ok());
    let mut leaving_hold = Snapshot::initial(None);
    leaving_hold.machine.hold = true;
    leaving_hold.machine.leaving = true;
    leaving_hold.machine.leave_requested = true;
    assert!(leaving_hold.validate().is_ok());
}

#[test]
fn leaving_rejects_join_intent() {
    assert_bad_durable(DurableRecord {
        leaving: true,
        leave_requested: true,
        join_intended: true,
        ..DurableRecord::default()
    });
}
#[test]
fn leaving_requires_leave_request() {
    assert_bad_durable(DurableRecord {
        leaving: true,
        ..DurableRecord::default()
    });
}
#[test]
fn verification_context_is_bounded_in_every_component() {
    for i in 0..4 {
        let mut d = DurableRecord {
            verification_context: [u64::MAX / 2; 4],
            ..DurableRecord::default()
        };
        assert!(d.to_core().is_ok());
        d.verification_context[i] += 1;
        assert_bad_durable(d);
    }
}
#[test]
fn durable_cleanup_requires_leaving_and_canonical_order() {
    for steps in [
        vec![Step::StopChild],
        vec![Step::CleanupDns, Step::CleanupRoutes],
        vec![Step::StopChild; 2],
        vec![Step::ReleaseReference],
        vec![Step::Backoff { until: 1 }],
    ] {
        let d = DurableRecord {
            leaving: steps != [Step::StopChild],
            leave_requested: true,
            pending_cleanup: steps
                .into_iter()
                .map(StepRecord::from)
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
            ..DurableRecord::default()
        };
        assert_bad_durable(d);
    }
}
#[test]
fn durable_reference_slots_and_duplicates_are_rejected() {
    for (tokens, uncertain) in [
        (vec![1, 1], vec![]),
        (vec![1, 2], vec![1]),
        (vec![], vec![1, 1]),
    ] {
        assert_bad_durable(DurableRecord {
            pf_reference: tokens.first().copied(),
            older_references: tokens
                .into_iter()
                .skip(1)
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
            uncertain_acquires: uncertain.try_into().unwrap(),
            reference_sequence: 1,
            ..DurableRecord::default()
        });
    }
}
fn assert_bad_durable(d: DurableRecord) {
    assert!(d.to_core().is_err(), "{d:?}");
    let s = Snapshot {
        machine: d,
        ..Snapshot::initial(None)
    };
    assert!(s.validate().is_err());
    assert!(encode(1, &s).is_err());
    is_invalid(raw(1, &serde_json::to_vec(&s).unwrap()));
}

#[test]
fn noncanonical_body_spellings_are_invalid() {
    let snapshot = Snapshot::recovery(Some(boot()), None, None, None);
    let canonical = serde_json::to_string(&snapshot).unwrap();
    assert!(matches!(class(1, &snapshot), CopyClass::V { .. }));
    let escaped = canonical.replacen("Acquire", r"\u0041cquire", 1);
    assert_ne!(escaped, canonical);
    is_invalid(raw(1, escaped.as_bytes()));
    is_invalid(raw(1, format!("{canonical} ").as_bytes()));
    // Remove fields without perturbing the canonical order of the remaining fields.
    for field in ["\"endpoint\":null,", "\"hold\":true,"] {
        assert!(canonical.contains(field));
        let missing = canonical.replacen(field, "", 1);
        is_invalid(raw(1, missing.as_bytes()));
    }
    let reordered = serde_json::to_vec(&serde_json::to_value(snapshot).unwrap()).unwrap();
    assert_ne!(reordered, canonical.as_bytes());
    is_invalid(raw(1, &reordered));
}

#[test]
fn recovery_helper_equal_sequence_ties_choose_a() {
    let mut a = Snapshot::initial(None);
    a.helper = Some(helper(1));
    let mut b = a.clone();
    b.helper = Some(helper(2));
    for (a, b) in [
        (class(5, &a), class(5, &b)),
        (
            CopyClass::I {
                seq: 5,
                helper: a.helper,
            },
            CopyClass::I {
                seq: 5,
                helper: b.helper,
            },
        ),
    ] {
        assert_eq!(
            decide(a, b),
            StartDecision::Recovery {
                seq: 6,
                helper: Some(helper(1))
            }
        );
    }
}
#[test]
#[should_panic(expected = "trust requires a validated copy")]
fn trust_rejects_non_v_instead_of_silently_recovering() {
    let _ = trust(
        CopyClass::I {
            seq: 99,
            helper: Some(helper(1)),
        },
        Copy::A,
        None,
    );
}

fn raw_maximal() -> Snapshot {
    let text: BoundedText<256> = "W".repeat(256).try_into().unwrap();
    let reason = ReasonRecord {
        kind: 5,
        text,
        argument: u64::MAX,
    };
    let step = StepRecord::from(Step::Backoff { until: u64::MAX });
    let reference = |token| {
        Some(RefEvidence {
            key: ReferenceEntry::Token(token),
            boot: Some(boot()),
            release_unknown: true,
            fingerprint: Some(RefFingerprint {
                pid: u32::MAX,
                timestamp: u64::MAX,
            }),
        })
    };
    Snapshot {
        owner_uid: Some(u32::MAX),
        machine: DurableRecord {
            verification_context: [u64::MAX; 4],
            join_intended: true,
            hold: true,
            retry_attempts: 7,
            leave_requested: true,
            leaving: true,
            pf_reference: Some(u64::MAX),
            older_references: vec![u64::MAX - 1].try_into().unwrap(),
            uncertain_acquires: vec![COUNTER_MAX - 2, COUNTER_MAX - 1].try_into().unwrap(),
            reference_intent: Some((true, COUNTER_MAX - 1)),
            reference_needs_reconcile: true,
            reference_error: Some(reason.clone()),
            reference_sequence: COUNTER_MAX - 1,
            enforcement_error: Some(reason.clone()),
            previous_generation: Some(COUNTER_MAX - 1),
            pending_cleanup: vec![step; 5].try_into().unwrap(),
            cleanup_errors: vec![(step, reason.clone()); 8].try_into().unwrap(),
            last_error: Some(reason),
        },
        references: [reference(u64::MAX), reference(u64::MAX - 1)],
        endpoint: Some("255.255.255.255:65535".parse().unwrap()),
        helper: Some(helper(u32::MAX)),
        requests: vec![
            RequestRecord {
                id: COUNTER_MAX - 1,
                kind: RequestKind::JoinDoneCancelled
            };
            8
        ]
        .try_into()
        .unwrap(),
        internal_error: Some(InternalError::InvariantViolation),
    }
}
#[test]
fn reachable_rich_and_raw_maximal_field_bodies_fit() {
    let valid = rich_reachable_snapshot();
    assert!(valid.validate().is_ok());
    assert!(encode(COUNTER_MAX - 1, &valid).is_ok());
    let mut raw_max = raw_maximal();
    raw_max.machine.retry_attempts = u8::MAX;
    // u8 step/reason tags and their arguments are maximized even though unknown tags are invalid.
    for step in &mut raw_max.machine.pending_cleanup.0 {
        step.tag = u8::MAX;
    }
    for (step, reason) in &mut raw_max.machine.cleanup_errors.0 {
        step.tag = u8::MAX;
        reason.kind = u8::MAX;
    }
    for reason in [
        &mut raw_max.machine.reference_error,
        &mut raw_max.machine.enforcement_error,
        &mut raw_max.machine.last_error,
    ]
    .into_iter()
    .flatten()
    {
        reason.kind = u8::MAX;
    }
    assert!(raw_max.validate().is_err());
    let bytes = serde_json::to_vec(&raw_max).unwrap();
    assert!(
        bytes.len() <= BODY_MAX,
        "raw maximal body {} > {BODY_MAX}",
        bytes.len()
    );
    assert!(serde_json::to_vec(&valid).unwrap().len() <= bytes.len());
    eprintln!(
        "maximal valid body: {}; raw maximal body: {}; BODY_MAX: {BODY_MAX}",
        serde_json::to_vec(&valid).unwrap().len(),
        bytes.len()
    );
}

#[test]
fn core_conversion_refuses_bounds_and_invalid_reason_text() {
    let mut d = Durable {
        older_references: vec![1, 2],
        ..Durable::default()
    };
    assert_eq!(DurableRecord::try_from(&d), Err(SnapshotError::Bound));
    d.older_references.clear();
    d.uncertain_acquires = vec![1, 2, 3];
    assert_eq!(DurableRecord::try_from(&d), Err(SnapshotError::Bound));
    d.uncertain_acquires.clear();
    d.pending_cleanup = vec![Step::StopChild; 7];
    assert_eq!(DurableRecord::try_from(&d), Err(SnapshotError::Bound));
    d.pending_cleanup.clear();
    d.cleanup_errors = vec![(Step::StopChild, Reason::HookMissing); 9];
    assert_eq!(DurableRecord::try_from(&d), Err(SnapshotError::Bound));
    d.cleanup_errors.clear();
    d.last_error = Some(Reason::Observation("bad!"));
    assert_eq!(DurableRecord::try_from(&d), Err(SnapshotError::Invalid));
}

#[derive(Clone, Copy)]
struct Clock(u64);
impl SleepCountingClock for Clock {
    fn now(&self) -> u64 {
        self.0
    }
}
fn from_machine(machine: &Machine) -> Snapshot {
    let d = machine.durable();
    // Build slots imperatively, independently of validate's iterator chain.
    let mut keys = Vec::new();
    if let Some(token) = d.pf_reference {
        keys.push(ReferenceEntry::Token(token));
    }
    for token in &d.older_references {
        keys.push(ReferenceEntry::Token(*token));
    }
    for sequence in &d.uncertain_acquires {
        keys.push(ReferenceEntry::Acquire(*sequence));
    }
    if let Some(ReferenceIntent::Acquire(sequence)) = d.reference_intent {
        keys.push(ReferenceEntry::Acquire(sequence));
    }
    assert!(keys.len() <= 2);
    Snapshot {
        machine: DurableRecord::try_from(d).unwrap(),
        references: std::array::from_fn(|i| keys.get(i).copied().map(evidence)),
        ..Snapshot::initial(None)
    }
}
fn check_round_trip(machine: &Machine) {
    let d = machine.durable();
    assert!(d.pending_cleanup.len() <= 5);
    assert!(d.cleanup_errors.len() <= 8);
    assert!(
        d.cleanup_errors
            .iter()
            .enumerate()
            .all(|(i, (step, _))| d.cleanup_errors[..i].iter().all(|(other, _)| step != other))
    );
    let snapshot = from_machine(machine);
    assert_eq!(&snapshot.validate().unwrap(), machine.durable());
    match class(1, &snapshot) {
        CopyClass::V {
            snapshot: decoded, ..
        } => assert_eq!(decoded, snapshot),
        other => panic!("valid lifecycle state rejected: {other:?}"),
    }
    assert!(
        serde_json::to_vec(&snapshot).unwrap().len()
            <= serde_json::to_vec(&raw_maximal()).unwrap().len()
    );
}

// Small pure verifier fixture, using the same typed evidence as the core driver.
fn fixture(machine: &Machine, form: Form, now: u64) -> (Observations, Expected) {
    let generation = machine
        .durable()
        .previous_generation
        .map_or(1, TunnelGeneration::value);
    let tunnel = Tunnel {
        name: "utun6".parse().unwrap(),
        generation: TunnelGeneration::new(generation).unwrap(),
    };
    let inputs = Inputs::new(
        "en0".parse().unwrap(),
        "198.51.100.7:51820".parse().unwrap(),
        BTreeMap::from([(
            "en0".parse().unwrap(),
            DhcpPhase::Bound {
                server: "192.0.2.1".parse().unwrap(),
            },
        )]),
        tunnel.clone(),
        HopLimitPolicy::QualifiedLimitation,
    )
    .unwrap();
    let text = match form {
        Form::PreTunnel => policy::render_pre_tunnel(&inputs),
        Form::Joined => policy::render_joined(&inputs),
    };
    let rules = parse::pf_rules(text.as_str()).unwrap();
    let main = parse::pf_rules("anchor \"com.apple/*\" all\n").unwrap();
    let normalization = Normalization {
        expanded_lists: true,
        named_icmp: true,
        implicit_tcp_flags: true,
    };
    let qualification = Qualification {
        os_build: "synthetic-until-qualification".into(),
        main: main.clone(),
        main_translation: parse::translation("").unwrap(),
        siblings: BTreeMap::new(),
        anchor_translation: BTreeMap::new(),
        physical: inputs.physical().keys().cloned().collect(),
        normalization: normalization.clone(),
        hop_limit: HopLimitPolicy::QualifiedLimitation,
    };
    let inventory = parse::anchor_list("com.apple/scupper\n").unwrap();
    let tree = LiveTree {
        before: inventory.clone(),
        after: inventory,
        complete: true,
        anchors: BTreeMap::from([(
            "com.apple/scupper".into(),
            AnchorObservation {
                rules: Ok(rules.clone()),
                translation: parse::translation(""),
            },
        )]),
    };
    let interfaces = parse::ifconfig_list("lo0 en0 utun6\n").unwrap();
    let route = parse::route(
        "route to: 198.51.100.7\ndestination: default\ngateway: 192.0.2.1\ninterface: en0\n",
    )
    .unwrap();
    let observations = Observations {
        started_at: verify::required_reads(&tree)
            .into_iter()
            .map(|r| (r, now))
            .collect(),
        states: machine
            .states_clean_at()
            .map_or(StateEvidence::Unproven, |completed_at| {
                StateEvidence::Clean {
                    epoch: machine.context().state_epoch,
                    completed_at,
                }
            }),
        os_build: qualification.os_build.clone(),
        pf: Ok(parse::PfInfo { enabled: true }),
        anchor: Ok(Some(rules)),
        main: Ok(main),
        translation: parse::translation(""),
        live_tree: Ok(tree),
        skips: Ok(interfaces.iter().cloned().map(|i| (i, false)).collect()),
        interfaces: Ok(interfaces),
        dns: parse::dns(include_str!("../../tests/fixtures/dns.txt")),
        local_address: Ok("192.0.2.2".parse().unwrap()),
        route: Ok(route.clone()),
        policy_inputs: Ok(inputs.clone()),
        identity: IdentityEvidence::CurrentGeneration(tunnel),
        selected_path: SelectedPath::Selected,
        tool_integrity: ToolIntegrity::Match,
        external_hop_limit_verified: false,
        step: StepOutcome::Complete,
    };
    let expected = Expected {
        context: machine.context(),
        baseline: verify::capture_baseline(text.as_str(), &inputs, form, &normalization).unwrap(),
        inputs,
        transport: Transport {
            local_address: "192.0.2.2".parse().unwrap(),
            endpoint_route: route,
        },
        form,
        qualification,
        max_age: 5,
        join_intended: machine.durable().join_intended,
    };
    (observations, expected)
}
fn completion(machine: &Machine, now: &mut u64, token: &mut u64) -> Event {
    match machine.pending().unwrap() {
        Step::AcquireReference => {
            *token += 1;
            Event::ReferenceAcquired(*token)
        }
        Step::ReconcileReference => Event::ReferenceReconciled {
            context: machine.context(),
            current: machine.durable().pf_reference,
            predecessor: machine.durable().older_references.first().copied(),
        },
        Step::ReserveGeneration => Event::GenerationReserved(
            TunnelGeneration::new(
                machine
                    .durable()
                    .previous_generation
                    .map_or(1, |g| g.value() + 1),
            )
            .unwrap(),
        ),
        Step::StartChild | Step::VerifyIdentity => {
            let tunnel = Tunnel {
                name: "utun6".parse().unwrap(),
                generation: machine.durable().previous_generation.unwrap(),
            };
            if machine.pending() == Some(Step::StartChild) {
                Event::ChildStarted(tunnel)
            } else {
                Event::IdentityVerified(tunnel)
            }
        }
        Step::VerifyPreTunnelLoad | Step::VerifyJoinedLoad | Step::VerifyReplacement(_) => {
            let form = match machine.pending().unwrap() {
                Step::VerifyJoinedLoad => Form::Joined,
                Step::VerifyReplacement(form) => form,
                _ => Form::PreTunnel,
            };
            Event::ReadbackValidated(fixture(machine, form, *now).1.baseline)
        }
        Step::VerifyPreTunnel | Step::VerifyJoined => {
            let form = machine.installed_form().unwrap();
            let (observations, expected) = fixture(machine, form, *now);
            Event::Observed {
                context: machine.context(),
                form,
                verdict: verify::verify(&observations, &expected, &Clock(*now)),
            }
        }
        Step::FlushStates => Event::StatesClean {
            epoch: machine.context().state_epoch,
            completed_at: *now,
        },
        Step::RemoveVanishedInterfaceStates => Event::InterfaceStatesRemoved {
            interfaces: machine.vanished_interfaces().clone(),
            completed_at: *now,
        },
        Step::Backoff { until } => {
            *now = (*now).max(until);
            Event::Completed(Step::Backoff { until })
        }
        step => Event::Completed(step),
    }
}
#[test]
fn fair_lifecycle_driver_covers_joined_and_leaving_with_serializable_boundaries() {
    let mut machine = Machine::restart(Durable::default())
        .transition(Event::Join, &Clock(100))
        .unwrap();
    let mut now = 100;
    let mut token = 1000;
    let mut steps = Vec::new();
    for _ in 0..80 {
        check_round_trip(&machine);
        let Some(step) = machine.pending() else {
            break;
        };
        steps.push(step);
        let event = completion(&machine, &mut now, &mut token);
        machine = machine.transition(event, &Clock(now)).unwrap();
    }
    assert!(steps.contains(&Step::AcquireReference));
    assert!(steps.contains(&Step::ReserveGeneration));
    assert!(steps.contains(&Step::StartChild));
    assert!(steps.contains(&Step::VerifyJoined));
    assert!(matches!(
        machine.enforcement_at(&Clock(now)),
        Verdict::Protected(_)
    ));
    machine = machine.transition(Event::Leave, &Clock(now)).unwrap();
    for _ in 0..40 {
        check_round_trip(&machine);
        let Some(_) = machine.pending() else {
            break;
        };
        let event = completion(&machine, &mut now, &mut token);
        machine = machine.transition(event, &Clock(now)).unwrap();
    }
    check_round_trip(&machine);
    assert!(!machine.durable().join_intended);
    assert!(!machine.durable().leaving);
}

fn joined_machine() -> (Machine, u64, u64) {
    let mut machine = Machine::restart(Durable::default())
        .transition(Event::Join, &Clock(100))
        .unwrap();
    let mut now = 100;
    let mut token = 1000;
    for _ in 0..80 {
        if machine.pending().is_none() {
            break;
        }
        let event = completion(&machine, &mut now, &mut token);
        machine = machine.transition(event, &Clock(now)).unwrap();
    }
    assert!(matches!(
        machine.enforcement_at(&Clock(now)),
        Verdict::Protected(_)
    ));
    (machine, now, token)
}
fn reacquire(machine: &Machine, now: u64) -> Machine {
    let event = Event::Observed {
        context: machine.context(),
        form: Form::Joined,
        verdict: Verdict::Repair(Action::EnableAndRejoin),
    };
    machine.transition(event, &Clock(now)).unwrap()
}
fn rich_reachable_snapshot() -> Snapshot {
    let (machine, mut now, mut token) = joined_machine();
    let mut machine = reacquire(&machine, now);
    let event = completion(&machine, &mut now, &mut token);
    machine = machine.transition(event, &Clock(now)).unwrap();
    machine = machine.transition(Event::Leave, &Clock(now)).unwrap();
    // Preserve the complete pending cleanup suffix and the two live tokens.
    for _ in 0..8 {
        if machine.durable().leaving {
            break;
        }
        let event = completion(&machine, &mut now, &mut token);
        machine = machine.transition(event, &Clock(now)).unwrap();
    }
    assert!(machine.durable().leaving && machine.durable().leave_requested);
    assert!(!machine.durable().join_intended);
    let mut snapshot = from_machine(&machine);
    snapshot.owner_uid = Some(u32::MAX);
    snapshot.helper = Some(helper(u32::MAX));
    snapshot.endpoint = Some("255.255.255.255:65535".parse().unwrap());
    snapshot.requests = (0..8)
        .map(|id| RequestRecord {
            id,
            kind: RequestKind::Leave,
        })
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    snapshot
}

#[derive(Default)]
struct Coverage {
    two_tokens: usize,
    token_acquire: usize,
    token_intent: usize,
}
impl Coverage {
    fn observe(&mut self, machine: &Machine) {
        let d = machine.durable();
        self.two_tokens += usize::from(d.pf_reference.is_some() && !d.older_references.is_empty());
        self.token_acquire +=
            usize::from(d.pf_reference.is_some() && !d.uncertain_acquires.is_empty());
        self.token_intent += usize::from(
            d.pf_reference.is_some()
                && matches!(d.reference_intent, Some(ReferenceIntent::Acquire(_))),
        );
        check_round_trip(machine);
    }
    fn assert_covered(&self) {
        assert!(
            self.two_tokens > 0 && self.token_acquire > 0 && self.token_intent > 0,
            "coverage: two_tokens={}, token_acquire={}, token_intent={}",
            self.two_tokens,
            self.token_acquire,
            self.token_intent
        );
    }
}
#[test]
fn fair_reacquire_driver_covers_two_tokens_and_token_plus_acquire() {
    let mut coverage = Coverage::default();
    for fail in [false, true] {
        let (machine, mut now, mut token) = joined_machine();
        let mut machine = reacquire(&machine, now);
        coverage.observe(&machine);
        assert_eq!(
            from_machine(&machine).references.map(|e| e.map(|e| e.key)),
            [
                Some(ReferenceEntry::Token(1001)),
                Some(ReferenceEntry::Acquire(2))
            ]
        );
        let event = if fail {
            Event::Failed(Reason::Observation("configuration readback mismatch"))
        } else {
            completion(&machine, &mut now, &mut token)
        };
        machine = machine.transition(event, &Clock(now)).unwrap();
        coverage.observe(&machine);
        let expected = if fail {
            [ReferenceEntry::Token(1001), ReferenceEntry::Acquire(2)]
        } else {
            [ReferenceEntry::Token(1002), ReferenceEntry::Token(1001)]
        };
        assert_eq!(
            from_machine(&machine).references.map(|e| e.unwrap().key),
            expected
        );
    }
    coverage.assert_covered();
}

#[test]
fn every_producer_reason_literal_fits_and_round_trips_exactly() {
    let mut count = 0;
    for source in REASON_SOURCES {
        let source = source.split("\n#[cfg(test)]\nmod tests").next().unwrap();
        for marker in [
            "Reason::Observation(",
            "Reason::Unsupported(",
            "Error(",
            "SysError::Failed(",
            "self.failure = Some(",
            "self.failure.unwrap_or(",
            "StepOutcome::Failed(",
        ] {
            for call in source.split(marker).skip(1) {
                let Some(literal) = call.trim_start().strip_prefix('"') else {
                    continue;
                };
                let text: &'static str = literal.split('"').next().unwrap();
                assert!(
                    BoundedText::<256>::try_from(text).is_ok(),
                    "invalid diagnostic {text:?}"
                );
                // The source-derived pool must provide static storage for both categories.
                assert_eq!(
                    static_reason(text),
                    Some(text),
                    "missing diagnostic {text:?}"
                );
                for reason in [Reason::Observation(text), Reason::Unsupported(text)] {
                    assert_eq!(
                        ReasonRecord::try_from(&reason).unwrap().to_core().unwrap(),
                        reason
                    );
                }
                count += 1;
            }
        }
    }
    assert!(count > 150, "diagnostic audit unexpectedly empty: {count}");
    let reason = Reason::Skip("abcdefghijklmno".parse().unwrap());
    assert_eq!(
        ReasonRecord::try_from(&reason).unwrap().to_core().unwrap(),
        reason
    );
    eprintln!("audited {count} diagnostic constructor literals");
}

#[test]
fn every_failable_leave_and_hold_cleanup_step_stays_bounded() {
    let mut attempted = Vec::new();
    let mut max_errors = 0;
    for (hold, only_clear) in [(false, false), (true, false), (false, true)] {
        let (mut machine, mut now, mut token) = if hold {
            (
                Machine::restart(
                    Snapshot::recovery(None, None, None, None)
                        .validate()
                        .unwrap(),
                ),
                100,
                1000,
            )
        } else {
            joined_machine()
        };
        if !hold {
            machine = machine.transition(Event::Leave, &Clock(now)).unwrap();
        }
        for _ in 0..160 {
            check_round_trip(&machine);
            max_errors = max_errors.max(machine.durable().cleanup_errors.len());
            let Some(step) = machine.pending() else {
                now += 61;
                machine = machine
                    .transition(
                        Event::PfEnabledObserved {
                            context: machine.context(),
                        },
                        &Clock(now),
                    )
                    .unwrap();
                continue;
            };
            let event = if (only_clear && step == Step::ClearIntent)
                || (!only_clear
                    && matches!(
                        step,
                        Step::StopChild
                            | Step::CleanupRoutes
                            | Step::CleanupDns
                            | Step::CleanupArtifacts
                            | Step::RemoveAnchor
                            | Step::ReleaseReference
                            | Step::ClearIntent
                            | Step::ReconcileReference
                    )) {
                if !attempted.contains(&step) {
                    attempted.push(step);
                }
                Event::Failed(Reason::Observation("configuration readback mismatch"))
            } else {
                completion(&machine, &mut now, &mut token)
            };
            machine = machine.transition(event, &Clock(now)).unwrap();
            now += 61;
        }
    }
    // ReleaseReference is deliberately removed from core's cleanup plan; checked
    // exact settlements replace it. All seven currently reachable failable steps run.
    for step in [
        Step::StopChild,
        Step::CleanupRoutes,
        Step::CleanupDns,
        Step::CleanupArtifacts,
        Step::RemoveAnchor,
        Step::ClearIntent,
        Step::ReconcileReference,
    ] {
        assert!(attempted.contains(&step), "never failed {step:?}");
    }
    assert!(
        max_errors >= 5,
        "failure accumulation was not exercised: {max_errors}"
    );
    assert!(max_errors <= 8);
}

proptest! {
    #[test]
    fn random_valid_instances_are_bounded_and_round_trip(
        tokens in prop::collection::btree_set(1..=u64::MAX, 0..=2),
        acquire_count in 0usize..=2, intent in any::<bool>(),
        seq in 2..COUNTER_MAX, owner in prop::option::of(any::<u32>()),
        generation in prop::option::of(1..COUNTER_MAX),
        text in "[A-Za-z0-9 .,:;()/_-]{0,256}",
        request_ids in prop::collection::vec(0..COUNTER_MAX, 0..=8),
        with_helper in any::<bool>(),
        release_unknown in any::<[bool; 2]>(),
        fingerprints in any::<[Option<(u32, u64)>; 2]>(),
    ) {
        let tokens: Vec<_> = tokens.into_iter().collect();
        let count = acquire_count.min(2 - tokens.len());
        let mut snapshot = Snapshot::initial(owner);
        snapshot.machine.join_intended = true;
        snapshot.machine.reference_sequence = seq;
        snapshot.machine.previous_generation = generation;
        snapshot.machine.pf_reference = tokens.first().copied();
        snapshot.machine.older_references = tokens.iter().skip(1).copied().collect::<Vec<_>>().try_into().unwrap();
        let acquire_keys: Vec<_> = (0..count).map(|n| seq - u64::try_from(n).unwrap()).collect();
        snapshot.machine.uncertain_acquires = acquire_keys.iter().copied().take(count - usize::from(intent && count > 0)).collect::<Vec<_>>().try_into().unwrap();
        if intent && count > 0 { snapshot.machine.reference_intent = Some((true, *acquire_keys.last().unwrap())); }
        let keys: Vec<_> = tokens.into_iter().map(ReferenceEntry::Token).chain(acquire_keys.into_iter().map(ReferenceEntry::Acquire)).collect();
        snapshot.references = std::array::from_fn(|i| keys.get(i).copied().map(|key| {
            let mut e = evidence(key);
            if matches!(key, ReferenceEntry::Token(_)) {
                e.release_unknown = release_unknown[i];
                e.fingerprint = fingerprints[i].map(|(pid, timestamp)| RefFingerprint { pid, timestamp });
            }
            e
        }));
        snapshot.machine.last_error = Some(ReasonRecord { kind: 5, text: text.try_into().unwrap(), argument: u64::MAX });
        snapshot.requests = request_ids.into_iter().map(|id| RequestRecord { id, kind: RequestKind::Join }).collect::<Vec<_>>().try_into().unwrap();
        snapshot.helper = with_helper.then(|| helper(u32::MAX));
        let durable = snapshot.validate().unwrap();
        prop_assert_eq!(durable.pf_reference, keys.iter().find_map(|key| match key { ReferenceEntry::Token(token) => Some(*token), ReferenceEntry::Acquire(_) => None }));
        prop_assert_eq!(snapshot.references.each_ref().map(|e| e.as_ref().map(|e| e.key)), std::array::from_fn(|i| keys.get(i).copied()));
        prop_assert!(serde_json::to_vec(&snapshot).unwrap().len() <= serde_json::to_vec(&raw_maximal()).unwrap().len());
        prop_assert!(matches!(class(seq, &snapshot), CopyClass::V { snapshot: decoded, .. } if decoded == snapshot), "round-trip must preserve snapshot");
    }

    #[test]
    fn lifecycle_event_sequences_round_trip_after_every_boundary(
        recovery in any::<bool>(), warm_join in any::<bool>(),
        events in prop::collection::vec((0u8..18, 0u64..4, any::<usize>()), 1..160),
    ) {
        let mut coverage = Coverage::default();
        let (joined, mut fair_now, mut fair_token) = joined_machine();
        let acquiring = reacquire(&joined, fair_now);
        coverage.observe(&acquiring);
        let uncertain = acquiring.transition(Event::Failed(Reason::Observation("configuration readback mismatch")), &Clock(fair_now)).unwrap();
        coverage.observe(&uncertain);
        let event = completion(&acquiring, &mut fair_now, &mut fair_token);
        let two_tokens = acquiring.transition(event, &Clock(fair_now)).unwrap();
        coverage.observe(&two_tokens);
        coverage.assert_covered();
        let d = if recovery { Snapshot::recovery(None, None, None, None).validate().unwrap() } else { Durable::default() };
        let mut machine = Machine::restart(d);
        let mut now = 100;
        let mut token = 1000;
        check_round_trip(&machine);
        if !recovery && warm_join {
            machine = machine.transition(Event::Join, &Clock(now)).unwrap();
            check_round_trip(&machine);
            for _ in 0..40 {
                if machine.pending().is_none() { break; }
                let event = completion(&machine, &mut now, &mut token);
                machine = machine.transition(event, &Clock(now)).unwrap();
                check_round_trip(&machine);
            }
            prop_assert!(matches!(machine.enforcement_at(&Clock(now)), Verdict::Protected(_)), "fair warm-up reaches Joined");
        }
        let reasons: Vec<_> = std::str::from_utf8(&REASON_BYTES).unwrap().split('\0').filter(|text| !text.is_empty()).collect();
        for (kind, elapsed, reason_index) in events {
            now += elapsed;
            let event = match kind {
                0 => Event::Join,
                1 => Event::Leave,
                2 => Event::ChildDied,
                3 => Event::Repair(Action::EnableAndRejoin),
                4 => Event::Repair(Action::Rerender { form: Form::PreTunnel }),
                5 => Event::InvalidateObservations { since: now },
                6 => Event::Observed { context: machine.context(), form: Form::PreTunnel, verdict: Verdict::NotProtected(Reason::HookMissing) },
                7 => Event::Observed { context: machine.context(), form: Form::PreTunnel, verdict: Verdict::Unknown { since: now } },
                8 => Event::Failed(Reason::Observation(reasons[reason_index % reasons.len()])) ,
                9 => { machine = Machine::restart(machine.durable().clone()); check_round_trip(&machine); continue; },
                10 => Event::PfEnabledObserved { context: machine.context() },
                11 if machine.durable().pf_reference.is_some() => Event::ReferenceSettled {
                    entry: ReferenceEntry::Token(machine.durable().pf_reference.unwrap()), how: ReferenceSettlement::Absent,
                },
                12 if !machine.durable().uncertain_acquires.is_empty() => Event::ReferenceSettled {
                    entry: ReferenceEntry::Acquire(machine.durable().uncertain_acquires[0]), how: ReferenceSettlement::Void,
                },
                _ if machine.pending().is_some() => completion(&machine, &mut now, &mut token),
                _ => Event::Join,
            };
            if let Ok(next) = machine.transition(event, &Clock(now)) { machine = next; }
            check_round_trip(&machine);
        }
    }
}
