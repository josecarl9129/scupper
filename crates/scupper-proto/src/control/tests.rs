#![allow(clippy::unwrap_used, clippy::too_many_lines)]
use super::*;
use crate::{
    Event, EventKind, ExitId,
    event::{actor_samples, event_samples},
};
use serde_json::{Value, json};
use std::collections::BTreeSet;

fn id() -> Identifier {
    Identifier::try_from("request-1".to_owned()).unwrap()
}
fn keys(value: &Value, found: &mut BTreeSet<String>) {
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                found.insert(key.clone());
                keys(value, found);
            }
        }
        Value::Array(array) => {
            for value in array {
                keys(value, found);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}
fn private_strings(value: &Value, closed: &BTreeSet<&str>) {
    match value {
        Value::String(text) => assert!(
            Identifier::try_from(text.clone()).is_ok() || closed.contains(text.as_str()),
            "invalid event string: {text}"
        ),
        Value::Object(object) => {
            for value in object.values() {
                private_strings(value, closed);
            }
        }
        Value::Array(array) => {
            for value in array {
                private_strings(value, closed);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}
#[test]
fn every_variant_roundtrips_and_keys_are_private() {
    let mut values = Vec::new();
    let closed: BTreeSet<_> = [
        EventKind::NAMES,
        crate::Actor::NAMES,
        Reason::NAMES,
        crate::ObjectKind::NAMES,
        crate::RepairClass::NAMES,
        crate::Outcome::NAMES,
        crate::Health::NAMES,
        VerdictCode::NAMES,
        crate::Command::NAMES,
        crate::StepKind::NAMES,
    ]
    .into_iter()
    .flatten()
    .copied()
    .collect();
    assert_eq!(op_samples().len(), Op::NAMES.len());
    assert_eq!(result_samples().len(), OpResult::NAMES.len());
    assert!(ApiErrorCode::NAMES.contains(&"Timeout"));
    for kind in event_samples() {
        for actor in actor_samples() {
            let event = Event {
                seq: 1,
                at: UnixSeconds(1),
                kind: kind.clone(),
                actor,
                gateway: Identifier("home".into()),
                config_version: Some(1),
            };
            let value = serde_json::to_value(&event).unwrap();
            private_strings(&value, &closed);
            assert_eq!(
                value
                    .as_object()
                    .unwrap()
                    .keys()
                    .map(String::as_str)
                    .collect::<BTreeSet<_>>(),
                BTreeSet::from([
                    "seq",
                    "at",
                    "kind",
                    "actor",
                    "gateway",
                    "config_version",
                    "data"
                ])
            );
            assert_eq!(
                serde_json::from_value::<Event>(value.clone()).unwrap(),
                event
            );
            let mut event_keys = BTreeSet::new();
            keys(&value, &mut event_keys);
            let event_allowed = [
                "seq",
                "at",
                "kind",
                "actor",
                "gateway",
                "config_version",
                "data",
                "Local",
                "uid",
                "Device",
                "id",
                "user",
                "version",
                "parent",
                "sha",
                "reason",
                "from",
                "to",
                "cause",
                "exit",
                "duration",
                "secs",
                "nanos",
                "object",
                "class",
                "result",
                "command",
                "major",
                "minor",
                "patch",
                "step",
                "sink",
                "dropped",
                "first_seq",
                "last_seq",
                "local_first",
                "local_last",
                "replayed",
            ];
            assert!(
                event_keys
                    .iter()
                    .all(|key| event_allowed.contains(&key.as_str()))
            );
            values.push(value);
        }
    }
    for op in op_samples() {
        let request = Request {
            request_id: id(),
            op,
        };
        let value = serde_json::to_value(&request).unwrap();
        assert_eq!(
            decode_request(&serde_json::to_vec(&request).unwrap()).unwrap(),
            request
        );
        let mut unknown = value.clone();
        unknown["op"]["args"]["unexpected"] = json!("$(id)");
        assert!(decode_request(&serde_json::to_vec(&unknown).unwrap()).is_err());
        values.push(value);
    }
    for result in result_samples().into_iter().map(Ok).chain([Err(ApiError {
        code: ApiErrorCode::Timeout,
        observation: None,
    })]) {
        let response = Response {
            request_id: id(),
            schema: Schema,
            replayed: false,
            observed_at: None,
            result,
        };
        let value = serde_json::to_value(&response).unwrap();
        assert_eq!(value["schema"], 1);
        assert_eq!(
            serde_json::from_value::<Response>(value.clone()).unwrap(),
            response
        );
        values.push(value);
    }
    let allowed = [
        "seq",
        "at",
        "kind",
        "actor",
        "gateway",
        "config_version",
        "data",
        "Local",
        "uid",
        "Device",
        "id",
        "user",
        "version",
        "parent",
        "sha",
        "reason",
        "from",
        "to",
        "cause",
        "exit",
        "duration",
        "secs",
        "nanos",
        "object",
        "class",
        "result",
        "command",
        "major",
        "minor",
        "patch",
        "step",
        "sink",
        "dropped",
        "first_seq",
        "last_seq",
        "local_first",
        "local_last",
        "replayed",
        "request_id",
        "op",
        "args",
        "dry_run",
        "toml",
        "schema",
        "Ok",
        "Err",
        "code",
        "health",
        "report",
        "verdict",
        "warnings",
        "age",
        "observations",
        "complete",
        "safety_ms",
        "steps",
        "failed_steps",
        "kernel",
        "ruleset_exact",
        "forwarding_v4",
        "forwarding_v6",
        "default_v4",
        "default_v6",
        "links",
        "name",
        "up",
        "peers_present",
        "last_complete_iteration_age",
        "quarantined",
        "selection",
        "plan",
        "repair_plan",
        "observed_at",
        "netns",
        "device",
        "inode",
    ];
    let denied = [
        "dst",
        "destination",
        "domain",
        "qname",
        "host",
        "url",
        "sni",
        "payload",
        "bytes",
        "addr",
        "ip",
        "address",
        "endpoint",
        "query",
        "traffic",
        "packet",
        "private_key",
        "token",
    ];
    let mut found = BTreeSet::new();
    for value in values {
        keys(&value, &mut found);
    }
    assert!(
        found.iter().all(|key| allowed.contains(&key.as_str())),
        "unexpected keys: {found:?}"
    );
    assert!(found.iter().all(|key| !denied.contains(&key.as_str())));
}
#[test]
fn strict_bounded_requests() {
    assert_eq!(
        decode_request(&vec![b' '; MAX_REQUEST_SIZE + 1])
            .unwrap_err()
            .code,
        ApiErrorCode::RequestTooLarge
    );
    assert!(decode_request(&vec![b' '; MAX_REQUEST_SIZE]).is_err());
    let mut boundary = serde_json::to_vec(&Request {
        request_id: id(),
        op: Op::Ping {},
    })
    .unwrap();
    boundary.resize(MAX_REQUEST_SIZE, b' ');
    assert!(decode_request(&boundary).is_ok());
    boundary.push(b'\n');
    assert_eq!(
        decode_request(&boundary).unwrap_err().code,
        ApiErrorCode::RequestTooLarge
    );
    for bad in [
        "'",
        "\"",
        "a\nb",
        "$(id)",
        "`id`",
        "-ch1",
        "UPPER",
        "a/b",
        "",
        &"a".repeat(33),
    ] {
        for field in ["exit", "request_id"] {
            let mut request =
                json!({"request_id":"r1", "op":{"kind":"Connect", "args":{"exit":"ch1"}}});
            if field == "exit" {
                request["op"]["args"][field] = json!(bad);
            } else {
                request[field] = json!(bad);
            }
            assert!(decode_request(&serde_json::to_vec(&request).unwrap()).is_err());
        }
        let request = json!({"request_id":"r1", "op":{"kind":"Commit", "args":{"parent":null,"toml":"invalid", "reason":bad}}});
        assert!(decode_request(&serde_json::to_vec(&request).unwrap()).is_err());
    }
    for request in [
        json!({"request_id":"r1","op":{"kind":"Ping","args":{}}, "extra":0}),
        json!({"request_id":"r1","op":{"kind":"Ping","args":{"extra":0}}}),
        json!({"request_id":"r1","op":{"kind":"Ping","args":{},"extra":0}}),
    ] {
        assert!(decode_request(&serde_json::to_vec(&request).unwrap()).is_err());
    }
    assert!(
        decode_request(b"{\n\"request_id\":\"r1\",\"op\":{\"kind\":\"Ping\",\"args\":{}}}")
            .is_err()
    );
    assert!(serde_json::from_value::<Schema>(json!(2)).is_err());
    assert!(
        decode_request(b"{\"request_id\":\"r1\",\"op\":{\"kind\":\"Ping\",\"args\":{}}}\n").is_ok()
    );
}
#[test]
fn core_report_keeps_its_schema() {
    let report = crate::Report {
        verdict: scupper_core::verdict::v2::Verdict::Protected {
            exit: ExitId("ch1".into()),
            exit_ip: "192.0.2.1".parse().unwrap(),
        },
        warnings: vec![],
        at: 1,
        config_version: 2,
    };
    assert_eq!(HealthSummary::from(&report).verdict, VerdictCode::Protected);
    assert_eq!(serde_json::to_value(report).unwrap()["schema"], 1);
}
#[test]
fn source_events_are_redacted() {
    use scupper_core::{
        failover::{FailClosedReason, FailoverEvent},
        planner::{ClearLatch, PlannerEvent, Step},
    };
    let failover = [
        FailoverEvent::Failover {
            from: ExitId("ch1".into()),
            to: ExitId("ch2".into()),
        },
        FailoverEvent::Failback {
            from: ExitId("ch2".into()),
            to: ExitId("ch1".into()),
        },
        FailoverEvent::FailClosedStarted(FailClosedReason::AdminDisconnected),
        FailoverEvent::FailClosedStarted(FailClosedReason::NoHealthyExit),
        FailoverEvent::FailClosedStarted(FailClosedReason::PinnedExitDown(ExitId("ch1".into()))),
        FailoverEvent::FailClosedEnded {
            duration: std::time::Duration::from_secs(1),
        },
        FailoverEvent::Flapping,
    ];
    for event in failover {
        assert!(serde_json::to_value(EventKind::from(event)).is_ok());
    }
    let planner = [
        PlannerEvent::RepairSuppressed {
            object: "safety:ruleset".into(),
        },
        PlannerEvent::SafetyDrift {
            object: "secret.domain".into(),
        },
        PlannerEvent::ObservationUnknown,
        PlannerEvent::IngressQuarantined,
        PlannerEvent::PersistenceFailed,
        PlannerEvent::EdgeDead,
        PlannerEvent::ReplanAfterFailure {
            failed: Box::new(Step::RuleDelete {
                rule: "secret.domain".into(),
            }),
            applied_version: 1,
        },
        PlannerEvent::AdminAction {
            action: ClearLatch::RepairClear,
        },
        PlannerEvent::AdminAction {
            action: ClearLatch::VerifiedFullApply,
        },
    ];
    for event in planner {
        assert!(
            !serde_json::to_string(&EventKind::from(event))
                .unwrap()
                .contains("secret.domain")
        );
    }
}

#[test]
fn operational_ids_are_validated_at_every_wire_boundary() {
    for bad in ["tracker.example.com", "203.0.113.9", "UPPER", "", "a/b"] {
        let event = json!({"seq":1,"at":1,"kind":"FailClosedStarted","data":{"reason":"NoHealthyExit","exit":bad},"actor":"Daemon","gateway":"home","config_version":null});
        assert!(serde_json::from_value::<Event>(event.clone()).is_err());
        let mut gateway = event;
        gateway["data"]["exit"] = Value::Null;
        gateway["gateway"] = json!(bad);
        assert!(serde_json::from_value::<Event>(gateway).is_err());
        let request = json!({"request_id":"r1","op":{"kind":"Connect","args":{"exit":bad}}});
        assert!(serde_json::from_value::<Request>(request).is_err());
        assert!(Identifier::try_from(bad.to_owned()).is_err());
        let sanitized = EventKind::from(scupper_core::failover::FailoverEvent::Failback {
            from: ExitId(bad.into()),
            to: ExitId("ch1".into()),
        });
        assert_eq!(
            serde_json::to_value(sanitized).unwrap()["data"]["from"],
            "invalid-id"
        );
    }
}
