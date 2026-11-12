//! Every deploy operation rejects malformed data before gateway execution.
#![allow(clippy::unwrap_used)]
use scupper_proto::deploy::{MAX_REMOTE_REQUEST, read_deploy};
use serde_json::json;

#[test]
fn all_operations_are_strictly_validated() {
    for op in ["Prepare", "Stage", "Plan", "Switch", "Check"] {
        let mut args = json!({"id":"d1"});
        if op == "Stage" {
            args["sha256"] = "0".repeat(64).into();
        }
        let request = json!({"op":op, "args":args, "request_id":"r1"});
        assert!(read_deploy(request.to_string().as_bytes()).is_ok(), "{op}");
        for hostile in ["'", "\"", "x\ny", "$(id)", "`id`", "-option", "../x"] {
            for key in ["id", "request_id"] {
                let mut bad = request.clone();
                if key == "id" {
                    bad["args"][key] = hostile.into();
                } else {
                    bad[key] = hostile.into();
                }
                assert!(read_deploy(bad.to_string().as_bytes()).is_err());
            }
        }
        let mut extra = request.clone();
        extra["args"]["command"] = "true".into();
        assert!(read_deploy(extra.to_string().as_bytes()).is_err());
        let mut extra = request.clone();
        extra["command"] = "true".into();
        assert!(read_deploy(extra.to_string().as_bytes()).is_err());
        let mut missing = request;
        missing["args"].as_object_mut().unwrap().remove("id");
        assert!(read_deploy(missing.to_string().as_bytes()).is_err());
    }
}
#[test]
fn size_limit_unknown_operations_and_malformed_requests() {
    for bytes in [
        b"null".as_slice(),
        b"{}",
        b"[]",
        b"{",
        br#"{"op":"Execute","args":{"id":"d1"},"request_id":"r1"}"#,
        br#"{"op":"Stage","args":{"id":"d1","sha256":"$(id)"},"request_id":"r1"}"#,
    ] {
        assert!(read_deploy(bytes).is_err());
    }
    let mut boundary = br#"{"op":"Plan","args":{"id":"d1"},"request_id":"r1"}"#.to_vec();
    boundary.resize(MAX_REMOTE_REQUEST, b' ');
    assert!(read_deploy(boundary.as_slice()).is_ok());
    boundary.push(b' ');
    assert!(read_deploy(boundary.as_slice()).is_err());
}

#[test]
fn duplicate_fields_are_malformed() {
    for body in [
        r#"{"request_id":"r1","request_id":"r2","op":"Plan","args":{"id":"d1"}}"#,
        r#"{"request_id":"r1","op":"Plan","op":"Switch","args":{"id":"d1"}}"#,
        r#"{"request_id":"r1","op":"Plan","args":{"id":"d1","id":"d2"}}"#,
    ] {
        assert!(read_deploy(body.as_bytes()).is_err());
    }
}

proptest::proptest! {
    #[test]
    fn every_operation_refuses_hostile_identifiers(payload in ".{0,60}") {
        for op in ["Prepare", "Stage", "Plan", "Switch", "Check"] {
            for hostile in [format!("-{payload}"), format!("a\n{payload}"), format!("a'\"{payload}"), format!("$(x){payload}"), format!("`x`{payload}")] {
                let mut args = json!({"id":hostile});
                if op == "Stage" { args["sha256"] = "0".repeat(64).into(); }
                let request = json!({"op":op, "args":args, "request_id":"r1"});
                proptest::prop_assert!(read_deploy(request.to_string().as_bytes()).is_err());
            }
        }
    }
}
