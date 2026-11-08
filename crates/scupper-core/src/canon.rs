//! Pure canonicalization, comparison and diagnostic fingerprints for nft rulesets.

use std::time::Duration;

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{
    parse::ParseError,
    verdict::{Probe, RulesetObs},
};

/// Deadline for the namespace creation, ruleset load and JSON dump together.
pub const CANON_TIMEOUT: Duration = Duration::from_secs(8);

/// Diagnostic hash input for live rulesets exceeding the exec output cap.
/// Such output cannot be the roughly 3 KB policy; no repeat is needed.
pub const OVERSIZED_LIVE_RULESET: &[u8] = b"live ruleset exceeded output cap";

/// Diagnostic hash input when live stdout overflow makes canonicalization unnecessary.
pub const WANT_NOT_COMPUTED_LIVE_OVERFLOW: &[u8] =
    b"want side not computed: live ruleset exceeded output cap";

/// Removes only nft runtime metadata, retaining every other field and array order.
///
/// # Errors
/// Returns a parse error for malformed JSON or an invalid nftables envelope.
pub fn canonicalize(json: &str) -> Result<Value, ParseError> {
    let mut value: Value =
        serde_json::from_str(json).map_err(|_| ParseError::Topology("malformed nft JSON"))?;
    let entries = value
        .get_mut("nftables")
        .and_then(Value::as_array_mut)
        .ok_or(ParseError::Topology("expected an nftables array"))?;
    if entries.iter().any(|entry| !entry.is_object()) {
        return Err(ParseError::Topology("expected nftables object entries"));
    }
    entries.retain(|entry| !entry.get("metainfo").is_some_and(Value::is_object));
    strip_metadata(&mut value);
    Ok(value)
}

fn strip_metadata(value: &mut Value) {
    match value {
        Value::Object(fields) => {
            fields.remove("handle");
            if let Some(Value::Object(counter)) = fields.get_mut("counter") {
                counter.remove("packets");
                counter.remove("bytes");
            }
            for child in fields.values_mut() {
                strip_metadata(child);
            }
        }
        Value::Array(values) => {
            for child in values {
                strip_metadata(child);
            }
        }
        _ => {}
    }
}

/// Hashes a canonical JSON value for a ruleset diagnostic.
///
/// # Errors
/// Returns a parse error if the canonical value cannot be serialized.
pub fn fingerprint(value: &Value) -> Result<[u8; 32], ParseError> {
    // serde_json's default map is ordered (no preserve_order feature), making
    // to_vec deterministic even when input object keys were in another order.
    let bytes = serde_json::to_vec(value)
        .map_err(|_| ParseError::Topology("cannot serialize canonical nft JSON"))?;
    Ok(Sha256::digest(bytes).into())
}

/// Compares canonical rulesets and indicates whether a difference needs confirmation.
///
/// # Errors
/// Returns a parse error if either diagnostic fingerprint cannot be serialized.
pub fn compare_rulesets(want: &Value, live: &Value) -> Probe<(RulesetObs, bool)> {
    if live == want {
        Ok((RulesetObs::Exact, false))
    } else if !live["nftables"].as_array().is_some_and(|entries| {
        entries
            .iter()
            .any(|entry| entry["table"]["family"] == "inet" && entry["table"]["name"] == "scupper")
    }) {
        Ok((RulesetObs::Missing, false))
    } else {
        Ok((
            RulesetObs::Differs {
                live_sha256: fingerprint(live)?,
                want_sha256: fingerprint(want)?,
            },
            true,
        ))
    }
}

/// Describes live output that exceeds the execution cap without computing a wanted ruleset.
#[must_use]
pub fn oversized_live_ruleset() -> RulesetObs {
    RulesetObs::Differs {
        live_sha256: Sha256::digest(OVERSIZED_LIVE_RULESET).into(),
        want_sha256: Sha256::digest(WANT_NOT_COMPUTED_LIVE_OVERFLOW).into(),
    }
}
