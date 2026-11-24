//! Portable decoding and ownership checks for the fixture write-ahead journal.
use serde::Deserialize;

#[derive(Clone, Deserialize)]
pub(super) struct Entry {
    pub kind: String,
    #[serde(default)]
    pub pid: u32,
    #[serde(default)]
    pub start: String,
    #[serde(default)]
    pub at: u64,
    #[serde(default)]
    pub token: u64,
    #[serde(default)]
    pub path: String,
}

// A partial final append cannot grant a child permission to mutate. The writer
// fsyncs the entire newline-terminated entry before releasing its exec gate.
pub(super) fn committed(text: &str) -> Result<Vec<Entry>, serde_json::Error> {
    text.split_inclusive('\n')
        .filter(|line| line.ends_with('\n'))
        .map(serde_json::from_str)
        .collect()
}

pub(super) fn owns_token(
    entries: &[Entry],
    value: u64,
    pid: u64,
    timestamp: u64,
    now: u64,
) -> bool {
    value != 0
        && entries.iter().any(|e| {
            (e.kind == "token" && e.token == value)
                || (e.kind == "pf-acquire"
                    && u64::from(e.pid) == pid
                    && timestamp >= e.at.saturating_sub(1)
                    && timestamp <= now.saturating_add(1))
        })
}

#[derive(Debug, Eq, PartialEq)]
pub(super) struct Token {
    pub value: u64,
    pub pid: u64,
    pub timestamp: u64,
}

pub(super) fn ioctl_tokens(value: &serde_json::Value) -> Result<Vec<Token>, &'static str> {
    let inventory = value["events"]
        .as_array()
        .and_then(|events| events.iter().find(|e| e["event"] == "inventory"))
        .ok_or("missing token inventory")?;
    if inventory["rc"] == -1 && inventory["errno"] == 2 {
        return Ok(Vec::new());
    }
    let size = inventory["returned_size"]
        .as_u64()
        .ok_or("invalid inventory size")?;
    if inventory["rc"] != 0 || size % 84 != 0 || size > 84 * 127 {
        return Err("incomplete ioctl token inventory");
    }
    let tokens = inventory["tokens"]
        .as_array()
        .ok_or("missing recovery tokens")?;
    if tokens.len() != usize::try_from(size / 84).unwrap_or(usize::MAX) {
        return Err("recovery token count mismatch");
    }
    tokens
        .iter()
        .map(|token| {
            Ok(Token {
                value: token["token"]
                    .as_u64()
                    .filter(|n| *n != 0)
                    .ok_or("invalid token value")?,
                pid: token["pid"].as_u64().ok_or("invalid token pid")?,
                timestamp: token["timestamp"]
                    .as_u64()
                    .ok_or("invalid token timestamp")?,
            })
        })
        .collect()
}

// pfctl prints an elapsed age; reconstruct wall time for the acquisition-intent
// check. Exact journaled token values remain authoritative regardless of age.
pub(super) fn text_tokens(text: &str, now: u64) -> Result<Vec<Token>, &'static str> {
    let mut lines = text.lines().map(str::trim).filter(|line| !line.is_empty());
    if lines.next() != Some("TOKENS:")
        || !lines.next().is_some_and(|line| {
            line.split_whitespace()
                .eq(["PID", "Process", "Name", "TOKEN", "TIMESTAMP"])
        })
    {
        return Err("unrecognized pfctl References header");
    }
    let mut tokens = Vec::new();
    for line in lines {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() < 6 || fields[fields.len() - 2] != "days" {
            return Err("malformed pfctl References row");
        }
        let parse = |s: &str| {
            s.parse::<u64>()
                .map_err(|_| "invalid pfctl References number")
        };
        let pid = parse(fields[0])?;
        let value = parse(fields[fields.len() - 4])?;
        let days = parse(fields[fields.len() - 3])?;
        let clock = fields[fields.len() - 1]
            .split(':')
            .map(parse)
            .collect::<Result<Vec<_>, _>>()?;
        if clock.len() != 3
            || clock[0] >= 24
            || clock[1] >= 60
            || clock[2] >= 60
            || pid == 0
            || value == 0
            || tokens.iter().any(|t: &Token| t.value == value)
        {
            return Err("invalid pfctl References row");
        }
        let age = days
            .checked_mul(86400)
            .and_then(|age| age.checked_add(clock[0] * 3600 + clock[1] * 60 + clock[2]))
            .ok_or("pfctl token age overflow")?;
        tokens.push(Token {
            value,
            pid,
            timestamp: now.saturating_sub(age),
        });
    }
    Ok(tokens)
}

/// Parse the fallback inventory only with complete streams and exact qualified stderr.
pub(super) fn live_text_tokens(
    build: &crate::decode::pftext::Build,
    evidence: &super::Evidence,
    now: u64,
) -> Result<Vec<Token>, &'static str> {
    if !evidence.complete() {
        return Err("pfctl References unavailable");
    }
    if super::guard::no_foreign_references(build, &evidence.stdout, &evidence.stderr) {
        return Ok(Vec::new());
    }
    if !crate::decode::pftext::stderr(build, evidence.stderr.as_bytes()).is_empty() {
        return Err("unrecognized pfctl References stderr");
    }
    text_tokens(&evidence.stdout, now)
}

// Inventory failure must not prevent release attempts for durably known tokens.
pub(super) fn recovery_tokens(
    entries: &[Entry],
    inventory: Result<Vec<Token>, String>,
    now: u64,
) -> (Vec<u64>, Vec<String>) {
    let mut release = std::collections::BTreeSet::new();
    let mut failures = Vec::new();
    match inventory {
        Ok(tokens) => {
            for token in tokens {
                if owns_token(entries, token.value, token.pid, token.timestamp, now) {
                    release.insert(token.value);
                } else {
                    failures.push("unowned token appeared during fixture; not released".into());
                }
            }
        }
        Err(error) => {
            failures.push(format!("token recovery inventory failed: {error}"));
            release.extend(
                entries
                    .iter()
                    .filter(|e| e.kind == "token" && e.token != 0)
                    .map(|e| e.token),
            );
        }
    }
    (release.into_iter().collect(), failures)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_tokens_requires_qualified_complete_stderr() {
        let text = "TOKENS:\nPID Process Name TOKEN TIMESTAMP\n42 pfctl 123 0 days 00:00:00\n";
        for name in crate::decode::pftext::BUILDS {
            let build = crate::decode::pftext::Build::fixture(name);
            let mut evidence = super::super::Evidence {
                command: vec![],
                stdin: None,
                pid: Some(42),
                exit_code: Some(0),
                started_unix_ms: 0,
                elapsed_ms: 0,
                timed_out: false,
                truncated: false,
                stdout: text.into(),
                stderr: String::from_utf8_lossy(crate::decode::pftext::ALTQ_PREAMBLE).into_owned(),
            };
            assert_eq!(
                live_text_tokens(&build, &evidence, 100),
                Ok(vec![Token {
                    value: 123,
                    pid: 42,
                    timestamp: 100
                }])
            );
            evidence.stderr.push_str("unexpected\n");
            assert!(live_text_tokens(&build, &evidence, 100).is_err());
            evidence.stderr.clear();
            evidence.truncated = true;
            assert!(live_text_tokens(&build, &evidence, 100).is_err());
        }
        let resources = include_str!("resources.rs");
        assert!(resources.contains(
            "super::super::journal::live_text_tokens(&build, &evidence, unix_seconds())"
        ));
    }

    #[test]
    fn incomplete_final_append_does_not_discard_committed_intents() -> Result<(), serde_json::Error>
    {
        let text = "{\"kind\":\"probe\",\"pid\":12,\"start\":\"100:9\"}\n{\"kind\":\"key\",\"path\":\"State:/Network/Service/scupper-qual-0/DNS\"}\n{\"kind\":";
        let entries = committed(text)?;
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].start, "100:9");
        assert_eq!(entries[1].path, "State:/Network/Service/scupper-qual-0/DNS");
        assert!(committed("broken\n").is_err());
        Ok(())
    }

    #[test]
    fn token_recovery_requires_recorded_value_or_matching_acquirer_and_time()
    -> Result<(), serde_json::Error> {
        let entries = committed(
            "{\"kind\":\"pf-acquire\",\"pid\":42,\"at\":100}\n{\"kind\":\"token\",\"token\":7}\n",
        )?;
        assert!(owns_token(&entries, 7, 9, 0, 120));
        assert!(owns_token(&entries, 8, 42, 100, 120));
        assert!(!owns_token(&entries, 8, 43, 100, 120));
        assert!(!owns_token(&entries, 8, 42, 98, 120));
        assert!(!owns_token(&entries, 8, 42, 122, 120));
        assert!(!owns_token(&entries, 0, 42, 100, 120));
        Ok(())
    }
    #[test]
    fn references_text_recovers_tokens_with_process_names_and_elapsed_age()
    -> Result<(), Box<dyn std::error::Error>> {
        let text = "TOKENS:\nPID      Process Name                 TOKEN                    TIMESTAMP\n14576    pfctl                        7056986734673252366      0 days 00:00:00\n42       process with spaces          8                        1 days 01:02:03\n";
        let tokens = text_tokens(text, 100_000)?;
        assert_eq!(
            text_tokens(
                &text.replace("7056986734673252366", "18446744073709551615"),
                100_000
            )?[0]
                .value,
            u64::MAX
        );
        assert_eq!(
            tokens,
            [
                Token {
                    value: 7_056_986_734_673_252_366,
                    pid: 14576,
                    timestamp: 100_000
                },
                Token {
                    value: 8,
                    pid: 42,
                    timestamp: 9_877
                }
            ]
        );
        assert!(text_tokens("TOKENS:\n", 100).is_err());
        assert!(text_tokens(&text.replace("00:00:00", "00:60:00"), 100).is_err());
        assert!(text_tokens(&text.replace("7056986734673252366", "overflow"), 100).is_err());
        let entries = committed("{\"kind\":\"pf-acquire\",\"pid\":14576,\"at\":100000}\n")?;
        let (release, failures) = recovery_tokens(&entries, Ok(tokens), 100_000);
        assert_eq!(release, [7_056_986_734_673_252_366]);
        assert_eq!(failures.len(), 1);
        Ok(())
    }

    #[test]
    fn inventory_failure_still_releases_known_tokens_and_names_the_problem()
    -> Result<(), serde_json::Error> {
        let entries = committed(
            "{\"kind\":\"token\",\"token\":7}\n{\"kind\":\"token\",\"token\":7}\n{\"kind\":\"token\",\"token\":9}\n",
        )?;
        let (release, failures) =
            recovery_tokens(&entries, Err("ioctl ENODEV; text unavailable".into()), 120);
        assert_eq!(release, [7, 9]);
        assert_eq!(
            failures,
            ["token recovery inventory failed: ioctl ENODEV; text unavailable"]
        );
        assert_eq!(
            recovery_tokens(&entries, Ok(Vec::new()), 120),
            (Vec::new(), Vec::new())
        );
        Ok(())
    }

    #[test]
    fn ioctl_inventory_requires_complete_whole_records() {
        use serde_json::json;
        assert_eq!(
            ioctl_tokens(&json!({"events":[{"event":"inventory", "rc":-1, "errno":2}]})),
            Ok(Vec::new())
        );
        for (size, rc) in [(84, -1), (83, 0), (84, 0), (84 * 128, 0)] {
            assert!(ioctl_tokens(&json!({"events":[{"event":"inventory", "rc":rc, "returned_size":size,"tokens":[]}]})).is_err());
        }
        assert_eq!(
            ioctl_tokens(
                &json!({"events":[{"event":"inventory", "rc":0, "returned_size":84,"tokens":[{"token":7,"pid":42,"timestamp":100}]}]})
            ),
            Ok(vec![Token {
                value: 7,
                pid: 42,
                timestamp: 100
            }])
        );
    }
}

/// Only a successful absence observation can grant write-ahead cleanup authority.
/// Configured or unreadable anchors never grant authority. A listed empty
/// namespace may be journaled after a complete configuration-absence read.
pub(super) fn anchor_after_absence<E>(
    read: &Result<Option<String>, crate::platform::SysError>,
    append: impl FnOnce() -> Result<(), E>,
) -> Result<(), E>
where
    E: From<Box<dyn std::error::Error>>,
{
    match read {
        Ok(None) => append(),
        _ => Err(Box::<dyn std::error::Error>::from(
            "anchor absence not established; not journaled",
        )
        .into()),
    }
}
#[cfg(test)]
mod r7 {
    #[test]
    fn preexisting_configuration_or_failed_anchor_is_never_journaled() {
        for read in [
            Ok(Some(String::new())),
            Ok(Some("block all\n".into())),
            Err(crate::platform::SysError::Unknown),
            Ok(None),
        ] {
            let absent = read == Ok(None);
            let mut appended = false;
            let result: Result<(), Box<dyn std::error::Error>> =
                super::anchor_after_absence(&read, || {
                    appended = true;
                    Ok(())
                });
            assert_eq!(appended, absent);
            assert_eq!(result.is_ok(), absent);
        }
    }
}
