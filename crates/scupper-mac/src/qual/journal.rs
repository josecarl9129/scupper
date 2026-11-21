//! Portable decoding and ownership checks for the fixture write-ahead journal.
use serde::Deserialize;

#[derive(Deserialize)]
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
