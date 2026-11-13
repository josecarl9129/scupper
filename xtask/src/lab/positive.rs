//! Bounded recovery of a positive TCP canary; every attempt remains evidence.
use super::{Lab, Result, fail, helpers::Outcome};
use std::{
    fs::OpenOptions,
    io::Write,
    path::Path,
    time::{Duration, Instant},
};

pub(super) fn tcp(
    markers: &mut Vec<String>,
    log: &Path,
    probe: impl FnMut(&str, Instant) -> Result<Outcome>,
) -> Result<String> {
    tcp_bounded(markers, log, Duration::from_secs(15), probe)
}

fn tcp_bounded(
    markers: &mut Vec<String>,
    log: &Path,
    budget: Duration,
    mut probe: impl FnMut(&str, Instant) -> Result<Outcome>,
) -> Result<String> {
    let started = Instant::now();
    let deadline = started + budget;
    let mut log = OpenOptions::new().create(true).append(true).open(log)?;
    for attempt in 1..=3 {
        if Instant::now() >= deadline {
            break;
        }
        let marker = Lab::marker()?;
        // Register before launching: even a timed-out or failed probe must be
        // searched for in the unfiltered uplink capture by the leak oracle.
        markers.push(marker.clone());
        let at = Instant::now();
        let result = probe(&marker, deadline);
        writeln!(
            log,
            "{}",
            serde_json::json!({
                "attempt":attempt,"marker":marker,"started_ms":at.duration_since(started).as_millis(),
                "elapsed_ms":at.elapsed().as_millis(),"total_ms":started.elapsed().as_millis(),
                "outcome":result.as_ref().ok(),"error":result.as_ref().err().map(ToString::to_string),
            })
        )?;
        log.flush()?;
        if Instant::now() >= deadline {
            return fail("positive TCP canary deadline exceeded");
        }
        match result? {
            Outcome::Delivered => return Ok(marker),
            Outcome::TimedOut => {}
            outcome => {
                return fail(format!(
                    "positive TCP canary: wanted Delivered, got {outcome:?}"
                ));
            }
        }
    }
    fail("positive TCP canary did not deliver within 3 attempts / 15 seconds")
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn retries_only_timeouts_and_keeps_every_marker_and_attempt() {
        let dir = super::super::tests::test_dir("positive-tcp");
        for (name, outcomes, succeeds) in [
            (
                "recover",
                vec![Outcome::TimedOut, Outcome::TimedOut, Outcome::Delivered],
                true,
            ),
            ("exhaust", vec![Outcome::TimedOut; 3], false),
            ("reject", vec![Outcome::LocalReject(1)], false),
            (
                "error",
                vec![Outcome::HarnessError {
                    errno: None,
                    message: "bad ack".into(),
                }],
                false,
            ),
        ] {
            let path = dir.join(name);
            let mut markers = Vec::new();
            let mut attempted = outcomes.clone().into_iter();
            let result = tcp(&mut markers, &path, |_, deadline| {
                assert!(deadline > Instant::now());
                Ok(attempted.next().unwrap())
            });
            assert_eq!(result.is_ok(), succeeds);
            assert_eq!(markers.len(), outcomes.len());
            let text = std::fs::read_to_string(path).unwrap();
            let records: Vec<serde_json::Value> = text
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect();
            for (i, record) in records.iter().enumerate() {
                assert_eq!(record["marker"], markers[i]);
                assert_eq!(record["attempt"], i + 1);
                assert!(record["elapsed_ms"].is_number());
            }
            assert_eq!(records.len(), outcomes.len());
            let unique: std::collections::BTreeSet<_> = markers.iter().collect();
            assert_eq!(unique.len(), markers.len());
            if succeeds {
                assert_eq!(result.unwrap(), *markers.last().unwrap());
            }
        }
        let mut markers = Vec::new();
        assert!(tcp(&mut markers, &dir.join("launcher"), |_, _| fail("launcher")).is_err());
        assert_eq!(markers.len(), 1);
        let mut markers = Vec::new();
        assert!(
            tcp_bounded(
                &mut markers,
                &dir.join("deadline"),
                Duration::ZERO,
                |_, _| fail("expired deadline must not launch a probe"),
            )
            .is_err()
        );
        assert_eq!(markers, Vec::<String>::new());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
