//! Conservative state-id extraction for raw measurements, never adapter proof.
use std::{collections::BTreeSet, net::SocketAddr};

#[derive(Debug)]
pub(super) struct State {
    pub header: String,
    pub identity: String,
}
const REVIEWED_PROTOCOLS: &[&str] = &["udp"];

/// 24H232 and 25G332 UDP `-v` has no kernel id/creatorid. The measurement key is the
/// interface/protocol/directed endpoint tuple, never a kernel state identity.
/// `-vv` and other protocols remain unreviewed and capture-only.
pub(super) fn parse(build: &str, text: &str) -> Result<Vec<State>, &'static str> {
    if !matches!(build, "24H232" | "25G332") {
        return Err("state listing unparsed: build grammar unreviewed");
    }
    if text.contains('\0') || (!text.is_empty() && !text.ends_with('\n')) {
        return Err("state listing unparsed: incomplete text");
    }
    let mut lines = text.lines();
    let mut result = Vec::new();
    let mut seen = BTreeSet::new();
    while let Some(header) = lines.next() {
        let words: Vec<_> = header.split_whitespace().collect();
        if header.starts_with(char::is_whitespace)
            || words.len() != 6
            || !REVIEWED_PROTOCOLS.contains(&words[1])
            || !matches!(words[3], "->" | "<-")
            || !matches!(words[5], "SINGLE:NO_TRAFFIC" | "NO_TRAFFIC:SINGLE")
            || words[0] == "all"
            || !endpoint_valid(words[2])
            || !endpoint_valid(words[4])
            || words[0].is_empty()
            || !words[0]
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_')
        {
            return Err("state listing unparsed: unknown header");
        }
        let detail = lines
            .next()
            .ok_or("state listing unparsed: missing detail")?;
        if !detail.starts_with("   age ") || !detail_valid(detail.trim()) {
            return Err("state listing unparsed: unknown detail");
        }
        let identity = words[..5].join(" ");
        if !seen.insert(identity.clone()) {
            return Err("state listing unparsed: duplicate tuple");
        }
        result.push(State {
            header: header.to_owned(),
            identity,
        });
    }
    Ok(result)
}
fn endpoint_valid(text: &str) -> bool {
    if text.parse::<SocketAddr>().is_ok() {
        return true;
    }
    text.strip_suffix(']')
        .and_then(|s| s.rsplit_once('['))
        .is_some_and(|(ip, port)| {
            ip.parse::<std::net::Ipv6Addr>().is_ok() && port.parse::<u16>().is_ok()
        })
}
fn decimal(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}
fn pair(s: &str) -> bool {
    s.split_once(':')
        .is_some_and(|(a, b)| decimal(a) && decimal(b))
}
fn clock(s: &str) -> bool {
    let fields = s.split(':').collect::<Vec<_>>();
    fields.len() == 3 && fields.iter().all(|f| f.len() == 2 && decimal(f))
}
fn detail_valid(s: &str) -> bool {
    let fields = s.split(", ").collect::<Vec<_>>();
    fields.len() == 7
        && fields[0].strip_prefix("age ").is_some_and(clock)
        && fields[1].strip_prefix("expires in ").is_some_and(clock)
        && fields[2].strip_suffix(" pkts").is_some_and(pair)
        && fields[3].strip_suffix(" bytes").is_some_and(pair)
        && fields[4].strip_prefix("anchor ").is_some_and(decimal)
        && fields[5].strip_prefix("rule ").is_some_and(decimal)
        && fields[6]
            .strip_prefix("flowhash 0x")
            .is_some_and(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_hexdigit()))
}
pub(super) fn known(
    states: &[State],
    source: SocketAddr,
    destination: SocketAddr,
    interface: Option<&str>,
) -> Option<String> {
    let endpoint = |header: &str, address: SocketAddr| {
        let conventional = address.to_string();
        let pf6 = format!("{}[{}]", address.ip(), address.port());
        header
            .split_whitespace()
            .any(|word| word == conventional || (address.is_ipv6() && word == pf6))
    };
    states
        .iter()
        .find(|s| {
            interface.is_none_or(|name| s.header.split_whitespace().next() == Some(name))
                && endpoint(&s.header, source)
                && endpoint(&s.header, destination)
        })
        .map(|s| s.identity.clone())
}

/// Preserve read/parse failure separately from a complete missing tuple.
pub(super) fn known_read<E>(
    rows: Result<Vec<State>, E>,
    source: SocketAddr,
    destination: SocketAddr,
    interface: Option<&str>,
) -> Result<Option<String>, E> {
    let states = rows?;
    Ok(known(&states, source, destination, interface))
}

/// A state read is evidence for the lifecycle, never permission to skip it.
/// Keep the error explicit while running the remaining measurement steps.
pub(super) fn continue_after_read<T, E: std::fmt::Display, R>(
    read: Result<T, E>,
    next: impl FnOnce(Result<T, String>) -> Result<R, E>,
) -> Result<R, E> {
    next(read.map_err(|e| e.to_string()))
}

/// State measurement issues cannot hide a measured removal refutation.
pub(super) fn finish_anchor<E>(
    r: &mut super::CaseResult,
    state_issues: &[String],
    env: impl FnOnce(bool, &str) -> Result<(), E>,
) -> Result<(), E> {
    if !state_issues.is_empty() {
        use std::fmt::Write as _;
        let _ = write!(
            r.detail,
            "; Q-ANCHOR state measurement issues: {state_issues:?}"
        );
    }
    if r.verdict != super::Verdict::AssumptionRefuted {
        env(
            state_issues.is_empty(),
            &format!("Q-ANCHOR state measurement issues: {state_issues:?}"),
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    const LIST: &str = include_str!("../../qualification/goldens/25G332/states-v.txt");
    #[test]
    fn state_issues_preserve_removal_refutation_and_detail() {
        use super::super::{CaseResult, Verdict};
        for verdict in [
            Verdict::AssumptionRefuted,
            Verdict::Inconclusive,
            Verdict::AssumptionHolds,
        ] {
            for issues in [
                vec![],
                vec![
                    "hooked iteration 0: state listing unparsed".to_owned(),
                    "F-all after: state read failed".to_owned(),
                ],
            ] {
                let mut r = CaseResult {
                    case: "Q-ANCHOR".into(),
                    binary_sha256: String::new(),
                    verdict,
                    iterations: 20,
                    elapsed_ms: None,
                    detail: "gone_every_time=false".into(),
                    evidence: vec![],
                };
                let result = finish_anchor(&mut r, &issues, |ok, reason| {
                    if ok { Ok(()) } else { Err(reason.to_owned()) }
                });
                assert_eq!(
                    result.is_ok(),
                    verdict == Verdict::AssumptionRefuted || issues.is_empty()
                );
                assert_eq!(r.verdict, verdict);
                assert!(r.detail.starts_with("gone_every_time=false"));
                for issue in &issues {
                    assert!(r.detail.contains(issue));
                }
                // The case runner replaces a verdict on Err; a refutation must reach it as Ok.
                if let Err(error) = result {
                    r.verdict = Verdict::Inconclusive;
                    r.detail = error;
                }
                assert_eq!(
                    r.verdict,
                    if issues.is_empty() {
                        verdict
                    } else if verdict == Verdict::AssumptionRefuted {
                        Verdict::AssumptionRefuted
                    } else {
                        Verdict::Inconclusive
                    }
                );
            }
        }
    }
    #[test]
    fn read_errors_do_not_abort_lifecycle_or_scope_measurements() {
        let mut steps = Vec::new();
        let mut issues = Vec::new();
        for iteration in 0..20 {
            let result = continue_after_read(
                Err::<Option<String>, _>("state listing unparsed"),
                |known| {
                    issues.push(format!("iteration {iteration}: {}", known.unwrap_err()));
                    steps.extend([
                        "remove with states",
                        "reload",
                        "flush states",
                        "remove after flush",
                    ]);
                    Ok::<_, &str>(())
                },
            );
            assert_eq!(result, Ok(()));
        }
        for label in ["F-all before", "F-all after"] {
            assert_eq!(
                continue_after_read(Err::<Vec<State>, _>("state read failed"), |known| {
                    issues.push(format!("{label}: {}", known.unwrap_err()));
                    steps.push(label);
                    Ok::<_, &str>(())
                }),
                Ok(())
            );
        }
        assert_eq!(steps.len(), 82);
        assert_eq!(issues.len(), 22);
        assert!(issues[0].contains("iteration 0: state listing unparsed"));
        assert!(issues[21].contains("F-all after: state read failed"));
    }
    #[test]
    fn pinned_25g332_no_id_rows_and_uppercase_floating_interface() {
        let rows = parse("25G332", LIST).unwrap();
        assert_eq!(rows.len(), 2);
        let src = "127.0.0.1:55220".parse().unwrap();
        let dst = "127.0.0.1:64402".parse().unwrap();
        assert!(known(&rows, src, dst, Some("ALL")).is_some());
        assert!(known(&rows, src, dst, Some("all")).is_none());
        assert!(known(&rows, "127.0.0.1:5522".parse().unwrap(), dst, None).is_none());
        assert!(parse("25G332", "").unwrap().is_empty());
        assert!(parse("unreviewed", LIST).is_err());
        assert!(parse("unreviewed", "").is_err());
    }
    #[test]
    fn pinned_24h232_udp_and_whole_listing_validation() {
        let golden = include_str!("../../qualification/goldens/24H232/states-v.txt");
        let rows = parse("24H232", golden).unwrap();
        assert_eq!(rows.len(), 2);
        assert!(
            known(
                &rows,
                "127.0.0.1:51589".parse().unwrap(),
                "127.0.0.1:53669".parse().unwrap(),
                Some("ALL")
            )
            .is_some()
        );
        for build in ["24H232", "25G332"] {
            for invalid in [
                format!("{golden}{}", LIST.replace("udp", "tcp")),
                format!("{golden}unknown trailing line\n"),
                golden.trim_end().to_owned(),
                golden.replace("flowhash", "unknown"),
                golden.lines().take(3).collect::<Vec<_>>().join("\n") + "\n",
            ] {
                assert!(parse(build, &invalid).is_err(), "{build}: {invalid}");
            }
        }
    }
    #[test]
    fn parse_failure_is_explicit_never_absence() {
        let source = "127.0.0.1:1".parse().unwrap();
        let destination = "127.0.0.1:2".parse().unwrap();
        assert_eq!(
            known_read::<&str>(Err("state listing unparsed"), source, destination, None),
            Err("state listing unparsed")
        );
        assert_eq!(
            known_read::<&str>(Ok(vec![]), source, destination, None),
            Ok(None)
        );
        for text in [
            LIST.trim_end().to_owned(),
            LIST.replace("flowhash", "unknown"),
            format!("{LIST}   id: 0000000000000001 creatorid: 00000002\n"),
            LIST.replace("400:0 bytes", "400 bytes"),
            LIST.replace("SINGLE:NO_TRAFFIC", ":"),
            LIST.replace("ALL udp", "all icmp"),
        ] {
            let error = parse("25G332", &text).unwrap_err();
            assert!(error.contains("state listing unparsed"));
        }
    }
}
