//! Conservative state-id extraction for raw measurements, never adapter proof.
use std::{
    collections::{BTreeMap, BTreeSet},
    net::SocketAddr,
};

#[derive(Debug)]
pub(super) struct State {
    pub header: String,
    pub identity: String,
}
const REVIEWED_PROTOCOLS: &[&str] = &["udp", "tcp"];

/// Reviewed 24H232 and 25G332 UDP/TCP `-v` records use directed tuple keys.
/// TCP is restricted to the captured ESTABLISHED state and sequence shape.
/// Any unreviewed record invalidates the whole listing; `-vv` is measurement only.
pub(super) fn parse(build: &str, text: &str) -> Result<Vec<State>, &'static str> {
    if !matches!(build, "24H232" | "25G332") {
        return Err("state listing unparsed: build grammar unreviewed");
    }
    if text.contains(['\0', '\r']) || (!text.is_empty() && !text.ends_with('\n')) {
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
            || !header_state_valid(words[1], words[5])
            || header != format!("{}       {}", words[..5].join(" "), words[5])
            || (words[1] == "tcp" && words[0] != "ALL")
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
        if words[1] == "tcp" && !lines.next().is_some_and(sequence_valid) {
            return Err("state listing unparsed: unknown TCP sequence");
        }
        let detail = lines
            .next()
            .ok_or("state listing unparsed: missing detail")?;
        if !detail.starts_with("   age ") || !detail_valid(&detail[3..]) {
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
/// Observational -vv decoding only. These ids never enter a qualification verdict.
pub(super) fn measure_vv(
    build: &str,
    text: &str,
) -> Result<BTreeMap<String, (String, String)>, &'static str> {
    if text.contains(['\0', '\r']) || (!text.is_empty() && !text.ends_with('\n')) {
        return Err("vv measurement incomplete");
    }
    let mut listing = String::new();
    let mut ids = Vec::new();
    let mut lines = text.lines();
    let mut seen = BTreeSet::new();
    while let Some(line) = lines.next() {
        listing.push_str(line);
        listing.push('\n');
        if line.starts_with("   age ") {
            let id = lines
                .next()
                .and_then(|s| s.strip_prefix("   id: "))
                .and_then(|s| s.split_once(" creatorid: "))
                .ok_or("vv measurement missing id row")?;
            let hex = |s: &str, len: usize| {
                s.len() == len
                    && s.bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            };
            if !hex(id.0, 16) || !hex(id.1, 8) || !seen.insert(id) {
                return Err("vv measurement malformed or duplicate id");
            }
            ids.push((id.0.to_owned(), id.1.to_owned()));
        }
    }
    let rows = parse(build, &listing)?;
    if rows.len() != ids.len() {
        return Err("vv measurement id multiplicity");
    }
    Ok(rows
        .into_iter()
        .zip(ids)
        .map(|(row, id)| (row.identity, id))
        .collect())
}

fn endpoint_valid(text: &str) -> bool {
    if text.parse::<std::net::SocketAddrV4>().is_ok()
        && text
            .rsplit_once(':')
            .is_some_and(|(_, port)| unsigned(port, u64::from(u16::MAX)))
    {
        return true;
    }
    text.strip_suffix(']')
        .and_then(|s| s.rsplit_once('['))
        .is_some_and(|(ip, port)| {
            ip.parse::<std::net::Ipv6Addr>().is_ok() && unsigned(port, u64::from(u16::MAX))
        })
}
fn header_state_valid(protocol: &str, state: &str) -> bool {
    match protocol {
        "udp" => matches!(state, "SINGLE:NO_TRAFFIC" | "NO_TRAFFIC:SINGLE"),
        "tcp" => state == "ESTABLISHED:ESTABLISHED",
        _ => false,
    }
}
fn sequence_valid(line: &str) -> bool {
    let half = |s: &str| {
        let Some((numbers, scale)) = s.strip_prefix('[').and_then(|s| s.split_once("] wscale "))
        else {
            return false;
        };
        numbers.split_once(" + ").is_some_and(|(a, b)| {
            unsigned(a, u64::from(u32::MAX)) && unsigned(b, u64::from(u32::MAX))
        }) && unsigned(scale, 14)
    };
    line.strip_prefix("   ")
        .and_then(|s| s.split_once("  "))
        .is_some_and(|(a, b)| half(a) && half(b))
}
fn unsigned(s: &str, max: u64) -> bool {
    decimal(s) && s.parse::<u64>().is_ok_and(|n| n <= max)
}
fn decimal(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}
fn pair(s: &str) -> bool {
    s.split_once(':')
        .is_some_and(|(a, b)| unsigned(a, u64::MAX) && unsigned(b, u64::MAX))
}
fn clock(s: &str) -> bool {
    let fields = s.split(':').collect::<Vec<_>>();
    fields.len() == 3
        && fields.iter().all(|f| f.len() == 2 && decimal(f))
        && unsigned(fields[1], 59)
        && unsigned(fields[2], 59)
}
fn detail_valid(s: &str) -> bool {
    let fields = s.split(", ").collect::<Vec<_>>();
    fields.len() == 7
        && fields[0].strip_prefix("age ").is_some_and(clock)
        && fields[1].strip_prefix("expires in ").is_some_and(clock)
        && fields[2].strip_suffix(" pkts").is_some_and(pair)
        && fields[3].strip_suffix(" bytes").is_some_and(pair)
        && fields[4]
            .strip_prefix("anchor ")
            .is_some_and(|s| unsigned(s, u64::from(u32::MAX)))
        && fields[5]
            .strip_prefix("rule ")
            .is_some_and(|s| unsigned(s, u64::from(u32::MAX)))
        && fields[6].strip_prefix("flowhash 0x").is_some_and(|s| {
            !s.is_empty()
                && s.len() <= 8
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
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

/// Retain every selector fixture until all listings are finished. Strict state
/// grammar must never see teardown states from an earlier selector iteration.
/// Cleanup also closes retained connections after an error or panic.
pub(super) fn selector_measurements<I, C, E>(
    io: &mut I,
    mut connect: impl FnMut(&mut I) -> Result<C, E>,
    mut measure: impl FnMut(&mut I, &[&str], &C) -> Result<(), E>,
) -> Result<(), E> {
    let mut connections = Vec::new();
    let (result, ()) = super::contract_check::with_cleanup(
        &mut connections,
        |connections| {
            for args in [
                &["-i", "feth0", "-F", "states"][..],
                &["-k", "198.18.0.1"][..],
            ] {
                let fresh = connect(io)?;
                measure(io, args, &fresh)?;
                connections.push(fresh);
            }
            Ok(())
        },
        Vec::clear,
    );
    result
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
    #[test]
    fn selector_connections_survive_all_listings_and_close_on_every_exit() {
        use std::{cell::RefCell, rc::Rc};
        struct Connection {
            index: usize,
            states: Rc<RefCell<Vec<bool>>>,
        }
        impl Drop for Connection {
            fn drop(&mut self) {
                self.states.borrow_mut()[self.index] = false;
            }
        }
        for stop in [
            "success",
            "connect-error",
            "pre-error",
            "post-error",
            "panic",
        ] {
            let states = Rc::new(RefCell::new(Vec::new()));
            let mut listings = Vec::new();
            let mut selectors = Vec::new();
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                super::selector_measurements(
                    &mut (),
                    |()| {
                        let index = states.borrow().len();
                        if stop == "connect-error" && index == 1 {
                            return Err("connect failed");
                        }
                        states.borrow_mut().push(true);
                        Ok(Connection {
                            index,
                            states: Rc::clone(&states),
                        })
                    },
                    |(), args, fresh| {
                        selectors.push(args.join(" "));
                        // The interface selector leaves the earlier floating tuple.
                        // Closing a socket changes its next listing to FIN_WAIT_2.
                        let template =
                            include_str!("../../qualification/goldens/24H232/states-v-tcp.txt")
                                .lines()
                                .skip(4)
                                .take(3)
                                .collect::<Vec<_>>()
                                .join("\n")
                                + "\n";
                        for phase in ["pre", "post"] {
                            let listing = states
                                .borrow()
                                .iter()
                                .enumerate()
                                .map(|(i, live)| {
                                    let row = template.replace("49257", &(49257 + i).to_string());
                                    if *live {
                                        row
                                    } else {
                                        row.replace(
                                            "ESTABLISHED:ESTABLISHED",
                                            "FIN_WAIT_2:FIN_WAIT_2",
                                        )
                                    }
                                })
                                .collect::<String>();
                            let rows = super::parse("24H232", &listing)?;
                            assert_eq!(rows.len(), fresh.index + 1);
                            assert!(
                                super::known(
                                    &rows,
                                    format!("127.0.0.1:{}", 49257 + fresh.index)
                                        .parse()
                                        .unwrap(),
                                    "127.0.0.1:49254".parse().unwrap(),
                                    Some("ALL")
                                )
                                .is_some()
                            );
                            listings.push(rows.len());
                            if fresh.index == 1 {
                                assert_ne!(stop, "panic", "measurement panic");
                                if (phase == "pre" && stop == "pre-error")
                                    || (phase == "post" && stop == "post-error")
                                {
                                    return Err("listing failed");
                                }
                            }
                        }
                        Ok(())
                    },
                )
            }));
            assert!(states.borrow().iter().all(|live| !live), "{stop}");
            if stop == "success" {
                assert_eq!(result.unwrap(), Ok(()));
                assert_eq!(listings, [1, 1, 2, 2]);
                assert_eq!(selectors, ["-i feth0 -F states", "-k 198.18.0.1"]);
            } else if stop == "panic" {
                assert!(result.is_err());
            } else {
                assert!(result.unwrap().is_err(), "{stop}");
            }
        }
    }

    use super::*;
    const LIST: &str = include_str!("../../qualification/goldens/25G332/states-v.txt");
    #[test]
    fn pinned_tcp_full_listings_and_negative_variants() {
        for (build, text) in [
            (
                "24H232",
                include_str!("../../qualification/goldens/24H232/states-v-tcp.txt"),
            ),
            (
                "25G332",
                include_str!("../../qualification/goldens/25G332/states-v-tcp.txt"),
            ),
        ] {
            let states = parse(build, text).unwrap();
            assert_eq!(states.len(), 7);
            assert_eq!(
                states.iter().filter(|s| s.header.contains(" tcp ")).count(),
                5
            );
            for bad in [
                text.replace("] wscale", "](+1) wscale"),
                text.replacen(" wscale 6", "", 1),
                text.replace("ESTABLISHED:ESTABLISHED", "TIME_WAIT:TIME_WAIT"),
                text.replace(" wscale 6", " wscale 15"),
                text.replace(" wscale 6", " wscale -1"),
                text.replacen(" + ", " + 4294967296", 1),
                text.replacen("   [", "   [x", 1),
                text.replace("::1[49254]", "[::1]:49254")
                    .replace("::1[49258]", "[::1]:49258"),
                text.replace(":4925", ":99999"),
                text.replace('\n', "\r\n"),
                text.replace("       ESTABLISHED", "      ESTABLISHED"),
                text.replace("  [", "   ["),
                text.replace("23:59:59", "23:60:59")
                    .replace("24:00:00", "24:00:60"),
                text.replace("3:3 pkts", "18446744073709551616:3 pkts"),
                text.replace("rule 2", "rule 4294967296"),
                text.replace("flowhash 0x", "flowhash 0xfffffffff"),
                format!("{text}{text}"),
                format!("{text}ALL icmp unknown\n"),
                text.trim_end().to_owned(),
                // Good records before and after a bad TCP record cannot become absence.
                format!("{LIST}{}{LIST}", text.replacen("ESTABLISHED", "CLOSED", 1)),
            ] {
                assert!(
                    parse(build, &bad).is_err(),
                    "assertion failed: {build}: {bad}"
                );
            }
            let tcp = text.lines().skip(4).take(3).collect::<Vec<_>>().join("\n") + "\n";
            let parts = tcp.lines().collect::<Vec<_>>();
            for bad in [
                format!("{}\n{}\n{}\n", parts[1], parts[0], parts[2]),
                format!("{}\n{}\n{}\n", parts[0], parts[2], parts[1]),
                format!("{tcp}{}\n", parts[1]),
                format!("{}\n{}\n", parts[0], parts[2]),
            ] {
                assert!(parse(build, &bad).is_err());
            }
        }
        assert!(sequence_valid(
            "   [0 + 4294967295] wscale 0  [4294967295 + 0] wscale 14"
        ));
    }
    #[test]
    fn vv_observer_keeps_ids_per_tuple_and_fails_closed() {
        for (build, text, prefix, creator) in [
            (
                "24H232",
                include_str!("../../qualification/goldens/24H232/states-v-tcp.txt"),
                "94010000",
                "46543612",
            ),
            (
                "25G332",
                include_str!("../../qualification/goldens/25G332/states-v-tcp.txt"),
                "c6010000",
                "924d977a",
            ),
        ] {
            let mut vv = String::new();
            let mut index = 42;
            for line in text.lines() {
                vv.push_str(line);
                vv.push('\n');
                if line.starts_with("   age ") {
                    use std::fmt::Write as _;
                    writeln!(vv, "   id: {prefix}{index:02x}000000 creatorid: {creator}").unwrap();
                    index += 1;
                }
            }
            let observed = measure_vv(build, &vv).unwrap();
            assert_eq!(observed.len(), 7);
            assert_eq!(observed, measure_vv(build, &vv).unwrap());
            assert!(observed.values().all(|(_, c)| c == creator));
            for invalid in [
                vv.replace(" creatorid:", " unknown:"),
                vv.replace("2b000000", "2a000000"),
                vv.trim_end().to_owned(),
                text.to_owned(),
            ] {
                assert!(measure_vv(build, &invalid).is_err());
            }
        }
    }
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
