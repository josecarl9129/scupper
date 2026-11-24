//! Conservative state-id extraction for raw measurements, never adapter proof.
use std::{collections::BTreeSet, net::SocketAddr};

#[derive(Debug)]
pub(super) struct State {
    pub header: String,
    pub identity: String,
}
/// An id and creatorid are retained together to prevent id reuse/misattribution.
/// A nonempty listing without identities is inconclusive, never absence.
pub(super) fn parse(text: &str) -> Result<Vec<State>, &'static str> {
    if text.contains('\0') || (!text.is_empty() && !text.ends_with('\n')) {
        return Err("incomplete state text");
    }
    let mut result = vec![];
    let mut header = None;
    let mut identity = None;
    let mut seen = BTreeSet::new();
    for line in text.lines() {
        if !line.starts_with(char::is_whitespace) {
            if let Some(old) = header.take() {
                result.push(State {
                    header: old,
                    identity: identity.take().ok_or("state id not printed")?,
                });
            }
            let words: Vec<_> = line.split_whitespace().collect();
            if words.len() < 4
                || !matches!(words[1], "tcp" | "udp" | "icmp" | "icmp6" | "ipv6-icmp")
            {
                return Err("unknown state header");
            }
            header = Some(line.to_owned());
        } else if let Some(ids) = line.trim().strip_prefix("id: ") {
            let words: Vec<_> = ids.split_whitespace().collect();
            if header.is_none()
                || identity.is_some()
                || words.len() != 3
                || words[1] != "creatorid:"
                || !hex(words[0], 16)
                || !hex(words[2], 8)
            {
                return Err("unknown state identity");
            }
            let key = ids.to_ascii_lowercase();
            if !seen.insert(key.clone()) {
                return Err("duplicate state identity");
            }
            identity = Some(key);
        } else if header.is_none()
            || !["age ", "origif:", "route-to:", "source-track", "rule "]
                .iter()
                .any(|prefix| line.trim().starts_with(prefix))
        {
            return Err("unknown state detail");
        }
    }
    if let Some(header) = header {
        result.push(State {
            header,
            identity: identity.ok_or("state id not printed")?,
        });
    }
    Ok(result)
}
fn hex(s: &str, width: usize) -> bool {
    s.len() == width && s.bytes().all(|b| b.is_ascii_hexdigit())
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

#[cfg(test)]
mod tests {
    use super::*;
    const LIST: &str = "all tcp 127.0.0.1:1234 -> 127.0.0.1:5000 ESTABLISHED:ESTABLISHED\n   age 00:00:01, expires in 00:00:59, 1:1 pkts\n   id: 0000000000000001 creatorid: 00000002\nall tcp ::1[4000] -> ::1[5000] ESTABLISHED:ESTABLISHED\n   id: 0000000000000002 creatorid: 00000002\n";
    #[test]
    fn identities_and_exact_endpoints_prevent_substring_misattribution() {
        let states = parse(LIST).unwrap();
        assert_eq!(states.len(), 2);
        assert!(
            known(
                &states,
                "127.0.0.1:1234".parse().unwrap(),
                "127.0.0.1:5000".parse().unwrap(),
                None
            )
            .is_some()
        );
        assert_eq!(
            known(
                &states,
                "127.0.0.1:123".parse().unwrap(),
                "127.0.0.1:5000".parse().unwrap(),
                None
            ),
            None
        );
        assert!(
            known(
                &states,
                "[::1]:4000".parse().unwrap(),
                "[::1]:5000".parse().unwrap(),
                None
            )
            .is_some()
        );
        assert_eq!(
            known(
                &states,
                "[::1]:400".parse().unwrap(),
                "[::1]:5000".parse().unwrap(),
                None
            ),
            None
        );
        assert!(parse("").unwrap().is_empty());
    }
    #[test]
    fn floating_measurements_require_the_all_interface_header() {
        let source = "127.0.0.1:1234".parse().unwrap();
        let destination = "127.0.0.1:5000".parse().unwrap();
        let states = parse(LIST).unwrap();
        assert!(known(&states, source, destination, Some("all")).is_some());
        let bound = parse(&LIST.replace("all tcp", "feth0 tcp")).unwrap();
        assert!(known(&bound, source, destination, Some("all")).is_none());
        assert!(known(&bound, source, destination, Some("feth0")).is_some());
    }
    #[test]
    fn missing_or_unknown_id_text_never_proves_absence() {
        for text in [
            LIST.trim_end().to_owned(),
            LIST.replace("creatorid:", "other:"),
            LIST.replace("0000000000000001", "1"),
            LIST.replace("   id: 0000000000000001 creatorid: 00000002\n", ""),
            format!("{LIST}unknown\n"),
            LIST.replace("   age", "   garbage"),
        ] {
            assert!(parse(&text).is_err(), "{text:?}");
        }
    }
}
