//! Minimal, bounded DNS A codec. No resolver, network access or TCP fallback.

use std::net::Ipv4Addr;

/// Maximum accepted UDP message (no EDNS is advertised).
pub const MAX_MESSAGE: usize = 512;
const MAX_RECORDS: usize = 64;

/// Encodes one recursive IN/A question for an ASCII DNS hostname.
#[must_use]
pub fn query(id: u16, host: &str) -> Option<Vec<u8>> {
    if host.is_empty() || host.len() > 253 {
        return None;
    }
    let mut bytes = vec![0; 12];
    bytes[..2].copy_from_slice(&id.to_be_bytes());
    bytes[2] = 1; // RD
    bytes[5] = 1; // QDCOUNT
    for label in host.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return None;
        }
        bytes.push(u8::try_from(label.len()).ok()?);
        bytes.extend_from_slice(label.as_bytes());
    }
    bytes.extend_from_slice(&[0, 0, 1, 0, 1]);
    Some(bytes)
}

fn word(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes(
        bytes.get(at..at.checked_add(2)?)?.try_into().ok()?,
    ))
}

// Both expanded length and hops are bounded. A compression cycle, including one
// through labels, cannot recurse or allocate indefinitely.
fn name(bytes: &[u8], cursor: &mut usize) -> Option<String> {
    let mut at = *cursor;
    let mut end = None;
    let mut result = Vec::new();
    for _ in 0..128 {
        let len = *bytes.get(at)?;
        if len & 0xc0 == 0xc0 {
            end.get_or_insert(at + 2);
            at = usize::from(word(bytes, at)? & 0x3fff);
        } else if len == 0 {
            *cursor = end.unwrap_or(at + 1);
            return String::from_utf8(result).ok();
        } else {
            if len > 63 {
                return None;
            }
            at += 1;
            let label = bytes.get(at..at + usize::from(len))?;
            // A dot within a wire label must never compare equal to a label
            // separator in the requested hostname. Only hostname labels are
            // relevant to this A-only client.
            if !label
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
            {
                return None;
            }
            if !result.is_empty() {
                result.push(b'.');
            }
            result.extend(label.iter().map(u8::to_ascii_lowercase));
            if result.len() > 253 {
                return None;
            }
            at += usize::from(len);
        }
    }
    None
}

/// A matching DNS reply that cannot provide usable IPv4 addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DnsFailure {
    /// Resolver returned a nonzero response code.
    #[error("DNS rcode {0}")]
    Rcode(u8),
    /// Reply requires unsupported TCP fallback.
    #[error("DNS truncated reply")]
    Truncated,
    /// Answer is malformed or has no usable A record.
    #[error("DNS malformed answer or no usable IPv4 addresses")]
    Unusable,
}

/// Ignores unrelated packets; matching replies return addresses or a failure.
/// Returns at most two addresses, following at most eight CNAMEs entirely within
/// the answer section. Once the id and exact IN/A question match, unusable replies
/// end the query rather than consuming its deadline.
#[must_use]
pub fn response(bytes: &[u8], id: u16, host: &str) -> Option<Result<Vec<Ipv4Addr>, DnsFailure>> {
    let flags = word(bytes, 2)?;
    if word(bytes, 0)? != id || flags & 0xf800 != 0x8000 || word(bytes, 4)? != 1 {
        return None;
    }
    let mut at = 12;
    if !name(bytes, &mut at)?.eq_ignore_ascii_case(host)
        || word(bytes, at)? != 1
        || word(bytes, at + 2)? != 1
    {
        return None;
    }
    if flags & 0xf != 0 {
        return Some(Err(DnsFailure::Rcode(u8::try_from(flags & 0xf).ok()?)));
    }
    if flags & 0x0200 != 0 {
        return Some(Err(DnsFailure::Truncated));
    }
    Some(answers(bytes, at + 4, host).ok_or(DnsFailure::Unusable))
}
fn answers(bytes: &[u8], mut at: usize, host: &str) -> Option<Vec<Ipv4Addr>> {
    let count = usize::from(word(bytes, 6)?);
    if bytes.len() > MAX_MESSAGE || count > MAX_RECORDS {
        return None;
    }
    let mut aliases = Vec::new();
    let mut addresses = Vec::new();
    for _ in 0..count {
        let owner = name(bytes, &mut at)?;
        let kind = word(bytes, at)?;
        let class = word(bytes, at + 2)?;
        let length = usize::from(word(bytes, at + 8)?);
        at += 10;
        let data = bytes.get(at..at + length)?;
        if class == 1 && kind == 1 {
            if length != 4 {
                return None;
            }
            addresses.push((owner, Ipv4Addr::new(data[0], data[1], data[2], data[3])));
        } else if class == 1 && kind == 5 {
            let mut cursor = at;
            let alias = name(bytes, &mut cursor)?;
            if cursor != at + length {
                return None;
            }
            aliases.push((owner, alias));
        }
        at += length;
    }
    let mut owner = host.to_ascii_lowercase();
    let mut visited = Vec::new();
    for _ in 0..=8 {
        if visited.contains(&owner) {
            return None;
        }
        visited.push(owner.clone());
        let links: Vec<_> = aliases.iter().filter(|(from, _)| from == &owner).collect();
        let found: Vec<_> = addresses
            .iter()
            .filter(|(from, _)| from == &owner)
            .collect();
        if links.is_empty() {
            let mut result = Vec::new();
            for (_, address) in found {
                if !result.contains(address) && result.len() < 2 {
                    result.push(*address);
                }
            }
            return (!result.is_empty()).then_some(result);
        }
        if links.len() != 1 || !found.is_empty() {
            return None;
        }
        owner.clone_from(&links[0].1);
    }
    None
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn answer(id: u16, host: &str) -> Vec<u8> {
        let mut bytes = query(id, host).unwrap();
        bytes[2] = 0x81;
        bytes[3] = 0x80;
        bytes[7] = 1;
        bytes.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 1, 0, 4, 10, 2, 0, 1]);
        bytes
    }

    #[test]
    fn validates_question_flags_id_and_compression() {
        let bytes = answer(42, "probe.test");
        assert_eq!(
            response(&bytes, 42, "PROBE.test"),
            Some(Ok(vec![Ipv4Addr::new(10, 2, 0, 1)]))
        );
        assert_eq!(response(&bytes, 43, "probe.test"), None);
        assert_eq!(response(&bytes, 42, "other.test"), None);
        let mut wrong_label_boundaries = bytes.clone();
        wrong_label_boundaries[12] = 10;
        wrong_label_boundaries[18] = b'.';
        assert_eq!(response(&wrong_label_boundaries, 42, "probe.test"), None);
        let mut truncated = bytes.clone();
        truncated[2] |= 2;
        assert_eq!(
            response(&truncated, 42, "probe.test"),
            Some(Err(DnsFailure::Truncated))
        );
        for packet in [&[0xc0, 0][..], &[1, b'a', 0xc0, 0], &[0xc0, 2, 0xc0, 0]] {
            assert!(name(packet, &mut 0).is_none());
        }
    }

    #[test]
    fn follows_only_answer_cnames_and_rejects_cycles() {
        let mut bytes = query(1, "a.test").unwrap();
        bytes[2] = 0x81;
        bytes[7] = 2;
        bytes.extend_from_slice(&[0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 1, 0, 4, 1, b'b', 0xc0, 14]);
        bytes.extend_from_slice(&[1, b'b', 0xc0, 14, 0, 1, 0, 1, 0, 0, 0, 1, 0, 4, 1, 2, 3, 4]);
        assert_eq!(
            response(&bytes, 1, "a.test"),
            Some(Ok(vec![Ipv4Addr::new(1, 2, 3, 4)]))
        );
        bytes[37] = b'a';
        assert_eq!(
            response(&bytes, 1, "a.test"),
            Some(Err(DnsFailure::Unusable))
        );
        assert_eq!(response(&answer(1, "unrelated.test"), 1, "a.test"), None);
    }

    #[test]
    fn matching_dns_failures_are_not_unrelated_packets() {
        let mut bytes = answer(42, "probe.test");
        bytes[3] |= 3;
        assert_eq!(
            response(&bytes, 42, "probe.test"),
            Some(Err(DnsFailure::Rcode(3)))
        );
        bytes[3] = 2;
        assert_eq!(
            response(&bytes, 42, "probe.test"),
            Some(Err(DnsFailure::Rcode(2)))
        );
        bytes[3] = 0;
        bytes.truncate(bytes.len() - 1);
        assert_eq!(
            response(&bytes, 42, "probe.test"),
            Some(Err(DnsFailure::Unusable))
        );
        bytes[7] = 0;
        assert_eq!(
            response(&bytes, 42, "probe.test"),
            Some(Err(DnsFailure::Unusable))
        );
    }

    #[test]
    fn matching_malformed_owners_and_cname_with_a_fail_the_query() {
        let mut bytes = answer(42, "probe.test");
        bytes[7] = 2;
        bytes.extend_from_slice(&[0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 1, 0, 3, 1, b'a', 0]);
        assert_eq!(
            response(&bytes, 42, "probe.test"),
            Some(Err(DnsFailure::Unusable))
        );
        let mut bytes = query(42, "probe.test").unwrap();
        bytes[2] = 0x81;
        bytes[7] = 1;
        bytes.extend_from_slice(&[1, b'_', 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 4, 1, 2, 3, 4]);
        assert_eq!(
            response(&bytes, 42, "probe.test"),
            Some(Err(DnsFailure::Unusable))
        );
    }

    proptest! {
        #[test]
        fn arbitrary_packets_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..2048), id in any::<u16>()) {
            let _ = response(&bytes, id, "probe.test");
            let _ = name(&bytes, &mut 0);
        }
        #[test]
        fn queries_round_trip(host in "[a-z][a-z0-9]{0,30}(\\.[a-z][a-z0-9]{0,30}){0,4}", id in any::<u16>()) {
            let bytes = query(id, &host).unwrap();
            let mut cursor = 12;
            prop_assert_eq!(name(&bytes, &mut cursor), Some(host.clone()));
            prop_assert_eq!(word(&bytes, cursor), Some(1));
            prop_assert_eq!(word(&bytes, cursor + 2), Some(1));
            prop_assert_eq!(response(&answer(id, &host), id, &host).unwrap().unwrap().len(), 1);
        }
    }
}
