//! Strict, allocation-free network syntax and address classification.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::Ipv4Net;

pub(super) fn client_prefix(net: Ipv4Net) -> bool {
    (16..=30).contains(&net.prefix_len())
        && net.network().is_private()
        && net.broadcast().is_private()
        && net.addr() != net.network()
        && net.addr() != net.broadcast()
}

pub(super) fn public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    // Reject special-purpose networks as well as the explicitly forbidden
    // private, shared, local, documentation, multicast and reserved ranges.
    !(a == 0
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || (a == 100 && (64..=127).contains(&b))
        || (a == 192 && b == 0 && (c == 0 || c == 2))
        || (a == 192 && b == 88 && c == 99)
        || (a == 198 && (b == 18 || b == 19 || (b == 51 && c == 100)))
        || (a == 203 && b == 0 && c == 113)
        || a >= 224)
}

pub(super) fn global_v6(ip: Ipv6Addr) -> bool {
    let s = ip.segments();
    // Global unicast is 2000::/3. Exclude documentation and special-purpose
    // assignments within it rather than accepting all non-local addresses.
    (s[0] & 0xe000) == 0x2000
        && !(s[0] == 0x2001 && (s[1] < 0x200 || s[1] == 0xdb8))
        && s[0] != 0x2002
        && !(s[0] == 0x3fff && (s[1] & 0xf000) == 0)
}

/// Returns the host of a strict HTTPS URL, without performing DNS or I/O.
pub(super) fn https_host(text: &str) -> Option<&str> {
    if text.chars().any(|c| c.is_whitespace() || c.is_control()) || text.contains('\\') {
        return None;
    }
    let rest = text.strip_prefix("https://")?;
    let authority = rest.split(['/', '?', '#']).next()?;
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let (host, tail) = rest.split_once(']')?;
        host.parse::<Ipv6Addr>().ok()?;
        (
            host,
            if tail.is_empty() {
                None
            } else {
                Some(tail.strip_prefix(':')?)
            },
        )
    } else {
        let (host, port) = authority
            .split_once(':')
            .map_or((authority, None), |(host, port)| (host, Some(port)));
        if host.parse::<Ipv4Addr>().is_err() && !dns_name(host) {
            return None;
        }
        (host, port)
    };
    if let Some(port) = port
        && (port.is_empty()
            || !port.bytes().all(|b| b.is_ascii_digit())
            || port.parse::<u16>().ok()? == 0)
    {
        return None;
    }
    Some(host)
}

fn dns_name(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        // Numeric final labels and hex-prefixed labels can trigger legacy IPv4
        // parsing (including shortened, octal and integer forms) in resolvers.
        && !host.rsplit('.').next().unwrap_or_default().bytes().all(|b| b.is_ascii_digit())
        && host.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && !label.get(..2).is_some_and(|prefix| prefix.eq_ignore_ascii_case("0x"))
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

pub(super) fn https_ip(text: &str) -> Option<IpAddr> {
    https_host(text)?.parse().ok()
}
