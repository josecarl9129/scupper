//! Byte-preserving edits to the three qBittorrent binding keys only.
use std::net::Ipv4Addr;
const KEYS: [&[u8]; 3] = [
    b"Session\\Interface",
    b"Session\\InterfaceAddress",
    b"Session\\InterfaceName",
];

fn section(line: &[u8]) -> Option<bool> {
    let line = line.trim_ascii();
    line.starts_with(b"[").then_some(line == b"[BitTorrent]")
}
fn key(line: &[u8]) -> Option<(usize, usize)> {
    let eq = line.iter().position(|b| *b == b'=')?;
    KEYS.iter()
        .position(|k| *k == line[..eq].trim_ascii())
        .map(|k| (k, eq))
}

pub(super) fn address(bytes: &[u8]) -> Option<Ipv4Addr> {
    let mut inside = false;
    let mut value = None;
    for line in bytes.split(|b| *b == b'\n') {
        if let Some(bit) = section(line) {
            inside = bit;
        } else if inside && let Some((1, eq)) = key(line) {
            value = std::str::from_utf8(line[eq + 1..].trim_ascii())
                .ok()
                .and_then(|s| s.parse().ok());
        }
    }
    value
}

pub(super) fn edit(bytes: &[u8], address: Option<Ipv4Addr>) -> Vec<u8> {
    let newline: &[u8] = if bytes.windows(2).any(|w| w == b"\r\n") {
        b"\r\n"
    } else {
        b"\n"
    };
    let lines: Vec<&[u8]> = bytes.split_inclusive(|b| *b == b'\n').collect();
    let mut inside = false;
    let mut insertion = None;
    let mut keys = [false; 3];
    let mut replacements = vec![None; lines.len()];
    for (i, line) in lines.iter().enumerate() {
        if let Some(bit) = section(line) {
            inside = bit;
        } else if inside && let Some((k, eq)) = key(line) {
            keys[k] = true;
            replacements[i] = Some((k, eq));
        }
        if inside {
            insertion = Some(i + 1);
        }
    }
    let ip = address.map(|ip| ip.to_string()).unwrap_or_default();
    let values = ["", ip.as_str(), ""];
    let mut out = Vec::with_capacity(bytes.len() + 150);
    for (i, line) in lines.iter().enumerate() {
        if let Some((k, eq)) = replacements[i] {
            out.extend_from_slice(&line[..=eq]);
            out.extend_from_slice(values[k].as_bytes());
            if line.ends_with(b"\r\n") {
                out.extend_from_slice(b"\r\n");
            } else if line.ends_with(b"\n") {
                out.push(b'\n');
            }
        } else {
            out.extend_from_slice(line);
        }
        if insertion == Some(i + 1) {
            append_missing(&mut out, keys, &values, newline);
        }
    }
    if insertion.is_none() {
        ensure_newline(&mut out, newline);
        out.extend_from_slice(b"[BitTorrent]");
        out.extend_from_slice(newline);
        append_missing(&mut out, keys, &values, newline);
    }
    out
}
fn ensure_newline(out: &mut Vec<u8>, newline: &[u8]) {
    if !out.is_empty() && !out.ends_with(b"\n") {
        out.extend_from_slice(newline);
    }
}
fn append_missing(out: &mut Vec<u8>, keys: [bool; 3], values: &[&str; 3], newline: &[u8]) {
    for k in 0..3 {
        if !keys[k] {
            ensure_newline(out, newline);
            out.extend_from_slice(KEYS[k]);
            out.push(b'=');
            out.extend_from_slice(values[k].as_bytes());
            out.extend_from_slice(newline);
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    #[test]
    fn preserves_bytes_and_replaces_only_binding_keys() {
        let before = b";keep\xff\r\n[Other]\r\nSession\\InterfaceAddress=unchanged\r\n[BitTorrent]\r\nSession\\Interface=utun9\r\nSession\\InterfaceAddress=10.1.2.3\r\nSession\\InterfaceName=old\r\nOther = untouched \r\n[Tail]\r\nx=1";
        let ip = "100.64.1.2".parse().unwrap();
        let after = edit(before, Some(ip));
        assert_eq!(after, b";keep\xff\r\n[Other]\r\nSession\\InterfaceAddress=unchanged\r\n[BitTorrent]\r\nSession\\Interface=\r\nSession\\InterfaceAddress=100.64.1.2\r\nSession\\InterfaceName=\r\nOther = untouched \r\n[Tail]\r\nx=1");
        assert_eq!(address(&after), Some(ip));
        assert_eq!(edit(&after, Some(ip)), after);
        let unbound = edit(&after, None);
        assert_eq!(address(&unbound), None);
        assert!(unbound.ends_with(b"[Tail]\r\nx=1"));
    }
    #[test]
    fn adds_missing_sections_keys_and_handles_no_final_newline() {
        for before in [
            b"".as_slice(),
            b"[Other]\nx=1",
            b"[BitTorrent]\r\nx=1\r\n[Tail]\r\nx=2",
            b"[BitTorrent]\nx=1",
        ] {
            let ip = "10.99.0.2".parse().unwrap();
            let after = edit(before, Some(ip));
            assert_eq!(address(&after), Some(ip));
            assert_eq!(edit(&after, Some(ip)), after);
            assert_eq!(
                after
                    .split(|b| *b == b'\n')
                    .filter(|line| key(line).is_some_and(|(k, _)| k == 0))
                    .count(),
                1
            );
        }
        let before =
            b"[BitTorrent]\nSession\\InterfaceAddress=1.1.1.1\nSession\\InterfaceAddress=2.2.2.2\n";
        let after = edit(before, Some("10.0.0.2".parse().unwrap()));
        assert!(!after.windows(7).any(|w| w == b"1.1.1.1" || w == b"2.2.2.2"));
    }
}
