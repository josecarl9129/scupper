//! Read only the client profile's IPv4 Address; never format profile contents.
use std::{io::Read, net::Ipv4Addr};
use zeroize::Zeroizing;

const MAX_PROFILE_BYTES: usize = 16 * 1024;

const INVALID: &str = "profile must contain one tunnel IPv4 Address in [Interface]";

/// Validate an IPv4 literal in RFC 1918 or the shared address range.
///
/// # Errors
/// Returns a constant diagnostic for invalid or non-tunnel addresses.
pub fn tunnel_address(value: &str) -> Result<Ipv4Addr, &'static str> {
    let ip: Ipv4Addr = value
        .parse()
        .map_err(|_| "expected a tunnel IPv4 literal")?;
    let [a, b, _, _] = ip.octets();
    if a == 10
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 168)
        || (a == 100 && (64..=127).contains(&b))
    {
        Ok(ip)
    } else {
        Err("address must be in 10/8, 172.16/12, 192.168/16 or 100.64/10")
    }
}

/// Parse only Address values in the Interface section of a `WireGuard` profile.
///
/// # Errors
/// Refuses missing, ambiguous, malformed or non-tunnel IPv4 addresses. Errors
/// never include input bytes, including private keys or invalid Address values.
pub fn parse_address(profile: &[u8]) -> Result<Ipv4Addr, &'static str> {
    let mut interface = false;
    let mut found = None;
    for line in profile.split(|b| *b == b'\n') {
        let line = line
            .split(|b| *b == b'#' || *b == b';')
            .next()
            .unwrap_or_default()
            .trim_ascii();
        if line.starts_with(b"[") {
            interface = line == b"[Interface]";
            continue;
        }
        if !interface {
            continue;
        }
        let Some(eq) = line.iter().position(|b| *b == b'=') else {
            continue;
        };
        if line[..eq].trim_ascii() != b"Address" {
            continue;
        }
        // No UTF-8 conversion or parsing is performed on any other value.
        let value = std::str::from_utf8(&line[eq + 1..]).map_err(|_| INVALID)?;
        for address in value.split(',') {
            let address = address.trim();
            let (host, prefix) = address
                .split_once('/')
                .map_or((address, None), |(h, p)| (h, Some(p)));
            let ip: std::net::IpAddr = host.parse().map_err(|_| INVALID)?;
            let max = if ip.is_ipv4() { 32 } else { 128 };
            if prefix.is_some_and(|p| p.parse::<u8>().map_or(true, |p| p > max)) {
                return Err(INVALID);
            }
            if ip.is_ipv4() {
                let ip = tunnel_address(host).map_err(|_| INVALID)?;
                if found.replace(ip).is_some() {
                    return Err(INVALID);
                }
            }
        }
    }
    found.ok_or(INVALID)
}

/// Read supplied profile bytes into a zeroized buffer, extracting only Address.
///
/// # Errors
/// Returns content-free read/parse errors; the buffer is wiped on all exits.
pub fn read_address(reader: impl Read) -> Result<Ipv4Addr, &'static str> {
    // Reserve the full capped read up front: avoid reallocations and the stack
    // probe in read_to_end, which would leave unzeroized copies of private keys.
    let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_PROFILE_BYTES + 1));
    reader
        .take((MAX_PROFILE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| "could not read client profile")?;
    if bytes.len() > MAX_PROFILE_BYTES {
        return Err("client profile exceeds 16 KiB");
    }
    parse_address(&bytes)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    #[test]
    fn profiles_and_secrets() {
        for value in [
            "10.99.0.2/32",
            "fd00::2/128, 10.99.0.2/24",
            "10.99.0.2, fd00::2/64",
        ] {
            let profile = format!(
                "# comment\n[Interface]\r\nPrivateKey = NEVER_EXPOSE_THIS_KEY\n Address = {value} # comment\n[Peer]\nAddress = 8.8.8.8\n"
            );
            assert_eq!(
                parse_address(profile.as_bytes()).unwrap().to_string(),
                "10.99.0.2"
            );
        }
        for value in [
            "",
            "8.8.8.8/32",
            "fd00::1",
            "10.1.1.1/33",
            "10.1.1.1,10.2.2.2",
            "NEVER_EXPOSE_THIS_KEY",
        ] {
            let profile =
                format!("[Interface]\nPrivateKey = NEVER_EXPOSE_THIS_KEY\nAddress = {value}\n");
            let result = parse_address(profile.as_bytes());
            assert!(result.is_err());
            assert!(!format!("{result:?}").contains("NEVER_EXPOSE_THIS_KEY"));
            assert!(
                !result
                    .unwrap_err()
                    .to_string()
                    .contains("NEVER_EXPOSE_THIS_KEY")
            );
        }
        assert!(parse_address(b"[Peer]\nAddress = 10.1.1.1").is_err());
        assert!(parse_address(b"[Interface]\nPrivateKey=\xff\nAddress=10.1.1.1").is_ok());
    }
    #[test]
    fn supplied_profile_reader_errors_never_format_contents() {
        struct FailingReader;
        impl std::io::Read for FailingReader {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("PrivateKey=NEVER_EXPOSE_THIS_KEY"))
            }
        }
        assert_eq!(
            read_address(FailingReader).unwrap_err(),
            "could not read client profile"
        );
        assert_eq!(
            read_address(
                b"[Interface]\nPrivateKey=NEVER_EXPOSE_THIS_KEY\nAddress=10.99.0.2/32".as_slice()
            )
            .unwrap()
            .to_string(),
            "10.99.0.2"
        );
    }
    #[test]
    fn profile_reads_stop_at_size_limit() {
        let prefix = b"[Interface]\nAddress=10.99.0.2\n#";
        let mut bytes = prefix.to_vec();
        bytes.resize(MAX_PROFILE_BYTES, b'x');
        assert!(read_address(bytes.as_slice()).is_ok());
        bytes.push(b'x');
        assert_eq!(
            read_address(bytes.as_slice()).unwrap_err(),
            "client profile exceeds 16 KiB"
        );
        assert!(read_address(std::io::repeat(b'x')).is_err());
    }
    #[test]
    fn address_ranges() {
        for ip in [
            "10.0.0.0",
            "10.255.255.255",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.2",
            "100.64.0.0",
            "100.127.255.255",
        ] {
            assert!(tunnel_address(ip).is_ok(), "{ip}");
        }
        for ip in [
            "127.0.0.1",
            "0.0.0.0",
            "8.8.8.8",
            "172.15.0.1",
            "172.32.0.1",
            "100.63.255.255",
            "100.128.0.0",
            "192.169.0.1",
            "::1",
            "10.1.1.1/32",
            "localhost",
            "10.1.1.1;echo",
        ] {
            assert!(tunnel_address(ip).is_err(), "{ip}");
        }
    }
}
