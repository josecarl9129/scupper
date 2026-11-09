//! Pure Linux procfs UDP socket parsing, including native-endian address words.

use super::ParseError;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// One bound UDP socket from procfs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpSocket {
    /// Local address and port, including wildcard addresses.
    pub local: SocketAddr,
    /// Socket inode used to correlate with descriptor ownership.
    pub inode: u64,
}
fn invalid() -> ParseError {
    ParseError::Topology("invalid procfs UDP socket table")
}
fn address(text: &str, v6: bool) -> Result<SocketAddr, ParseError> {
    let (address, port) = text.split_once(':').ok_or_else(invalid)?;
    if address.len() != if v6 { 32 } else { 8 }
        || port.len() != 4
        || !address
            .bytes()
            .chain(port.bytes())
            .all(|b| b.is_ascii_hexdigit())
    {
        return Err(invalid());
    }
    let port = u16::from_str_radix(port, 16).map_err(|_| invalid())?;
    let word = |text| {
        u32::from_str_radix(text, 16)
            .map(u32::to_ne_bytes)
            .map_err(|_| invalid())
    };
    let ip = if v6 {
        let mut bytes = [0; 16];
        for (index, chunk) in address.as_bytes().as_chunks::<8>().0.iter().enumerate() {
            let text = std::str::from_utf8(chunk).map_err(|_| invalid())?;
            bytes[index * 4..index * 4 + 4].copy_from_slice(&word(text)?);
        }
        IpAddr::V6(Ipv6Addr::from(bytes))
    } else {
        IpAddr::V4(Ipv4Addr::from(word(address)?))
    };
    Ok(SocketAddr::new(ip, port))
}
fn parse(out: &str, v6: bool) -> Result<Vec<UdpSocket>, ParseError> {
    let mut lines = out.lines().filter(|line| !line.trim().is_empty());
    let header: Vec<_> = lines
        .next()
        .ok_or_else(invalid)?
        .split_whitespace()
        .collect();
    if header.first() != Some(&"sl")
        || header.get(1) != Some(&"local_address")
        || !header.contains(&"inode")
    {
        return Err(invalid());
    }
    lines
        .map(|line| {
            let columns: Vec<_> = line.split_whitespace().collect();
            if columns.len() < 10 || !columns[0].ends_with(':') {
                return Err(invalid());
            }
            let local = address(columns[1], v6)?;
            address(columns[2], v6)?;
            if columns[3].len() != 2
                || !columns[3].bytes().all(|b| b.is_ascii_hexdigit())
                || !columns[9].bytes().all(|b| b.is_ascii_digit())
            {
                return Err(invalid());
            }
            Ok(UdpSocket {
                local,
                inode: columns[9].parse().map_err(|_| invalid())?,
            })
        })
        .collect()
}

/// Parses `/proc/net/udp` without I/O.
///
/// # Errors
/// Rejects missing headers and malformed records, addresses, ports or inodes.
pub fn parse_proc_net_udp(out: &str) -> Result<Vec<UdpSocket>, ParseError> {
    parse(out, false)
}

/// Parses `/proc/net/udp6` without I/O. Each address word is native endian.
///
/// # Errors
/// Rejects missing headers and malformed records, addresses, ports or inodes.
pub fn parse_proc_net_udp6(out: &str) -> Result<Vec<UdpSocket>, ParseError> {
    parse(out, true)
}

/// Whether an already parsed UDP inventory includes a bound port, even wildcard.
#[must_use]
pub fn udp_port_bound(sockets: &[UdpSocket], port: u16) -> bool {
    sockets.iter().any(|socket| socket.local.port() == port)
}
