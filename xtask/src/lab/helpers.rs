//! Namespace-local sinks, probes and one deliberately spoofed positive control.
use super::{Result, fail};
use serde::{Deserialize, Serialize};
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    fs::OpenOptions,
    io::{BufRead, BufReader, Read, Write},
    net::{IpAddr, SocketAddr, TcpListener, TcpStream, UdpSocket},
    path::Path,
    thread,
    time::Duration,
};

const IO_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Receipt {
    pub protocol: String,
    pub marker: String,
    pub peer: SocketAddr,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Attempt {
    pub protocol: String,
    pub marker: String,
    pub destination: SocketAddr,
    pub outcome: Outcome,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(super) enum Outcome {
    Delivered,
    TimedOut,
    LocalReject(i32),
    HarnessError { errno: Option<i32>, message: String },
}
impl Outcome {
    fn from_error(error: &std::io::Error, attempted: bool) -> Self {
        if attempted
            && matches!(
                error.kind(),
                std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
            )
        {
            Self::TimedOut
        } else if attempted && error.raw_os_error() == Some(1) {
            Self::LocalReject(1)
        } else {
            Self::HarnessError {
                errno: error.raw_os_error(),
                message: if error.raw_os_error() == Some(126) {
                    format!(
                        "ENOKEY: WireGuard has no peer or endpoint for the probe destination; verify the intended route and socket device binding: {error}"
                    )
                } else {
                    error.to_string()
                },
            }
        }
    }
}

// No libc/NSS resolution: the only resolver contacted is the lab dnsmasq.
fn resolve(target: &str, ipv6: bool) -> Result<IpAddr> {
    if let Ok(ip) = target.parse::<IpAddr>() {
        if ip.is_ipv6() == ipv6 {
            return Ok(ip);
        }
        return fail("target address family mismatch");
    }
    if !target.ends_with(".lab.test") {
        return fail("non-lab DNS name");
    }
    let query = dns_query(target, ipv6)?;
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_read_timeout(Some(IO_TIMEOUT))?;
    socket.connect((super::addresses::A.provider_inner, 53))?;
    socket.send(&query)?;
    let mut bytes = [0; 4096];
    let n = socket.recv(&mut bytes)?;
    dns_answer(&bytes[..n], &query, ipv6)
}
fn dns_query(name: &str, ipv6: bool) -> Result<Vec<u8>> {
    let mut query = vec![0x53, 0x43, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 {
            return fail("invalid DNS label");
        }
        query.push(u8::try_from(label.len())?);
        query.extend(label.as_bytes());
    }
    query.extend([0, 0, if ipv6 { 28 } else { 1 }, 0, 1]);
    Ok(query)
}
fn dns_answer(bytes: &[u8], query: &[u8], ipv6: bool) -> Result<IpAddr> {
    if bytes.len() < query.len()
        || bytes[..2] != query[..2]
        || bytes[2] & 0x82 != 0x80
        || bytes[3] & 15 != 0
        || bytes[4..6] != [0, 1]
        || bytes[12..query.len()] != query[12..]
    {
        return fail("invalid lab DNS response");
    }
    let mut at = query.len();
    for _ in 0..u16::from_be_bytes([bytes[6], bytes[7]]) {
        loop {
            let len = *bytes.get(at).ok_or("short DNS name")?;
            at += 1;
            if len & 0xc0 == 0xc0 {
                bytes.get(at).ok_or("short DNS pointer")?;
                at += 1;
                break;
            }
            if len == 0 {
                break;
            }
            if len > 63 {
                return fail("invalid DNS name");
            }
            at += usize::from(len);
            if at > bytes.len() {
                return fail("short DNS label");
            }
        }
        let header = bytes.get(at..at + 10).ok_or("short DNS answer")?;
        at += 10;
        let len = usize::from(u16::from_be_bytes([header[8], header[9]]));
        let data = bytes.get(at..at + len).ok_or("short DNS address")?;
        if header[..4] == [0, if ipv6 { 28 } else { 1 }, 0, 1] {
            if ipv6 && len == 16 {
                let octets: [u8; 16] = data.try_into()?;
                return Ok(std::net::Ipv6Addr::from(octets).into());
            }
            if !ipv6 && len == 4 {
                return Ok(std::net::Ipv4Addr::new(data[0], data[1], data[2], data[3]).into());
            }
        }
        at += len;
    }
    fail("lab DNS response has no requested address")
}

pub(super) fn receipts(text: &str) -> Result<Vec<Receipt>> {
    text.lines()
        .map(|line| {
            let receipt: Receipt = serde_json::from_str(line)?;
            if !valid_marker(&receipt.marker)
                || !matches!(receipt.protocol.as_str(), "tcp" | "udp")
                || receipt.peer.port() == 0
            {
                return fail("invalid sink receipt");
            }
            Ok(receipt)
        })
        .collect()
}
fn record(log: &Path, protocol: &str, marker: &str, peer: SocketAddr) -> Result<()> {
    let receipt = Receipt {
        protocol: protocol.into(),
        marker: marker.into(),
        peer,
    };
    let mut file = OpenOptions::new().append(true).create(true).open(log)?;
    // One append write per line, shared by the four sinks.
    let line = format!("{}\n", serde_json::to_string(&receipt)?);
    file.write_all(line.as_bytes())?;
    Ok(())
}
fn valid_marker(text: &str) -> bool {
    text.starts_with("scupper-canary-")
        && text.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        && text.len() <= 128
}

/// Runs a TCP or UDP marker sink until its owning suite stops the process.
///
/// # Errors
/// Returns socket, log or malformed-marker errors.
pub fn sink(protocol: &str, bind: SocketAddr, log: &Path) -> Result<()> {
    if protocol == "udp-drain" {
        let socket = UdpSocket::bind(bind)?;
        let mut bytes = vec![0; 65535];
        loop {
            match socket.recv_from(&mut bytes) {
                Ok((len, peer)) => record(log, protocol, &format!("datagram-{len}"), peer)?,
                // A PMTU error belongs to the sender's evidence, and may also
                // be delivered asynchronously to this bound UDP drain socket.
                Err(error)
                    if error.raw_os_error() == Some(90)
                        || error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error.into()),
            }
        }
    }
    if protocol == "tcp" {
        let listener = TcpListener::bind(bind)?;
        listener.set_nonblocking(true)?;
        loop {
            match listener.accept() {
                Ok((mut stream, peer)) => {
                    stream.set_read_timeout(Some(IO_TIMEOUT))?;
                    stream.set_write_timeout(Some(IO_TIMEOUT))?;
                    let mut line = String::new();
                    BufReader::new((&stream).take(1024)).read_line(&mut line)?;
                    let marker = line.trim_end();
                    if !valid_marker(marker) {
                        return fail("invalid TCP marker");
                    }
                    record(log, protocol, marker, peer)?;
                    writeln!(stream, "{marker}")?;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(e) => return Err(e.into()),
            }
        }
    }
    if protocol == "udp" {
        let socket = UdpSocket::bind(bind)?;
        socket.set_read_timeout(Some(Duration::from_millis(100)))?;
        let mut buffer = [0; 1024];
        loop {
            match socket.recv_from(&mut buffer) {
                Ok((len, peer)) => {
                    let marker = std::str::from_utf8(&buffer[..len])?;
                    if !valid_marker(marker) {
                        return fail("invalid UDP marker");
                    }
                    record(log, protocol, marker, peer)?;
                    socket.send_to(marker.as_bytes(), peer)?;
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) => {}
                Err(e) => return Err(e.into()),
            }
        }
    }
    fail("protocol must be tcp or udp")
}

/// Sends a marker or DNS question and reports its structured delivery outcome.
///
/// # Errors
/// Returns resolution, connection, timeout or acknowledgment failures.
pub fn probe(
    protocol: &str,
    target: &str,
    port: u16,
    marker: &str,
    ipv6: bool,
    source_port: u16,
    source: Option<IpAddr>,
) -> Result<bool> {
    if !valid_marker(marker) {
        return fail("invalid probe marker");
    }
    let address = SocketAddr::new(resolve(target, ipv6)?, port);
    let payload = if protocol == "dns" {
        dns_query(&format!("{marker}.lab.test"), ipv6)?
    } else {
        marker.as_bytes().to_vec()
    };
    let mut attempted = false;
    let result: std::io::Result<()> = (|| {
        if protocol == "tcp" {
            let socket = Socket::new(
                if ipv6 { Domain::IPV6 } else { Domain::IPV4 },
                Type::STREAM,
                Some(Protocol::TCP),
            )?;
            let local = if ipv6 {
                IpAddr::from(std::net::Ipv6Addr::UNSPECIFIED)
            } else {
                IpAddr::from(std::net::Ipv4Addr::UNSPECIFIED)
            };
            socket.bind(&SocketAddr::new(local, source_port).into())?;
            socket
                .connect_timeout(&address.into(), IO_TIMEOUT)
                .inspect_err(|error| {
                    // Only connect_timeout's timeout proves an attempted SYN.
                    attempted = error.kind() == std::io::ErrorKind::TimedOut;
                })?;
            let mut stream: TcpStream = socket.into();
            stream.set_write_timeout(Some(IO_TIMEOUT))?;
            stream.set_read_timeout(Some(IO_TIMEOUT))?;
            writeln!(stream, "{marker}")?;
            attempted = true;
            let mut reply = String::new();
            BufReader::new(stream).read_line(&mut reply)?;
            if reply.trim_end() != marker {
                return Err(std::io::Error::other("TCP acknowledgment mismatch"));
            }
        } else if matches!(protocol, "udp" | "dns") {
            let local = source.unwrap_or_else(|| {
                if ipv6 {
                    std::net::Ipv6Addr::UNSPECIFIED.into()
                } else {
                    std::net::Ipv4Addr::UNSPECIFIED.into()
                }
            });
            let socket = Socket::new(
                if ipv6 { Domain::IPV6 } else { Domain::IPV4 },
                Type::DGRAM,
                Some(Protocol::UDP),
            )?;
            // Only link-local IPv6 needs a scope device. Binding an exit's
            // IPv4 source to wg0 overrides the preferred L19 bridge route.
            if source
                .is_some_and(|addr| matches!(addr, IpAddr::V6(v6) if v6.is_unicast_link_local()))
            {
                socket.bind_device(Some(b"wg0"))?;
            }
            socket.bind(&SocketAddr::new(local, source_port).into())?;
            socket.set_read_timeout(Some(IO_TIMEOUT))?;
            socket.connect(&address.into())?;
            let socket: UdpSocket = socket.into();
            socket.send(&payload).inspect_err(|error| {
                // nft output drop is EPERM, distinct from local send failures.
                attempted = error.raw_os_error() == Some(1);
            })?;
            attempted = true;
            let mut reply = [0; 1024];
            let len = socket.recv(&mut reply)?;
            if protocol == "dns" {
                if len < 12 || reply[..2] != payload[..2] || reply[2] & 0x80 == 0 {
                    return Err(std::io::Error::other("DNS acknowledgment mismatch"));
                }
            } else if &reply[..len] != marker.as_bytes() {
                return Err(std::io::Error::other("UDP acknowledgment mismatch"));
            }
        } else {
            return Err(std::io::Error::other("protocol must be tcp or udp"));
        }
        Ok(())
    })();
    let outcome = match result {
        Ok(()) => Outcome::Delivered,
        Err(error) => Outcome::from_error(&error, attempted),
    };
    let delivered = outcome == Outcome::Delivered;
    println!(
        "{}",
        serde_json::to_string(&Attempt {
            protocol: protocol.into(),
            marker: marker.into(),
            destination: address,
            outcome
        })?
    );
    Ok(delivered)
}

/// Injects one forbidden-source packet and two marker-only packets on eth0.
///
/// # Errors
/// Requires Linux `CAP_NET_RAW`; returns packet construction or socket errors.
pub fn inject(marker: &str) -> Result<()> {
    if !valid_marker(marker) {
        return fail("invalid injection marker");
    }
    let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::UDP))?;
    socket.set_header_included_v4(true)?;
    socket.bind_device(Some(b"eth0"))?;
    for packet in injection_packets(marker)? {
        let dst = std::net::Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
        socket.send_to(&packet, &SocketAddr::new(dst.into(), 0).into())?;
    }
    Ok(())
}
pub(super) fn injection_packets(marker: &str) -> Result<Vec<Vec<u8>>> {
    use super::addresses::A;
    let forbidden = spoofed_packet(
        A.client_inner.parse()?,
        A.internet.peer.parse()?,
        marker.as_bytes(),
    )?;
    let mut dns = spoofed_packet(
        A.gwhost.peer.parse()?,
        A.gwhost.wan.parse()?,
        &dns_query(&format!("{marker}.lab.test"), false)?,
    )?;
    dns[20..22].copy_from_slice(&40002_u16.to_be_bytes());
    dns[22..24].copy_from_slice(&53_u16.to_be_bytes());
    let mut payload = spoofed_packet(
        A.gwhost.peer.parse()?,
        A.gwhost.wan.parse()?,
        marker.as_bytes(),
    )?;
    payload[20..22].copy_from_slice(&40003_u16.to_be_bytes());
    Ok(vec![forbidden, dns, payload])
}
pub(super) fn spoofed_packet(
    source: IpAddr,
    destination: IpAddr,
    marker: &[u8],
) -> Result<Vec<u8>> {
    let (IpAddr::V4(src), IpAddr::V4(dst)) = (source, destination) else {
        return fail("injection requires IPv4");
    };
    let length = u16::try_from(28 + marker.len())?;
    let mut packet = vec![0_u8; usize::from(length)];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&length.to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&src.octets());
    packet[16..20].copy_from_slice(&dst.octets());
    let sum: u32 = packet[..20]
        .as_chunks::<2>()
        .0
        .iter()
        .map(|b| u32::from(u16::from_be_bytes([b[0], b[1]])))
        .sum();
    let checksum = !u16::try_from((sum & 0xffff) + (sum >> 16))?;
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
    packet[20..22].copy_from_slice(&40001_u16.to_be_bytes());
    packet[22..24].copy_from_slice(&super::addresses::PORT.to_be_bytes());
    packet[24..26].copy_from_slice(&(length - 20).to_be_bytes());
    // An IPv4 UDP checksum of zero means absent.
    packet[28..].copy_from_slice(marker);
    Ok(packet)
}

/// Sends a complete lab IP datagram through one explicitly bound tunnel.
///
/// # Errors
/// Returns malformed input, privilege, binding or transmit errors.
pub fn send_packet(interface: &str, file: &Path) -> Result<()> {
    let bytes = std::fs::read(file)?;
    let destination: IpAddr = match bytes.first().map(|b| b >> 4) {
        Some(4) if bytes.len() >= 28 => {
            std::net::Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19]).into()
        }
        Some(6) if bytes.len() >= 48 => {
            std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[24..40])?).into()
        }
        _ => return fail("invalid raw lab packet"),
    };
    let socket = Socket::new(
        if destination.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        },
        Type::RAW,
        Some(Protocol::from(255)),
    )?;
    socket.bind_device(Some(interface.as_bytes()))?;
    if destination.is_ipv4() {
        socket.set_header_included_v4(true)?;
    } else {
        socket.set_header_included_v6(true)?;
    }
    socket.send_to(&bytes, &SocketAddr::new(destination, 0).into())?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    #[test]
    fn source_bound_udp_uses_the_route_without_forcing_wg0() {
        let echo = UdpSocket::bind("127.0.0.1:0").unwrap();
        echo.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
        let port = echo.local_addr().unwrap().port();
        let responder = thread::spawn(move || {
            let mut bytes = [0; 1024];
            let (len, peer) = echo.recv_from(&mut bytes).unwrap();
            echo.send_to(&bytes[..len], peer).unwrap();
        });
        let result = probe(
            "udp",
            "127.0.0.1",
            port,
            "scupper-canary-source-route",
            false,
            0,
            Some("127.0.0.1".parse().unwrap()),
        );
        responder.join().unwrap();
        assert!(result.unwrap());
    }
    #[test]
    fn local_socket_errors_never_count_as_a_forward_drop() {
        for errno in [101, 98, 99, 111, 113, 126] {
            let error = std::io::Error::from_raw_os_error(errno);
            for attempted in [false, true] {
                assert!(
                    matches!(Outcome::from_error(&error, attempted), Outcome::HarnessError { errno: Some(value), .. } if value == errno)
                );
            }
        }
        for attempted in [false, true] {
            let error = std::io::Error::from_raw_os_error(126);
            assert!(
                matches!(Outcome::from_error(&error, attempted), Outcome::HarnessError { errno: Some(126), message } if message.contains("ENOKEY") && message.contains("socket device binding"))
            );
        }
        let again = std::io::Error::from_raw_os_error(11);
        assert_eq!(Outcome::from_error(&again, true), Outcome::TimedOut);
        assert!(matches!(
            Outcome::from_error(&again, false),
            Outcome::HarnessError { .. }
        ));
        let denied = std::io::Error::from_raw_os_error(1);
        assert_eq!(Outcome::from_error(&denied, true), Outcome::LocalReject(1));
        assert!(matches!(
            Outcome::from_error(&denied, false),
            Outcome::HarnessError { .. }
        ));
    }
    #[test]
    fn lab_dns_is_explicit_and_rejects_malformed_responses() {
        let query = dns_query("scupper-canary-0011223344556677.lab.test", false).unwrap();
        let mut response = query.clone();
        response[2] = 0x84;
        response[7] = 1;
        response.extend([0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 192, 0, 2, 6]);
        assert_eq!(
            dns_answer(&response, &query, false).unwrap().to_string(),
            "192.0.2.6"
        );
        for len in 0..response.len() {
            assert!(dns_answer(&response[..len], &query, false).is_err());
        }
        response[0] ^= 1;
        assert!(dns_answer(&response, &query, false).is_err());
        assert!(resolve("example.invalid", false).is_err());
        assert!(resolve("::1", false).is_err());
    }
    #[test]
    fn strict_sink_log_and_spoofed_packet() {
        let receipt = Receipt {
            protocol: "udp".into(),
            marker: "scupper-canary-12345678901234567890123456789012".into(),
            peer: "203.0.113.2:40000".parse().unwrap(),
        };
        let text = serde_json::to_string(&receipt).unwrap();
        assert_eq!(receipts(&format!("{text}\n")).unwrap(), vec![receipt]);
        assert!(receipts("{\"marker\":\"cut\"").is_err());
        assert!(receipts("garbage\n").is_err());
        let packet = spoofed_packet(
            "10.99.0.2".parse().unwrap(),
            "192.0.2.6".parse().unwrap(),
            b"scupper-canary-0123456789012345",
        )
        .unwrap();
        let sum: u32 = packet[..20]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|b| u32::from(u16::from_be_bytes([b[0], b[1]])))
            .sum();
        assert_eq!((sum & 0xffff) + (sum >> 16), 0xffff);
    }
}
