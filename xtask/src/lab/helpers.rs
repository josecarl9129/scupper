//! Namespace-local sinks, probes and one deliberately spoofed positive control.
use super::{Result, fail};
use serde::{Deserialize, Serialize};
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    fs::OpenOptions,
    io::{BufRead, BufReader, Read, Write},
    net::{IpAddr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs, UdpSocket},
    path::Path,
    thread,
    time::{Duration, Instant},
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

/// Runs a TCP or UDP marker sink for at most 1050 seconds.
///
/// # Errors
/// Returns socket, log or malformed-marker errors.
pub fn sink(protocol: &str, bind: SocketAddr, log: &Path) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(1050);
    if protocol == "tcp" {
        let listener = TcpListener::bind(bind)?;
        listener.set_nonblocking(true)?;
        while Instant::now() < deadline {
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
    } else if protocol == "udp" {
        let socket = UdpSocket::bind(bind)?;
        socket.set_read_timeout(Some(Duration::from_millis(100)))?;
        let mut buffer = [0; 1024];
        while Instant::now() < deadline {
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
    } else {
        return fail("protocol must be tcp or udp");
    }
    fail("sink lifetime exceeded")
}

/// Sends one marker and requires an identical acknowledgment from the sink.
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
) -> Result<()> {
    if !valid_marker(marker) {
        return fail("invalid probe marker");
    }
    let address = (target, port)
        .to_socket_addrs()?
        .find(|addr| addr.is_ipv6() == ipv6)
        .ok_or("target has no addresses")?;
    println!(
        "{}",
        serde_json::to_string(&Attempt {
            protocol: protocol.into(),
            marker: marker.into(),
            destination: address
        })?
    );
    std::io::stdout().flush()?;
    if protocol == "tcp" {
        let mut stream = TcpStream::connect_timeout(&address, IO_TIMEOUT)?;
        stream.set_write_timeout(Some(IO_TIMEOUT))?;
        stream.set_read_timeout(Some(IO_TIMEOUT))?;
        writeln!(stream, "{marker}")?;
        let mut reply = String::new();
        BufReader::new(stream).read_line(&mut reply)?;
        if reply.trim_end() != marker {
            return fail("TCP acknowledgment mismatch");
        }
    } else if protocol == "udp" {
        let local = if address.is_ipv4() {
            format!("0.0.0.0:{source_port}")
        } else {
            format!("[::]:{source_port}")
        };
        let socket = UdpSocket::bind(local)?;
        socket.set_read_timeout(Some(IO_TIMEOUT))?;
        socket.connect(address)?;
        socket.send(marker.as_bytes())?;
        let mut reply = [0; 1024];
        let len = socket.recv(&mut reply)?;
        if &reply[..len] != marker.as_bytes() {
            return fail("UDP acknowledgment mismatch");
        }
    } else {
        return fail("protocol must be tcp or udp");
    }
    Ok(())
}

/// Injects a marker-bearing IPv4 UDP packet with a forbidden source on eth0.
///
/// # Errors
/// Requires Linux `CAP_NET_RAW`; returns packet construction or socket errors.
pub fn inject(marker: &str) -> Result<()> {
    if !valid_marker(marker) {
        return fail("invalid injection marker");
    }
    let source = super::addresses::A.client_inner.parse()?;
    let destination = super::addresses::A.internet.peer.parse()?;
    let packet = spoofed_packet(source, destination, marker.as_bytes())?;
    let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::UDP))?;
    socket.set_header_included_v4(true)?;
    socket.bind_device(Some(b"eth0"))?;
    socket.send_to(
        &packet,
        &SocketAddr::new(destination, super::addresses::PORT).into(),
    )?;
    Ok(())
}
fn spoofed_packet(source: IpAddr, destination: IpAddr, marker: &[u8]) -> Result<Vec<u8>> {
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
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
