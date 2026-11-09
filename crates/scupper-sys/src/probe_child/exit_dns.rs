//! DNS over the already-created namespace UDP socket, with no host resolver.
use crate::{
    probe::{IoOperation, io_failure, remaining},
    verdict::{Probe, ProbeError},
};
use scupper_core::dns;
use std::{
    net::{Ipv4Addr, SocketAddr, UdpSocket},
    time::Instant,
};

pub(super) struct ExitDns {
    socket: UdpSocket,
    server: SocketAddr,
}
impl ExitDns {
    pub fn new(socket: UdpSocket, dns: Ipv4Addr) -> Self {
        Self {
            socket,
            server: (dns, 53).into(),
        }
    }
    pub fn resolve(&self, host: &str, deadline: Instant) -> Probe<Vec<Ipv4Addr>> {
        let mut random = [0; 2];
        let mut at = 0;
        while at < random.len() {
            match rustix::rand::getrandom(&mut random[at..], rustix::rand::GetRandomFlags::empty())
            {
                Ok(0) => return Err(ProbeError::setup("DNS entropy unavailable")),
                Ok(count) => at += count,
                Err(rustix::io::Errno::INTR) => {}
                Err(error) => return Err(ProbeError::setup(&error.to_string())),
            }
        }
        let id = u16::from_ne_bytes(random);
        let query =
            dns::query(id, host).ok_or_else(|| ProbeError::setup("invalid DNS hostname"))?;
        self.socket
            .set_write_timeout(Some(remaining(deadline)?))
            .map_err(path)?;
        self.socket.send_to(&query, self.server).map_err(path)?;
        // One extra byte distinguishes oversized datagrams from valid packets.
        let mut bytes = [0; dns::MAX_MESSAGE + 1];
        loop {
            self.socket
                .set_read_timeout(Some(remaining(deadline)?))
                .map_err(path)?;
            let (count, source) = match self.socket.recv_from(&mut bytes) {
                Ok(packet) => packet,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(path(error)),
            };
            remaining(deadline)?;
            if let Some(addresses) = accept(&bytes[..count], source, self.server, id, host) {
                if addresses.is_empty() {
                    return Err(ProbeError::io("DNS returned no IPv4 addresses"));
                }
                return Ok(addresses);
            }
        }
    }
}
#[allow(clippy::needless_pass_by_value)] // Used as a map_err callback.
fn path(error: std::io::Error) -> ProbeError {
    io_failure(IoOperation::Resolve, &error)
}
fn accept(
    bytes: &[u8],
    source: SocketAddr,
    server: SocketAddr,
    id: u16,
    host: &str,
) -> Option<Vec<Ipv4Addr>> {
    (source == server)
        .then(|| dns::response(bytes, id, host))
        .flatten()
}
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    #[test]
    fn ignores_wrong_source_port_id_and_question() {
        let mut bytes = dns::query(7, "probe.test").unwrap();
        bytes[2] = 0x81;
        bytes[7] = 1;
        bytes.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 1, 0, 4, 1, 2, 3, 4]);
        let server = ([10, 2, 0, 1], 53).into();
        assert!(accept(&bytes, server, server, 7, "probe.test").is_some());
        assert!(accept(&bytes, ([10, 2, 0, 1], 54).into(), server, 7, "probe.test").is_none());
        assert!(accept(&bytes, ([10, 2, 0, 2], 53).into(), server, 7, "probe.test").is_none());
        assert!(accept(&bytes, server, server, 8, "probe.test").is_none());
        assert!(accept(&bytes, server, server, 7, "other.test").is_none());
    }
    #[test]
    fn udp_io_ignores_spoofs_then_accepts_the_matching_answer() {
        let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        server
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        let address = server.local_addr().unwrap();
        let worker = std::thread::spawn(move || {
            let mut query = [0; 512];
            let (count, client) = server.recv_from(&mut query).unwrap();
            let mut response = query[..count].to_vec();
            response[2] = 0x81;
            response[7] = 1;
            response.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 1, 0, 4, 10, 2, 0, 1]);
            let spoof = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            spoof.send_to(&response, client).unwrap();
            let mut wrong_id = response.clone();
            wrong_id[0] ^= 1;
            server.send_to(&wrong_id, client).unwrap();
            let mut wrong_question = response.clone();
            wrong_question[13] = b'x';
            server.send_to(&wrong_question, client).unwrap();
            server.send_to(&response, client).unwrap();
        });
        let resolver = ExitDns {
            socket: UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap(),
            server: address,
        };
        assert_eq!(
            resolver
                .resolve(
                    "probe.test",
                    Instant::now() + std::time::Duration::from_secs(2)
                )
                .unwrap(),
            vec![Ipv4Addr::new(10, 2, 0, 1)]
        );
        worker.join().unwrap();
    }
    #[test]
    fn timeout_is_bounded_without_resolver() {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let resolver = ExitDns {
            socket,
            server: server.local_addr().unwrap(),
        };
        let started = Instant::now();
        assert!(matches!(
            resolver.resolve("probe.test", started + std::time::Duration::from_millis(30)),
            Err(ProbeError::Timeout)
        ));
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
    }
}
