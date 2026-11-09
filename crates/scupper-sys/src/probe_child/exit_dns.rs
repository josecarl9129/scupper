//! DNS over the already-created namespace UDP socket, with no host resolver.
use crate::{
    probe::{IoOperation, io_failure},
    verdict::{Probe, ProbeError},
};
use scupper_core::dns;
use std::{
    io,
    net::{Ipv4Addr, SocketAddr, UdpSocket},
    time::{Duration, Instant},
};

pub(super) trait DnsSocket {
    fn now(&self) -> Instant {
        Instant::now()
    }
    fn send(&self, query: &[u8], server: SocketAddr, timeout: Duration) -> io::Result<()>;
    fn receive(&self, bytes: &mut [u8], timeout: Duration) -> io::Result<(usize, SocketAddr)>;
}
impl DnsSocket for UdpSocket {
    fn send(&self, query: &[u8], server: SocketAddr, timeout: Duration) -> io::Result<()> {
        self.set_write_timeout(Some(timeout))?;
        self.send_to(query, server).map(|_| ())
    }
    fn receive(&self, bytes: &mut [u8], timeout: Duration) -> io::Result<(usize, SocketAddr)> {
        self.set_read_timeout(Some(timeout))?;
        self.recv_from(bytes)
    }
}
pub(super) struct ExitDns<S = UdpSocket> {
    socket: S,
    server: SocketAddr,
}
impl ExitDns {
    pub fn new(socket: UdpSocket, dns: Ipv4Addr) -> Self {
        Self {
            socket,
            server: (dns, 53).into(),
        }
    }
}
impl<S: DnsSocket> ExitDns<S> {
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
        let left = |end: Instant| {
            end.checked_duration_since(self.socket.now())
                .filter(|duration| !duration.is_zero())
                .ok_or(ProbeError::Timeout)
        };
        self.socket
            .send(&query, self.server, left(deadline)?)
            .map_err(path)?;
        let retry_at = self.socket.now() + Duration::from_secs(1);
        let mut retransmitted = false;
        // One extra byte distinguishes oversized datagrams from valid packets.
        let mut bytes = [0; dns::MAX_MESSAGE + 1];
        loop {
            left(deadline)?;
            if !retransmitted && self.socket.now() >= retry_at {
                self.socket
                    .send(&query, self.server, left(deadline)?)
                    .map_err(path)?;
                retransmitted = true;
            }
            let receive_until = if retransmitted {
                deadline
            } else {
                deadline.min(retry_at)
            };
            let Ok(timeout) = left(receive_until) else {
                // The retry boundary can pass between the clock check and this
                // timeout calculation. Recheck it instead of ending the query.
                continue;
            };
            let (count, source) = match self.socket.receive(&mut bytes, timeout) {
                Ok(packet) => packet,
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::Interrupted
                            | io::ErrorKind::TimedOut
                            | io::ErrorKind::WouldBlock
                    ) =>
                {
                    continue;
                }
                Err(error) => return Err(path(error)),
            };
            left(deadline)?;
            if let Some(result) = accept(&bytes[..count], source, self.server, id, host) {
                return result.map_err(|failure| ProbeError::io(&failure.to_string()));
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
) -> Option<Result<Vec<Ipv4Addr>, dns::DnsFailure>> {
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
    use std::{
        cell::{Cell, RefCell},
        collections::VecDeque,
    };
    enum Packet {
        Wait,
        Reply {
            rcode: u8,
            truncated: bool,
            address: bool,
        },
    }
    struct FakeSocket {
        now: Cell<Instant>,
        sent: RefCell<Vec<(Instant, Vec<u8>)>>,
        packets: RefCell<VecDeque<Packet>>,
    }
    impl FakeSocket {
        fn new(packets: impl IntoIterator<Item = Packet>) -> Self {
            Self {
                now: Cell::new(Instant::now()),
                sent: RefCell::default(),
                packets: RefCell::new(packets.into_iter().collect()),
            }
        }
    }
    impl DnsSocket for FakeSocket {
        fn now(&self) -> Instant {
            self.now.get()
        }
        fn send(&self, query: &[u8], _: SocketAddr, _: Duration) -> io::Result<()> {
            self.sent.borrow_mut().push((self.now(), query.to_vec()));
            Ok(())
        }
        fn receive(&self, bytes: &mut [u8], timeout: Duration) -> io::Result<(usize, SocketAddr)> {
            match self
                .packets
                .borrow_mut()
                .pop_front()
                .unwrap_or(Packet::Wait)
            {
                Packet::Wait => {
                    self.now.set(self.now() + timeout);
                    Err(io::ErrorKind::TimedOut.into())
                }
                Packet::Reply {
                    rcode,
                    truncated,
                    address,
                } => {
                    let mut reply = self.sent.borrow().last().unwrap().1.clone();
                    reply[2] = if truncated { 0x83 } else { 0x81 };
                    reply[3] = rcode;
                    if address {
                        reply[7] = 1;
                        reply.extend_from_slice(&[
                            0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 1, 0, 4, 1, 2, 3, 4,
                        ]);
                    }
                    bytes[..reply.len()].copy_from_slice(&reply);
                    Ok((reply.len(), ([10, 2, 0, 1], 53).into()))
                }
            }
        }
    }
    #[test]
    fn matching_failures_end_immediately_as_path_errors() {
        for (rcode, truncated, address, diagnostic) in [
            (3, false, false, "rcode 3"),
            (2, false, false, "rcode 2"),
            (0, true, true, "truncated"),
            (0, false, false, "no usable"),
        ] {
            let resolver = ExitDns {
                socket: FakeSocket::new([Packet::Reply {
                    rcode,
                    truncated,
                    address,
                }]),
                server: ([10, 2, 0, 1], 53).into(),
            };
            let started = resolver.socket.now();
            let error = resolver
                .resolve("probe.test", started + Duration::from_secs(3))
                .unwrap_err();
            assert!(matches!(error, ProbeError::Io(_)), "{error}");
            assert!(error.to_string().contains(diagnostic), "{error}");
            assert_eq!(resolver.socket.now(), started);
            assert_eq!(resolver.socket.sent.borrow().len(), 1);
        }
    }
    #[test]
    fn negative_dns_is_a_path_error_and_exit_ip_falls_through_to_second_target() {
        use crate::{
            probe::Target,
            probe_child::{ProbeKind, child::observe_targets},
        };
        let targets = [
            Target::new("first.test", "/").unwrap(),
            Target::new("second.test", "/").unwrap(),
        ];
        for kind in [ProbeKind::Path, ProbeKind::ExitIp] {
            let resolver = ExitDns {
                socket: FakeSocket::new([
                    Packet::Reply {
                        rcode: 3,
                        truncated: false,
                        address: false,
                    },
                    Packet::Reply {
                        rcode: 0,
                        truncated: false,
                        address: true,
                    },
                ]),
                server: ([10, 2, 0, 1], 53).into(),
            };
            let result = observe_targets(
                kind,
                &targets,
                vec![0, 1, 2, 3],
                Instant::now() + Duration::from_secs(8),
                |host, end| resolver.resolve(host, end),
                |socket, target, _, _| {
                    assert_eq!(socket, 2);
                    assert_eq!(target.host(), "second.test");
                    Ok(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\n1.2.3.4".to_vec())
                },
            );
            if kind == ProbeKind::Path {
                assert!(
                    matches!(result, Err(ProbeError::Io(ref message)) if message == "DNS rcode 3")
                );
                assert_eq!(resolver.socket.sent.borrow().len(), 1);
            } else {
                assert_eq!(result, Ok(Some("1.2.3.4".parse().unwrap())));
                assert_eq!(resolver.socket.sent.borrow().len(), 2);
            }
        }
    }
    #[test]
    fn lost_query_retransmits_once_after_one_second_with_same_id_and_socket() {
        let resolver = ExitDns {
            socket: FakeSocket::new([
                Packet::Wait,
                Packet::Reply {
                    rcode: 0,
                    truncated: false,
                    address: true,
                },
            ]),
            server: ([10, 2, 0, 1], 53).into(),
        };
        let started = resolver.socket.now();
        assert_eq!(
            resolver
                .resolve("probe.test", started + Duration::from_secs(3))
                .unwrap(),
            vec![Ipv4Addr::new(1, 2, 3, 4)]
        );
        let sent = resolver.socket.sent.borrow();
        assert_eq!(sent.len(), 2);
        assert_eq!(sent[1].0 - sent[0].0, Duration::from_secs(1));
        assert_eq!(sent[0].1, sent[1].1);
        drop(sent);
        resolver.socket.sent.borrow_mut().clear();
        let started = resolver.socket.now();
        assert_eq!(
            resolver.resolve("probe.test", started + Duration::from_secs(3)),
            Err(ProbeError::Timeout)
        );
        assert_eq!(resolver.socket.sent.borrow().len(), 2);
        assert_eq!(resolver.socket.now() - started, Duration::from_secs(3));
    }
    #[test]
    fn crossing_retry_time_while_computing_receive_timeout_still_retransmits() {
        struct CrossingClock {
            socket: FakeSocket,
            started: Instant,
            reads: Cell<usize>,
        }
        impl DnsSocket for CrossingClock {
            fn now(&self) -> Instant {
                self.reads.set(self.reads.get() + 1);
                let now = self.started
                    + if self.reads.get() >= 5 {
                        Duration::from_secs(1)
                    } else {
                        Duration::ZERO
                    };
                self.socket.now.set(now);
                now
            }
            fn send(&self, query: &[u8], server: SocketAddr, timeout: Duration) -> io::Result<()> {
                self.socket.send(query, server, timeout)
            }
            fn receive(
                &self,
                bytes: &mut [u8],
                timeout: Duration,
            ) -> io::Result<(usize, SocketAddr)> {
                self.socket.receive(bytes, timeout)
            }
        }
        let socket = FakeSocket::new([Packet::Reply {
            rcode: 0,
            truncated: false,
            address: true,
        }]);
        let started = socket.now();
        let resolver = ExitDns {
            socket: CrossingClock {
                socket,
                started,
                reads: Cell::new(0),
            },
            server: ([10, 2, 0, 1], 53).into(),
        };
        assert!(
            resolver
                .resolve("probe.test", started + Duration::from_secs(3))
                .is_ok()
        );
        assert_eq!(resolver.socket.socket.sent.borrow().len(), 2);
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
